#!/usr/bin/env python3
"""
Extrai eventos de remoção de dependências com contexto de segurança (OSV) e métricas before/after.

Para cada commit que toca package.json:
- Calcula:
  - lines_of_code_before / after
  - avg_complexity_before / after (via lizard se disponível; senão fallback heurístico)
  - dependencies_before / after (unique deps + devDeps)
- Para cada dependência REMOVIDA nesse commit:
  - removed_dep, versions_before (quando possível)
  - vulns (OSV): id, summary, published, modified, aliases, references, max_cvss
  - advisory_before_commit (published <= commit_date)
  - commit_msg_hits (CVE-…, GHSA-…, security, vulnerability, dependabot, etc.)
  - likely_security_removal (advisory_before_commit && commit_msg_hits != [])
  - version_exact_match (True se alguma versão listada em OSV coincide com uma das versões_before)
Saída: JSON com um registro POR REMOÇÃO de dependência.

Uso:
  pip install requests lizard
  python quick_removed_dep_vulns.py --repo airbnb/javascript --commit-limit 200 --clone-depth 2000 --output out.json
"""

import argparse
import json
import os
import subprocess
import tempfile
import time
import re
from typing import List, Dict, Tuple, Optional

# lizard opcional para complexidade ciclomática
try:
    import lizard  # type: ignore
except Exception:
    lizard = None

try:
    import requests
except Exception:
    requests = None

GIT = "git"
JS_EXTS = (".js", ".jsx", ".ts", ".tsx")

SECURITY_KEYWORDS = [
    "security", "vulnerability", "vulnerab", "advisory", "cve", "ghsa",
    "dependabot", "snyk", "cvss", "severity", "fix", "patch", "upgrade",
    "bump", "mitigate", "exploit", "xss", "rce", "csp", "csrf"
]
CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
GHSA_RE = re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)

# ---------------- Git helpers ----------------

def run_git(args: List[str], cwd: Optional[str] = None, timeout: Optional[int] = None) -> str:
    p = subprocess.run(
        [GIT] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout
    )
    if p.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.returncode}\nstdout:\n{p.stdout}\nstderr:\n{p.stderr}")
    return p.stdout

def clone_repo(full: str, depth: int, target: str, timeout: int) -> None:
    args = [
        "clone",
        "--filter=blob:none",
        "--quiet",
        f"--depth={depth}",
        "--no-tags",
        f"https://github.com/{full}.git",
        target,
    ]
    run_git(args, timeout=timeout)

def commits_touching_pkg_json(repo_dir: str) -> List[str]:
    out = run_git(["-C", repo_dir, "log", "--pretty=format:%H", "--no-renames", "--diff-filter=AMDR", ":(glob)**/package.json"])
    return [l.strip() for l in out.splitlines() if l.strip()]

def commit_info(repo_dir: str, sha: str) -> Tuple[str, str, str]:
    """Retorna (parent_sha, subject, isoDate)"""
    out = run_git(["-C", repo_dir, "rev-list", "--parents", "-n", "1", sha]).strip()
    parts = out.split()
    parent = parts[1] if len(parts) >= 2 else ""
    meta = run_git(["-C", repo_dir, "show", "-s", "--format=%s%x00%cI", sha])
    sp = meta.split("\x00")
    subj, iso = ("", "")
    if len(sp) >= 2:
        subj = sp[0].strip()
        iso = sp[1].strip()
    return parent, subj, iso

def list_paths_at_commit(repo_dir: str, sha: str) -> List[str]:
    out = run_git(["-C", repo_dir, "ls-tree", "-r", "--name-only", sha])
    return [l.strip() for l in out.splitlines() if l.strip()]

def git_show(repo_dir: str, sha: str, path: str) -> str:
    try:
        return run_git(["-C", repo_dir, "show", f"{sha}:{path}"])
    except Exception:
        return ""

# ---------------- package.json helpers ----------------

def list_package_json_paths_at_commit(repo_dir: str, sha: str) -> List[str]:
    return [p for p in list_paths_at_commit(repo_dir, sha) if p.lower().endswith("package.json")]

def load_package_json_at_commit(repo_dir: str, sha: str, path: str) -> Optional[dict]:
    txt = git_show(repo_dir, sha, path)
    if not txt:
        return None
    try:
        return json.loads(txt)
    except Exception:
        return None

def load_all_pkg_at_commit(repo_dir: str, sha: str) -> Tuple[Dict[str, dict], List[str]]:
    paths = list_package_json_paths_at_commit(repo_dir, sha)
    data = {}
    for p in paths:
        pj = load_package_json_at_commit(repo_dir, sha, p)
        if pj:
            data[p] = pj
    return data, paths

def aggregate_deps(pkgs: Dict[str, dict]) -> Tuple[Dict[str, str], Dict[str, str]]:
    deps, dev = {}, {}
    for _, pkg in pkgs.items():
        d = pkg.get("dependencies") or {}
        dv = pkg.get("devDependencies") or {}
        for k, v in d.items():
            deps.setdefault(k, str(v))
        for k, v in dv.items():
            dev.setdefault(k, str(v))
    return deps, dev

# ---------------- métricas inline ----------------

def iter_js_ts_files(repo_dir: str, sha: str):
    for p in list_paths_at_commit(repo_dir, sha):
        pl = p.lower()
        if pl.endswith(JS_EXTS) and not pl.endswith(".d.ts"):
            yield p

FALLBACK_COMPLEX_TOKENS = (" if ", " for ", " while ", "case ", " switch ", " catch", " else if", " =>", " function ")

def compute_metrics_inline(repo_dir: str, sha: str) -> Dict[str, object]:
    total_loc = 0
    complexities = []
    files = list(iter_js_ts_files(repo_dir, sha))
    for path in files:
        code = git_show(repo_dir, sha, path)
        if not code:
            continue
        loc = sum(1 for ln in code.splitlines() if ln.strip())
        total_loc += loc
        if lizard is not None:
            try:
                res = lizard.analyze_file.analyze_source_code(path, code)  # type: ignore
                funs = getattr(res, "function_list", []) or []
                for fn in funs:
                    cc = getattr(fn, "cyclomatic_complexity", None)
                    if isinstance(cc, int):
                        complexities.append(cc)
            except Exception:
                pass
        else:
            c = 0
            low = " " + code.replace("\t", "    ").lower() + " "
            for tok in FALLBACK_COMPLEX_TOKENS:
                c += low.count(tok)
            complexities.append(max(0, c))
    avg_complex = float(sum(complexities) / len(complexities)) if complexities else 0.0
    return {
        "lines_of_code": total_loc,
        "avg_complexity": avg_complex,
        "files_scanned": len(files),
        "functions_counted": len(complexities) if lizard is not None else "fallback",
        "complexity_tool": "lizard" if lizard is not None else "fallback",
    }

# ---------------- OSV (CVE/GHSA) ----------------

def load_osv_cache(path: str) -> Dict[str, dict]:
    if path and os.path.exists(path):
        try:
            return json.load(open(path, "r", encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_osv_cache(path: str, cache: Dict[str, dict]) -> None:
    if not path:
        return
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=2, ensure_ascii=False)
    except Exception:
        pass

def osv_query_package(pkg: str, session, cache: Dict[str, dict]) -> dict:
    key = f"npm:{pkg}"
    if key in cache:
        return cache[key]
    if session is None or requests is None:
        cache[key] = {}
        return cache[key]
    try:
        r = session.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": pkg, "ecosystem": "npm"}},
            timeout=12,
        )
        if r.status_code == 200:
            data = r.json()
        else:
            data = {}
    except Exception:
        data = {}
    cache[key] = data
    return data

def extract_vuln_briefs(osv_resp: dict, versions_before: List[str]) -> List[dict]:
    vulns = osv_resp.get("vulns") if isinstance(osv_resp, dict) else None
    if not isinstance(vulns, list):
        return []
    briefs = []
    vset = set(versions_before or [])
    for v in vulns:
        vid = v.get("id") or ""
        summary = v.get("summary") or v.get("details", "")[:200]
        published = v.get("published") or ""
        modified = v.get("modified") or ""
        aliases = v.get("aliases") or []
        refs = [r.get("url") for r in (v.get("references") or []) if isinstance(r, dict) and r.get("url")]
        # severidade: pega o maior CVSS disponível
        max_cvss = None
        for sev in (v.get("severity") or []):
            score = sev.get("score")
            if not score:
                continue
            try:
                # formato costuma ser "CVSS:3.1/AV:N/..." ou número; tente float
                val = float(score) if score.replace(".", "", 1).isdigit() else None
            except Exception:
                val = None
            if val is not None:
                max_cvss = max(val, max_cvss) if max_cvss is not None else val
        # tentativa simples de match por versão exata (muitos advisories não listam enumerados)
        exact_match = False
        for aff in (v.get("affected") or []):
            for vv in (aff.get("versions") or []):
                if vv in vset:
                    exact_match = True
                    break
            if exact_match:
                break
        briefs.append({
            "id": vid,
            "summary": summary,
            "published": published,
            "modified": modified,
            "aliases": aliases,
            "references": refs,
            "max_cvss": max_cvss,
            "version_exact_match": exact_match,
        })
    return briefs

def commit_msg_hits(msg: str) -> List[str]:
    hits = []
    if not msg:
        return hits
    low = msg.lower()
    cves = CVE_RE.findall(msg)
    ghsas = GHSA_RE.findall(msg)
    hits.extend(cves)
    hits.extend(ghsas)
    for kw in SECURITY_KEYWORDS:
        if kw in low:
            hits.append(kw)
    # dedup mantendo ordem
    seen = set()
    uniq = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq

def iso_to_epoch(iso: str) -> Optional[int]:
    try:
        # Formatos ISO comuns
        from datetime import datetime
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return int(dt.timestamp())
    except Exception:
        return None

# ---------------- core por repo ----------------

def process_repo(full: str,
                 commit_limit: int,
                 clone_depth: int,
                 clone_timeout: int,
                 include_osv: bool,
                 osv_cache_path: str) -> List[dict]:
    t0 = time.time()
    import shutil
    tmp_root = tempfile.mkdtemp(prefix="rv_")
    repo_dir = os.path.join(tmp_root, full.split("/")[-1])
    session = requests.Session() if (include_osv and requests is not None) else None
    osv_cache = load_osv_cache(osv_cache_path) if include_osv else {}
    rows = []
    try:
        print(f"[clone] {full}")
        clone_repo(full, clone_depth, repo_dir, timeout=clone_timeout)
        commits = commits_touching_pkg_json(repo_dir)
        if commit_limit and len(commits) > commit_limit:
            commits = commits[:commit_limit]
        print(f"[{full}] commits touching package.json: {len(commits)}")

        for sha in commits:
            parent, subj, iso = commit_info(repo_dir, sha)
            if not parent:
                continue
            before_pkgs, _ = load_all_pkg_at_commit(repo_dir, parent)
            after_pkgs, _ = load_all_pkg_at_commit(repo_dir, sha)
            if not before_pkgs:
                continue

            deps_b, dev_b = aggregate_deps(before_pkgs)
            deps_a, dev_a = aggregate_deps(after_pkgs)

            dep_names_before = sorted(set(list(deps_b.keys()) + list(dev_b.keys())))
            dep_names_after  = sorted(set(list(deps_a.keys()) + list(dev_a.keys())))
            dependencies_before = len(dep_names_before)
            dependencies_after  = len(dep_names_after)

            # removed deps
            removed = [d for d in deps_b.keys() if d not in deps_a]
            if not removed:
                continue

            mb = compute_metrics_inline(repo_dir, parent)
            ma = compute_metrics_inline(repo_dir, sha)

            commit_epoch = iso_to_epoch(iso) or 0
            msg_hits = commit_msg_hits(subj or "")

            for dep in removed:
                # versões "antes" dessa dependência (coletadas dos package.json do snapshot)
                versions_before = []
                for _, pkg in before_pkgs.items():
                    for section in ("dependencies", "devDependencies"):
                        v = (pkg.get(section) or {}).get(dep)
                        if v and v not in versions_before:
                            versions_before.append(str(v))

                vulns = []
                advisory_before_commit = False
                if include_osv:
                    osv_resp = osv_query_package(dep, session, osv_cache)
                    briefs = extract_vuln_briefs(osv_resp, versions_before)
                    # published <= commit_date?
                    for b in briefs:
                        pub_epoch = iso_to_epoch(b.get("published") or "") or 0
                        if pub_epoch and pub_epoch <= commit_epoch:
                            advisory_before_commit = True
                            break
                    vulns = briefs

                likely_security = advisory_before_commit and bool(msg_hits)

                row = {
                    "repo": full,
                    "commit": sha,
                    "commit_date": iso,
                    "commit_message": subj,
                    "removed_dep": dep,
                    "versions_before": versions_before,

                    "lines_of_code_before": mb.get("lines_of_code", 0),
                    "lines_of_code_after":  ma.get("lines_of_code", 0),
                    "avg_complexity_before": mb.get("avg_complexity", 0.0),
                    "avg_complexity_after":  ma.get("avg_complexity", 0.0),

                    "dependencies_before": dependencies_before,
                    "dependencies_after":  dependencies_after,

                    "vulns": vulns,  # lista de {id, summary, published, modified, aliases, references, max_cvss, version_exact_match}
                    "advisory_before_commit": advisory_before_commit,
                    "commit_msg_hits": msg_hits,
                    "likely_security_removal": likely_security,
                }
                rows.append(row)

        dt = int((time.time() - t0) * 1000)
        print(f"[done] {full} removals={len(rows)} time_ms={dt}")
        return rows
    finally:
        if include_osv:
            save_osv_cache(osv_cache_path, osv_cache)
        try:
            shutil.rmtree(tmp_root, ignore_errors=True)
        except Exception:
            pass

# ---------------- entrada ----------------

def load_repos_file(path: str) -> List[str]:
    data = json.load(open(path, "r", encoding="utf-8"))
    if isinstance(data, list):
        out = []
        for item in data:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                if item.get("repo"):
                    out.append(item["repo"])
                elif item.get("name"):
                    out.append(item["name"])
        return out
    raise ValueError("repos file deve ser uma lista JSON de strings ou de objetos com 'repo'/'name'")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", type=str, help="owner/repo")
    ap.add_argument("--repos-file", type=str, help='JSON: ["owner/repo", ...]')
    ap.add_argument("--limit", type=int, default=0, help="limita número de repos do arquivo (0=todos)")
    ap.add_argument("--commit-limit", type=int, default=200, help="limita commits que tocam package.json")
    ap.add_argument("--clone-depth", type=int, default=2000, help="profundidade do clone raso")
    ap.add_argument("--clone-timeout", type=int, default=600, help="timeout do clone (s)")
    ap.add_argument("--include-osv", action="store_true", help="consultar OSV e incluir vulnerabilidades (mais lento)")
    ap.add_argument("--osv-cache", type=str, default="osv_cache.json", help="arquivo de cache OSV")
    ap.add_argument("--output", type=str, default="removed_dep_vulns.json", help="arquivo de saída JSON")
    args = ap.parse_args()

    targets: List[str] = []
    if args.repo:
        targets = [args.repo]
    elif args.repos_file:
        repos = load_repos_file(args.repos_file)
        if args.limit and len(repos) > args.limit:
            repos = repos[:args.limit]
        targets = repos
    else:
        print("Use --repo owner/repo ou --repos-file repos.json")
        return

    all_rows: List[dict] = []
    for r in targets:
        try:
            rows = process_repo(
                full=r,
                commit_limit=args.commit_limit,
                clone_depth=args.clone_depth,
                clone_timeout=args.clone_timeout,
                include_osv=args.include_osv,
                osv_cache_path=args.osv_cache,
            )
            all_rows.extend(rows)
        except Exception as e:
            print(f"[error] {r}: {e}")

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(all_rows, f, indent=2, ensure_ascii=False)
    print(f"[ok] wrote {args.output} removals={len(all_rows)}")

if __name__ == "__main__":
    main()