#!/usr/bin/env python3
"""
Script rápido: extrai APENAS informações "before/after" por commit:

- lines_of_code_before / lines_of_code_after
- avg_complexity_before / avg_complexity_after (via lizard; fallback heurístico se lizard ausente)
- dependencies_before / dependencies_after (unique deps + devDeps em todos os package.json do commit)
- vulnerable_dependencies_before / vulnerable_dependencies_after (opcional via OSV, com cache local)

Como funciona:
- Clona o repo (shallow + --filter=blob:none) para acelerar.
- Lista commits que tocaram qualquer package.json.
- Para cada commit e seu pai:
  - Lê blobs direto do git (git show sha:path) sem checkout.
  - Agrega dependências dos package.json.
  - Calcula LOC/complexidade lendo arquivos JS/TS do snapshot.

Requisitos:
- git no PATH
- pip install lizard requests  (lizard é recomendado; sem ele, complexidade usa fallback simples)

Exemplos:
  python quick_before_after.py --repo airbnb/javascript --commit-limit 200 --clone-depth 2000 --output out.json
  python quick_before_after.py --repos-file repos.json --limit 10 --commit-limit 150 --clone-depth 1500 --include-osv --output out.json
"""
import argparse
import json
import os
import sys
import subprocess
import tempfile
import time
from typing import List, Dict, Tuple, Optional
import re

# lizard opcional
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

# ------------------- Git helpers -------------------

def run_git(args: List[str], cwd: Optional[str] = None, timeout: Optional[int] = None) -> str:
    """Executa git e retorna stdout como str; lança em erro."""
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
    lines = [l.strip() for l in out.splitlines() if l.strip()]
    return lines

def commit_info(repo_dir: str, sha: str) -> Tuple[str, str, str]:
    """Retorna (parent_sha, subject, isoDate). Parent pode ser ''."""
    out = run_git(["-C", repo_dir, "rev-list", "--parents", "-n", "1", sha]).strip()
    parts = out.split()
    parent = parts[1] if len(parts) >= 2 else ""
    meta = run_git(["-C", repo_dir, "show", "-s", "--format=%s%x00%cI", sha])
    subj, iso = ("", "")
    sp = meta.split("\x00")
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

# ------------------- Package.json helpers -------------------

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

# ------------------- Métricas inline -------------------

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
        # LOC: linhas não vazias
        loc = sum(1 for ln in code.splitlines() if ln.strip())
        total_loc += loc
        # Complexidade: lizard se disponível, senão fallback
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
            # Fallback: contar linhas que contêm tokens de controle como proxy
            c = 0
            low = " " + code.replace("\t", "    ").lower() + " "
            for tok in FALLBACK_COMPLEX_TOKENS:
                c += low.count(tok)
            complexities.append(max(0, c))  # evita negativo
    avg_complex = float(sum(complexities) / len(complexities)) if complexities else 0.0
    return {
        "lines_of_code": total_loc,
        "avg_complexity": avg_complex,
        "files_scanned": len(files),
        "functions_counted": len(complexities) if lizard is not None else "fallback",
        "complexity_tool": "lizard" if lizard is not None else "fallback",
    }

# ------------------- OSV (opcional) -------------------

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

def osv_query_count(pkg: str, session, cache: Dict[str, dict]) -> int:
    # Assume ecossistema NPM
    key = f"npm:{pkg}"
    if key in cache:
        data = cache[key]
    else:
        if session is None or requests is None:
            return 0
        try:
            r = session.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"name": pkg, "ecosystem": "npm"}},
                timeout=10,
            )
            if r.status_code == 200:
                data = r.json()
            else:
                data = {}
        except Exception:
            data = {}
        cache[key] = data
    vulns = data.get("vulns") if isinstance(data, dict) else None
    return len(vulns) if isinstance(vulns, list) else 0

def vuln_dep_count(dep_names: List[str], session, cache: Dict[str, dict]) -> int:
    c = 0
    for name in dep_names:
        if osv_query_count(name, session, cache) > 0:
            c += 1
    return c

# ------------------- Core por repositório -------------------

def process_repo(full: str,
                 commit_limit: int,
                 clone_depth: int,
                 clone_timeout: int,
                 include_osv: bool,
                 osv_cache_path: str) -> List[dict]:
    t0 = time.time()
    tmp_root = tempfile.mkdtemp(prefix="ba_")
    repo_dir = os.path.join(tmp_root, full.split("/")[-1])
    session = requests.Session() if (include_osv and requests is not None) else None
    osv_cache = load_osv_cache(osv_cache_path) if include_osv else {}
    results = []
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

            if include_osv:
                vb = vuln_dep_count(dep_names_before, session, osv_cache)
                va = vuln_dep_count(dep_names_after, session, osv_cache)
            else:
                vb = va = 0

            mb = compute_metrics_inline(repo_dir, parent)
            ma = compute_metrics_inline(repo_dir, sha)

            rec = {
                "repo": full,
                "commit": sha,
                "parent": parent,
                "commit_message": subj,
                "commit_date": iso,

                "lines_of_code_before": mb.get("lines_of_code", 0),
                "lines_of_code_after":  ma.get("lines_of_code", 0),
                "avg_complexity_before": mb.get("avg_complexity", 0.0),
                "avg_complexity_after":  ma.get("avg_complexity", 0.0),

                "dependencies_before": dependencies_before,
                "dependencies_after":  dependencies_after,
                "vulnerable_dependencies_before": vb,
                "vulnerable_dependencies_after":  va,
            }
            results.append(rec)

        dt = int((time.time() - t0) * 1000)
        print(f"[done] {full} commits_out={len(results)} time_ms={dt}")
        return results
    finally:
        if include_osv:
            save_osv_cache(osv_cache_path, osv_cache)
        try:
            import shutil
            shutil.rmtree(tmp_root, ignore_errors=True)
        except Exception:
            pass

# ------------------- Entrada -------------------

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
    raise ValueError("repos file must be a JSON array of strings or objects with 'repo'/'name'")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", type=str, help="owner/repo")
    ap.add_argument("--repos-file", type=str, help='JSON: ["owner/repo", ...]')
    ap.add_argument("--limit", type=int, default=0, help="limita número de repos do arquivo (0 = todos)")
    ap.add_argument("--commit-limit", type=int, default=200, help="limita commits que tocam package.json")
    ap.add_argument("--clone-depth", type=int, default=2000, help="profundidade do clone raso")
    ap.add_argument("--clone-timeout", type=int, default=600, help="timeout do git clone (s)")
    ap.add_argument("--include-osv", action="store_true", help="contar deps vulneráveis via OSV (mais lento)")
    ap.add_argument("--osv-cache", type=str, default="osv_cache.json", help="arquivo de cache OSV")
    ap.add_argument("--output", type=str, default="before_after.json", help="arquivo de saída JSON")
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
        sys.exit(2)

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
    print(f"[ok] wrote {args.output} records={len(all_rows)}")

if __name__ == "__main__":
    main()