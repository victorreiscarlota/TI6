#!/usr/bin/env python3
"""
Mining + sinais de migração para nativo com proteção de timeout e clone controlado.
Inclui:
- contagens before/after de dependencies e vulnerable_dependencies (via OSV com cache)
- CÁLCULO DE MÉTRICAS INLINE POR COMMIT (sem checkout):
  - lines_of_code e avg_complexity usando blobs do git
  - lizard para complexidade ciclomática por função em JS/TS

Requer: lizard (pip install lizard) para avg_complexity > 0.0
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import List, Dict, Tuple

import requests

# imports robustos (relativo + fallback absoluto)
try:
    from .repo_watchdog_subprocess import run_callable_in_subprocess
    from .metrics import get_cve_for_package, load_osv_cache, save_osv_cache
except ImportError:
    from app.scripts.repo_watchdog_subprocess import run_callable_in_subprocess
    from app.scripts.metrics import get_cve_for_package, load_osv_cache, save_osv_cache

# lizard é opcional, mas recomendado
try:
    import lizard  # type: ignore
except Exception:
    lizard = None

GIT = "git"
PYTHON = "python"

DEFAULT_REPO_TIMEOUT = int(os.environ.get("REPO_TIMEOUT", 1800))
DEFAULT_CLONE_TIMEOUT = int(os.environ.get("REPO_CLONE_TIMEOUT", 600))
DEFAULT_MAX_COMMITS_SCAN = int(os.environ.get("MAX_COMMITS_SCAN", 1200))

LOG_ROOT = os.path.join("app", "results", "logs")

JS_EXTS = (".js", ".jsx", ".ts", ".tsx")

def log(repo: str, msg: str):
    os.makedirs(LOG_ROOT, exist_ok=True)
    safe_name = repo.replace("/", "__")
    path = os.path.join(LOG_ROOT, f"{safe_name}.log")
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"[{ts}] {msg}\n")

def run(cmd, cwd=None, check=True, timeout=None):
    result = subprocess.run(
        cmd,
        shell=True,
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\nstdout:{result.stdout}\nstderr:{result.stderr}")
    return result.stdout.strip()

def clone_repo_light(full_name: str, target_dir: str, clone_timeout: int):
    os.makedirs(os.path.dirname(target_dir), exist_ok=True)
    cmd = f'{GIT} clone --filter=blob:none --no-checkout --quiet https://github.com/{full_name}.git "{target_dir}"'
    run(cmd, timeout=clone_timeout, check=True)

def commits_touching_any_package_json(repo_dir: str, limit: int = None) -> List[Tuple[str, int, str]]:
    out = run(f'{GIT} -C "{repo_dir}" log --pretty=format:%H --no-renames --diff-filter=AMDR -- ":(glob)**/package.json"', check=False)
    shas = [l for l in (out.splitlines() if out else []) if l.strip()]
    result = []
    for sha in (shas[:limit] if limit else shas):
        info = run(f'{GIT} -C "{repo_dir}" show -s --format=%ct%x00%s {sha}', check=False)
        if info:
            try:
                ts, subj = info.split("\x00", 1)
                result.append((sha, int(ts), subj))
            except Exception:
                result.append((sha, 0, ""))
        else:
            result.append((sha, 0, ""))
    return result

def parent_of(repo_dir: str, sha: str) -> str:
    line = run(f'{GIT} -C "{repo_dir}" rev-list --parents -n 1 {sha}', check=False)
    parts = line.split()
    return parts[1] if len(parts) >= 2 else ""

def list_paths_at_commit(repo_dir: str, sha: str) -> List[str]:
    out = run(f'{GIT} -C "{repo_dir}" ls-tree -r --name-only {sha}', check=False)
    return [l for l in (out.splitlines() if out else []) if l.strip()]

def list_package_json_paths_at_commit(repo_dir: str, sha: str) -> List[str]:
    return [p for p in list_paths_at_commit(repo_dir, sha) if p.lower().endswith("package.json")]

def load_package_json_at_commit(repo_dir: str, sha: str, path: str):
    try:
        txt = run(f'{GIT} -C "{repo_dir}" show {sha}:{path}', check=False)
        if not txt:
            return None
        import json as _json
        return _json.loads(txt)
    except Exception:
        return None

def aggregate_deps(pkg_dict: Dict[str, dict]):
    deps_agg, dev_agg, versions = {}, {}, {}
    for p, pkg in pkg_dict.items():
        deps = (pkg.get("dependencies") or {})
        dev = (pkg.get("devDependencies") or {})
        for k, v in deps.items():
            if k not in deps_agg:
                deps_agg[k] = v
            versions.setdefault(k, set()).add(v)
        for k, v in dev.items():
            if k not in dev_agg:
                dev_agg[k] = v
            versions.setdefault(k, set()).add(v)
    versions = {k: sorted(list(vs)) for k, vs in versions.items()}
    return deps_agg, dev_agg, versions

def load_all_pkg_at_commit(repo_dir: str, sha: str):
    paths = list_package_json_paths_at_commit(repo_dir, sha)
    d = {}
    for p in paths:
        pj = load_package_json_at_commit(repo_dir, sha, p)
        if pj:
            d[p] = pj
    return d, paths

# ------------- Métricas inline por commit (sem checkout) -------------

def _iter_js_ts_files(repo_dir: str, sha: str):
    for p in list_paths_at_commit(repo_dir, sha):
        if not p.lower().endswith(JS_EXTS):
            continue
        # ignorar declarações TypeScript
        if p.endswith(".d.ts"):
            continue
        yield p

def _git_show(repo_dir: str, sha: str, path: str) -> str:
    return run(f'{GIT} -C "{repo_dir}" show {sha}:{path}', check=False) or ""

def compute_js_metrics_inline(repo_dir: str, sha: str) -> dict:
    """
    Calcula lines_of_code e avg_complexity lendo blobs do commit (sha) via git show.
    - LOC: linhas não vazias
    - Complexidade: média das complexidades por função via lizard (se disponível)
    """
    total_loc = 0
    complexities = []
    for path in _iter_js_ts_files(repo_dir, sha):
        code = _git_show(repo_dir, sha, path)
        if not code:
            continue
        # LOC simples: não vazias
        loc = sum(1 for ln in code.splitlines() if ln.strip())
        total_loc += loc
        # Complexidade via lizard, se disponível
        if lizard is not None:
            try:
                # analyze_source_code(filename, source_code)
                result = lizard.analyze_file.analyze_source_code(path, code)  # type: ignore
                for fn in getattr(result, "function_list", []) or []:
                    cc = getattr(fn, "cyclomatic_complexity", None)
                    if isinstance(cc, int):
                        complexities.append(cc)
            except Exception:
                # ignora erros por arquivo
                pass
    avg_complex = float(sum(complexities) / len(complexities)) if complexities else 0.0
    return {
        "lines_of_code": total_loc,
        "avg_complexity": avg_complex,
        "commit_snapshot": sha,
        "files_scanned": len(list(_iter_js_ts_files(repo_dir, sha))),
        "functions_counted": len(complexities),
        "complexity_tool": "lizard" if lizard is not None else "none",
    }

def grep_count(repo_dir: str, sha: str, pattern: str) -> int:
    out = run(f'{GIT} -C "{repo_dir}" grep -I -n -E "{pattern}" {sha} -- "*.js" "*.jsx" "*.ts" "*.tsx"', check=False)
    if not out:
        return 0
    return len([l for l in out.splitlines() if l.strip()])

def or_regex(parts):
    parts_escaped = [p for p in parts if p]
    return "(?:" + "|".join(parts_escaped) + ")" if parts_escaped else "(?!)"

def build_patterns_for_dep(dep: str):
    d = dep.lower()
    if d in ("lodash", "underscore"):
        third = or_regex([
            r"(?:from|require)\s*['\"](?:lodash|underscore)['\"]",
            r"[_]\s*\.", r"lodash\.",
        ])
        native = or_regex([
            r"\.map\s*\(", r"\.filter\s*\(", r"\.reduce\s*\(",
            r"Object\.assign\s*\(", r"Object\.(?:keys|values|entries)\s*\(",
            r"Array\.from\s*\(", r"String\.includes\s*\(",
        ])
        return ("lodash", third, native)
    if d == "left-pad":
        return ("left-pad",
                or_regex([r"(?:from|require)\s*['\"]left-pad['\"]", r"leftpad\s*\("]),
                or_regex([r"\.padStart\s*\(", r"\.padEnd\s*\("]))
    if d == "uuid":
        return ("uuid",
                or_regex([r"(?:from|require)\s*['\"]uuid['\"]"]),
                or_regex([r"crypto\.randomUUID\s*\("]))
    if d == "querystring":
        return ("querystring",
                or_regex([r"(?:from|require)\s*['\"]querystring['\"]"]),
                or_regex([r"URLSearchParams\s*\("]))
    if d in ("node-fetch", "request"):
        return ("fetch",
                or_regex([r"(?:from|require)\s*['\"](?:node-fetch|request)['\"]"]),
                or_regex([r"(?<!\.)\bfetch\s*\("]))
    if d == "mkdirp":
        return ("mkdirp",
                or_regex([r"(?:from|require)\s*['\"]mkdirp['\"]", r"\bmkdirp\s*\("]),
                or_regex([r"fs\.mkdir\s*\([^)]*recursive\s*:\s*true"]))
    if d == "rimraf":
        return ("rimraf",
                or_regex([r"(?:from|require)\s*['\"]rimraf['\"]", r"\brimraf\s*\("]),
                or_regex([r"fs\.rm\s*\([^)]*recursive\s*:\s*true"]))
    if d == "moment":
        return ("moment",
                or_regex([r"(?:from|require)\s*['\"]moment['\"]", r"\bmoment\s*\("]),
                or_regex([r"Intl\.DateTimeFormat\s*\(", r"Temporal\."]))
    # genérico
    third = or_regex([
        rf"(?:from|require)\s*['\"]{re.escape(dep)}['\"]",
        rf"['\"]{re.escape(dep)}['\"]",
    ])
    native = or_regex([
        r"\.map\s*\(", r"\.filter\s*\(", r"\.reduce\s*\(",
        r"Object\.assign\s*\(", r"URLSearchParams\s*\(", r"(?<!\.)\bfetch\s*\(",
        r"\.padStart\s*\(", r"crypto\.randomUUID\s*\("
    ])
    return ("generic", third, native)

def native_migration_signal(repo_dir: str, before_sha: str, after_sha: str, dep: str) -> dict:
    ruleset, third_rx, native_rx = build_patterns_for_dep(dep)
    t_before = grep_count(repo_dir, before_sha, third_rx) if third_rx else 0
    t_after  = grep_count(repo_dir, after_sha, third_rx) if third_rx else 0
    n_before = grep_count(repo_dir, before_sha, native_rx) if native_rx else 0
    n_after  = grep_count(repo_dir, after_sha, native_rx) if native_rx else 0
    evidence = (t_before > 0 and t_after == 0 and n_after > n_before)
    return {
        "ruleset": ruleset,
        "third_party_hits_before": t_before,
        "third_party_hits_after": t_after,
        "native_hits_before": n_before,
        "native_hits_after": n_after,
        "native_replacement_evidence": bool(evidence),
        "native_migration_score": (n_after - n_before) - (t_before - t_after),
    }

# ---- Vulnerability helpers (OSV) ----

def vulnerable_count_for(dep_names, session, cache) -> int:
    cnt = 0
    for name in dep_names:
        try:
            vul_count, _ = get_cve_for_package(name, session=session, cache=cache)
            if vul_count and vul_count > 0:
                cnt += 1
        except Exception:
            pass
    return cnt

# ---- Worker (roda em subprocess) ----

def _worker_analyze(full_name: str,
                    limit_commits: int,
                    out_json_path: str,
                    clone_timeout: int,
                    max_commits_scan: int):
    """
    Faz clone e análise; chamada dentro do wrapper subprocess.
    Inclui contagens before/after de dependencies e vulnerable_dependencies e
    métricas inline por commit (LOC/complexidade).
    """
    tmp_root = tempfile.mkdtemp(prefix="mine_")
    repo_dir = os.path.join(tmp_root, full_name.split("/")[-1])
    results = []
    session = requests.Session()
    osv_cache = load_osv_cache()
    try:
        log(full_name, f"START clone")
        try:
            clone_repo_light(full_name, repo_dir, clone_timeout=clone_timeout)
        except Exception as e:
            log(full_name, f"CLONE_FAILED: {e}")
            return results
        log(full_name, f"CLONE_OK")

        commits = commits_touching_any_package_json(repo_dir, limit=None)
        total_commits = len(commits)
        log(full_name, f"COMMITS_TOUCHING_PACKAGE_JSON={total_commits}")

        if max_commits_scan and total_commits > max_commits_scan:
            commits = commits[:max_commits_scan]
            log(full_name, f"COMMITS_TRUNCATED_TO={len(commits)} (max_commits_scan={max_commits_scan})")

        if limit_commits and limit_commits > 0 and len(commits) > limit_commits:
            commits = commits[:limit_commits]
            log(full_name, f"COMMITS_LIMITED_TO={len(commits)} (limit_commits={limit_commits})")

        for sha, ts, subj in commits:
            parent = parent_of(repo_dir, sha)
            if not parent:
                continue

            before_pkgs, before_paths = load_all_pkg_at_commit(repo_dir, parent)
            after_pkgs, after_paths = load_all_pkg_at_commit(repo_dir, sha)
            if not before_pkgs:
                continue

            deps_b, dev_b, vers_b = aggregate_deps(before_pkgs)
            deps_a, dev_a, vers_a = aggregate_deps(after_pkgs)

            # Contagens before/after
            dep_names_before = set(deps_b.keys()) | set(dev_b.keys())
            dep_names_after  = set(deps_a.keys()) | set(dev_a.keys())
            dependencies_before = len(dep_names_before)
            dependencies_after  = len(dep_names_after)

            vulnerable_before = vulnerable_count_for(dep_names_before, session, osv_cache)
            vulnerable_after  = vulnerable_count_for(dep_names_after,  session, osv_cache)

            removed = [d for d in deps_b.keys() if d not in deps_a]
            if not removed:
                continue

            # MÉTRICAS INLINE POR COMMIT (sem checkout)
            metrics_before = compute_js_metrics_inline(repo_dir, parent)
            metrics_after  = compute_js_metrics_inline(repo_dir, sha)

            iso = run(f'{GIT} -C "{repo_dir}" show -s --format=%cI {sha}', check=False) or ""

            for dep in removed:
                nat = native_migration_signal(repo_dir, parent, sha, dep)
                candidate = {
                    "repo": full_name,
                    "commit": sha,
                    "parent": parent,
                    "commit_message": subj or "",
                    "commit_date": iso,
                    "removed_dep": dep,
                    "removed_dep_details": {
                        "versions_before": vers_b.get(dep, []),
                        "versions_after": vers_a.get(dep, []),
                        "cve_count": 0,
                        "cve_ids": [],
                    },
                    "metrics_before": metrics_before,
                    "metrics_after": metrics_after,
                    "native_migration": nat,
                    "pkg_before_paths": before_paths,
                    "pkg_after_paths": after_paths,
                    "dependencies_before": dependencies_before,
                    "dependencies_after": dependencies_after,
                    "vulnerable_dependencies_before": vulnerable_before,
                    "vulnerable_dependencies_after": vulnerable_after,
                }
                results.append(candidate)

        # salva resultado
        if out_json_path:
            os.makedirs(os.path.dirname(out_json_path) or ".", exist_ok=True)
            with open(out_json_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        return results
    finally:
        try:
            save_osv_cache(osv_cache)
        except Exception:
            pass
        shutil.rmtree(tmp_root, ignore_errors=True)

def analyze_repo(full_name: str,
                 limit_commits: int = None,
                 timeout_seconds: int = None,
                 clone_timeout: int = None,
                 max_commits_scan: int = None) -> list:
    if timeout_seconds is None:
        timeout_seconds = DEFAULT_REPO_TIMEOUT
    if clone_timeout is None:
        clone_timeout = DEFAULT_CLONE_TIMEOUT
    if max_commits_scan is None:
        max_commits_scan = DEFAULT_MAX_COMMITS_SCAN

    tmp_root = tempfile.mkdtemp(prefix="mine_supervisor_")
    out_json = os.path.join(tmp_root, "worker_out.json")

    success, payload = run_callable_in_subprocess(
        module_name="app.scripts.find_dependency_replacements",
        func_name="_worker_analyze",
        args=[full_name, limit_commits, out_json, clone_timeout, max_commits_scan],
        out_json_path=out_json,
        timeout_seconds=timeout_seconds
    )
    try:
        if not success:
            log(full_name, f"TIMEOUT_OR_ERROR: {payload}")
            return []
        if payload is None:
            try:
                return json.load(open(out_json, "r", encoding="utf-8"))
            except Exception:
                return []
        return payload
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--timeout", type=int, default=DEFAULT_REPO_TIMEOUT)
    ap.add_argument("--clone-timeout", type=int, default=DEFAULT_CLONE_TIMEOUT)
    ap.add_argument("--max-commits-scan", type=int, default=DEFAULT_MAX_COMMITS_SCAN)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    res = analyze_repo(args.repo,
                       limit_commits=args.limit,
                       timeout_seconds=args.timeout,
                       clone_timeout=args.clone_timeout,
                       max_commits_scan=args.max_commits_scan)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2, ensure_ascii=False)
    print(json.dumps(res[:2], indent=2, ensure_ascii=False))