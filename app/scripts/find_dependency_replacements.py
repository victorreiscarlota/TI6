#!/usr/bin/env python3
"""
Mining sem REST (só git local) + métrica de migração para nativo.

Alterações principais:
- Adicionada proteção por timeout para análise POR-REPO (via repo_watchdog.run_worker_with_timeout).
  Se a análise demorar mais que timeout_seconds, o repo será pulado e o pipeline segue.
- Mantido comportamento anterior (agregação de dependências, detecção de remoções e sinais de migração).
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
from typing import List, Dict, Tuple

from app.scripts import repo_watchdog  # novo helper
GIT = "git"
PYTHON = "python"

# default timeout por repositório (segundos). Ajuste conforme necessário.
DEFAULT_REPO_TIMEOUT = int(os.environ.get("REPO_TIMEOUT", 1800))  # 30min

def run(cmd, cwd=None, check=True, timeout=None):
    """
    Wrapper para subprocess.run com encoding utf-8 e errors='replace'
    para evitar UnicodeDecodeError em Windows.
    """
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

def clone_repo_light(full_name: str, target_dir: str, timeout=None):
    """
    Partial clone do repositório sem fazer checkout do working tree.
    Não usamos --depth aqui porque a mining precisa de histórico completo.
    O clone pode receber timeout (segundos).
    """
    os.makedirs(os.path.dirname(target_dir), exist_ok=True)
    run(f'{GIT} clone --filter=blob:none --no-checkout --quiet https://github.com/{full_name}.git "{target_dir}"', timeout=timeout)

def commits_touching_any_package_json(repo_dir: str, limit: int = None) -> List[Tuple[str,int,str]]:
    out = run(f'{GIT} -C "{repo_dir}" log --pretty=format:%H --no-renames --diff-filter=AMDR -- ":(glob)**/package.json"', check=False)
    shas = [l for l in (out.splitlines() if out else []) if l.strip()]
    if limit:
        shas = shas[:limit]
    result = []
    for sha in shas:
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

def list_package_json_paths_at_commit(repo_dir: str, sha: str) -> List[str]:
    out = run(f'{GIT} -C "{repo_dir}" ls-tree -r --name-only {sha}', check=False)
    return [l for l in (out.splitlines() if out else []) if l.lower().endswith("package.json")]

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
    versions = {k: sorted(list(vs)) for k,vs in versions.items()}
    return deps_agg, dev_agg, versions

def load_all_pkg_at_commit(repo_dir: str, sha: str):
    paths = list_package_json_paths_at_commit(repo_dir, sha)
    d = {}
    for p in paths:
        pj = load_package_json_at_commit(repo_dir, sha, p)
        if pj:
            d[p] = pj
    return d, paths

def compute_js_metrics_with_tool(repo_dir: str, sha: str, tmpdir: str) -> dict:
    script = os.path.join(os.path.dirname(__file__), "compute_js_metrics.py")
    out_json = os.path.join(tmpdir, f"metrics_{sha}.json")
    cmd = f'{PYTHON} "{script}" --repo "{repo_dir}" --commit "{sha}" --out "{out_json}"'
    run(cmd, cwd=repo_dir, check=False)
    try:
        import json as _json
        return _json.load(open(out_json, "r", encoding="utf-8"))
    except Exception:
        return {"lines_of_code": 0, "avg_complexity": 0.0}

def grep_count(repo_dir: str, sha: str, pattern: str) -> int:
    # git grep por commit/ref; captura ocorrências aproximadas
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

# ---------------- worker que roda a análise por repositório ----------------
def _analyze_repo_worker(full_name: str, limit_commits: int, out_json_path: str):
    """
    Worker que executa a análise e escreve JSON em out_json_path.
    Este código é essencialmente a versão antiga de analyze_repo, isolada para execução em processo filho.
    """
    tmp_root = tempfile.mkdtemp(prefix="mine_")
    repo_dir = os.path.join(tmp_root, full_name.split("/")[-1])
    results = []
    try:
        print(f"[clone] {full_name}")
        clone_repo_light(full_name, repo_dir)
        commits = commits_touching_any_package_json(repo_dir, limit=limit_commits)
        print(f"[{full_name}] commits touching package.json: {len(commits)}")

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
            removed = [d for d in deps_b.keys() if d not in deps_a]
            if not removed:
                continue

            tmp_metrics = os.path.join(tmp_root, "m")
            os.makedirs(tmp_metrics, exist_ok=True)
            metrics_before = compute_js_metrics_with_tool(repo_dir, parent, tmp_metrics)
            metrics_after  = compute_js_metrics_with_tool(repo_dir, sha, tmp_metrics)

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
                }
                results.append(candidate)
        # escreve resultado final em out_json_path
        if out_json_path:
            os.makedirs(os.path.dirname(out_json_path) or ".", exist_ok=True)
            with open(out_json_path, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
        return results
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

def analyze_repo(full_name: str, limit_commits: int = None, timeout_seconds: int = None) -> list:
    """
    Versão pública compatível. Internamente executa o worker em processo separado com timeout.
    Se timeout_seconds é None, usa DEFAULT_REPO_TIMEOUT.
    Retorna a lista de candidatos (pode ser vazia).
    """
    if timeout_seconds is None:
        timeout_seconds = DEFAULT_REPO_TIMEOUT

    tmp_root = tempfile.mkdtemp(prefix="mine_supervisor_")
    out_json = os.path.join(tmp_root, "worker_out.json")
    try:
        # CORREÇÃO: passamos out_json como terceiro argumento posicional para que
        # _analyze_repo_worker receba (full_name, limit_commits, out_json_path)
        success, payload = repo_watchdog.run_worker_with_timeout(_analyze_repo_worker,
                                                                args=(full_name, limit_commits, out_json),
                                                                out_json_path=out_json,
                                                                timeout_seconds=timeout_seconds)
        if not success:
            # log e retorna lista vazia para seguir em frente
            print(f"[timeout] Skipping {full_name} after {timeout_seconds} seconds: {payload}")
            return []
        # payload pode ser None se o worker escreveu no arquivo (run_worker_with_timeout retorna loaded data)
        if payload is None:
            try:
                with open(out_json, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                return []
        return payload
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

# Quando executado standalone para debug
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--out", default=None)
    ap.add_argument("--timeout", type=int, default=DEFAULT_REPO_TIMEOUT, help="timeout por repo em segundos")
    args = ap.parse_args()
    res = analyze_repo(args.repo, limit_commits=args.limit, timeout_seconds=args.timeout)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(res, f, indent=2, ensure_ascii=False)
    print(json.dumps(res[:2], indent=2, ensure_ascii=False))