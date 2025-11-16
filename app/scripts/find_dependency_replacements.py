#!/usr/bin/env python3
"""
Mineração de commits (API + shallow clone para métricas), adaptada para monorepos:
- agora detecta package.jsons em subpastas e compara agregação de dependências antes/after.
- retorna candidatos com versões_before(list) e versions_after(list) e CVE info.
"""
import argparse
import json
import os
import shutil
import subprocess
import tempfile
from app.scripts.github_api import list_commits_touching_path, find_package_json_paths, fetch_package_json_at_ref
from app.scripts.metrics import get_cve_for_package, load_osv_cache, save_osv_cache
from dotenv import load_dotenv
import requests
load_dotenv()

GIT = "git"
PYTHON = "python"

def run(cmd, cwd=None, check=True):
    result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    if check and result.returncode != 0:
        raise RuntimeError(f"Command failed: {cmd}\nstdout:{result.stdout}\nstderr:{result.stderr}")
    return result.stdout.strip()

def shallow_clone_single_commit(repo_full_name, target_dir, commit_sha):
    os.makedirs(target_dir, exist_ok=True)
    run(f"{GIT} init", cwd=target_dir)
    run(f"{GIT} remote add origin https://github.com/{repo_full_name}.git", cwd=target_dir)
    run(f"{GIT} fetch --depth 1 origin {commit_sha}", cwd=target_dir, check=False)
    run(f"{GIT} checkout FETCH_HEAD", cwd=target_dir, check=False)
    return target_dir

def _load_all_package_jsons(repo_full_name, ref, token=None):
    """
    Retorna dict mapping path -> package_json dict para todos package.json em ref.
    """
    pkg_paths = find_package_json_paths(repo_full_name, ref=ref, token=token)
    result = {}
    for p in pkg_paths:
        pj = fetch_package_json_at_ref(repo_full_name, ref=ref, path=p, token=token)
        if pj:
            result[p] = pj
    return result

def _aggregate_deps_from_pkg_dict(pkg_dict):
    """
    Dado {path: pkg_json}, retorna two dicts: deps_agg, dev_deps_agg and mapping dep->list_of_versions
    """
    deps_agg = {}
    dev_deps_agg = {}
    versions_map = {}  # dep -> set of versions found
    for path,pkg in pkg_dict.items():
        deps = pkg.get("dependencies", {}) or {}
        dev = pkg.get("devDependencies", {}) or {}
        for k,v in deps.items():
            if k not in deps_agg:
                deps_agg[k] = v
            versions_map.setdefault(k,set()).add(v)
        for k,v in dev.items():
            if k not in dev_deps_agg:
                dev_deps_agg[k] = v
            versions_map.setdefault(k,set()).add(v)
    # convert versions sets to sorted lists
    versions_map = {k: sorted(list(vs)) for k,vs in versions_map.items()}
    return deps_agg, dev_deps_agg, versions_map

def detect_removed_dependencies_in_commit(repo_full_name, commit_obj, token=None):
    """
    Compara a agregação de dependências entre parent_sha e sha.
    Retorna:
      removed_info (list of dicts: name, versions_before(list), versions_after(list)),
      parent_sha, sha, commit_message, commit_date, pkg_before (paths), pkg_after (paths)
    """
    sha = commit_obj.get("sha")
    commit_info = commit_obj.get("commit", {}) or {}
    commit_message = commit_info.get("message", "")
    author_info = commit_info.get("author", {}) or {}
    commit_date = author_info.get("date", "")

    parents = commit_obj.get("parents", [])
    if not parents:
        return [], None, None, commit_message, commit_date, [], []

    parent_sha = parents[0].get("sha")

    pkg_before_map = _load_all_package_jsons(repo_full_name, parent_sha, token=token)
    pkg_after_map = _load_all_package_jsons(repo_full_name, sha, token=token)

    if not pkg_before_map and not pkg_after_map:
        return [], parent_sha, sha, commit_message, commit_date, list(pkg_before_map.keys()), list(pkg_after_map.keys())

    deps_before, dev_before, versions_before = _aggregate_deps_from_pkg_dict(pkg_before_map)
    deps_after, dev_after, versions_after = _aggregate_deps_from_pkg_dict(pkg_after_map)

    # any dependency present in before and not present in after (in any package.json)
    removed = []
    for dep in deps_before.keys():
        if dep not in deps_after:
            removed.append({
                "name": dep,
                "versions_before": versions_before.get(dep, []),
                "versions_after": versions_after.get(dep, []),
            })

    return removed, parent_sha, sha, commit_message, commit_date, list(pkg_before_map.keys()), list(pkg_after_map.keys())

def compute_metrics_with_local_tool(repo_dir, commit, out_json):
    script = os.path.join(os.path.dirname(__file__), "compute_js_metrics.py")
    cmd = f'{PYTHON} "{script}" --repo "{repo_dir}" --commit "{commit}" --out "{out_json}"'
    run(cmd, cwd=repo_dir, check=False)
    try:
        with open(out_json, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"lines_of_code": 0, "avg_complexity": 0.0}

def analyze_repo(full_name, token=None, limit_commits=None, include_pkg_snapshots=False, write_per_repo_file=None):
    commits = list_commits_touching_path(full_name, path="package.json", token=token)
    if limit_commits:
        commits = commits[:limit_commits]
    results = []
    tmpdir = tempfile.mkdtemp(prefix="repo_")

    session = requests.Session()
    cache = load_osv_cache() or {}

    try:
        for c in commits:
            removed_list, parent_sha, sha, commit_message, commit_date, pkg_before_paths, pkg_after_paths = detect_removed_dependencies_in_commit(full_name, c, token=token)
            if not removed_list:
                continue

            try:
                checkout_dir = os.path.join(tmpdir, sha)
                shallow_clone_single_commit(full_name, checkout_dir, sha)

                out_before = os.path.join(tmpdir, f"metrics_{parent_sha}.json")
                out_after = os.path.join(tmpdir, f"metrics_{sha}.json")
                before_metrics = compute_metrics_with_local_tool(checkout_dir, parent_sha, out_before)
                after_metrics = compute_metrics_with_local_tool(checkout_dir, sha, out_after)

                for r in removed_list:
                    dep_name = r.get("name")
                    try:
                        cve_count, cve_ids = get_cve_for_package(dep_name, session=session, cache=cache)
                    except Exception:
                        cve_count, cve_ids = 0, []

                    candidate = {
                        "repo": full_name,
                        "commit": sha,
                        "parent": parent_sha,
                        "commit_message": commit_message,
                        "commit_date": commit_date,
                        "removed_dep": dep_name,
                        "removed_dep_details": {
                            "versions_before": r.get("versions_before", []),
                            "versions_after": r.get("versions_after", []),
                            "cve_count": cve_count,
                            "cve_ids": cve_ids,
                        },
                        "metrics_before": before_metrics,
                        "metrics_after": after_metrics,
                        "pkg_before_paths": pkg_before_paths,
                        "pkg_after_paths": pkg_after_paths,
                    }
                    if include_pkg_snapshots:
                        # if requested, also include the package.json content snapshots
                        pkg_before_map = _load_all_package_jsons(full_name, parent_sha, token=token)
                        pkg_after_map = _load_all_package_jsons(full_name, sha, token=token)
                        candidate["pkg_before"] = pkg_before_map
                        candidate["pkg_after"] = pkg_after_map

                    results.append(candidate)

            except Exception as e:
                print(f"Erro processando commit {c.get('sha')}: {e}")
                continue

        save_osv_cache(cache)

        # optional per-repo file
        if write_per_repo_file:
            os.makedirs(os.path.dirname(write_per_repo_file), exist_ok=True)
            with open(write_per_repo_file, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)

        return results

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--out", default=None, help="se fornecido, grava JSON por-repo")
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--include_pkg_snapshots", action="store_true")
    args = parser.parse_args()
    res = analyze_repo(args.repo, token=os.getenv("GITHUB_TOKEN"), limit_commits=args.limit, include_pkg_snapshots=args.include_pkg_snapshots, write_per_repo_file=args.out)
    print(json.dumps(res, indent=2, ensure_ascii=False))