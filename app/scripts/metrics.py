#!/usr/bin/env python3
"""
Métricas de dependências via git local + consulta OSV.

Pequenas melhorias: _run agora aceita timeout opcional para subprocess.run.
"""
import requests
import json
import os
import shutil
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
import subprocess

load_dotenv()

OSV_URL = "https://api.osv.dev/v1/query"
OSV_CACHE = os.path.join("app", "results", "osv_cache.json")

def load_osv_cache():
    try:
        with open(OSV_CACHE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_osv_cache(cache):
    os.makedirs(os.path.dirname(OSV_CACHE), exist_ok=True)
    with open(OSV_CACHE, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=2, ensure_ascii=False)

def get_cve_for_package(package_name, session=None, cache=None):
    """Busca vulnerabilidades no OSV.dev para pacote npm; usa cache."""
    if cache is None:
        cache = {}
    if package_name in cache:
        return cache[package_name]
    payload = {"package": {"name": package_name, "ecosystem": "npm"}}
    s = session or requests
    try:
        r = s.post(OSV_URL, json=payload, timeout=15)
        if r.status_code == 200:
            vulns = r.json().get("vulns", [])
            result = (len(vulns), [v.get("id") for v in vulns])
            cache[package_name] = result
            return result
    except Exception:
        pass
    cache[package_name] = (0, [])
    return (0, [])

# ==== Git helpers (sem usar API do GitHub) ====

GIT = "git"

def _run(cmd, cwd=None, check=True, timeout=None):
    """
    Wrapper robusto para subprocess.run que força UTF-8 e substitui bytes inválidos.
    Permite timeout (segundos) opcional.
    Retorna stdout.strip().
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

def _clone_light(full_name: str, target_dir: str, timeout=None):
    """
    Partial clone sem checkout para reduzir uso de disco (HEAD only).
    Usa --filter=blob:none, --no-checkout e --depth 1 para economizar espaço.
    timeout (segundos) é repassado para o subprocesso git clone.
    """
    os.makedirs(os.path.dirname(target_dir), exist_ok=True)
    _run(f'{GIT} clone --filter=blob:none --no-checkout --depth 1 --quiet https://github.com/{full_name}.git "{target_dir}"', timeout=timeout)

def _list_package_json_paths(repo_dir: str, ref: str = "HEAD"):
    out = _run(f'{GIT} -C "{repo_dir}" ls-tree -r --name-only {ref}', check=False)
    return [l for l in (out.splitlines() if out else []) if l.lower().endswith("package.json")]

def _load_package_json(repo_dir: str, ref: str, path: str):
    try:
        txt = _run(f'{GIT} -C "{repo_dir}" show {ref}:{path}', check=False)
        if not txt:
            return None
        return json.loads(txt)
    except Exception:
        return None

def _aggregate_deps(pkg_jsons):
    """
    pkg_jsons: list of (path, pkg_dict)
    Retorna deps_agg, dev_deps_agg e lista de paths.
    """
    deps_agg, dev_agg = {}, {}
    paths = []
    for p, pkg in pkg_jsons:
        paths.append(p)
        deps = (pkg.get("dependencies") or {})
        dev = (pkg.get("devDependencies") or {})
        for k, v in deps.items():
            if k not in deps_agg:
                deps_agg[k] = v
        for k, v in dev.items():
            if k not in dev_agg:
                dev_agg[k] = v
    return deps_agg, dev_agg, paths

def compute_dep_metrics_via_git(full_name: str, clone_timeout=None) -> dict:
    """
    Clona o repo (leve), agrega dependências de todos package.json em HEAD e consulta CVEs via OSV.
    O clone é temporário e removido ao final (shutil.rmtree).
    clone_timeout (segundos) é repassado para o git clone.
    """
    tmp = tempfile.mkdtemp(prefix="deps_")
    repo_dir = os.path.join(tmp, full_name.split("/")[-1])
    try:
        _clone_light(full_name, repo_dir, timeout=clone_timeout)
        paths = _list_package_json_paths(repo_dir, "HEAD")
        pkg_jsons = []
        for p in paths:
            pj = _load_package_json(repo_dir, "HEAD", p)
            if pj:
                pkg_jsons.append((p, pj))

        deps_agg, dev_agg, path_list = _aggregate_deps(pkg_jsons)
        # CVEs
        cache = load_osv_cache()
        session = requests.Session()
        total_vulns = 0
        cve_ids = []
        for dep in deps_agg.keys():
            count, ids = get_cve_for_package(dep, session=session, cache=cache)
            total_vulns += count
            if ids:
                cve_ids.extend(ids)
        save_osv_cache(cache)

        return {
            "repo": full_name,
            "dependencies": len(deps_agg),
            "dev_dependencies": len(dev_agg),
            "vulnerable_deps": total_vulns,
            "cves": sorted(list(set(cve_ids))),
            "path_used": ",".join(path_list),
        }
    finally:
        # limpar temporário (silencioso)
        shutil.rmtree(tmp, ignore_errors=True)

def get_metrics_batch(repos, workers=4, clone_timeout=None):
    """
    Calcula métricas de dependências para uma lista de repos usando git local (sem API GitHub).
    Cada item em repos deve ter 'repo' e opcional 'stars'/'forks'.
    clone_timeout é repassado para clones.
    """
    results = []
    def process(repo_item):
        full = repo_item.get("repo") or repo_item.get("name")
        m = compute_dep_metrics_via_git(full, clone_timeout=clone_timeout)
        # propaga metadados
        m["stars"] = repo_item.get("stars") or repo_item.get("stargazers_count", 0)
        m["forks"] = repo_item.get("forks") or repo_item.get("forks_count", 0)
        return m

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(process, r): r for r in repos}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                # loga e continua
                print("Erro get_metrics_batch:", e)
    return results