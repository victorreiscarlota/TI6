import requests
import json
from scripts.github_api import fetch_package_json

COMMON_PATHS = [
    "",
    "packages/react",
    "packages/next",
    "packages/core",
    "apps",
    "examples",
    "src",
]


def try_fetch_any_package_json(repo_full_name):
    """Tenta buscar o package.json em vários caminhos e escolhe o mais completo."""
    best_pkg = None
    best_path = ""
    max_deps = 0

    for path in COMMON_PATHS:
        pkg = fetch_package_json(repo_full_name, subpath=path)
        if not pkg:
            continue

        deps = pkg.get("dependencies", {})
        total = len(deps)
        if total > max_deps:
            best_pkg = pkg
            best_path = path
            max_deps = total

    return best_pkg, best_path


def get_cve_for_package(package_name):
    """Busca vulnerabilidades (CVE) de um pacote NPM via API do OSV.dev."""
    url = "https://api.osv.dev/v1/query"
    payload = {"package": {"name": package_name, "ecosystem": "npm"}}
    try:
        response = requests.post(url, json=payload, timeout=10)
        if response.status_code == 200:
            vulns = response.json().get("vulns", [])
            return len(vulns), [v["id"] for v in vulns]
        return 0, []
    except Exception as e:
        print(f"⚠️ Erro ao consultar CVE de {package_name}: {e}")
        return 0, []


def get_metrics(repo, token):
    """Coleta métricas principais: dependências e vulnerabilidades."""
    metrics = {
        "repo": repo["name"],
        "stars": repo["stars"],
        "forks": repo["forks"],
        "dependencies": 0,
        "dev_dependencies": 0,
        "vulnerable_deps": 0,
        "cves": [],
        "path_usado": "",
    }

    pkg, used_path = try_fetch_any_package_json(repo["name"])
    if not pkg:
        print(f"⚠️ Nenhum package.json encontrado em {repo['name']}")
        return metrics

    deps = pkg.get("dependencies", {})
    dev_deps = pkg.get("devDependencies", {})

    metrics["dependencies"] = len(deps)
    metrics["dev_dependencies"] = len(dev_deps)
    metrics["path_usado"] = used_path or "root"

    total_vulns = 0
    cve_list = []

    for dep_name in deps.keys():
        count, ids = get_cve_for_package(dep_name)
        total_vulns += count
        cve_list.extend(ids)

    metrics["vulnerable_deps"] = total_vulns
    metrics["cves"] = cve_list

    return metrics
