import requests
import json
from scripts.github_api import fetch_package_json


def get_cve_for_package(package_name):
    """
    Busca vulnerabilidades (CVE) de um pacote NPM via API do OSV (Google).
    Documentação: https://osv.dev/docs/
    """
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
    """
    Coleta métricas principais: dependências e vulnerabilidades.
    Não baixa o repositório completo — apenas o package.json.
    """
    metrics = {
        "repo": repo["name"],
        "stars": repo["stars"],
        "forks": repo["forks"],
        "dependencies": 0,
        "dev_dependencies": 0,
        "vulnerable_deps": 0,
        "cves": [],
    }

    pkg = fetch_package_json(repo["name"])
    if not pkg:
        return metrics

    deps = pkg.get("dependencies", {})
    dev_deps = pkg.get("devDependencies", {})
    metrics["dependencies"] = len(deps)
    metrics["dev_dependencies"] = len(dev_deps)

    # 🔍 Verifica vulnerabilidades de cada dependência
    total_vulns = 0
    cve_list = []
    for dep in deps.keys():
        count, ids = get_cve_for_package(dep)
        total_vulns += count
        cve_list.extend(ids)

    metrics["vulnerable_deps"] = total_vulns
    metrics["cves"] = cve_list

    return metrics
