import requests
import os
import json
import base64
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv("GITHUB_TOKEN")
HEADERS = {"Authorization": f"token {TOKEN}"} if TOKEN else {}

GITHUB_API = "https://api.github.com"


def get_top_js_repos(limit=100):
    """Busca os repositórios JavaScript mais populares do GitHub."""
    url = f"{GITHUB_API}/search/repositories"
    params = {"q": "language:javascript", "sort": "stars", "order": "desc", "per_page": limit}
    r = requests.get(url, headers=HEADERS, params=params)
    r.raise_for_status()
    data = r.json()["items"]

    repos = []
    for repo in data:
        repos.append({
            "name": repo["full_name"],
            "url": repo["html_url"],
            "stars": repo["stargazers_count"],
            "forks": repo["forks_count"],
            "size_kb": repo["size"],
            "updated_at": repo["updated_at"],
        })
    return repos


def fetch_package_json(repo_full_name, subpath=""):
    """Baixa o package.json de uma subpasta (ou raiz) via API do GitHub."""
    base_url = f"{GITHUB_API}/repos/{repo_full_name}/contents"
    url = f"{base_url}/{subpath}/package.json" if subpath else f"{base_url}/package.json"

    r = requests.get(url, headers=HEADERS)
    if r.status_code == 404:
        return None

    r.raise_for_status()
    data = r.json()

    if data.get("encoding") == "base64":
        decoded = base64.b64decode(data["content"]).decode("utf-8")
        try:
            return json.loads(decoded)
        except Exception as e:
            print(f"⚠️ Erro ao ler package.json em {repo_full_name}/{subpath}: {e}")
            return None
    return None
