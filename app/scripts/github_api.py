import requests
import os
import json
import base64
from urllib.parse import quote
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv("GITHUB_TOKEN")
HEADERS = {"Authorization": f"token {TOKEN}"} if TOKEN else {}

GITHUB_API = "https://api.github.com"

def get_top_js_repos(limit=100, token=None):
    """Busca os repositórios JavaScript mais populares do GitHub (usa token se presente)."""
    headers = {"Authorization": f"token {token}"} if token else HEADERS
    url = f"{GITHUB_API}/search/repositories"
    params = {"q": "language:javascript", "sort": "stars", "order": "desc", "per_page": min(limit,100)}
    r = requests.get(url, headers=headers, params=params, timeout=30)
    r.raise_for_status()
    data = r.json().get("items", [])
    repos = []
    for repo in data:
        repos.append({
            "repo": repo["full_name"],
            "name": repo["full_name"],
            "url": repo["html_url"],
            "stars": repo["stargazers_count"],
            "forks": repo["forks_count"],
            "size_kb": repo["size"],
            "updated_at": repo["updated_at"],
        })
    return repos

def fetch_package_json_at_ref(repo_full_name, ref="HEAD", path="package.json", token=None):
    """Baixa package.json de um repo no ref (branch/commit) usando contents API."""
    headers = {"Authorization": f"token {token}"} if token else HEADERS
    encoded_path = quote(path, safe="")
    url = f"{GITHUB_API}/repos/{repo_full_name}/contents/{encoded_path}"
    params = {"ref": ref}
    r = requests.get(url, headers=headers, params=params, timeout=20)
    if r.status_code == 404:
        return None
    # Some repos return directory listing for path that is a dir; handle gracefully
    r.raise_for_status()
    data = r.json()
    if isinstance(data, list):
        # path is a directory, not file
        return None
    if data.get("encoding") == "base64":
        decoded = base64.b64decode(data["content"]).decode("utf-8")
        try:
            return json.loads(decoded)
        except Exception:
            return None
    return None

def list_commits_touching_path(repo_full_name, path="package.json", token=None, per_page=100):
    """Lista commits que tocaram um determinado path (usa commits endpoint)."""
    headers = {"Authorization": f"token {token}"} if token else HEADERS
    url = f"{GITHUB_API}/repos/{repo_full_name}/commits"
    params = {"path": path, "per_page": per_page}
    r = requests.get(url, headers=headers, params=params, timeout=20)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    items = r.json()
    return items  # list of commit objects

def get_file_at_commit_raw(repo_full_name, filepath, commit_sha, token=None):
    """Pega conteúdo bruto de um arquivo em um commit (via contents endpoint with ref=sha)."""
    return fetch_package_json_at_ref(repo_full_name, ref=commit_sha, path=filepath, token=token)

def _get_tree_sha_for_ref(repo_full_name, ref, token=None):
    """
    Retorna tree sha para um ref. Tenta:
     - chamar GET /repos/:owner/:repo/commits/:ref para obter commit -> tree.sha
     - se falhar, tenta usar ref diretamente
    """
    headers = {"Authorization": f"token {token}"} if token else HEADERS
    # Try commits endpoint first (works for branch names and commit shas)
    url = f"{GITHUB_API}/repos/{repo_full_name}/commits/{ref}"
    r = requests.get(url, headers=headers, timeout=20)
    if r.status_code == 200:
        data = r.json()
        tree = data.get("commit", {}).get("tree", {}) or {}
        sha = tree.get("sha")
        if sha:
            return sha
    # fallback: return ref (may be a tree sha already)
    return ref

def list_files_at_ref(repo_full_name, ref="HEAD", token=None):
    """
    Lista (recursivamente) arquivos no repo para o ref fornecido usando git/trees API.
    Retorna list of paths (strings). Se houver erro, retorna [].
    """
    headers = {"Authorization": f"token {token}"} if token else HEADERS
    tree_sha = _get_tree_sha_for_ref(repo_full_name, ref, token=token)
    url = f"{GITHUB_API}/repos/{repo_full_name}/git/trees/{tree_sha}"
    params = {"recursive": "1"}
    try:
        r = requests.get(url, headers=headers, params=params, timeout=30)
        if r.status_code == 200:
            data = r.json()
            tree = data.get("tree", []) or []
            paths = [item.get("path") for item in tree if item.get("type") == "blob"]
            return paths
        else:
            # fallback to contents API listing root (non-recursive)
            r2 = requests.get(f"{GITHUB_API}/repos/{repo_full_name}/contents", headers=headers, params={"ref": ref}, timeout=20)
            if r2.status_code == 200:
                data = r2.json()
                if isinstance(data, list):
                    return [item.get("path") for item in data if item.get("type") == "file"]
    except Exception:
        pass
    return []

def find_package_json_paths(repo_full_name, ref="HEAD", token=None):
    """
    Retorna lista de caminhos relativos para todos os package.json presentes em um ref.
    Exemplos: ['package.json', 'packages/core/package.json', 'apps/web/package.json']
    """
    paths = list_files_at_ref(repo_full_name, ref=ref, token=token)
    pkg_paths = [p for p in paths if p.lower().endswith("package.json")]
    # Prefer root first
    pkg_paths_sorted = sorted(pkg_paths, key=lambda p: (0 if p == "package.json" else 1, p))
    return pkg_paths_sorted