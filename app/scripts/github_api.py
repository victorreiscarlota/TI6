import requests
import os
from dotenv import load_dotenv

load_dotenv()
TOKEN = os.getenv("GITHUB_TOKEN")
HEADERS = {"Authorization": f"token {TOKEN}"}

def get_top_js_repos(limit=5):
    url = "https://api.github.com/search/repositories"
    params = {"q": "language:javascript", "sort": "stars", "order": "desc", "per_page": limit}
    r = requests.get(url, headers=HEADERS, params=params)
    r.raise_for_status()
    data = r.json()["items"]

    repos = []
    for repo in data:
        # pega o branch principal dinamicamente (main, master, etc)
        default_branch = repo.get("default_branch", "main")
        download_url = f"https://codeload.github.com/{repo['full_name']}/zip/refs/heads/{default_branch}"

        repos.append({
            "name": repo["full_name"],
            "url": repo["html_url"],
            "stars": repo["stargazers_count"],
            "forks": repo["forks_count"],
            "size_kb": repo["size"],
            "updated_at": repo["updated_at"],
            "download_url": download_url,
        })
    return repos
