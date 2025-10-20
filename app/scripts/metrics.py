import os
import tempfile
import zipfile
import requests
import json
from scripts.utils import run_command

def download_and_extract(repo, token):
    headers = {"Authorization": f"token {token}"}
    response = requests.get(repo["download_url"], headers=headers)
    response.raise_for_status()

    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, "repo.zip")

    with open(zip_path, "wb") as f:
        f.write(response.content)

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(temp_dir)
    return temp_dir

def get_metrics(repo, token):
    temp_dir = download_and_extract(repo, token)
    metrics = {"repo": repo["name"], "stars": repo["stars"], "forks": repo["forks"], "size_kb": repo["size_kb"]}

    # Linhas de código
    try:
        cloc_output = run_command("cloc . --json --quiet", cwd=temp_dir)
        cloc_data = json.loads(cloc_output)
        metrics["lines_of_code"] = cloc_data.get("JavaScript", {}).get("code", 0)
    except Exception:
        metrics["lines_of_code"] = 0

    # Complexidade (radon)
    try:
        radon_output = run_command("radon cc . -s -j", cwd=temp_dir)
        radon_data = json.loads(radon_output)
        complexities = [i["complexity"] for f in radon_data.values() for i in f]
        metrics["avg_complexity"] = sum(complexities) / len(complexities) if complexities else 0
    except Exception:
        metrics["avg_complexity"] = 0

    # Dependências
    pkg_path = os.path.join(temp_dir, "package.json")
    if os.path.exists(pkg_path):
        try:
            pkg = json.load(open(pkg_path, "r", encoding="utf-8"))
            metrics["dependencies"] = len(pkg.get("dependencies", {}))
        except:
            metrics["dependencies"] = 0
    else:
        metrics["dependencies"] = 0

    return metrics
