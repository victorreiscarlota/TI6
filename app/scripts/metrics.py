import os
import tempfile
import zipfile
import requests
import json
from utils import run_command
from pygount import analysis
from pathlib import Path

def download_and_extract(repo, token):
    """Baixa o repositório em ZIP e retorna o caminho da pasta extraída."""
    headers = {"Authorization": f"token {token}"}
    response = requests.get(repo["download_url"], headers=headers)
    response.raise_for_status()

    temp_dir = tempfile.mkdtemp()
    zip_path = os.path.join(temp_dir, "repo.zip")
    with open(zip_path, "wb") as f:
        f.write(response.content)

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(temp_dir)

    extracted_folders = [
        os.path.join(temp_dir, i)
        for i in os.listdir(temp_dir)
        if os.path.isdir(os.path.join(temp_dir, i))
    ]

    return extracted_folders[0] if extracted_folders else temp_dir


def count_loc_fallback(repo_path):
    """Conta linhas manualmente em arquivos .js (fallback)."""
    count = 0
    for root, _, files in os.walk(repo_path):
        for f in files:
            if f.endswith(".js"):
                try:
                    with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as file:
                        count += sum(1 for _ in file)
                except Exception:
                    pass
    return count


def find_package_json_files(root_dir):
    """Busca todos os package.json no repositório."""
    matches = []
    for root, _, files in os.walk(root_dir):
        for f in files:
            if f == "package.json":
                matches.append(os.path.join(root, f))
    return matches

def count_js_loc(repo_path: str) -> int:
    total_loc = 0
    repo_dir = Path(repo_path)

    for file_path in repo_dir.rglob("*.js"):
        if not file_path.is_file():
            # pula entradas que são diretórios (mesmo que terminem com .js)
            continue

        try:
            result = analysis.SourceAnalysis.from_file(
                str(file_path),
                group=repo_dir.name,
                encoding="utf-8"
            )
            total_loc += result.code_count
        except UnicodeDecodeError:
            print(f"⚠️ Arquivo com encoding inválido: {file_path}")
        except Exception as e:
            print(f"⚠️ Erro ao analisar {file_path}: {e}")

    return total_loc

def get_metrics(repo, token):
    """Calcula métricas do repositório (LOC, complexidade, dependências)."""
    repo_path = download_and_extract(repo, token)
    metrics = {
        "repo": repo["name"],
        "stars": repo["stars"],
        "forks": repo["forks"],
        "size_kb": repo["size_kb"],
    }

    # 1️⃣ Linhas de código (pygount com fallback)
    try:
        total_loc = count_js_loc(repo_path)
        metrics["lines_of_code"] = total_loc
    except Exception as e:
        metrics["lines_of_code"] = count_loc_fallback(repo_path)
        print(f"⚠️ Erro ao calcular LOC (pygount) em {repo['name']}: {e}")

    # 2️⃣ Complexidade ciclomática (radon)
    try:
        radon_output = run_command("python -m radon cc . -s -j", cwd=repo_path)
        if not radon_output.strip():
            raise ValueError("radon output vazio")
        radon_data = json.loads(radon_output)
        complexities = [i["complexity"] for f in radon_data.values() for i in f]
        metrics["avg_complexity"] = sum(complexities) / len(complexities) if complexities else 0
    except Exception as e:
        metrics["avg_complexity"] = 0
        print(f"⚠️ radon falhou em {repo['name']}: {e}")

    # 3️⃣ Dependências (procura todos os package.json)
    try:
        pkg_files = find_package_json_files(repo_path)
        total_deps = 0
        for pkg_path in pkg_files:
            try:
                with open(pkg_path, "r", encoding="utf-8") as f:
                    pkg = json.load(f)
                    total_deps += len(pkg.get("dependencies", {}))
            except Exception:
                pass
        metrics["dependencies"] = total_deps
    except Exception as e:
        metrics["dependencies"] = 0
        print(f"⚠️ Erro ao ler dependências em {repo['name']}: {e}")

    return metrics