import os
import tempfile
import zipfile
import requests
import json
from utils import run_command
from pygount import analysis
from pathlib import Path
import lizard  # ✅ nova dependência

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
    """Conta linhas de código em arquivos JS com pygount."""
    total_loc = 0
    repo_dir = Path(repo_path)

    for file_path in repo_dir.rglob("*.js"):
        if not file_path.is_file():
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


def calc_js_complexity(repo_path: str, extensions=None) -> float:
    """
    Calcula a complexidade média do código JS usando lizard.
    - repo_path: caminho para a pasta do repo.
    - extensions: lista opcional de sufixos de arquivo (ex: ['.js', '.jsx', '.ts', '.tsx'])
    """
    if extensions is None:
        extensions = [".js", ".jsx", ".ts", ".tsx"]

    repo_dir = Path(repo_path)
    complexities = []

    for ext in extensions:
        for file_path in repo_dir.rglob(f"*{ext}"):
            # print(f"   🔍 Analisando complexidade em {file_path}...")
            
            # pular entradas que não são arquivos (por ex.: pastas com nome terminado em .js)
            if not file_path.is_file():
                continue

            # pular arquivos muito grandes (opcional), por exemplo > 5MB
            try:
                if file_path.stat().st_size > 1_000_000:
                    continue
            except Exception:
                pass

            try:
                # lizard.analyze_file analisa um único arquivo e retorna um FileInfo-like object
                file_info = lizard.analyze_file(str(file_path))
                for func in getattr(file_info, "function_list", []):
                    # cyclomatic_complexity é o campo padrão
                    cc = getattr(func, "cyclomatic_complexity", None)
                    if cc is not None:
                        complexities.append(cc)
            except Exception as e:
                # só log pra debug; não interrompe o processamento do repo
                print(f"   ⚠️ Lizard falhou em {file_path}: {e}")

    return sum(complexities) / len(complexities) if complexities else 0.0


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

    # 2️⃣ Complexidade ciclomática (lizard)
    try:
        avg_complexity = calc_js_complexity(repo_path)
        metrics["avg_complexity"] = avg_complexity
        print(f"   🧮 Complexidade média em {repo['name']}: {avg_complexity:.2f}")
    except Exception as e:
        metrics["avg_complexity"] = 0
        print(f"⚠️ Lizard falhou em {repo['name']}: {e}")

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
