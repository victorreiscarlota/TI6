import os
import sys
import pandas as pd
from dotenv import load_dotenv

sys.path.append(os.path.join(os.path.dirname(__file__), "app"))

from scripts.github_api import get_top_js_repos
from scripts.metrics import get_metrics
from scripts.utils import save_json

load_dotenv()
TOKEN = os.getenv("GITHUB_TOKEN")

RESULTS_DIR = os.path.join("app", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)


def run_analysis():
    """Executa toda a análise de dependências e CVEs."""
    print("🔍 Buscando repositórios JavaScript mais populares...")
    repos = get_top_js_repos(limit=5)

    if not repos:
        print("❌ Nenhum repositório foi retornado pela API do GitHub.")
        return

    summary = []
    for repo in repos:
        print(f"\n📦 Analisando dependências e CVEs em: {repo['name']} ...")
        metrics = get_metrics(repo, TOKEN)
        summary.append(metrics)

    df = pd.DataFrame(summary)
    csv_path = os.path.join(RESULTS_DIR, "dependencies_cve_summary.csv")
    json_path = os.path.join(RESULTS_DIR, "dependencies_cve_summary.json")

    df.to_csv(csv_path, index=False)
    save_json(json_path, summary)

    print("\n✅ Análise concluída!")
    print(f"📁 CSV salvo em: {csv_path}")
    print(f"📁 JSON salvo em: {json_path}")

    try:
        import matplotlib.pyplot as plt

        if "dependencies" in df.columns and "vulnerable_deps" in df.columns:
            df.plot(
                x="repo",
                y=["dependencies", "vulnerable_deps"],
                kind="bar",
                figsize=(8, 4),
                title="Dependências e Vulnerabilidades (Top JS Repos)",
            )
            plt.tight_layout()
            chart_path = os.path.join(RESULTS_DIR, "chart_cve.png")
            plt.savefig(chart_path)
            print(f"📈 Gráfico salvo em {chart_path}")
        else:
            print("⚠️ Colunas esperadas não encontradas para gerar gráfico.")

    except Exception as e:
        print(f"⚠️ Erro ao gerar gráfico: {e}")


if __name__ == "__main__":
    print("🚀 Iniciando análise automática de repositórios JavaScript...")
    if not TOKEN:
        print("❌ Erro: variável GITHUB_TOKEN não encontrada. Adicione-a no .env.")
    else:
        run_analysis()