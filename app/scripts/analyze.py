import os
import pandas as pd
from dotenv import load_dotenv
from github_api import get_top_js_repos
from metrics import get_metrics
from utils import save_json

load_dotenv()
TOKEN = os.getenv("GITHUB_TOKEN")

RESULTS_DIR = "./results"
os.makedirs(RESULTS_DIR, exist_ok=True)

def main():
    print("🔍 Buscando repositórios JavaScript mais populares...")
    repos = get_top_js_repos(limit=5)
    summary = []

    for repo in repos:
        print(f"📊 Analisando: {repo['name']} ...")
        metrics = get_metrics(repo, TOKEN)
        summary.append(metrics)

    df = pd.DataFrame(summary)
    df.to_csv(f"{RESULTS_DIR}/summary.csv", index=False)
    save_json(f"{RESULTS_DIR}/summary.json", summary)

    print("✅ Análise concluída! Resultados salvos em ./results/summary.csv")

    # Gráfico opcional
    try:
        import matplotlib.pyplot as plt
        df.plot(x="repo", y=["lines_of_code", "avg_complexity"], kind="bar")
        plt.title("Linhas de Código e Complexidade Média (Top JS Repos)")
        plt.tight_layout()
        plt.savefig(f"{RESULTS_DIR}/chart.png")
        print("📈 Gráfico salvo em ./results/chart.png")
    except Exception as e:
        print(f"⚠️ Erro ao gerar gráfico: {e}")

if __name__ == "__main__":
    main()
