#!/usr/bin/env python3
"""
Orquestrador principal do pipeline.

Stages suportados:
- deps: coleta métricas de dependências (usa app.scripts.metrics.get_metrics_batch)
- mining: executa mining por repositório (usa app.scripts.find_dependency_replacements.analyze_repo)
- plots: gera plots a partir do dataset final (app.scripts.plots.generate_all_plots_from_dataset)
- all: executa deps -> mining -> plots

Observações:
- A etapa "deps" espera um arquivo de entrada com lista de repositórios em formato JSON (lista de objetos com chave "repo").
  Use --repos-file para apontar para esse JSON. Se não informado, tentará carregar "app/data/repos.json".
- Timeout por repositório (em segundos) é aplicado durante a análise mining. Padrão: 1800s (30 minutos).
- clone_timeout (em segundos) é repassado para git clone na etapa deps.
"""
import argparse
import json
import os
import sys
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

# imports dos scripts internos
from app.scripts import metrics as metrics_mod
from app.scripts import find_dependency_replacements as mining_mod
from app.scripts import plots as plots_mod

def load_repos_from_file(path: str, limit: int = None) -> List[Dict]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # espera lista de objetos; permissivo: aceitar lista de strings "owner/repo"
    out = []
    for item in data:
        if isinstance(item, str):
            out.append({"repo": item})
        elif isinstance(item, dict):
            # deve conter "repo" ou "name"
            if item.get("repo"):
                out.append(item)
            elif item.get("name"):
                out.append({"repo": item.get("name"), **{k:v for k,v in item.items() if k!="name"}})
    if limit:
        return out[:limit]
    return out

def save_json(path: str, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def run_deps_stage(args):
    # Repositórios de entrada
    repos = []
    if args.repos_file and os.path.exists(args.repos_file):
        repos = load_repos_from_file(args.repos_file, limit=args.limit)
    else:
        # tenta carregar app/data/repos.json como fallback
        alt = os.path.join("app", "data", "repos.json")
        if os.path.exists(alt):
            repos = load_repos_from_file(alt, limit=args.limit)
        else:
            print("Nenhum arquivo de repos fornecido (--repos-file) e app/data/repos.json não existe.")
            print("Crie um JSON com lista de repositórios (ex: [\"owner/repo\", ...]) e passe via --repos-file")
            return []

    print(f"[deps] Running dependency metrics for {len(repos)} repos with workers={args.workers} clone_timeout={args.clone_timeout}")
    results = metrics_mod.get_metrics_batch(repos, workers=args.workers, clone_timeout=args.clone_timeout)
    save_json(args.deps_out, results)
    print(f"[deps] Saved deps dataset: {args.deps_out} (repos: {len(results)})")
    return results

def run_mining_stage(args):
    # espera o arquivo deps_out para saber quais repos processar
    if not os.path.exists(args.deps_out):
        print(f"[mining] deps file not found: {args.deps_out}. Rode a stage deps primeiro.")
        return []

    deps = load_repos_from_file(args.deps_out, limit=None)
    # from the deps dataset produced by metrics.get_metrics_batch we may have list of dicts where repo key is 'repo'
    if not deps:
        # tentar carregar como lista de objects produzidos pelo metrics (cada entry tem 'repo' key)
        with open(args.deps_out, "r", encoding="utf-8") as f:
            try:
                raw = json.load(f)
                deps = [{"repo": item.get("repo")} for item in raw if isinstance(item, dict) and item.get("repo")]
            except Exception:
                deps = []

    if args.mining_sample and args.mining_sample > 0:
        deps = deps[:args.mining_sample]

    # aplicar limite global se passado
    if args.limit:
        deps = deps[:args.limit]

    repos = [d.get("repo") for d in deps if d.get("repo")]
    print(f"[mining] Will analyze {len(repos)} repos with mining_workers={args.mining_workers} and per-repo timeout={args.repo_timeout}s")

    all_candidates = []
    # sequential or threaded - each analyze_repo already imposes per-repo timeout internally
    def worker(repo_full):
        try:
            candidates = mining_mod.analyze_repo(repo_full, limit_commits=args.limit_commits, timeout_seconds=args.repo_timeout)
            print(f"[mining] Done mining {repo_full} -> {len(candidates)} candidates")
            return candidates
        except Exception as e:
            print(f"[mining] Error analyzing {repo_full}: {e}")
            return []

    with ThreadPoolExecutor(max_workers=args.mining_workers) as ex:
        futs = {ex.submit(worker, r): r for r in repos}
        for fut in as_completed(futs):
            try:
                res = fut.result()
                if res:
                    all_candidates.extend(res)
            except Exception as e:
                print("Error in mining thread:", e)

    # salvar JSON e CSV
    save_json(args.mining_json_out, all_candidates)
    print(f"[mining] Saved mining JSON: {args.mining_json_out} (candidates: {len(all_candidates)})")

    # CSV: seleção simples de colunas para inspeção
    csv_path = args.mining_csv_out
    os.makedirs(os.path.dirname(csv_path) or ".", exist_ok=True)
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        header = [
            "repo", "commit", "parent", "commit_date", "removed_dep", "commit_message",
            "native_replacement_evidence", "native_migration_score",
            "lines_of_code_before", "lines_of_code_after", "avg_complexity_before", "avg_complexity_after"
        ]
        writer.writerow(header)
        for c in all_candidates:
            mb = c.get("metrics_before") or {}
            ma = c.get("metrics_after") or {}
            nat = c.get("native_migration") or {}
            row = [
                c.get("repo"),
                c.get("commit"),
                c.get("parent"),
                c.get("commit_date"),
                c.get("removed_dep"),
                (c.get("commit_message") or "").replace("\n", " "),
                nat.get("native_replacement_evidence"),
                nat.get("native_migration_score"),
                mb.get("lines_of_code") or mb.get("lines_of_code_before") or "",
                ma.get("lines_of_code") or ma.get("lines_of_code_after") or "",
                mb.get("avg_complexity") or mb.get("avg_complexity_before") or "",
                ma.get("avg_complexity") or ma.get("avg_complexity_after") or "",
            ]
            writer.writerow(row)
    print(f"[mining] Saved mining CSV: {csv_path}")
    return all_candidates

def run_plots_stage(args):
    # escolher dataset: final_out if exists else mining_json_out
    dataset = args.final_out if args.final_out and os.path.exists(args.final_out) else args.mining_json_out
    if not os.path.exists(dataset):
        print(f"[plots] Dataset not found: {dataset}. Run mining stage first.")
        return
    plots_mod.generate_all_plots_from_dataset(dataset, out_dir=args.plots)
    print(f"[plots] Plots generated to {args.plots}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["deps","mining","plots","all"], default="all")
    ap.add_argument("--limit", type=int, default=None, help="limit number of repos (for deps/mining)")
    ap.add_argument("--limit-commits", dest="limit_commits", type=int, default=None, help="limit commits per repo when mining")
    ap.add_argument("--workers", type=int, default=4, help="workers for deps stage")
    ap.add_argument("--mining_workers", type=int, default=1, help="workers (threads) for mining stage")
    ap.add_argument("--mining_sample", type=int, default=0, help="sample size for mining (0 means all from deps)")
    ap.add_argument("--repos-file", type=str, default=None, help="JSON file with list of repos to analyze (for deps)")
    ap.add_argument("--deps-out", default="app/results/dependencies_cve_summary.json")
    ap.add_argument("--mining-json-out", dest="mining_json_out", default="app/results/commit_changes_all.json")
    ap.add_argument("--mining-csv-out", dest="mining_csv_out", default="app/results/commit_changes_all.csv")
    ap.add_argument("--plots", default="app/results/plots")
    ap.add_argument("--final-out", dest="final_out", default="app/results/final_dataset.json")
    ap.add_argument("--repo-timeout", dest="repo_timeout", type=int, default=int(os.environ.get("REPO_TIMEOUT", 1800)), help="timeout per repo (seconds) for mining")
    ap.add_argument("--clone-timeout", dest="clone_timeout", type=int, default=int(os.environ.get("CLONE_TIMEOUT", 600)), help="timeout for git clone during deps stage (seconds)")
    args = ap.parse_args()

    # map args to functions
    if args.stage in ("deps", "all"):
        # prepare list of repos
        if args.repos_file is None:
            # try the default path inside app/data
            default_repos = os.path.join("app", "data", "repos.json")
            if os.path.exists(default_repos):
                args.repos_file = default_repos
        # run deps stage
        try:
            # pass clone_timeout to metrics
            deps_results = run_deps_stage(args)
        except Exception as e:
            print("Error running deps stage:", e)
            deps_results = []

    if args.stage in ("mining", "all"):
        # ensure mining uses the deps_out file generated above (or provided)
        try:
            candidates = run_mining_stage(args)
            # save final dataset (can be used by plots)
            save_json(args.final_out, candidates)
            print(f"[main] Final dataset saved to {args.final_out}")
        except Exception as e:
            print("Error running mining stage:", e)

    if args.stage in ("plots", "all"):
        try:
            run_plots_stage(args)
        except Exception as e:
            print("Error generating plots:", e)

if __name__ == "__main__":
    main()