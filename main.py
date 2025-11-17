#!/usr/bin/env python3
"""
Main com checkpoints periódicos e escrita incremental.

O que há de novo:
- Checkpoints automáticos a cada N segundos (default 600 = 10 minutos) em:
  app/results/checkpoints/commit_changes_all.partial-YYYYmmdd-HHMMSS.json
  app/results/checkpoints/commit_changes_all.partial-YYYYmmdd-HHMMSS.csv
  (nunca sobrescreve: sempre cria um novo arquivo)
- Escrita incremental por repositório em NDJSON:
  app/results/commit_changes_all.ndjson
  (cada candidato é escrito como uma linha JSON assim que o repo termina)

Você pode usar seu comando atual sem mudanças:
python main.py --stage all --limit 100 --workers 16 --mining_sample 0 --mining_workers 10 --deps-out app/results/dependencies_cve_summary.json --mining-json-out app/results/commit_changes_all.json --mining-csv-out app/results/commit_changes_all.csv --plots app/results/plots --final-out app/results/final_dataset.json

Se quiser ajustar:
--checkpoint-interval-sec 600     (intervalo em segundos)
--checkpoint-dir app/results/checkpoints
--ndjson-out app/results/commit_changes_all.ndjson
"""
import argparse
import json
import os
import sys
import csv
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

from app.scripts import metrics as metrics_mod
from app.scripts import find_dependency_replacements as mining_mod
from app.scripts import plots as plots_mod

# ---------------- Utils ----------------

def safe_mkdir(p: str):
    if p:
        os.makedirs(p, exist_ok=True)

def save_json(path: str, obj):
    safe_mkdir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def append_ndjson(path: str, records: List[dict]):
    if not records:
        return
    safe_mkdir(os.path.dirname(path) or ".")
    with open(path, "a", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def write_candidates_csv(candidates: List[dict], csv_path: str):
    safe_mkdir(os.path.dirname(csv_path) or ".")
    header = [
        "repo", "commit", "parent", "commit_date", "removed_dep", "commit_message",
        "native_replacement_evidence", "native_migration_score",
        "lines_of_code_before", "lines_of_code_after", "avg_complexity_before", "avg_complexity_after"
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as cf:
        writer = csv.writer(cf)
        writer.writerow(header)
        for c in candidates:
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

def timestamp():
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# ---------------- Repos helpers ----------------

def load_repos_from_file(path: str, limit: int = None) -> List[Dict]:
    if not path or not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    out = []
    for item in data:
        if isinstance(item, str):
            out.append({"repo": item})
        elif isinstance(item, dict):
            if item.get("repo"):
                out.append(item)
            elif item.get("name"):
                out.append({"repo": item.get("name"), **{k: v for k, v in item.items() if k != "name"}})
    if limit:
        return out[:limit]
    return out

# ---------------- Stages ----------------

def run_deps_stage(args):
    # Fonte de repositórios é obrigatória se stage inclui deps
    src_path = None
    if args.repos_file and os.path.exists(args.repos_file):
        src_path = args.repos_file
    else:
        default_path = os.path.join("app", "data", "repos.json")
        if os.path.exists(default_path):
            src_path = default_path

    if not src_path:
        print("ERRO: Nenhum arquivo de repositórios fornecido (--repos-file) e app/data/repos.json não existe.")
        print('Crie um JSON: ["owner/repo", "owner2/repo2", ...] ou passe --repos-file.')
        sys.exit(2)

    repos = load_repos_from_file(src_path, limit=args.limit)
    if not repos:
        print(f"ERRO: arquivo de repositórios vazio ou inválido: {src_path}")
        sys.exit(2)

    print(f"[deps] Running dependency metrics for {len(repos)} repos (workers={args.workers}) clone_timeout={args.clone_timeout}")
    results = metrics_mod.get_metrics_batch(repos, workers=args.workers, clone_timeout=args.clone_timeout)
    save_json(args.deps_out, results)
    print(f"[deps] Saved deps dataset: {args.deps_out} (repos: {len(results)})")
    return results

def run_mining_stage(args):
    # arquivo deps_out deve existir (lista de repos para mining)
    if not os.path.exists(args.deps_out):
        print(f"[mining] deps file not found: {args.deps_out}. Rode a stage deps primeiro (com --repos-file).")
        return []

    # Tenta carregar como lista de dicts com chave repo (output de metrics)
    try:
        with open(args.deps_out, "r", encoding="utf-8") as f:
            raw = json.load(f)
        deps = [{"repo": item.get("repo")} for item in raw if isinstance(item, dict) and item.get("repo")]
    except Exception:
        deps = []

    if args.mining_sample and args.mining_sample > 0:
        deps = deps[:args.mining_sample]
    if args.limit:
        deps = deps[:args.limit]

    repos = [d.get("repo") for d in deps if d.get("repo")]
    print(f"[mining] Will analyze {len(repos)} repos (workers={args.mining_workers}) repo_timeout={args.repo_timeout}s")

    all_candidates = []
    lock = threading.Lock()

    # Checkpoint worker
    stop_event = threading.Event()

    def write_checkpoint():
        # snapshot sob lock
        with lock:
            snapshot = list(all_candidates)
        if not snapshot:
            return
        ts = timestamp()
        safe_mkdir(args.checkpoint_dir)
        chk_json = os.path.join(args.checkpoint_dir, f"commit_changes_all.partial-{ts}.json")
        chk_csv = os.path.join(args.checkpoint_dir, f"commit_changes_all.partial-{ts}.csv")
        try:
            save_json(chk_json, snapshot)
            write_candidates_csv(snapshot, chk_csv)
            print(f"[checkpoint] wrote {chk_json} and {chk_csv} (items={len(snapshot)})")
        except Exception as e:
            print(f"[checkpoint] error: {e}")

    def checkpoint_loop():
        # aguarda intervalos e escreve
        interval = max(30, int(args.checkpoint_interval_sec))  # sanidade: >=30s
        while not stop_event.wait(interval):
            write_checkpoint()

    # inicia thread de checkpoint
    checkpoint_thread = threading.Thread(target=checkpoint_loop, name="checkpoint-writer", daemon=True)
    checkpoint_thread.start()

    # NDJSON incremental: cada repo concluído, escrevemos
    ndjson_path = args.ndjson_out

    def worker(repo_full):
        try:
            cands = mining_mod.analyze_repo(
                repo_full,
                limit_commits=args.limit_commits,
                timeout_seconds=args.repo_timeout
            )
            # agrega e grava incremental
            with lock:
                all_candidates.extend(cands or [])
            if ndjson_path and cands:
                try:
                    append_ndjson(ndjson_path, cands)
                except Exception as e:
                    print(f"[ndjson] error appending {repo_full}: {e}")
            print(f"[mining] Done mining {repo_full} -> {len(cands or [])} candidates")
            return cands or []
        except Exception as e:
            print(f"[mining] Error analyzing {repo_full}: {e}")
            return []

    try:
        with ThreadPoolExecutor(max_workers=args.mining_workers) as ex:
            futs = {ex.submit(worker, r): r for r in repos}
            for fut in as_completed(futs):
                try:
                    _ = fut.result()
                except Exception as e:
                    print("Error in mining thread:", e)
    finally:
        # encerra checkpoints e força um último snapshot
        stop_event.set()
        checkpoint_thread.join(timeout=2.0)
        write_checkpoint()

    # salvar finais "oficiais"
    save_json(args.mining_json_out, all_candidates)
    print(f"[mining] Saved mining JSON: {args.mining_json_out} (candidates: {len(all_candidates)})")
    write_candidates_csv(all_candidates, args.mining_csv_out)
    print(f"[mining] Saved mining CSV: {args.mining_csv_out}")
    return all_candidates

def run_plots_stage(args):
    dataset = args.final_out if args.final_out and os.path.exists(args.final_out) else args.mining_json_out
    if not os.path.exists(dataset):
        print(f"[plots] Dataset not found: {dataset}. Run mining stage first.")
        return
    plots_mod.generate_all_plots_from_dataset(dataset, out_dir=args.plots)
    print(f"[plots] Plots generated to {args.plots}")

# ---------------- CLI ----------------

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

    # NOVOS argumentos para checkpoints e incremental
    ap.add_argument("--checkpoint-interval-sec", type=int, default=int(os.environ.get("CHECKPOINT_INTERVAL_SEC", 600)),
                    help="intervalo (segundos) para gravar checkpoints (default 600)")
    ap.add_argument("--checkpoint-dir", type=str, default=os.environ.get("CHECKPOINT_DIR", "app/results/checkpoints"),
                    help="diretório onde checkpoints serão gravados")
    ap.add_argument("--ndjson-out", type=str, default=os.environ.get("NDJSON_OUT", "app/results/commit_changes_all.ndjson"),
                    help="arquivo NDJSON incremental (uma linha JSON por candidato)")

    args = ap.parse_args()

    # deps
    if args.stage in ("deps", "all"):
        try:
            run_deps_stage(args)
        except SystemExit as e:
            sys.exit(e.code)
        except Exception as e:
            print("Error running deps stage:", e)
            sys.exit(1)

    # mining
    if args.stage in ("mining", "all"):
        try:
            candidates = run_mining_stage(args)
            save_json(args.final_out, candidates)
            print(f"[main] Final dataset saved to {args.final_out}")
        except Exception as e:
            print("Error running mining stage:", e)
            sys.exit(1)

    # plots
    if args.stage in ("plots", "all"):
        try:
            run_plots_stage(args)
        except Exception as e:
            print("Error generating plots:", e)
            sys.exit(1)

if __name__ == "__main__":
    main()