#!/usr/bin/env python3
"""
Main com:
- Descoberta automática (GitHub API) quando não há --repos-file nem app/data/repos.json.
- Checkpoints periódicos + NDJSON incremental.
- CSV inclui before/after de dependencies e vulnerable_dependencies.
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
from typing import List, Dict, Optional

from app.scripts import metrics as metrics_mod
from app.scripts import find_dependency_replacements as mining_mod
from app.scripts import plots as plots_mod

def safe_mkdir(p: str):
    if p:
        os.makedirs(p, exist_ok=True)

def save_json(path: str, obj):
    safe_mkdir(os.path.dirname(path) or ".")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)

def append_ndjson(path: str, records: List[dict]):
    if not records or not path:
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
        "lines_of_code_before", "lines_of_code_after", "avg_complexity_before", "avg_complexity_after",
        # NOVOS CAMPOS:
        "dependencies_before", "dependencies_after",
        "vulnerable_dependencies_before", "vulnerable_dependencies_after",
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
                c.get("dependencies_before", ""),
                c.get("dependencies_after", ""),
                c.get("vulnerable_dependencies_before", ""),
                c.get("vulnerable_dependencies_after", ""),
            ]
            writer.writerow(row)

def timestamp():
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")

# Descoberta (mesma de antes)
def discover_repos_via_github(language: str, min_stars: int, count: int, token: Optional[str] = None) -> List[Dict]:
    import urllib.request, urllib.parse, time as _time
    per_page = 100
    out = []
    page = 1
    q = f"language:{language} stars:>={min_stars}"
    base = "https://api.github.com/search/repositories"
    while len(out) < count:
        remaining = count - len(out)
        pp = per_page if remaining > per_page else remaining
        query = f"{base}?q={urllib.parse.quote(q)}&sort=stars&order=desc&per_page={pp}&page={page}"
        req = urllib.request.Request(query, headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "ti6-miner/1.0",
        })
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = resp.read()
            js = json.loads(data.decode("utf-8", errors="replace"))
        items = js.get("items") or []
        if not items:
            break
        for it in items:
            full = it.get("full_name")
            if full:
                out.append({
                    "repo": full,
                    "stargazers_count": it.get("stargazers_count", 0),
                    "forks_count": it.get("forks_count", 0),
                })
                if len(out) >= count:
                    break
        page += 1
        if not token:
            _time.sleep(1.8)
    return out

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

def run_deps_stage(args):
    src_path = None
    if args.repos_file and os.path.exists(args.repos_file):
        src_path = args.repos_file
        print(f"[deps] Usando --repos-file {src_path}")
        repos = load_repos_from_file(src_path, limit=args.limit)
    else:
        default_path = os.path.join("app", "data", "repos.json")
        if os.path.exists(default_path):
            src_path = default_path
            print(f"[deps] Usando {default_path}")
            repos = load_repos_from_file(src_path, limit=args.limit)
        else:
            token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
            print(f"[deps][discover] language={args.discover_language} minStars={args.discover_min_stars} count={args.discover_count} token={'yes' if token else 'no'}")
            discovered = discover_repos_via_github(args.discover_language, args.discover_min_stars, args.discover_count, token=token)
            if args.limit:
                discovered = discovered[:args.limit]
            save_json(args.discover_out, discovered)
            print(f"[deps][discover] Lista salva em {args.discover_out} (n={len(discovered)})")
            repos = discovered

    if not repos:
        print("ERRO: Nenhum repositório para deps.")
        sys.exit(2)

    print(f"[deps] Running dependency metrics for {len(repos)} repos (workers={args.workers}) clone_timeout={args.clone_timeout}")
    results = metrics_mod.get_metrics_batch(repos, workers=args.workers, clone_timeout=args.clone_timeout)
    save_json(args.deps_out, results)
    print(f"[deps] Saved deps dataset: {args.deps_out} (repos: {len(results)})")
    return results

def run_mining_stage(args):
    if not os.path.exists(args.deps_out):
        print(f"[mining] deps file not found: {args.deps_out}. Rode stage deps primeiro (ou all).")
        return []

    try:
        raw = json.load(open(args.deps_out, "r", encoding="utf-8"))
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

    stop_event = threading.Event()
    def write_checkpoint():
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
        interval = max(30, int(args.checkpoint_interval_sec))
        while not stop_event.wait(interval):
            write_checkpoint()

    checkpoint_thread = threading.Thread(target=checkpoint_loop, name="checkpoint-writer", daemon=True)
    checkpoint_thread.start()

    ndjson_path = args.ndjson_out

    def worker(repo_full):
        try:
            cands = mining_mod.analyze_repo(
                repo_full,
                limit_commits=args.limit_commits,
                timeout_seconds=args.repo_timeout
            )
            with lock:
                if cands:
                    all_candidates.extend(cands)
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
        stop_event.set()
        checkpoint_thread.join(timeout=2.0)
        write_checkpoint()

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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stage", choices=["deps","mining","plots","all"], default="all")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--limit-commits", dest="limit_commits", type=int, default=None)
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--mining_workers", type=int, default=1)
    ap.add_argument("--mining_sample", type=int, default=0)
    ap.add_argument("--repos-file", type=str, default=None)
    ap.add_argument("--deps-out", default="app/results/dependencies_cve_summary.json")
    ap.add_argument("--mining-json-out", dest="mining_json_out", default="app/results/commit_changes_all.json")
    ap.add_argument("--mining-csv-out", dest="mining_csv_out", default="app/results/commit_changes_all.csv")
    ap.add_argument("--plots", default="app/results/plots")
    ap.add_argument("--final-out", dest="final_out", default="app/results/final_dataset.json")
    ap.add_argument("--repo-timeout", dest="repo_timeout", type=int, default=int(os.environ.get("REPO_TIMEOUT", 400)))
    ap.add_argument("--clone-timeout", dest="clone_timeout", type=int, default=int(os.environ.get("CLONE_TIMEOUT", 400)))

    # Descoberta
    ap.add_argument("--discover-language", type=str, default=os.environ.get("DISCOVER_LANGUAGE", "JavaScript"))
    ap.add_argument("--discover-min-stars", type=int, default=int(os.environ.get("DISCOVER_MIN_STARS", 5000)))
    ap.add_argument("--discover-count", type=int, default=int(os.environ.get("DISCOVER_COUNT", 100)))
    ap.add_argument("--discover-out", type=str, default=os.environ.get("DISCOVER_OUT", "app/results/discovered_repos.json"))

    # Checkpoints/NDJSON
    ap.add_argument("--checkpoint-interval-sec", type=int, default=int(os.environ.get("CHECKPOINT_INTERVAL_SEC", 600)))
    ap.add_argument("--checkpoint-dir", type=str, default=os.environ.get("CHECKPOINT_DIR", "app/results/checkpoints"))
    ap.add_argument("--ndjson-out", type=str, default=os.environ.get("NDJSON_OUT", "app/results/commit_changes_all.ndjson"))

    args = ap.parse_args()

    if args.stage in ("deps", "all"):
        try:
            run_deps_stage(args)
        except SystemExit as e:
            sys.exit(e.code)
        except Exception as e:
            print("Error running deps stage:", e)
            sys.exit(1)

    if args.stage in ("mining", "all"):
        try:
            candidates = run_mining_stage(args)
            save_json(args.final_out, candidates)
            print(f"[main] Final dataset saved to {args.final_out}")
        except Exception as e:
            print("Error running mining stage:", e)
            sys.exit(1)

    if args.stage in ("plots", "all"):
        try:
            run_plots_stage(args)
        except Exception as e:
            print("Error generating plots:", e)
            sys.exit(1)

if __name__ == "__main__":
    main()