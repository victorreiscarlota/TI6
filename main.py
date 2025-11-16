import argparse
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
import pandas as pd

from app.scripts.github_api import get_top_js_repos
from app.scripts.metrics import get_metrics_batch
from app.scripts.find_dependency_replacements import analyze_repo
from app.scripts.merge_and_plot import merge_and_plot_main

load_dotenv()
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

RESULTS_DIR = os.path.join("app", "results")
os.makedirs(RESULTS_DIR, exist_ok=True)

def stage_deps(limit, workers, out_json):
    repos = get_top_js_repos(limit=limit, token=GITHUB_TOKEN)
    summaries = get_metrics_batch(repos, token=GITHUB_TOKEN, workers=workers)
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(summaries, f, indent=2, ensure_ascii=False)
    return summaries

def stage_mining_aggregate(deps_json, sample=None, workers=1, include_pkg_snapshots=False, out_json=None, out_csv=None):
    with open(deps_json, "r", encoding="utf-8") as f:
        repos = json.load(f)
    repo_names = [r["repo"] for r in repos]
    if sample:
        repo_names = repo_names[:sample]

    all_candidates = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(analyze_repo, repo, GITHUB_TOKEN, None, include_pkg_snapshots, None): repo for repo in repo_names}
        for fut in as_completed(futures):
            repo = futures[fut]
            try:
                res = fut.result()
                if res:
                    all_candidates.extend(res)
                print(f"Done mining {repo} -> {len(res or [])} candidates")
            except Exception as e:
                print(f"Mining failed for {repo}: {e}")

    if out_json:
        os.makedirs(os.path.dirname(out_json), exist_ok=True)
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(all_candidates, f, indent=2, ensure_ascii=False)
        print(f"Saved aggregated mining JSON: {out_json}")

    if out_csv:
        rows = []
        for c in all_candidates:
            rd = c.get("removed_dep_details", {}) or {}
            rows.append({
                "repo": c.get("repo"),
                "commit": c.get("commit"),
                "parent": c.get("parent"),
                "commit_date": c.get("commit_date"),
                "commit_message": c.get("commit_message"),
                "removed_dep": c.get("removed_dep"),
                "version_before": rd.get("version_before"),
                "version_after": rd.get("version_after"),
                "cve_count": rd.get("cve_count", 0),
                "cve_ids": ";".join(rd.get("cve_ids") or []),
                "lines_before": c.get("metrics_before", {}).get("lines_of_code"),
                "lines_after": c.get("metrics_after", {}).get("lines_of_code"),
                "complex_before": c.get("metrics_before", {}).get("avg_complexity"),
                "complex_after": c.get("metrics_after", {}).get("avg_complexity"),
            })
        df = pd.DataFrame(rows)
        os.makedirs(os.path.dirname(out_csv), exist_ok=True)
        df.to_csv(out_csv, index=False)
        print(f"Saved aggregated mining CSV: {out_csv}")

    return all_candidates

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", choices=["deps","mining","merge","all"], default="all")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--mining_workers", type=int, default=2)
    parser.add_argument("--mining_sample", type=int, default=50, help="0 or None = process all repos")
    parser.add_argument("--deps_out", default=os.path.join(RESULTS_DIR,"dependencies_cve_summary.json"))
    parser.add_argument("--mining_json_out", default=os.path.join(RESULTS_DIR,"commit_changes_all.json"))
    parser.add_argument("--mining_csv_out", default=os.path.join(RESULTS_DIR,"commit_changes_all.csv"))
    parser.add_argument("--plots", default=os.path.join(RESULTS_DIR,"plots"))
    parser.add_argument("--final_out", default=os.path.join(RESULTS_DIR,"final_dataset.json"))
    args = parser.parse_args()

    if args.stage in ("deps","all"):
        print("Running stage: deps")
        stage_deps(limit=args.limit, workers=args.workers, out_json=args.deps_out)

    if args.stage in ("mining","all"):
        print("Running stage: mining (aggregated)")
        sample = None if (args.mining_sample==0) else args.mining_sample
        stage_mining_aggregate(args.deps_out, sample=sample, workers=args.mining_workers, include_pkg_snapshots=False, out_json=args.mining_json_out, out_csv=args.mining_csv_out)

    if args.stage in ("merge","all"):
        commits_input = [args.mining_json_out] if os.path.exists(args.mining_json_out) else []
        merge_and_plot_main(args.deps_out, commits_input, None, args.final_out, args.plots)
        print(f"Merge done -> {args.final_out} and plots at {args.plots}")

if __name__ == "__main__":
    main()