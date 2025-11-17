#!/usr/bin/env python3
"""
Plots atualizados para usar before/after de dependencies e vulnerable_dependencies.
"""
import json
import os
from typing import List, Dict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

def safe_mkdir(p):
    os.makedirs(p, exist_ok=True)

def _save(fig, path):
    safe_mkdir(os.path.dirname(path) or ".")
    fig.savefig(path, bbox_inches="tight")
    plt.close(fig)

def plot_dep_counts_before_after(dataset: List[Dict], out_dir: str):
    xb, xa = [], []
    for r in dataset:
        xb.append(int(r.get("dependencies_before", 0) or 0))
        xa.append(int(r.get("dependencies_after", 0) or 0))
    if not xb:
        return
    fig, ax = plt.subplots(figsize=(6,6))
    ax.scatter(xb, xa, alpha=0.6, s=15)
    m = max(max(xb), max(xa), 1)
    ax.plot([0, m], [0, m], "--", color="red", label="y=x (sem mudança)")
    ax.set_xlabel("Dependencies (before)")
    ax.set_ylabel("Dependencies (after)")
    ax.set_title("Dependencies: before vs after")
    ax.legend()
    ax.grid(True, alpha=0.3)
    _save(fig, os.path.join(out_dir, "deps_before_vs_after.png"))

def plot_vuln_dep_counts_before_after(dataset: List[Dict], out_dir: str):
    xb, xa = [], []
    for r in dataset:
        xb.append(int(r.get("vulnerable_dependencies_before", 0) or 0))
        xa.append(int(r.get("vulnerable_dependencies_after", 0) or 0))
    if not xb:
        return
    fig, ax = plt.subplots(figsize=(6,6))
    ax.scatter(xb, xa, alpha=0.6, s=15, color="C3")
    m = max(max(xb), max(xa), 1)
    ax.plot([0, m], [0, m], "--", color="gray", label="y=x (sem mudança)")
    ax.set_xlabel("Vulnerable dependencies (before)")
    ax.set_ylabel("Vulnerable dependencies (after)")
    ax.set_title("Vulnerable dependencies: before vs after (OSV)")
    ax.legend()
    ax.grid(True, alpha=0.3)
    _save(fig, os.path.join(out_dir, "vuln_deps_before_vs_after.png"))

    # Histograma do delta
    deltas = [a-b for a,b in zip(xa, xb)]
    fig2, ax2 = plt.subplots(figsize=(7,4))
    ax2.hist(deltas, bins=20, color="C1", alpha=0.8)
    ax2.set_xlabel("Δ vulnerable dependencies (after - before)")
    ax2.set_ylabel("Count")
    ax2.set_title("Distribuição da mudança em deps vulneráveis")
    _save(fig2, os.path.join(out_dir, "vuln_deps_delta_hist.png"))

def generate_all_plots_from_dataset(dataset_path: str, out_dir="app/results/plots"):
    safe_mkdir(out_dir)
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        return
    plot_dep_counts_before_after(data, out_dir)
    plot_vuln_dep_counts_before_after(data, out_dir)
    print(f"Plots gerados em: {out_dir}")