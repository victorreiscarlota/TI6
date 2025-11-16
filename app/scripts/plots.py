#!/usr/bin/env python3
"""
Funções de plotagem com rótulos e descrições úteis para as perguntas do projeto.

Geram:
- Gráficos com rótulos explícitos e unidades (eixo X/Y legíveis).
- Anotações/resumo textual para responder às perguntas de pesquisa.
- Salvam imagens e um JSON metadata por gráfico com a descrição.

Uso (exemplo):
  from app.scripts.plots import generate_all_plots_from_dataset
  generate_all_plots_from_dataset("app/results/final_dataset.json", out_dir="app/results/plots")

Observação:
- Espera que os registros no dataset contenham:
  - metrics_before/metrics_after com campos lines_of_code e avg_complexity
  - native_migration.{native_hits_before, native_hits_after, native_replacement_evidence}
  - removed_dep
  - commit_message
"""
import json
import os
from collections import Counter
from typing import List, Dict
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import textwrap

def safe_mkdir(p):
    os.makedirs(p, exist_ok=True)

def _save_plot_and_meta(fig, out_path_img, meta: Dict):
    safe_mkdir(os.path.dirname(out_path_img) or ".")
    fig.savefig(out_path_img, bbox_inches="tight")
    plt.close(fig)
    meta_path = os.path.splitext(out_path_img)[0] + ".meta.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

def plot_lines_vs_vulns(dataset: List[Dict], out_dir="app/results/plots"):
    """
    Gráfico: lines_of_code_before (eixo X) vs vulnerable_deps (eixo Y)
    Objetivo: responder Q1 — se menos linhas (refatoração) correlaciona com menor exposição.
    """
    x = []
    y = []
    for r in dataset:
        mb = r.get("metrics_before") or {}
        dep_info = r.get("removed_dep_details") or {}
        # fallback names
        loc = mb.get("lines_of_code") or mb.get("log_lines_before") or mb.get("lines_of_code_before") or 0
        vulns = dep_info.get("cve_count", 0) or r.get("vulnerable_deps", 0)
        x.append(loc)
        y.append(vulns)

    fig, ax = plt.subplots(figsize=(8,5))
    ax.scatter(x, y, alpha=0.7, s=20)
    ax.set_xlabel("Lines of code (before refactor) — unidades: linhas")
    ax.set_ylabel("Exposição a vulnerabilidades (vulnerable deps / CVEs)")
    ax.set_title("Relação: tamanho do código antes da refatoração vs vulnerabilidades")
    ax.grid(True, linestyle="--", alpha=0.4)

    # estatística rápida no meta
    meta = {
        "purpose": "Responder Q1: verificar se repos com refatoração/nativas reduzem exposição a CVEs",
        "notes": "Pontos representando (lines_of_code_before, vulnerable_deps). Interpretação: olho na tendência (correlação negativa sugere redução da superfície de ataque).",
        "n_points": len(x),
        "x_summary": {
            "min": int(np.min(x)) if x else 0,
            "max": int(np.max(x)) if x else 0,
            "median": float(np.median(x)) if x else 0
        },
        "y_summary": {
            "min": int(np.min(y)) if y else 0,
            "max": int(np.max(y)) if y else 0,
            "median": float(np.median(y)) if y else 0
        }
    }
    _save_plot_and_meta(fig, os.path.join(out_dir, "lines_vs_vulns.png"), meta)

def plot_migration_reasons_wordcount(dataset: List[Dict], out_dir="app/results/plots", top_n=40):
    """
    Gera uma visualização simples das palavras mais frequentes nas mensagens de commit
    que acompanham remoção de dependências (ajuda responder Q2).
    Produz um barra horizontal das palavras mais frequentes.
    """
    messages = []
    for r in dataset:
        m = (r.get("commit_message") or "").lower()
        if m:
            messages.append(m)
    # tokenização simples
    tokens = []
    for m in messages:
        for t in re.findall(r"[a-zA-Z0-9\-_]+", m):
            if len(t) > 2 and not t.isdigit():
                tokens.append(t)
    counter = Counter(tokens)
    common = counter.most_common(top_n)
    if not common:
        return
    words, counts = zip(*common)
    fig, ax = plt.subplots(figsize=(8, max(3, len(words)*0.2)))
    y_pos = np.arange(len(words))
    ax.barh(y_pos, counts, align='center', color='C0', alpha=0.8)
    ax.set_yticks(y_pos)
    ax.set_yticklabels(words)
    ax.invert_yaxis()
    ax.set_xlabel("Ocorrências nas mensagens de commit")
    ax.set_title("Top palavras em mensagens de commit (remover dependências) — indica motivos (Q2)")
    meta = {
        "purpose": "Responder Q2: identificar motivos declarados nas mensagens de commit para substituir bibliotecas por nativas",
        "notes": "Remova stopwords manuais ou refine tokenização se necessário.",
        "top_words": [{ "word": w, "count": int(c) } for w, c in common]
    }
    _save_plot_and_meta(fig, os.path.join(out_dir, "commit_reasons_wordcount.png"), meta)

def plot_stability_over_time(dataset: List[Dict], out_dir="app/results/plots"):
    """
    Analisa métricas_before/after para tentar inferir estabilidade (Q3).
    Utiliza avg_complexity_before vs after e lines_of_code change to hint at maintainability.
    """
    before_complex = []
    after_complex = []
    loc_before = []
    loc_after = []
    for r in dataset:
        mb = r.get("metrics_before") or {}
        ma = r.get("metrics_after") or {}
        bc = mb.get("avg_complexity") or mb.get("avg_complexity_before") or 0.0
        ac = ma.get("avg_complexity") or ma.get("avg_complexity_after") or 0.0
        lb = mb.get("lines_of_code") or mb.get("lines_of_code_before") or 0
        la = ma.get("lines_of_code") or ma.get("lines_of_code_after") or 0
        before_complex.append(bc)
        after_complex.append(ac)
        loc_before.append(lb)
        loc_after.append(la)
    # plot de mudanças - scatter com linha y=x
    fig, ax = plt.subplots(figsize=(7,7))
    ax.scatter(before_complex, after_complex, alpha=0.6, s=20)
    maxv = max(max(before_complex or [0]), max(after_complex or [0]), 1)
    ax.plot([0, maxv], [0, maxv], color="red", linestyle="--", label="no change")
    ax.set_xlabel("Avg complexity (before)")
    ax.set_ylabel("Avg complexity (after)")
    ax.set_title("Complexidade média: antes vs depois (Q3)")
    ax.legend()
    meta = {
        "purpose": "Responder Q3: avaliar se refatoração para nativas reduz complexidade média (indireto: estabilidade/manutenção).",
        "notes": "Pontos abaixo da linha y=x indicam redução de complexidade após mudança (potencial ganho de estabilidade).",
        "n_points": len(before_complex)
    }
    _save_plot_and_meta(fig, os.path.join(out_dir, "complexity_before_vs_after.png"), meta)

    # também produzir histograma de variação LOC (Q4)
    delta_loc = [ (a - b) for a,b in zip(loc_after, loc_before) ]
    fig2, ax2 = plt.subplots(figsize=(8,4))
    ax2.hist(delta_loc, bins=30, color="C1", alpha=0.8)
    ax2.set_xlabel("Mudança em linhas de código (after - before)")
    ax2.set_ylabel("Número de ocorrências")
    ax2.set_title("Distribuição de mudança no tamanho do código após remoção de dependências (Q4)")
    meta2 = {
        "purpose": "Responder Q4: verificar impacto em tamanho do código mantido",
        "notes": "Valores positivos indicam aumento do código (possivelmente por adaptação native), negativos indicam redução."
    }
    _save_plot_and_meta(fig2, os.path.join(out_dir, "loc_delta_hist.png"), meta2)

def generate_all_plots_from_dataset(dataset_path: str, out_dir="app/results/plots"):
    safe_mkdir(out_dir)
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # assumimos lista de candidatos no dataset
    plot_lines_vs_vulns(data, out_dir=out_dir)
    plot_migration_reasons_wordcount(data, out_dir=out_dir)
    plot_stability_over_time(data, out_dir=out_dir)
    print(f"Plots gerados em: {out_dir}")