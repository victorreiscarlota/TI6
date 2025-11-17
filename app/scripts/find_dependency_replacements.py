#!/usr/bin/env python3
"""
Mining otimizado + logs + enriquecimento vulnerável + opção de gerar registros mesmo sem remoção.

Novos env vars:
  EARLY_METRICS=1           -> gera registro para todo commit que toca package.json (removed_dep=None se não houve remoção)
  ALWAYS_COMMITS=1          -> alias de EARLY_METRICS
  DEP_CHANGE_RECENT_COMMITS=N -> seleciona os N commits mais recentes que MUDARAM dependências (adição ou remoção)
  COMMIT_LEVEL_ENTRY=1      -> quando há remoções, além dos registros por remoção, gera também 1 registro agregado por commit (removed_dep=None)
  (já existentes)
  FAST_MODE=1, RECENT_COMMITS=N, NO_COMPLEXITY=1, NO_OSV=1, MAX_JS_FILES, TIME_CAP_PER_COMMIT_MS, EXPORT_ENRICHED_OSV

Cada registro agora pode conter (quando EARLY_METRICS ou COMMIT_LEVEL_ENTRY):
  removal_count, addition_count (número de deps removidas / adicionadas entre parent e commit)
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import List, Dict, Tuple, Optional

import requests

try:
    from .repo_watchdog_subprocess import run_callable_in_subprocess
    from .metrics import get_cve_for_package, load_osv_cache, save_osv_cache
except ImportError:
    from app.scripts.repo_watchdog_subprocess import run_callable_in_subprocess
    from app.scripts.metrics import get_cve_for_package, load_osv_cache, save_osv_cache

try:
    import lizard  # type: ignore
except Exception:
    lizard = None

GIT = "git"
DEFAULT_REPO_TIMEOUT = int(os.environ.get("REPO_TIMEOUT", 1800))
DEFAULT_CLONE_TIMEOUT = int(os.environ.get("REPO_CLONE_TIMEOUT", 600))
DEFAULT_MAX_COMMITS_SCAN = int(os.environ.get("MAX_COMMITS_SCAN", 1200))
LOG_ROOT = os.path.join("app", "results", "logs")
JS_EXTS = (".js", ".jsx", ".ts", ".tsx")

LOG_COMMIT = bool(int(os.environ.get("LOG_COMMIT", "0") or "0"))
LOG_METRICS = bool(int(os.environ.get("LOG_METRICS", "0") or "0"))
LOG_OSV = bool(int(os.environ.get("LOG_OSV", "0") or "0"))

def log(repo: str, msg: str):
    os.makedirs(LOG_ROOT, exist_ok=True)
    safe = repo.replace("/", "__")
    path = os.path.join(LOG_ROOT, f"{safe}.log")
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    if LOG_COMMIT or any(k in msg for k in ("START","CLONE","FINISHED","COMMITS","TIMEOUT","ERROR")):
        print(f"[find_dep] {repo} {msg}", flush=True)

def run(cmd, cwd=None, check=True, timeout=None):
    t0 = time.perf_counter()
    r = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True,
                       encoding="utf-8", errors="replace", timeout=timeout)
    dt = (time.perf_counter()-t0)*1000
    if check and r.returncode != 0:
        raise RuntimeError(f"Command failed ({dt:.1f}ms): {cmd}\nstdout:{r.stdout}\nstderr:{r.stderr}")
    return r.stdout.strip()

def clone_repo_light(full_name: str, target_dir: str, clone_timeout: int):
    os.makedirs(os.path.dirname(target_dir), exist_ok=True)
    t0=time.perf_counter()
    run(f'{GIT} clone --filter=blob:none --no-checkout --quiet https://github.com/{full_name}.git "{target_dir}"',
        timeout=clone_timeout, check=True)
    log(full_name, f"CLONE_OK time_ms={(time.perf_counter()-t0)*1000:.1f}")

def commits_touching_any_package_json(repo_dir: str) -> List[Tuple[str,int,str]]:
    out = run(f'{GIT} -C "{repo_dir}" log --pretty=format:%H --no-renames --diff-filter=AMDR -- ":(glob)**/package.json"', check=False)
    shas=[l for l in (out.splitlines() if out else []) if l.strip()]
    res=[]
    for sha in shas:
        info=run(f'{GIT} -C "{repo_dir}" show -s --format=%ct%x00%s {sha}', check=False)
        if info:
            try: ts, subj = info.split("\x00",1); res.append((sha,int(ts),subj))
            except: res.append((sha,0,""))
        else: res.append((sha,0,""))
    return res

def recent_commits_touching_any_package_json(repo_dir: str, n: int) -> List[Tuple[str,int,str]]:
    out = run(f'{GIT} -C "{repo_dir}" log -n {n} --pretty=format:%H --no-renames --diff-filter=AMDR -- ":(glob)**/package.json"', check=False)
    shas=[l for l in (out.splitlines() if out else []) if l.strip()]
    res=[]
    for sha in shas:
        info=run(f'{GIT} -C "{repo_dir}" show -s --format=%ct%x00%s {sha}', check=False)
        if info:
            try: ts, subj = info.split("\x00",1); res.append((sha,int(ts),subj))
            except: res.append((sha,0,""))
        else: res.append((sha,0,""))
    return res

def parent_of(repo_dir: str, sha: str) -> str:
    line = run(f'{GIT} -C "{repo_dir}" rev-list --parents -n 1 {sha}', check=False)
    parts=line.split()
    return parts[1] if len(parts)>=2 else ""

def list_package_json_paths_at_commit(repo_dir: str, sha: str) -> List[str]:
    out=run(f'{GIT} -C "{repo_dir}" ls-tree -r --name-only {sha}', check=False)
    return [l for l in (out.splitlines() if out else []) if l.lower().endswith("package.json")]

def load_package_json_at_commit(repo_dir: str, sha: str, path: str):
    try:
        txt=run(f'{GIT} -C "{repo_dir}" show {sha}:{path}', check=False)
        if not txt: return None
        return json.loads(txt)
    except: return None

def load_all_pkg_at_commit(repo_dir: str, sha: str):
    t0=time.perf_counter()
    paths=list_package_json_paths_at_commit(repo_dir, sha)
    d={}
    for p in paths:
        pj=load_package_json_at_commit(repo_dir, sha, p)
        if pj: d[p]=pj
    return d, paths, (time.perf_counter()-t0)*1000

def aggregate_deps(pkg_dict: Dict[str, dict]):
    deps, dev, versions = {}, {}, {}
    for _, pkg in pkg_dict.items():
        d=pkg.get("dependencies") or {}
        dv=pkg.get("devDependencies") or {}
        for k,v in d.items():
            deps.setdefault(k,v); versions.setdefault(k,set()).add(v)
        for k,v in dv.items():
            dev.setdefault(k,v); versions.setdefault(k,set()).add(v)
    versions={k:sorted(list(vs)) for k,vs in versions.items()}
    return deps, dev, versions

def list_all_paths(repo_dir: str, sha: str) -> List[str]:
    out=run(f'{GIT} -C "{repo_dir}" ls-tree -r --name-only {sha}', check=False)
    return [l for l in (out.splitlines() if out else []) if l.strip()]

def compute_js_metrics_inline(repo_dir: str, sha: str, no_complexity: bool,
                              max_js_files: Optional[int]=None, time_cap_ms: Optional[int]=None,
                              repo_name: str="") -> dict:
    start=time.perf_counter()
    paths=list_all_paths(repo_dir, sha)
    js=[p for p in paths if p.lower().endswith(JS_EXTS) and not p.endswith(".d.ts")]
    if max_js_files and len(js)>max_js_files:
        if LOG_METRICS: log(repo_name,f"METRICS skip commit={sha[:7]} js_files={len(js)} max_js_files={max_js_files}")
        return {"lines_of_code":0,"avg_complexity":0.0,"commit_snapshot":sha,"files_scanned":0,"functions_counted":0,"complexity_tool":"skipped (max_js_files)","metrics_skipped":True}
    loc=0
    complex_list=[]
    for f in js:
        code=run(f'{GIT} -C "{repo_dir}" show {sha}:{f}', check=False)
        if not code: continue
        loc+=sum(1 for ln in code.splitlines() if ln.strip())
        if not no_complexity:
            if lizard:
                try:
                    res=lizard.analyze_file.analyze_source_code(f, code)  # type: ignore
                    for fn in getattr(res,"function_list",[]) or []:
                        cc=getattr(fn,"cyclomatic_complexity",None)
                        if isinstance(cc,int): complex_list.append(cc)
                except: pass
            else:
                lw=" "+code.lower()+" "
                tokens=[" if "," for "," while ","case "," switch "," catch"," else if"," =>"," function "]
                c=0
                for t in tokens:
                    c+=lw.count(t)
                complex_list.append(c)
        if time_cap_ms and (time.perf_counter()-start)*1000>time_cap_ms:
            if LOG_METRICS: log(repo_name,f"METRICS time_cap commit={sha[:7]} loc={loc}")
            avg = 0.0 if no_complexity else (sum(complex_list)/len(complex_list) if complex_list else 0.0)
            return {"lines_of_code":loc,"avg_complexity":avg,"commit_snapshot":sha,
                    "files_scanned":len(js),"functions_counted":len(complex_list),
                    "complexity_tool":"partial-time-cap","time_cap_exceeded_ms":(time.perf_counter()-start)*1000}
    avg = 0.0 if no_complexity else (sum(complex_list)/len(complex_list) if complex_list else 0.0)
    if LOG_METRICS:
        log(repo_name,f"METRICS commit={sha[:7]} files={len(js)} loc={loc} avg_complex={avg:.2f}")
    return {"lines_of_code":loc,"avg_complexity":avg,"commit_snapshot":sha,
            "files_scanned":len(js),"functions_counted":len(complex_list),
            "complexity_tool":("off" if no_complexity else ("lizard" if lizard else "fallback"))}

def grep_count(repo_dir: str, sha: str, pattern: str) -> int:
    out=run(f'{GIT} -C "{repo_dir}" grep -I -n -E "{pattern}" {sha} -- "*.js" "*.jsx" "*.ts" "*.tsx"', check=False)
    if not out: return 0
    return len([l for l in out.splitlines() if l.strip()])

def or_regex(parts):
    parts=[p for p in parts if p]
    return "(?:"+"|".join(parts)+")" if parts else "(?!)"

def build_patterns_for_dep(dep: str):
    d=dep.lower()
    if d in ("lodash","underscore"):
        third=or_regex([r"(?:from|require)\s*['\"](?:lodash|underscore)['\"]",r"[_]\s*\.",r"lodash\."])
        native=or_regex([r"\.map\s*\(",r"\.filter\s*\(",r"\.reduce\s*\(",r"Object\.assign\s*\(",r"Object\.(?:keys|values|entries)\s*\(",r"Array\.from\s*\(",r"String\.includes\s*\("])
        return ("lodash",third,native)
    if d=="left-pad":
        return ("left-pad",or_regex([r"(?:from|require)\s*['\"]left-pad['\"]",r"leftpad\s*\("]),or_regex([r"\.padStart\s*\(",r"\.padEnd\s*\("]))
    if d=="uuid":
        return ("uuid",or_regex([r"(?:from|require)\s*['\"]uuid['\"]"]),or_regex([r"crypto\.randomUUID\s*\("]))
    if d=="querystring":
        return ("querystring",or_regex([r"(?:from|require)\s*['\"]querystring['\"]"]),or_regex([r"URLSearchParams\s*\("]))
    if d in ("node-fetch","request"):
        return ("fetch",or_regex([r"(?:from|require)\s*['\"](?:node-fetch|request)['\"]"]),or_regex([r"(?<!\.)\bfetch\s*\("]))
    if d=="mkdirp":
        return ("mkdirp",or_regex([r"(?:from|require)\s*['\"]mkdirp['\"]",r"\bmkdirp\s*\("]),or_regex([r"fs\.mkdir\s*\([^)]*recursive\s*:\s*true"]))
    if d=="rimraf":
        return ("rimraf",or_regex([r"(?:from|require)\s*['\"]rimraf['\"]",r"\brimraf\s*\("]),or_regex([r"fs\.rm\s*\([^)]*recursive\s*:\s*true"]))
    if d=="moment":
        return ("moment",or_regex([r"(?:from|require)\s*['\"]moment['\"]",r"\bmoment\s*\("]),or_regex([r"Intl\.DateTimeFormat\s*\(",r"Temporal\."]))
    third=or_regex([rf"(?:from|require)\s*['\"]{re.escape(dep)}['\"]",rf"['\"]{re.escape(dep)}['\"]"])
    native=or_regex([r"\.map\s*\(",r"\.filter\s*\(",r"\.reduce\s*\(",r"Object\.assign\s*\(",r"URLSearchParams\s*\(",r"(?<!\.)\bfetch\s*\(",r"\.padStart\s*\(",r"crypto\.randomUUID\s*\("])
    return ("generic",third,native)

def native_migration_signal(repo_dir: str, before_sha: str, after_sha: str, dep: str) -> dict:
    ruleset, third_rx, native_rx=build_patterns_for_dep(dep)
    t_before=grep_count(repo_dir,before_sha,third_rx) if third_rx else 0
    t_after=grep_count(repo_dir,after_sha,third_rx) if third_rx else 0
    n_before=grep_count(repo_dir,before_sha,native_rx) if native_rx else 0
    n_after=grep_count(repo_dir,after_sha,native_rx) if native_rx else 0
    evidence = (t_before>0 and t_after==0 and n_after>n_before)
    return {
        "ruleset": ruleset,
        "third_party_hits_before": t_before,
        "third_party_hits_after": t_after,
        "native_hits_before": n_before,
        "native_hits_after": n_after,
        "native_replacement_evidence": bool(evidence),
        "native_migration_score": (n_after - n_before) - (t_before - t_after),
    }

def extract_vuln_briefs(osv_resp: dict) -> List[dict]:
    vulns=osv_resp.get("vulns") if isinstance(osv_resp, dict) else None
    if not isinstance(vulns,list): return []
    out=[]
    for v in vulns:
        vid=v.get("id",""); summary=v.get("summary") or v.get("details","")[:200]
        published=v.get("published",""); aliases=v.get("aliases",[])
        refs=[r.get("url") for r in (v.get("references") or []) if isinstance(r,dict) and r.get("url")]
        max_cvss=None
        for sev in v.get("severity",[]) or []:
            sc=sev.get("score")
            if sc and sc.replace(".","",1).isdigit():
                val=float(sc); max_cvss=val if max_cvss is None else max(max_cvss,val)
        out.append({"id":vid,"summary":summary,"published":published,"aliases":aliases,"references":refs,"max_cvss":max_cvss})
    return out

def vulnerable_count_for(dep_names, session, cache, no_osv: bool, repo: str) -> int:
    if no_osv: return 0
    t0=time.perf_counter()
    cnt=0
    for name in dep_names:
        try:
            vul_count,_=get_cve_for_package(name, session=session, cache=cache)
            if LOG_OSV: log(repo,f"OSV pkg={name} vulns={vul_count}")
            if vul_count and vul_count>0: cnt+=1
        except: pass
    if LOG_COMMIT:
        log(repo,f"OSV aggregate dep_total={len(dep_names)} vulnerable={cnt} time_ms={(time.perf_counter()-t0)*1000:.1f}")
    return cnt

def _worker_analyze(full_name: str,
                    limit_commits: Optional[int],
                    out_json_path: str,
                    clone_timeout: int,
                    max_commits_scan: int,
                    recent_commits: int,
                    fast_mode: bool,
                    no_complexity: bool,
                    no_osv: bool,
                    max_js_files: Optional[int],
                    time_cap_ms: Optional[int],
                    early_metrics: bool):
    tmp_root=tempfile.mkdtemp(prefix="mine_")
    repo_dir=os.path.join(tmp_root, full_name.split("/")[-1])
    results=[]
    osv_enriched=[]
    session=requests.Session()
    osv_cache=load_osv_cache() if not no_osv else {}
    try:
        log(full_name,"START")
        try:
            clone_repo_light(full_name, repo_dir, clone_timeout)
        except Exception as e:
            log(full_name,f"CLONE_FAILED: {e}")
            return results

        always_commits = early_metrics or bool(int(os.environ.get("ALWAYS_COMMITS","0") or "0"))
        commit_level_entry = bool(int(os.environ.get("COMMIT_LEVEL_ENTRY","0") or "0"))
        removal_recent_target = int(os.environ.get("REMOVAL_RECENT_COMMITS","0") or "0")
        dep_change_recent_target = int(os.environ.get("DEP_CHANGE_RECENT_COMMITS","0") or "0")

        if recent_commits > 0:
            commits = recent_commits_touching_any_package_json(repo_dir, recent_commits)
        else:
            commits = commits_touching_any_package_json(repo_dir)

        log(full_name,f"COMMITS_INITIAL={len(commits)} recent_mode={recent_commits>0}")

        # Optional: filter for removal commits
        if removal_recent_target > 0:
            filtered=[]
            for sha,ts,subj in commits:
                parent=parent_of(repo_dir, sha)
                parent=parent if parent else ""
                if not parent: continue
                before_pkgs,_,_=load_all_pkg_at_commit(repo_dir,parent)
                after_pkgs,_,_=load_all_pkg_at_commit(repo_dir,sha)
                if not before_pkgs: continue
                deps_b,dev_b,_=aggregate_deps(before_pkgs)
                deps_a,dev_a,_=aggregate_deps(after_pkgs)
                removed=[d for d in deps_b.keys() if d not in deps_a]
                if removed:
                    filtered.append((sha,ts,subj))
                if len(filtered)>=removal_recent_target: break
            if filtered:
                commits=filtered
                log(full_name,f"REMOVAL_RECENT selected={len(commits)} target={removal_recent_target}")
            else:
                log(full_name,"REMOVAL_RECENT none found -> fallback original list")

        # Filter for dependency change (add or remove)
        if dep_change_recent_target > 0:
            filtered=[]
            for sha,ts,subj in commits:
                parent=parent_of(repo_dir, sha)
                parent=parent if parent else ""
                if not parent: continue
                before_pkgs,_,_=load_all_pkg_at_commit(repo_dir,parent)
                after_pkgs,_,_=load_all_pkg_at_commit(repo_dir,sha)
                if not before_pkgs: continue
                deps_b,dev_b,_=aggregate_deps(before_pkgs)
                deps_a,dev_a,_=aggregate_deps(after_pkgs)
                names_before=set(deps_b.keys())|set(dev_b.keys())
                names_after=set(deps_a.keys())|set(dev_a.keys())
                removed=[d for d in names_before if d not in names_after]
                added=[d for d in names_after if d not in names_before]
                if removed or added:
                    filtered.append((sha,ts,subj))
                if len(filtered)>=dep_change_recent_target: break
            if filtered:
                commits=filtered
                log(full_name,f"DEP_CHANGE_RECENT selected={len(commits)} target={dep_change_recent_target}")
            else:
                log(full_name,"DEP_CHANGE_RECENT none found -> fallback original list")

        if max_commits_scan and len(commits)>max_commits_scan:
            commits=commits[:max_commits_scan]; log(full_name,f"TRUNCATE_MAX_SCAN={len(commits)}")
        if limit_commits and limit_commits>0 and len(commits)>limit_commits:
            commits=commits[:limit_commits]; log(full_name,f"TRUNCATE_LIMIT={len(commits)}")

        for sha, _, subj in commits:
            t_commit=time.perf_counter()
            parent=parent_of(repo_dir, sha)
            parent=parent if parent else ""
            if not parent:
                if LOG_COMMIT: log(full_name,f"COMMIT {sha[:7]} skip(no parent)")
                continue
            before_pkgs, before_paths, t_before_ms = load_all_pkg_at_commit(repo_dir,parent)
            after_pkgs, after_paths, t_after_ms = load_all_pkg_at_commit(repo_dir,sha)
            if not before_pkgs:
                if LOG_COMMIT: log(full_name,f"COMMIT {sha[:7]} skip(no before pkg.json)")
                continue

            deps_b, dev_b, vers_b = aggregate_deps(before_pkgs)
            deps_a, dev_a, vers_a = aggregate_deps(after_pkgs)

            names_before=set(deps_b.keys())|set(dev_b.keys())
            names_after=set(deps_a.keys())|set(dev_a.keys())

            dependencies_before=len(names_before)
            dependencies_after=len(names_after)

            vulnerable_before=vulnerable_count_for(names_before, session, osv_cache, no_osv, full_name)
            vulnerable_after=vulnerable_count_for(names_after, session, osv_cache, no_osv, full_name)

            removed=[d for d in names_before if d not in names_after]
            added=[d for d in names_after if d not in names_before]

            metrics_before={}
            metrics_after={}
            if removed or added or always_commits:
                metrics_before=compute_js_metrics_inline(repo_dir,parent,no_complexity,max_js_files,time_cap_ms,full_name)
                metrics_after=compute_js_metrics_inline(repo_dir,sha,no_complexity,max_js_files,time_cap_ms,full_name)

            iso=run(f'{GIT} -C "{repo_dir}" show -s --format=%cI {sha}', check=False) or ""

            # Se não há remoções e não queremos commit sem remoção
            if not removed and not always_commits and not added:
                if LOG_COMMIT: log(full_name,f"COMMIT {sha[:7]} no removal/addition skip")
                continue

            # Registro agregado por commit (se EARLY ou COMMIT_LEVEL_ENTRY)
            if (always_commits or commit_level_entry) and (removed or added or always_commits):
                agg_entry = {
                    "repo": full_name,
                    "commit": sha,
                    "parent": parent,
                    "commit_message": subj or "",
                    "commit_date": iso,
                    "removed_dep": None,
                    "removed_dep_details": None,
                    "metrics_before": metrics_before,
                    "metrics_after": metrics_after,
                    "native_migration": None,
                    "pkg_before_paths": before_paths,
                    "pkg_after_paths": after_paths,
                    "dependencies_before": dependencies_before,
                    "dependencies_after": dependencies_after,
                    "vulnerable_dependencies_before": vulnerable_before,
                    "vulnerable_dependencies_after": vulnerable_after,
                    "removal_count": len(removed),
                    "addition_count": len(added),
                    "fast_mode": fast_mode,
                }
                results.append(agg_entry)

            # Registros por remoção (mantém comportamento anterior)
            for dep in removed:
                if not no_osv:
                    try:
                        vul_count_raw, osv_raw = get_cve_for_package(dep, session=session, cache=osv_cache)
                    except Exception:
                        osv_raw={}
                    vulnerabilities_before=extract_vuln_briefs(osv_raw)
                    vulnerabilities_after=[]  # removido
                    vuln_count_before=len(vulnerabilities_before)
                    vuln_count_after=0
                else:
                    vulnerabilities_before=[]
                    vulnerabilities_after=[]
                    vuln_count_before=vuln_count_after=0

                nat=native_migration_signal(repo_dir,parent,sha,dep)
                details={
                    "versions_before": vers_b.get(dep, []),
                    "versions_after": vers_a.get(dep, []),
                    "vulnerabilities_before": vulnerabilities_before,
                    "vulnerabilities_after": vulnerabilities_after,
                    "vuln_count_before": vuln_count_before,
                    "vuln_count_after": vuln_count_after
                }
                cand={
                    "repo": full_name,
                    "commit": sha,
                    "parent": parent,
                    "commit_message": subj or "",
                    "commit_date": iso,
                    "removed_dep": dep,
                    "removed_dep_details": details,
                    "metrics_before": metrics_before,
                    "metrics_after": metrics_after,
                    "native_migration": nat,
                    "pkg_before_paths": before_paths,
                    "pkg_after_paths": after_paths,
                    "dependencies_before": dependencies_before,
                    "dependencies_after": dependencies_after,
                    "vulnerable_dependencies_before": vulnerable_before,
                    "vulnerable_dependencies_after": vulnerable_after,
                    "removal_count": len(removed),
                    "addition_count": len(added),
                    "fast_mode": fast_mode,
                }
                results.append(cand)
                osv_enriched.append({
                    "repo": full_name,
                    "commit": sha,
                    "date": iso,
                    "removed_dep": dep,
                    "versions_before": details["versions_before"],
                    "vuln_count_before": vuln_count_before,
                    "vulnerabilities_before": vulnerabilities_before
                })

            if LOG_COMMIT:
                log(full_name,
                    f"COMMIT {sha[:7]} removed={len(removed)} added={len(added)} deps_before={dependencies_before} deps_after={dependencies_after} vuln_before={vulnerable_before} vuln_after={vulnerable_after} time_ms={(time.perf_counter()-t_commit)*1000:.1f}")

        if out_json_path:
            os.makedirs(os.path.dirname(out_json_path) or ".", exist_ok=True)
            with open(out_json_path,"w",encoding="utf-8") as f:
                json.dump(results,f,indent=2,ensure_ascii=False)
        export_enriched=os.environ.get("EXPORT_ENRICHED_OSV")
        if export_enriched:
            os.makedirs(os.path.dirname(export_enriched) or ".", exist_ok=True)
            with open(export_enriched,"a",encoding="utf-8") as f:
                for row in osv_enriched:
                    f.write(json.dumps(row,ensure_ascii=False)+"\n")
        log(full_name,f"FINISHED total_records={len(results)}")
        return results
    finally:
        try:
            if not no_osv:
                save_osv_cache(osv_cache)
        except: pass
        shutil.rmtree(tmp_root, ignore_errors=True)

def analyze_repo(full_name: str,
                 limit_commits: int = None,
                 timeout_seconds: int = None,
                 clone_timeout: int = None,
                 max_commits_scan: int = None) -> list:
    if timeout_seconds is None: timeout_seconds=DEFAULT_REPO_TIMEOUT
    if clone_timeout is None: clone_timeout=DEFAULT_CLONE_TIMEOUT
    if max_commits_scan is None: max_commits_scan=DEFAULT_MAX_COMMITS_SCAN

    fast_mode=bool(int(os.environ.get("FAST_MODE","0") or "0"))
    recent_commits=int(os.environ.get("RECENT_COMMITS","0") or "0")
    no_complexity=bool(int(os.environ.get("NO_COMPLEXITY","0") or "0"))
    no_osv=bool(int(os.environ.get("NO_OSV","0") or "0"))
    max_js_files_env=os.environ.get("MAX_JS_FILES")
    max_js_files_val=int(max_js_files_env) if max_js_files_env and max_js_files_env.isdigit() else None
    time_cap_ms_env=os.environ.get("TIME_CAP_PER_COMMIT_MS")
    time_cap_ms=int(time_cap_ms_env) if time_cap_ms_env and time_cap_ms_env.isdigit() else None
    early_metrics=bool(int(os.environ.get("EARLY_METRICS","0") or "0")) or bool(int(os.environ.get("ALWAYS_COMMITS","0") or "0"))

    if fast_mode:
        if recent_commits<=0: recent_commits=10
        no_complexity=True
        no_osv=True

    tmp_root=tempfile.mkdtemp(prefix="mine_supervisor_")
    out_json=os.path.join(tmp_root,"worker_out.json")

    success,payload=run_callable_in_subprocess(
        module_name="app.scripts.find_dependency_replacements",
        func_name="_worker_analyze",
        args=[full_name,limit_commits,out_json,clone_timeout,max_commits_scan,
              recent_commits,fast_mode,no_complexity,no_osv,max_js_files_val,time_cap_ms,early_metrics],
        out_json_path=out_json,
        timeout_seconds=timeout_seconds
    )
    try:
        if not success:
            log(full_name,f"TIMEOUT_OR_ERROR: {payload}")
            return []
        if payload is None:
            try: return json.load(open(out_json,"r",encoding="utf-8"))
            except: return []
        return payload
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)

if __name__ == "__main__":
    ap=argparse.ArgumentParser()
    ap.add_argument("--repo",required=True)
    ap.add_argument("--limit",type=int,default=None)
    ap.add_argument("--timeout",type=int,default=DEFAULT_REPO_TIMEOUT)
    ap.add_argument("--clone-timeout",type=int,default=DEFAULT_CLONE_TIMEOUT)
    ap.add_argument("--max-commits-scan",type=int,default=DEFAULT_MAX_COMMITS_SCAN)
    ap.add_argument("--out",default=None)
    ap.add_argument("--recent",type=int,default=0)
    ap.add_argument("--fast",action="store_true")
    ap.add_argument("--no-complexity",action="store_true")
    ap.add_argument("--no-osv",action="store_true")
    ap.add_argument("--max-js-files",type=int,default=None)
    ap.add_argument("--time-cap-ms",type=int,default=None)
    ap.add_argument("--early-metrics",action="store_true")
    ap.add_argument("--always-commits",action="store_true")
    ap.add_argument("--export-enriched-osv",type=str,default=None)
    ap.add_argument("--commit-level-entry",action="store_true")
    ap.add_argument("--dep-change-recent",type=int,default=None,help="N commits recentes com mudança (add/rem) de deps")
    ap.add_argument("--removal-recent",type=int,default=None,help="N commits recentes com remoção de deps")
    args=ap.parse_args()

    # Map to env so subprocess worker vê
    if args.recent>0: os.environ["RECENT_COMMITS"]=str(args.recent)
    if args.fast: os.environ["FAST_MODE"]="1"
    if args.no_complexity: os.environ["NO_COMPLEXITY"]="1"
    if args.no_osv: os.environ["NO_OSV"]="1"
    if args.max_js_files is not None: os.environ["MAX_JS_FILES"]=str(args.max_js_files)
    if args.time_cap_ms is not None: os.environ["TIME_CAP_PER_COMMIT_MS"]=str(args.time_cap_ms)
    if args.early_metrics: os.environ["EARLY_METRICS"]="1"
    if args.always_commits: os.environ["ALWAYS_COMMITS"]="1"
    if args.export_enriched_osv: os.environ["EXPORT_ENRICHED_OSV"]=args.export_enriched_osv
    if args.commit_level_entry: os.environ["COMMIT_LEVEL_ENTRY"]="1"
    if args.dep_change_recent is not None: os.environ["DEP_CHANGE_RECENT_COMMITS"]=str(args.dep_change_recent)
    if args.removal_recent is not None: os.environ["REMOVAL_RECENT_COMMITS"]=str(args.removal_recent)

    res=analyze_repo(args.repo,
                     limit_commits=args.limit,
                     timeout_seconds=args.timeout,
                     clone_timeout=args.clone_timeout,
                     max_commits_scan=args.max_commits_scan)
    if args.out:
        os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
        with open(args.out,"w",encoding="utf-8") as f:
            json.dump(res,f,indent=2,ensure_ascii=False)
    print(json.dumps(res[:5],indent=2,ensure_ascii=False))