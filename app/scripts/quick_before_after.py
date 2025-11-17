#!/usr/bin/env python3
"""
Before/After metrics com LOGS.

Logs:
- clone (tempo)
- commits list (tempo)
- por commit (se LOG_COMMIT=1)
- métricas (se LOG_METRICS=1)
- OSV por pacote (se LOG_OSV=1)

Variáveis ambiente:
  LOG_COMMIT=1 LOG_METRICS=1 LOG_OSV=1
"""
import argparse, json, os, sys, subprocess, tempfile, time, re
from typing import List, Dict, Tuple, Optional

try:
    import lizard  # type: ignore
except Exception:
    lizard = None
try:
    import requests
except Exception:
    requests = None

GIT = "git"
JS_EXTS = (".js",".jsx",".ts",".tsx")

LOG_COMMIT = bool(int(os.environ.get("LOG_COMMIT","0") or "0"))
LOG_OSV = bool(int(os.environ.get("LOG_OSV","0") or "0"))
LOG_METRICS = bool(int(os.environ.get("LOG_METRICS","0") or "0"))

def log(msg: str):
    print(f"[quick_before_after] {msg}", flush=True)

def run_git(args: List[str], cwd: Optional[str]=None, timeout: Optional[int]=None) -> str:
    t0=time.perf_counter()
    p=subprocess.run([GIT]+args, cwd=cwd, capture_output=True, text=True,
                     encoding="utf-8", errors="replace", timeout=timeout)
    dt=(time.perf_counter()-t0)*1000
    if p.returncode!=0:
        raise RuntimeError(f"git {' '.join(args)} failed ({p.returncode}) in {dt:.1f}ms: {p.stderr[:400]}")
    return p.stdout

def clone_repo(full: str, depth: int, target: str, timeout: int):
    t0=time.perf_counter()
    run_git(["clone","--filter=blob:none","--quiet",f"--depth={depth}","--no-tags",f"https://github.com/{full}.git",target], timeout=timeout)
    log(f"clone repo={full} depth={depth} time_ms={(time.perf_counter()-t0)*1000:.1f}")

def recent_commits_touching_pkg_json(repo_dir: str, n: int) -> List[str]:
    t0=time.perf_counter()
    out=run_git(["-C",repo_dir,"log","-n",str(n),"--pretty=format:%H","--no-renames","--diff-filter=AMDR",":(glob)**/package.json"])
    lines=[l.strip() for l in out.splitlines() if l.strip()]
    log(f"list commits recent={n} count={len(lines)} time_ms={(time.perf_counter()-t0)*1000:.1f}")
    return lines

def all_commits_touching_pkg_json(repo_dir: str)->List[str]:
    t0=time.perf_counter()
    out=run_git(["-C",repo_dir,"log","--pretty=format:%H","--no-renames","--diff-filter=AMDR",":(glob)**/package.json"])
    lines=[l.strip() for l in out.splitlines() if l.strip()]
    log(f"list commits all count={len(lines)} time_ms={(time.perf_counter()-t0)*1000:.1f}")
    return lines

def commit_info(repo_dir: str, sha: str) -> Tuple[str,str,str]:
    out=run_git(["-C",repo_dir,"rev-list","--parents","-n","1",sha]).strip()
    parts=out.split()
    parent=parts[1] if len(parts)>=2 else ""
    meta=run_git(["-C",repo_dir,"show","-s","--format=%s%x00%cI",sha])
    sp=meta.split("\x00")
    subj=sp[0].strip() if sp else ""
    iso =sp[1].strip() if len(sp)>1 else ""
    return parent, subj, iso

def list_paths_at_commit(repo_dir:str, sha:str)->List[str]:
    out=run_git(["-C",repo_dir,"ls-tree","-r","--name-only",sha])
    return [l.strip() for l in out.splitlines() if l.strip()]

def git_show(repo_dir:str, sha:str, path:str)->str:
    try:
        return run_git(["-C",repo_dir,"show",f"{sha}:{path}"])
    except Exception:
        return ""

def list_pkg_json_paths(repo_dir:str, sha:str)->List[str]:
    return [p for p in list_paths_at_commit(repo_dir, sha) if p.lower().endswith("package.json")]

def load_package_json(repo_dir:str, sha:str, path:str)->Optional[dict]:
    txt=git_show(repo_dir, sha, path)
    if not txt: return None
    try: return json.loads(txt)
    except Exception: return None

def load_all_pkgs(repo_dir:str, sha:str)->Dict[str,dict]:
    t0=time.perf_counter()
    data={}
    for p in list_pkg_json_paths(repo_dir, sha):
        pj=load_package_json(repo_dir, sha, p)
        if pj: data[p]=pj
    if LOG_COMMIT:
        log(f"load pkgjson commit={sha[:7]} count={len(data)} time_ms={(time.perf_counter()-t0)*1000:.1f}")
    return data

def aggregate_deps(pkgs:Dict[str,dict])->Tuple[Dict[str,str],Dict[str,str]]:
    deps,dev={},{}
    for pkg in pkgs.values():
        d=pkg.get("dependencies") or {}
        dv=pkg.get("devDependencies") or {}
        for k,v in d.items():  deps.setdefault(k,str(v))
        for k,v in dv.items(): dev.setdefault(k,str(v))
    return deps,dev

def iter_js_files(repo_dir:str, sha:str):
    for p in list_paths_at_commit(repo_dir, sha):
        pl=p.lower()
        if pl.endswith(JS_EXTS) and not pl.endswith(".d.ts"):
            yield p

FALLBACK_TOKENS=(" if "," for "," while ","case "," switch "," catch"," else if"," =>"," function ")

def compute_metrics(repo_dir:str, sha:str, use_complexity:bool)->Dict[str,object]:
    t0=time.perf_counter()
    total_loc=0
    complexities=[]
    files=list(iter_js_files(repo_dir, sha))
    if not use_complexity:
        for path in files:
            code=git_show(repo_dir, sha, path)
            if not code: continue
            total_loc+=sum(1 for ln in code.splitlines() if ln.strip())
        if LOG_METRICS:
            log(f"metrics commit={sha[:7]} files={len(files)} LOC={total_loc} complexity=OFF time_ms={(time.perf_counter()-t0)*1000:.1f}")
        return {"lines_of_code": total_loc, "avg_complexity": 0.0, "files_scanned": len(files), "complexity_tool":"off"}
    for path in files:
        code=git_show(repo_dir, sha, path)
        if not code: continue
        loc=sum(1 for ln in code.splitlines() if ln.strip())
        total_loc+=loc
        if lizard is not None:
            try:
                res=lizard.analyze_file.analyze_source_code(path, code)  # type: ignore
                for fn in getattr(res,"function_list",[]) or []:
                    cc=getattr(fn,"cyclomatic_complexity",None)
                    if isinstance(cc,int): complexities.append(cc)
            except Exception: pass
        else:
            low=" "+code.lower()+" "
            c=0
            for tok in FALLBACK_TOKENS:
                c+=low.count(tok)
            complexities.append(max(0,c))
    avg_c=float(sum(complexities)/len(complexities)) if complexities else 0.0
    if LOG_METRICS:
        log(f"metrics commit={sha[:7]} files={len(files)} LOC={total_loc} avg_complexity={avg_c:.3f} tool={'lizard' if lizard else 'fallback'} time_ms={(time.perf_counter()-t0)*1000:.1f}")
    return {"lines_of_code": total_loc, "avg_complexity": avg_c, "files_scanned": len(files),
            "complexity_tool": "lizard" if lizard else "fallback"}

def load_osv_cache(path:str)->Dict[str,dict]:
    if os.path.exists(path):
        try: return json.load(open(path,"r",encoding="utf-8"))
        except Exception: return {}
    return {}

def save_osv_cache(path:str, cache:Dict[str,dict]):
    try: json.dump(cache, open(path,"w",encoding="utf-8"), indent=2, ensure_ascii=False)
    except Exception: pass

def osv_query_count(pkg: str, session, cache: Dict[str, dict]) -> int:
    key = f"npm:{pkg}"
    if key in cache:
        data = cache[key]
    else:
        if session is None or requests is None:
            cache[key] = {}
            return 0
        t0=time.perf_counter()
        try:
            r = session.post("https://api.osv.dev/v1/query",
                             json={"package": {"name": pkg, "ecosystem": "npm"}},
                             timeout=8)
            data = r.json() if r.status_code == 200 else {}
        except Exception:
            data = {}
        dt=(time.perf_counter()-t0)*1000
        cache[key] = data
        if LOG_OSV:
            vulns=len(data.get("vulns",[]) if isinstance(data,dict) else [])
            log(f"OSV pkg={pkg} vulns={vulns} time_ms={dt:.1f}")
    vulns = data.get("vulns") if isinstance(data, dict) else None
    return len(vulns) if isinstance(vulns, list) else 0

def vuln_dep_count(dep_names: List[str], session, cache: Dict[str, dict]) -> int:
    t0=time.perf_counter()
    c = 0
    for name in dep_names:
        if osv_query_count(name, session, cache) > 0:
            c += 1
    if LOG_COMMIT:
        log(f"OSV aggregate dep_total={len(dep_names)} vulnerable={c} time_ms={(time.perf_counter()-t0)*1000:.1f}")
    return c

def process_repo(full: str,
                 commit_limit: int,
                 recent: int,
                 clone_depth: int,
                 clone_timeout: int,
                 include_osv: bool,
                 osv_cache_path: str,
                 use_complexity: bool) -> List[dict]:
    t_repo0=time.perf_counter()
    tmp_root=tempfile.mkdtemp(prefix="ba_")
    repo_dir=os.path.join(tmp_root, full.split("/")[-1])
    session=requests.Session() if (include_osv and requests is not None) else None
    osv_cache=load_osv_cache(osv_cache_path) if include_osv else {}
    results=[]
    commits_processed=0
    try:
        clone_repo(full, clone_depth, repo_dir, timeout=clone_timeout)
        commits = recent_commits_touching_pkg_json(repo_dir, recent) if recent>0 else all_commits_touching_pkg_json(repo_dir)
        if commit_limit and len(commits)>commit_limit:
            commits=commits[:commit_limit]
        log(f"repo={full} commit_candidates={len(commits)} recent={recent} limit={commit_limit}")

        for sha in commits:
            t_commit=time.perf_counter()
            parent, subj, iso = commit_info(repo_dir, sha)
            if not parent:
                if LOG_COMMIT: log(f"commit={sha[:7]} skip(no parent)")
                continue
            before_pkgs = load_all_pkgs(repo_dir, parent)
            after_pkgs  = load_all_pkgs(repo_dir, sha)
            if not before_pkgs:
                if LOG_COMMIT: log(f"commit={sha[:7]} skip(no before pkg.json)")
                continue

            deps_b, dev_b = aggregate_deps(before_pkgs)
            deps_a, dev_a = aggregate_deps(after_pkgs)

            dep_names_before = sorted(set(list(deps_b.keys()) + list(dev_b.keys())))
            dep_names_after  = sorted(set(list(deps_a.keys()) + list(dev_a.keys())))
            dependencies_before = len(dep_names_before)
            dependencies_after  = len(dep_names_after)

            if include_osv:
                vb = vuln_dep_count(dep_names_before, session, osv_cache)
                va = vuln_dep_count(dep_names_after, session, osv_cache)
            else:
                vb = va = 0

            mb = compute_metrics(repo_dir, parent, use_complexity)
            ma = compute_metrics(repo_dir, sha, use_complexity)

            rec = {
                "repo": full,
                "commit": sha,
                "commit_date": iso,
                "commit_message": subj,
                "lines_of_code_before": mb.get("lines_of_code", 0),
                "lines_of_code_after":  ma.get("lines_of_code", 0),
                "avg_complexity_before": mb.get("avg_complexity", 0.0),
                "avg_complexity_after":  ma.get("avg_complexity", 0.0),
                "dependencies_before": dependencies_before,
                "dependencies_after":  dependencies_after,
                "vulnerable_dependencies_before": vb,
                "vulnerable_dependencies_after":  va,
            }
            results.append(rec)
            commits_processed+=1
            if LOG_COMMIT:
                log(f"commit={sha[:7]} done dep_before={dependencies_before} dep_after={dependencies_after} vuln_before={vb} vuln_after={va} time_ms={(time.perf_counter()-t_commit)*1000:.1f}")

        repo_dt=(time.perf_counter()-t_repo0)*1000
        log(f"repo={full} finished commits={commits_processed} total_ms={repo_dt:.1f} avg_ms={(repo_dt/commits_processed) if commits_processed else 0:.1f}")
        return results
    finally:
        if include_osv:
            save_osv_cache(osv_cache_path, osv_cache)
        import shutil
        shutil.rmtree(tmp_root, ignore_errors=True)

def load_repos_file(path: str) -> List[str]:
    data=json.load(open(path,"r",encoding="utf-8"))
    if isinstance(data,list):
        out=[]
        for item in data:
            if isinstance(item,str): out.append(item)
            elif isinstance(item,dict):
                if item.get("repo"): out.append(item["repo"])
                elif item.get("name"): out.append(item["name"])
        return out
    raise ValueError("repos file deve ser lista")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--repo", type=str)
    ap.add_argument("--repos-file", type=str)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--commit-limit", type=int, default=0)
    ap.add_argument("--recent", type=int, default=0)
    ap.add_argument("--clone-depth", type=int, default=2000)
    ap.add_argument("--clone-timeout", type=int, default=600)
    ap.add_argument("--include-osv", action="store_true")
    ap.add_argument("--osv-cache", type=str, default="osv_cache.json")
    ap.add_argument("--no-complexity", action="store_true")
    ap.add_argument("--no-osv", action="store_true")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--output", type=str, default="before_after.json")
    args=ap.parse_args()

    if args.fast:
        if args.recent <=0: args.recent=10
        args.no_complexity=True
        args.no_osv=True
        if args.clone_depth==2000: args.clone_depth=200

    targets=[]
    if args.repo:
        targets=[args.repo]
    elif args.repos_file:
        repos=load_repos_file(args.repos_file)
        if args.limit and len(repos)>args.limit:
            repos=repos[:args.limit]
        targets=repos
    else:
        print("Use --repo ou --repos-file", file=sys.stderr); sys.exit(2)

    include_osv_effective = (args.include_osv and not args.no_osv)
    use_complexity = (not args.no_complexity)

    t_global=time.perf_counter()
    all_rows=[]
    for r in targets:
        try:
            rows=process_repo(r, args.commit_limit, args.recent, args.clone_depth,
                              args.clone_timeout, include_osv_effective,
                              args.osv_cache, use_complexity)
            all_rows.extend(rows)
        except Exception as e:
            log(f"repo={r} error={e}")

    with open(args.output,"w",encoding="utf-8") as f:
        json.dump(all_rows,f,indent=2,ensure_ascii=False)
    dt=(time.perf_counter()-t_global)*1000
    log(f"ALL repos done total_records={len(all_rows)} time_ms={dt:.1f}")
    print(f"[ok] wrote {args.output} records={len(all_rows)}")

if __name__=="__main__":
    main()