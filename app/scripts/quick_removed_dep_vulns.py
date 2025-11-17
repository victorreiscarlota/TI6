#!/usr/bin/env python3
"""
Remoções de dependências + segurança (OSV) com LOGS.

Logs:
- clone + tempo
- commits list + tempo
- por commit (se LOG_COMMIT=1) incluindo tempo métricas/OSV
- OSV por pacote (LOG_OSV=1)
- métricas detalhadas (LOG_METRICS=1)
"""

import argparse, json, os, subprocess, tempfile, time, re
from typing import List, Dict, Optional, Tuple

try:
    import lizard  # type: ignore
except Exception:
    lizard = None
try:
    import requests
except Exception:
    requests = None

GIT="git"
JS_EXTS=(".js",".jsx",".ts",".tsx")
SECURITY_KEYWORDS=["security","vulnerability","vulnerab","advisory","cve","ghsa","dependabot","snyk","cvss","severity","fix","patch","upgrade","bump","mitigate","exploit","xss","rce","csp","csrf"]
CVE_RE=re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)
GHSA_RE=re.compile(r"\bGHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}\b", re.IGNORECASE)

LOG_COMMIT=bool(int(os.environ.get("LOG_COMMIT","0") or "0"))
LOG_OSV=bool(int(os.environ.get("LOG_OSV","0") or "0"))
LOG_METRICS=bool(int(os.environ.get("LOG_METRICS","0") or "0"))

def log(msg: str):
    print(f"[quick_removed_dep_vulns] {msg}", flush=True)

def run_git(args: List[str], cwd: Optional[str]=None, timeout: Optional[int]=None) -> str:
    t0=time.perf_counter()
    p=subprocess.run([GIT]+args,cwd=cwd,capture_output=True,text=True,encoding="utf-8",errors="replace",timeout=timeout)
    dt=(time.perf_counter()-t0)*1000
    if p.returncode!=0:
        raise RuntimeError(f"git {' '.join(args)} failed ({p.returncode}) in {dt:.1f}ms: {p.stderr[:300]}")
    return p.stdout

def clone_repo(full:str, depth:int, target:str, timeout:int):
    t0=time.perf_counter()
    run_git(["clone","--filter=blob:none","--quiet",f"--depth={depth}","--no-tags",f"https://github.com/{full}.git",target],timeout=timeout)
    log(f"clone repo={full} depth={depth} time_ms={(time.perf_counter()-t0)*1000:.1f}")

def recent_commits_touching_pkg_json(repo_dir:str,n:int)->List[str]:
    t0=time.perf_counter()
    out=run_git(["-C",repo_dir,"log","-n",str(n),"--pretty=format:%H","--no-renames","--diff-filter=AMDR",":(glob)**/package.json"])
    lines=[l.strip() for l in out.splitlines() if l.strip()]
    log(f"list commits recent={n} count={len(lines)} time_ms={(time.perf_counter()-t0)*1000:.1f}")
    return lines

def all_commits_touching_pkg_json(repo_dir:str)->List[str]:
    t0=time.perf_counter()
    out=run_git(["-C",repo_dir,"log","--pretty=format:%H","--no-renames","--diff-filter=AMDR",":(glob)**/package.json"])
    lines=[l.strip() for l in out.splitlines() if l.strip()]
    log(f"list commits all count={len(lines)} time_ms={(time.perf_counter()-t0)*1000:.1f}")
    return lines

def commit_info(repo_dir:str, sha:str)->Tuple[str,str,str]:
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

def osv_query(pkg:str, session, cache:Dict[str,dict])->dict:
    key=f"npm:{pkg}"
    if key in cache: return cache[key]
    if session is None or requests is None:
        cache[key]={}; return cache[key]
    t0=time.perf_counter()
    try:
        r=session.post("https://api.osv.dev/v1/query",json={"package":{"name":pkg,"ecosystem":"npm"}},timeout=8)
        data=r.json() if r.status_code==200 else {}
    except Exception:
        data={}
    dt=(time.perf_counter()-t0)*1000
    cache[key]=data
    if LOG_OSV:
        vulns=len(data.get("vulns",[]) if isinstance(data,dict) else [])
        log(f"OSV pkg={pkg} vulns={vulns} time_ms={dt:.1f}")
    return data

def vuln_package_count(dep_names, session, cache)->int:
    t0=time.perf_counter()
    c=0
    for n in dep_names:
        resp=osv_query(n, session, cache)
        vulns=resp.get("vulns")
        if isinstance(vulns,list) and vulns:
            c+=1
    dt=(time.perf_counter()-t0)*1000
    if LOG_COMMIT:
        log(f"OSV aggregate dep_total={len(dep_names)} vulnerable={c} time_ms={dt:.1f}")
    return c

def extract_vulns(osv_resp:dict, versions_before:List[str])->List[dict]:
    vulns=osv_resp.get("vulns")
    if not isinstance(vulns,list): return []
    versions_set=set(versions_before or [])
    out=[]
    for v in vulns:
        vid=v.get("id","")
        summary=v.get("summary") or (v.get("details","")[:180])
        published=v.get("published","")
        aliases=v.get("aliases",[])
        refs=[r.get("url") for r in (v.get("references") or []) if isinstance(r,dict) and r.get("url")]
        max_cvss=None
        for sev in v.get("severity",[]) or []:
            sc=sev.get("score")
            if sc and sc.replace(".","",1).isdigit():
                val=float(sc); max_cvss=val if max_cvss is None else max(max_cvss,val)
        exact=False
        for aff in v.get("affected",[]) or []:
            for vers in aff.get("versions",[]) or []:
                if vers in versions_set:
                    exact=True; break
            if exact: break
        out.append({
            "id":vid,"summary":summary,"published":published,
            "aliases":aliases,"references":refs,"max_cvss":max_cvss,
            "version_exact_match":exact
        })
    return out

def iso_to_epoch(iso:str)->Optional[int]:
    if not iso: return None
    try:
        from datetime import datetime
        dt=datetime.fromisoformat(iso.replace("Z","+00:00"))
        return int(dt.timestamp())
    except Exception:
        return None

def commit_msg_hits(msg:str)->List[str]:
    hits=[]
    if not msg: return hits
    hits.extend(CVE_RE.findall(msg))
    hits.extend(GHSA_RE.findall(msg))
    low=msg.lower()
    for kw in SECURITY_KEYWORDS:
        if kw in low: hits.append(kw)
    seen=set(); uniq=[]
    for h in hits:
        if h not in seen:
            seen.add(h); uniq.append(h)
    return uniq

def process_repo(full:str,
                 recent:int,
                 commit_limit:int,
                 depth:int,
                 clone_timeout:int,
                 include_osv:bool,
                 use_complexity:bool,
                 osv_cache_path:str)->List[dict]:
    import shutil
    t_repo=time.perf_counter()
    tmp=tempfile.mkdtemp(prefix="rmf_")
    repo_dir=os.path.join(tmp, full.split("/")[-1])
    session=requests.Session() if (include_osv and requests is not None) else None
    cache=load_osv_cache(osv_cache_path) if include_osv else {}
    rows=[]
    try:
        clone_repo(full, depth, repo_dir, timeout=clone_timeout)
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
            before_pkgs=load_all_pkgs(repo_dir, parent)
            after_pkgs =load_all_pkgs(repo_dir, sha)
            if not before_pkgs:
                if LOG_COMMIT: log(f"commit={sha[:7]} skip(no before pkg.json)")
                continue

            deps_b, dev_b = aggregate_deps(before_pkgs)
            deps_a, dev_a = aggregate_deps(after_pkgs)
            names_before=set(deps_b.keys()) | set(dev_b.keys())
            names_after =set(deps_a.keys()) | set(dev_a.keys())
            dep_before=len(names_before); dep_after=len(names_after)
            removed=[d for d in deps_b.keys() if d not in deps_a]
            if not removed:
                if LOG_COMMIT: log(f"commit={sha[:7]} no removals time_ms={(time.perf_counter()-t_commit)*1000:.1f}")
                continue

            vul_before = vuln_package_count(names_before, session, cache) if include_osv else 0
            vul_after  = vuln_package_count(names_after, session, cache) if include_osv else 0

            mb=compute_metrics(repo_dir, parent, use_complexity)
            ma=compute_metrics(repo_dir, sha, use_complexity)

            commit_epoch=iso_to_epoch(iso) or 0
            msg_hits=commit_msg_hits(subj or "")

            for dep in removed:
                versions_before=[]
                for pkg in before_pkgs.values():
                    for sect in ("dependencies","devDependencies"):
                        v=(pkg.get(sect) or {}).get(dep)
                        if v and v not in versions_before:
                            versions_before.append(str(v))
                vulns=[]
                advisory_before=False
                if include_osv:
                    resp=osv_query(dep, session, cache)
                    vulns=extract_vulns(resp, versions_before)
                    for vv in vulns:
                        pub=iso_to_epoch(vv.get("published","") or "")
                        if pub and pub<=commit_epoch:
                            advisory_before=True; break
                likely_security = advisory_before and bool(msg_hits)
                rows.append({
                    "repo": full,
                    "commit": sha,
                    "commit_date": iso,
                    "commit_message": subj,
                    "removed_dep": dep,
                    "versions_before": versions_before,
                    "dependencies_before": dep_before,
                    "dependencies_after": dep_after,
                    "vulnerable_dependencies_before": vul_before,
                    "vulnerable_dependencies_after": vul_after,
                    "lines_of_code_before": mb["lines_of_code"],
                    "lines_of_code_after":  ma["lines_of_code"],
                    "avg_complexity_before": mb["avg_complexity"],
                    "avg_complexity_after":  ma["avg_complexity"],
                    "vulns": vulns,
                    "advisory_before_commit": advisory_before,
                    "commit_msg_hits": msg_hits,
                    "likely_security_removal": likely_security
                })
            if LOG_COMMIT:
                log(f"commit={sha[:7]} removals={len(removed)} dep_before={dep_before} dep_after={dep_after} vuln_before={vul_before} vuln_after={vul_after} time_ms={(time.perf_counter()-t_commit)*1000:.1f}")

        dt_repo=(time.perf_counter()-t_repo)*1000
        log(f"repo={full} finished removals={len(rows)} time_ms={dt_repo:.1f} avg_per_removal_ms={(dt_repo/len(rows)) if rows else 0:.1f}")
        return rows
    finally:
        if include_osv: save_osv_cache(osv_cache_path, cache)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

def load_repos_file(path:str)->List[str]:
    data=json.load(open(path,"r",encoding="utf-8"))
    if isinstance(data,list):
        out=[]
        for item in data:
            if isinstance(item,str): out.append(item)
            elif isinstance(item,dict):
                if item.get("repo"): out.append(item["repo"])
                elif item.get("name"): out.append(item["name"])
        return out
    raise ValueError("repos file inválido")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--repo", type=str)
    ap.add_argument("--repos-file", type=str)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--recent", type=int, default=0)
    ap.add_argument("--commit-limit", type=int, default=0)
    ap.add_argument("--clone-depth", type=int, default=2000)
    ap.add_argument("--clone-timeout", type=int, default=600)
    ap.add_argument("--include-osv", action="store_true")
    ap.add_argument("--osv-cache", type=str, default="osv_cache_removed.json")
    ap.add_argument("--no-complexity", action="store_true")
    ap.add_argument("--no-osv", action="store_true")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--removals-output", type=str, default="removed_dep_vulns.json")
    args=ap.parse_args()

    if args.fast:
        if args.recent<=0: args.recent=10
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
        print("Use --repo ou --repos-file"); return

    include_osv_effective=(args.include_osv and not args.no_osv)
    use_complexity=(not args.no_complexity)

    t_global=time.perf_counter()
    all_rows=[]
    for r in targets:
        try:
            rows=process_repo(r,args.recent,args.commit_limit,args.clone_depth,
                              args.clone_timeout,include_osv_effective,use_complexity,
                              args.osv_cache)
            all_rows.extend(rows)
        except Exception as e:
            log(f"repo={r} error={e}")

    json.dump(all_rows, open(args.removals_output,"w",encoding="utf-8"), indent=2, ensure_ascii=False)
    dt=(time.perf_counter()-t_global)*1000
    log(f"ALL repos done removals_total={len(all_rows)} time_ms={dt:.1f}")
    print(f"[ok] wrote {args.removals_output} removals={len(all_rows)}")

if __name__=="__main__":
    main()