package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ---------------- Tipos ----------------

type Candidate struct {
	Repo              string                 `json:"repo"`
	Commit            string                 `json:"commit"`
	Parent            string                 `json:"parent"`
	CommitMessage     string                 `json:"commit_message"`
	CommitDate        string                 `json:"commit_date"`
	RemovedDep        string                 `json:"removed_dep"`
	RemovedDepDetails map[string]interface{} `json:"removed_dep_details"`
	MetricsBefore     map[string]interface{} `json:"metrics_before"`
	MetricsAfter      map[string]interface{} `json:"metrics_after"`
	NativeMigration   map[string]interface{} `json:"native_migration"`
	PkgBeforePaths    []string               `json:"pkg_before_paths"`
	PkgAfterPaths     []string               `json:"pkg_after_paths"`
}

type RepoResult struct {
	Repo           string      `json:"repo"`
	Candidates     []Candidate `json:"candidates"`
	Error          string      `json:"error,omitempty"`
	DurationMs     int64       `json:"duration_ms"`
	CommitsScanned int         `json:"commits_scanned"`
	Source         string      `json:"source"` // "api" ou "file"
}

// ---------------- Git Helpers ----------------

func runGit(ctx context.Context, dir string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("git %v failed: %v stderr=%s", args, err, errb.String())
	}
	return out.String(), nil
}

func cloneRepo(ctx context.Context, repo string, depth int, target string) error {
	args := []string{
		"clone",
		"--filter=blob:none",
		"--quiet",
		fmt.Sprintf("--depth=%d", depth),
		"--no-tags",
		"https://github.com/" + repo + ".git",
		target,
	}
	_, err := runGit(ctx, "", args...)
	return err
}

func listCommitsTouchingPkgJSON(ctx context.Context, dir string) ([]string, error) {
	out, err := runGit(ctx, dir, "log", "--pretty=format:%H", "--no-renames", "--diff-filter=AMDR", ":(glob)**/package.json")
	if err != nil {
		return nil, err
	}
	var commits []string
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		ll := strings.TrimSpace(l)
		if ll != "" {
			commits = append(commits, ll)
		}
	}
	return commits, nil
}

type CommitInfo struct {
	SHA      string
	Parent   string
	Message  string
	ISODate  string
	UnixTS   int64
	PkgPaths []string
}

func getCommitInfo(ctx context.Context, dir, sha string) (*CommitInfo, error) {
	pl, err := runGit(ctx, dir, "rev-list", "--parents", "-n", "1", sha)
	if err != nil {
		return nil, err
	}
	parts := strings.Fields(strings.TrimSpace(pl))
	var parent string
	if len(parts) >= 2 {
		parent = parts[1]
	}
	meta, err := runGit(ctx, dir, "show", "-s", "--format=%ct%x00%s%x00%cI", sha)
	if err != nil {
		return nil, err
	}
	split := strings.Split(meta, "\x00")
	var ts int64
	var msg, iso string
	if len(split) >= 3 {
		fmt.Sscanf(split[0], "%d", &ts)
		msg = split[1]
		iso = strings.TrimSpace(split[2])
	}
	pkgPaths, _ := listPkgJSONPathsAtCommit(ctx, dir, sha)
	return &CommitInfo{
		SHA:      sha,
		Parent:   parent,
		Message:  msg,
		ISODate:  iso,
		UnixTS:   ts,
		PkgPaths: pkgPaths,
	}, nil
}

func listPkgJSONPathsAtCommit(ctx context.Context, dir, sha string) ([]string, error) {
	out, err := runGit(ctx, dir, "ls-tree", "-r", "--name-only", sha)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, l := range strings.Split(out, "\n") {
		ll := strings.TrimSpace(l)
		if strings.HasSuffix(strings.ToLower(ll), "package.json") {
			paths = append(paths, ll)
		}
	}
	return paths, nil
}

func fileAtCommit(ctx context.Context, dir, sha, path string) (string, error) {
	out, err := runGit(ctx, dir, "show", fmt.Sprintf("%s:%s", sha, path))
	if err != nil {
		return "", err
	}
	return out, nil
}

// ---------------- Package.json parsing ----------------

func loadAllPackages(ctx context.Context, dir, sha string) (map[string]map[string]interface{}, []string) {
	paths, _ := listPkgJSONPathsAtCommit(ctx, dir, sha)
	res := make(map[string]map[string]interface{})
	for _, p := range paths {
		content, err := fileAtCommit(ctx, dir, sha, p)
		if err != nil {
			continue
		}
		var obj map[string]interface{}
		if json.Unmarshal([]byte(content), &obj) == nil {
			res[p] = obj
		}
	}
	return res, paths
}

func aggregateDeps(pkgs map[string]map[string]interface{}) (map[string]string, map[string]string) {
	deps := map[string]string{}
	dev := map[string]string{}
	for _, d := range pkgs {
		if dd, ok := d["dependencies"].(map[string]interface{}); ok {
			for k, v := range dd {
				if _, seen := deps[k]; !seen {
					deps[k] = fmt.Sprintf("%v", v)
				}
			}
		}
		if dv, ok := d["devDependencies"].(map[string]interface{}); ok {
			for k, v := range dv {
				if _, seen := dev[k]; !seen {
					dev[k] = fmt.Sprintf("%v", v)
				}
			}
		}
	}
	return deps, dev
}

func diffRemoved(before, after map[string]string) []string {
	var out []string
	for k := range before {
		if _, ok := after[k]; !ok {
			out = append(out, k)
		}
	}
	return out
}

func versionsFor(dep string, pkgs map[string]map[string]interface{}) []string {
	vers := map[string]struct{}{}
	for _, p := range pkgs {
		if dd, ok := p["dependencies"].(map[string]interface{}); ok {
			if v, ok2 := dd[dep]; ok2 {
				vers[fmt.Sprintf("%v", v)] = struct{}{}
			}
		}
		if dv, ok := p["devDependencies"].(map[string]interface{}); ok {
			if v, ok2 := dv[dep]; ok2 {
				vers[fmt.Sprintf("%v", v)] = struct{}{}
			}
		}
	}
	out := []string{}
	for v := range vers {
		out = append(out, v)
	}
	return out
}

// ---------------- Métricas ----------------

func computeMetrics(ctx context.Context, repoDir, sha string) map[string]interface{} {
	out, err := runGit(ctx, repoDir, "ls-tree", "-r", "--name-only", sha)
	if err != nil {
		return map[string]interface{}{"lines_of_code": 0, "avg_complexity": 0.0}
	}
	files := []string{}
	for _, l := range strings.Split(out, "\n") {
		ll := strings.TrimSpace(l)
		if ll == "" {
			continue
		}
		if strings.HasSuffix(ll, ".js") || strings.HasSuffix(ll, ".ts") || strings.HasSuffix(ll, ".jsx") || strings.HasSuffix(ll, ".tsx") {
			files = append(files, ll)
		}
	}
	totalLOC := 0
	totalComplex := 0
	fileCount := 0
	for _, f := range files {
		content, err := runGit(ctx, repoDir, "show", sha+":"+f)
		if err != nil {
			continue
		}
		lines := strings.Split(content, "\n")
		loc := 0
		comp := 0
		for _, ln := range lines {
			t := strings.TrimSpace(ln)
			if t == "" || strings.HasPrefix(t, "//") {
				continue
			}
			loc++
			if strings.Contains(t, "if ") || strings.Contains(t, "for ") || strings.Contains(t, "switch ") ||
				strings.Contains(t, "function") || strings.Contains(t, "=>") {
				comp++
			}
		}
		if loc > 0 {
			totalLOC += loc
			totalComplex += comp
			fileCount++
		}
	}
	avgComplex := 0.0
	if fileCount > 0 {
		avgComplex = float64(totalComplex) / float64(fileCount)
	}
	return map[string]interface{}{
		"lines_of_code":  totalLOC,
		"avg_complexity": avgComplex,
		"js_file_count":  fileCount,
	}
}

// ---------------- Migração nativa (heurística) ----------------

func grepPatterns(ctx context.Context, repoDir, sha string, patterns []string) int {
	total := 0
	for _, pat := range patterns {
		out, err := runGit(ctx, repoDir, "grep", "-I", "-n", "-E", pat, sha, "--", "*.js", "*.jsx", "*.ts", "*.tsx")
		if err != nil {
			continue
		}
		for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
			if strings.TrimSpace(l) != "" {
				total++
			}
		}
	}
	return total
}

func detectNativeMigration(ctx context.Context, repoDir, beforeSha, afterSha, dep string) map[string]interface{} {
	d := strings.ToLower(dep)
	var thirdPatterns, nativePatterns []string
	switch d {
	case "lodash", "underscore":
		thirdPatterns = []string{"lodash", "underscore", "_."}
		nativePatterns = []string{".map(", ".filter(", ".reduce(", "Object.assign(", "Object.keys("}
	case "left-pad":
		thirdPatterns = []string{"left-pad", "leftpad("}
		nativePatterns = []string{".padStart(", ".padEnd("}
	case "uuid":
		thirdPatterns = []string{"require(\"uuid\"", "from 'uuid'"}
		nativePatterns = []string{"crypto.randomUUID("}
	case "querystring":
		thirdPatterns = []string{"querystring"}
		nativePatterns = []string{"URLSearchParams("}
	case "node-fetch", "request":
		thirdPatterns = []string{"node-fetch", "request("}
		nativePatterns = []string{"fetch("}
	case "mkdirp":
		thirdPatterns = []string{"mkdirp("}
		nativePatterns = []string{"fs.mkdir(", "recursive: true"}
	case "rimraf":
		thirdPatterns = []string{"rimraf("}
		nativePatterns = []string{"fs.rm(", "recursive: true"}
	case "moment":
		thirdPatterns = []string{"moment("}
		nativePatterns = []string{"Intl.DateTimeFormat(", "Temporal."}
	default:
		thirdPatterns = []string{dep}
		nativePatterns = []string{"fetch(", ".map(", ".filter(", ".reduce(", ".padStart(", "crypto.randomUUID("}
	}
	thirdBefore := grepPatterns(ctx, repoDir, beforeSha, thirdPatterns)
	thirdAfter := grepPatterns(ctx, repoDir, afterSha, thirdPatterns)
	nativeBefore := grepPatterns(ctx, repoDir, beforeSha, nativePatterns)
	nativeAfter := grepPatterns(ctx, repoDir, afterSha, nativePatterns)
	evidence := thirdBefore > 0 && thirdAfter == 0 && nativeAfter > nativeBefore
	score := (nativeAfter - nativeBefore) - (thirdBefore - thirdAfter)
	return map[string]interface{}{
		"third_party_hits_before":     thirdBefore,
		"third_party_hits_after":      thirdAfter,
		"native_hits_before":          nativeBefore,
		"native_hits_after":           nativeAfter,
		"native_replacement_evidence": evidence,
		"native_migration_score":      score,
	}
}

// ---------------- Análise por repositório ----------------

func analyzeRepo(ctx context.Context, full string, maxCommits, commitLimit, depth int) ([]Candidate, int, error) {
	tmp, err := os.MkdirTemp("", "gomin_")
	if err != nil {
		return nil, 0, err
	}
	defer os.RemoveAll(tmp)
	repoDir := filepath.Join(tmp, strings.ReplaceAll(strings.Split(full, "/")[1], " ", "_"))
	cloneCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	if err := cloneRepo(cloneCtx, full, depth, repoDir); err != nil {
		return nil, 0, fmt.Errorf("clone fail: %w", err)
	}
	commits, err := listCommitsTouchingPkgJSON(ctx, repoDir)
	if err != nil {
		return nil, 0, err
	}
	originalCount := len(commits)
	if maxCommits > 0 && len(commits) > maxCommits {
		commits = commits[:maxCommits]
	}
	if commitLimit > 0 && len(commits) > commitLimit {
		commits = commits[:commitLimit]
	}

	candidates := []Candidate{}
	for _, sha := range commits {
		select {
		case <-ctx.Done():
			return candidates, originalCount, ctx.Err()
		default:
		}
		info, err := getCommitInfo(ctx, repoDir, sha)
		if err != nil || info.Parent == "" {
			continue
		}
		beforePkgs, beforePaths := loadAllPackages(ctx, repoDir, info.Parent)
		afterPkgs, afterPaths := loadAllPackages(ctx, repoDir, sha)
		if len(beforePkgs) == 0 {
			continue
		}
		depsBefore, _ := aggregateDeps(beforePkgs)
		depsAfter, _ := aggregateDeps(afterPkgs)
		removed := diffRemoved(depsBefore, depsAfter)
		if len(removed) == 0 {
			continue
		}
		metricsBefore := computeMetrics(ctx, repoDir, info.Parent)
		metricsAfter := computeMetrics(ctx, repoDir, sha)
		for _, dep := range removed {
			nat := detectNativeMigration(ctx, repoDir, info.Parent, sha, dep)
			c := Candidate{
				Repo:          full,
				Commit:        sha,
				Parent:        info.Parent,
				CommitMessage: info.Message,
				CommitDate:    info.ISODate,
				RemovedDep:    dep,
				RemovedDepDetails: map[string]interface{}{
					"versions_before": versionsFor(dep, beforePkgs),
					"versions_after":  versionsFor(dep, afterPkgs),
					"cve_count":       0,
					"cve_ids":         []string{},
				},
				MetricsBefore:   metricsBefore,
				MetricsAfter:    metricsAfter,
				NativeMigration: nat,
				PkgBeforePaths:  beforePaths,
				PkgAfterPaths:   afterPaths,
			}
			candidates = append(candidates, c)
		}
	}
	return candidates, originalCount, nil
}

// ---------------- Fetch de repositórios via GitHub API ----------------

type ghSearchResp struct {
	Items []struct {
		FullName string `json:"full_name"`
		Stargazers int  `json:"stargazers_count"`
	} `json:"items"`
}

func fetchReposFromGitHub(language string, minStars, count int, token string) ([]string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	base := "https://api.github.com/search/repositories"
	perPage := 100
	var all []string
	page := 1
	for len(all) < count {
		q := fmt.Sprintf("language:%s stars:>=%d", language, minStars)
		url := fmt.Sprintf("%s?q=%s&sort=stars&order=desc&per_page=%d&page=%d", base, urlQueryEscape(q), perPage, page)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("GitHub API status=%d body=%s", resp.StatusCode, string(body))
		}
		var sr ghSearchResp
		if err := json.Unmarshal(body, &sr); err != nil {
			return nil, err
		}
		if len(sr.Items) == 0 {
			break
		}
		for _, it := range sr.Items {
			all = append(all, it.FullName)
			if len(all) >= count {
				break
			}
		}
		page++
		// pequena pausa para evitar rate limit sem token
		if token == "" {
			time.Sleep(2 * time.Second)
		}
	}
	return all, nil
}

// URL escape manual simples (evitar importar net/url)
func urlQueryEscape(s string) string {
	replacer := strings.NewReplacer(" ", "+", ":", "%3A", ">=", "%3E%3D")
	return replacer.Replace(s)
}

// ---------------- Carregar repos de arquivo ----------------

func loadRepos(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, nil
	}
	var generic []map[string]interface{}
	if err := json.Unmarshal(data, &generic); err == nil {
		out := []string{}
		for _, o := range generic {
			if v, ok := o["repo"].(string); ok {
				out = append(out, v)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("formato inválido em %s", path)
}

// ---------------- Main ----------------

func main() {
	// Se você NÃO passar -repos, faremos fetch automático
	reposFile := flag.String("repos", "", "Arquivo JSON com lista de repos (opcional se usar fetch)")
	outFile := flag.String("out", "dataset.json", "Arquivo de saída")
	parallel := flag.Int("parallel", 3, "Repositórios simultâneos")
	repoTimeout := flag.Int("repoTimeout", 900, "Timeout por repositório (seg)")
	maxCommits := flag.Int("maxCommits", 600, "Máx commits tocando package.json (pré-corte)")
	commitLimit := flag.Int("commitLimit", 300, "Corte final de commits (0 = sem limite extra)")
	cloneDepth := flag.Int("cloneDepth", 2000, "Profundidade do clone raso")
	limit := flag.Int("limit", 0, "Limita número total de repositórios (0 = todos)")

	// Parâmetros de busca via API (se repos não fornecido)
	fetchLanguage := flag.String("fetchLanguage", "JavaScript", "Linguagem para busca automática")
	minStars := flag.Int("minStars", 5000, "Mínimo de estrelas para busca")
	fetchCount := flag.Int("fetchCount", 50, "Quantos repositórios buscar via API")
	flag.Parse()

	var repos []string
	source := "file"

	if *reposFile == "" {
		source = "api"
		token := os.Getenv("GITHUB_TOKEN")
		fmt.Printf("[fetch] buscando %d repos language=%s minStars=%d token=%v\n",
			*fetchCount, *fetchLanguage, *minStars, token != "")
		rs, err := fetchReposFromGitHub(*fetchLanguage, *minStars, *fetchCount, token)
		if err != nil {
			fmt.Println("ERRO busca API:", err)
			os.Exit(1)
		}
		repos = rs
	} else {
		rs, err := loadRepos(*reposFile)
		if err != nil {
			fmt.Println("ERRO carregando repos:", err)
			os.Exit(1)
		}
		repos = rs
	}

	if *limit > 0 && len(repos) > *limit {
		repos = repos[:*limit]
	}

	fmt.Printf("[start] repos=%d source=%s parallel=%d timeout=%ds depth=%d\n",
		len(repos), source, *parallel, *repoTimeout, *cloneDepth)

	results := make([]RepoResult, len(repos))
	var wg sync.WaitGroup
	sem := make(chan struct{}, *parallel)

	for i, r := range repos {
		wg.Add(1)
		sem <- struct{}{}
		go func(idx int, repo string) {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*repoTimeout)*time.Second)
			defer cancel()
			start := time.Now()
			cands, scanned, err := analyzeRepo(ctx, repo, *maxCommits, *commitLimit, *cloneDepth)
			res := RepoResult{
				Repo:           repo,
				Candidates:     cands,
				DurationMs:     time.Since(start).Milliseconds(),
				CommitsScanned: scanned,
				Source:         source,
			}
			if err != nil {
				res.Error = err.Error()
			}
			results[idx] = res
			fmt.Printf("[done] %s candidates=%d commits_scanned=%d err=%v time=%dms\n",
				repo, len(cands), scanned, err, res.DurationMs)
		}(i, r)
	}

	wg.Wait()

	f, err := os.Create(*outFile)
	if err != nil {
		fmt.Println("ERRO criando saída:", err)
		os.Exit(1)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		fmt.Println("ERRO escrevendo JSON:", err)
		os.Exit(1)
	}
	totalCand := 0
	for _, rr := range results {
		totalCand += len(rr.Candidates)
	}
	fmt.Printf("[ok] dataset salvo em %s | total_candidates=%d\n", *outFile, totalCand)

	// Mini resumo textual para você colar no artigo rapidamente:
	fmt.Printf("[resumo] Linguagem=%s minStars=%d reposProcessados=%d timeoutRepo=%ds maxCommits=%d commitLimit=%d depth=%d\n",
		*fetchLanguage, *minStars, len(repos), *repoTimeout, *maxCommits, *commitLimit, *cloneDepth)
}