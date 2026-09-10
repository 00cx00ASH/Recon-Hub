// int-github-audit — audita a superfície PÚBLICA de uma conta/org do GitHub (ou
// um repo): enumera repos, procura arquivos sensíveis e segredos nos arquivos e
// gists, e analisa os workflows do Actions por pwn-request / injeção de shell.
// Um github_token (opcional) sobe o rate limit de 60 p/ 5000 req/h.
// Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type payload struct {
	Target string         `json:"target"`
	Params map[string]any `json:"params"`
	JobID  string         `json:"job_id"`
}

type ev struct {
	Type        string         `json:"type"`
	Level       string         `json:"level,omitempty"`
	Msg         string         `json:"msg,omitempty"`
	Kind        string         `json:"kind,omitempty"`
	Value       string         `json:"value,omitempty"`
	Severity    string         `json:"severity,omitempty"`
	FindingType string         `json:"finding_type,omitempty"`
	Title       string         `json:"title,omitempty"`
	Asset       string         `json:"asset,omitempty"`
	Evidence    string         `json:"evidence,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
	OK          bool           `json:"ok,omitempty"`
}

var (
	out    = bufio.NewWriter(os.Stdout)
	pretty bool
	finds  int
)

func emit(e ev) {
	if e.Type == "finding" {
		finds++
	}
	if pretty {
		switch e.Type {
		case "finding":
			fmt.Fprintf(out, "[%s] %s\n        %s\n", strings.ToUpper(e.Severity), e.Title, e.Evidence)
		case "asset":
			fmt.Fprintln(out, "  ["+e.Kind+"] "+e.Value)
		case "done":
			fmt.Fprintln(out, "done: "+e.Msg)
		case "error":
			fmt.Fprintln(out, "erro: "+e.Msg)
		default:
			lv := e.Level
			if lv == "" {
				lv = "info"
			}
			fmt.Fprintf(out, "[%s] %s\n", lv, e.Msg)
		}
	} else {
		b, _ := json.Marshal(e)
		out.Write(b)
		out.WriteByte('\n')
	}
	out.Flush()
}

func main() {
	var (
		flagTarget = flag.String("target", "", "login de org/usuário, ou owner/repo")
		flagToken  = flag.String("github-token", "", "token do GitHub (opcional, sobe o rate limit)")
		flagMaxR   = flag.Int("max-repos", 0, "teto de repos a inspecionar (0 = param/25)")
		flagNoGist = flag.Bool("no-gists", false, "não olhar os gists")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/15000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 15000)) * time.Millisecond
	maxRepos := pick(*flagMaxR, intParam(pl.Params, "max_repos"), 25)
	doGists := !*flagNoGist && !boolParam(pl.Params, "no_gists")
	token := firstNonEmpty(*flagToken, strParam(pl.Params, "github_token"), os.Getenv("RECONHUB_PARAM_GITHUB_TOKEN"), os.Getenv("GITHUB_TOKEN"))

	tgt := strings.TrimSpace(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	tgt = strings.TrimPrefix(tgt, "https://github.com/")
	tgt = strings.Trim(tgt, "/")
	if tgt == "" {
		emit(ev{Type: "error", Msg: "informe um login de org/usuário, ou owner/repo"})
		os.Exit(2)
	}

	gh := newGH(token, timeout)
	auth := "sem token (60 req/h)"
	if token != "" {
		auth = "com token (5000 req/h)"
	}
	emit(ev{Type: "log", Level: "info", Msg: "auditando " + tgt + " — " + auth})

	var repos []ghRepo
	var owner string

	if strings.Contains(tgt, "/") {
		owner = strings.SplitN(tgt, "/", 2)[0]
		b, st, err := gh.get("/repos/" + tgt)
		if err != nil || st != 200 {
			emit(ev{Type: "error", Msg: fmt.Sprintf("repo %s: HTTP %d %v", tgt, st, err)})
			os.Exit(1)
		}
		var r ghRepo
		decodeJSON(b, &r)
		repos = []ghRepo{r}
	} else {
		owner = tgt
		accountInfo(gh, tgt)
		repos = listRepos(gh, tgt, maxRepos)
	}
	if len(repos) == 0 {
		emit(ev{Type: "done", OK: true, Msg: "nenhum repositório público"})
		return
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d repo(s) a inspecionar", len(repos))})

	for _, r := range repos {
		if gh.exhausted {
			emit(ev{Type: "log", Level: "warn", Msg: "rate limit esgotado — parando"})
			break
		}
		auditRepo(gh, r)
	}

	if doGists && !strings.Contains(tgt, "/") && !gh.exhausted {
		auditGists(gh, owner)
	}

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d repo(s), %d finding(s) (rate limit restante: %d)", len(repos), finds, gh.remain)})
}

func accountInfo(gh *ghClient, login string) {
	for _, ep := range []string{"/orgs/" + login, "/users/" + login} {
		b, st, err := gh.get(ep)
		if err != nil || st != 200 {
			continue
		}
		var a struct {
			Login       string `json:"login"`
			Type        string `json:"type"`
			Name        string `json:"name"`
			Company     string `json:"company"`
			Blog        string `json:"blog"`
			Email       string `json:"email"`
			PublicRepos int    `json:"public_repos"`
			PublicGists int    `json:"public_gists"`
			CreatedAt   string `json:"created_at"`
		}
		decodeJSON(b, &a)
		emit(ev{Type: "asset", Kind: "url", Value: "https://github.com/" + a.Login})
		emit(ev{Type: "finding", Severity: "info", FindingType: "github-account",
			Title: fmt.Sprintf("conta GitHub: %s (%s)", a.Login, a.Type),
			Asset: "https://github.com/" + a.Login,
			Evidence: fmt.Sprintf("%s · %d repos públicos · %d gists · blog %q · email %q · desde %s",
				a.Name, a.PublicRepos, a.PublicGists, a.Blog, a.Email, firstWords(a.CreatedAt, 1)),
			Meta: map[string]any{"login": a.Login, "type": a.Type, "public_repos": a.PublicRepos,
				"public_gists": a.PublicGists, "email": a.Email, "blog": a.Blog}})
		return
	}
}

func listRepos(gh *ghClient, login string, max int) []ghRepo {
	var all []ghRepo
	for page := 1; page <= 5 && len(all) < max; page++ {
		b, st, err := gh.get(fmt.Sprintf("/users/%s/repos?per_page=100&sort=pushed&page=%d", login, page))
		if err != nil || st != 200 {
			break
		}
		var batch []ghRepo
		if decodeJSON(b, &batch) != nil || len(batch) == 0 {
			break
		}
		for _, r := range batch {
			if r.Fork {
				continue
			}
			all = append(all, r)
			if len(all) >= max {
				break
			}
		}
		if len(batch) < 100 {
			break
		}
	}
	return all
}

func auditRepo(gh *ghClient, r ghRepo) {
	owner := strings.SplitN(r.FullName, "/", 2)[0]
	emit(ev{Type: "asset", Kind: "url", Value: r.HTMLURL})

	branch := r.DefaultBranch
	if branch == "" {
		branch = "main"
	}
	b, st, err := gh.get(fmt.Sprintf("/repos/%s/git/trees/%s?recursive=1", r.FullName, branch))
	if err != nil || st != 200 {
		return
	}
	var tree ghTree
	if decodeJSON(b, &tree) != nil {
		return
	}

	var risky, workflows []string
	for _, e := range tree.Tree {
		if e.Type != "blob" {
			continue
		}
		if isWorkflow(e.Path) {
			workflows = append(workflows, e.Path)
		}
		if isRiskyFile(e.Path) && e.Size < 512*1024 {
			risky = append(risky, e.Path)
		}
	}

	if len(risky) > 0 {
		emit(ev{Type: "finding", Severity: "medium", FindingType: "github-sensitive-file",
			Title:    fmt.Sprintf("%d arquivo(s) de nome sensível em %s", len(risky), r.FullName),
			Asset:    r.HTMLURL,
			Evidence: strings.Join(trimList(risky, 20), ", "),
			Meta:     map[string]any{"repo": r.FullName, "files": risky}})
	}

	// baixa e varre os arquivos sensíveis (teto)
	scanned := 0
	for _, p := range risky {
		if scanned >= 12 || gh.exhausted {
			break
		}
		scanned++
		content, cst, _ := gh.getRaw(owner, r.Name, branch, p)
		if cst != 200 || content == "" {
			continue
		}
		for _, h := range scanSecrets(content) {
			emit(ev{Type: "finding", Severity: h.Severity, FindingType: "github-repo-secret",
				Title:    fmt.Sprintf("segredo (%s) em %s: %s", h.Kind, r.Name, p),
				Asset:    r.HTMLURL + "/blob/" + branch + "/" + p,
				Evidence: h.Kind + " = " + h.Value + " no arquivo versionado " + p,
				Meta:     map[string]any{"repo": r.FullName, "path": p, "kind": h.Kind}})
		}
	}

	// workflows
	for _, wf := range workflows {
		if gh.exhausted {
			break
		}
		content, cst, _ := gh.getRaw(owner, r.Name, branch, wf)
		if cst != 200 {
			continue
		}
		for _, w := range analyzeWorkflow(content) {
			emit(ev{Type: "finding", Severity: w.sev, FindingType: w.kind,
				Title:    fmt.Sprintf("%s: %s / %s", w.kind, r.Name, wf),
				Asset:    r.HTMLURL + "/blob/" + branch + "/" + wf,
				Evidence: w.note,
				Meta:     map[string]any{"repo": r.FullName, "workflow": wf}})
		}
		for _, h := range scanSecrets(content) {
			emit(ev{Type: "finding", Severity: h.Severity, FindingType: "github-repo-secret",
				Title:    fmt.Sprintf("segredo (%s) no workflow %s: %s", h.Kind, r.Name, wf),
				Asset:    r.HTMLURL + "/blob/" + branch + "/" + wf,
				Evidence: h.Kind + " = " + h.Value + " hardcoded no workflow (use secrets:)",
				Meta:     map[string]any{"repo": r.FullName, "path": wf, "kind": h.Kind}})
		}
	}
}

func auditGists(gh *ghClient, login string) {
	b, st, err := gh.get("/users/" + login + "/gists?per_page=100")
	if err != nil || st != 200 {
		return
	}
	var gists []ghGist
	if decodeJSON(b, &gists) != nil {
		return
	}
	n := 0
	for _, g := range gists {
		if n >= 30 || gh.exhausted {
			break
		}
		for _, f := range g.Files {
			if f.Size > 512*1024 || f.RawURL == "" {
				continue
			}
			n++
			body, _, _ := gh.get(f.RawURL)
			for _, h := range scanSecrets(string(body)) {
				emit(ev{Type: "finding", Severity: h.Severity, FindingType: "github-gist-secret",
					Title:    fmt.Sprintf("segredo (%s) no gist %s: %s", h.Kind, g.ID, f.Filename),
					Asset:    g.HTML,
					Evidence: h.Kind + " = " + h.Value + " no gist público " + f.Filename,
					Meta:     map[string]any{"gist": g.ID, "file": f.Filename, "kind": h.Kind}})
			}
		}
	}
}

// --- helpers ---

func firstWords(s string, n int) string {
	f := strings.Fields(strings.ReplaceAll(s, "T", " "))
	if len(f) > n {
		f = f[:n]
	}
	return strings.Join(f, " ")
}

func trimList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], "…")
}

func readPayload() payload {
	var p payload
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) != 0 {
		return p
	}
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if s := strings.TrimSpace(string(b)); s != "" {
		_ = json.Unmarshal([]byte(s), &p)
	}
	return p
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func strParam(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func boolParam(m map[string]any, k string) bool {
	switch v := m[k].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}

func intParam(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

func pick(vs ...int) int {
	for _, v := range vs {
		if v > 0 {
			return v
		}
	}
	if len(vs) > 0 {
		return vs[len(vs)-1]
	}
	return 0
}
