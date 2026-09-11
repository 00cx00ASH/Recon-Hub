// scan-dep-confusion — lê um manifesto de dependências (npm/pypi/cargo/composer)
// ou varre uma página web pelos módulos que ela importa, e checa cada nome no
// registro público. Nome ausente = dependency confusion (o build interno pode
// ser sequestrado por um pacote público homônimo).
// Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
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
	mu     sync.Mutex
	out    = bufio.NewWriter(os.Stdout)
	pretty bool
	client *http.Client
)

func emit(e ev) {
	mu.Lock()
	defer mu.Unlock()
	if pretty {
		switch e.Type {
		case "finding":
			fmt.Fprintf(out, "[%s] %s\n        %s\n", strings.ToUpper(e.Severity), e.Title, e.Evidence)
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
		flagTarget = flag.String("target", "", "URL do manifesto, ou (modo site) URL da página")
		flagMode   = flag.String("mode", "", "url | paste | file | site")
		flagEco    = flag.String("ecosystem", "", "npm|pypi|cargo|composer (força)")
		flagMan    = flag.String("manifest", "", "conteúdo do manifesto (modo paste)")
		flagManF   = flag.String("manifest-file", "", "arquivo no servidor (modo file)")
		flagConc   = flag.Int("concurrency", 0, "workers (0 = param/8)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/10000)")
		flagNoDev  = flag.Bool("no-dev", false, "ignorar dev/optional dependencies")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 8)
	mode := firstNonEmpty(*flagMode, strParam(pl.Params, "mode"), "url")
	eco := firstNonEmpty(*flagEco, strParam(pl.Params, "ecosystem"), os.Getenv("RECONHUB_PARAM_ECOSYSTEM"))
	target := firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET"))
	noDev := *flagNoDev || boolParam(pl.Params, "no_dev")

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives: false,
		MaxIdleConns:      32,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
	}
	applyProxy(transport, timeout)
	client = &http.Client{
		Timeout:   timeout,
		Transport: withBlockRotation(transport, func(msg string) { emit(ev{Type: "log", Level: "info", Msg: msg}) }),
	}

	var deps []dep
	var srcLabel string
	switch mode {
	case "paste":
		content := firstNonEmpty(*flagMan, strParam(pl.Params, "manifest"), os.Getenv("RECONHUB_PARAM_MANIFEST"))
		if content == "" {
			emit(ev{Type: "error", Msg: "modo paste: preencha params.manifest"})
			os.Exit(2)
		}
		if eco == "" {
			eco = sniffEcosystem(content)
		}
		deps = parseManifest(eco, content)
		srcLabel = "manifesto colado (" + eco + ")"
	case "file":
		f := firstNonEmpty(*flagManF, strParam(pl.Params, "manifest_file"), os.Getenv("RECONHUB_PARAM_MANIFEST_FILE"))
		b, err := os.ReadFile(f)
		if err != nil {
			emit(ev{Type: "error", Msg: "não li o arquivo: " + err.Error()})
			os.Exit(2)
		}
		if eco == "" {
			eco = ecosystemFor(f)
		}
		if eco == "" {
			eco = sniffEcosystem(string(b))
		}
		deps = parseManifest(eco, string(b))
		srcLabel = f + " (" + eco + ")"
	case "site", "site-list":
		pages := collectURLs(target, pl)
		if len(pages) == 0 {
			emit(ev{Type: "error", Msg: "modo site: informe a URL alvo (ou params.urls / urls_file)"})
			os.Exit(2)
		}
		seen := map[string]bool{}
		for _, p := range pages {
			for _, n := range harvestSite(p) {
				if !seen[n] {
					seen[n] = true
					deps = append(deps, dep{Name: n, Ecosystem: "npm", Section: "site"})
				}
			}
		}
		eco = "npm"
		if len(pages) == 1 {
			srcLabel = "imports de " + pages[0]
		} else {
			srcLabel = fmt.Sprintf("imports de %d página(s)", len(pages))
		}
	default: // url
		if target == "" {
			emit(ev{Type: "error", Msg: "modo url: informe a URL do manifesto"})
			os.Exit(2)
		}
		u := normURL(target)
		body, err := fetch(u)
		if err != nil {
			emit(ev{Type: "error", Msg: "não baixei o manifesto: " + err.Error()})
			os.Exit(2)
		}
		if eco == "" {
			eco = ecosystemFor(u)
		}
		if eco == "" {
			eco = sniffEcosystem(body)
		}
		deps = parseManifest(eco, body)
		srcLabel = u + " (" + eco + ")"
	}

	if eco == "" {
		emit(ev{Type: "error", Msg: "não identifiquei o ecossistema — passe params.ecosystem"})
		os.Exit(2)
	}
	if noDev {
		deps = filterDeps(deps, func(d dep) bool { return d.Section != "dev" && d.Section != "optional" && d.Section != "peer" })
	}
	if len(deps) == 0 {
		emit(ev{Type: "log", Level: "warn", Msg: "nenhuma dependência confusável em " + srcLabel})
		emit(ev{Type: "done", OK: true, Msg: "0 dependências, 0 findings"})
		return
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d dependência(s) de %s — checando %s",
		len(deps), srcLabel, registryLabel(eco))})

	var (
		wg          sync.WaitGroup
		ch          = make(chan dep)
		mu2         sync.Mutex
		done, finds int
		unknown     []string
	)
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for d := range ch {
				status, scopeEmpty := check(d)
				mu2.Lock()
				done++
				dcount := done
				if status == "unknown" {
					unknown = append(unknown, d.Name)
				}
				mu2.Unlock()
				if dcount%25 == 0 || dcount == len(deps) {
					emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d", dcount, len(deps))})
				}
				v, hit := classifyResult(d, status, scopeEmpty)
				if !hit {
					continue
				}
				mu2.Lock()
				finds++
				mu2.Unlock()
				emit(ev{Type: "asset", Kind: "package", Value: eco + ":" + d.Name})
				emit(ev{
					Type: "finding", Severity: v.severity, FindingType: v.ftype,
					Title: fmt.Sprintf("dependency confusion: %s (%s)", d.Name, eco),
					Asset: eco + ":" + d.Name,
					Evidence: fmt.Sprintf("%s — seção %q, versão %q. %s",
						registryLabel(eco), sectionOr(d.Section), verOr(d.Version), v.note),
					Meta: map[string]any{
						"ecosystem": eco, "package": d.Name, "section": d.Section,
						"version": d.Version, "registry_status": status,
					},
				})
			}
		}()
	}
	for _, d := range deps {
		ch <- d
	}
	close(ch)
	wg.Wait()

	if len(unknown) > 0 {
		sort.Strings(unknown)
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf(
			"%d nome(s) sem resposta clara do registro (rede/rate-limit): %s",
			len(unknown), strings.Join(trimList(unknown, 15), ", "))})
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d dependência(s), %d dependency confusion", len(deps), finds)})
}

// check consulta o registro público. Retorna status claimed|unclaimed|unknown
// e, pra npm com escopo, se o escopo inteiro parece vazio.
func check(d dep) (status string, scopeEmpty bool) {
	switch d.Ecosystem {
	case "npm":
		st := httpStatusClass("https://registry.npmjs.org/" + npmEscape(d.Name))
		if st == "unclaimed" && strings.HasPrefix(d.Name, "@") {
			scope := strings.SplitN(strings.TrimPrefix(d.Name, "@"), "/", 2)[0]
			scopeEmpty = npmScopeEmpty(scope)
		}
		return st, scopeEmpty
	case "pypi":
		return httpStatusClass("https://pypi.org/pypi/" + url.PathEscape(d.Name) + "/json"), false
	case "cargo":
		return httpStatusClass("https://crates.io/api/v1/crates/" + url.PathEscape(d.Name)), false
	case "composer":
		return httpStatusClass("https://repo.packagist.org/p2/" + d.Name + ".json"), false
	}
	return "unknown", false
}

func httpStatusClass(u string) string {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "recon-hub/scan-dep-confusion (+https://github.com/)")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "unknown"
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	resp.Body.Close()
	switch {
	case resp.StatusCode == 200:
		return "claimed"
	case resp.StatusCode == 404 || resp.StatusCode == 410:
		return "unclaimed"
	default:
		return "unknown"
	}
}

func npmEscape(name string) string {
	if strings.HasPrefix(name, "@") {
		return "@" + url.PathEscape(strings.TrimPrefix(name, "@"))
	}
	return url.PathEscape(name)
}

type npmSearch struct {
	Total int `json:"total"`
}

func npmScopeEmpty(scope string) bool {
	u := "https://registry.npmjs.org/-/v1/search?size=1&text=" + url.QueryEscape("@"+scope+"/")
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "recon-hub/scan-dep-confusion")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return false
	}
	var s npmSearch
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&s) != nil {
		return false
	}
	return s.Total == 0
}

// harvestSite baixa a página + os <script src> e extrai os module specifiers
// bare (não relativos) importados.
func harvestSite(pageURL string) []string {
	pageBody, err := fetch(pageURL)
	if err != nil {
		emit(ev{Type: "error", Msg: "não baixei a página: " + err.Error()})
		os.Exit(2)
	}
	bodies := []string{pageBody}
	for _, src := range scriptSrcRe.FindAllStringSubmatch(pageBody, -1) {
		abs := resolveRef(pageURL, src[1])
		if abs == "" || !strings.Contains(abs, ".js") {
			continue
		}
		if len(bodies) > 40 {
			break
		}
		if b, err := fetch(abs); err == nil {
			bodies = append(bodies, b)
		}
	}
	seen := map[string]bool{}
	var names []string
	for _, b := range bodies {
		for _, re := range specRes {
			for _, m := range re.FindAllStringSubmatch(b, -1) {
				if n := pkgFromSpecifier(m[1]); n != "" && !seen[n] {
					seen[n] = true
					names = append(names, n)
				}
			}
		}
	}
	sort.Strings(names)
	return names
}

var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	specRes     = []*regexp.Regexp{
		regexp.MustCompile(`import\s+(?:[\w${},*\s]+\s+from\s+)?["']([^"']+)["']`),
		regexp.MustCompile(`import\(\s*["']([^"']+)["']\s*\)`),
		regexp.MustCompile(`require\(\s*["']([^"']+)["']\s*\)`),
	}
)

// pkgFromSpecifier turns "lodash/fp/get" -> "lodash", "@ns/x/y" -> "@ns/x".
func pkgFromSpecifier(spec string) string {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}
	for _, p := range []string{".", "/", "http:", "https:", "node:", "data:", "blob:", "#"} {
		if strings.HasPrefix(spec, p) {
			return ""
		}
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(parts) < 2 {
			return ""
		}
		name := parts[0] + "/" + parts[1]
		if !npmNameRe.MatchString(name) {
			return ""
		}
		return name
	}
	if !npmNameRe.MatchString(parts[0]) {
		return ""
	}
	return parts[0]
}

var npmNameRe = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$`)

// --- http helpers ---

func fetch(u string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "recon-hub/scan-dep-confusion")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(b), nil
}

func resolveRef(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return b.ResolveReference(r).String()
}

// --- misc helpers ---

func registryLabel(eco string) string {
	switch eco {
	case "npm":
		return "registry.npmjs.org"
	case "pypi":
		return "pypi.org"
	case "cargo":
		return "crates.io"
	case "composer":
		return "packagist.org"
	}
	return eco
}

func filterDeps(in []dep, keep func(dep) bool) []dep {
	out := in[:0]
	for _, d := range in {
		if keep(d) {
			out = append(out, d)
		}
	}
	return out
}

func readPayload() payload {
	var p payload
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) != 0 {
		return p
	}
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if s := strings.TrimSpace(string(b)); s != "" {
		_ = json.Unmarshal([]byte(s), &p)
	}
	return p
}

// collectURLs gathers page URLs from target + params.urls + params.urls_file.
func collectURLs(target string, pl payload) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if u := normURL(s); u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	add(target)
	for _, s := range splitLines(firstNonEmpty(strParam(pl.Params, "urls"), os.Getenv("RECONHUB_PARAM_URLS"))) {
		add(s)
	}
	if f := firstNonEmpty(strParam(pl.Params, "urls_file"), os.Getenv("RECONHUB_PARAM_URLS_FILE")); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			for _, s := range splitLines(string(b)) {
				add(s)
			}
		}
	}
	return out
}

func splitLines(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
}

func normURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return s
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

func sectionOr(s string) string {
	if s == "" {
		return "?"
	}
	return s
}
func verOr(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

func trimList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], "…")
}
