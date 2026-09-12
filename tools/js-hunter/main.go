// js-hunter — recon de JavaScript: baixa a página + os <script src>, tenta os
// source maps (.js.map) e reconstrói o código-fonte original, e extrai
// endpoints de API (fetch/axios/XHR/constantes de URL) — marcando os
// interessantes (/admin, /graphql, /internal, /actuator, …).
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
	finds  int
)

func emit(e ev) {
	mu.Lock()
	defer mu.Unlock()
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
		flagTarget = flag.String("target", "", "URL da página")
		flagURLs   = flag.String("urls", "", "várias URLs por vírgula/linha")
		flagURLsF  = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagNoMaps = flag.Bool("no-maps", false, "não tentar os source maps")
		flagMaxJS  = flag.Int("max-js", 0, "teto de arquivos JS por página (0 = param/60)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/12000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 12000)) * time.Millisecond
	maxJS := pick(*flagMaxJS, intParam(pl.Params, "max_js"), 60)
	doMaps := !*flagNoMaps && !boolParam(pl.Params, "no_maps")

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
	}
	applyProxy(transport, timeout)
	client = &http.Client{
		Timeout:   timeout,
		Transport: withBlockRotation(transport, func(msg string) { emit(ev{Type: "log", Level: "info", Msg: msg}) }),
	}

	var pages []string
	seen := map[string]bool{}
	add := func(s string) {
		if u := normURL(s); u != "" && !seen[u] {
			seen[u] = true
			pages = append(pages, u)
		}
	}
	add(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	for _, s := range splitList(firstNonEmpty(*flagURLs, strParam(pl.Params, "urls"), os.Getenv("RECONHUB_PARAM_URLS"))) {
		add(s)
	}
	if f := firstNonEmpty(*flagURLsF, strParam(pl.Params, "urls_file"), os.Getenv("RECONHUB_PARAM_URLS_FILE")); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			for _, s := range splitList(string(b)) {
				add(s)
			}
		}
	}
	if len(pages) == 0 {
		emit(ev{Type: "error", Msg: "informe target (URL) ou params.urls"})
		os.Exit(2)
	}

	for _, p := range pages {
		huntPage(p, doMaps, maxJS)
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d página(s), %d finding(s)", len(pages), finds)})
}

func huntPage(page string, doMaps bool, maxJS int) {
	html, err := fetch(page)
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: page + ": " + err.Error()})
		return
	}

	// coleta os arquivos JS
	jsURLs := []string{}
	jsSeen := map[string]bool{}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		abs := resolve(page, m[1])
		if abs == "" || !strings.Contains(abs, ".js") || jsSeen[abs] {
			continue
		}
		jsSeen[abs] = true
		jsURLs = append(jsURLs, abs)
		if len(jsURLs) >= maxJS {
			break
		}
	}

	corpus := []struct{ src, text string }{{page + " (HTML inline)", html}}
	mapsFound := 0
	srcFilesTotal := 0

	for _, ju := range jsURLs {
		body, err := fetch(ju)
		if err != nil {
			continue
		}
		corpus = append(corpus, struct{ src, text string }{ju, body})

		if !doMaps {
			continue
		}
		gotMap := false
		for _, mc := range mapCandidates(ju, body) {
			mb, err := fetch(mc)
			if err != nil || !strings.Contains(mb, `"sources"`) {
				continue
			}
			files, perr := parseSourceMap(mb)
			if perr != nil || len(files) == 0 {
				continue
			}
			gotMap = true
			mapsFound++
			withContent := 0
			for _, f := range files {
				if f.Content != "" {
					withContent++
					corpus = append(corpus, struct{ src, text string }{ju + " ← " + trimPath(f.Path), f.Content})
				}
			}
			srcFilesTotal += withContent
			emit(ev{Type: "asset", Kind: "url", Value: mc})
			emit(ev{Type: "finding", Severity: "low", FindingType: "js-sourcemap-exposed",
				Title:    "source map exposto: " + trimURL(mc),
				Asset:    mc,
				Evidence: fmt.Sprintf("%d fonte(s) original(is), %d com conteúdo embutido — revela o código não-minificado (nomes, comentários, lógica, rotas)", len(files), withContent),
				Meta:     map[string]any{"js": ju, "map": mc, "sources": len(files), "sources_with_content": withContent}})
			break
		}
		_ = gotMap
	}

	// extrai endpoints de todo o corpus
	type epInfo struct {
		methods map[string]bool
		srcs    map[string]bool
	}
	eps := map[string]*epInfo{}
	for _, c := range corpus {
		for _, e := range extractEndpoints(c.text) {
			ei := eps[e.Ref]
			if ei == nil {
				ei = &epInfo{methods: map[string]bool{}, srcs: map[string]bool{}}
				eps[e.Ref] = ei
			}
			if e.Method != "" {
				ei.methods[e.Method] = true
			}
			ei.srcs[c.src] = true
		}
	}

	refs := make([]string, 0, len(eps))
	for r := range eps {
		refs = append(refs, r)
	}
	sort.Strings(refs)

	interesting := 0
	for _, r := range refs {
		emit(ev{Type: "asset", Kind: "endpoint", Value: r})
		if ok, why := interestingEndpoint(r); ok {
			interesting++
			ei := eps[r]
			emit(ev{Type: "finding", Severity: "medium", FindingType: "js-interesting-endpoint",
				Title:    "endpoint sensível referenciado no JS: " + r,
				Asset:    page,
				Evidence: fmt.Sprintf("%s (%s) — visto em: %s", r, why, strings.Join(keysOf(ei.srcs), "; ")),
				Meta:     map[string]any{"endpoint": r, "why": why, "methods": keysOf(ei.methods)}})
		}
	}

	if len(refs) > 0 {
		emit(ev{Type: "finding", Severity: "info", FindingType: "js-endpoints-discovered",
			Title:    fmt.Sprintf("%d endpoint(s) de API extraído(s) do JS de %s", len(refs), hostOf(page)),
			Asset:    page,
			Evidence: fmt.Sprintf("%d interessante(s). Amostra: %s", interesting, strings.Join(trimList(refs, 30), ", ")),
			Meta:     map[string]any{"count": len(refs), "endpoints": refs}})
	}

	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf(
		"%s — %d JS, %d source map(s), %d fonte(s) recuperada(s), %d endpoint(s)",
		page, len(jsURLs), mapsFound, srcFilesTotal, len(refs))})
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// --- helpers ---

// applyAuth attaches the operator's shared auth context for this program —
// set once via PUT /api/programs/{name}/auth (internal/project.Auth),
// injected by the engine as env vars — to a request, but ONLY when it's
// going to the same host as the job's own target. Without that check, a
// tool that also talks to an unrelated third party would leak the target's
// session cookie/token to a host it was never meant for.
func applyAuth(req *http.Request) {
	if !sameHostAsTarget(req.URL.Host) {
		return
	}
	if v := os.Getenv("RECONHUB_AUTH_COOKIE"); v != "" {
		req.Header.Set("Cookie", v)
	}
	if v := os.Getenv("RECONHUB_AUTH_BEARER"); v != "" {
		req.Header.Set("Authorization", "Bearer "+v)
	}
	if v := os.Getenv("RECONHUB_AUTH_HEADERS"); v != "" {
		var extra map[string]string
		if json.Unmarshal([]byte(v), &extra) == nil {
			for k, val := range extra {
				req.Header.Set(k, val)
			}
		}
	}
}

// sameHostAsTarget reports whether host matches RECONHUB_TARGET's host
// (port ignored). No RECONHUB_TARGET set (e.g. running outside the hub)
// doesn't block — there's nothing to compare against.
func sameHostAsTarget(host string) bool {
	t := strings.TrimSpace(os.Getenv("RECONHUB_TARGET"))
	if t == "" {
		return true
	}
	th := t
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		th = u.Host
	}
	strip := func(h string) string {
		if i := strings.LastIndexByte(h, ':'); i >= 0 {
			h = h[:i]
		}
		return strings.ToLower(h)
	}
	return strip(host) == strip(th)
}

func fetch(u string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 recon-hub/js-hunter")
	req.Header.Set("Accept", "*/*")
	applyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 24<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(b), nil
}

func trimURL(u string) string {
	if len(u) > 90 {
		return u[:90] + "…"
	}
	return u
}

func trimPath(p string) string {
	p = strings.TrimPrefix(p, "./")
	if len(p) > 60 {
		return "…" + p[len(p)-60:]
	}
	return p
}

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	return p.Host
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
	if s := strings.TrimSpace(string(b)); s != "" {
		_ = json.Unmarshal([]byte(s), &p)
	}
	return p
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

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
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
