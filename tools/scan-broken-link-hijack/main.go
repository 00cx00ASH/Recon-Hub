// scan-broken-link-hijack — varre uma página pelos links/recursos externos
// (a/script/img/iframe/link/form) que apontam pra plataformas sequestráveis
// (GitHub, npm, S3, Heroku/Netlify/Vercel/…, redes sociais) e checa quais o
// alvo pode registrar. Contrato NDJSON do recon-hub no stdout.
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
		flagTarget     = flag.String("target", "", "URL da página")
		flagURLs       = flag.String("urls", "", "várias URLs por vírgula/linha")
		flagURLsF      = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagConc       = flag.Int("concurrency", 0, "workers (0 = param/12)")
		flagTOms       = flag.Int("timeout-ms", 0, "timeout req (0 = param/10000)")
		flagIncludeSub = flag.Bool("include-subresources", false, "também checar img/link além de a/script/iframe/form")
		flagPretty     = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 12)
	inclSub := *flagIncludeSub || boolParam(pl.Params, "include_subresources")

	client = &http.Client{
		Timeout: timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 8 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
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
		emit(ev{Type: "error", Msg: "informe target (URL da página) ou params.urls"})
		os.Exit(2)
	}

	// coleta candidatos de todas as páginas
	type cand struct {
		url, where, page string
		kind             hijackKind
	}
	var cands []cand
	candSeen := map[string]bool{}
	genSeen := map[string]bool{}
	genCount := 0
	for _, p := range pages {
		html, err := fetch(p)
		if err != nil {
			emit(ev{Type: "log", Level: "warn", Msg: p + ": " + err.Error()})
			continue
		}
		refs := extractRefs(html, p)
		pageReg := registrableGuess(hostOf(p))
		n, g := 0, 0
		for _, r := range refs {
			if !inclSub && (r.Where == "img" || r.Where == "link") {
				continue
			}
			if candSeen[r.URL] {
				continue
			}
			if k, ok := classifyRef(r.URL); ok {
				candSeen[r.URL] = true
				cands = append(cands, cand{r.URL, r.Where, p, k})
				n++
				continue
			}
			// fallback: link externo em domínio próprio — só interessa se não resolver
			if k, ok := genericExternal(r.URL); ok && registrableGuess(hostOf(r.URL)) != pageReg {
				h := hostOf(r.URL)
				if genSeen[h] || genCount >= 200 {
					continue
				}
				genSeen[h] = true
				genCount++
				candSeen[r.URL] = true
				cands = append(cands, cand{r.URL, r.Where, p, k})
				g++
			}
		}
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%s — %d refs, %d em plataforma + %d domínio externo", p, len(refs), n, g)})
	}
	if len(cands) == 0 {
		emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d página(s), 0 links sequestráveis", len(pages))})
		return
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("checando %d link(s) candidato(s)", len(cands))})

	var (
		wg          sync.WaitGroup
		ch          = make(chan cand)
		mu2         sync.Mutex
		done, finds int
	)
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range ch {
				pr := probeTarget(c.url)
				v, hit := decide(c.kind, pr)

				mu2.Lock()
				done++
				d := done
				if hit {
					finds++
				}
				mu2.Unlock()
				if d%20 == 0 || d == len(cands) {
					emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d", d, len(cands))})
				}
				if !hit {
					continue
				}
				emit(ev{Type: "asset", Kind: "url", Value: c.url})
				emit(ev{
					Type: "finding", Severity: v.severity, FindingType: v.kind,
					Title: fmt.Sprintf("%s: %s (link em %s)", v.kind, c.kind.platform, hostOf(c.page)),
					Asset: c.url,
					Evidence: fmt.Sprintf("<%s> em %s aponta para %s — %s",
						c.where, c.page, c.url, v.note),
					Meta: map[string]any{
						"page": c.page, "where": c.where, "link": c.url,
						"platform": c.kind.platform, "claim_target": c.kind.target,
						"http_status": pr.status, "resolves": pr.resolves,
					},
				})
			}
		}()
	}
	for _, c := range cands {
		ch <- c
	}
	close(ch)
	wg.Wait()

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d página(s), %d link(s) checado(s), %d sequestrável(is)", len(pages), len(cands), finds)})
}

func probeTarget(rawURL string) probeResult {
	u, err := url.Parse(rawURL)
	if err != nil {
		return probeResult{}
	}
	pr := probeResult{resolves: true}
	if _, err := net.LookupHost(u.Hostname()); err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && (dnsErr.IsNotFound) {
			pr.resolves = false
			return pr
		}
		// erro temporário de resolução: não afirma nada
	}
	req, _ := http.NewRequest(http.MethodGet, rawURL, nil)
	req.Header.Set("User-Agent", "recon-hub/scan-broken-link-hijack")
	resp, err := client.Do(req)
	if err != nil {
		return pr
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<10))
	resp.Body.Close()
	pr.status = resp.StatusCode
	pr.body = string(b)
	return pr
}

// --- helpers ---

// applyAuth attaches the operator's shared auth context for this program —
// set once via PUT /api/programs/{name}/auth (internal/project.Auth),
// injected by the engine as env vars — to a request, but ONLY when it's
// going to the same host as the job's own target. Deliberately NOT used by
// probeTarget below: that function checks whether an EXTERNAL link (GitHub,
// npm, an abandoned PaaS subdomain…) is registrable, and the target's
// session cookie/token has no business leaving the target's own host.
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
	req.Header.Set("User-Agent", "recon-hub/scan-broken-link-hijack")
	req.Header.Set("Accept", "text/html,*/*")
	applyAuth(req)
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

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Host
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
