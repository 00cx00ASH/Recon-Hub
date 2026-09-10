// scan-cors — testa CORS mal configurado: reflexão de origem, origem null,
// wildcard com credentials, e bypasses de regex (prefixo/sufixo/hífen no
// subdomínio). Faz um GET com Origin: <atacante> e lê ACAO/ACAC da resposta.
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
		flagTarget = flag.String("target", "", "URL alvo")
		flagURLs   = flag.String("urls", "", "várias URLs por vírgula/linha")
		flagURLsF  = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagConc   = flag.Int("concurrency", 0, "URLs em paralelo (0 = param/8)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/10000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 8)

	client = &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	var targets []string
	seen := map[string]bool{}
	add := func(s string) {
		if u := normURL(s); u != "" && !seen[u] {
			seen[u] = true
			targets = append(targets, u)
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
	if len(targets) == 0 {
		emit(ev{Type: "error", Msg: "informe target ou params.urls"})
		os.Exit(2)
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d URL(s), ~9 origens de teste cada", len(targets))})

	var (
		wg          sync.WaitGroup
		ch          = make(chan string)
		mu2         sync.Mutex
		done, finds int
	)
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for u := range ch {
				f := scanURL(u)
				mu2.Lock()
				done++
				d := done
				finds += f
				mu2.Unlock()
				emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d", d, len(targets))})
			}
		}()
	}
	for _, u := range targets {
		ch <- u
	}
	close(ch)
	wg.Wait()

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d URL(s), %d finding(s)", len(targets), finds)})
}

func scanURL(target string) int {
	pu, err := url.Parse(target)
	if err != nil {
		return 0
	}
	host := pu.Hostname()

	// baseline sem Origin
	_, bh, bstatus, berr := doGET(target, "")
	if berr != nil {
		emit(ev{Type: "log", Level: "warn", Msg: target + ": baseline falhou: " + berr.Error()})
		return 0
	}
	finds := 0
	if v := baselineWildcard(bh); v.kind != "" {
		finds++
		emitFinding(target, "(baseline)", "(sem Origin)", v, bstatus, bh)
	}

	reported := map[string]bool{}
	for _, o := range testOrigins(host) {
		_, rh, status, err := doGET(target, o.value)
		if err != nil {
			continue
		}
		v := analyze(o.value, rh, host)
		if v.kind == "" || reported[v.kind] {
			continue
		}
		reported[v.kind] = true
		finds++
		emitFinding(target, o.label, o.value, v, status, rh)
	}
	return finds
}

func emitFinding(target, how, sentOrigin string, v verdict, status int, h http.Header) {
	emit(ev{Type: "asset", Kind: "url", Value: target})
	emit(ev{
		Type: "finding", Severity: v.severity, FindingType: v.kind,
		Title: fmt.Sprintf("%s: %s", v.kind, hostOf(target)),
		Asset: target,
		Evidence: fmt.Sprintf("Origin: %s (%s) → ACAO: %q · ACAC: %q · Vary: %q (status %d). %s",
			sentOrigin, how,
			h.Get("Access-Control-Allow-Origin"),
			h.Get("Access-Control-Allow-Credentials"),
			h.Get("Vary"), status, v.note),
		Meta: map[string]any{
			"target": target, "sent_origin": sentOrigin, "bypass": how,
			"acao":        h.Get("Access-Control-Allow-Origin"),
			"acac":        h.Get("Access-Control-Allow-Credentials"),
			"acam":        h.Get("Access-Control-Allow-Methods"),
			"acah":        h.Get("Access-Control-Allow-Headers"),
			"http_status": status,
		},
	})
}

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

func doGET(u, origin string) (string, http.Header, int, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", nil, 0, err
	}
	req.Header.Set("User-Agent", "recon-hub/scan-cors")
	applyAuth(req)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, 0, err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	return string(b), resp.Header, resp.StatusCode, nil
}

// --- helpers ---

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	return p.Host
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
