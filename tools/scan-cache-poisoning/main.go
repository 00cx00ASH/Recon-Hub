// scan-cache-poisoning — testa web cache poisoning via entradas não-chaveadas
// (X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL, …). Cada teste usa um
// cache-buster único na query, então a resposta envenenada fica presa numa URL
// que nenhum usuário real acessa. Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
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
		flagHdrs   = flag.String("headers", "", "csv de headers a testar (sobrescreve a lista)")
		flagConc   = flag.Int("concurrency", 0, "hosts em paralelo (0 = param/4)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/10000)")
		flagDelay  = flag.Int("delay-ms", 0, "pausa entre requisições ao mesmo host (0 = param/150)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 4)
	delay := time.Duration(pick(*flagDelay, intParam(pl.Params, "delay_ms"), 150)) * time.Millisecond

	client := &http.Client{
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

	probes := defaultProbes()
	if h := firstNonEmpty(*flagHdrs, strParam(pl.Params, "headers")); h != "" {
		probes = probes[:0]
		for _, name := range splitList(h) {
			probes = append(probes, probe{header: http.CanonicalHeaderKey(name),
				value: func(c string) string { return c }, where: "any"})
		}
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d alvo(s) × %d entrada(s) não-chaveada(s); cache-buster único por teste",
		len(targets), len(probes))})

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
				f := scanURL(client, u, probes, delay)
				mu2.Lock()
				done++
				d := done
				finds += f
				mu2.Unlock()
				emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d alvos", d, len(targets))})
			}
		}()
	}
	for _, u := range targets {
		ch <- u
	}
	close(ch)
	wg.Wait()

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d alvo(s), %d finding(s)", len(targets), finds)})
}

// scanURL runs every probe against one URL and returns the finding count.
func scanURL(c *http.Client, target string, probes []probe, delay time.Duration) int {
	// baseline (com cache-buster próprio) — confirma que a URL responde
	base := bust(target, "cb"+randHex(6))
	_, bstatus, _, berr := doGET(c, base, nil, nil)
	if berr != nil {
		emit(ev{Type: "log", Level: "warn", Msg: target + ": baseline falhou: " + berr.Error()})
		return 0
	}
	if bstatus >= 500 {
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("%s: baseline HTTP %d — pulando", target, bstatus)})
		return 0
	}

	finds := 0
	for _, p := range probes {
		time.Sleep(delay)
		canary := "cachepoison-" + randHex(8) + ".example.com"
		cb := "cb" + randHex(8)

		var reqURL string
		var hdr http.Header
		if p.header != "" {
			reqURL = bust(target, cb)
			hdr = http.Header{p.header: []string{p.value(canary)}}
		} else {
			reqURL = bustExtra(target, cb, p.param, p.value(canary))
		}

		body, status, rh, err := doGET(c, reqURL, hdr, nil)
		if err != nil || status >= 500 {
			continue
		}
		refl := reflections(canary, body, rh)
		if len(refl) == 0 {
			continue
		}
		cv := readCache(rh)

		// tenta confirmar a persistência: requisição LIMPA à mesma URL cacheada
		time.Sleep(delay)
		persisted := false
		if p.header != "" { // só faz sentido p/ header não-chaveado + mesma query
			body2, st2, _, err2 := doGET(c, reqURL, nil, nil)
			if err2 == nil && st2 < 500 && strings.Contains(body2, canary) {
				persisted = true
			}
		}

		v := classify(refl, cv, persisted)
		if v.kind == "" {
			continue
		}
		finds++
		emit(ev{Type: "asset", Kind: "url", Value: reqURL})
		emit(ev{
			Type: "finding", Severity: v.severity, FindingType: v.kind,
			Title: fmt.Sprintf("%s via %s: %s", v.kind, p.label(), hostOf(target)),
			Asset: reqURL,
			Evidence: fmt.Sprintf("%s = %q refletido em %s (status %d). %s. Teste isolado por cache-buster %s.",
				p.label(), truncate(payloadFor(p, canary), 60), strings.Join(refl, "+"), status, v.note, cb),
			Meta: map[string]any{
				"target": target, "probe": p.label(), "canary": canary,
				"reflected_in": refl, "cache": cv.reason, "persisted": persisted,
				"cache_buster": cb, "test_url": reqURL,
			},
		})
	}
	return finds
}

func payloadFor(p probe, canary string) string { return p.value(canary) }

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

// doGET performs a GET and returns body, status, headers.
func doGET(c *http.Client, u string, extra http.Header, _ any) (string, int, http.Header, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", 0, nil, err
	}
	req.Header.Set("User-Agent", "recon-hub/scan-cache-poisoning")
	applyAuth(req)
	for k, vs := range extra {
		for _, v := range vs {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, nil, err
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	resp.Body.Close()
	return string(b), resp.StatusCode, resp.Header, nil
}

// bust adds/overwrites a cache-buster query param.
func bust(rawURL, cb string) string { return bustExtra(rawURL, cb, "", "") }

func bustExtra(rawURL, cb, extraKey, extraVal string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := u.Query()
	q.Set("cb", cb)
	if extraKey != "" {
		q.Set(extraKey, extraVal)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// --- helpers ---

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func hostOf(u string) string {
	p, err := url.Parse(u)
	if err != nil {
		return u
	}
	return p.Host
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
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
