// scan-open-redirect — injeta payloads de bypass em parâmetros de redirect e
// confirma o open redirect pelo destino real da resposta (Location 3xx ou
// redirect client-side) apontando pro canary inofensivo example.com.
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

// embedded fallback — usado só se nenhuma wordlist for resolvida.
var builtinParams = []string{
	"url", "redirect", "redirect_uri", "redirect_url", "redirecturl", "return",
	"return_url", "returnurl", "return_to", "next", "target", "dest",
	"destination", "redir", "redirurl", "rurl", "u", "link", "goto", "go",
	"out", "view", "callback", "continue", "checkout_url", "returnTo", "r",
	"back", "backurl", "success", "cancel", "forward", "to", "path",
}

func main() {
	var (
		flagTarget = flag.String("target", "", "URL alvo (pode já ter query)")
		flagURLs   = flag.String("urls", "", "várias URLs por vírgula/linha")
		flagURLsF  = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagWL     = flag.String("wordlist", "", "caminho de wordlist de nomes de parâmetro")
		flagParams = flag.String("params", "", "nomes de parâmetro extra (csv)")
		flagCanary = flag.String("canary", "", "host canary (default example.com)")
		flagConc   = flag.Int("concurrency", 0, "workers (0 = param/20)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/8000)")
		flagMaxP   = flag.Int("max-params", 0, "teto de parâmetros por URL (0 = param/80)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 8000)) * time.Millisecond
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 20)
	maxParams := pick(*flagMaxP, intParam(pl.Params, "max_params"), 80)
	canary := firstNonEmpty(*flagCanary, strParam(pl.Params, "canary"), os.Getenv("RECONHUB_PARAM_CANARY"), defaultCanary)

	// bases
	seen := map[string]bool{}
	var bases []string
	add := func(s string) {
		if u := normURL(s); u != "" && !seen[u] {
			seen[u] = true
			bases = append(bases, u)
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
	if len(bases) == 0 {
		emit(ev{Type: "error", Msg: "informe target ou params.urls (uma URL http/https)"})
		os.Exit(2)
	}

	// wordlist de nomes de parâmetro (o engine já resolve o nome pra caminho abs)
	wlPath := firstNonEmpty(*flagWL, strParam(pl.Params, "wordlist"), os.Getenv("RECONHUB_PARAM_WORDLIST"))
	names := builtinParams
	wlSrc := "embutida"
	if wlPath != "" {
		if lines, err := readLines(wlPath); err == nil && len(lines) > 0 {
			names = lines
			wlSrc = wlPath
		} else if err != nil {
			emit(ev{Type: "log", Level: "warn", Msg: "wordlist '" + wlPath + "' não lida (" + err.Error() + ") — usando lista embutida"})
		}
	}
	params := paramNames(*flagParams+"\n"+strParam(pl.Params, "params"), names)
	if len(params) > maxParams {
		params = params[:maxParams]
	}
	nPayloads := len(buildPayloads(canary, ""))

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
	}
	applyProxy(transport, timeout)
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     withBlockRotation(transport, func(msg string) { emit(ev{Type: "log", Level: "info", Msg: msg}) }),
	}

	// tarefas: (base, param). Cada uma testa os payloads em ordem e para no 1º hit.
	type task struct {
		base, param string
	}
	var tasks []task
	for _, b := range bases {
		for _, p := range params {
			tasks = append(tasks, task{b, p})
		}
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf(
		"%d URL(s) × %d parâmetro(s) × %d payload(s) — canary=%s, wordlist=%s",
		len(bases), len(params), nPayloads, canary, wlSrc)})

	var (
		wg              sync.WaitGroup
		ch              = make(chan task)
		mu2             sync.Mutex
		done, reqs, hit int
	)
	worker := func() {
		defer wg.Done()
		for t := range ch {
			th := hostOf(t.base)
			for _, pay := range buildPayloads(canary, th) {
				u := withParam(t.base, t.param, pay.value)
				if u == "" {
					continue
				}
				sev, ftype, dest, mech := probe(client, u, canary)
				mu2.Lock()
				reqs++
				mu2.Unlock()
				if sev == "" {
					continue
				}
				mu2.Lock()
				hit++
				mu2.Unlock()
				evi := fmt.Sprintf("param %q payload %q (%s) → redireciona para %s", t.param, pay.value, pay.label, dest)
				if mech != "" {
					evi += " via " + mech
				}
				emit(ev{Type: "asset", Kind: "url", Value: u})
				emit(ev{
					Type: "finding", Severity: sev, FindingType: ftype,
					Title:    "open redirect em " + t.param + " (" + hostOf(t.base) + ")",
					Asset:    u,
					Evidence: evi,
					Meta: map[string]any{
						"param": t.param, "payload": pay.value, "bypass": pay.label,
						"canary": canary, "destino": dest,
					},
				})
				break // um hit por (base,param) basta
			}
			mu2.Lock()
			done++
			d := done
			mu2.Unlock()
			if d%50 == 0 || d == len(tasks) {
				emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d params", d, len(tasks))})
			}
		}
	}
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go worker()
	}
	for _, t := range tasks {
		ch <- t
	}
	close(ch)
	wg.Wait()

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d URL(s), %d requisições, %d open redirect(s)", len(bases), reqs, hit)})
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

// probe faz o GET e decide se houve open redirect. Retorna (sev, finding_type,
// destino, mecanismo). sev=="" quando não houve.
func probe(c *http.Client, u, canary string) (sev, ftype, dest, mech string) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", "", "", ""
	}
	req.Header.Set("User-Agent", "recon-hub/scan-open-redirect")
	applyAuth(req)
	resp, err := c.Do(req)
	if err != nil {
		return "", "", "", ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()

	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		loc := resp.Header.Get("Location")
		if redirectsToCanary(loc, canary) {
			return "high", "open-redirect", loc, ""
		}
	}
	if ok, m := bodyRedirectsToCanary(string(body), canary); ok {
		return "medium", "open-redirect-clientside", canary, m
	}
	return "", "", "", ""
}

// withParam devolve u com o parâmetro key=val setado (substitui se existir).
func withParam(u, key, val string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	q := parsed.Query()
	q.Set(key, val)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

// --- helpers ---

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
	if _, err := url.Parse(s); err != nil {
		return ""
	}
	return s
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out, nil
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
