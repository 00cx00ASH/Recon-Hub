// scan-sqli — injeta aspa/aspa-dupla em parâmetros e confirma SQL injection
// só quando um erro de banco de dados conhecido aparece na resposta com o
// payload mas NÃO aparece na resposta sem ele (baseline). Nunca usa
// time-based (SLEEP/WAITFOR) nem extração booleana — só vazamento de erro,
// zero carga extra no alvo além de 3 requisições por parâmetro. Contrato
// NDJSON do recon-hub no stdout.
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
	"id", "user_id", "userid", "uid", "product_id", "item_id", "cat_id",
	"category_id", "category", "page", "pid", "sort", "order", "orderby",
	"filter", "search", "q", "query", "name", "username", "email",
	"account", "ref", "code", "token", "key", "value", "type", "status",
	"year", "month", "date", "limit", "offset", "start", "end", "num",
}

func main() {
	var (
		flagTarget = flag.String("target", "", "URL alvo (pode já ter query)")
		flagURLs   = flag.String("urls", "", "várias URLs por vírgula/linha")
		flagURLsF  = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagWL     = flag.String("wordlist", "", "caminho de wordlist de nomes de parâmetro")
		flagParams = flag.String("params", "", "nomes de parâmetro extra (csv)")
		flagConc   = flag.Int("concurrency", 0, "workers (0 = param/15)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/8000)")
		flagMaxP   = flag.Int("max-params", 0, "teto de parâmetros por URL (0 = param/80)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 8000)) * time.Millisecond
	// concorrência mais baixa que os outros scanners de propósito: cada
	// parâmetro já faz 3 requisições (baseline + 2 payloads), então o
	// mesmo teto de "requisições simultâneas no alvo" pede menos workers.
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 15)
	maxParams := pick(*flagMaxP, intParam(pl.Params, "max_params"), 80)

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

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
	}
	applyProxy(transport, timeout)
	client := &http.Client{
		Timeout:   timeout,
		Transport: withBlockRotation(transport, func(msg string) { emit(ev{Type: "log", Level: "info", Msg: msg}) }),
	}

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
		"%d URL(s) × %d parâmetro(s) × %d payload(s) — wordlist=%s",
		len(bases), len(params), len(probePayloads), wlSrc)})

	var (
		wg              sync.WaitGroup
		ch              = make(chan task)
		mu2             sync.Mutex
		done, reqs, hit int
	)
	worker := func() {
		defer wg.Done()
		for t := range ch {
			baseline, err := fetch(client, t.base)
			mu2.Lock()
			reqs++
			mu2.Unlock()
			if err != nil {
				mu2.Lock()
				done++
				d := done
				mu2.Unlock()
				if d%50 == 0 || d == len(tasks) {
					emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d params", d, len(tasks))})
				}
				continue
			}
			for _, pay := range probePayloads {
				u := withParamAppend(t.base, t.param, pay)
				if u == "" {
					continue
				}
				injected, err := fetch(client, u)
				mu2.Lock()
				reqs++
				mu2.Unlock()
				if err != nil {
					continue
				}
				sev, ftype, sig, ok := classify(baseline, injected)
				if !ok {
					continue
				}
				mu2.Lock()
				hit++
				mu2.Unlock()
				emit(ev{Type: "asset", Kind: "url", Value: u})
				emit(ev{
					Type: "finding", Severity: sev, FindingType: ftype,
					Title:    "SQL injection em " + t.param + " (" + hostOf(t.base) + ")",
					Asset:    u,
					Evidence: fmt.Sprintf("param %q, payload %q → erro de banco vazado (%q), ausente no baseline sem o payload", t.param, pay, sig),
					Meta:     map[string]any{"param": t.param, "payload": pay, "signature": sig},
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

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d URL(s), %d requisições, %d SQL injection(s)", len(bases), reqs, hit)})
}

// fetch faz o GET e devolve o corpo (limitado) como string.
func fetch(c *http.Client, u string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "recon-hub/scan-sqli")
	applyAuth(req)
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return string(body), nil
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

// withParamAppend devolve u com payload ANEXADO ao valor existente do
// parâmetro (ou como valor único, se o parâmetro não existia) — anexar
// simula melhor o caso real de "quebrar uma query que já usa esse valor"
// do que substituir, quando a URL já tem um valor legítimo ali.
func withParamAppend(u, key, payload string) string {
	parsed, err := url.Parse(u)
	if err != nil {
		return ""
	}
	q := parsed.Query()
	q.Set(key, q.Get(key)+payload)
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil {
		return p.Host
	}
	return u
}

// --- helpers (idênticos ao padrão dos outros scanners do hub) ---

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

// paramNames mescla os nomes extras (csv/linha) com a wordlist base,
// deduplicando preservando ordem.
func paramNames(extra string, base []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range splitList(extra) {
		add(s)
	}
	for _, s := range base {
		add(s)
	}
	return out
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
