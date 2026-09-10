// js-jwt-finder — acha JWTs no HTML/JS de uma página (ou colados), decodifica
// header e payload sem verificar assinatura, aponta problemas (alg=none, sem
// exp, vida longa, claims sensíveis, emissor conhecido) e tenta quebrar o
// segredo HS* com uma lista de segredos fracos (+ wordlist opcional).
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
		flagToken  = flag.String("token", "", "JWT colado (um ou vários, separados por espaço/linha)")
		flagWL     = flag.String("wordlist", "", "wordlist de segredos p/ crack HS* (o engine resolve o nome)")
		flagNoJS   = flag.Bool("no-js", false, "não baixar os <script src>")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/12000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 12000)) * time.Millisecond
	doJS := !*flagNoJS && !boolParam(pl.Params, "no_js")
	client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	// segredos p/ crack: embutidos + wordlist (se houver)
	var extra []string
	if wl := firstNonEmpty(*flagWL, strParam(pl.Params, "wordlist"), os.Getenv("RECONHUB_PARAM_WORDLIST")); wl != "" {
		if lines, err := readLines(wl); err == nil {
			extra = lines
			emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("wordlist de segredos: %d entradas de %s", len(lines), wl)})
		} else {
			emit(ev{Type: "log", Level: "warn", Msg: "wordlist não lida (" + err.Error() + ") — só a lista embutida"})
		}
	}
	secrets := mergeSecrets(extra)

	// colhe os tokens: colados + páginas
	type srcTok struct{ tok, origin string }
	seenTok := map[string]bool{}
	var toks []srcTok
	addTok := func(t, origin string) {
		t = strings.Trim(strings.TrimSpace(t), `"',;`)
		if t == "" || seenTok[t] {
			return
		}
		if _, _, _, err := decodeJWT(t); err != nil {
			return
		}
		seenTok[t] = true
		toks = append(toks, srcTok{t, origin})
	}
	for _, t := range strings.Fields(firstNonEmpty(*flagToken, strParam(pl.Params, "token"), os.Getenv("RECONHUB_PARAM_TOKEN"))) {
		addTok(t, "colado")
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
	if len(toks) == 0 && len(pages) == 0 {
		emit(ev{Type: "error", Msg: "informe target (URL) ou params.token"})
		os.Exit(2)
	}

	for _, p := range pages {
		body, err := fetch(p)
		if err != nil {
			emit(ev{Type: "log", Level: "warn", Msg: p + ": " + err.Error()})
			continue
		}
		texts := []string{body}
		if doJS {
			for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
				if abs := resolveRef(p, m[1]); abs != "" && strings.Contains(abs, ".js") && len(texts) < 30 {
					if js, e := fetch(abs); e == nil {
						texts = append(texts, js)
					}
				}
			}
		}
		n := 0
		for _, t := range findJWTs(strings.Join(texts, "\n")) {
			addTok(t, p)
			n++
		}
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%s — %d JWT(s)", p, n)})
	}

	if len(toks) == 0 {
		emit(ev{Type: "done", OK: true, Msg: "nenhum JWT encontrado"})
		return
	}

	for _, st := range toks {
		auditToken(st.tok, st.origin, secrets)
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d JWT(s), %d finding(s)", len(toks), finds)})
}

func auditToken(tok, origin string, secrets []string) {
	hdr, plc, sig, err := decodeJWT(tok)
	if err != nil {
		return
	}
	alg, _ := hdr["alg"].(string)
	emit(ev{Type: "asset", Kind: "jwt", Value: redactJWT(tok)})

	base := ev{Type: "finding", Severity: "info", FindingType: "jwt-found",
		Title:    fmt.Sprintf("JWT (%s) em %s", orDash(alg), origin),
		Asset:    redactJWT(tok),
		Evidence: fmt.Sprintf("header: %s · claims: %s", compactJSON(hdr), strings.Join(claimKeys(plc), ", ")),
		Meta: map[string]any{
			"origin": origin, "alg": alg, "header": hdr, "claims": claimKeys(plc),
			"sig_bytes": len(sig),
		}}
	emit(base)

	for _, is := range analyze(hdr, plc, tok) {
		emit(ev{Type: "finding", Severity: is.severity, FindingType: is.kind,
			Title:    is.kind + ": " + origin,
			Asset:    redactJWT(tok),
			Evidence: is.detail,
			Meta:     map[string]any{"origin": origin, "alg": alg}})
	}

	if hmacFor(alg) != nil {
		if s, ok := crackHS(tok, secrets); ok {
			emit(ev{Type: "finding", Severity: "critical", FindingType: "jwt-weak-secret",
				Title:    "segredo HMAC do JWT quebrado: " + origin,
				Asset:    redactJWT(tok),
				Evidence: fmt.Sprintf("o segredo %s (alg %s) reproduz a assinatura — dá pra forjar QUALQUER token deste emissor. %d segredos testados.", quoteSecret(s), alg, len(secrets)),
				Meta:     map[string]any{"origin": origin, "alg": alg, "secret": s}})
		}
	}
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
	req.Header.Set("User-Agent", "Mozilla/5.0 recon-hub/js-jwt-finder")
	req.Header.Set("Accept", "text/html,application/javascript,*/*")
	applyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 12<<20))
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

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimRight(ln, "\r")
		if ln != "" && !strings.HasPrefix(ln, "#") {
			out = append(out, ln)
		}
	}
	return out, nil
}

func compactJSON(v any) string {
	b, _ := json.Marshal(v)
	if len(b) > 300 {
		return string(b[:300]) + "…"
	}
	return string(b)
}

func quoteSecret(s string) string {
	if s == "" {
		return `"" (segredo vazio!)`
	}
	return `"` + s + `"`
}

func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
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
