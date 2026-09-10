// js-ai-key-hunter — varre a página + JS + source maps por credenciais de
// provedores de IA/ML (OpenAI, Anthropic, Groq, Mistral, HuggingFace, Replicate,
// Google AI, Azure OpenAI, ElevenLabs, Deepgram, LangSmith, Vertex/GCP, …).
// Filtro de entropia + denylist de placeholders. Validação read-only opcional.
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
		flagJS     = flag.Bool("no-js", false, "não baixar os <script src>")
		flagMaps   = flag.Bool("no-maps", false, "não tentar os source maps")
		flagMinLen = flag.Int("min-len", 0, "tamanho mínimo do valor (0 = param/16)")
		flagVal    = flag.Bool("validate", false, "checar cada chave com 1 GET read-only ao provedor")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/12000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 12000)) * time.Millisecond
	minLen := pick(*flagMinLen, intParam(pl.Params, "min_len"), 16)
	doJS := !*flagJS && !boolParam(pl.Params, "no_js")
	doMaps := !*flagMaps && !boolParam(pl.Params, "no_maps")
	doValidate := *flagVal || boolParam(pl.Params, "validate")

	client = &http.Client{
		Timeout: timeout,
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
		emit(ev{Type: "error", Msg: "informe target (URL) ou params.urls"})
		os.Exit(2)
	}
	mode := "validação OFF"
	if doValidate {
		mode = "validação ON (1 GET read-only por chave)"
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d página(s), %d padrões — %s", len(pages), len(patterns), mode)})

	total := 0
	for _, p := range pages {
		total += scanURL(p, doJS, doMaps, minLen, doValidate, timeout)
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d página(s), %d chave(s) de IA, %d finding(s)", len(pages), total, finds)})
}

func scanURL(page string, doJS, doMaps bool, minLen int, doValidate bool, timeout time.Duration) int {
	body, err := fetch(page)
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: page + ": " + err.Error()})
		return 0
	}
	bodies := map[string]string{page: body}
	if doJS {
		for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
			abs := resolveRef(page, m[1])
			if abs == "" || !strings.Contains(abs, ".js") || len(bodies) > 40 {
				continue
			}
			js, e := fetch(abs)
			if e != nil {
				continue
			}
			bodies[abs] = js
			if doMaps {
				for _, mu := range mapURLRe.FindAllStringSubmatch(js, -1) {
					mapAbs := resolveRef(abs, strings.TrimSpace(mu[1]))
					if mapAbs == "" || len(bodies) > 60 {
						continue
					}
					if mm, e := fetch(mapAbs); e == nil {
						bodies[mapAbs+" (source map)"] = mm
					}
				}
			}
		}
	}

	count := 0
	for src, txt := range bodies {
		for _, h := range scan(txt, minLen) {
			count++
			sev, ftype := h.Severity, "ai-key-exposed"
			evd := fmt.Sprintf("%s: %s em %s", h.Provider, redact(h.Value), src)
			meta := map[string]any{"provider": h.Provider, "source": src, "value_redacted": redact(h.Value)}

			if doValidate && h.Validate != "" {
				vr := validateKey(h.Validate, h.Value, timeout)
				meta["validation"] = vr.state
				meta["validation_detail"] = vr.detail
				switch vr.state {
				case "valid":
					sev, ftype = "critical", "ai-key-valid"
					evd += " — VÁLIDA (" + vr.detail + ")"
				case "invalid":
					sev, ftype = "info", "ai-key-invalid"
					evd += " — inválida/revogada (" + vr.detail + ")"
				default:
					evd += " — validação inconclusiva (" + vr.detail + ")"
				}
			}

			emit(ev{Type: "asset", Kind: "credential", Value: h.Provider + ":" + redact(h.Value)})
			emit(ev{Type: "finding", Severity: sev, FindingType: ftype,
				Title:    fmt.Sprintf("chave de IA exposta: %s", h.Provider),
				Asset:    page,
				Evidence: evd,
				Meta:     meta})
		}
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%s — %d fonte(s), %d chave(s)", page, len(bodies), count)})
	return count
}

var (
	scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)
	mapURLRe    = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s'"]+)`)
)

// --- helpers ---

// applyAuth attaches the operator's shared auth context for this program —
// set once via PUT /api/programs/{name}/auth (internal/project.Auth),
// injected by the engine as env vars — to a request, but ONLY when it's
// going to the same host as the job's own target. Deliberately NOT used by
// validate.go's requests: those check a discovered key against its OWN
// provider's API (OpenAI, Anthropic, Google…), a different origin the
// target's session cookie/token has no business reaching.
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
	req.Header.Set("User-Agent", "Mozilla/5.0 recon-hub/js-ai-key-hunter")
	req.Header.Set("Accept", "text/html,application/javascript,*/*")
	applyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
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
