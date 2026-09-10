// js-secret-hunter — baixa a página + JS + source maps e procura credenciais
// (~35 padrões: chaves de cloud, tokens, JWT, chaves privadas, DB URLs…).
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
	w      = bufio.NewWriter(os.Stdout)
	pretty bool
)

func emit(e ev) {
	mu.Lock()
	defer mu.Unlock()
	if pretty {
		switch e.Type {
		case "finding":
			fmt.Fprintf(w, "[%s] %s\n        %s\n", strings.ToUpper(e.Severity), e.Title, e.Evidence)
		case "done":
			fmt.Fprintln(w, "done: "+e.Msg)
		default:
			lv := e.Level
			if lv == "" {
				lv = "info"
			}
			fmt.Fprintf(w, "[%s] %s\n", lv, e.Msg)
		}
	} else {
		b, _ := json.Marshal(e)
		w.Write(b)
		w.WriteByte('\n')
	}
	w.Flush()
}

var scriptRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)
var mapRe = regexp.MustCompile(`(?m)//# sourceMappingURL=(\S+)`)

func main() {
	var (
		flagTarget = flag.String("target", "", "URL (fallback stdin/env)")
		flagURLs   = flag.String("urls", "", "URLs por vírgula/linha")
		flagURLsF  = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagNoJS   = flag.Bool("no-js", false, "não baixar <script src>")
		flagNoMaps = flag.Bool("no-maps", false, "não tentar source maps")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout HTTP (0 = param/12000)")
		flagMin    = flag.Int("min-len", 0, "tamanho mínimo do valor (0 = 12)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer w.Flush()

	pl := readPayload()
	doJS := !*flagNoJS && paramBool(pl.Params, "js", true)
	doMaps := !*flagNoMaps && paramBool(pl.Params, "maps", true)
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 12000)) * time.Millisecond
	minLen := pick(*flagMin, intParam(pl.Params, "min_len"), 12)

	seen := map[string]bool{}
	var urls []string
	add := func(s string) {
		if u := normURL(s); u != "" && !seen[u] {
			seen[u] = true
			urls = append(urls, u)
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
	if len(urls) == 0 {
		emit(ev{Type: "error", Msg: "informe target ou params.urls"})
		os.Exit(2)
	}

	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return nil },
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("varrendo %d URL(s), %d padrões", len(urls), len(patterns))})

	total := 0
	for _, u := range urls {
		total += scanURL(client, u, doJS, doMaps, minLen)
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d URL(s), %d secret(s)", len(urls), total)})
}

// scanURL busca a página + assets e reporta os hits.
func scanURL(c *http.Client, pageURL string, doJS, doMaps bool, minLen int) int {
	base, err := url.Parse(pageURL)
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "URL inválida: " + pageURL})
		return 0
	}
	bodies := map[string]string{} // sourceURL -> body
	html, ok := get(c, pageURL)
	if !ok {
		emit(ev{Type: "log", Level: "warn", Msg: "sem resposta: " + pageURL})
		return 0
	}
	bodies[pageURL] = html

	if doJS {
		scripts := map[string]bool{}
		for _, m := range scriptRe.FindAllStringSubmatch(html, -1) {
			if abs := resolve(base, m[1]); abs != "" {
				scripts[abs] = true
			}
		}
		for s := range scripts {
			js, ok := get(c, s)
			if !ok {
				continue
			}
			bodies[s] = js
			if doMaps {
				if mb, mu := fetchMap(c, base, s, js); mb != "" {
					bodies[mu] = mb
				}
			}
		}
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%s: %d script(s)", pageURL, len(scripts))})
	}

	found := 0
	for src, body := range bodies {
		for _, h := range scan(body, minLen) {
			found++
			emit(ev{
				Type: "finding", Severity: h.Severity, FindingType: "secret",
				Title:    h.Pattern + " em " + trimURL(src),
				Asset:    trimURL(src),
				Evidence: h.Pattern + ": " + redact(h.Value),
				Meta:     map[string]any{"pattern": h.Pattern, "source": src, "value_redacted": redact(h.Value)},
			})
		}
	}
	return found
}

func fetchMap(c *http.Client, base *url.URL, jsURL, jsBody string) (body, mapURL string) {
	mapURL = jsURL + ".map"
	if m := mapRe.FindStringSubmatch(jsBody); len(m) == 2 && !strings.HasPrefix(m[1], "data:") {
		if ju, e := url.Parse(jsURL); e == nil {
			if abs := resolve(ju, m[1]); abs != "" {
				mapURL = abs
			}
		}
	}
	if b, ok := get(c, mapURL); ok {
		return b, mapURL
	}
	return "", ""
}

func get(c *http.Client, u string) (string, bool) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "recon-hub/js-secret-hunter")
	resp, err := c.Do(req)
	if err != nil {
		return "", false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	resp.Body.Close()
	return string(b), true
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
	return s
}

func resolve(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "data:") {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(u)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	return abs.String()
}

func trimURL(s string) string {
	if len(s) > 120 {
		return s[:117] + "…"
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
func paramBool(m map[string]any, k string, def bool) bool {
	if v, ok := m[k].(bool); ok {
		return v
	}
	return def
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
