// recon-web-enum — recon web leve: faz um crawl same-site raso, identifica a
// stack (headers/cookies/markers), coleta formulários e parâmetros, e sonda uma
// lista de caminhos administrativos/sensíveis com calibração de soft-404.
// Contrato NDJSON do recon-hub no stdout.
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
		flagTarget  = flag.String("target", "", "URL raiz")
		flagDepth   = flag.Int("depth", 0, "profundidade do crawl (0 = param/2)")
		flagMax     = flag.Int("max-pages", 0, "teto de páginas no crawl (0 = param/60)")
		flagNoProbe = flag.Bool("no-probe", false, "não sondar caminhos administrativos/sensíveis")
		flagBypass  = flag.Bool("try-bypass", false, "tenta um punhado de técnicas clássicas de bypass (barra dupla, X-Original-URL, X-Forwarded-For…) nos 401/403 achados — opt-in, só dispara nos já bloqueados, não é fuzzing")
		flagConc    = flag.Int("concurrency", 0, "requisições simultâneas (0 = param/10)")
		flagDelay   = flag.Int("delay-ms", 0, "pausa entre requisições de cada worker na sondagem (0 = param/25) — espaça o tráfego pra não acionar WAF/rate-limit")
		flagTOms    = flag.Int("timeout-ms", 0, "timeout req (0 = param/10000)")
		flagPretty  = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	depth := pick(*flagDepth, intParam(pl.Params, "depth"), 2)
	maxPages := pick(*flagMax, intParam(pl.Params, "max_pages"), 60)
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 10)
	delay := time.Duration(pick(*flagDelay, intParam(pl.Params, "delay_ms"), 25)) * time.Millisecond
	doProbe := !*flagNoProbe && !boolParam(pl.Params, "no_probe")
	tryBypassFlag := *flagBypass || boolParam(pl.Params, "try_bypass")

	// uma ou mais raízes (o feed de pipeline pode injetar em params.target)
	seenR := map[string]bool{}
	var roots []string
	addRoot := func(s string) {
		if u := normURL(s); u != "" && !seenR[u] {
			if _, err := url.Parse(u); err == nil {
				seenR[u] = true
				roots = append(roots, u)
			}
		}
	}
	addRoot(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	for _, s := range splitLines(firstNonEmpty(strParam(pl.Params, "target"), strParam(pl.Params, "roots"), os.Getenv("RECONHUB_PARAM_ROOTS"))) {
		addRoot(s)
	}
	if len(roots) == 0 {
		emit(ev{Type: "error", Msg: "informe a URL raiz (ou params.roots)"})
		os.Exit(2)
	}

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives: false,
		MaxIdleConns:      32,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
	}
	applyProxy(transport, timeout)
	client = &http.Client{
		Timeout: timeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 6 {
				return http.ErrUseLastResponse
			}
			return nil
		},
		Transport: transport,
	}

	if len(roots) > 1 {
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d site(s) a analisar", len(roots))})
	}
	totalPages, totalHits := 0, 0
	for _, root := range roots {
		p, h := enumSite(root, depth, maxPages, conc, doProbe, delay, tryBypassFlag)
		totalPages += p
		totalHits += h
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d site(s), %d página(s) no crawl, %d caminho(s) encontrado(s), %d finding(s)", len(roots), totalPages, totalHits, finds)})
}

// enumSite runs the full crawl + fingerprint + probe for one root URL.
// Returns (pages crawled, probe paths found).
func enumSite(root string, depth, maxPages, conc int, doProbe bool, delay time.Duration, doBypass bool) (int, int) {
	ru, err := url.Parse(root)
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "URL inválida: " + root})
		return 0, 0
	}
	baseHost := strings.ToLower(ru.Hostname())

	// --- crawl ---
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("crawl de %s (depth %d, max %d páginas)", root, depth, maxPages)})
	visited := map[string]bool{}
	var techAll = map[string]bool{}
	var forms []webForm
	params := map[string]bool{}

	queue := []struct {
		u string
		d int
	}{{root, 0}}
	for len(queue) > 0 && len(visited) < maxPages {
		cur := queue[0]
		queue = queue[1:]
		if visited[cur.u] {
			continue
		}
		visited[cur.u] = true

		body, hdr, status, err := fetch(cur.u)
		if err != nil {
			continue
		}
		emit(ev{Type: "asset", Kind: "url", Value: cur.u})
		for _, tsig := range fingerprint(hdr, body) {
			techAll[tsig] = true
		}
		for _, pn := range queryParams(cur.u) {
			params[pn] = true
		}
		if status >= 200 && status < 300 && isHTML(hdr) {
			for _, f := range extractForms(body, cur.u) {
				forms = append(forms, f)
				for _, in := range f.Inputs {
					params[in] = true
				}
			}
		}
		if cur.d < depth && isHTML(hdr) {
			for _, l := range pageLinks(body, cur.u, baseHost) {
				lu, _ := url.Parse(l)
				lu.RawQuery = "" // enfileira o path sem query pra não explodir
				key := lu.String()
				if !visited[key] && !visited[l] {
					queue = append(queue, struct {
						u string
						d int
					}{l, cur.d + 1})
				}
			}
		}
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d página(s) visitada(s), %d formulário(s), %d parâmetro(s)", len(visited), len(forms), len(params))})

	// --- tech ---
	if len(techAll) > 0 {
		var tl []string
		for t := range techAll {
			tl = append(tl, t)
		}
		sort.Strings(tl)
		emit(ev{Type: "finding", Severity: "info", FindingType: "web-tech-detected",
			Title:    "stack detectada: " + baseHost,
			Asset:    root,
			Evidence: strings.Join(tl, " · "),
			Meta:     map[string]any{"tech": tl}})
	}

	// --- forms ---
	for _, f := range forms {
		sev, ft := "info", "web-form"
		title := "formulário: " + f.Method + " " + f.Action
		if f.Password {
			sev, ft = "low", "web-login-form"
			title = "formulário de login: " + f.Method + " " + f.Action
		}
		emit(ev{Type: "finding", Severity: sev, FindingType: ft,
			Title:    title,
			Asset:    f.Action,
			Evidence: "campos: " + strings.Join(f.Inputs, ", "),
			Meta:     map[string]any{"method": f.Method, "inputs": f.Inputs, "password": f.Password}})
	}
	if len(params) > 0 {
		var pl2 []string
		for p := range params {
			pl2 = append(pl2, p)
		}
		sort.Strings(pl2)
		emit(ev{Type: "finding", Severity: "info", FindingType: "web-params-observed",
			Title:    fmt.Sprintf("%d parâmetro(s) observado(s) no site", len(pl2)),
			Asset:    root,
			Evidence: strings.Join(trimList(pl2, 40), ", "),
			Meta:     map[string]any{"params": pl2}})
	}

	// --- probe ---
	if !doProbe {
		return len(visited), 0
	}

	base := calibrate(root)
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("baseline soft-404: status %d, ~%d bytes — sondando %d caminho(s) (%d workers, %s de pausa/req)", base.status, base.size, len(probePaths), conc, delay)})

	type task struct {
		path, kind, sev string
	}
	ch := make(chan task)
	var wg sync.WaitGroup
	var mu2 sync.Mutex
	hitCount := 0
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range ch {
				if delay > 0 {
					time.Sleep(delay)
				}
				u := strings.TrimRight(root, "/") + t.path
				body, hdr, status, err := fetch(u)
				if err != nil {
					continue
				}
				ok, confirmed, note := probeVerdict(t.kind, status, len(body), hdr.Get("Content-Type"), body, base)
				if !ok {
					continue
				}
				mu2.Lock()
				hitCount++
				mu2.Unlock()
				emit(ev{Type: "asset", Kind: "url", Value: u, Meta: map[string]any{"http_status": status}})
				sev := t.sev
				ft := "web-path-found"
				switch t.kind {
				case "sensitive-file":
					ft = "sensitive-file-exposed"
				case "admin":
					ft = "admin-panel-found"
				case "debug":
					ft = "debug-endpoint-found"
				case "api-doc":
					ft = "api-doc-found"
				case "info":
					ft = "web-info-file"
				}
				title := t.kind + ": " + u
				if !confirmed {
					// só prova que o caminho existe e está atrás de auth — não é
					// achado reportável isoladamente, então não infla a severidade
					// nem marca como confirmado (ver probeVerdict).
					sev = "info"
					title = "[bloqueado] " + title
				}
				emit(ev{Type: "finding", Severity: sev, FindingType: ft,
					Title:    title,
					Asset:    u,
					Evidence: note,
					Meta:     map[string]any{"path": t.path, "kind": t.kind, "http_status": status, "confirmed": confirmed}})

				// candidato a bypass: só dispara pra um caminho JÁ confirmado
				// bloqueado (401/403), com opt-in explícito, e só um punhado de
				// técnicas fixas — nunca um fuzzer geral. Ver bypass.go.
				if !confirmed && doBypass && (t.kind == "admin" || t.kind == "debug") {
					if delay > 0 {
						time.Sleep(delay)
					}
					if bOK, technique, bNote := tryBypass(root, t.path, base); bOK {
						emit(ev{Type: "finding", Severity: "high", FindingType: "auth-bypass-candidate",
							Title:    "possível bypass de auth (" + technique + "): " + u,
							Asset:    u,
							Evidence: bNote,
							Meta:     map[string]any{"path": t.path, "kind": t.kind, "technique": technique, "confirmed": true, "needs_manual_review": true}})
					}
				}
			}
		}()
	}
	for _, p := range probePaths {
		ch <- task{p.path, p.kind, p.sev}
	}
	close(ch)
	wg.Wait()

	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%s — %d caminho(s) encontrado(s)", baseHost, hitCount)})
	return len(visited), hitCount
}

// calibrate probes 2 random paths to learn the soft-404 shape.
func calibrate(root string) baseline {
	var b baseline
	for i := 0; i < 2; i++ {
		u := strings.TrimRight(root, "/") + "/" + randHex(10) + "/" + randHex(6)
		body, _, status, err := fetch(u)
		if err != nil {
			continue
		}
		if b.status == 0 || status == b.status {
			b.status = status
			b.size = len(body)
		}
	}
	if b.status == 0 {
		b.status = 404
	}
	return b
}

// --- helpers ---

// applyAuth attaches the operator's shared auth context for this program —
// set once via PUT /api/programs/{name}/auth (internal/project.Auth),
// injected by the engine as env vars — to a request, but ONLY when it's
// going to the same host as the job's own target. Without that check, a
// tool that also talks to an unrelated third party (a cloud bucket, an API
// provider, a CDN) would leak the target's session cookie/token to a host
// it was never meant for.
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

func fetch(u string) (string, http.Header, int, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 recon-hub/recon-web-enum")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json,*/*")
	applyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(b), resp.Header, resp.StatusCode, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
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

func splitLines(s string) []string {
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

func trimList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], "…")
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
