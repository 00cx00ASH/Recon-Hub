// recon-tech-cve — extrai produto+versão do fingerprint passivo de uma
// página (Server, X-Powered-By, meta generator, assets versionados) e cruza
// com uma tabela curada, estática, de CVEs conhecidas — sem API externa nem
// feed de CVE, mesmo espírito do internal/intel.knownRisk do hub. Não prova
// exploração nenhuma: sinaliza "essa versão é velha o bastante pra ter tido
// esse problema", pra o operador confirmar manualmente. Contrato NDJSON do
// recon-hub no stdout.
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

func main() {
	var (
		flagTarget = flag.String("target", "", "URL alvo")
		flagURLs   = flag.String("urls", "", "várias URLs por vírgula/linha")
		flagURLsF  = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagConc   = flag.Int("concurrency", 0, "URLs em paralelo (0 = param/8)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout por requisição (0 = param/10000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 8)

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

	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return nil },
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d URL(s) — fingerprint passivo + %d entrada(s) na tabela curada", len(bases), len(knownVulns))})

	var (
		wg                     sync.WaitGroup
		ch                     = make(chan string)
		mu2                    sync.Mutex
		done, hitTech, hitVuln int
	)
	worker := func() {
		defer wg.Done()
		for base := range ch {
			dets, matches := scanOne(client, base)
			mu2.Lock()
			hitTech += len(dets)
			hitVuln += len(matches)
			done++
			d := done
			mu2.Unlock()
			emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d URLs", d, len(bases))})
		}
	}
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go worker()
	}
	for _, b := range bases {
		ch <- b
	}
	close(ch)
	wg.Wait()

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d URL(s), %d tecnologia(s) identificada(s), %d candidato(s) a CVE", len(bases), hitTech, hitVuln)})
}

func scanOne(client *http.Client, base string) ([]detected, []vulnMatch) {
	req, err := http.NewRequest(http.MethodGet, base, nil)
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "URL inválida: " + base})
		return nil, nil
	}
	req.Header.Set("User-Agent", "recon-hub/recon-tech-cve")
	applyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: base + ": " + err.Error()})
		return nil, nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512<<10))
	body := string(b)

	dets := fingerprint(resp, body)
	for _, d := range dets {
		emit(ev{Type: "asset", Kind: "tech", Value: d.Product + "@" + d.Version})
	}

	matches := matchVulns(dets)
	for _, m := range matches {
		emit(ev{
			Type: "finding", Severity: m.Vuln.Severity, FindingType: "outdated-software",
			Title: fmt.Sprintf("%s %s desatualizado (corrigido em %s) — %s", m.Det.Product, m.Det.Version, m.Vuln.FixedIn, m.Vuln.CVE),
			Asset: base,
			Evidence: fmt.Sprintf(
				"%s. Detectado via: %s. %s",
				m.Vuln.Desc, m.Det.Evidence,
				"Versão inferida do fingerprint passivo — confirme manualmente antes de reportar (o header pode estar desatualizado por engano, ou ser um proxy reescrevendo o Server)."),
			Meta: map[string]any{
				"produto": m.Det.Product, "versao_detectada": m.Det.Version,
				"corrigido_em": m.Vuln.FixedIn, "cve": m.Vuln.CVE,
			},
		})
	}
	return dets, matches
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
