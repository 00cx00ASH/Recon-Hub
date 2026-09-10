// scan-ssrf — injeta URLs de recursos internos/bem-conhecidos (metadata de
// nuvem, loopback, file://) em parâmetros que classicamente são buscados
// pelo SERVIDOR (webhook, import, proxy, avatar por URL…) e só reporta
// quando a RESPOSTA prova que o servidor realmente buscou aquele recurso —
// nunca só pela presença do payload. Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
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
		flagTarget = flag.String("target", "", "URL alvo (pode já ter query)")
		flagURLs   = flag.String("urls", "", "várias URLs por vírgula/linha")
		flagURLsF  = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagParams = flag.String("params", "", "nomes de parâmetro extra (csv)")
		flagConc   = flag.Int("concurrency", 0, "workers (0 = param/10)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/6000)")
		flagMaxP   = flag.Int("max-params", 0, "teto de parâmetros por URL (0 = param/60)")
		flagCand   = flag.Bool("candidates", false, "reportar também candidatos sem confirmação de conteúdo (localhost/loopback)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 6000)) * time.Millisecond
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 10)
	maxParams := pick(*flagMaxP, intParam(pl.Params, "max_params"), 60)
	reportCandidates := *flagCand || boolParam(pl.Params, "candidates")

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

	params := paramNames(*flagParams + "\n" + strParam(pl.Params, "params"))
	if len(params) > maxParams {
		params = params[:maxParams]
	}
	targets := ssrfTargets()

	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	type task struct{ base, param string }
	var tasks []task
	for _, b := range bases {
		for _, p := range params {
			tasks = append(tasks, task{b, p})
		}
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf(
		"%d URL(s) × %d parâmetro(s) × %d alvo(s) internos — candidatos sem confirmação: %v",
		len(bases), len(params), len(targets), reportCandidates)})

	var (
		wg              sync.WaitGroup
		ch              = make(chan task)
		mu2             sync.Mutex
		done, reqs, hit int
	)
	worker := func() {
		defer wg.Done()
		for t := range ch {
			baseline := baselineProbe(client, t.base, t.param)
			for _, tg := range targets {
				u := withParam(t.base, t.param, tg.URL)
				if u == "" {
					continue
				}
				status, body := doProbe(client, u)
				mu2.Lock()
				reqs++
				mu2.Unlock()
				if status == 0 {
					continue
				}
				if tg.confirm != nil {
					if tg.confirm(body) {
						reportConfirmed(t.base, t.param, tg, u)
						mu2.Lock()
						hit++
						mu2.Unlock()
						break // um hit confirmado por (base,param) já basta
					}
					continue
				}
				if reportCandidates && looksDifferent(baseline, status, len(body)) {
					reportCandidate(t.base, t.param, tg, u, baseline, status, len(body))
					mu2.Lock()
					hit++
					mu2.Unlock()
					break
				}
			}
			mu2.Lock()
			done++
			d := done
			mu2.Unlock()
			if d%25 == 0 || d == len(tasks) {
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

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d URL(s), %d requisições, %d achado(s)", len(bases), reqs, hit)})
}

func reportConfirmed(base, param string, tg ssrfTarget, u string) {
	emit(ev{Type: "asset", Kind: "url", Value: u})
	emit(ev{
		Type: "finding", Severity: tg.Sev, FindingType: "ssrf-confirmed",
		Title:    "SSRF confirmado em " + param + " (" + hostOf(base) + ") — " + tg.Label,
		Asset:    u,
		Evidence: "parâmetro " + param + " apontado pra " + tg.URL + " — a resposta contém o conteúdo do recurso interno (" + tg.Label + "), prova de que o servidor buscou o recurso.",
		Meta:     map[string]any{"param": param, "target": tg.Label, "url_injetada": tg.URL},
	})
}

func reportCandidate(base, param string, tg ssrfTarget, u, baseline string, status, bodyLen int) {
	emit(ev{Type: "asset", Kind: "url", Value: u})
	emit(ev{
		Type: "finding", Severity: tg.Sev, FindingType: "ssrf-candidate",
		Title:    "SSRF candidato em " + param + " (" + hostOf(base) + ") — " + tg.Label,
		Asset:    u,
		Evidence: fmt.Sprintf("parâmetro %s apontado pra %s: status %d, %d byte(s) — difere do baseline (%s). SEM confirmação de conteúdo: pode ser blind SSRF, mas precisa de um collaborator OOB (fora do escopo desta ferramenta) pra confirmar 100%%.", param, tg.URL, status, bodyLen, baseline),
		Meta:     map[string]any{"param": param, "target": tg.Label, "url_injetada": tg.URL, "confirmado": false},
	})
}

// baselineProbe busca a resposta de um host que não existe (canary aleatório
// e único por par base/param) — é contra isso que os alvos "sem assinatura"
// (localhost, loopback) são comparados pra decidir se a resposta é
// suspeita o bastante pra virar candidato.
func baselineProbe(c *http.Client, base, param string) string {
	nonce := fmt.Sprintf("ssrf-baseline-%d-nonexistent.invalid", rand.Int63())
	u := withParam(base, param, "http://"+nonce+"/")
	if u == "" {
		return "erro=0 bytes=0"
	}
	status, body := doProbe(c, u)
	return fmt.Sprintf("status=%d bytes=%d", status, len(body))
}

// looksDifferent: heurística simples — se o status ou o tamanho do corpo
// mudou de forma perceptível em relação ao baseline (host inexistente), a
// resposta pro alvo interno é digna de nota. Ainda assim fica marcada como
// candidato, nunca finding confirmado.
func looksDifferent(baseline string, status, bodyLen int) bool {
	var bStatus, bLen int
	fmt.Sscanf(baseline, "status=%d bytes=%d", &bStatus, &bLen)
	if status == 0 {
		return false // a própria requisição falhou, não dá pra comparar
	}
	if bStatus == 0 && status != 0 {
		return true // baseline nem respondeu, o alvo respondeu
	}
	if status != bStatus {
		return true
	}
	diff := bodyLen - bLen
	if diff < 0 {
		diff = -diff
	}
	return diff > 200 // corpo mudou de tamanho de forma perceptível
}

func doProbe(c *http.Client, u string) (status int, body string) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "recon-hub/scan-ssrf")
	applyAuth(req)
	resp, err := c.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	return resp.StatusCode, string(b)
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

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Host
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

// paramNames junta os nomes extra (csv) com a lista embutida de nomes
// classicamente buscados server-side.
func paramNames(csv string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, p := range splitList(csv) {
		add(p)
	}
	for _, p := range builtinParams {
		add(p)
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

func boolParam(m map[string]any, k string) bool {
	switch v := m[k].(type) {
	case bool:
		return v
	case string:
		b, _ := strconv.ParseBool(v)
		return b
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
