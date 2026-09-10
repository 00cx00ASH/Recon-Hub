// scan-smuggling — detecta candidatos a HTTP Request Smuggling (CL.TE /
// TE.CL) por timing oracle: manda um corpo propositalmente ambíguo entre
// Content-Length e Transfer-Encoding numa conexão TCP isolada e mede se o
// servidor demora anormalmente pra responder, comparado com uma requisição
// de baseline normal na mesma conexão/alvo. NUNCA encadeia uma 2ª requisição
// real pra "provar" o desync lendo a resposta de outro usuário — é
// deliberadamente a técnica mais segura pra testar isso sem risco de
// interceptar tráfego alheio. Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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
		flagConc   = flag.Int("concurrency", 0, "URLs testadas em paralelo (0 = param/2 — baixo de propósito)")
		flagReadMs = flag.Int("read-timeout-ms", 0, "quanto esperar por resposta antes de considerar 'travou' (0 = param/5000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	readTimeout := time.Duration(pick(*flagReadMs, intParam(pl.Params, "read_timeout_ms"), 5000)) * time.Millisecond
	dialTimeout := 8 * time.Second
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 2)
	if conc > 5 {
		// teste de timing sob concorrência alta vira ruído (fila de rede
		// mascara a demora que estamos tentando medir) — e é mais gentil
		// com a infra do alvo. Capado de propósito, mesmo se pedirem mais.
		conc = 5
	}

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

	emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf(
		"%d URL(s) — teste de timing em conexão isolada por probe, sem encadear requisição real (seguro pra produção, mas gera 2 conexões incomuns por URL)", len(bases))})

	var (
		wg  sync.WaitGroup
		ch  = make(chan string)
		mu2 sync.Mutex
		hit int
	)
	worker := func() {
		defer wg.Done()
		for base := range ch {
			testURL(base, readTimeout, dialTimeout, &mu2, &hit)
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

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d URL(s) testadas, %d candidato(s)", len(bases), hit)})
}

func testURL(base string, readTimeout, dialTimeout time.Duration, mu2 *sync.Mutex, hit *int) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		emit(ev{Type: "log", Level: "warn", Msg: "URL inválida, pulando: " + base})
		return
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}

	baseElapsed, baseTimedOut, _ := sendAndTime(u, baselineRequest(u.Host, path), readTimeout, dialTimeout)
	emit(ev{Type: "asset", Kind: "url", Value: base})
	if baseTimedOut {
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf(
			"%s: baseline já não respondeu em %s — alvo lento/instável, pulando (sem baseline confiável não dá pra comparar)", base, readTimeout)})
		return
	}

	// só considera "suspeito" um probe que demorou perto do teto do
	// read-timeout E claramente mais que o baseline — não só "um pouco mais
	// lento" (rede tem variação normal).
	threshold := baseElapsed*3 + 500*time.Millisecond
	if threshold > readTimeout-200*time.Millisecond {
		threshold = readTimeout - 200*time.Millisecond
	}

	clteElapsed, clteTimedOut, _ := sendAndTime(u, clteRequest(u.Host, path), readTimeout, dialTimeout)
	if clteTimedOut || clteElapsed >= threshold {
		reportCandidate(base, "http-smuggling-cl-te", "CL.TE", clteElapsed, baseElapsed, clteTimedOut)
		mu2.Lock()
		*hit++
		mu2.Unlock()
	}

	teclElapsed, teclTimedOut, _ := sendAndTime(u, teclRequest(u.Host, path), readTimeout, dialTimeout)
	if teclTimedOut || teclElapsed >= threshold {
		reportCandidate(base, "http-smuggling-te-cl", "TE.CL", teclElapsed, baseElapsed, teclTimedOut)
		mu2.Lock()
		*hit++
		mu2.Unlock()
	}

	emit(ev{Type: "progress", Msg: "concluído: " + base})
}

func reportCandidate(base, ftype, label string, probeElapsed, baseElapsed time.Duration, timedOut bool) {
	status := fmt.Sprintf("demorou %s", probeElapsed.Round(time.Millisecond))
	if timedOut {
		status = fmt.Sprintf("não respondeu em %s (timeout)", probeElapsed.Round(time.Millisecond))
	}
	emit(ev{
		Type: "finding", Severity: "high", FindingType: ftype,
		Title: "Candidato a HTTP request smuggling (" + label + ") em " + hostOf(base),
		Asset: base,
		Evidence: fmt.Sprintf(
			"probe %s %s, contra um baseline de %s — diferença de timing consistente com um componente na cadeia (proxy/CDN/origem) interpretando o corpo por %s enquanto outro usa %s. SEM confirmação de desync real (a ferramenta nunca encadeia uma 2ª requisição pra não arriscar ler resposta de outro usuário) — confirme manualmente (repita o teste 2-3x pra descartar rede instável; Burp Suite com HTTP Request Smuggler é o próximo passo pra confirmar de verdade) antes de reportar.",
			label, status, baseElapsed.Round(time.Millisecond),
			map[string]string{"CL.TE": "Content-Length", "TE.CL": "Transfer-Encoding"}[label],
			map[string]string{"CL.TE": "Transfer-Encoding", "TE.CL": "Content-Length"}[label]),
		Meta: map[string]any{
			"tipo": label, "confirmado": false,
			"baseline_ms": baseElapsed.Milliseconds(), "probe_ms": probeElapsed.Milliseconds(), "timeout": timedOut,
		},
	})
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
