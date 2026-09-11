// scan-fuzz — content discovery por wordlist (estilo ffuf/gobuster), com
// calibração de soft-404. Contrato NDJSON do recon-hub no stdout.
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
	"os"
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
	Data        map[string]any `json:"data,omitempty"`
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
			fmt.Fprintf(out, "[%s] %s  %s\n", strings.ToUpper(e.Severity), e.Title, e.Evidence)
		case "done":
			fmt.Fprintln(out, "done: "+e.Msg)
		default:
			fmt.Fprintf(out, "[%s] %s\n", orInfo(e.Level), e.Msg)
		}
	} else {
		b, _ := json.Marshal(e)
		out.Write(b)
		out.WriteByte('\n')
	}
	out.Flush()
}
func orInfo(s string) string {
	if s == "" {
		return "info"
	}
	return s
}

func main() {
	var (
		flagTarget = flag.String("target", "", "URL base (fallback do stdin/env)")
		flagURLs   = flag.String("urls", "", "várias URLs base (vírgula/linha)")
		flagURLsF  = flag.String("urls-file", "", "arquivo com uma URL base por linha")
		flagWL     = flag.String("wordlist", "", "caminho da wordlist")
		flagExt    = flag.String("extensions", "", ".php,.bak,~ …")
		flagCodes  = flag.String("match-codes", "", "status que contam como hit")
		flagFilter = flag.Int("filter-size", -1, "esconder respostas desse tamanho")
		flagConc   = flag.Int("concurrency", 0, "workers")
		flagDelay  = flag.Int("delay-ms", 0, "pausa entre requisições de cada worker (espaça o tráfego pra não acionar WAF/rate-limit; 0 = usa o padrão)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout por req")
		flagRecD   = flag.Int("recursive-depth", 0, "níveis de recursão em diretório achado (0 = desligado)")
		flagMaxDir = flag.Int("max-recursive-dirs", 0, "teto de diretórios recursados no total (0 = param/50)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()

	seen := map[string]bool{}
	var bases []string
	addBase := func(s string) {
		if b := normBase(s); b != "" && !seen[b] {
			seen[b] = true
			bases = append(bases, b)
		}
	}
	addBase(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	for _, s := range splitLines(firstNonEmpty(*flagURLs, strParam(pl.Params, "urls"), os.Getenv("RECONHUB_PARAM_URLS"))) {
		addBase(s)
	}
	if f := firstNonEmpty(*flagURLsF, strParam(pl.Params, "urls_file"), os.Getenv("RECONHUB_PARAM_URLS_FILE")); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			for _, s := range splitLines(string(b)) {
				addBase(s)
			}
		}
	}
	if len(bases) == 0 {
		emit(ev{Type: "error", Msg: "informe a URL base (target) ou params.urls"})
		os.Exit(2)
	}

	wlPath := firstNonEmpty(*flagWL, strParam(pl.Params, "wordlist"), os.Getenv("RECONHUB_PARAM_WORDLIST"))
	if wlPath == "" {
		emit(ev{Type: "error", Msg: "escolha uma wordlist (param wordlist)"})
		os.Exit(2)
	}
	raw, err := os.ReadFile(wlPath)
	if err != nil {
		emit(ev{Type: "error", Msg: "wordlist: " + err.Error()})
		os.Exit(1)
	}
	words := wordsFrom(string(raw))
	if len(words) == 0 {
		emit(ev{Type: "error", Msg: "wordlist vazia: " + wlPath})
		os.Exit(1)
	}

	exts := splitCSV(firstNonEmpty(*flagExt, strParam(pl.Params, "extensions")))
	codes := parseCodes(firstNonEmpty(*flagCodes, strParam(pl.Params, "match_codes"), "200,204,301,302,307,401,403"))
	filterSize := *flagFilter
	if v, ok := pl.Params["filter_size"]; ok {
		if n := intParam(pl.Params, "filter_size"); n >= 0 || v != nil {
			filterSize = n
		}
	}
	// padrão mais conservador que o clássico "ffuf-style" — content discovery
	// em rajada de dezenas de req/s é o gatilho mais comum de bloqueio por
	// WAF/rate-limit, e a maioria dos programas de bug bounty proíbe tráfego
	// automatizado pesado. delay_ms pausa cada worker entre requisições.
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 10)
	if conc < 1 {
		conc = 10
	}
	delay := time.Duration(pick(*flagDelay, intParam(pl.Params, "delay_ms"), 25)) * time.Millisecond
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 7000)) * time.Millisecond
	recDepth := pick(*flagRecD, intParam(pl.Params, "recursive_depth"), 0)
	if recDepth < 0 {
		recDepth = 0
	}
	maxRecDirs := pick(*flagMaxDir, intParam(pl.Params, "max_recursive_dirs"), 50)

	fuzzTransport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        conc * 2,
		MaxIdleConnsPerHost: conc * 2,
		DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
	}
	applyProxy(fuzzTransport, timeout)
	client := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     withBlockRotation(fuzzTransport, func(msg string) { emit(ev{Type: "log", Level: "info", Msg: msg}) }),
	}

	recMsg := ""
	if recDepth > 0 {
		recMsg = fmt.Sprintf(" · recursivo até %d nível(is), teto %d diretório(s)", recDepth, maxRecDirs)
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf(
		"%d URL(s) base · %d palavras · exts=%v · codes=%v · %d workers · %s de pausa/req%s", len(bases), len(words), exts, sortedCodes(codes), conc, delay, recMsg)})

	totalReq, totalHits := 0, 0
	for _, base := range bases {
		r, h := runFuzz(client, base, words, exts, codes, filterSize, conc, delay, recDepth, maxRecDirs)
		totalReq += r
		totalHits += h
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf(
		"%d URL(s), %d requisições, %d hit(s)", len(bases), totalReq, totalHits)})
}

// candidate is one path to probe: word sozinha (bare — pode ser diretório,
// candidata a recursão se der hit) ou word+extensão (nunca é diretório —
// uma extensão como .php/.bak só faz sentido em arquivo).
type candidate struct {
	path string
	bare bool
}

func buildCandidates(words, exts []string) []candidate {
	var out []candidate
	for _, w := range words {
		out = append(out, candidate{w, true})
		for _, e := range exts {
			out = append(out, candidate{w + e, false})
		}
	}
	return out
}

// runFuzz calibra o soft-404 de base UMA vez (reaproveitado em toda
// recursão — recalibrar por diretório multiplicaria o custo em requisições
// pra um alvo que provavelmente responde igual em toda a árvore) e roda a
// wordlist em BFS: nível 0 é a raiz; um hit "bare" (sem extensão) com
// status 2xx/3xx vira candidato a diretório e entra na fila do próximo
// nível, até recDepth ou até o teto maxDirs de diretórios recursados no
// total (o que vier primeiro corta ali — sem isso, um alvo que responde
// 200 pra quase tudo explodiria o número de requisições exponencialmente).
// recDepth=0 é o comportamento de sempre: só a raiz, sem recursão nenhuma.
func runFuzz(client *http.Client, base string, words, exts []string, codes map[int]bool, filterSize, conc int, delay time.Duration, recDepth, maxDirs int) (reqs, hits int) {
	bl := calibrate(client, base, exts)
	if bl.present {
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%s — soft-404: status %d, ~%d bytes", base, bl.status, bl.size)})
	} else {
		emit(ev{Type: "log", Level: "warn", Msg: base + " — soft-404 não calibrado (alvo inconsistente)"})
	}

	candidates := buildCandidates(words, exts)
	visited := map[string]bool{"": true}
	queue := []string{""}
	dirsQueued := 0
	truncated := false

	for depth := 0; len(queue) > 0; depth++ {
		var next []string
		for _, prefix := range queue {
			r, h, dirs := fuzzLevel(client, base, prefix, candidates, codes, filterSize, conc, delay, bl)
			reqs += r
			hits += h
			if depth >= recDepth {
				continue // já no último nível permitido — acha, mas não recursa mais
			}
			for _, d := range dirs {
				childPrefix := prefix + "/" + d
				if visited[childPrefix] {
					continue
				}
				if dirsQueued >= maxDirs {
					truncated = true
					continue
				}
				visited[childPrefix] = true
				dirsQueued++
				next = append(next, childPrefix)
			}
		}
		queue = next
	}
	if truncated {
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("%s — teto de %d diretório(s) recursado(s) atingido, parou de aprofundar", base, maxDirs)})
	}
	return reqs, hits
}

// fuzzLevel roda a wordlist contra base+prefix e devolve, além de
// requisições/hits, os nomes (bare) que parecem diretório — pra quem
// chamou decidir se recursa.
func fuzzLevel(client *http.Client, base, prefix string, candidates []candidate, codes map[int]bool, filterSize, conc int, delay time.Duration, bl baseline) (reqs, hits int, dirs []string) {
	var (
		wg      sync.WaitGroup
		jobs    = make(chan candidate)
		mu      sync.Mutex
		done    int
		total   = len(candidates)
		dirsSet []string
	)
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for c := range jobs {
				if delay > 0 {
					time.Sleep(delay)
				}
				u := base + prefix + "/" + c.path
				st, sz, ok := probe(client, u)

				mu.Lock()
				done++
				d := done
				mu.Unlock()
				if d%250 == 0 || d == total {
					emit(ev{Type: "progress", Msg: fmt.Sprintf("%s%s %d/%d", base, prefix, d, total),
						Data: map[string]any{"pct": d * 100 / total, "done": d, "total": total}})
				}

				if !ok || !codes[st] || bl.isSoftNotFound(st, sz) {
					continue
				}
				if filterSize >= 0 && sz == filterSize {
					continue
				}
				mu.Lock()
				hits++
				if c.bare && st < 400 {
					dirsSet = append(dirsSet, c.path)
				}
				mu.Unlock()

				ft, sev := classify(st)
				emit(ev{Type: "asset", Kind: "url", Value: u})
				emit(ev{
					Type: "finding", Severity: sev, FindingType: ft,
					Title:    fmt.Sprintf("%s%s → HTTP %d (%d bytes)", base, prefix+"/"+c.path, st, sz),
					Asset:    u,
					Evidence: fmt.Sprintf("GET %s → %d, %d bytes", u, st, sz),
					Meta:     map[string]any{"status": st, "size": sz, "path": prefix + "/" + c.path, "base": base},
				})
			}
		}()
	}
	for _, c := range candidates {
		jobs <- c
	}
	close(jobs)
	wg.Wait()
	return total, hits, dirsSet
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

func normBase(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return strings.TrimRight(s, "/")
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func splitLines(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	}) {
		if p != "" && !strings.HasPrefix(p, "#") {
			out = append(out, p)
		}
	}
	return out
}

func parseCodes(s string) map[int]bool {
	m := map[int]bool{}
	for _, p := range splitCSV(s) {
		if n, err := strconv.Atoi(p); err == nil {
			m[n] = true
		}
	}
	return m
}

func sortedCodes(m map[int]bool) []int {
	var out []int
	for k := range m {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
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
