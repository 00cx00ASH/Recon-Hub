// scan-xss-dom — XSS DOM-based via navegador headless de verdade
// (chromedp/Chrome DevTools Protocol), o único jeito de confirmar
// os dois casos que scan-xss (requisição HTTP crua) é estruturalmente
// incapaz de ver:
//
//   - vetor hash: o fragmento da URL nunca chega no servidor — só existe
//     no navegador. Um app que lê location.hash e insere no DOM sem
//     sanitizar é invisível pra qualquer scanner que só olhe a resposta
//     HTTP.
//   - vetor query: a resposta HTTP inicial pode escapar certinho (scan-xss
//     não acharia nada), mas o JS do lado do CLIENTE relê
//     location.search/URLSearchParams e insere sem sanitizar depois que a
//     página já carregou — de novo, só executar o JS revela isso.
//
// Confirma por EXECUÇÃO real: o payload seta uma propriedade JS
// (window.__rhxss_<token>, token aleatório por candidato) só se o
// navegador tratar o valor como código, não texto — nunca por heurística
// de texto aparecendo na resposta. Não fala HTTP puro (não usa
// http.Client) — não usa proxy.go/applyProxy pela mesma exceção do
// TOOL_CONTRACT que scan-mongodb já documenta; proxy é suportado só no
// allocator local (ver buildAllocator em browser.go), nunca no sidecar
// compartilhado.
//
// Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
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

// embedded fallback — mesma lista base do scan-xss (params classicamente
// renderizados de volta), usada só se nenhuma wordlist for resolvida.
var builtinParams = []string{
	"q", "query", "search", "s", "keyword", "text", "input", "value",
	"name", "title", "message", "msg", "comment", "content", "id",
	"ref", "tag", "category", "page", "redirect", "url", "next",
}

func main() {
	var (
		flagTarget     = flag.String("target", "", "URL alvo")
		flagURLs       = flag.String("urls", "", "várias URLs por vírgula/linha")
		flagURLsF      = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagWL         = flag.String("wordlist", "", "wordlist de nomes de parâmetro (vetor query)")
		flagParams     = flag.String("params", "", "nomes de parâmetro extra, separados por vírgula (vetor query)")
		flagMaxP       = flag.Int("max-params", 0, "teto de parâmetros testados por URL (0 = param/25)")
		flagConc       = flag.Int("concurrency", 0, "abas de navegador simultâneas (0 = param/3 — cada aba é bem mais cara que uma requisição HTTP)")
		flagTOms       = flag.Int("timeout-ms", 0, "timeout de navegação por candidato (0 = param/15000)")
		flagSettleMs   = flag.Int("settle-ms", 0, "espera após a navegação antes de checar execução, pro JS assíncrono da página rodar (0 = param/900)")
		flagSkipHash   = flag.Bool("skip-hash", false, "não testar o vetor hash")
		flagSkipQ      = flag.Bool("skip-query", false, "não testar o vetor query")
		flagChromeURL  = flag.String("chrome-url", "", "endpoint CDP remoto (ws://host:porta ou http://host:porta) — default: RECONHUB_CHROME_URL ou navegador local")
		flagChromePath = flag.String("chrome-path", "", "caminho do binário Chrome/Chromium local (só usado sem chrome-url)")
		flagPretty     = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	maxParams := pick(*flagMaxP, intParam(pl.Params, "max_params"), 25)
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 3)
	navTimeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 15000)) * time.Millisecond
	settle := time.Duration(pick(*flagSettleMs, intParam(pl.Params, "settle_ms"), 900)) * time.Millisecond
	skipHash := *flagSkipHash || boolParam(pl.Params, "skip_hash")
	skipQuery := *flagSkipQ || boolParam(pl.Params, "skip_query")

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

	var params []string
	if !skipQuery {
		wlPath := firstNonEmpty(*flagWL, strParam(pl.Params, "wordlist"), os.Getenv("RECONHUB_PARAM_WORDLIST"))
		params = builtinParams
		if wlPath != "" {
			if lines, err := readLines(wlPath); err == nil && len(lines) > 0 {
				params = lines
			} else if err != nil {
				emit(ev{Type: "log", Level: "warn", Msg: "wordlist '" + wlPath + "' não lida (" + err.Error() + ") — usando lista embutida"})
			}
		}
		params = mergeParams(*flagParams+"\n"+strParam(pl.Params, "params"), params)
		if len(params) > maxParams {
			params = params[:maxParams]
		}
	}

	allocCtx, allocCancel, mode := buildAllocator(firstNonEmpty(*flagChromeURL, strParam(pl.Params, "chrome_url"), os.Getenv("RECONHUB_CHROME_URL")),
		firstNonEmpty(*flagChromePath, strParam(pl.Params, "chrome_path"), os.Getenv("RECONHUB_CHROME_PATH")))
	defer allocCancel()
	emit(ev{Type: "log", Level: "info", Msg: "navegador: " + mode})

	type task struct {
		base, vec, param, url, token string
	}
	var tasks []task
	for _, b := range bases {
		if !skipHash {
			tok := randToken()
			tasks = append(tasks, task{b, "hash", "", withHash(b, domPayload(tok)), tok})
		}
		if !skipQuery {
			for _, p := range params {
				tok := randToken()
				u, err := withQueryParam(b, p, domPayload(tok))
				if err != nil {
					continue
				}
				tasks = append(tasks, task{b, "query", p, u, tok})
			}
		}
	}
	if len(tasks) == 0 {
		emit(ev{Type: "error", Msg: "nada pra testar (skip_hash e skip_query juntos desligam tudo?)"})
		os.Exit(2)
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d URL(s) base, %d candidato(s) (hash + query), %d aba(s) simultânea(s)", len(bases), len(tasks), conc)})

	var (
		wg          sync.WaitGroup
		ch          = make(chan task)
		mu2         sync.Mutex
		done, found int
	)
	worker := func() {
		defer wg.Done()
		for t := range ch {
			confirmed, err := checkExecution(allocCtx, t.url, t.token, navTimeout, settle)
			mu2.Lock()
			done++
			d := done
			mu2.Unlock()
			if d%25 == 0 || d == len(tasks) {
				emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d", d, len(tasks))})
			}
			if err != nil {
				continue // timeout/erro de navegação — não é sinal de nada, só pula
			}
			if !confirmed {
				continue
			}
			mu2.Lock()
			found++
			mu2.Unlock()
			detail := t.vec
			if t.param != "" {
				detail = "param " + t.param
			}
			emit(ev{Type: "asset", Kind: "url", Value: t.url})
			emit(ev{
				Type: "finding", Severity: "high", FindingType: "dom-xss",
				Title:    fmt.Sprintf("DOM XSS em %s (%s) — %s", t.base, t.vec, detail),
				Asset:    t.url,
				Evidence: fmtEvidence(t.vec, detail),
				Meta:     map[string]any{"vector": t.vec, "param": t.param, "base": t.base},
			})
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

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d URL(s), %d candidato(s) testado(s), %d DOM XSS confirmado(s)", len(bases), len(tasks), found)})
}

// checkExecution abre uma aba NOVA e isolada (nunca reaproveita estado de
// cookies/localStorage entre candidatos — cada teste começa limpo, e a aba
// fecha no fim independente do resultado), navega até u, espera settle
// pro JS assíncrono da página rodar, e avalia se o payload foi executado.
func checkExecution(allocCtx context.Context, u, token string, navTimeout, settle time.Duration) (bool, error) {
	// WithErrorf/WithLogf silenciam o logger interno padrão do chromedp
	// (log.Printf pro stderr, que o hub captura como log nível error) —
	// ele registra todo evento CDP que não consegue desserializar (ex:
	// campo novo que uma versão de Chrome manda e essa versão do cdproto
	// ainda não conhece), o que é ruído cosmético sem relação nenhuma com
	// o resultado real da navegação/avaliação. Erro de verdade (timeout,
	// falha de navegação) continua chegando pelo `err` que chromedp.Run
	// devolve, tratado normalmente pelo chamador.
	tabCtx, cancel := chromedp.NewContext(allocCtx, chromedp.WithErrorf(func(string, ...any) {}))
	defer cancel()
	tabCtx, cancelTO := context.WithTimeout(tabCtx, navTimeout)
	defer cancelTO()

	var result bool
	err := chromedp.Run(tabCtx,
		chromedp.Navigate(u),
		chromedp.Sleep(settle),
		chromedp.Evaluate(evalExpr(token), &result),
	)
	return result, err
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

// mergeParams mescla os nomes extra (csv/linha, prioridade — testados
// primeiro) com a wordlist base, deduplicando preservando ordem. Mesmo
// padrão de scan-xss/scan-sqli/scan-ssti.
func mergeParams(extra string, base []string) []string {
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
