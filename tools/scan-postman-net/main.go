// scan-postman-net — busca na rede pública do Postman por um termo (domínio,
// nome da empresa, produto), lista as collections/workspaces públicas, baixa o
// JSON de cada collection (run.pstmn.io) e varre por segredos e hosts internos.
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
		flagTarget = flag.String("target", "", "termo de busca (domínio, empresa, produto)")
		flagSize   = flag.Int("size", 0, "resultados por busca (0 = param/25)")
		flagNoDeep = flag.Bool("no-deep", false, "não baixar o JSON de cada collection")
		flagDomain = flag.String("match-domain", "", "domínio p/ marcar hosts relacionados (default: o termo, se parecer domínio)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/15000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 15000)) * time.Millisecond
	size := pick(*flagSize, intParam(pl.Params, "size"), 25)
	deep := !*flagNoDeep && !boolParam(pl.Params, "no_deep")

	query := strings.TrimSpace(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	if query == "" {
		emit(ev{Type: "error", Msg: "informe um termo de busca (ex exemplo.com ou 'ACME Corp')"})
		os.Exit(2)
	}
	matchDomain := firstNonEmpty(*flagDomain, strParam(pl.Params, "match_domain"))
	if matchDomain == "" && looksDomain(query) {
		matchDomain = strings.ToLower(query)
	}

	client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("buscando %q na rede pública do Postman (size %d, deep=%v)", query, size, deep)})

	body, st, err := postJSON("https://www.postman.com/_api/ws/proxy", searchRequest(query, size))
	if err != nil {
		emit(ev{Type: "error", Msg: "busca no Postman falhou: " + err.Error()})
		os.Exit(1)
	}
	if st != 200 {
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("proxy respondeu %d — a API pode ter mudado", st)})
		emit(ev{Type: "done", OK: true, Msg: "0 resultados"})
		return
	}
	hits, perr := parseSearch(body)
	if perr != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "resposta em formato inesperado: " + perr.Error()})
		emit(ev{Type: "done", OK: true, Msg: "0 resultados"})
		return
	}
	if len(hits) == 0 {
		emit(ev{Type: "done", OK: true, Msg: "nenhuma collection/workspace pública pro termo"})
		return
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d resultado(s)", len(hits))})

	nColl := 0
	for _, h := range hits {
		emit(ev{Type: "asset", Kind: "url", Value: h.publicURL()})
		emit(ev{Type: "finding", Severity: "info", FindingType: "postman-public-entity",
			Title:    fmt.Sprintf("Postman %s público: %q por %s", h.Type, h.Name, orDash(h.Publisher)),
			Asset:    h.publicURL(),
			Evidence: fmt.Sprintf("workspace %q (@%s). %s", h.Workspace, orDash(h.Handle), trunc(h.Desc, 160)),
			Meta:     map[string]any{"type": h.Type, "id": h.ID, "publisher": h.Publisher, "handle": h.Handle, "workspace": h.Workspace}})

		if h.Type != "collection" || !deep {
			continue
		}
		nColl++
		cj, cst, cerr := get("https://run.pstmn.io/collections/" + url.PathEscape(h.ID))
		if cerr != nil || cst != 200 || !strings.Contains(cj, `"item"`) {
			emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("collection %s: JSON indisponível (%d)", h.ID, cst)})
			continue
		}
		auditCollection(h, cj, matchDomain)
	}

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d resultado(s), %d collection(s) baixada(s), %d finding(s)", len(hits), nColl, finds)})
}

func auditCollection(h pmHit, cj, matchDomain string) {
	for _, s := range scanSecrets(cj) {
		emit(ev{Type: "finding", Severity: s.Severity, FindingType: "postman-secret-in-collection",
			Title:    fmt.Sprintf("segredo (%s) na collection pública %q", s.Kind, h.Name),
			Asset:    h.publicURL(),
			Evidence: fmt.Sprintf("%s = %s embutido numa requisição/variável da collection de @%s", s.Kind, s.Value, orDash(h.Handle)),
			Meta:     map[string]any{"kind": s.Kind, "collection_id": h.ID, "publisher": h.Publisher}})
	}
	hosts := internalHosts(cj, matchDomain)
	if len(hosts) > 0 {
		emit(ev{Type: "finding", Severity: "low", FindingType: "postman-internal-host",
			Title:    fmt.Sprintf("%d host(s) interno(s)/relacionado(s) na collection %q", len(hosts), h.Name),
			Asset:    h.publicURL(),
			Evidence: strings.Join(trimList(hosts, 25), ", "),
			Meta:     map[string]any{"hosts": hosts, "collection_id": h.ID}})
		for _, host := range hosts {
			emit(ev{Type: "asset", Kind: "subdomain", Value: host})
		}
	}
}

// --- http ---

func postJSON(u, body string) (string, int, error) {
	req, err := http.NewRequest(http.MethodPost, u, strings.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "recon-hub/scan-postman-net")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	return string(b), resp.StatusCode, nil
}

func get(u string) (string, int, error) {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "recon-hub/scan-postman-net")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 24<<20))
	return string(b), resp.StatusCode, nil
}

// --- helpers ---

func looksDomain(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return !strings.Contains(s, " ") && strings.Contains(s, ".") &&
		!strings.Contains(s, "/") && len(s) > 3
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

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func trunc(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
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
