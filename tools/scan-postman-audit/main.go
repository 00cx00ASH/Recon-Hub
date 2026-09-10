// scan-postman-audit — auditoria PROFUNDA de uma collection do Postman
// (por id ou URL pública, ou todas de um workspace público): baixa o JSON
// completo (run.pstmn.io), inventaria os requests, e varre por segredos, PII
// (e-mail, CPF, SSN, cartão com Luhn, IBAN, telefone), auth hardcoded e hosts
// internos. Contrato NDJSON do recon-hub no stdout.
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
		flagTarget = flag.String("target", "", "id da collection, URL pública, ou URL de workspace")
		flagIDs    = flag.String("collections", "", "vários ids/URLs por vírgula/linha")
		flagDomain = flag.String("match-domain", "", "domínio p/ marcar hosts relacionados")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/15000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 15000)) * time.Millisecond
	matchDomain := strings.ToLower(firstNonEmpty(*flagDomain, strParam(pl.Params, "match_domain")))

	client = &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
			DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	seen := map[string]bool{}
	var targets []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s != "" && !seen[s] {
			seen[s] = true
			targets = append(targets, s)
		}
	}
	add(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	for _, s := range splitList(firstNonEmpty(*flagIDs, strParam(pl.Params, "collections"), os.Getenv("RECONHUB_PARAM_COLLECTIONS"))) {
		add(s)
	}
	if len(targets) == 0 {
		emit(ev{Type: "error", Msg: "informe o id/URL de uma collection ou workspace do Postman"})
		os.Exit(2)
	}

	// expande URLs de workspace em collections
	var colIDs []string
	for _, t := range targets {
		if id := collectionID(t); id != "" {
			colIDs = append(colIDs, id)
			continue
		}
		if m := reWSslug.FindStringSubmatch(t); m != nil {
			ids := workspaceCollections(m[1], m[2])
			if len(ids) == 0 {
				emit(ev{Type: "log", Level: "warn", Msg: "workspace " + t + ": não consegui listar as collections"})
			}
			colIDs = append(colIDs, ids...)
			continue
		}
		emit(ev{Type: "log", Level: "warn", Msg: "não reconheci como id/URL de collection: " + t})
	}
	if len(colIDs) == 0 {
		emit(ev{Type: "done", OK: true, Msg: "nada para auditar"})
		return
	}

	audited := 0
	for _, id := range dedupe(colIDs) {
		if auditCollection(id, matchDomain) {
			audited++
		}
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d collection(s) auditada(s), %d finding(s)", audited, finds)})
}

func auditCollection(id, matchDomain string) bool {
	body, st, err := get("https://run.pstmn.io/collections/" + url.PathEscape(id))
	if err != nil || st != 200 || !strings.Contains(body, `"item"`) {
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("collection %s: JSON indisponível (%d)", id, st)})
		return false
	}
	var col struct {
		Info struct {
			Name string `json:"name"`
		} `json:"info"`
		Item     []any          `json:"item"`
		Variable []any          `json:"variable"`
		Auth     map[string]any `json:"auth"`
	}
	_ = json.Unmarshal([]byte(body), &col)

	name := col.Info.Name
	if name == "" {
		name = id
	}
	pub := "https://www.postman.com/_collection/" + id
	emit(ev{Type: "asset", Kind: "url", Value: pub})

	// inventário
	var calls []apiCall
	walkItems(col.Item, &calls)
	bases := map[string]bool{}
	for _, c := range calls {
		if u, e := url.Parse(c.URL); e == nil && u.Host != "" {
			bases[u.Scheme+"://"+u.Host] = true
			emit(ev{Type: "asset", Kind: "endpoint", Value: strings.TrimSpace(c.Method + " " + c.URL)})
		}
	}
	emit(ev{Type: "finding", Severity: "info", FindingType: "postman-collection-inventory",
		Title:    fmt.Sprintf("collection %q: %d request(s), %d host(s)", name, len(calls), len(bases)),
		Asset:    pub,
		Evidence: "hosts: " + strings.Join(keys(bases), ", "),
		Meta:     map[string]any{"collection_id": id, "requests": len(calls), "hosts": keys(bases)}})

	// segredos + PII no JSON inteiro
	for _, h := range scanText(body) {
		ft := "postman-secret-in-collection"
		if h.Class == "pii" {
			ft = "postman-pii-in-collection"
		}
		emit(ev{Type: "finding", Severity: h.Severity, FindingType: ft,
			Title:    fmt.Sprintf("%s (%s) na collection %q", labelFor(h.Class), h.Kind, name),
			Asset:    pub,
			Evidence: h.Kind + " = " + h.Value + " embutido numa requisição/variável/exemplo",
			Meta:     map[string]any{"class": h.Class, "kind": h.Kind, "collection_id": id}})
	}

	// auth hardcoded (nível collection + por request)
	auditAuthBlock(col.Auth, name, pub, id)
	var authWalk func(items []any)
	authWalk = func(items []any) {
		for _, raw := range items {
			it, _ := raw.(map[string]any)
			if it == nil {
				continue
			}
			if sub, ok := it["item"].([]any); ok {
				authWalk(sub)
				continue
			}
			if req, ok := it["request"].(map[string]any); ok {
				if a, ok := req["auth"].(map[string]any); ok {
					auditAuthBlock(a, name, pub, id)
				}
			}
		}
	}
	authWalk(col.Item)

	// hosts internos
	if hosts := internalHosts(body, matchDomain); len(hosts) > 0 {
		emit(ev{Type: "finding", Severity: "low", FindingType: "postman-internal-host",
			Title:    fmt.Sprintf("%d host(s) interno(s)/relacionado(s) na collection %q", len(hosts), name),
			Asset:    pub,
			Evidence: strings.Join(trimList(hosts, 25), ", "),
			Meta:     map[string]any{"hosts": hosts, "collection_id": id}})
		for _, h := range hosts {
			emit(ev{Type: "asset", Kind: "subdomain", Value: h})
		}
	}
	return true
}

func auditAuthBlock(a map[string]any, name, pub, id string) {
	if a == nil {
		return
	}
	for _, h := range scanAuth(a) {
		emit(ev{Type: "finding", Severity: h.Severity, FindingType: "postman-hardcoded-auth",
			Title:    fmt.Sprintf("credencial hardcoded (%s) na collection %q", h.Kind, name),
			Asset:    pub,
			Evidence: h.Kind + " = " + h.Value + " (valor literal, não {{variável}})",
			Meta:     map[string]any{"kind": h.Kind, "collection_id": id}})
	}
}

// workspaceCollections lists collection ids of a public workspace via the search API.
func workspaceCollections(handle, slug string) []string {
	body := `{"service":"search","method":"POST","path":"/search-all","body":{"queryText":"` + slug + `","service":"search","requestOrigin":"srp","mergeEntities":true,"nonNestedRequests":true,"domain":"public","size":50}}`
	req, _ := http.NewRequest(http.MethodPost, "https://www.postman.com/_api/ws/proxy", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "recon-hub/scan-postman-audit")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var r struct {
		Data []struct {
			Document map[string]any `json:"document"`
		} `json:"data"`
	}
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	var ids []string
	for _, d := range r.Data {
		if asStr(d.Document["entityType"]) != "collection" {
			continue
		}
		if asStr(d.Document["publisherHandle"]) != handle {
			continue
		}
		if id := asStr(d.Document["id"]); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// --- helpers ---

func get(u string) (string, int, error) {
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "recon-hub/scan-postman-audit")
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 24<<20))
	return string(b), resp.StatusCode, nil
}

func labelFor(class string) string {
	switch class {
	case "pii":
		return "PII"
	case "auth":
		return "auth hardcoded"
	default:
		return "segredo"
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func trimList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], "…")
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

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t'
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
