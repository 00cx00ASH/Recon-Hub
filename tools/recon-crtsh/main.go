// recon-crtsh — enumeração passiva de subdomínios via Certificate Transparency.
//
// Consulta crt.sh (output=json), normaliza os nomes e emite um evento
// `asset` kind=subdomain por host. Pensado para ser o 1º step de uma pipeline
// que alimenta scan-subdomain-takeover / js-bucket-scanner.
//
// Entradas (precedência): stdin JSON {target,params} > flags > env RECONHUB_*.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type payload struct {
	Target string         `json:"target"`
	Params map[string]any `json:"params"`
}

type crtRow struct {
	NameValue  string `json:"name_value"`
	CommonName string `json:"common_name"`
}

type ev struct {
	Type  string `json:"type"`
	Level string `json:"level,omitempty"`
	Msg   string `json:"msg,omitempty"`
	Kind  string `json:"kind,omitempty"`
	Value string `json:"value,omitempty"`
	OK    bool   `json:"ok,omitempty"`
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
		case "asset":
			fmt.Fprintln(w, "  "+e.Value)
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

func main() {
	var (
		flagDomain = flag.String("domain", "", "domínio (fallback do stdin/env)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout HTTP em ms (0 = param/30000)")
		flagWild   = flag.Bool("wildcards", false, "incluir entradas *.x como x")
		flagMax    = flag.Int("max", 0, "teto de hosts (0 = param/5000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer w.Flush()

	pl := readPayload()
	domain := cleanHost(firstNonEmpty(pl.Target, *flagDomain, os.Getenv("RECONHUB_TARGET")))
	if domain == "" {
		emit(ev{Type: "error", Msg: "informe o domínio (target ou -domain)"})
		os.Exit(2)
	}
	timeoutMS := pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 30000)
	maxHosts := pick(*flagMax, intParam(pl.Params, "max"), 5000)
	wild := *flagWild || boolParam(pl.Params, "wildcards")

	timeout := time.Duration(timeoutMS) * time.Millisecond
	set := map[string]struct{}{}
	sources := 0

	// fonte 1: crt.sh
	emit(ev{Type: "log", Level: "info", Msg: "consultando crt.sh: %." + domain})
	if rows, err := fetchCrtsh(domain, timeout); err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "crt.sh indisponível: " + err.Error()})
	} else {
		sources++
		n := len(set)
		for _, r := range rows {
			for _, raw := range strings.Split(r.NameValue+"\n"+r.CommonName, "\n") {
				if h := normalizeHost(raw, domain, wild); h != "" {
					set[h] = struct{}{}
				}
			}
		}
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("crt.sh: %d registro(s), +%d host(s)", len(rows), len(set)-n)})
	}

	// fonte 2: certspotter (complementar; sem token tem limite baixo)
	emit(ev{Type: "log", Level: "info", Msg: "consultando certspotter"})
	if names, err := fetchCertspotter(domain, timeout); err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "certspotter indisponível: " + err.Error()})
	} else {
		sources++
		n := len(set)
		for _, raw := range names {
			if h := normalizeHost(raw, domain, wild); h != "" {
				set[h] = struct{}{}
			}
		}
		emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("certspotter: %d nome(s), +%d host(s)", len(names), len(set)-n)})
	}

	if sources == 0 {
		// nenhuma fonte respondeu: não é falha da ferramenta (não derruba pipeline)
		emit(ev{Type: "done", OK: true, Msg: "0 subdomínio(s) — nenhuma fonte de CT respondeu"})
		return
	}

	hosts := make([]string, 0, len(set))
	for h := range set {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)

	if maxHosts > 0 && len(hosts) > maxHosts {
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf("%d hosts, truncando em %d", len(hosts), maxHosts)})
		hosts = hosts[:maxHosts]
	}
	for _, h := range hosts {
		emit(ev{Type: "asset", Kind: "subdomain", Value: h})
	}
	emit(ev{Type: "done", OK: true,
		Msg: fmt.Sprintf("%d subdomínio(s) de %d fonte(s) de Certificate Transparency", len(hosts), sources)})
}

func fetchCrtsh(domain string, timeout time.Duration) ([]crtRow, error) {
	endpoint := "https://crt.sh/?q=" + url.QueryEscape("%."+domain) + "&output=json"
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			DisableKeepAlives: true,
		},
	}
	const attempts = 4
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			time.Sleep(3 * time.Second)
		}
		req, _ := http.NewRequest(http.MethodGet, endpoint, nil)
		req.Header.Set("User-Agent", "recon-hub/recon-crtsh")
		req.Header.Set("Accept", "application/json")

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 128<<20))
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			// 404/429/5xx no crt.sh = "tente de novo", não "sem resultados"
			// (sem resultados é 200 com corpo "[]").
			lastErr = fmt.Errorf("HTTP %d (tentativa %d/%d)", resp.StatusCode, attempt, attempts)
			continue
		}
		trimmed := strings.TrimSpace(string(body))
		if !strings.HasPrefix(trimmed, "[") {
			lastErr = fmt.Errorf("resposta não-JSON de %d bytes (tentativa %d/%d)", len(trimmed), attempt, attempts)
			continue
		}
		return parseCrtshBody([]byte(trimmed))
	}
	return nil, lastErr
}

// parseCrtshBody parses crt.sh's JSON array response into rows. Kept
// separate from the HTTP retry loop above so it can be unit tested against a
// captured response body, without needing the network.
func parseCrtshBody(body []byte) ([]crtRow, error) {
	var rows []crtRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("JSON inválido: %w", err)
	}
	return rows, nil
}

// fetchCertspotter consulta a API pública do certspotter (sem token: limite
// baixo, pode dar 429). É complementar ao crt.sh.
func fetchCertspotter(domain string, timeout time.Duration) ([]string, error) {
	endpoint := "https://api.certspotter.com/v1/issuances?domain=" + url.QueryEscape(domain) +
		"&include_subdomains=true&expand=dns_names"
	client := &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true},
	}
	req, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	req.Header.Set("User-Agent", "recon-hub/recon-crtsh")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("rate-limited (use um token p/ subir o limite)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return parseCertspotterBody(body)
}

// parseCertspotterBody parses certspotter's issuances array, flattening
// dns_names across every issuance. Separate from the HTTP call above so it
// can be unit tested against a captured response body.
func parseCertspotterBody(body []byte) ([]string, error) {
	var issuances []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(body, &issuances); err != nil {
		return nil, fmt.Errorf("JSON inválido: %w", err)
	}
	var names []string
	for _, is := range issuances {
		names = append(names, is.DNSNames...)
	}
	return names, nil
}

func normalizeHost(raw, domain string, wild bool) string {
	h := strings.TrimSpace(strings.ToLower(raw))
	if h == "" || strings.ContainsAny(h, "@ \t") {
		return ""
	}
	if strings.HasPrefix(h, "*.") {
		if !wild {
			return ""
		}
		h = h[2:]
	}
	h = strings.TrimSuffix(h, ".")
	if h != domain && !strings.HasSuffix(h, "."+domain) {
		return ""
	}
	for _, r := range h {
		if !(r == '.' || r == '-' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')) {
			return ""
		}
	}
	return h
}

// --- entrada ---

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

func cleanHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "*.")
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func intParam(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		var n int
		fmt.Sscan(v, &n)
		return n
	}
	return 0
}

func boolParam(m map[string]any, k string) bool {
	b, _ := m[k].(bool)
	return b
}

func pick(vals ...int) int {
	for _, v := range vals {
		if v > 0 {
			return v
		}
	}
	return 0
}
