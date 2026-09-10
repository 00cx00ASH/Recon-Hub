package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// source is one passive data provider.
type source struct {
	name  string
	fetch func(c *http.Client, root string) ([]string, error)
}

// allSources — order is stable for reporting.
func allSources() []source {
	return []source{
		{"crtsh", srcCrtsh},
		{"certspotter", srcCertspotter},
		{"hackertarget", srcHackerTarget},
		{"alienvault", srcAlienVault},
		{"anubis", srcAnubis},
		{"rapiddns", srcRapidDNS},
		{"wayback", srcWayback},
	}
}

func get(c *http.Client, url string) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "recon-hub/recon-passive-enum")
	req.Header.Set("Accept", "application/json, text/plain, */*")
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 24<<20))
	return b, resp.StatusCode, nil
}

func srcCrtsh(c *http.Client, root string) ([]string, error) {
	for attempt := 0; attempt < 3; attempt++ {
		b, st, err := get(c, "https://crt.sh/?q=%25."+root+"&output=json")
		if err == nil && st == 200 && len(b) > 0 {
			if out, ok := parseCrtshHosts(b); ok {
				return out, nil
			}
		}
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	return nil, fmt.Errorf("crt.sh sem resposta utilizável")
}

// parseCrtshHosts extracts raw host candidates from crt.sh's JSON array
// (name_value can carry several SANs separated by \n). Separate from the
// fetch/retry loop above so it's unit testable against a captured response,
// without needing crt.sh reachable.
func parseCrtshHosts(b []byte) ([]string, bool) {
	var rows []struct {
		NameValue  string `json:"name_value"`
		CommonName string `json:"common_name"`
	}
	if json.Unmarshal(b, &rows) != nil {
		return nil, false
	}
	var out []string
	for _, r := range rows {
		for _, line := range strings.Split(r.NameValue, "\n") {
			out = append(out, line)
		}
		out = append(out, r.CommonName)
	}
	return out, true
}

func srcCertspotter(c *http.Client, root string) ([]string, error) {
	b, st, err := get(c, "https://api.certspotter.com/v1/issuances?domain="+root+
		"&include_subdomains=true&expand=dns_names")
	if err != nil {
		return nil, err
	}
	if st == 429 {
		return nil, fmt.Errorf("rate-limited (429)")
	}
	if st != 200 {
		return nil, fmt.Errorf("HTTP %d", st)
	}
	return parseCertspotterHosts(b)
}

// parseCertspotterHosts flattens dns_names across every issuance.
func parseCertspotterHosts(b []byte) ([]string, error) {
	var rows []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.DNSNames...)
	}
	return out, nil
}

func srcHackerTarget(c *http.Client, root string) ([]string, error) {
	b, st, err := get(c, "https://api.hackertarget.com/hostsearch/?q="+root)
	if err != nil {
		return nil, err
	}
	text := string(b)
	if st != 200 || strings.Contains(text, "API count exceeded") || strings.Contains(text, "error") {
		return nil, fmt.Errorf("indisponível (%d): %s", st, strings.TrimSpace(firstLine(text)))
	}
	return parseHackerTargetHosts(text), nil
}

// parseHackerTargetHosts reads hackertarget's CSV response ("host,ip\n...").
func parseHackerTargetHosts(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if h, _, ok := strings.Cut(strings.TrimSpace(line), ","); ok {
			out = append(out, h)
		}
	}
	return out
}

func srcAlienVault(c *http.Client, root string) ([]string, error) {
	b, st, err := get(c, "https://otx.alienvault.com/api/v1/indicators/domain/"+root+"/passive_dns")
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("HTTP %d", st)
	}
	return parseAlienVaultHosts(b)
}

// parseAlienVaultHosts reads OTX's passive_dns array.
func parseAlienVaultHosts(b []byte) ([]string, error) {
	var body struct {
		PassiveDNS []struct {
			Hostname string `json:"hostname"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal(b, &body); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range body.PassiveDNS {
		out = append(out, r.Hostname)
	}
	return out, nil
}

func srcAnubis(c *http.Client, root string) ([]string, error) {
	b, st, err := get(c, "https://jldc.me/anubis/subdomains/"+root)
	if err != nil {
		return nil, err
	}
	if st == 404 {
		return nil, nil // nada indexado
	}
	if st != 200 {
		return nil, fmt.Errorf("HTTP %d", st)
	}
	return parseAnubisHosts(b)
}

// parseAnubisHosts reads jldc.me's response: a plain JSON array of hostnames.
func parseAnubisHosts(b []byte) ([]string, error) {
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func srcRapidDNS(c *http.Client, root string) ([]string, error) {
	b, st, err := get(c, "https://rapiddns.io/subdomain/"+root+"?full=1")
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("HTTP %d", st)
	}
	return hostsFromText(string(b), root), nil
}

func srcWayback(c *http.Client, root string) ([]string, error) {
	b, st, err := get(c, "https://web.archive.org/cdx/search/cdx?url=*."+root+
		"&output=text&fl=original&collapse=urlkey&limit=40000")
	if err != nil {
		return nil, err
	}
	if st != 200 {
		return nil, fmt.Errorf("HTTP %d", st)
	}
	return hostsFromText(string(b), root), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 160 {
		return s[:160]
	}
	return s
}
