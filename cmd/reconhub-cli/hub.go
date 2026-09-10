package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// hubClient talks to a running recon-hub over its HTTP API. Same token/URL
// resolution convention as cmd/reconhub-mcp, so anything that works to
// configure one works for the other.
type hubClient struct {
	base  string
	token string
	http  *http.Client
}

func newHubClient() *hubClient {
	base := envOr("RECONHUB_URL", "http://127.0.0.1:7878")
	token := strings.TrimSpace(os.Getenv("RECONHUB_TOKEN"))
	if token == "" {
		if f := os.Getenv("RECONHUB_TOKEN_FILE"); f != "" {
			if b, err := os.ReadFile(f); err == nil {
				token = strings.TrimSpace(string(b))
			}
		}
	}
	if token == "" {
		candidates := []string{"data/token", "./data/token"}
		if exe, err := os.Executable(); err == nil {
			d := filepath.Dir(exe)
			candidates = append(candidates,
				filepath.Join(d, "data", "token"),
				filepath.Join(d, "..", "data", "token"),
			)
		}
		for _, p := range candidates {
			if b, err := os.ReadFile(p); err == nil {
				token = strings.TrimSpace(string(b))
				break
			}
		}
	}
	return &hubClient{
		base:  strings.TrimRight(base, "/"),
		token: token,
		http:  &http.Client{Timeout: 30 * time.Second},
	}
}

// call issues one request against the hub's API and decodes the JSON
// response into out (skip decoding by passing nil).
func (h *hubClient) call(method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}

	resp, err := h.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w (o recon-hub está rodando em %s?)", method, path, err, h.base)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))

	if resp.StatusCode == http.StatusUnauthorized {
		return fmt.Errorf("401 do recon-hub — defina RECONHUB_TOKEN (ou rode na pasta do hub p/ ler data/token)")
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("HTTP %d de %s %s: %s", resp.StatusCode, method, path, msg)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, out)
}

func (h *hubClient) get(path string, out any) error { return h.call(http.MethodGet, path, nil, out) }
func (h *hubClient) post(path string, body, out any) error {
	return h.call(http.MethodPost, path, body, out)
}
func (h *hubClient) put(path string, body, out any) error {
	return h.call(http.MethodPut, path, body, out)
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// qs builds a query string from non-empty values, e.g.
// qs(map[string]string{"program": p, "severity": sev}).
func qs(vals map[string]string) string {
	q := url.Values{}
	for k, v := range vals {
		if v != "" {
			q.Set(k, v)
		}
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}
