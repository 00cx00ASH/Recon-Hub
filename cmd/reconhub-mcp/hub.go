package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// hubClient talks to a running recon-hub over its HTTP API.
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
		// Convenience: read the token the hub saved locally. Try the working
		// dir first, then next to (and one level up from) this executable, so
		// the MCP server finds it no matter which cwd the client launches it in.
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

// call issues one request. body may be nil. It returns the decoded JSON (as
// any) plus the raw bytes for passing straight back to the MCP client.
func (h *hubClient) call(method, path string, body any) (json.RawMessage, error) {
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.base+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if h.token != "" {
		req.Header.Set("Authorization", "Bearer "+h.token)
	}

	resp, err := h.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w (o recon-hub está rodando em %s?)", method, path, err, h.base)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("401 do recon-hub — defina RECONHUB_TOKEN (ou rode o MCP na pasta do hub p/ ler data/token)")
	}
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return nil, fmt.Errorf("HTTP %d de %s %s: %s", resp.StatusCode, method, path, msg)
	}
	return json.RawMessage(raw), nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
