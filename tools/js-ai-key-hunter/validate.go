package main

import (
	"io"
	"net/http"
	"strings"
	"time"
)

// valResult is the outcome of a read-only liveness check.
type valResult struct {
	state  string // valid | invalid | unknown | skipped
	detail string
}

// validateKey performs ONE read-only GET to the provider to check if `key` is
// live. Never writes, never spends credits beyond a metadata read. Only called
// when the user opts in (params.validate=true).
func validateKey(spec, key string, timeout time.Duration) valResult {
	c := &http.Client{Timeout: timeout}

	var url, authHeader, authValue string
	switch {
	case spec == "openai":
		url, authHeader, authValue = "https://api.openai.com/v1/models", "Authorization", "Bearer "+key
	case spec == "anthropic":
		url, authHeader, authValue = "https://api.anthropic.com/v1/models", "x-api-key", key
	case spec == "huggingface":
		url, authHeader, authValue = "https://huggingface.co/api/whoami-v2", "Authorization", "Bearer "+key
	case spec == "replicate":
		url, authHeader, authValue = "https://api.replicate.com/v1/account", "Authorization", "Bearer "+key
	case spec == "elevenlabs":
		url, authHeader, authValue = "https://api.elevenlabs.io/v1/user", "xi-api-key", key
	case spec == "deepgram":
		url, authHeader, authValue = "https://api.deepgram.com/v1/projects", "Authorization", "Token "+key
	case spec == "google-ai":
		url = "https://generativelanguage.googleapis.com/v1beta/models?key=" + key
	case strings.HasPrefix(spec, "openai-compat:"):
		base := strings.TrimPrefix(spec, "openai-compat:")
		url, authHeader, authValue = strings.TrimRight(base, "/")+"/v1/models", "Authorization", "Bearer "+key
	default:
		return valResult{"skipped", "sem checagem para este provedor"}
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return valResult{"unknown", err.Error()}
	}
	req.Header.Set("User-Agent", "recon-hub/js-ai-key-hunter")
	if authHeader != "" {
		req.Header.Set(authHeader, authValue)
	}
	if spec == "anthropic" {
		req.Header.Set("anthropic-version", "2023-06-01")
	}
	resp, err := c.Do(req)
	if err != nil {
		return valResult{"unknown", err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))

	switch {
	case resp.StatusCode == 200:
		return valResult{"valid", "HTTP 200 — a chave está ativa"}
	case resp.StatusCode == 401 || resp.StatusCode == 403:
		return valResult{"invalid", "HTTP " + itoa(resp.StatusCode) + " — chave rejeitada"}
	case resp.StatusCode == 429:
		return valResult{"valid", "HTTP 429 — rate-limited, mas a chave foi aceita"}
	default:
		return valResult{"unknown", "HTTP " + itoa(resp.StatusCode) + ": " + strings.TrimSpace(firstLine(string(body)))}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 160 {
		return s[:160]
	}
	return s
}
