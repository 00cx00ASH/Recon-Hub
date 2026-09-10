package main

import (
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

// searchRequest is the body sent to the Postman public search proxy.
func searchRequest(query string, size int) string {
	body := map[string]any{
		"service": "search",
		"method":  "POST",
		"path":    "/search-all",
		"body": map[string]any{
			"queryText":         query,
			"service":           "search",
			"requestOrigin":     "srp",
			"mergeEntities":     true,
			"nonNestedRequests": true,
			"domain":            "public",
			"size":              size,
		},
	}
	b, _ := json.Marshal(body)
	return string(b)
}

// pmHit is one search result.
type pmHit struct {
	Type      string // collection | workspace | request | api
	ID        string
	Name      string
	Publisher string
	Handle    string
	Workspace string
	WSSlug    string
	Desc      string
}

func (h pmHit) publicURL() string {
	switch h.Type {
	case "collection":
		if h.Handle != "" && h.WSSlug != "" {
			return "https://www.postman.com/" + h.Handle + "/" + h.WSSlug + "/collection/" + h.ID
		}
		return "https://www.postman.com/_collection/" + h.ID
	case "workspace":
		if h.Handle != "" && h.WSSlug != "" {
			return "https://www.postman.com/" + h.Handle + "/" + h.WSSlug
		}
	}
	return "https://www.postman.com/search?q=" + h.Name
}

// parseSearch pulls hits from the proxy response.
func parseSearch(body string) ([]pmHit, error) {
	var resp struct {
		Data []struct {
			Document map[string]any `json:"document"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		return nil, err
	}
	var out []pmHit
	for _, d := range resp.Data {
		doc := d.Document
		h := pmHit{
			Type:      str(doc["entityType"]),
			ID:        str(doc["id"]),
			Name:      str(doc["name"]),
			Publisher: str(doc["publisherName"]),
			Handle:    str(doc["publisherHandle"]),
			Workspace: str(doc["workspaceName"]),
			WSSlug:    str(doc["workspaceSlug"]),
			Desc:      str(doc["description"]),
		}
		if h.WSSlug == "" {
			if wss, ok := doc["workspaces"].([]any); ok && len(wss) > 0 {
				if w, ok := wss[0].(map[string]any); ok {
					h.WSSlug = str(w["slug"])
					if h.Workspace == "" {
						h.Workspace = str(w["name"])
					}
				}
			}
		}
		if h.ID == "" || h.Type == "" {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// --- secret scan over collection text ---

type secHit struct {
	Kind     string
	Severity string
	Value    string // redacted
}

var secretRes = []struct {
	kind, sev string
	re        *regexp.Regexp
	group     int
	entropy   float64
}{
	{"aws-access-key-id", "high", regexp.MustCompile(`\b((?:AKIA|ASIA)[A-Z0-9]{16})\b`), 1, 0},
	{"aws-secret-key", "critical", regexp.MustCompile(`(?i)aws.{0,20}?['"]([A-Za-z0-9/+=]{40})['"]`), 1, 4.0},
	{"google-api-key", "high", regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`), 1, 0},
	{"gcp-oauth-token", "high", regexp.MustCompile(`\b(ya29\.[0-9A-Za-z_\-]{20,})`), 1, 0},
	{"github-token", "high", regexp.MustCompile(`\b((?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36})\b`), 1, 0},
	{"slack-token", "high", regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b`), 1, 0},
	{"stripe-live-key", "critical", regexp.MustCompile(`\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b`), 1, 0},
	{"twilio-key", "high", regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`), 1, 0},
	{"sendgrid-key", "high", regexp.MustCompile(`\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b`), 1, 0},
	{"openai-key", "high", regexp.MustCompile(`\b(sk-(?:proj-)?[0-9A-Za-z_\-]{40,})`), 1, 3.2},
	{"private-key", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), 0, 0},
	{"jwt", "medium", regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`), 1, 0},
	{"basic-auth-url", "high", regexp.MustCompile(`\bhttps?://[A-Za-z0-9._%+\-]+:([^@\s/"']{6,})@`), 1, 0},
	{"bearer-token", "medium", regexp.MustCompile(`(?i)bearer\s+([A-Za-z0-9_\-\.=]{24,})`), 1, 3.4},
	{"generic-api-key", "medium", regexp.MustCompile(`(?i)["'](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|x-api-key)["']\s*:\s*["']([^"']{16,80})["']`), 1, 3.4},
}

func scanSecrets(text string) []secHit {
	seen := map[string]bool{}
	var out []secHit
	for _, p := range secretRes {
		for _, m := range p.re.FindAllStringSubmatch(text, -1) {
			v := m[0]
			if p.group < len(m) {
				v = m[p.group]
			}
			if p.entropy > 0 && shannon(v) < p.entropy {
				continue
			}
			if looksPlaceholder(v) {
				continue
			}
			key := p.kind + "\x00" + v
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, secHit{p.kind, p.sev, redact(v)})
		}
	}
	return out
}

var placeholders = []string{
	"your_", "your-", "example", "xxxx", "0000", "changeme", "placeholder",
	"<token>", "<your", "insert", "dummy", "sample", "replace", "abcabc",
	"123456", "token_here", "access_token", "secret_here", "{{", "}}",
}

func looksPlaceholder(v string) bool {
	l := strings.ToLower(v)
	for _, w := range placeholders {
		if strings.Contains(l, w) {
			return true
		}
	}
	return false
}

func shannon(s string) float64 {
	if s == "" {
		return 0
	}
	var f [256]float64
	for i := 0; i < len(s); i++ {
		f[s[i]]++
	}
	n := float64(len(s))
	h := 0.0
	for _, c := range f {
		if c > 0 {
			p := c / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

func redact(s string) string {
	if len(s) <= 10 {
		return "***"
	}
	return s[:4] + "…" + s[len(s)-4:]
}

// --- internal host detection ---

var hostRe = regexp.MustCompile(`https?://([a-zA-Z0-9.\-]+)(?::\d+)?`)

var internalHints = []string{
	"internal", "intranet", "corp", "staging", "stg", "qa", "uat", "dev",
	"test", "sandbox", "preprod", "pre-prod", "local", "vpn", "admin",
	"jenkins", "gitlab", "jira", "confluence", "grafana", "kibana", "consul",
	"vault", "nexus", "artifactory", "10.", "192.168.", "172.16.", "172.17.",
	"172.18.", "172.19.", "172.2", "172.30", "172.31", "localhost", ".lan",
	".corp", ".internal", ".local",
}

// internalHosts returns distinct hostnames from text that look non-public.
func internalHosts(text, matchDomain string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range hostRe.FindAllStringSubmatch(text, -1) {
		h := strings.ToLower(m[1])
		if seen[h] || h == "" {
			continue
		}
		hit := false
		if matchDomain != "" && (h == matchDomain || strings.HasSuffix(h, "."+matchDomain)) {
			hit = true
		}
		for _, hint := range internalHints {
			if strings.Contains(h, hint) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		// skip the obvious public ones
		if h == "api.getpostman.com" || strings.HasSuffix(h, ".postman.com") ||
			strings.HasSuffix(h, ".githubusercontent.com") || h == "schema.getpostman.com" {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}
