package main

import (
	"math"
	"regexp"
	"strings"
)

// --- collection id / url handling ---

var (
	reColID  = regexp.MustCompile(`\b(\d{4,}-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	reUUID   = regexp.MustCompile(`\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	reWSslug = regexp.MustCompile(`postman\.com/([a-z0-9][a-z0-9-]*)/([a-z0-9][a-z0-9-]*)`)
)

// collectionID pulls a runnable collection id from a raw id or a public URL.
func collectionID(s string) string {
	s = strings.TrimSpace(s)
	if m := reColID.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	if m := reUUID.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return ""
}

// --- request inventory ---

type apiCall struct {
	Method string
	URL    string
	Name   string
}

// walkItems recurses the Postman v2 item tree collecting requests.
func walkItems(items []any, out *[]apiCall) {
	for _, raw := range items {
		it, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if sub, ok := it["item"].([]any); ok {
			walkItems(sub, out)
			continue
		}
		req, ok := it["request"].(map[string]any)
		if !ok {
			continue
		}
		c := apiCall{Name: asStr(it["name"])}
		c.Method = strings.ToUpper(asStr(req["method"]))
		c.URL = urlOf(req["url"])
		*out = append(*out, c)
	}
}

func urlOf(v any) string {
	switch u := v.(type) {
	case string:
		return u
	case map[string]any:
		if raw := asStr(u["raw"]); raw != "" {
			return raw
		}
		host := joinAny(u["host"], ".")
		path := joinAny(u["path"], "/")
		proto := asStr(u["protocol"])
		if proto == "" {
			proto = "https"
		}
		if host != "" {
			return proto + "://" + host + "/" + path
		}
	}
	return ""
}

func joinAny(v any, sep string) string {
	arr, ok := v.([]any)
	if !ok {
		return asStr(v)
	}
	parts := make([]string, 0, len(arr))
	for _, e := range arr {
		if s := asStr(e); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, sep)
}

func asStr(v any) string { s, _ := v.(string); return s }

// --- secret + PII scan ---

type hit struct {
	Class    string // secret | pii | auth
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
	{"aws-secret-key", "critical", regexp.MustCompile(`(?i)aws(?:.{0,20})?['"]([A-Za-z0-9/+=]{40})['"]`), 1, 4.0},
	{"gcp-api-key", "high", regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`), 1, 0},
	{"gcp-oauth-token", "high", regexp.MustCompile(`\b(ya29\.[0-9A-Za-z_\-]{20,})`), 1, 0},
	{"github-token", "critical", regexp.MustCompile(`\b(ghp_[0-9A-Za-z]{36}|github_pat_[0-9A-Za-z_]{82})\b`), 1, 0},
	{"gitlab-token", "high", regexp.MustCompile(`\b(glpat-[0-9A-Za-z_\-]{20})\b`), 1, 0},
	{"slack-token", "high", regexp.MustCompile(`\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b`), 1, 0},
	{"stripe-live-key", "critical", regexp.MustCompile(`\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b`), 1, 0},
	{"stripe-test-key", "low", regexp.MustCompile(`\b((?:sk|rk)_test_[0-9A-Za-z]{24,})\b`), 1, 0},
	{"twilio-key", "high", regexp.MustCompile(`\b(SK[0-9a-fA-F]{32})\b`), 1, 0},
	{"sendgrid-key", "high", regexp.MustCompile(`\b(SG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43})\b`), 1, 0},
	{"openai-key", "high", regexp.MustCompile(`\b(sk-(?:proj-)?[0-9A-Za-z_\-]{40,})`), 1, 3.2},
	{"anthropic-key", "critical", regexp.MustCompile(`\b(sk-ant-api03-[0-9A-Za-z_\-]{80,})`), 1, 0},
	{"private-key", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----`), 0, 0},
	{"jwt", "medium", regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`), 1, 0},
	{"db-conn-string", "high", regexp.MustCompile(`\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/"]+:[^\s:@/"]{4,}@[^\s/"]+)`), 1, 0},
	{"basic-auth-url", "high", regexp.MustCompile(`\bhttps?://[A-Za-z0-9._%+\-]+:([^@\s/"']{6,})@`), 1, 0},
	{"generic-api-key", "medium", regexp.MustCompile(`(?i)["'](?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|x-api-key|secret)["']\s*:\s*["']([^"']{16,80})["']`), 1, 3.4},
}

var (
	reEmail = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)
	rePhone = regexp.MustCompile(`(?:\+?\d{1,3}[ .\-]?)?\(?\d{2,4}\)?[ .\-]?\d{3,4}[ .\-]?\d{4}\b`)
	reCPF   = regexp.MustCompile(`\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`)
	reSSN   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	reCC    = regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)
	reIBAN  = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b`)
)

// scanText runs the secret + PII patterns over one string.
func scanText(text string) []hit {
	seen := map[string]bool{}
	var out []hit
	add := func(class, kind, sev, val string) {
		key := kind + "\x00" + val
		if val == "" || seen[key] {
			return
		}
		seen[key] = true
		out = append(out, hit{class, kind, sev, redact(val)})
	}

	for _, p := range secretRes {
		for _, m := range p.re.FindAllStringSubmatch(text, -1) {
			v := m[0]
			if p.group > 0 && p.group < len(m) {
				v = m[p.group]
			}
			if p.entropy > 0 && shannon(v) < p.entropy {
				continue
			}
			if looksPlaceholder(v) {
				continue
			}
			add("secret", p.kind, p.sev, v)
		}
	}

	for _, m := range reEmail.FindAllString(text, -1) {
		if !strings.HasSuffix(m, "example.com") && !strings.HasSuffix(m, "test.com") {
			add("pii", "email", "low", m)
		}
	}
	for _, m := range reCPF.FindAllString(text, -1) {
		add("pii", "cpf", "medium", m)
	}
	for _, m := range reSSN.FindAllString(text, -1) {
		add("pii", "ssn", "medium", m)
	}
	for _, m := range reIBAN.FindAllString(text, -1) {
		add("pii", "iban", "medium", m)
	}
	for _, m := range reCC.FindAllString(text, -1) {
		digits := onlyDigits(m)
		if len(digits) >= 13 && len(digits) <= 19 && luhn(digits) {
			add("pii", "credit-card", "high", digits)
		}
	}
	for _, m := range rePhone.FindAllString(text, -1) {
		d := onlyDigits(m)
		if len(d) >= 10 && len(d) <= 13 {
			add("pii", "phone", "low", m)
		}
	}
	return out
}

// scanAuth pulls literal credentials out of a Postman request `auth` block.
func scanAuth(auth map[string]any) []hit {
	var out []hit
	typ := asStr(auth["type"])
	block, _ := auth[typ].([]any)
	for _, raw := range block {
		kv, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		val := asStr(kv["value"])
		if val == "" || strings.Contains(val, "{{") { // {{variable}} = not hardcoded
			continue
		}
		if looksPlaceholder(val) || len(val) < 6 {
			continue
		}
		sev := "medium"
		if typ == "bearer" || typ == "apikey" || typ == "oauth2" {
			sev = "high"
		}
		out = append(out, hit{"auth", "hardcoded-" + typ, sev, redact(val)})
	}
	return out
}

// --- internal hosts ---

var hostRe = regexp.MustCompile(`https?://([a-zA-Z0-9.\-]+)`)

var internalHints = []string{
	"internal", "intranet", "corp", "staging", "stg", "qa", "uat", "dev",
	"sandbox", "preprod", "pre-prod", "vpn", "jenkins", "gitlab", "jira",
	"grafana", "kibana", "vault", "nexus", "artifactory", "10.", "192.168.",
	"172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30", "172.31",
	"localhost", ".lan", ".corp", ".internal", ".local",
}

func internalHosts(text, matchDomain string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range hostRe.FindAllStringSubmatch(text, -1) {
		h := strings.ToLower(m[1])
		if h == "" || seen[h] {
			continue
		}
		hit := (matchDomain != "" && (h == matchDomain || strings.HasSuffix(h, "."+matchDomain)))
		for _, hint := range internalHints {
			if strings.Contains(h, hint) {
				hit = true
				break
			}
		}
		if !hit || strings.HasSuffix(h, ".postman.com") || h == "schema.getpostman.com" {
			continue
		}
		seen[h] = true
		out = append(out, h)
	}
	return out
}

// --- helpers ---

var placeholders = []string{
	"your_", "your-", "example", "xxxx", "0000", "changeme", "placeholder",
	"<token>", "<your", "insert", "dummy", "sample", "replace", "token_here",
	"access_token", "secret_here", "abc123", "test123", "1234567",
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

func onlyDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func luhn(num string) bool {
	sum, alt := 0, false
	for i := len(num) - 1; i >= 0; i-- {
		d := int(num[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
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
	if len(s) <= 12 {
		if len(s) <= 4 {
			return "***"
		}
		return s[:2] + "…" + s[len(s)-2:]
	}
	return s[:4] + "…" + s[len(s)-4:]
}
