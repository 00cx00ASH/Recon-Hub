package main

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// --- tracking id extraction ---

var idRes = map[string]*regexp.Regexp{
	"GTM": regexp.MustCompile(`\bGTM-[A-Z0-9]{4,10}\b`),
	"GA4": regexp.MustCompile(`\bG-[A-Z0-9]{6,12}\b`),
	"UA":  regexp.MustCompile(`\bUA-\d{4,10}-\d{1,4}\b`),
	"AW":  regexp.MustCompile(`\bAW-\d{9,12}\b`),
	"GT":  regexp.MustCompile(`\bGT-[A-Z0-9]{5,12}\b`),
	"DC":  regexp.MustCompile(`\bDC-\d{6,12}\b`),
}

// extractTrackingIDs pulls every Google tag id from source text, grouped by type.
func extractTrackingIDs(text string) map[string][]string {
	out := map[string][]string{}
	for typ, re := range idRes {
		seen := map[string]bool{}
		for _, m := range re.FindAllString(text, -1) {
			if !seen[m] {
				seen[m] = true
				out[typ] = append(out[typ], m)
			}
		}
		sort.Strings(out[typ])
	}
	return out
}

// flatIDs returns "TYPE:id" strings for every id in the map.
func flatIDs(m map[string][]string) []string {
	var out []string
	for typ, ids := range m {
		for _, id := range ids {
			out = append(out, typ+":"+id)
		}
	}
	sort.Strings(out)
	return out
}

// --- container parsing ---

type container struct {
	Version    string
	Macros     []map[string]any
	Tags       []map[string]any
	Predicates []map[string]any
	Rules      []any
	parsed     bool
}

// parseContainer extracts the GTM "resource" object from a gtm.js body.
func parseContainer(gtmJS string) container {
	var c container
	raw := extractJSONObject(gtmJS, `"resource":`)
	if raw == "" {
		// newer builds: "resource": {...} may be split; try the whole "data" blob
		raw = extractJSONObject(gtmJS, `"resource" :`)
	}
	if raw == "" {
		return c
	}
	var res struct {
		Version    string            `json:"version"`
		Macros     []map[string]any  `json:"macros"`
		Tags       []map[string]any  `json:"tags"`
		Predicates []map[string]any  `json:"predicates"`
		Rules      []json.RawMessage `json:"rules"`
	}
	if json.Unmarshal([]byte(raw), &res) != nil {
		return c
	}
	c.Version = res.Version
	c.Macros = res.Macros
	c.Tags = res.Tags
	c.Predicates = res.Predicates
	for range res.Rules {
		c.Rules = append(c.Rules, nil)
	}
	c.parsed = true
	return c
}

// extractJSONObject finds `marker` in s and returns the balanced {...} that
// follows it (respecting strings/escapes). "" if not found or unbalanced.
func extractJSONObject(s, marker string) string {
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}
	j := i + len(marker)
	for j < len(s) && s[j] != '{' {
		if s[j] != ' ' && s[j] != '\t' && s[j] != '\n' && s[j] != '\r' {
			return ""
		}
		j++
	}
	if j >= len(s) {
		return ""
	}
	depth := 0
	inStr := false
	esc := false
	for k := j; k < len(s); k++ {
		ch := s[k]
		if inStr {
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			}
			continue
		}
		switch ch {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[j : k+1]
			}
		}
	}
	return ""
}

// tagInfo is a flattened view of one GTM tag.
type tagInfo struct {
	Function string // e.g. __html, __googtag, __fbq
	Name     string
	HTML     string // decoded vtp_html for custom-HTML tags
}

func (c container) tags() []tagInfo {
	var out []tagInfo
	for _, t := range c.Tags {
		ti := tagInfo{Function: asStr(t["function"]), Name: firstStr(t, "vtp_name", "tag_id", "name")}
		if h := asStr(t["vtp_html"]); h != "" {
			ti.HTML = h
		}
		out = append(out, ti)
	}
	return out
}

// tagTypeCounts summarizes tag function types.
func (c container) tagTypeCounts() map[string]int {
	m := map[string]int{}
	for _, t := range c.Tags {
		f := asStr(t["function"])
		if f == "" {
			f = "(sem função)"
		}
		m[f]++
	}
	return m
}

// thirdPartyTags maps known GTM tag "function" ids to a human label.
var thirdPartyTags = map[string]string{
	"__fbq":                 "Facebook Pixel",
	"__twitter_website_tag": "Twitter/X Pixel",
	"__bzi":                 "LinkedIn Insight",
	"__pntr":                "Pinterest Tag",
	"__hjtc":                "Hotjar",
	"__awct":                "Google Ads Conversion",
	"__sp":                  "Floodlight",
	"__gclidw":              "Google Ads Conversion Linker",
	"__qpx":                 "Quantcast",
	"__crto":                "Criteo OneTag",
	"__tdc":                 "TikTok Pixel",
	"__bb":                  "Bing/Microsoft UET",
	"__cegg":                "Crazy Egg",
	"__ta":                  "TripAdvisor",
	"__mf":                  "Mouseflow",
	"__nds":                 "Nielsen",
}

// interestingHTML flags a custom-HTML tag body worth a closer look.
func interestingHTML(html string) (bool, string) {
	l := strings.ToLower(html)
	switch {
	case strings.Contains(l, "document.write"):
		return true, "usa document.write"
	case strings.Contains(l, "eval("):
		return true, "usa eval()"
	case strings.Contains(l, "atob(") || strings.Contains(l, "fromcharcode"):
		return true, "decodifica string ofuscada (atob/fromCharCode)"
	case extScriptRe.MatchString(html):
		if m := extScriptRe.FindStringSubmatch(html); m != nil && !trustedScriptHost(m[1]) {
			return true, "injeta <script src> de " + m[1]
		}
	}
	return false, ""
}

var extScriptRe = regexp.MustCompile(`(?i)<script[^>]+src=["']https?://([^/"']+)`)

func trustedScriptHost(host string) bool {
	host = strings.ToLower(host)
	for _, s := range []string{
		"googletagmanager.com", "google-analytics.com", "googleadservices.com",
		"gstatic.com", "google.com", "doubleclick.net", "googlesyndication.com",
		"cdn.jsdelivr.net", "cdnjs.cloudflare.com", "code.jquery.com", "unpkg.com",
	} {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// --- lightweight secret scan over the container text ---

type secretHit struct {
	Kind     string
	Severity string
	Value    string
}

var containerSecretRes = []struct {
	kind, sev string
	re        *regexp.Regexp
	group     int
}{
	{"google-api-key", "medium", regexp.MustCompile(`\b(AIza[0-9A-Za-z_\-]{35})\b`), 1},
	{"aws-access-key-id", "high", regexp.MustCompile(`\b((?:AKIA|ASIA)[A-Z0-9]{16})\b`), 1},
	{"jwt", "medium", regexp.MustCompile(`\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b`), 1},
	{"slack-webhook", "high", regexp.MustCompile(`(https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]+)`), 1},
	{"bearer-token", "medium", regexp.MustCompile(`(?i)\b(?:authorization|bearer)["'\s:=]+([A-Za-z0-9_\-\.]{24,})\b`), 1},
	{"url-embedded-key", "low", regexp.MustCompile(`(?i)[?&](?:api_?key|access_?token|token|secret)=([A-Za-z0-9_\-\.]{12,})`), 1},
}

func scanContainerSecrets(text string) []secretHit {
	seen := map[string]bool{}
	var out []secretHit
	for _, p := range containerSecretRes {
		for _, m := range p.re.FindAllStringSubmatch(text, -1) {
			v := m[p.group]
			if looksPlaceholder(v) || seen[p.kind+"\x00"+v] {
				continue
			}
			seen[p.kind+"\x00"+v] = true
			out = append(out, secretHit{p.kind, p.sev, redact(v)})
		}
	}
	return out
}

func looksPlaceholder(v string) bool {
	l := strings.ToLower(v)
	for _, p := range []string{"example", "your_", "xxxx", "changeme", "placeholder", "dummy", "test123", "0000000000"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func redact(s string) string {
	if len(s) <= 10 {
		return "***"
	}
	return s[:4] + "…" + s[len(s)-4:]
}

// --- helpers ---

func asStr(v any) string {
	s, _ := v.(string)
	return s
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s := asStr(m[k]); s != "" {
			return s
		}
	}
	return ""
}

func snippet(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}
