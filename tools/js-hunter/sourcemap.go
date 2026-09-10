package main

import (
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var (
	mapURLRe = regexp.MustCompile(`(?m)//[#@]\s*sourceMappingURL=([^\s'"]+)`)
)

// mapCandidates returns source-map URLs for a JS file: the declared
// sourceMappingURL plus the "<js>.map" guess.
func mapCandidates(jsURL, jsBody string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u != "" && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	for _, m := range mapURLRe.FindAllStringSubmatch(jsBody, -1) {
		ref := strings.TrimSpace(m[1])
		if strings.HasPrefix(ref, "data:") {
			continue
		}
		add(resolve(jsURL, ref))
	}
	add(jsURL + ".map")
	return out
}

// srcFile is one recovered original source.
type srcFile struct {
	Path    string
	Content string
}

// parseSourceMap pulls sources + sourcesContent from a v3 source map.
func parseSourceMap(body string) ([]srcFile, error) {
	var sm struct {
		Sources        []string `json:"sources"`
		SourcesContent []string `json:"sourcesContent"`
		SourceRoot     string   `json:"sourceRoot"`
	}
	if err := json.Unmarshal([]byte(body), &sm); err != nil {
		return nil, err
	}
	var out []srcFile
	for i, s := range sm.Sources {
		p := strings.TrimPrefix(s, sm.SourceRoot)
		p = strings.TrimPrefix(p, "webpack://")
		if i < len(sm.SourcesContent) && sm.SourcesContent[i] != "" {
			out = append(out, srcFile{Path: p, Content: sm.SourcesContent[i]})
		} else {
			out = append(out, srcFile{Path: p})
		}
	}
	return out, nil
}

// --- endpoint extraction ---

type endpoint struct {
	Method string // GET/POST/... or "" when unknown
	Ref    string // path or absolute URL
}

var (
	reFetch  = regexp.MustCompile(`(?i)\bfetch\(\s*["'` + "`" + `]([^"'` + "`" + `]{2,300}?)["'` + "`" + `]`)
	reAxios  = regexp.MustCompile(`(?i)\b(?:axios|http|client|api|\$http)\s*\.\s*(get|post|put|patch|delete|head|options|request)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]{1,300}?)["'` + "`" + `]`)
	reOpen   = regexp.MustCompile(`(?i)\.open\(\s*["'](GET|POST|PUT|PATCH|DELETE|HEAD)["']\s*,\s*["'` + "`" + `]([^"'` + "`" + `]{1,300}?)["'` + "`" + `]`)
	reURLKey = regexp.MustCompile(`(?i)["'](?:url|uri|endpoint|path|route|href|baseURL|base_url|apiUrl|api_url)["']\s*:\s*["'` + "`" + `]([^"'` + "`" + `]{2,300}?)["'` + "`" + `]`)
	rePath   = regexp.MustCompile(`["'` + "`" + `](/(?:api|v\d|rest|graphql|internal|admin|auth|oauth|user|users|account|gateway|service|svc|rpc|_next/data)[A-Za-z0-9_./:{}$\-]{0,200})["'` + "`" + `]`)
	reAbsURL = regexp.MustCompile(`\bhttps?://[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9_%./:{}$\-]{0,200}`)
)

// extractEndpoints pulls API references out of source text.
func extractEndpoints(text string) []endpoint {
	seen := map[string]bool{}
	var out []endpoint
	push := func(method, ref string) {
		ref = strings.TrimSpace(ref)
		if !plausibleRef(ref) {
			return
		}
		key := method + " " + ref
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, endpoint{method, ref})
	}
	for _, m := range reFetch.FindAllStringSubmatch(text, -1) {
		push("", m[1])
	}
	for _, m := range reAxios.FindAllStringSubmatch(text, -1) {
		push(strings.ToUpper(m[1]), m[2])
	}
	for _, m := range reOpen.FindAllStringSubmatch(text, -1) {
		push(strings.ToUpper(m[1]), m[2])
	}
	for _, m := range reURLKey.FindAllStringSubmatch(text, -1) {
		push("", m[1])
	}
	for _, m := range rePath.FindAllStringSubmatch(text, -1) {
		push("", m[1])
	}
	for _, m := range reAbsURL.FindAllString(text, -1) {
		if !cdnHost(m) {
			push("", m)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Ref != out[j].Ref {
			return out[i].Ref < out[j].Ref
		}
		return out[i].Method < out[j].Method
	})
	return out
}

func plausibleRef(ref string) bool {
	if len(ref) < 2 || len(ref) > 300 {
		return false
	}
	if strings.HasPrefix(ref, "//") {
		return false
	}
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return !cdnHost(ref)
	}
	if !strings.HasPrefix(ref, "/") {
		return false
	}
	// drop static asset paths
	for _, ext := range []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".ico", ".map", ".webp", ".mp4"} {
		if strings.HasSuffix(strings.ToLower(ref), ext) {
			return false
		}
	}
	return true
}

func cdnHost(u string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	h := strings.ToLower(p.Hostname())
	for _, s := range []string{
		"googleapis.com", "gstatic.com", "google-analytics.com", "googletagmanager.com",
		"cloudflare.com", "cloudflareinsights.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com",
		"fontawesome.com", "fonts.googleapis.com", "w3.org", "schema.org", "youtube.com",
		"facebook.com", "facebook.net", "doubleclick.net", "sentry.io", "segment.com", "segment.io",
		"jquery.com", "bootstrapcdn.com", "polyfill.io", "gravatar.com",
	} {
		if h == s || strings.HasSuffix(h, "."+s) {
			return true
		}
	}
	return false
}

// interestingEndpoint flags a ref worth a closer look.
func interestingEndpoint(ref string) (bool, string) {
	l := strings.ToLower(ref)
	pairs := []struct{ needle, why string }{
		{"/admin", "painel/rota administrativa"},
		{"/internal", "rota interna"},
		{"/debug", "endpoint de debug"},
		{"/actuator", "Spring Boot Actuator"},
		{"/graphql", "endpoint GraphQL"},
		{"/.env", "arquivo de ambiente"},
		{"/swagger", "spec de API"},
		{"/openapi", "spec de API"},
		{"/api-docs", "spec de API"},
		{"/metrics", "métricas expostas"},
		{"/.git", "repositório git"},
		{"/backup", "backup"},
		{"/token", "endpoint de token"},
		{"/oauth", "fluxo OAuth"},
		{"/upload", "upload de arquivo"},
		{"/export", "exportação de dados"},
		{"/user/", "recurso de usuário"},
		{"/users/", "recurso de usuários"},
	}
	for _, p := range pairs {
		if strings.Contains(l, p.needle) {
			return true, p.why
		}
	}
	return false, ""
}

func resolve(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return b.ResolveReference(r).String()
}
