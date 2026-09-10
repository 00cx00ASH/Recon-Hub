package main

import (
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// --- link / form extraction ---

var (
	hrefRe    = regexp.MustCompile(`(?i)<a\b[^>]*?\bhref\s*=\s*["']([^"'#]+)["']`)
	srcRe     = regexp.MustCompile(`(?i)<(?:script|iframe)\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']`)
	formRe    = regexp.MustCompile(`(?is)<form\b[^>]*>.*?</form>`)
	actionRe  = regexp.MustCompile(`(?i)\baction\s*=\s*["']([^"']*)["']`)
	methodRe  = regexp.MustCompile(`(?i)\bmethod\s*=\s*["']([^"']*)["']`)
	inputRe   = regexp.MustCompile(`(?i)<input\b[^>]*?\bname\s*=\s*["']([^"']+)["']`)
	pwFieldRe = regexp.MustCompile(`(?i)<input\b[^>]*?\btype\s*=\s*["']password["']`)
)

// sameSite reports whether u shares base's registrable-ish host (last 2 labels).
func sameSite(u, baseHost string) bool {
	p, err := url.Parse(u)
	if err != nil {
		return false
	}
	h := strings.ToLower(p.Hostname())
	return h == baseHost || reg2(h) == reg2(baseHost)
}

func reg2(h string) string {
	l := strings.Split(strings.Trim(h, "."), ".")
	if len(l) <= 2 {
		return h
	}
	return strings.Join(l[len(l)-2:], ".")
}

// pageLinks returns same-site page URLs linked from html.
func pageLinks(html, pageURL, baseHost string) []string {
	b, _ := url.Parse(pageURL)
	seen := map[string]bool{}
	var out []string
	for _, re := range []*regexp.Regexp{hrefRe, srcRe} {
		for _, m := range re.FindAllStringSubmatch(html, -1) {
			raw := strings.TrimSpace(m[1])
			if raw == "" || strings.HasPrefix(raw, "mailto:") || strings.HasPrefix(raw, "tel:") ||
				strings.HasPrefix(raw, "javascript:") || strings.HasPrefix(raw, "data:") {
				continue
			}
			r, err := url.Parse(raw)
			if err != nil {
				continue
			}
			abs := b.ResolveReference(r)
			abs.Fragment = ""
			if abs.Scheme != "http" && abs.Scheme != "https" {
				continue
			}
			if !sameSite(abs.String(), baseHost) {
				continue
			}
			s := abs.String()
			if seen[s] {
				continue
			}
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

type webForm struct {
	Action   string
	Method   string
	Inputs   []string
	Password bool
}

func extractForms(html, pageURL string) []webForm {
	b, _ := url.Parse(pageURL)
	var out []webForm
	for _, block := range formRe.FindAllString(html, -1) {
		f := webForm{Method: "GET"}
		if m := actionRe.FindStringSubmatch(block); m != nil {
			if r, err := url.Parse(strings.TrimSpace(m[1])); err == nil {
				f.Action = b.ResolveReference(r).String()
			}
		}
		if f.Action == "" {
			f.Action = pageURL
		}
		if m := methodRe.FindStringSubmatch(block); m != nil && strings.TrimSpace(m[1]) != "" {
			f.Method = strings.ToUpper(strings.TrimSpace(m[1]))
		}
		for _, im := range inputRe.FindAllStringSubmatch(block, -1) {
			f.Inputs = append(f.Inputs, im[1])
		}
		f.Password = pwFieldRe.MatchString(block)
		out = append(out, f)
	}
	return out
}

// queryParams pulls distinct query param names from a URL.
func queryParams(u string) []string {
	p, err := url.Parse(u)
	if err != nil {
		return nil
	}
	var out []string
	for k := range p.Query() {
		out = append(out, k)
	}
	return out
}

// --- tech fingerprint ---

// fingerprint inspects headers + body for tech/framework/CDN signals.
func fingerprint(h http.Header, body string) []string {
	set := map[string]bool{}
	add := func(s string) {
		if s != "" {
			set[s] = true
		}
	}
	hv := func(k string) string { return strings.TrimSpace(h.Get(k)) }

	if s := hv("Server"); s != "" {
		add("Server: " + s)
	}
	if s := hv("X-Powered-By"); s != "" {
		add("X-Powered-By: " + s)
	}
	if s := hv("X-AspNet-Version"); s != "" {
		add("ASP.NET " + s)
	}
	if s := hv("X-Generator"); s != "" {
		add("Generator: " + s)
	}
	if s := hv("X-Drupal-Cache"); s != "" {
		add("Drupal")
	}

	// cookies
	for _, c := range h.Values("Set-Cookie") {
		lc := strings.ToLower(c)
		switch {
		case strings.HasPrefix(lc, "phpsessid"):
			add("PHP (PHPSESSID)")
		case strings.HasPrefix(lc, "jsessionid"):
			add("Java (JSESSIONID)")
		case strings.HasPrefix(lc, "asp.net_sessionid"), strings.HasPrefix(lc, "aspxauth"):
			add("ASP.NET")
		case strings.HasPrefix(lc, "csrftoken"), strings.HasPrefix(lc, "sessionid") && strings.Contains(lc, "django"):
			add("Django")
		case strings.HasPrefix(lc, "laravel_session"), strings.HasPrefix(lc, "xsrf-token"):
			add("Laravel")
		case strings.HasPrefix(lc, "connect.sid"):
			add("Express / Node")
		case strings.HasPrefix(lc, "_shopify"), strings.Contains(lc, "shopify"):
			add("Shopify")
		}
	}

	// cdn / waf
	if h.Get("CF-RAY") != "" || strings.Contains(strings.ToLower(hv("Server")), "cloudflare") {
		add("Cloudflare")
	}
	if h.Get("X-Amz-Cf-Id") != "" {
		add("AWS CloudFront")
	}
	if h.Get("X-Fastly-Request-ID") != "" || strings.Contains(strings.ToLower(hv("Via")), "fastly") {
		add("Fastly")
	}
	if h.Get("X-Akamai-Transformed") != "" || strings.Contains(strings.ToLower(hv("Server")), "akamai") {
		add("Akamai")
	}
	if h.Get("X-Sucuri-ID") != "" {
		add("Sucuri WAF")
	}
	if h.Get("X-Vercel-Id") != "" {
		add("Vercel")
	}
	if h.Get("X-Nf-Request-Id") != "" {
		add("Netlify")
	}

	// body markers
	bl := strings.ToLower(body)
	markers := []struct{ needle, tech string }{
		{"wp-content", "WordPress"},
		{"wp-includes", "WordPress"},
		{`name="generator" content="wordpress`, "WordPress"},
		{"/sites/default/files", "Drupal"},
		{"drupal.settings", "Drupal"},
		{"joomla", "Joomla"},
		{"__next_data__", "Next.js"},
		{"/_next/static/", "Next.js"},
		{"/_nuxt/", "Nuxt.js"},
		{"ng-version", "Angular"},
		{"data-reactroot", "React"},
		{"__nuxt__", "Nuxt.js"},
		{"csrf-param", "Ruby on Rails"},
		{"x-shopify", "Shopify"},
		{"cdn.shopify.com", "Shopify"},
		{"gtm.js", "Google Tag Manager"},
		{"static.parastorage.com", "Wix"},
		{"squarespace", "Squarespace"},
		{"hs-scripts.com", "HubSpot"},
		{"__typename", "GraphQL client"},
	}
	for _, m := range markers {
		if strings.Contains(bl, m.needle) {
			add(m.tech)
		}
	}
	if m := regexp.MustCompile(`(?i)<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']`).FindStringSubmatch(body); m != nil {
		add("Generator: " + m[1])
	}

	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// --- probe path list ---

// probePaths — admin panels, debug, config, VCS, api docs.
var probePaths = []struct {
	path string
	kind string // admin | sensitive-file | api-doc | debug
	sev  string
}{
	{"/admin", "admin", "medium"},
	{"/admin/", "admin", "medium"},
	{"/administrator/", "admin", "medium"},
	{"/wp-admin/", "admin", "medium"},
	{"/wp-login.php", "admin", "low"},
	{"/user/login", "admin", "low"},
	{"/login", "admin", "low"},
	{"/cpanel", "admin", "medium"},
	{"/manager/html", "admin", "high"},
	{"/phpmyadmin/", "admin", "high"},
	{"/adminer.php", "admin", "high"},
	{"/.env", "sensitive-file", "high"},
	{"/.env.local", "sensitive-file", "high"},
	{"/.env.production", "sensitive-file", "high"},
	{"/config.json", "sensitive-file", "medium"},
	{"/config.php.bak", "sensitive-file", "high"},
	{"/.git/config", "sensitive-file", "high"},
	{"/.git/HEAD", "sensitive-file", "high"},
	{"/.svn/entries", "sensitive-file", "high"},
	{"/.DS_Store", "sensitive-file", "low"},
	{"/backup.zip", "sensitive-file", "medium"},
	{"/backup.sql", "sensitive-file", "high"},
	{"/dump.sql", "sensitive-file", "high"},
	{"/.htpasswd", "sensitive-file", "high"},
	{"/server-status", "debug", "medium"},
	{"/server-info", "debug", "medium"},
	{"/phpinfo.php", "debug", "high"},
	{"/info.php", "debug", "high"},
	{"/debug", "debug", "medium"},
	{"/_debugbar/open", "debug", "high"},
	{"/actuator", "debug", "high"},
	{"/actuator/health", "debug", "low"},
	{"/metrics", "debug", "medium"},
	{"/api", "api-doc", "low"},
	{"/api/", "api-doc", "low"},
	{"/api-docs", "api-doc", "low"},
	{"/swagger.json", "api-doc", "low"},
	{"/swagger-ui.html", "api-doc", "low"},
	{"/openapi.json", "api-doc", "low"},
	{"/v2/api-docs", "api-doc", "low"},
	{"/graphql", "api-doc", "medium"},
	{"/graphiql", "api-doc", "medium"},
	{"/robots.txt", "info", "info"},
	{"/sitemap.xml", "info", "info"},
	{"/.well-known/security.txt", "info", "info"},
	{"/crossdomain.xml", "info", "low"},
}

// baseline is a soft-404 fingerprint.
type baseline struct {
	status int
	size   int
}

func (b baseline) isSoft(status, size int) bool {
	if b.status == status {
		if b.status != 200 {
			return true
		}
		d := size - b.size
		if d < 0 {
			d = -d
		}
		return d < 200
	}
	return false
}

// probeVerdict classifies a probed path response.
func probeVerdict(kind string, status, size int, ctype, body string, base baseline) (bool, string) {
	if status == 401 || status == 403 {
		if kind == "admin" || kind == "debug" {
			return true, "existe mas exige auth (HTTP " + itoa(status) + ")"
		}
		return false, ""
	}
	if status < 200 || status >= 400 || status == 429 {
		return false, ""
	}
	if base.isSoft(status, size) {
		return false, ""
	}
	bl := strings.ToLower(body)
	switch kind {
	case "sensitive-file":
		// require it to actually look like the file, not an HTML error page
		if strings.Contains(strings.ToLower(ctype), "html") && !strings.Contains(bl, "ref:") && !strings.Contains(bl, "[core]") {
			if strings.Contains(bl, "<html") && status == 200 {
				return false, "" // provavelmente SPA / página custom
			}
		}
		return true, "HTTP " + itoa(status) + " — " + itoa(size) + " bytes servidos"
	case "debug":
		return true, "HTTP " + itoa(status) + " (" + ctype + ")"
	default:
		return true, "HTTP " + itoa(status)
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
