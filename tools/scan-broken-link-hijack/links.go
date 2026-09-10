package main

import (
	"net"
	"net/url"
	"regexp"
	"strings"
)

// ref is an outbound reference found on a page.
type ref struct {
	URL   string
	Where string // a | script | img | iframe | link | form
}

var attrRes = []struct {
	where string
	re    *regexp.Regexp
}{
	{"a", regexp.MustCompile(`(?i)<a\b[^>]*?\bhref\s*=\s*["']([^"']+)["']`)},
	{"script", regexp.MustCompile(`(?i)<script\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']`)},
	{"img", regexp.MustCompile(`(?i)<img\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']`)},
	{"iframe", regexp.MustCompile(`(?i)<iframe\b[^>]*?\bsrc\s*=\s*["']([^"']+)["']`)},
	{"link", regexp.MustCompile(`(?i)<link\b[^>]*?\bhref\s*=\s*["']([^"']+)["']`)},
	{"form", regexp.MustCompile(`(?i)<form\b[^>]*?\baction\s*=\s*["']([^"']+)["']`)},
}

// extractRefs pulls outbound absolute URLs from HTML, resolved against base.
func extractRefs(html, base string) []ref {
	b, _ := url.Parse(base)
	seen := map[string]bool{}
	var out []ref
	for _, a := range attrRes {
		for _, m := range a.re.FindAllStringSubmatch(html, -1) {
			raw := strings.TrimSpace(m[1])
			if raw == "" || strings.HasPrefix(raw, "#") || strings.HasPrefix(raw, "mailto:") ||
				strings.HasPrefix(raw, "tel:") || strings.HasPrefix(raw, "javascript:") ||
				strings.HasPrefix(raw, "data:") {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				continue
			}
			if b != nil {
				u = b.ResolveReference(u)
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				continue
			}
			key := a.where + " " + u.String()
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, ref{URL: u.String(), Where: a.where})
		}
	}
	return out
}

// hijackKind names how a dead reference could be taken over.
type hijackKind struct {
	platform string
	// probe tells the prober how to decide "claimable".
	probe string // github-user | github-repo | npm | s3 | fingerprint | social
	sev   string
	// target is the concrete thing an attacker would register (handle/pkg/bucket).
	target string
	// marker is the body substring that means "unclaimed" (probe == fingerprint).
	marker string
}

// cnameFingerprints: host suffix -> body marker that means "unclaimed site".
var cnameFingerprints = map[string]string{
	".herokuapp.com":     "no such app",
	".netlify.app":       "not found",
	".vercel.app":        "deployment_not_found",
	".pages.dev":         "nothing is here",
	".surge.sh":          "project not found",
	".bitbucket.io":      "repository not found",
	".gitlab.io":         "the page you're looking for could not be found",
	".readthedocs.io":    "maze found",
	".wordpress.com":     "do you want to register",
	".myshopify.com":     "sorry, this shop is currently unavailable",
	".statuspage.io":     "you are being redirected",
	".uservoice.com":     "this uservoice subdomain is currently available",
	".pantheonsite.io":   "the gods are wise",
	".launchrock.com":    "it looks like you may have taken a wrong turn",
	".canny.io":          "company not found",
	".helpscoutdocs.com": "no settings were found for this company",
	".tilda.ws":          "please renew your subscription",
	".webflow.io":        "the page you are looking for doesn't exist",
	".frontify.com":      "404",
	".getresponse.com":   "with getresponse landing pages",
	".helpjuice.com":     "we could not find what you're looking for",
}

var socialHosts = map[string]bool{
	"twitter.com": true, "x.com": true, "instagram.com": true,
	"facebook.com": true, "www.facebook.com": true, "t.me": true,
	"medium.com": true, "www.instagram.com": true, "tiktok.com": true,
}

// classifyRef decides whether an outbound URL sits on a hijackable platform.
func classifyRef(rawURL string) (hijackKind, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return hijackKind{}, false
	}
	host := strings.ToLower(u.Hostname())
	path := strings.Trim(u.Path, "/")
	segs := strings.Split(path, "/")
	first := ""
	if len(segs) > 0 {
		first = segs[0]
	}

	mk := func(platform, probe, sev, target string) (hijackKind, bool) {
		return hijackKind{platform: platform, probe: probe, sev: sev, target: target}, true
	}

	switch {
	case host == "github.com" || host == "www.github.com":
		if first == "" || reservedGitHub[strings.ToLower(first)] {
			return hijackKind{}, false
		}
		if len(segs) >= 2 && segs[1] != "" {
			return mk("GitHub repo", "github-repo", "high", segs[0]+"/"+segs[1])
		}
		return mk("GitHub user/org", "github-user", "high", segs[0])

	case strings.HasSuffix(host, ".github.io"):
		return mk("GitHub Pages", "github-user", "high", strings.TrimSuffix(host, ".github.io"))

	case host == "gist.github.com":
		if first != "" {
			return mk("GitHub gist owner", "github-user", "medium", first)
		}

	case host == "www.npmjs.com" || host == "npmjs.com":
		if first == "package" && len(segs) >= 2 {
			return mk("npm package", "npm", "high", strings.Join(segs[1:], "/"))
		}
	case host == "unpkg.com" || host == "cdn.jsdelivr.net":
		if p := npmFromCDN(host, path); p != "" {
			return mk("npm package (CDN)", "npm", "high", p)
		}

	case strings.HasSuffix(host, ".s3.amazonaws.com"):
		return mk("S3 bucket", "s3", "high", strings.TrimSuffix(host, ".s3.amazonaws.com"))
	case host == "s3.amazonaws.com" && first != "":
		return mk("S3 bucket", "s3", "high", first)
	case regexp.MustCompile(`^s3[.-][a-z0-9-]+\.amazonaws\.com$`).MatchString(host) && first != "":
		return mk("S3 bucket", "s3", "high", first)

	case socialHosts[host]:
		h := strings.TrimPrefix(first, "@")
		if h == "" || reservedSocial[strings.ToLower(h)] {
			return hijackKind{}, false
		}
		return mk("social ("+host+")", "social", "medium", h)
	}

	for suf, marker := range cnameFingerprints {
		if strings.HasSuffix(host, suf) {
			return hijackKind{
				platform: "CNAME " + strings.TrimPrefix(suf, "."),
				probe:    "fingerprint", sev: "high", target: host, marker: marker,
			}, true
		}
	}
	return hijackKind{}, false
}

// genericExternal is the fallback candidate for an off-site link on no known
// platform — only reported if its host fails to resolve (dangling domain).
func genericExternal(rawURL string) (hijackKind, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return hijackKind{}, false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || net.ParseIP(host) != nil {
		return hijackKind{}, false
	}
	return hijackKind{platform: "domínio externo", probe: "dns-only", sev: "high", target: host}, true
}

// registrableGuess is a cheap eTLD+1 approximation (last 2 labels, or 3 for a
// short second-level TLD like co.uk / com.br). Good enough to skip same-site refs.
func registrableGuess(host string) string {
	host = strings.ToLower(strings.Trim(host, "."))
	labels := strings.Split(host, ".")
	if len(labels) <= 2 {
		return host
	}
	secondLevel := map[string]bool{
		"co": true, "com": true, "org": true, "net": true, "gov": true,
		"edu": true, "ac": true, "or": true, "ne": true,
	}
	if secondLevel[labels[len(labels)-2]] && len(labels) >= 3 {
		return strings.Join(labels[len(labels)-3:], ".")
	}
	return strings.Join(labels[len(labels)-2:], ".")
}

func npmFromCDN(host, path string) string {
	// unpkg.com/lodash@4/... or cdn.jsdelivr.net/npm/lodash@4/...
	p := path
	if host == "cdn.jsdelivr.net" {
		if !strings.HasPrefix(p, "npm/") {
			return ""
		}
		p = strings.TrimPrefix(p, "npm/")
	}
	segs := strings.Split(p, "/")
	if len(segs) == 0 || segs[0] == "" {
		return ""
	}
	stripVer := func(s string) string {
		if i := strings.IndexByte(s, '@'); i > 0 {
			return s[:i]
		}
		return s
	}
	if strings.HasPrefix(segs[0], "@") && len(segs) >= 2 {
		return segs[0] + "/" + stripVer(segs[1])
	}
	return stripVer(segs[0])
}

var reservedGitHub = map[string]bool{
	"about": true, "pricing": true, "features": true, "enterprise": true,
	"team": true, "customer-stories": true, "security": true, "login": true,
	"join": true, "explore": true, "marketplace": true, "sponsors": true,
	"topics": true, "collections": true, "trending": true, "events": true,
	"notifications": true, "settings": true, "orgs": true, "apps": true,
	"contact": true, "site": true, "readme": true, "search": true, "new": true,
}

var reservedSocial = map[string]bool{
	"home": true, "about": true, "help": true, "explore": true, "search": true,
	"login": true, "signup": true, "i": true, "settings": true, "share": true,
	"intent": true, "hashtag": true, "privacy": true, "tos": true,
}
