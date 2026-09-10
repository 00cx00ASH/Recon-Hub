package main

import (
	"regexp"
	"strings"
)

// cleanRoot normalizes a user-supplied target into a bare root domain.
func cleanRoot(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "*.")
	if i := strings.IndexAny(s, "/:?#"); i >= 0 {
		s = s[:i]
	}
	return strings.Trim(s, ".")
}

var hostCharRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$`)

// normalizeHost validates raw as a hostname in scope of root. "" if it isn't.
func normalizeHost(raw, root string) string {
	h := strings.TrimSpace(strings.ToLower(raw))
	h = strings.TrimPrefix(h, "*.")
	h = strings.Trim(h, ".")
	if h == "" || strings.ContainsAny(h, "@ \t/:") {
		return ""
	}
	// strip a leading wildcard label leftover like "%2a."
	h = strings.TrimPrefix(h, "%2a.")
	if h != root && !strings.HasSuffix(h, "."+root) {
		return ""
	}
	if len(h) > 253 || !hostCharRe.MatchString(h) {
		return ""
	}
	return h
}

// hostsFromText scrapes anything that looks like a hostname of root out of free
// text (CSV, HTML, URL lists).
func hostsFromText(text, root string) []string {
	re := regexp.MustCompile(`(?i)([a-z0-9_](?:[a-z0-9_-]|\.)*\.` + regexp.QuoteMeta(root) + `)\b`)
	seen := map[string]bool{}
	var out []string
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		if h := normalizeHost(m[1], root); h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out
}
