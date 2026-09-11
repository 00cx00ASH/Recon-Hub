package main

import (
	"io"
	"net/http"
	"strings"
)

// bypassTechnique is one classic 403-bypass trick: a request variant that
// sometimes reaches an app/proxy layer that trusts a header or path shape
// the front door's access-control check didn't account for.
//
// headerBased matters for how we judge success: a header-injection trick
// (X-Original-URL, X-Rewrite-URL) is sent to "/" — and "/" itself almost
// always answers 200 with real content, so comparing its response to the
// generic soft-404 baseline would flag every single site as "bypassed"
// (this was caught by a live test against a fake target before this code
// ever shipped). Those techniques must instead be compared against the
// site's own plain "/" response with no special header — only a response
// that's *meaningfully different from that control* proves the header had
// any effect at all. Path-shape tricks (double slash, trailing slash) hit a
// genuinely different URL, so the existing soft-404 baseline is the right
// control for those.
type bypassTechnique struct {
	name        string
	url         string
	headers     map[string]string
	headerBased bool
}

// bypassTechniques builds the short, fixed list of variants to try against a
// path already confirmed blocked (401/403). Deliberately small (5 requests)
// and read-only GETs — this is not a fuzzer, it only fires once per already-
// discovered blocked admin/debug path, so the added volume stays tiny even
// with delay_ms pacing applied to each request (see tryBypass).
func bypassTechniques(root, path string) []bypassTechnique {
	trimmed := strings.TrimPrefix(path, "/")
	altSlash := strings.TrimSuffix(path, "/")
	if !strings.HasSuffix(path, "/") {
		altSlash = path + "/"
	}
	return []bypassTechnique{
		{name: "barra dupla", url: root + "//" + trimmed},
		{name: "barra final alternada", url: root + altSlash},
		{name: "X-Original-URL", url: root + "/", headers: map[string]string{"X-Original-URL": path}, headerBased: true},
		{name: "X-Rewrite-URL", url: root + "/", headers: map[string]string{"X-Rewrite-URL": path}, headerBased: true},
		{name: "X-Forwarded-For localhost", url: root + path, headers: map[string]string{"X-Forwarded-For": "127.0.0.1"}, headerBased: true},
	}
}

// sameShape reports whether two responses look like "the same page" — used
// to tell "the header changed nothing" from "the header actually mattered".
// Exact byte-for-byte equality is too strict (timestamps, CSRF tokens...),
// so this allows a small size delta, same as baseline.isSoft.
func sameShape(status1, size1, status2, size2 int) bool {
	if status1 != status2 {
		return false
	}
	d := size1 - size2
	if d < 0 {
		d = -d
	}
	return d < 200
}

// tryBypass fires the fixed technique list at a path already known to be
// blocked. It reports a hit ONLY when the response is a real 2xx with actual
// content that's demonstrably different from the right control for that
// technique (the site's soft-404 for a path trick, or the plain "/" response
// for a header trick) — never on a mere status change, since some WAFs
// answer everything 200 with an error page. Evidence always tells the
// operator to confirm manually before reporting: this proves "something
// answered differently", not "this is exploitable".
func tryBypass(root, path string, base baseline) (ok bool, technique, note string) {
	var plainStatus, plainSize int
	var plainFetched bool

	for _, t := range bypassTechniques(root, path) {
		body, _, status, err := fetchWithHeaders(t.url, t.headers)
		if err != nil {
			continue
		}
		if status < 200 || status >= 300 {
			continue
		}
		if len(strings.TrimSpace(body)) < 20 {
			continue // resposta 2xx vazia/quase vazia não prova nada
		}

		if t.headerBased {
			if !plainFetched {
				pBody, _, pStatus, pErr := fetchWithHeaders(root+"/", nil)
				if pErr == nil {
					plainStatus, plainSize = pStatus, len(pBody)
				}
				plainFetched = true
			}
			if sameShape(status, len(body), plainStatus, plainSize) {
				continue // o header não mudou nada — "/" respondeu igual de qualquer jeito
			}
		} else if base.isSoft(status, len(body)) {
			continue
		}

		return true, t.name, "técnica \"" + t.name + "\" respondeu HTTP " + itoa(status) + " (" + itoa(len(body)) +
			" bytes), diferente do controle (" + controlLabel(t.headerBased) + ") — confirme manualmente antes de reportar como bypass"
	}
	return false, "", ""
}

func controlLabel(headerBased bool) string {
	if headerBased {
		return "resposta normal de \"/\" sem o header"
	}
	return "soft-404 do site"
}

func fetchWithHeaders(u string, extra map[string]string) (string, http.Header, int, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", nil, 0, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 recon-hub/recon-web-enum")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json,*/*")
	for k, v := range extra {
		req.Header.Set(k, v)
	}
	applyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return string(b), resp.Header, resp.StatusCode, nil
}
