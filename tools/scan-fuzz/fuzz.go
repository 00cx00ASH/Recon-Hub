package main

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
)

// baseline is the target's "not found" fingerprint, learned by requesting random
// paths that certainly do not exist.
type baseline struct {
	status  int
	size    int
	present bool
}

// calibrate probes a few random paths (one per extension + one bare) and, if
// they all answer the same way, records that as the soft-404 fingerprint.
func calibrate(c *http.Client, base string, exts []string) baseline {
	probes := []string{randToken()}
	for _, e := range exts {
		probes = append(probes, randToken()+e)
	}
	var last baseline
	for i, p := range probes {
		st, sz, ok := probe(c, base+"/"+p)
		if !ok {
			return baseline{}
		}
		b := baseline{status: st, size: sz, present: true}
		if i > 0 && (b.status != last.status || abs(b.size-last.size) > 128) {
			return baseline{} // target is inconsistent; don't filter on it
		}
		last = b
	}
	return last
}

// isSoftNotFound reports whether a response looks like the calibrated 404.
func (b baseline) isSoftNotFound(status, size int) bool {
	if !b.present {
		return false
	}
	return status == b.status && abs(size-b.size) <= 128
}

// classify turns a hit into a finding_type + severity.
func classify(status int) (ftype, sev string) {
	switch {
	case status == 401 || status == 403:
		return "content-restricted", "medium"
	case status >= 200 && status < 300:
		return "content", "low"
	case status >= 300 && status < 400:
		return "content-redirect", "info"
	default:
		return "content", "info"
	}
}

func probe(c *http.Client, url string) (status, size int, ok bool) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return 0, 0, false
	}
	req.Header.Set("User-Agent", "recon-hub/scan-fuzz")
	resp, err := c.Do(req)
	if err != nil {
		return 0, 0, false
	}
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	return resp.StatusCode, int(n), true
}

// words: parse a wordlist já lida em memória.
func wordsFrom(data string) []string {
	seen := map[string]bool{}
	var out []string
	for _, ln := range strings.Split(data, "\n") {
		w := strings.TrimSpace(ln)
		if w == "" || strings.HasPrefix(w, "#") || seen[w] {
			continue
		}
		w = strings.TrimPrefix(w, "/")
		seen[w] = true
		out = append(out, w)
	}
	return out
}

func randToken() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}
