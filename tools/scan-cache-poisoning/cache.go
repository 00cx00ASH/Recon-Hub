package main

import (
	"net/http"
	"strconv"
	"strings"
)

// probe is one unkeyed-input test: an HTTP header (or query param) that a CDN
// often forwards to the origin without including in the cache key.
type probe struct {
	header string // header name; "" means it's a query param
	param  string // query param name (when header == "")
	// value builds the payload from the canary host.
	value func(canary string) string
	// where says what to inspect: "any" (body+headers), "location", "body".
	where string
}

// defaultProbes — curated, ordered by how commonly they land.
func defaultProbes() []probe {
	host := func(canary string) string { return canary }
	return []probe{
		{header: "X-Forwarded-Host", value: host, where: "any"},
		{header: "X-Forwarded-Scheme", value: func(string) string { return "http" }, where: "any"},
		{header: "X-Forwarded-Proto", value: func(string) string { return "http" }, where: "any"},
		{header: "X-Forwarded-Port", value: func(string) string { return "1337" }, where: "any"},
		{header: "X-Host", value: host, where: "any"},
		{header: "X-Forwarded-Server", value: host, where: "any"},
		{header: "X-HTTP-Host-Override", value: host, where: "any"},
		{header: "X-Original-Host", value: host, where: "any"},
		{header: "Forwarded", value: func(c string) string { return "host=" + c }, where: "any"},
		{header: "X-Original-URL", value: func(c string) string { return "/" + c }, where: "any"},
		{header: "X-Rewrite-URL", value: func(c string) string { return "/" + c }, where: "any"},
		{header: "X-Forwarded-Path", value: func(c string) string { return "/" + c }, where: "any"},
		{header: "X-Forwarded-For", value: func(string) string { return "127.0.0.1" }, where: "any"},
		{header: "True-Client-IP", value: func(string) string { return "127.0.0.1" }, where: "any"},
		{header: "X-Forwarded-Prefix", value: func(c string) string { return "/" + c }, where: "any"},
		{header: "Accept-Language", value: func(c string) string { return c }, where: "body"},
		{param: "utm_content", value: func(c string) string { return c }, where: "body"},
	}
}

func (p probe) label() string {
	if p.header != "" {
		return "header " + p.header
	}
	return "param " + p.param
}

// cacheView is what we learned about caching from a response.
type cacheView struct {
	backed bool   // response looks served/holdable by a shared cache
	reason string // which header told us
}

// readCache inspects response headers for cache signals.
func readCache(h http.Header) cacheView {
	get := func(k string) string { return strings.ToLower(strings.TrimSpace(h.Get(k))) }

	for _, k := range []string{"X-Cache", "CF-Cache-Status", "X-Cache-Status", "X-Drupal-Cache", "X-Proxy-Cache", "CDN-Cache"} {
		v := get(k)
		if v == "" {
			continue
		}
		if strings.Contains(v, "hit") {
			return cacheView{true, k + ": " + v}
		}
		if strings.Contains(v, "miss") || strings.Contains(v, "dynamic") || strings.Contains(v, "expired") {
			return cacheView{true, k + ": " + v + " (cache presente)"}
		}
	}
	if a := get("age"); a != "" {
		if n, err := strconv.Atoi(a); err == nil && n >= 0 {
			return cacheView{true, "Age: " + a}
		}
	}
	cc := get("cache-control") + " " + get("cdn-cache-control") + " " + get("surrogate-control")
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return cacheView{false, "Cache-Control: " + strings.TrimSpace(cc)}
	}
	if strings.Contains(cc, "s-maxage") || strings.Contains(cc, "public") ||
		strings.Contains(cc, "max-age") {
		return cacheView{true, "Cache-Control: " + strings.TrimSpace(cc)}
	}
	if v := get("x-served-by"); v != "" {
		return cacheView{true, "X-Served-By: " + v}
	}
	if v := get("via"); v != "" && (strings.Contains(v, "varnish") || strings.Contains(v, "cache") || strings.Contains(v, "cloudfront")) {
		return cacheView{true, "Via: " + v}
	}
	return cacheView{false, ""}
}

// reflections lists where canary shows up in a response.
func reflections(canary, body string, h http.Header) []string {
	var out []string
	if strings.Contains(body, canary) {
		out = append(out, "corpo")
	}
	for k, vs := range h {
		for _, v := range vs {
			if strings.Contains(v, canary) {
				out = append(out, "header "+k)
				break
			}
		}
	}
	return out
}

type verdict struct {
	kind     string // cache-poisoning | cache-poisoning-likely | header-reflection | ""
	severity string
	note     string
}

// classify turns the observations into a verdict.
//
//	reflected  – where the canary appeared on the probed request
//	cache      – cache signals on the probed response
//	persisted  – a later clean request to the same cache-busted URL still
//	             returned the canary (⇒ the cache actually stored it)
func classify(reflected []string, cache cacheView, persisted bool) verdict {
	if len(reflected) == 0 {
		return verdict{}
	}
	loc := strings.Join(reflected, ", ")
	switch {
	case persisted:
		return verdict{"cache-poisoning", "high",
			"o valor do atacante (" + loc + ") foi servido de novo numa requisição limpa à mesma URL cacheada — cache poisoning confirmado"}
	case cache.backed:
		return verdict{"cache-poisoning-likely", "medium",
			"valor refletido em " + loc + " e a resposta é cacheável (" + cache.reason + "), mas não confirmei a persistência"}
	default:
		return verdict{"header-reflection", "low",
			"valor refletido em " + loc + " sem sinais claros de cache — revise se há um cache upstream"}
	}
}
