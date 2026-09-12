package main

import "strings"

// classify decides whether the response body proves a reflected-XSS
// candidate for the payload sent (see xssVariants). It never looks for JS
// execution (this tool makes plain HTTP requests, nothing ever runs); it
// only proves that HTML-breaking characters survived unescaped in the
// response text, which is the same "confirm from the real response" bar
// every other scanner in this repo holds itself to.
//
// Three tiers, checked in order:
//   - the FULL payload present raw → strongest signal, works for every
//     variant regardless of which tag/event it uses (a filter that blocks
//     "<script" but not "<svg" still lets this whole string through
//     unescaped). Always high.
//   - "<" + marker present raw (but not the full payload — e.g. quotes got
//     stripped while "<" survived) → real tag injection is still possible.
//     Always high.
//   - a quote (" or ') + marker present raw, but neither of the above → the
//     value broke out of its quoting without an unescaped "<". Inside a
//     <script> block that's still a real JS-string breakout (classic
//     "\";alert(1)//" pattern) → high. Outside a script block it depends on
//     the surrounding attribute the operator still needs to eyeball →
//     medium.
//
// Anything else (marker not reflected, or reflected but every special
// character got stripped/escaped) is not a finding — returns ok=false.
func classify(body, payload, marker string) (sev, ftype, context string, ok bool) {
	if strings.Contains(body, payload) {
		ctx := "dentro de <script>"
		if !inScriptContext(body, strings.Index(body, payload)) {
			ctx = "corpo HTML"
		}
		return "high", "reflected-xss", ctx + " — payload completo refletido sem escapar nenhum caractere", true
	}
	if strings.Contains(body, "<"+marker) {
		ctx := "dentro de <script>"
		if !inScriptContext(body, strings.Index(body, "<"+marker)) {
			ctx = "corpo HTML"
		}
		return "high", "reflected-xss", ctx + " — \"<\" refletido sem escapar, injeção de tag possível", true
	}
	for _, q := range []string{`"`, `'`} {
		idx := strings.Index(body, q+marker)
		if idx < 0 {
			continue
		}
		if inScriptContext(body, idx) {
			return "high", "reflected-xss", "dentro de <script> — aspa refletida sem escapar, quebra string JS (" + q + ")", true
		}
		return "medium", "reflected-xss-attribute", "provável atributo HTML — aspa (" + q + ") refletida sem escapar, mas sem \"<\" — confirme o contexto manualmente", true
	}
	return "", "", "", false
}

// inScriptContext is a cheap heuristic: idx is "inside <script>" when the
// nearest preceding "<script" tag hasn't been closed yet by a "</script"
// before idx. Doesn't parse HTML properly (nested/malformed markup can fool
// it) — good enough to separate "likely JS string" from "likely HTML
// attribute" for the operator to double check, same spirit as the other
// tools' heuristics (e.g. js-gtm-osint's "suspicious tag" detector).
func inScriptContext(body string, idx int) bool {
	if idx < 0 || idx > len(body) {
		return false
	}
	head := strings.ToLower(body[:idx])
	lastOpen := strings.LastIndex(head, "<script")
	if lastOpen < 0 {
		return false
	}
	lastClose := strings.LastIndex(head, "</script")
	return lastOpen > lastClose
}

// xssVariant is one probe value + a short label for what it tests, so a
// confirmed finding can say WHICH technique got through (useful when the
// baseline is blocked but a later variant isn't — that difference is itself
// evidence of a selective filter/WAF, not just "vulnerable or not").
type xssVariant struct {
	Technique string
	Payload   string
}

// xssVariants returns the probe values tried, in order, for one (url,
// param) — testing stops at the first confirmed hit (same "one hit, stop
// testing this task" pattern the rest of the repo's scanners use), but
// trying more than one variant before giving up matters here specifically:
// classify() only ever proves what actually came back unescaped, so a
// single fixed payload gives up the instant it happens to collide with
// whatever that one app/WAF filters — variantes que usam tags/técnicas
// diferentes existem pra não desistir cedo demais só por causa da baseline
// específica.
func xssVariants(marker string) []xssVariant {
	return []xssVariant{
		{"quebra genérica de aspas/tag", `"'><` + marker},
		{"tag <svg onload> — bypass de blacklist que só filtra <script>", `<svg onload=` + marker + `>`},
		{"tag <img onerror> — bypass de blacklist que só filtra <script>/<svg>", `<img src=x onerror=` + marker + `>`},
		{"case misto <ScRiPt> — bypass de filtro case-sensitive pra \"script\"", `<ScRiPt>` + marker + `</sCriPt>`},
	}
}
