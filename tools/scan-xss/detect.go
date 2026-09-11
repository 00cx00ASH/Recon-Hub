package main

import "strings"

// classify decides whether the response body proves a reflected-XSS
// candidate for the payload sent — marker + the special characters that
// prefix it (see buildPayload). It never looks for JS execution (this tool
// makes plain HTTP requests, nothing ever runs); it only proves that
// HTML-breaking characters survived unescaped in the response text, which is
// the same "confirm from the real response" bar every other scanner in this
// repo holds itself to.
//
// Two tiers:
//   - "<" + marker present raw  → real tag injection is possible regardless
//     of surrounding context. Always high.
//   - a quote (" or ') + marker present raw, but no "<" + marker → the value
//     broke out of its quoting, but without an unescaped "<" there's no bare
//     tag injection. Inside a <script> block that's still a real JS-string
//     breakout (classic "\";alert(1)//" pattern) → high. Outside a script
//     block it depends on the surrounding attribute the operator still needs
//     to eyeball → medium.
//
// Anything else (marker not reflected, or reflected but every special
// character got stripped/escaped) is not a finding — returns ok=false.
func classify(body, marker string) (sev, ftype, context string, ok bool) {
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

// buildPayload is the single probe value sent per (url, param): a quote, an
// apostrophe and an angle-bracket, all in front of the marker. One request
// tests every signal classify() looks for — matches the "one hit, stop
// testing this task" pattern the rest of the repo's scanners use.
func buildPayload(marker string) string {
	return `"'><` + marker
}
