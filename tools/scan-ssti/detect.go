package main

import (
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"
)

// engineProbe is one template engine's math-expression syntax. All five
// evaluate a*b when the engine actually renders the expression — the
// classic, minimal-footprint SSTI probe (PortSwigger/OWASP): it never reads
// a real file, never spawns a process, just proves the app evaluates an
// expression it should be treating as inert text.
type engineProbe struct {
	Engine string
	Build  func(a, b int) string
}

var engineProbes = []engineProbe{
	{"Jinja2/Twig", func(a, b int) string { return fmt.Sprintf("{{%d*%d}}", a, b) }},
	{"FreeMarker/Thymeleaf", func(a, b int) string { return fmt.Sprintf("${%d*%d}", a, b) }},
	{"Velocity", func(a, b int) string { return fmt.Sprintf("#set($x=%d*%d)$x", a, b) }},
	{"ERB (Ruby)", func(a, b int) string { return fmt.Sprintf("<%%= %d*%d %%>", a, b) }},
	{"Smarty", func(a, b int) string { return fmt.Sprintf("{%d*%d}", a, b) }},
	// Razor (.NET/ASP.NET) — @(expr) avalia C# arbitrário. Cobre stacks
	// .NET que nenhuma das sintaxes acima toca (nenhuma delas é válida
	// como C#, então um Razor vulnerável nunca daria falso positivo nas
	// outras — cada probe só bate na engine cuja sintaxe realmente é).
	{"Razor (.NET)", func(a, b int) string { return fmt.Sprintf("@(%d*%d)", a, b) }},
	// Pug/Jade (Node.js/Express) — #{expr} interpola JS arbitrário.
	{"Pug/Jade (Node.js)", func(a, b int) string { return fmt.Sprintf("#{%d*%d}", a, b) }},
}

// randPair picks two 3-digit factors per probe (crypto/rand, same house
// pattern as scan-xss's randMarker) — NOT a fixed classic like 7*7=49.
// A fixed product risks colliding with something already on the page
// (a price, a count, a phone number); a fresh ~90..989 × ~90..989 product
// is astronomically unlikely to be there by coincidence, and a distinct
// pair per (url,param) means one page's baseline can never leak into
// another target's confirmation.
func randPair() (a, b int) {
	return 90 + randN(900), 90 + randN(900)
}

func randN(max int) int {
	var buf [2]byte
	_, _ = rand.Read(buf[:])
	n := int(buf[0])<<8 | int(buf[1])
	return n % max
}

// classify decides whether injecting payload (one engine's a*b expression)
// proved server-side template evaluation. Two conditions, both required —
// this is the same "never key on a substring that's also literally present
// in the injected payload itself" lesson from this hub's own scan-ssrf
// false-positive fix, applied here from the start:
//
//  1. The COMPUTED result (e.g. "8811" for 89*99) appears in the injected
//     response but is ABSENT from the baseline — differential, same as
//     scan-sqli's error-signature check, rules out a page that already
//     happened to contain that number for an unrelated reason.
//  2. The raw payload text (e.g. "{{89*99}}") does NOT appear in the
//     injected response — rules out plain reflection (the app echoing the
//     input back unescaped, an XSS-shaped bug, not a template evaluating
//     it). A template engine that evaluates the expression never emits
//     the source text back verbatim; one that merely reflects it never
//     emits the product. Only real evaluation satisfies both at once.
func classify(baseline, injected, payload string, a, b int) (sev, ftype, product string, ok bool) {
	product = strconv.Itoa(a * b)
	if !strings.Contains(injected, product) {
		return "", "", "", false
	}
	if strings.Contains(baseline, product) {
		return "", "", "", false
	}
	if strings.Contains(injected, payload) {
		return "", "", "", false
	}
	return "critical", "ssti", product, true
}
