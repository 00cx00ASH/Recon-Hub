package main

import "testing"

func TestClassifyConfirmsWhenEvaluated(t *testing.T) {
	baseline := `<html><body>Olá, visitante</body></html>`
	payload := "{{89*97}}"
	injected := `<html><body>Olá, 8633</body></html>`
	sev, ftype, product, ok := classify(baseline, injected, payload, 89, 97)
	if !ok || sev != "critical" || ftype != "ssti" || product != "8633" {
		t.Fatalf("esperava critical/ssti/8633, veio sev=%q ftype=%q product=%q ok=%v", sev, ftype, product, ok)
	}
}

// TestClassifyRejectsPlainReflection é o teste central de falso-positivo:
// a app ecoa o payload cru de volta (comportamento tipo XSS, não SSTI) —
// o produto NUNCA aparece porque nada foi avaliado. Sem essa checagem, um
// scanner ingênuo que só olhasse "o texto do payload voltou" confundiria
// reflexão crua com avaliação de template.
func TestClassifyRejectsPlainReflection(t *testing.T) {
	baseline := `<html><body>Olá, visitante</body></html>`
	payload := "{{89*97}}"
	injected := `<html><body>Olá, {{89*97}}</body></html>` // ecoou cru, não avaliou
	_, _, _, ok := classify(baseline, injected, payload, 89, 97)
	if ok {
		t.Fatal("payload refletido cru (não avaliado) não deveria confirmar SSTI")
	}
}

// TestClassifyRejectsProductAlreadyInBaseline é o mesmo princípio do
// scan-sqli: uma página que já continha aquele número por coincidência
// (ex: um preço, uma contagem) antes mesmo do payload não prova nada — só
// a DIFERENÇA entre baseline e injetado é sinal real.
func TestClassifyRejectsProductAlreadyInBaseline(t *testing.T) {
	baseline := `<html><body>Total: 8633 itens em estoque</body></html>`
	payload := "{{89*97}}"
	injected := `<html><body>Total: 8633 itens em estoque</body></html>`
	_, _, _, ok := classify(baseline, injected, payload, 89, 97)
	if ok {
		t.Fatal("produto já presente no baseline não deveria confirmar SSTI")
	}
}

func TestClassifyRejectsNoMatch(t *testing.T) {
	baseline := `<html><body>ok</body></html>`
	payload := "{{89*97}}"
	injected := `<html><body>ok</body></html>`
	_, _, _, ok := classify(baseline, injected, payload, 89, 97)
	if ok {
		t.Fatal("sem produto nem payload na resposta não deveria confirmar nada")
	}
}

func TestEngineProbesCoverMainTemplateSyntaxes(t *testing.T) {
	want := map[string]string{
		"Jinja2/Twig":          "{{7*13}}",
		"FreeMarker/Thymeleaf": "${7*13}",
		"Velocity":             "#set($x=7*13)$x",
		"ERB (Ruby)":           "<%= 7*13 %>",
		"Smarty":               "{7*13}",
		"Razor (.NET)":         "@(7*13)",
		"Pug/Jade (Node.js)":   "#{7*13}",
	}
	if len(engineProbes) != len(want) {
		t.Fatalf("esperava %d engines, veio %d", len(want), len(engineProbes))
	}
	for _, e := range engineProbes {
		got := e.Build(7, 13)
		if want[e.Engine] != got {
			t.Errorf("%s: got %q, quer %q", e.Engine, got, want[e.Engine])
		}
	}
}

func TestRandPairInRange(t *testing.T) {
	for i := 0; i < 50; i++ {
		a, b := randPair()
		if a < 90 || a >= 990 || b < 90 || b >= 990 {
			t.Fatalf("par fora do range esperado [90,990): a=%d b=%d", a, b)
		}
	}
}
