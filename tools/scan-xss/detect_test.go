package main

import "testing"

func TestClassifyTagBreakoutInBody(t *testing.T) {
	marker := "rhxabc123"
	body := `<html><body><div>resultado: "'><` + marker + `</div></body></html>`
	sev, ftype, ctx, ok := classify(body, marker)
	if !ok || sev != "high" || ftype != "reflected-xss" {
		t.Fatalf("esperava high/reflected-xss, veio sev=%q ftype=%q ok=%v (ctx=%q)", sev, ftype, ok, ctx)
	}
}

func TestClassifyTagBreakoutInsideScript(t *testing.T) {
	marker := "rhxabc123"
	body := `<html><body><script>var x = "` + marker + `"; if (x < "'><` + marker + `") {}</script></body></html>`
	// injeta o "<"+marker literalmente dentro do bloco <script> pra provar
	// que o contexto é detectado corretamente mesmo quando o hit está lá.
	sev, ftype, ctx, ok := classify(body, marker)
	if !ok || sev != "high" || ftype != "reflected-xss" {
		t.Fatalf("esperava high/reflected-xss dentro de script, veio sev=%q ftype=%q ok=%v (ctx=%q)", sev, ftype, ok, ctx)
	}
	if want := "dentro de <script>"; ctx == "" || !contains(ctx, want) {
		t.Fatalf("esperava evidência mencionando %q, veio %q", want, ctx)
	}
}

func TestClassifyQuoteBreakoutInAttribute(t *testing.T) {
	marker := "rhxdef456"
	// "<" foi filtrado/removido, mas a aspa sobreviveu — quebra de atributo.
	body := `<html><body><input value="` + marker + `" data-x="'` + marker + `"></body></html>`
	sev, ftype, _, ok := classify(body, marker)
	if !ok || sev != "medium" || ftype != "reflected-xss-attribute" {
		t.Fatalf("esperava medium/reflected-xss-attribute, veio sev=%q ftype=%q ok=%v", sev, ftype, ok)
	}
}

func TestClassifyQuoteBreakoutInsideScriptIsHigh(t *testing.T) {
	marker := "rhxghi789"
	body := `<html><body><script>var msg = "'` + marker + `";</script></body></html>`
	sev, ftype, _, ok := classify(body, marker)
	if !ok || sev != "high" || ftype != "reflected-xss" {
		t.Fatalf("aspa quebrando string JS dentro de <script> devia ser high, veio sev=%q ftype=%q ok=%v", sev, ftype, ok)
	}
}

func TestClassifyEscapedIsNotAFinding(t *testing.T) {
	marker := "rhxjkl012"
	body := `<html><body><div>resultado: &#34;&#39;&gt;&lt;` + marker + `</div></body></html>`
	sev, ftype, _, ok := classify(body, marker)
	if ok {
		t.Fatalf("payload totalmente escapado não devia virar finding — veio sev=%q ftype=%q", sev, ftype)
	}
}

func TestClassifyNotReflectedAtAll(t *testing.T) {
	marker := "rhxmno345"
	body := `<html><body><div>nada a ver por aqui</div></body></html>`
	_, _, _, ok := classify(body, marker)
	if ok {
		t.Fatal("marcador ausente não devia virar finding")
	}
}

func TestClassifyStrippedSpecialCharsIsNotAFinding(t *testing.T) {
	marker := "rhxpqr678"
	// a app removeu TODOS os caracteres especiais mas manteve o marcador —
	// reflexão existe, mas sem prova de exploração.
	body := `<html><body><div>resultado: ` + marker + `</div></body></html>`
	_, _, _, ok := classify(body, marker)
	if ok {
		t.Fatal("marcador refletido sem nenhum caractere especial não devia virar finding")
	}
}

func TestInScriptContextBasic(t *testing.T) {
	body := `<html><script>here</script><div>there</div>`
	idxScript := indexOf(body, "here")
	idxDiv := indexOf(body, "there")
	if !inScriptContext(body, idxScript) {
		t.Fatal("posição dentro de <script>...</script> devia contar como script context")
	}
	if inScriptContext(body, idxDiv) {
		t.Fatal("posição depois de </script> não devia contar como script context")
	}
}

func TestBuildPayloadContainsAllProbeChars(t *testing.T) {
	p := buildPayload("MARK")
	for _, want := range []string{`"`, `'`, `<`, `>`, "MARK"} {
		if !contains(p, want) {
			t.Fatalf("payload %q não contém %q", p, want)
		}
	}
}

// helpers de teste minúsculos pra não importar strings só por isso em todo teste
func contains(s, sub string) bool { return indexOf(s, sub) >= 0 }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
