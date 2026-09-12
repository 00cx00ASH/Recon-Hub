package main

import (
	"strings"
	"testing"
)

func TestClassifyTagBreakoutInBody(t *testing.T) {
	marker := "rhxabc123"
	payload := `"'><` + marker
	body := `<html><body><div>resultado: ` + payload + `</div></body></html>`
	sev, ftype, ctx, ok := classify(body, payload, marker)
	if !ok || sev != "high" || ftype != "reflected-xss" {
		t.Fatalf("esperava high/reflected-xss, veio sev=%q ftype=%q ok=%v (ctx=%q)", sev, ftype, ok, ctx)
	}
}

func TestClassifyTagBreakoutInsideScript(t *testing.T) {
	marker := "rhxabc123"
	payload := `"'><` + marker
	body := `<html><body><script>var x = "` + marker + `"; if (x < ` + payload + `) {}</script></body></html>`
	// injeta o payload literalmente dentro do bloco <script> pra provar
	// que o contexto é detectado corretamente mesmo quando o hit está lá.
	sev, ftype, ctx, ok := classify(body, payload, marker)
	if !ok || sev != "high" || ftype != "reflected-xss" {
		t.Fatalf("esperava high/reflected-xss dentro de script, veio sev=%q ftype=%q ok=%v (ctx=%q)", sev, ftype, ok, ctx)
	}
	if want := "dentro de <script>"; ctx == "" || !contains(ctx, want) {
		t.Fatalf("esperava evidência mencionando %q, veio %q", want, ctx)
	}
}

func TestClassifyQuoteBreakoutInAttribute(t *testing.T) {
	marker := "rhxdef456"
	payload := `"'><` + marker
	// "<" foi filtrado/removido, mas a aspa sobreviveu — quebra de atributo.
	// O payload completo não aparece cru (falta o "<"), então cai no
	// fallback de aspa isolada.
	body := `<html><body><input value="` + marker + `" data-x="'` + marker + `"></body></html>`
	sev, ftype, _, ok := classify(body, payload, marker)
	if !ok || sev != "medium" || ftype != "reflected-xss-attribute" {
		t.Fatalf("esperava medium/reflected-xss-attribute, veio sev=%q ftype=%q ok=%v", sev, ftype, ok)
	}
}

func TestClassifyQuoteBreakoutInsideScriptIsHigh(t *testing.T) {
	marker := "rhxghi789"
	payload := `"'><` + marker
	body := `<html><body><script>var msg = "'` + marker + `";</script></body></html>`
	sev, ftype, _, ok := classify(body, payload, marker)
	if !ok || sev != "high" || ftype != "reflected-xss" {
		t.Fatalf("aspa quebrando string JS dentro de <script> devia ser high, veio sev=%q ftype=%q ok=%v", sev, ftype, ok)
	}
}

func TestClassifyEscapedIsNotAFinding(t *testing.T) {
	marker := "rhxjkl012"
	payload := `"'><` + marker
	body := `<html><body><div>resultado: &#34;&#39;&gt;&lt;` + marker + `</div></body></html>`
	sev, ftype, _, ok := classify(body, payload, marker)
	if ok {
		t.Fatalf("payload totalmente escapado não devia virar finding — veio sev=%q ftype=%q", sev, ftype)
	}
}

func TestClassifyNotReflectedAtAll(t *testing.T) {
	marker := "rhxmno345"
	payload := `"'><` + marker
	body := `<html><body><div>nada a ver por aqui</div></body></html>`
	_, _, _, ok := classify(body, payload, marker)
	if ok {
		t.Fatal("marcador ausente não devia virar finding")
	}
}

func TestClassifyStrippedSpecialCharsIsNotAFinding(t *testing.T) {
	marker := "rhxpqr678"
	payload := `"'><` + marker
	// a app removeu TODOS os caracteres especiais mas manteve o marcador —
	// reflexão existe, mas sem prova de exploração.
	body := `<html><body><div>resultado: ` + marker + `</div></body></html>`
	_, _, _, ok := classify(body, payload, marker)
	if ok {
		t.Fatal("marcador refletido sem nenhum caractere especial não devia virar finding")
	}
}

func TestClassifySvgVariantFullPayload(t *testing.T) {
	marker := "rhxsvg001"
	payload := `<svg onload=` + marker + `>`
	body := `<html><body><div>resultado: ` + payload + `</div></body></html>`
	sev, ftype, ctx, ok := classify(body, payload, marker)
	if !ok || sev != "high" || ftype != "reflected-xss" {
		t.Fatalf("payload <svg> completo refletido devia ser high/reflected-xss, veio sev=%q ftype=%q ok=%v (ctx=%q)", sev, ftype, ok, ctx)
	}
}

func TestClassifyImgVariantFullPayload(t *testing.T) {
	marker := "rhximg002"
	payload := `<img src=x onerror=` + marker + `>`
	body := `<html><body><div>resultado: ` + payload + `</div></body></html>`
	sev, ftype, _, ok := classify(body, payload, marker)
	if !ok || sev != "high" || ftype != "reflected-xss" {
		t.Fatalf("payload <img> completo refletido devia ser high/reflected-xss, veio sev=%q ftype=%q ok=%v", sev, ftype, ok)
	}
}

func TestClassifySvgVariantPartiallyStrippedIsNotAFinding(t *testing.T) {
	marker := "rhxsvg003"
	payload := `<svg onload=` + marker + `>`
	// app removeu "<" e ">" mas manteve o resto — payload completo não
	// sobrevive, e não há "<"+marker nem aspa+marker pros fallbacks.
	body := `<html><body><div>resultado: svg onload=` + marker + `</div></body></html>`
	_, _, _, ok := classify(body, payload, marker)
	if ok {
		t.Fatal("payload <svg> sem os caracteres < e > não devia virar finding")
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

func TestXSSVariantsBaselineContainsAllProbeChars(t *testing.T) {
	vs := xssVariants("MARK")
	if len(vs) == 0 {
		t.Fatal("xssVariants não devia devolver lista vazia")
	}
	p := vs[0].Payload
	for _, want := range []string{`"`, `'`, `<`, `>`, "MARK"} {
		if !contains(p, want) {
			t.Fatalf("baseline %q não contém %q", p, want)
		}
	}
}

func TestXSSVariantsEachContainsMarkerAndDistinctTechnique(t *testing.T) {
	vs := xssVariants("MARK")
	if len(vs) < 2 {
		t.Fatalf("esperava mais de uma variante pra dar mais chance de bypass, veio %d", len(vs))
	}
	seenTech := map[string]bool{}
	for _, v := range vs {
		if !contains(v.Payload, "MARK") {
			t.Fatalf("variante %q não contém o marcador", v.Payload)
		}
		if v.Technique == "" {
			t.Fatalf("variante sem descrição de técnica: %q", v.Payload)
		}
		if seenTech[v.Technique] {
			t.Fatalf("técnica duplicada: %q", v.Technique)
		}
		seenTech[v.Technique] = true
	}
}

func TestXSSVariantsIncludeAlternativeTagsNotJustScript(t *testing.T) {
	// pelo menos uma variante não usa "<script" — pra não desistir cedo
	// demais de um app que bloqueia só essa tag específica.
	vs := xssVariants("MARK")
	foundNonScript := false
	for _, v := range vs {
		lower := strings.ToLower(v.Payload)
		if strings.Contains(lower, "<") && !strings.Contains(lower, "<script") {
			foundNonScript = true
		}
	}
	if !foundNonScript {
		t.Fatal("esperava pelo menos uma variante de tag alternativa (svg/img/…), não só <script>")
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
