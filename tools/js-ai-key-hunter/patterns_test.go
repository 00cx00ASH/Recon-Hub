package main

import (
	"strings"
	"testing"
)

func providersOf(hs []hit) map[string]string {
	m := map[string]string{}
	for _, h := range hs {
		m[h.Provider] = h.Value
	}
	return m
}

func TestScanRealLooking(t *testing.T) {
	body := `
	const cfg = {
	  OPENAI_API_KEY: "sk-proj-` + strings.Repeat("aB3xK9zQ", 6) + `",
	  anthropicKey: "sk-ant-api03-` + strings.Repeat("Zx9Qw7Es", 11) + `AA",
	  groq: "gsk_` + strings.Repeat("k7Hg2Lp0", 6) + `",
	  hf_token: "hf_` + strings.Repeat("aB3xK9zQ12", 4) + `",
	  gemini: "AIzaSyD` + strings.Repeat("x", 32) + `"
	};`
	hs := scan(body, 16)
	got := providersOf(hs)
	for _, want := range []string{"OpenAI", "Anthropic", "Groq", "HuggingFace"} {
		if _, ok := got[want]; !ok {
			t.Errorf("faltou %s em %v", want, keysOf(got))
		}
	}
	// gemini value é 'x' repetido -> placeholder (allSame) -> não deve entrar
	if _, bad := got["Google AI (Gemini)"]; bad {
		t.Error("chave gemini toda 'x' deveria ser filtrada como placeholder")
	}
}

// TestScanPineconeRequiresContext é o teste de regressão pro bug real achado
// em triagem: um UUID v4 puro (o shape da chave do Pinecone) é indistinguível
// de QUALQUER outro UUID de uma página — session id, tracking id de
// analytics, id de feature flag, id gerado por um CMP de cookie consent de
// terceiro. Sem exigir "pinecone" por perto, confirmava em qualquer bundle
// grande só por coincidência.
func TestScanPineconeRequiresContext(t *testing.T) {
	uuid := "a1b2c3d4-e5f6-4a1b-8c2d-3e4f5a6b7c8d"

	// UUID solto, sem NADA de contexto — não deveria confirmar.
	if hs := scan("var sessionId = '"+uuid+"';", 16); len(hs) != 0 {
		t.Errorf("UUID solto sem contexto não deveria casar como Pinecone: %+v", hs)
	}
	// mesmo shape, mas claramente de outra biblioteca (CMP de cookie consent) —
	// caso real que apareceu na triagem.
	if hs := scan("window.__cmp.consentId = '"+uuid+"';", 16); len(hs) != 0 {
		t.Errorf("id de CMP de cookie consent não deveria casar como Pinecone: %+v", hs)
	}

	// com "pinecone" por perto, deve confirmar normalmente.
	body := `const PINECONE_API_KEY = "` + uuid + `";`
	hs := scan(body, 16)
	got := providersOf(hs)
	if v, ok := got["Pinecone"]; !ok || v != uuid {
		t.Errorf("esperava Pinecone=%s com contexto, veio %v", uuid, got)
	}
}

func TestScanIgnoresPlaceholders(t *testing.T) {
	body := `
	OPENAI_KEY = "sk-proj-your-key-here-example-000000000000000000000000"
	hf = "hf_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	`
	if hs := scan(body, 16); len(hs) != 0 {
		t.Errorf("placeholders não deveriam casar: %+v", hs)
	}
}

func TestScanEntropyFilter(t *testing.T) {
	// legacy OpenAI pattern requires entropy >= 3.2
	lowEnt := `key = "sk-` + strings.Repeat("a", 48) + `"`
	if hs := scan(lowEnt, 16); len(hs) != 0 {
		t.Errorf("baixa entropia deveria ser filtrada: %+v", hs)
	}
	highEnt := `key = "sk-` + strings.Repeat("aB3xK9zQ", 6) + `"`
	if hs := scan(highEnt, 16); len(hs) == 0 {
		t.Error("alta entropia deveria passar")
	}
}

func TestScanDedup(t *testing.T) {
	k := "sk-proj-" + strings.Repeat("aB3xK9zQ", 6)
	body := "a='" + k + "'; b='" + k + "'; c='" + k + "';"
	if hs := scan(body, 16); len(hs) != 1 {
		t.Errorf("mesma chave 3x -> 1 hit, got %d", len(hs))
	}
}

func TestRedact(t *testing.T) {
	if got := redact("sk-proj-abcdefghijklmnop"); got != "sk-p…mnop" {
		t.Errorf("redact = %q", got)
	}
	if redact("short") != "***" {
		t.Error("valor curto -> ***")
	}
}

func TestShannon(t *testing.T) {
	if shannon("aaaaaaaa") > 0.01 {
		t.Error("uma letra só -> ~0 bits")
	}
	if shannon("aB3xK9zQmN7pWr") < 3.0 {
		t.Error("string variada -> entropia alta")
	}
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
