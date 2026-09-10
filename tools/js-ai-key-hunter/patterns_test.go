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
