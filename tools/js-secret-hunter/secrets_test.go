package main

import "testing"

func TestScanFindsRealLooking(t *testing.T) {
	body := `
	const cfg = {
	  awsKey: "` + "AKIA" + `Z3XK7QW9P2M4RT8N",
	  gh: "` + "ghp_" + `aB3xY9qW2pL7mK4nR8vT1cD5eF0gH2iJ3k4z",
	  stripe: "` + "sk_live_" + `aB3xY9qW2pL7mK4nR8vT1cD5eF",
	  google: "` + "AIzaSy" + `D1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6X",
	};
	const dsn = "postgres://app:s3cr3tp4ss@db.internal:5432/app";
	const key = "-----BEGIN RSA PRIVATE KEY-----";
	const jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5OTk4ODdmZiJ9.q7Xk9mL2pQ7wR4vT8zN1";
	const notreal = "api_key: \"your_api_key_here_placeholder\"";
	`
	got := map[string]bool{}
	for _, h := range scan(body, 12) {
		got[h.Pattern] = true
		if h.Value == "your_api_key_here_placeholder" {
			t.Error("placeholder foi reportado")
		}
	}
	for _, w := range []string{
		"AWS Access Key ID", "GitHub Token", "Stripe Live Secret Key",
		"Google API Key", "Postgres URL", "Private Key (PEM)", "JWT",
	} {
		if !got[w] {
			t.Errorf("faltou detectar: %s", w)
		}
	}
}

func TestScanIgnoresDocumentedExampleKeys(t *testing.T) {
	// AWS's própria chave de documentação — não é vazamento
	if len(scan(`k="AKIAIOSFODNN7EXAMPLE"`, 12)) != 0 {
		t.Fatal("AKIAIOSFODNN7EXAMPLE não deveria ser reportada")
	}
}

func TestScanDedup(t *testing.T) {
	body := `key="AKIAZ3XK7QW9P2M4RT8N" other="AKIAZ3XK7QW9P2M4RT8N"`
	if n := len(scan(body, 12)); n != 1 {
		t.Fatalf("esperava 1 (deduplicado), veio %d", n)
	}
}

func TestEntropyFilter(t *testing.T) {
	low := `password: "abcabcabcabcabcabc12"` // padrão repetitivo, entropia baixa
	for _, h := range scan(low, 12) {
		if h.Pattern == "Generic Secret Assignment" {
			t.Fatal("valor de baixa entropia não deveria passar")
		}
	}
	high := `password: "aB3xY9qW2pL7mK4nR8vT1cD5eF"` // alnum variado, entropia alta
	found := false
	for _, h := range scan(high, 12) {
		if h.Pattern == "Generic Secret Assignment" {
			found = true
		}
	}
	if !found {
		t.Fatal("valor de alta entropia deveria passar")
	}
}

func TestRedact(t *testing.T) {
	if redact("short") != "short" {
		t.Fatal("curto não redige")
	}
	r := redact("AKIAZ3XK7QW9P2M4RT8N")
	if r == "AKIAZ3XK7QW9P2M4RT8N" || len(r) >= len("AKIAZ3XK7QW9P2M4RT8N") {
		t.Fatalf("deveria redigir: %q", r)
	}
}

func TestShannon(t *testing.T) {
	if shannon("aaaa") > 0.01 {
		t.Fatal("string uniforme tem entropia ~0")
	}
	if shannon("aB3xY9qW2pL7mK4nR8vT") < 3 {
		t.Fatal("string variada tem entropia alta")
	}
}
