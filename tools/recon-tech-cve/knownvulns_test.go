package main

import "testing"

func TestVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"2.4.41", "2.4.51", true},
		{"2.4.51", "2.4.51", false},
		{"2.4.52", "2.4.51", false},
		{"1.9.1", "1.10.0", true}, // comparação numérica, não lexicográfica ("9" < "10")
		{"5.8.3", "5.8.3", false},
		{"5.8.2", "5.8.3", true},
		{"7.4.0", "7.4", false}, // "7.4" == "7.4.0" nos componentes que existem
	}
	for _, c := range cases {
		if got := versionLess(c.a, c.b); got != c.want {
			t.Errorf("versionLess(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

func TestMatchVulnsFlagsOldApache(t *testing.T) {
	dets := []detected{{Product: "apache", Version: "2.4.41", Evidence: "Server: Apache/2.4.41"}}
	matches := matchVulns(dets)
	if len(matches) != 1 {
		t.Fatalf("esperava 1 match (apache 2.4.41 < 2.4.51), veio %d", len(matches))
	}
	if matches[0].Vuln.CVE == "" {
		t.Fatal("match sem CVE associado")
	}
}

func TestMatchVulnsSkipsPatchedVersion(t *testing.T) {
	dets := []detected{{Product: "apache", Version: "2.4.51", Evidence: "x"}}
	if matches := matchVulns(dets); len(matches) != 0 {
		t.Fatalf("versão já corrigida não deveria dar match: %+v", matches)
	}
}

func TestMatchVulnsIgnoresUnknownProduct(t *testing.T) {
	dets := []detected{{Product: "meu-framework-interno", Version: "0.1.0", Evidence: "x"}}
	if matches := matchVulns(dets); len(matches) != 0 {
		t.Fatalf("produto fora da tabela não deveria dar match: %+v", matches)
	}
}

func TestKnownVulnsTableWellFormed(t *testing.T) {
	for _, kv := range knownVulns {
		if kv.Product == "" || kv.FixedIn == "" || kv.CVE == "" || kv.Severity == "" || kv.Desc == "" {
			t.Fatalf("entrada incompleta na tabela: %+v", kv)
		}
		if kv.Product != stringsToLower(kv.Product) {
			t.Errorf("produto deveria estar em minúsculas (bate com fingerprint()): %q", kv.Product)
		}
	}
}

func stringsToLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
