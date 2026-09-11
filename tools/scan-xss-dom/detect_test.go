package main

import (
	"strings"
	"testing"
)

func TestDomPayloadContainsToken(t *testing.T) {
	tok := "abc123"
	p := domPayload(tok)
	if !strings.Contains(p, "__rhxss_abc123") {
		t.Fatalf("payload deveria conter o token no nome da propriedade: %q", p)
	}
	if !strings.Contains(p, "onerror") {
		t.Fatalf("payload deveria usar onerror (dispara sem clique/interação): %q", p)
	}
}

func TestEvalExprMatchesPayloadToken(t *testing.T) {
	tok := "abc123"
	if evalExpr(tok) != "!!window.__rhxss_abc123" {
		t.Fatalf("evalExpr(%q) = %q", tok, evalExpr(tok))
	}
}

func TestTwoTokensNeverCollideTrivially(t *testing.T) {
	a, b := randToken(), randToken()
	if a == b {
		t.Fatal("dois randToken() seguidos vieram iguais — entropia insuficiente")
	}
	if len(a) < 12 {
		t.Fatalf("token curto demais: %q", a)
	}
}

func TestWithHashReplacesExistingFragment(t *testing.T) {
	got := withHash("https://x.com/page#old", "PAYLOAD")
	want := "https://x.com/page#PAYLOAD"
	if got != want {
		t.Fatalf("got %q, quer %q", got, want)
	}
}

func TestWithHashAppendsWhenNoneExists(t *testing.T) {
	got := withHash("https://x.com/page", "PAYLOAD")
	want := "https://x.com/page#PAYLOAD"
	if got != want {
		t.Fatalf("got %q, quer %q", got, want)
	}
}

func TestWithQueryParamAppendsToExistingValue(t *testing.T) {
	got, err := withQueryParam("https://x.com/page?name=joao", "name", "PAYLOAD")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "name=joaoPAYLOAD") && !strings.Contains(got, "name=joao%22") {
		// url.Values.Encode() escapa o payload — só confere que o valor
		// original "joao" ainda está no começo, seguido do payload
		// (codificado ou não).
		t.Fatalf("esperava name=joao<payload codificado>, veio %q", got)
	}
}

func TestWithQueryParamSetsWhenParamAbsent(t *testing.T) {
	got, err := withQueryParam("https://x.com/page", "q", "x")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "q=x") {
		t.Fatalf("esperava q=x, veio %q", got)
	}
}

func TestMergeParamsPutsExtraFirstAndDedupes(t *testing.T) {
	got := mergeParams("name, q\nq", []string{"q", "search"})
	want := []string{"name", "q", "search"}
	if len(got) != len(want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, quer %v", got, want)
		}
	}
}

func TestMergeParamsHandlesEmptyExtra(t *testing.T) {
	got := mergeParams("", []string{"q", "search"})
	if len(got) != 2 || got[0] != "q" || got[1] != "search" {
		t.Fatalf("esperava [q search] inalterado, veio %v", got)
	}
}
