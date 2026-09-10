package auth

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestResolvePrecedence(t *testing.T) {
	dir := t.TempDir()

	// flag beats everything
	tok, err := Resolve(dir, "flagtok", "envtok", "cfgtok", false, false)
	if err != nil || tok.Value != "flagtok" || tok.Source != "flag" {
		t.Fatalf("flag: got %+v err %v", tok, err)
	}
	// env beats config + file
	tok, _ = Resolve(dir, "", "envtok", "cfgtok", false, false)
	if tok.Value != "envtok" || tok.Source != "env" {
		t.Fatalf("env: got %+v", tok)
	}
	// config beats file
	tok, _ = Resolve(dir, "", "", "cfgtok", false, false)
	if tok.Value != "cfgtok" || tok.Source != "config" {
		t.Fatalf("config: got %+v", tok)
	}

	// nothing supplied -> generate + persist
	tok, err = Resolve(dir, "", "", "", false, false)
	if err != nil || tok.Source != "generated" || len(tok.Value) != 64 {
		t.Fatalf("generate: got %+v err %v", tok, err)
	}
	saved, err := os.ReadFile(filepath.Join(dir, "token"))
	if err != nil || len(saved) == 0 {
		t.Fatalf("token file not written: %v", err)
	}

	// second call with nothing supplied -> reads the persisted file
	tok2, _ := Resolve(dir, "", "", "", false, false)
	if tok2.Source != "file" || tok2.Value != tok.Value {
		t.Fatalf("file: got %+v want value %q", tok2, tok.Value)
	}

	// regen ignores the persisted file and writes a new one
	tok3, _ := Resolve(dir, "", "", "", false, true)
	if tok3.Source != "generated" || tok3.Value == tok.Value {
		t.Fatalf("regen: got %+v (unchanged?)", tok3)
	}

	// no-auth wins over everything
	tok4, _ := Resolve(dir, "flagtok", "envtok", "cfgtok", true, false)
	if tok4.Enabled() || tok4.Source != "disabled" {
		t.Fatalf("no-auth: got %+v", tok4)
	}
}

func TestMatches(t *testing.T) {
	tok := Token{Value: "secret"}
	if !tok.Matches("secret") {
		t.Fatal("correct token rejected")
	}
	if tok.Matches("wrong") || tok.Matches("") || tok.Matches("secre") {
		t.Fatal("incorrect token accepted")
	}
	if !(Token{}).Matches("anything") {
		t.Fatal("disabled token should match anything")
	}
}

func TestFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?access_token=q", nil)
	r.Header.Set("Authorization", "Bearer h")
	if got := FromRequest(r, false); got != "h" {
		t.Fatalf("header: got %q", got)
	}

	r = httptest.NewRequest("GET", "/x?access_token=q", nil)
	if got := FromRequest(r, true); got != "q" {
		t.Fatalf("query allowed: got %q", got)
	}
	if got := FromRequest(r, false); got != "" {
		t.Fatalf("query not allowed: got %q", got)
	}
}
