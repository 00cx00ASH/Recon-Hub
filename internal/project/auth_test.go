package project

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadAuthMissingIsEmptyNotError(t *testing.T) {
	dataDir := t.TempDir()
	a, err := LoadAuth(dataDir, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Empty() {
		t.Fatalf("esperava vazio, veio %+v", a)
	}
}

func TestSaveLoadAuthRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	want := Auth{Cookie: "session=abc123", Bearer: "eyJ...", Headers: map[string]string{"X-Api-Key": "k1"}}
	if err := SaveAuth(dataDir, "acme", want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAuth(dataDir, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if got.Cookie != want.Cookie || got.Bearer != want.Bearer || got.Headers["X-Api-Key"] != "k1" {
		t.Fatalf("got %+v, quer %+v", got, want)
	}
	if got.Empty() {
		t.Fatal("não deveria estar vazio")
	}
}

func TestSaveAuthPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("permissões unix não se aplicam")
	}
	dataDir := t.TempDir()
	if err := SaveAuth(dataDir, "acme", Auth{Bearer: "secret"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(Dir(dataDir, "acme"), "auth.json")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("auth.json com permissão %v, quer 0600 (é credencial)", fi.Mode().Perm())
	}
}

func TestAuthEmpty(t *testing.T) {
	if !(Auth{}).Empty() {
		t.Error("zero value deveria ser Empty")
	}
	if (Auth{Cookie: "x"}).Empty() {
		t.Error("com cookie não deveria ser Empty")
	}
}
