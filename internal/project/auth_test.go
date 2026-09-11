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

func TestSaveLoadAuthProxyRoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	want := Auth{Proxy: "socks5://127.0.0.1:9050"}
	if err := SaveAuth(dataDir, "acme", want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadAuth(dataDir, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if got.Proxy != want.Proxy {
		t.Fatalf("proxy = %q, quer %q", got.Proxy, want.Proxy)
	}
	if got.Empty() {
		t.Fatal("com proxy setado não deveria ser Empty")
	}
}

func TestSaveAuthRejectsInvalidProxy(t *testing.T) {
	dataDir := t.TempDir()
	bad := []string{
		"ftp://127.0.0.1:21",     // esquema não suportado
		"127.0.0.1:8080",         // sem esquema
		"http://",                // sem host
		"nem uma url",
	}
	for _, p := range bad {
		if err := SaveAuth(dataDir, "acme", Auth{Proxy: p}); err == nil {
			t.Errorf("proxy %q deveria ser rejeitado", p)
		}
	}
	good := []string{"http://127.0.0.1:8080", "https://proxy.example.com:443", "socks5://127.0.0.1:9050", "socks5://user:pass@1.2.3.4:1080"}
	for _, p := range good {
		if err := SaveAuth(dataDir, "acme", Auth{Proxy: p}); err != nil {
			t.Errorf("proxy %q deveria ser aceito: %v", p, err)
		}
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
