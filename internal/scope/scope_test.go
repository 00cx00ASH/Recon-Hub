package scope

import (
	"os"
	"path/filepath"
	"testing"
)

func TestContains(t *testing.T) {
	p := Program{
		InScope:    []string{"*.example.com", "api.other.com"},
		OutOfScope: []string{"secret.example.com", "*.internal.example.com"},
	}
	in := []string{"example.com", "www.example.com", "a.b.example.com", "api.other.com",
		"https://shop.example.com/cart", "shop.example.com:8443"}
	out := []string{"other.com", "www.other.com", "secret.example.com",
		"x.internal.example.com", "example.com.evil.com", ""}

	for _, h := range in {
		if !p.Contains(h) {
			t.Errorf("%q deveria estar in-scope", h)
		}
	}
	for _, h := range out {
		if p.Contains(h) {
			t.Errorf("%q NÃO deveria estar in-scope", h)
		}
	}
}

func TestHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://Sub.Example.com/x?y=1": "sub.example.com",
		"sub.example.com:8080":          "sub.example.com",
		"aws-s3:my.bucket.name":         "aws-s3:my.bucket.name", // não é host, passa reto
		"  Example.com.  ":              "example.com",
	} {
		if got := Host(in); got != want {
			t.Errorf("Host(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "acme.json"), []byte(`{
	  "platform": "hackerone",
	  "in_scope": ["*.acme.com"],
	  "out_of_scope": ["blog.acme.com"]
	}`), 0o644)

	r, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p, ok := r.Get("acme")
	if !ok || !p.Contains("api.acme.com") || p.Contains("blog.acme.com") {
		t.Fatalf("programa acme carregado errado: %+v ok=%v", p, ok)
	}
}

func TestLoadRejectsEmptyScope(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"name":"bad"}`), 0o644)
	if _, err := Load(dir); err == nil {
		t.Fatal("esperava erro: in_scope vazio")
	}
}

func TestValidName(t *testing.T) {
	for _, ok := range []string{"acme", "acme-2024", "corp.io", "a_b"} {
		if !ValidName(ok) {
			t.Errorf("%q deveria ser válido", ok)
		}
	}
	for _, bad := range []string{"", "-x", "A", "x/y", "..", "with space", "e" + string(make([]byte, 70))} {
		if ValidName(bad) {
			t.Errorf("%q deveria ser inválido", bad)
		}
	}
}

func TestSave(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "programs")
	r, _ := Load(dir)

	if err := r.Save(Program{Name: "acme", InScope: []string{"*.acme.com", " *.acme.com ", ""}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	p, ok := r.Get("acme")
	if !ok || len(p.InScope) != 1 { // deduplicado + trim
		t.Fatalf("carregou errado: %+v ok=%v", p, ok)
	}
	if _, err := os.Stat(filepath.Join(dir, "acme.json")); err != nil {
		t.Fatalf("arquivo não escrito: %v", err)
	}
	// não sobrescreve
	if err := r.Save(Program{Name: "acme", InScope: []string{"*.acme.com"}}); err == nil {
		t.Fatal("deveria recusar sobrescrever")
	}
	// in_scope vazio
	if err := r.Save(Program{Name: "empty", InScope: []string{"  "}}); err == nil {
		t.Fatal("deveria recusar in_scope vazio")
	}
	// nome inválido
	if err := r.Save(Program{Name: "../evil", InScope: []string{"x.com"}}); err == nil {
		t.Fatal("deveria recusar nome inválido")
	}
}

func TestUpdate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "programs")
	r, _ := Load(dir)

	// não existe ainda -> Update recusa (usar Save pra criar)
	if err := r.Update("acme", Program{InScope: []string{"*.acme.com"}}); err == nil {
		t.Fatal("Update deveria recusar programa inexistente")
	}

	if err := r.Save(Program{Name: "acme", Platform: "hackerone", InScope: []string{"*.acme.com"}}); err != nil {
		t.Fatal(err)
	}

	// atualiza o escopo
	if err := r.Update("acme", Program{InScope: []string{"*.acme.com", "acme.io"}, OutOfScope: []string{"blog.acme.com"}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	p, ok := r.Get("acme")
	if !ok || len(p.InScope) != 2 || !p.Contains("acme.io") || p.Contains("blog.acme.com") {
		t.Fatalf("escopo não atualizou: %+v", p)
	}
	// o nome vem da URL/registro, não do corpo — mesmo mandando outro nome no Program, o arquivo continua acme.json
	if _, err := os.Stat(filepath.Join(dir, "acme.json")); err != nil {
		t.Fatalf("arquivo original deveria continuar existindo: %v", err)
	}

	// in_scope vazio continua inválido no Update também
	if err := r.Update("acme", Program{InScope: nil}); err == nil {
		t.Fatal("Update deveria recusar in_scope vazio")
	}
}

func TestDelete(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "programs")
	r, _ := Load(dir)

	if err := r.Delete("ghost"); err == nil {
		t.Fatal("Delete deveria recusar programa inexistente")
	}

	if err := r.Save(Program{Name: "acme", InScope: []string{"*.acme.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Delete("acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := r.Get("acme"); ok {
		t.Fatal("programa deveria ter sumido do registro depois do Delete")
	}
	if _, err := os.Stat(filepath.Join(dir, "acme.json")); !os.IsNotExist(err) {
		t.Fatalf("arquivo deveria ter sido removido: %v", err)
	}

	// depois de deletado, dá pra criar de novo com o mesmo nome (Save não acha mais conflito)
	if err := r.Save(Program{Name: "acme", InScope: []string{"*.acme.com"}}); err != nil {
		t.Fatalf("recriar após delete: %v", err)
	}
}
