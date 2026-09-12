package scopetemplate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "common-noise.json"), []byte(`{
	  "description": "ruído comum de programas SaaS",
	  "platform": "hackerone",
	  "out_of_scope": ["status.example.com", "*.internal.example.com"]
	}`), 0o644)

	r, err := Load(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	tpl, ok := r.Get("common-noise")
	if !ok || len(tpl.OutOfScope) != 2 || tpl.Platform != "hackerone" {
		t.Fatalf("template carregado errado: %+v ok=%v", tpl, ok)
	}
}

func TestLoadMissingDirIsEmpty(t *testing.T) {
	r, err := Load(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("dir ausente não deveria dar erro: %v", err)
	}
	if len(r.List()) != 0 {
		t.Fatal("esperava registry vazio")
	}
}

func TestSaveValidatesAndDedupes(t *testing.T) {
	r, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Save(Template{Name: "Common Noise", OutOfScope: []string{"a.com", "A.COM", "b.com"}}); err == nil {
		t.Fatal("nome com espaço deveria ser rejeitado")
	}
	if err := r.Save(Template{Name: "empty-oos"}); err == nil {
		t.Fatal("out_of_scope vazio deveria ser rejeitado")
	}
	if err := r.Save(Template{Name: "dupe-test", OutOfScope: []string{"a.com", "A.COM", "b.com"}}); err != nil {
		t.Fatalf("save: %v", err)
	}
	tpl, ok := r.Get("dupe-test")
	if !ok || len(tpl.OutOfScope) != 2 {
		t.Fatalf("esperava dedupe (a.com == A.COM): %+v", tpl)
	}

	// não sobrescreve
	if err := r.Save(Template{Name: "dupe-test", OutOfScope: []string{"c.com"}}); err == nil {
		t.Fatal("save de template existente deveria falhar (use Update)")
	}
}

func TestUpdateAndDelete(t *testing.T) {
	r, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Update("ghost", Template{OutOfScope: []string{"a.com"}}); err == nil {
		t.Fatal("update de template inexistente deveria falhar")
	}
	if err := r.Save(Template{Name: "t1", OutOfScope: []string{"a.com"}}); err != nil {
		t.Fatal(err)
	}
	if err := r.Update("t1", Template{OutOfScope: []string{"a.com", "b.com"}, Description: "v2"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	tpl, _ := r.Get("t1")
	if len(tpl.OutOfScope) != 2 || tpl.Description != "v2" {
		t.Fatalf("update não refletiu: %+v", tpl)
	}

	if err := r.Delete("t1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := r.Get("t1"); ok {
		t.Fatal("template deveria ter sumido após delete")
	}
	if err := r.Delete("t1"); err == nil {
		t.Fatal("2º delete deveria falhar")
	}
}

func TestList(t *testing.T) {
	r, err := Load(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Save(Template{Name: "b", OutOfScope: []string{"x.com"}})
	_ = r.Save(Template{Name: "a", OutOfScope: []string{"y.com"}})
	list := r.List()
	if len(list) != 2 || list[0].Name != "a" || list[1].Name != "b" {
		t.Fatalf("esperava [a, b] ordenado, veio: %+v", list)
	}
}
