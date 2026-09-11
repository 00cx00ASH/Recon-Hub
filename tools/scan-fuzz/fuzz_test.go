package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := map[int]struct{ ft, sev string }{
		200: {"content", "low"},
		204: {"content", "low"},
		301: {"content-redirect", "info"},
		401: {"content-restricted", "medium"},
		403: {"content-restricted", "medium"},
		500: {"content", "info"},
	}
	for st, want := range cases {
		ft, sev := classify(st)
		if ft != want.ft || sev != want.sev {
			t.Errorf("classify(%d) = %q/%q, quer %q/%q", st, ft, sev, want.ft, want.sev)
		}
	}
}

func TestBaselineSoftNotFound(t *testing.T) {
	b := baseline{status: 404, size: 1500, present: true}
	if !b.isSoftNotFound(404, 1500) || !b.isSoftNotFound(404, 1450) {
		t.Fatal("deveria casar o soft-404 (±128 bytes)")
	}
	if b.isSoftNotFound(404, 3000) || b.isSoftNotFound(200, 1500) {
		t.Fatal("não deveria casar")
	}
	if (baseline{}).isSoftNotFound(404, 100) {
		t.Fatal("baseline ausente nunca casa")
	}
}

func TestWordsFrom(t *testing.T) {
	in := "admin\n/api\n# comentário\n\nadmin\n  login  \n"
	got := wordsFrom(in)
	want := []string{"admin", "api", "login"}
	if len(got) != len(want) {
		t.Fatalf("got %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
}

func TestCalibrateAndProbe(t *testing.T) {
	// servidor que responde 404 fixo p/ paths aleatórios e 200 p/ /admin
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/admin" {
			w.Write([]byte("SECRET ADMIN PANEL"))
			return
		}
		w.WriteHeader(404)
		w.Write([]byte("nope, not here, 404 page, some padding padding padding"))
	}))
	defer srv.Close()
	c := &http.Client{Timeout: 3 * time.Second}

	bl := calibrate(c, srv.URL, nil)
	if !bl.present || bl.status != 404 {
		t.Fatalf("calibrate: %+v", bl)
	}
	st, sz, ok := probe(c, srv.URL+"/admin")
	if !ok || st != 200 || sz == 0 {
		t.Fatalf("probe /admin: %d %d %v", st, sz, ok)
	}
	if bl.isSoftNotFound(st, sz) {
		t.Fatal("/admin não deveria ser tratado como soft-404")
	}
	// um path aleatório DEVE bater no soft-404
	st, sz, _ = probe(c, srv.URL+"/"+randToken())
	if !bl.isSoftNotFound(st, sz) {
		t.Fatalf("random path deveria casar soft-404: %d %d", st, sz)
	}
}

func TestBuildCandidatesMarksBareVsExtension(t *testing.T) {
	cands := buildCandidates([]string{"admin"}, []string{".php", ".bak"})
	if len(cands) != 3 {
		t.Fatalf("esperava 3 candidatos (bare + 2 exts), veio %d", len(cands))
	}
	if cands[0].path != "admin" || !cands[0].bare {
		t.Errorf("1º candidato deveria ser a palavra pura e bare=true: %+v", cands[0])
	}
	if cands[1].path != "admin.php" || cands[1].bare {
		t.Errorf("2º candidato com extensão deveria ter bare=false: %+v", cands[1])
	}
	if cands[2].path != "admin.bak" || cands[2].bare {
		t.Errorf("3º candidato com extensão deveria ter bare=false: %+v", cands[2])
	}
}

// TestRunFuzzRecursion é o teste central do modo recursivo: sem
// recursive_depth só a raiz é testada (acha /admin, não vê o que tem
// dentro); com recursive_depth=1, o hit bare /admin vira um novo nível e
// /admin/backup também é achado.
func TestRunFuzzRecursion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin":
			w.Write([]byte("admin index page, tamanho bem diferente do 404 padrão"))
		case "/admin/backup":
			w.Write([]byte("backup file contents found nested inside the admin directory"))
		default:
			w.WriteHeader(404)
			w.Write([]byte("not found, generic 404 page with some padding text here"))
		}
	}))
	defer srv.Close()
	c := &http.Client{Timeout: 3 * time.Second}
	codes := map[int]bool{200: true}
	words := []string{"admin", "backup"}

	if _, hits := runFuzz(c, srv.URL, words, nil, codes, -1, 5, 0, 0, 50); hits != 1 {
		t.Fatalf("sem recursão (recDepth=0) esperava 1 hit (/admin), veio %d", hits)
	}
	if _, hits := runFuzz(c, srv.URL, words, nil, codes, -1, 5, 0, 1, 50); hits != 2 {
		t.Fatalf("com recDepth=1 esperava 2 hits (/admin + /admin/backup), veio %d", hits)
	}
}

// TestRunFuzzRespectsMaxRecursiveDirs prova que o teto de diretórios
// recursados corta a explosão combinatória: um alvo que responde 200 pra
// TODA palavra (o pior caso pra recursão ingênua) não deveria gerar
// requisições sem limite.
func TestRunFuzzRespectsMaxRecursiveDirs(t *testing.T) {
	real := map[string]bool{"a": true, "b": true, "c": true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		last := parts[len(parts)-1]
		if real[last] {
			w.Write([]byte(strings.Repeat("x", 1000))) // bem diferente do baseline
			return
		}
		w.Write([]byte("tiny")) // baseline "soft-404" (sempre 200, corpo pequeno)
	}))
	defer srv.Close()
	c := &http.Client{Timeout: 3 * time.Second}
	codes := map[int]bool{200: true}
	words := []string{"a", "b", "c"}

	reqs, _ := runFuzz(c, srv.URL, words, nil, codes, -1, 5, 0, 2, 1)
	if reqs != 6 {
		t.Fatalf("esperava exatamente 6 requisições (3 na raiz + 3 em só 1 diretório recursado, teto maxDirs=1), veio %d — recursão sem teto teria explodido", reqs)
	}
}
