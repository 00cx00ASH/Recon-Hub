package main

import (
	"net/http"
	"net/http/httptest"
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
