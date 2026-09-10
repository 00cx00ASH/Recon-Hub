package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"reconhub/internal/auth"
	"reconhub/internal/bus"
	"reconhub/internal/engine"
	"reconhub/internal/pipeline"
	"reconhub/internal/registry"
	"reconhub/internal/scope"
	"reconhub/internal/store"
)

func newTestServer(t *testing.T, tok auth.Token) http.Handler {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	reg, err := registry.Load(t.TempDir()) // empty tools dir is fine
	if err != nil {
		t.Fatalf("registry: %v", err)
	}

	progDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(progDir, "acme.json"),
		[]byte(`{"platform":"hackerone","in_scope":["*.acme.com"]}`), 0o644)
	progs, err := scope.Load(progDir)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	pipes, _ := pipeline.Load(t.TempDir())

	eng := engine.New(st, reg, bus.New(), 2)
	return (&Server{Store: st, Reg: reg, Engine: eng, Pipelines: pipes, Programs: progs, Token: tok}).Handler()
}

func do(h http.Handler, method, url string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestHealthIsOpen(t *testing.T) {
	h := newTestServer(t, auth.Token{Value: "sekret"})
	if w := do(h, "GET", "/api/health", nil); w.Code != http.StatusOK {
		t.Fatalf("health without token: got %d", w.Code)
	}
}

func TestGuardRejectsAndAccepts(t *testing.T) {
	h := newTestServer(t, auth.Token{Value: "sekret"})

	if w := do(h, "GET", "/api/tools", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no token: got %d, want 401", w.Code)
	}
	if w := do(h, "GET", "/api/tools", map[string]string{"Authorization": "Bearer wrong"}); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: got %d, want 401", w.Code)
	}
	w := do(h, "GET", "/api/tools", map[string]string{"Authorization": "Bearer sekret"})
	if w.Code != http.StatusOK {
		t.Fatalf("right token: got %d, want 200", w.Code)
	}
	if ch := w.Header().Get("WWW-Authenticate"); ch != "" {
		t.Fatalf("unexpected WWW-Authenticate on success: %q", ch)
	}
}

func TestSSEAcceptsQueryToken(t *testing.T) {
	h := newTestServer(t, auth.Token{Value: "sekret"})

	// bad token -> guard rejects before the handler
	if w := do(h, "GET", "/api/jobs/nope/events", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("sse no token: got %d, want 401", w.Code)
	}
	// good token via query -> guard passes, handler then 404s (job missing)
	if w := do(h, "GET", "/api/jobs/nope/events?access_token=sekret", nil); w.Code != http.StatusNotFound {
		t.Fatalf("sse query token: got %d, want 404", w.Code)
	}
}

func TestDisabledAuthAllowsAll(t *testing.T) {
	h := newTestServer(t, auth.Token{Source: "disabled"})
	if w := do(h, "GET", "/api/tools", nil); w.Code != http.StatusOK {
		t.Fatalf("disabled auth: got %d, want 200", w.Code)
	}
}

func doBody(h http.Handler, method, url, body string, hdr map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPrograms(t *testing.T) {
	h := newTestServer(t, auth.Token{Source: "disabled"})

	w := do(h, "GET", "/api/programs", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"acme"`) {
		t.Fatalf("GET /api/programs: %d %s", w.Code, w.Body.String())
	}

	// job com programa inexistente -> 400 "programa desconhecido"
	w = doBody(h, "POST", "/api/jobs", `{"tool":"x","target":"a.acme.com","program":"nope"}`, nil)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "programa desconhecido") {
		t.Fatalf("programa inválido: %d %s", w.Code, w.Body.String())
	}

	// programa válido mas tool inexistente -> 400 (resolve o programa, falha no tool)
	w = doBody(h, "POST", "/api/jobs", `{"tool":"x","target":"a.acme.com","program":"acme"}`, nil)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "programa") {
		t.Fatalf("esperava erro de tool, veio: %d %s", w.Code, w.Body.String())
	}
}
