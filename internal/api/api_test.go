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
	"reconhub/internal/monitor"
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

func TestCreateJobRejectsOutOfScope(t *testing.T) {
	h := newTestServer(t, auth.Token{Source: "disabled"})

	// alvo fora do escopo do programa "acme" (só *.acme.com) -> 403
	w := doBody(h, "POST", "/api/jobs", `{"tool":"x","target":"evil.example.com","program":"acme"}`, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "fora do escopo") {
		t.Fatalf("alvo fora do escopo: got %d %s, want 403 com \"fora do escopo\"", w.Code, w.Body.String())
	}

	// mesma ferramenta desconhecida, mas alvo em escopo -> passa da checagem de escopo,
	// falha só por causa da tool inexistente (sem menção a escopo/programa)
	w = doBody(h, "POST", "/api/jobs", `{"tool":"x","target":"a.acme.com","program":"acme"}`, nil)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "escopo") {
		t.Fatalf("alvo em escopo: got %d %s", w.Code, w.Body.String())
	}

	// ferramentas cujo alvo não é um host do programa (org/repo, ID de coleção)
	// ficam isentas mesmo com um programa restrito selecionado
	w = doBody(h, "POST", "/api/jobs", `{"tool":"int-github-audit","target":"octocat/Hello-World","program":"acme"}`, nil)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "escopo") {
		t.Fatalf("tool isenta (target sem host): got %d %s", w.Code, w.Body.String())
	}
	w = doBody(h, "POST", "/api/jobs", `{"tool":"int-github-audit","target":"github.com/octocat/Hello-World","program":"acme"}`, nil)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "escopo") {
		t.Fatalf("tool isenta (target com host de terceiro): got %d %s", w.Code, w.Body.String())
	}

	// sem programa selecionado, nada é bloqueado por escopo
	w = doBody(h, "POST", "/api/jobs", `{"tool":"x","target":"evil.example.com"}`, nil)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "escopo") {
		t.Fatalf("sem programa: got %d %s", w.Code, w.Body.String())
	}
}

// newScopeAwareServer is like newTestServer but also wires a real tool and a
// one-step pipeline, so pipeline-run and watch scope checks (which need to
// resolve a step's tool) can be exercised end to end.
func newScopeAwareServer(t *testing.T, tok auth.Token) *Server {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	toolsDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(toolsDir, "recon-web-enum"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(toolsDir, "recon-web-enum", "tool.json"),
		[]byte(`{"exec":["true"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := registry.Load(toolsDir)
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

	pipeDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(pipeDir, "basic.json"),
		[]byte(`{"name":"basic","steps":[{"tool":"recon-web-enum"}]}`), 0o644)
	pipes, err := pipeline.Load(pipeDir)
	if err != nil {
		t.Fatalf("pipeline: %v", err)
	}

	watches, err := monitor.Load(t.TempDir())
	if err != nil {
		t.Fatalf("watches: %v", err)
	}

	eng := engine.New(st, reg, bus.New(), 2)
	return &Server{Store: st, Reg: reg, Engine: eng, Pipelines: pipes, Programs: progs, Watches: watches, Token: tok, DataDir: t.TempDir()}
}

func TestCreatePipelineRunRejectsOutOfScope(t *testing.T) {
	h := newScopeAwareServer(t, auth.Token{Source: "disabled"}).Handler()

	w := doBody(h, "POST", "/api/pipeline-runs", `{"pipeline":"basic","target":"evil.example.com","program":"acme"}`, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "fora do escopo") {
		t.Fatalf("alvo fora do escopo: got %d %s, want 403 com \"fora do escopo\"", w.Code, w.Body.String())
	}

	w = doBody(h, "POST", "/api/pipeline-runs", `{"pipeline":"basic","target":"a.acme.com","program":"acme"}`, nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("alvo em escopo: got %d %s, want 202", w.Code, w.Body.String())
	}
}

func TestCreateWatchRejectsOutOfScope(t *testing.T) {
	h := newScopeAwareServer(t, auth.Token{Source: "disabled"}).Handler()

	w := doBody(h, "POST", "/api/watches",
		`{"name":"w1","pipeline":"basic","target":"evil.example.com","program":"acme","every":"1h"}`, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "fora do escopo") {
		t.Fatalf("alvo fora do escopo: got %d %s, want 403 com \"fora do escopo\"", w.Code, w.Body.String())
	}

	w = doBody(h, "POST", "/api/watches",
		`{"name":"w2","pipeline":"basic","target":"a.acme.com","program":"acme","every":"1h"}`, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("alvo em escopo: got %d %s, want 201", w.Code, w.Body.String())
	}
}
