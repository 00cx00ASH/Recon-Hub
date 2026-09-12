package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"reconhub/internal/auth"
	"reconhub/internal/bus"
	"reconhub/internal/engine"
	"reconhub/internal/monitor"
	"reconhub/internal/pipeline"
	"reconhub/internal/project"
	"reconhub/internal/registry"
	"reconhub/internal/scope"
	"reconhub/internal/scopetemplate"
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
	tpls, err := scopetemplate.Load(t.TempDir())
	if err != nil {
		t.Fatalf("scopetemplate: %v", err)
	}

	eng := engine.New(st, reg, bus.New(), 2)
	return (&Server{Store: st, Reg: reg, Engine: eng, Pipelines: pipes, Programs: progs, ScopeTemplates: tpls, Token: tok, DataDir: t.TempDir()}).Handler()
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

// TestCreateJobRejectsOutOfScopeInParams é o teste de regressão pro bug real:
// inScope() só olhava req.Target — mas todo tool com modo "lista"/"arquivo"
// (urls, hosts, subdomains + seus companheiros _file, e alvos extra de
// endpoint único como url_b) recebe os alvos DE VERDADE por Params, não por
// Target. Um job com target=a.acme.com (em escopo) e urls contendo um host
// fora do programa passava batido — escopo "enforced no servidor" era só
// decorativo pra qualquer ferramenta com lista colada.
func TestCreateJobRejectsOutOfScopeInParams(t *testing.T) {
	h := newTestServer(t, auth.Token{Source: "disabled"})

	// target em escopo, mas um host da lista "urls" não está -> 403
	w := doBody(h, "POST", "/api/jobs",
		`{"tool":"x","target":"a.acme.com","program":"acme","params":{"urls":"https://a.acme.com/x, https://evil.example.com/y"}}`, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "fora do escopo") {
		t.Fatalf("host fora do escopo dentro de params.urls: got %d %s, want 403", w.Code, w.Body.String())
	}

	// mesma coisa pro companheiro de arquivo (hosts_file) — lê o arquivo e
	// confere cada linha
	f := filepath.Join(t.TempDir(), "hosts.txt")
	_ = os.WriteFile(f, []byte("a.acme.com\nevil.example.com\n"), 0o644)
	w = doBody(h, "POST", "/api/jobs",
		`{"tool":"x","target":"a.acme.com","program":"acme","params":{"hosts_file":"`+f+`"}}`, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "fora do escopo") {
		t.Fatalf("host fora do escopo dentro de hosts_file: got %d %s, want 403", w.Code, w.Body.String())
	}

	// url_b (segundo endpoint de comparação, ex: scan-idor) também é checado
	w = doBody(h, "POST", "/api/jobs",
		`{"tool":"x","target":"a.acme.com","program":"acme","params":{"url_b":"https://evil.example.com/resource/1"}}`, nil)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "fora do escopo") {
		t.Fatalf("url_b fora do escopo: got %d %s, want 403", w.Code, w.Body.String())
	}

	// tudo em escopo -> passa da checagem de escopo (falha só por tool inexistente)
	w = doBody(h, "POST", "/api/jobs",
		`{"tool":"x","target":"a.acme.com","program":"acme","params":{"urls":"https://a.acme.com/x, https://b.acme.com/y","url_b":"https://c.acme.com/z"}}`, nil)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "escopo") {
		t.Fatalf("tudo em escopo: got %d %s", w.Code, w.Body.String())
	}

	// ferramenta isenta (scopeExempt) não tem os params checados mesmo com host de fora
	w = doBody(h, "POST", "/api/jobs",
		`{"tool":"int-github-audit","target":"octocat/Hello-World","program":"acme","params":{"urls":"https://evil.example.com/x"}}`, nil)
	if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "escopo") {
		t.Fatalf("tool isenta com params: got %d %s", w.Code, w.Body.String())
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

func TestFindingDraft(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg, _ := registry.Load(t.TempDir())
	eng := engine.New(st, reg, bus.New(), 2)
	h := (&Server{Store: st, Reg: reg, Engine: eng, Token: auth.Token{Source: "disabled"}}).Handler()

	_, err = st.AddFinding(&store.Finding{
		ID: "f1", JobID: "j1", Tool: "scan-subdomain-takeover", Program: "acme",
		Type: "subdomain-takeover", Title: "takeover em old.acme.com", Asset: "old.acme.com",
		Evidence: "CNAME pra old-acme.herokuapp.com, herokuapp devolve 'No such app'", Severity: "high",
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}

	w := do(h, "GET", "/api/findings/f1/draft.md", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("draft: got %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"Subdomain takeover", "old.acme.com", "Passos para reproduzir", "Correção", "Prioridade sugerida pelo recon-hub"} {
		if !strings.Contains(body, want) {
			t.Errorf("draft não contém %q:\n%s", want, body)
		}
	}

	if w := do(h, "GET", "/api/findings/ghost/draft.md", nil); w.Code != http.StatusNotFound {
		t.Fatalf("finding inexistente: got %d, want 404", w.Code)
	}
}

func TestUpdateAndDeleteProgram(t *testing.T) {
	h := newTestServer(t, auth.Token{Source: "disabled"})

	// atualiza o escopo do programa "acme" (já existe via newTestServer)
	w := doBody(h, "PUT", "/api/programs/acme", `{"in_scope":["*.acme.com","acme.io"]}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("update: got %d %s", w.Code, w.Body.String())
	}
	w = do(h, "GET", "/api/programs/acme", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "acme.io") {
		t.Fatalf("escopo não refletiu o update: %d %s", w.Code, w.Body.String())
	}

	// update de programa inexistente -> 400 (não existe pra atualizar)
	w = doBody(h, "PUT", "/api/programs/nope", `{"in_scope":["a.com"]}`, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("update de inexistente: got %d, want 400", w.Code)
	}

	// delete
	w = do(h, "DELETE", "/api/programs/acme", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: got %d %s", w.Code, w.Body.String())
	}
	w = do(h, "GET", "/api/programs/acme", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("programa deveria ter sumido: got %d", w.Code)
	}

	// delete de novo -> 404
	if w := do(h, "DELETE", "/api/programs/acme", nil); w.Code != http.StatusNotFound {
		t.Fatalf("2º delete: got %d, want 404", w.Code)
	}
}

func TestScopeTemplateCRUDAndApply(t *testing.T) {
	h := newTestServer(t, auth.Token{Source: "disabled"}) // "acme" já existe via newTestServer

	// cria template
	w := doBody(h, "POST", "/api/scope-templates", `{"name":"saas-noise","description":"ruído comum","platform":"hackerone","out_of_scope":["status.example.com","status.example.com","*.internal.example.com"]}`, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create template: got %d %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"*.internal.example.com"`) || strings.Count(w.Body.String(), "status.example.com") != 1 {
		t.Fatalf("dedupe não aconteceu: %s", w.Body.String())
	}

	// lista
	w = do(h, "GET", "/api/scope-templates", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "saas-noise") {
		t.Fatalf("list: got %d %s", w.Code, w.Body.String())
	}

	// get
	w = do(h, "GET", "/api/scope-templates/saas-noise", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("get: got %d %s", w.Code, w.Body.String())
	}
	// get inexistente
	if w := do(h, "GET", "/api/scope-templates/ghost", nil); w.Code != http.StatusNotFound {
		t.Fatalf("get inexistente: got %d, want 404", w.Code)
	}

	// update (PUT substitui por completo, igual a programas — reenvia platform)
	w = doBody(h, "PUT", "/api/scope-templates/saas-noise", `{"platform":"hackerone","out_of_scope":["status.example.com","new-exclusion.example.com"]}`, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "new-exclusion.example.com") {
		t.Fatalf("update: got %d %s", w.Code, w.Body.String())
	}

	// aplica o template na criação de um programa novo
	w = doBody(h, "POST", "/api/programs", `{"name":"beta","in_scope":["*.beta.com"],"template":"saas-noise"}`, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("create program com template: got %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{`"status.example.com"`, `"new-exclusion.example.com"`, `"hackerone"`, `"*.beta.com"`} {
		if !strings.Contains(body, want) {
			t.Errorf("programa criado sem %q do template: %s", want, body)
		}
	}

	// template desconhecido -> 400
	w = doBody(h, "POST", "/api/programs", `{"name":"gamma","in_scope":["*.gamma.com"],"template":"nope"}`, nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("template desconhecido: got %d, want 400", w.Code)
	}

	// delete
	w = do(h, "DELETE", "/api/scope-templates/saas-noise", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("delete: got %d %s", w.Code, w.Body.String())
	}
	if w := do(h, "GET", "/api/scope-templates/saas-noise", nil); w.Code != http.StatusNotFound {
		t.Fatalf("template deveria ter sumido: got %d", w.Code)
	}
}

func TestLessonsAppendReadAndOverwrite(t *testing.T) {
	h := newTestServer(t, auth.Token{Source: "disabled"})

	// vazio antes de qualquer lição
	w := do(h, "GET", "/api/lessons", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"lessons":""`) {
		t.Fatalf("esperava lessons vazio: %d %s", w.Code, w.Body.String())
	}

	// append 1
	w = doBody(h, "POST", "/api/lessons", `{"text":"este WAF bloqueia apos 20 req/10s","program":"acme","tool":"scan-fuzz","tags":["waf","rate-limit"]}`, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("append: got %d %s", w.Code, w.Body.String())
	}
	// append sem texto -> 400
	if w := doBody(h, "POST", "/api/lessons", `{"program":"acme"}`, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("texto vazio: got %d, want 400", w.Code)
	}
	// append 2 — nunca apaga o 1º
	w = doBody(h, "POST", "/api/lessons", `{"text":"segunda licao independente"}`, nil)
	if w.Code != http.StatusCreated {
		t.Fatalf("append 2: got %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{"este WAF bloqueia apos 20 req/10s", "programa: acme", "tool: scan-fuzz", "#waf", "segunda licao independente"} {
		if !strings.Contains(body, want) {
			t.Errorf("lessons sem %q: %s", want, body)
		}
	}

	// PUT reescreve tudo
	w = doBody(h, "PUT", "/api/lessons", `{"lessons":"# do zero\n\n- só isso\n"}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("put: got %d %s", w.Code, w.Body.String())
	}
	w = do(h, "GET", "/api/lessons", nil)
	if strings.Contains(w.Body.String(), "segunda licao") || !strings.Contains(w.Body.String(), "só isso") {
		t.Fatalf("PUT deveria substituir tudo: %s", w.Body.String())
	}
}

func timePtr(t time.Time) *time.Time { return &t }

func TestComparePipelineRuns(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg, _ := registry.Load(t.TempDir())
	eng := engine.New(st, reg, bus.New(), 2)
	h := (&Server{Store: st, Reg: reg, Engine: eng, Token: auth.Token{Source: "disabled"}}).Handler()

	t0 := time.Now().UTC().Add(-10 * time.Hour)
	runA := &store.PipelineRun{
		ID: "runA", Pipeline: "full-recon", Target: "acme.com", Program: "acme", Status: "succeeded",
		CreatedAt: t0, StartedAt: timePtr(t0), EndedAt: timePtr(t0.Add(5 * time.Minute)),
	}
	runB := &store.PipelineRun{
		ID: "runB", Pipeline: "full-recon", Target: "acme.com", Program: "acme", Status: "succeeded",
		CreatedAt: t0.Add(time.Hour), StartedAt: timePtr(t0.Add(time.Hour)), EndedAt: timePtr(t0.Add(time.Hour + 5*time.Minute)),
	}
	if err := st.CreatePipelineRun(runA); err != nil {
		t.Fatal(err)
	}
	if err := st.CreatePipelineRun(runB); err != nil {
		t.Fatal(err)
	}

	// existia antes da run A e foi reconfirmado durante a run B -> persiste
	_, _ = st.AddFinding(&store.Finding{
		ID: "f-persists", JobID: "j0", Tool: "scan-cors", Program: "acme", Target: "acme.com",
		Type: "cors-wildcard", Title: "persiste", Asset: "api.acme.com", Severity: "low",
		CreatedAt: t0.Add(-time.Hour), LastSeen: t0.Add(time.Hour + 2*time.Minute),
	})
	// existia antes da run A, só foi visto de novo DURANTE a run A -> não reapareceu na run B -> resolvido
	_, _ = st.AddFinding(&store.Finding{
		ID: "f-resolved", JobID: "j0", Tool: "scan-cors", Program: "acme", Target: "acme.com",
		Type: "cors-null-origin", Title: "resolvido", Asset: "old.acme.com", Severity: "low",
		CreatedAt: t0.Add(-time.Hour), LastSeen: t0.Add(2 * time.Minute),
	})
	// apareceu pela 1ª vez durante a run B -> novo
	_, _ = st.AddFinding(&store.Finding{
		ID: "f-new", JobID: "j1", Tool: "scan-cors", Program: "acme", Target: "acme.com",
		Type: "cors-reflect-origin", Title: "novo", Asset: "new.acme.com", Severity: "medium",
		CreatedAt: t0.Add(time.Hour + time.Minute), LastSeen: t0.Add(time.Hour + time.Minute),
	})

	// ativo já conhecido antes da run B -> não é novo
	_, _ = st.AddAsset(&store.Asset{ID: "a-old", JobID: "j0", Tool: "recon-crtsh", Program: "acme", Kind: "subdomain", Value: "old.acme.com", CreatedAt: t0.Add(-2 * time.Hour)})
	// ativo descoberto pela 1ª vez durante a run B -> novo
	_, _ = st.AddAsset(&store.Asset{ID: "a-new", JobID: "j1", Tool: "recon-crtsh", Program: "acme", Kind: "subdomain", Value: "new.acme.com", CreatedAt: t0.Add(time.Hour + time.Minute)})

	w := do(h, "GET", "/api/pipeline-runs/compare?a=runA&b=runB", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("compare: got %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{`"title":"novo"`, `"title":"resolvido"`, `"persisted_findings_count":1`, `"value":"new.acme.com"`} {
		if !strings.Contains(body, want) {
			t.Errorf("compare sem %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `"title":"persiste"`) {
		t.Errorf("finding persistente não deveria aparecer em new_findings nem resolved_findings:\n%s", body)
	}
	if strings.Contains(body, `"value":"old.acme.com"`) {
		t.Errorf("ativo já conhecido não deveria aparecer em new_assets:\n%s", body)
	}

	// ordem invertida (b=A, a=B) deve dar o mesmo resultado (detecta sozinho qual é a mais antiga)
	w2 := do(h, "GET", "/api/pipeline-runs/compare?a=runB&b=runA", nil)
	if w2.Code != http.StatusOK || w2.Body.String() != body {
		t.Fatalf("ordem invertida deveria dar o mesmo resultado: %d %s", w2.Code, w2.Body.String())
	}

	// runs de pipelines diferentes -> 400
	runC := &store.PipelineRun{ID: "runC", Pipeline: "js-suite", Target: "acme.com", Program: "acme", Status: "succeeded", CreatedAt: t0}
	_ = st.CreatePipelineRun(runC)
	if w := do(h, "GET", "/api/pipeline-runs/compare?a=runA&b=runC", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("pipelines diferentes: got %d, want 400", w.Code)
	}

	// runs de alvos diferentes -> 400
	runD := &store.PipelineRun{ID: "runD", Pipeline: "full-recon", Target: "other.com", Program: "acme", Status: "succeeded", CreatedAt: t0}
	_ = st.CreatePipelineRun(runD)
	if w := do(h, "GET", "/api/pipeline-runs/compare?a=runA&b=runD", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("alvos diferentes: got %d, want 400", w.Code)
	}

	// mesma run duas vezes -> 400
	if w := do(h, "GET", "/api/pipeline-runs/compare?a=runA&b=runA", nil); w.Code != http.StatusBadRequest {
		t.Fatalf("mesma run: got %d, want 400", w.Code)
	}

	// run inexistente -> 404
	if w := do(h, "GET", "/api/pipeline-runs/compare?a=runA&b=ghost", nil); w.Code != http.StatusNotFound {
		t.Fatalf("run inexistente: got %d, want 404", w.Code)
	}
}

func TestSearch(t *testing.T) {
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	reg, _ := registry.Load(t.TempDir())
	eng := engine.New(st, reg, bus.New(), 2)
	dataDir := t.TempDir()

	progDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(progDir, "acme.json"), []byte(`{"in_scope":["*.acme.com"]}`), 0o644)
	progs, _ := scope.Load(progDir)

	h := (&Server{Store: st, Reg: reg, Engine: eng, Programs: progs, Token: auth.Token{Source: "disabled"}, DataDir: dataDir}).Handler()

	_, _ = st.AddFinding(&store.Finding{
		ID: "f1", JobID: "j1", Tool: "scan-cors", Program: "acme",
		Type: "cors-wildcard", Title: "CORS liberado em api.acme.com", Asset: "api.acme.com",
		Evidence: "Access-Control-Allow-Origin: *", Severity: "low", CreatedAt: time.Now().UTC(),
	})
	_, _ = st.AddAsset(&store.Asset{ID: "a1", JobID: "j1", Tool: "recon-crtsh", Program: "acme", Kind: "subdomain", Value: "staging.acme.com", CreatedAt: time.Now().UTC()})
	_ = project.Init(dataDir, "acme")
	_ = project.WriteNotes(dataDir, "acme", "lembrar de checar o painel de staging antes de reportar")

	// acha o finding
	w := do(h, "GET", "/api/search?q=cors", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"kind":"finding"`) {
		t.Fatalf("busca por finding: %d %s", w.Code, w.Body.String())
	}

	// acha o asset (substring de "staging.acme.com", presente tanto no asset quanto na nota)
	w = do(h, "GET", "/api/search?q=staging", nil)
	body := w.Body.String()
	if w.Code != http.StatusOK || !strings.Contains(body, `"kind":"asset"`) || !strings.Contains(body, `"kind":"note"`) {
		t.Fatalf("busca por staging deveria achar asset E nota: %d %s", w.Code, body)
	}

	// query curta demais -> vazio, sem escanear nada
	w = do(h, "GET", "/api/search?q=a", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"results":[]`) {
		t.Fatalf("query curta deveria devolver vazio: %d %s", w.Code, w.Body.String())
	}

	// sem match nenhum
	w = do(h, "GET", "/api/search?q=xyzxyznotfound", nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"results":[]`) {
		t.Fatalf("sem match deveria devolver vazio: %d %s", w.Code, w.Body.String())
	}
}

func TestIntelFindingsIncludesChainCandidates(t *testing.T) {
	srv := newScopeAwareServer(t, auth.Token{Source: "disabled"})
	h := srv.Handler()

	_, _ = srv.Store.AddFinding(&store.Finding{
		ID: "f1", JobID: "j1", Tool: "scan-open-redirect", Program: "acme", Target: "acme.com",
		Type: "open-redirect", Title: "redirect", Asset: "https://login.acme.com/go?next=x", Severity: "high",
	})
	_, _ = srv.Store.AddFinding(&store.Finding{
		ID: "f2", JobID: "j2", Tool: "scan-auth-flow", Program: "acme", Target: "acme.com",
		Type: "oauth-redirect-uri-bypass", Title: "bypass", Asset: "https://login.acme.com/authorize", Severity: "critical",
	})

	w := do(h, "GET", "/api/intel/findings?program=acme", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, corpo %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"chains"`) || !strings.Contains(body, "open-redirect-oauth") {
		t.Fatalf("resposta sem chain candidate esperada: %s", body)
	}
}

// buildReport also needs a *http.Request, exercised indirectly via the
// report endpoints — confirm the rendered report surfaces the same chain.
func TestReportMarkdownIncludesChainCandidates(t *testing.T) {
	srv := newScopeAwareServer(t, auth.Token{Source: "disabled"})
	h := srv.Handler()

	_, _ = srv.Store.AddFinding(&store.Finding{
		ID: "f1", JobID: "j1", Tool: "scan-open-redirect", Program: "acme", Target: "acme.com",
		Type: "open-redirect", Title: "redirect", Asset: "https://login.acme.com/go?next=x", Severity: "high",
	})
	_, _ = srv.Store.AddFinding(&store.Finding{
		ID: "f2", JobID: "j2", Tool: "scan-auth-flow", Program: "acme", Target: "acme.com",
		Type: "oauth-redirect-uri-bypass", Title: "bypass", Asset: "https://login.acme.com/authorize", Severity: "critical",
	})

	w := do(h, "GET", "/api/programs/acme/report.md", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, corpo %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Possíveis encadeamentos") {
		t.Fatalf("relatório sem seção de encadeamentos: %s", w.Body.String())
	}
}

// Os encadeamentos do relatório/dashboard devem liderar pelo mais grave:
// chainCandidatesWithAssets ordena por severidade (estável).
func TestChainCandidatesOrderedBySeverity(t *testing.T) {
	fs := []*store.Finding{
		// vira open-redirect-oauth (high)
		{ID: "r1", Type: "open-redirect", Tool: "scan-open-redirect", Asset: "https://login.acme.com/go?next=x"},
		{ID: "a1", Type: "oauth-redirect-uri-bypass", Tool: "scan-auth-flow", Asset: "https://login.acme.com/authorize"},
		// vira idor-credential-leak (critical) — URL sugere credencial
		{ID: "i1", Type: "idor-horizontal", Tool: "scan-idor", Asset: "https://api.acme.com/users/1/token"},
	}
	chains := chainCandidatesWithAssets(fs)
	if len(chains) < 2 {
		t.Fatalf("esperava >=2 cadeias, veio %d: %+v", len(chains), chains)
	}
	if chains[0].Severity != "critical" {
		t.Fatalf("cadeia mais grave deveria vir primeiro; 1ª = %q (%s)", chains[0].Severity, chains[0].Title)
	}
}
