package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func fakeHub(t *testing.T) (*hubClient, *httptest.Server) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/tools", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"tools":[{"name":"example-echo"}]}`))
	})
	mux.HandleFunc("POST /api/jobs", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["tool"] != "example-echo" || body["target"] != "x.com" {
			t.Errorf("corpo inesperado: %v", body)
		}
		w.WriteHeader(202)
		w.Write([]byte(`{"id":"abc123","status":"queued"}`))
	})
	mux.HandleFunc("GET /api/findings", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("severity") != "high" {
			t.Errorf("query severity ausente: %s", r.URL.RawQuery)
		}
		w.Write([]byte(`{"findings":[]}`))
	})
	mux.HandleFunc("POST /api/findings/{id}/triage", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if r.PathValue("id") != "f1" || body["verdict"] != "confirmed" {
			t.Errorf("triage: id/body inesperado: id=%s body=%v", r.PathValue("id"), body)
		}
		reason, _ := body["reason"].(string)
		w.Write([]byte(`{"id":"f1","triage":"confirmed","triage_reason":"` + reason + `"}`))
	})
	mux.HandleFunc("POST /api/programs", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "acme" {
			t.Errorf("create_program: corpo inesperado: %v", body)
		}
		w.WriteHeader(201)
		w.Write([]byte(`{"name":"acme","in_scope":["*.acme.com"]}`))
	})
	mux.HandleFunc("GET /api/findings/{id}/draft.md", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Write([]byte("# Relatório de recon — finding " + r.PathValue("id") + "\n"))
	})
	mux.HandleFunc("GET /api/programs/{name}/report.md", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Write([]byte("# Relatório — " + r.PathValue("name") + "\n"))
	})
	mux.HandleFunc("GET /api/pipeline-runs/compare", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("a") != "runA" || r.URL.Query().Get("b") != "runB" {
			t.Errorf("compare: query inesperada: %s", r.URL.RawQuery)
		}
		w.Write([]byte(`{"new_findings":[],"resolved_findings":[],"persisted_findings_count":0,"new_assets":[]}`))
	})
	mux.HandleFunc("GET /api/scope-templates", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"templates":[{"name":"saas-noise","out_of_scope":["status.acme.com"]}]}`))
	})
	mux.HandleFunc("POST /api/scope-templates", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		if body["name"] != "saas-noise" {
			t.Errorf("create_scope_template: corpo inesperado: %v", body)
		}
		w.WriteHeader(201)
		w.Write([]byte(`{"name":"saas-noise","out_of_scope":["status.acme.com"]}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &hubClient{base: srv.URL, http: &http.Client{Timeout: 5 * time.Second}}, srv
}

func callTool(t *testing.T, reg map[string]mcpTool, name string, args map[string]any) map[string]any {
	t.Helper()
	params, _ := json.Marshal(map[string]any{"name": name, "arguments": args})
	req := &rpcRequest{ID: json.RawMessage(`1`), Method: "tools/call", Params: params}
	resp, isNotif := handle(req, reg)
	if isNotif {
		t.Fatal("tools/call não deveria ser notificação")
	}
	if resp.Error != nil {
		t.Fatalf("erro RPC: %+v", resp.Error)
	}
	m, _ := resp.Result.(map[string]any)
	return m
}

func TestInitializeAndList(t *testing.T) {
	h, _ := fakeHub(t)
	reg := buildTools(h)

	resp, _ := handle(&rpcRequest{ID: json.RawMessage(`1`), Method: "initialize"}, reg)
	r := resp.Result.(map[string]any)
	if r["protocolVersion"] != protocolVersion {
		t.Fatalf("protocolVersion: %v", r["protocolVersion"])
	}

	resp, _ = handle(&rpcRequest{ID: json.RawMessage(`2`), Method: "tools/list"}, reg)
	tools := resp.Result.(map[string]any)["tools"].([]map[string]any)
	if len(tools) != 19 {
		t.Fatalf("esperava 19 tools MCP, veio %d", len(tools))
	}
	if tools[0]["name"] != "hub_list_tools" {
		t.Fatalf("ordem inesperada: %v", tools[0]["name"])
	}
}

func TestCallForwardsToHub(t *testing.T) {
	h, _ := fakeHub(t)
	reg := buildTools(h)

	out := callTool(t, reg, "hub_list_tools", nil)
	txt := out["content"].([]map[string]any)[0]["text"].(string)
	if !contains(txt, "example-echo") {
		t.Fatalf("list_tools sem example-echo: %s", txt)
	}

	out = callTool(t, reg, "hub_run_job", map[string]any{
		"tool": "example-echo", "target": "x.com", "params": map[string]any{"count": 2},
	})
	if out["isError"] == true {
		t.Fatalf("run_job deu erro: %v", out)
	}
	if !contains(out["content"].([]map[string]any)[0]["text"].(string), "abc123") {
		t.Fatalf("run_job sem id: %v", out)
	}

	// query params encaminhados
	callTool(t, reg, "hub_list_findings", map[string]any{"severity": "high"})
}

func TestTriageFinding(t *testing.T) {
	h, _ := fakeHub(t)
	reg := buildTools(h)

	out := callTool(t, reg, "hub_triage_finding", map[string]any{
		"id": "f1", "verdict": "confirmed", "reason": "testado manualmente, bucket abre de verdade",
	})
	if out["isError"] == true {
		t.Fatalf("triage_finding deu erro: %v", out)
	}
	txt := out["content"].([]map[string]any)[0]["text"].(string)
	if !contains(txt, "confirmed") || !contains(txt, "bucket abre de verdade") {
		t.Fatalf("triage_finding sem verdict/reason: %s", txt)
	}
}

func TestTriageFindingMissingRequiredArgs(t *testing.T) {
	h, _ := fakeHub(t)
	reg := buildTools(h)
	out := callTool(t, reg, "hub_triage_finding", map[string]any{"id": "f1"}) // falta verdict
	if out["isError"] != true {
		t.Fatalf("esperava isError=true, veio %v", out)
	}
}

func TestCreateProgram(t *testing.T) {
	h, _ := fakeHub(t)
	reg := buildTools(h)

	out := callTool(t, reg, "hub_create_program", map[string]any{
		"name": "acme", "in_scope": []any{"*.acme.com", "acme.com"},
	})
	if out["isError"] == true {
		t.Fatalf("create_program deu erro: %v", out)
	}
	txt := out["content"].([]map[string]any)[0]["text"].(string)
	if !contains(txt, "acme") {
		t.Fatalf("create_program sem o nome: %s", txt)
	}
}

func TestCreateProgramRequiresInScope(t *testing.T) {
	h, _ := fakeHub(t)
	reg := buildTools(h)
	// in_scope ausente inteiramente
	out := callTool(t, reg, "hub_create_program", map[string]any{"name": "acme"})
	if out["isError"] != true {
		t.Fatalf("esperava isError=true (sem in_scope), veio %v", out)
	}
	// in_scope presente mas vazio
	out = callTool(t, reg, "hub_create_program", map[string]any{"name": "acme", "in_scope": []any{}})
	if out["isError"] != true {
		t.Fatalf("esperava isError=true (in_scope vazio), veio %v", out)
	}
}

func TestDraftFindingAndProgramReport(t *testing.T) {
	h, _ := fakeHub(t)
	reg := buildTools(h)

	out := callTool(t, reg, "hub_draft_finding", map[string]any{"id": "f1"})
	if out["isError"] == true {
		t.Fatalf("draft_finding deu erro: %v", out)
	}
	if txt := out["content"].([]map[string]any)[0]["text"].(string); !contains(txt, "f1") {
		t.Fatalf("draft_finding sem o id: %s", txt)
	}

	out = callTool(t, reg, "hub_program_report", map[string]any{"program": "acme"})
	if out["isError"] == true {
		t.Fatalf("program_report deu erro: %v", out)
	}
	if txt := out["content"].([]map[string]any)[0]["text"].(string); !contains(txt, "acme") {
		t.Fatalf("program_report sem o nome do programa: %s", txt)
	}
}

func TestComparePipelineRuns(t *testing.T) {
	h, _ := fakeHub(t)
	reg := buildTools(h)

	out := callTool(t, reg, "hub_compare_pipeline_runs", map[string]any{"a": "runA", "b": "runB"})
	if out["isError"] == true {
		t.Fatalf("compare_pipeline_runs deu erro: %v", out)
	}
	if txt := out["content"].([]map[string]any)[0]["text"].(string); !contains(txt, "persisted_findings_count") {
		t.Fatalf("compare_pipeline_runs sem o campo esperado: %s", txt)
	}

	out = callTool(t, reg, "hub_compare_pipeline_runs", map[string]any{"a": "runA"}) // falta b
	if out["isError"] != true {
		t.Fatalf("faltando b deveria dar erro: %v", out)
	}
}

func TestScopeTemplates(t *testing.T) {
	h, _ := fakeHub(t)
	reg := buildTools(h)

	out := callTool(t, reg, "hub_list_scope_templates", map[string]any{})
	if out["isError"] == true {
		t.Fatalf("list_scope_templates deu erro: %v", out)
	}
	if txt := out["content"].([]map[string]any)[0]["text"].(string); !contains(txt, "saas-noise") {
		t.Fatalf("list_scope_templates sem o template: %s", txt)
	}

	out = callTool(t, reg, "hub_create_scope_template", map[string]any{
		"name": "saas-noise", "out_of_scope": []any{"status.acme.com"},
	})
	if out["isError"] == true {
		t.Fatalf("create_scope_template deu erro: %v", out)
	}

	out = callTool(t, reg, "hub_create_scope_template", map[string]any{"name": "no-oos"}) // falta out_of_scope
	if out["isError"] != true {
		t.Fatalf("out_of_scope vazio deveria dar erro: %v", out)
	}
}

func TestCallMissingRequiredArg(t *testing.T) {
	h, _ := fakeHub(t)
	reg := buildTools(h)
	out := callTool(t, reg, "hub_run_job", map[string]any{"tool": "example-echo"}) // falta target
	if out["isError"] != true {
		t.Fatalf("esperava isError=true, veio %v", out)
	}
}

func TestUnknownMethod(t *testing.T) {
	h, _ := fakeHub(t)
	reg := buildTools(h)
	resp, _ := handle(&rpcRequest{ID: json.RawMessage(`9`), Method: "no/such"}, reg)
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("esperava -32601, veio %+v", resp.Error)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
