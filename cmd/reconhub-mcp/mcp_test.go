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
	if len(tools) != 12 {
		t.Fatalf("esperava 12 tools MCP, veio %d", len(tools))
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
