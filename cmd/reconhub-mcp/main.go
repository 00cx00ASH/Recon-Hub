// Command reconhub-mcp is a Model Context Protocol server (stdio) that exposes a
// running recon-hub over MCP, so Claude or any MCP client can list tools, fire
// jobs and pipelines, and read findings/assets.
//
// Protocol: newline-delimited JSON-RPC 2.0 on stdin/stdout; logs go to stderr.
// Zero external dependencies.
//
// Config (env): RECONHUB_URL (default http://127.0.0.1:7878),
// RECONHUB_TOKEN (else it reads ./data/token relative to the working dir).
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
)

const (
	serverName      = "reconhub-mcp"
	serverVersion   = "0.1.0"
	protocolVersion = "2024-11-05"
)

func main() {
	hub := newHubClient()
	reg := buildTools(hub)

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()

	logf("reconhub-mcp %s pronto (hub: %s)", serverVersion, hub.base)

	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			writeMsg(out, rpcError(nil, -32700, "parse error: "+err.Error()))
			continue
		}
		resp, isNotification := handle(&req, reg)
		if isNotification {
			continue
		}
		writeMsg(out, resp)
	}
	if err := in.Err(); err != nil {
		logf("stdin: %v", err)
	}
}

// --- JSON-RPC types ---

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"` // absent => notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func rpcOK(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}
func rpcError(id json.RawMessage, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcErr{Code: code, Message: msg}}
}

func writeMsg(w *bufio.Writer, v any) {
	b, _ := json.Marshal(v)
	w.Write(b)
	w.WriteByte('\n')
	w.Flush()
}

func logf(format string, a ...any) { fmt.Fprintf(os.Stderr, "[reconhub-mcp] "+format+"\n", a...) }

// --- dispatch ---

func handle(req *rpcRequest, reg map[string]mcpTool) (rpcResponse, bool) {
	notification := len(req.ID) == 0

	switch req.Method {
	case "initialize":
		return rpcOK(req.ID, map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": serverVersion},
		}), notification

	case "notifications/initialized", "notifications/cancelled":
		return rpcResponse{}, true

	case "ping":
		return rpcOK(req.ID, map[string]any{}), notification

	case "tools/list":
		list := make([]map[string]any, 0, len(reg))
		for _, t := range orderedTools(reg) {
			list = append(list, map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"inputSchema": t.Schema,
			})
		}
		return rpcOK(req.ID, map[string]any{"tools": list}), notification

	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return rpcError(req.ID, -32602, "invalid params: "+err.Error()), notification
		}
		t, ok := reg[p.Name]
		if !ok {
			return rpcError(req.ID, -32602, "ferramenta MCP desconhecida: "+p.Name), notification
		}
		if p.Arguments == nil {
			p.Arguments = map[string]any{}
		}
		raw, err := t.Run(p.Arguments)
		if err != nil {
			return rpcOK(req.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": err.Error()}},
				"isError": true,
			}), notification
		}
		return rpcOK(req.ID, map[string]any{
			"content": []map[string]any{{"type": "text", "text": string(pretty(raw))}},
		}), notification

	default:
		if notification {
			return rpcResponse{}, true
		}
		return rpcError(req.ID, -32601, "método não suportado: "+req.Method), notification
	}
}

func pretty(raw json.RawMessage) []byte {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return raw
	}
	return b
}

// --- argument helpers ---

func argStr(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func mustStr(m map[string]any, k string) (string, error) {
	s := argStr(m, k)
	if s == "" {
		return "", fmt.Errorf("argumento obrigatório ausente: %q", k)
	}
	return s, nil
}

// query builds a ?k=v string from the given argument keys that are present.
func query(m map[string]any, keys ...string) string {
	q := url.Values{}
	for _, k := range keys {
		if s := argStr(m, k); s != "" {
			q.Set(k, s)
		}
	}
	if len(q) == 0 {
		return ""
	}
	return "?" + q.Encode()
}
