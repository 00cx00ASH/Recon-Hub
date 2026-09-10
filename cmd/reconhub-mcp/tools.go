package main

import (
	"encoding/json"
	"sort"
)

// mcpTool is one MCP tool: metadata + a handler that calls the hub.
type mcpTool struct {
	Name        string
	Description string
	Schema      map[string]any
	order       int
	Run         func(args map[string]any) (json.RawMessage, error)
}

func orderedTools(reg map[string]mcpTool) []mcpTool {
	out := make([]mcpTool, 0, len(reg))
	for _, t := range reg {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].order < out[j].order })
	return out
}

// obj is a tiny helper to write JSON Schema.
func obj(props map[string]any, required ...string) map[string]any {
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	} else {
		s["required"] = []string{}
	}
	s["additionalProperties"] = false
	return s
}
func str(desc string) map[string]any  { return map[string]any{"type": "string", "description": desc} }
func integer(d string) map[string]any { return map[string]any{"type": "integer", "description": d} }
func object(d string) map[string]any {
	return map[string]any{"type": "object", "description": d, "additionalProperties": true}
}

func buildTools(h *hubClient) map[string]mcpTool {
	reg := map[string]mcpTool{}
	n := 0
	add := func(name, desc string, schema map[string]any, run func(map[string]any) (json.RawMessage, error)) {
		reg[name] = mcpTool{Name: name, Description: desc, Schema: schema, order: n, Run: run}
		n++
	}

	add("hub_list_tools",
		"Lista as ferramentas de recon registradas no hub (nome, linguagem, categoria, parâmetros).",
		obj(nil),
		func(a map[string]any) (json.RawMessage, error) { return h.call("GET", "/api/tools", nil) })

	add("hub_list_pipelines",
		"Lista as pipelines disponíveis e seus steps.",
		obj(nil),
		func(a map[string]any) (json.RawMessage, error) { return h.call("GET", "/api/pipelines", nil) })

	add("hub_list_programs",
		"Lista os programas (escopo de bug bounty) configurados.",
		obj(nil),
		func(a map[string]any) (json.RawMessage, error) { return h.call("GET", "/api/programs", nil) })

	add("hub_run_job",
		"Dispara um job: roda uma ferramenta contra um alvo. Retorna o job criado (id, status). Acompanhe com hub_get_job.",
		obj(map[string]any{
			"tool":    str("nome da ferramenta (ver hub_list_tools)"),
			"target":  str("alvo, ex: exemplo.com"),
			"program": str("nome do programa/escopo (opcional)"),
			"params":  object("parâmetros da ferramenta (ver o inputSchema dela em hub_list_tools)"),
		}, "tool", "target"),
		func(a map[string]any) (json.RawMessage, error) {
			tool, err := mustStr(a, "tool")
			if err != nil {
				return nil, err
			}
			target, err := mustStr(a, "target")
			if err != nil {
				return nil, err
			}
			body := map[string]any{"tool": tool, "target": target}
			if p := argStr(a, "program"); p != "" {
				body["program"] = p
			}
			if params, ok := a["params"].(map[string]any); ok {
				body["params"] = params
			}
			return h.call("POST", "/api/jobs", body)
		})

	add("hub_get_job",
		"Estado de um job + seus eventos (log/progress/finding/asset/done).",
		obj(map[string]any{"id": str("id do job")}, "id"),
		func(a map[string]any) (json.RawMessage, error) {
			id, err := mustStr(a, "id")
			if err != nil {
				return nil, err
			}
			return h.call("GET", "/api/jobs/"+id, nil)
		})

	add("hub_list_jobs",
		"Lista jobs (mais recentes primeiro).",
		obj(map[string]any{
			"tool":    str("filtra por ferramenta"),
			"program": str("filtra por programa"),
			"status":  str("queued|running|succeeded|failed|canceled"),
			"target":  str("filtra por alvo"),
			"limit":   integer("máx. de linhas (default 100)"),
		}),
		func(a map[string]any) (json.RawMessage, error) {
			return h.call("GET", "/api/jobs"+query(a, "tool", "program", "status", "target", "limit"), nil)
		})

	add("hub_cancel_job",
		"Cancela um job em execução.",
		obj(map[string]any{"id": str("id do job")}, "id"),
		func(a map[string]any) (json.RawMessage, error) {
			id, err := mustStr(a, "id")
			if err != nil {
				return nil, err
			}
			return h.call("POST", "/api/jobs/"+id+"/cancel", nil)
		})

	add("hub_run_pipeline",
		"Dispara uma pipeline (encadeia ferramentas). Retorna a run criada. Acompanhe com hub_get_pipeline_run.",
		obj(map[string]any{
			"pipeline": str("nome da pipeline (ver hub_list_pipelines)"),
			"target":   str("alvo"),
			"program":  str("nome do programa/escopo (opcional; filtra o feed p/ hosts in-scope)"),
		}, "pipeline", "target"),
		func(a map[string]any) (json.RawMessage, error) {
			pl, err := mustStr(a, "pipeline")
			if err != nil {
				return nil, err
			}
			target, err := mustStr(a, "target")
			if err != nil {
				return nil, err
			}
			body := map[string]any{"pipeline": pl, "target": target}
			if p := argStr(a, "program"); p != "" {
				body["program"] = p
			}
			return h.call("POST", "/api/pipeline-runs", body)
		})

	add("hub_get_pipeline_run",
		"Estado de uma pipeline-run: steps (com status e job_id) + findings agregados.",
		obj(map[string]any{"id": str("id da run")}, "id"),
		func(a map[string]any) (json.RawMessage, error) {
			id, err := mustStr(a, "id")
			if err != nil {
				return nil, err
			}
			return h.call("GET", "/api/pipeline-runs/"+id, nil)
		})

	add("hub_list_pipeline_runs",
		"Lista pipeline-runs (mais recentes primeiro).",
		obj(map[string]any{
			"pipeline": str("filtra por pipeline"),
			"program":  str("filtra por programa"),
			"status":   str("queued|running|succeeded|failed|canceled"),
			"limit":    integer("máx. de linhas (default 100)"),
		}),
		func(a map[string]any) (json.RawMessage, error) {
			return h.call("GET", "/api/pipeline-runs"+query(a, "pipeline", "program", "status", "limit"), nil)
		})

	add("hub_list_findings",
		"Lista findings normalizados (deduplicados; campo count = quantas vezes reapareceu).",
		obj(map[string]any{
			"program":  str("filtra por programa"),
			"severity": str("info|low|medium|high|critical"),
			"type":     str("filtra por finding_type"),
			"tool":     str("filtra por ferramenta"),
			"job":      str("filtra por job id"),
			"limit":    integer("máx. de linhas (default 500)"),
		}),
		func(a map[string]any) (json.RawMessage, error) {
			return h.call("GET", "/api/findings"+query(a, "program", "severity", "type", "tool", "job", "limit"), nil)
		})

	add("hub_list_assets",
		"Lista assets descobertos (subdomínios, URLs, buckets…).",
		obj(map[string]any{
			"program": str("filtra por programa"),
			"kind":    str("subdomain|url|bucket|endpoint|ip"),
			"tool":    str("filtra por ferramenta"),
			"job":     str("filtra por job id"),
			"limit":   integer("máx. de linhas (default 2000)"),
		}),
		func(a map[string]any) (json.RawMessage, error) {
			return h.call("GET", "/api/assets"+query(a, "program", "kind", "tool", "job", "limit"), nil)
		})

	return reg
}
