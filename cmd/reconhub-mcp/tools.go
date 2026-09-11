package main

import (
	"encoding/json"
	"fmt"
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

// obj is a tiny helper to write JSON Schema. A nil props must still serialize
// as an empty object ({}), not null — strict MCP clients reject a null
// "properties" and refuse the whole tools/list.
func obj(props map[string]any, required ...string) map[string]any {
	if props == nil {
		props = map[string]any{}
	}
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
func strArray(d string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": d}
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

	add("hub_compare_pipeline_runs",
		"Compara duas pipeline-runs da MESMA pipeline+alvo+programa: o que é novo, o que sumiu (provável correção) e o que persiste, em findings; e ativos novos. Útil pra confirmar retest ('o fix realmente resolveu?') ou ver o que mudou desde a última rodada.",
		obj(map[string]any{
			"a": str("id de uma pipeline-run"),
			"b": str("id da outra pipeline-run (ordem não importa — o hub detecta sozinho qual é a mais antiga)"),
		}, "a", "b"),
		func(a map[string]any) (json.RawMessage, error) {
			if _, err := mustStr(a, "a"); err != nil {
				return nil, err
			}
			if _, err := mustStr(a, "b"); err != nil {
				return nil, err
			}
			return h.call("GET", "/api/pipeline-runs/compare"+query(a, "a", "b"), nil)
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

	add("hub_triage_finding",
		"Marca o veredito do operador sobre um finding (confirmed, false_positive ou ignored), com um motivo opcional. É o feedback que internal/intel usa pra afinar o score de achados futuros do mesmo tipo+ferramenta — sem isso o hub nunca aprende com o que já foi revisado. Use depois de confirmar (ou descartar) um achado, não antes de checar a evidência.",
		obj(map[string]any{
			"id":      str("id do finding (ver hub_list_findings)"),
			"verdict": str("confirmed | false_positive | ignored"),
			"reason":  str("opcional: por que esse veredito — fica junto do finding pra reler depois, não afeta o score"),
		}, "id", "verdict"),
		func(a map[string]any) (json.RawMessage, error) {
			id, err := mustStr(a, "id")
			if err != nil {
				return nil, err
			}
			verdict, err := mustStr(a, "verdict")
			if err != nil {
				return nil, err
			}
			body := map[string]any{"verdict": verdict}
			if reason := argStr(a, "reason"); reason != "" {
				body["reason"] = reason
			}
			return h.call("POST", "/api/findings/"+id+"/triage", body)
		})

	add("hub_create_program",
		"Cria um programa (escopo de bug bounty) — precisa existir antes de rodar qualquer job/pipeline com enforcement de escopo nesse alvo. in_scope aceita padrões: \"example.com\" (exato), \"*.example.com\" (subdomínios), CIDR.",
		obj(map[string]any{
			"name":         str("nome do programa (a-z, 0-9, . _ -, até 63 chars — vira o nome do arquivo em programs/)"),
			"in_scope":     strArray("padrões em escopo — obrigatório, pelo menos 1"),
			"out_of_scope": strArray("padrões fora de escopo (tem precedência sobre in_scope)"),
			"platform":     str("opcional: hackerone | intigriti | bugcrowd | …"),
			"url":          str("opcional: URL da página do programa na plataforma"),
			"template":     str("opcional: nome de um template salvo (ver hub_list_scope_templates) — mescla o out_of_scope dele e preenche platform se não informado. NUNCA mexe em in_scope."),
		}, "name", "in_scope"),
		func(a map[string]any) (json.RawMessage, error) {
			name, err := mustStr(a, "name")
			if err != nil {
				return nil, err
			}
			inScope := argStrSlice(a, "in_scope")
			if len(inScope) == 0 {
				return nil, fmt.Errorf("in_scope precisa de pelo menos 1 padrão")
			}
			body := map[string]any{"name": name, "in_scope": inScope}
			if out := argStrSlice(a, "out_of_scope"); len(out) > 0 {
				body["out_of_scope"] = out
			}
			if p := argStr(a, "platform"); p != "" {
				body["platform"] = p
			}
			if u := argStr(a, "url"); u != "" {
				body["url"] = u
			}
			if tpl := argStr(a, "template"); tpl != "" {
				body["template"] = tpl
			}
			return h.call("POST", "/api/programs", body)
		})

	add("hub_list_scope_templates",
		"Lista templates de escopo salvos (presets de out_of_scope + platform reaproveitáveis ao criar um programa — ver hub_create_program).",
		obj(map[string]any{}),
		func(a map[string]any) (json.RawMessage, error) {
			return h.call("GET", "/api/scope-templates", nil)
		})

	add("hub_create_scope_template",
		"Salva um template de escopo reaproveitável: um preset de out_of_scope (+ platform opcional) que hub_create_program pode aplicar depois, em vez de repetir as mesmas exclusões toda vez que um programa novo é criado. NUNCA guarda in_scope — isso é sempre específico do programa.",
		obj(map[string]any{
			"name":         str("nome do template (a-z, 0-9, . _ -, até 63 chars)"),
			"out_of_scope": strArray("padrões fora de escopo — obrigatório, pelo menos 1 (é o motivo do template existir)"),
			"platform":     str("opcional: preenchido em hub_create_program se o programa não informar platform"),
			"description":  str("opcional: pra que serve esse template"),
		}, "name", "out_of_scope"),
		func(a map[string]any) (json.RawMessage, error) {
			name, err := mustStr(a, "name")
			if err != nil {
				return nil, err
			}
			out := argStrSlice(a, "out_of_scope")
			if len(out) == 0 {
				return nil, fmt.Errorf("out_of_scope precisa de pelo menos 1 padrão")
			}
			body := map[string]any{"name": name, "out_of_scope": out}
			if p := argStr(a, "platform"); p != "" {
				body["platform"] = p
			}
			if d := argStr(a, "description"); d != "" {
				body["description"] = d
			}
			return h.call("POST", "/api/scope-templates", body)
		})

	add("hub_get_lessons",
		"Lê a base de conhecimento cross-programa (lessons.md): padrões que se repetem ENTRE programas diferentes (comportamento de WAF/rate-limit, peculiaridade de plataforma, técnica que funcionou ou não) — diferente de notes.md, que é por programa. Leia isso no início de um programa novo pra reaproveitar o que já foi aprendido em outros.",
		obj(map[string]any{}),
		func(a map[string]any) (json.RawMessage, error) {
			return h.call("GET", "/api/lessons", nil)
		})

	add("hub_add_lesson",
		"Registra uma lição reaproveitável em QUALQUER programa (não só o atual) na base de conhecimento cross-programa — acrescenta, nunca apaga o que já tem. Use quando notar um padrão que vale lembrar em outro programa depois: um WAF com limiar específico, uma plataforma que sempre aceita/rejeita certo tipo de achado, uma técnica que funcionou bem. Não é o lugar pra observação específica de UM programa — isso é notes.md.",
		obj(map[string]any{
			"text":    str("a lição em si — objetiva, reaproveitável fora do contexto atual"),
			"program": str("opcional: onde foi aprendida, só como contexto"),
			"tool":    str("opcional: ferramenta/técnica relacionada"),
			"tags":    strArray("opcional: palavras-chave pra facilitar achar depois"),
		}, "text"),
		func(a map[string]any) (json.RawMessage, error) {
			text, err := mustStr(a, "text")
			if err != nil {
				return nil, err
			}
			body := map[string]any{"text": text}
			if p := argStr(a, "program"); p != "" {
				body["program"] = p
			}
			if tl := argStr(a, "tool"); tl != "" {
				body["tool"] = tl
			}
			if tags := argStrSlice(a, "tags"); len(tags) > 0 {
				body["tags"] = tags
			}
			return h.call("POST", "/api/lessons", body)
		})

	add("hub_draft_finding",
		"Rascunho de relatório (Markdown) pra UM finding: título, severidade, evidência, passos de reprodução, impacto, correção, CWE/referências quando o hub já tem o template desse finding_type. Pronto pra colar/adaptar pro programa — prefira isso a remontar o texto na mão.",
		obj(map[string]any{"id": str("id do finding")}, "id"),
		func(a map[string]any) (json.RawMessage, error) {
			id, err := mustStr(a, "id")
			if err != nil {
				return nil, err
			}
			return h.call("GET", "/api/findings/"+id+"/draft.md", nil)
		})

	add("hub_program_report",
		"Relatório completo (Markdown) de um programa: todos os findings reportáveis, agrupados por severidade, com resumo executivo.",
		obj(map[string]any{"program": str("nome do programa")}, "program"),
		func(a map[string]any) (json.RawMessage, error) {
			p, err := mustStr(a, "program")
			if err != nil {
				return nil, err
			}
			return h.call("GET", "/api/programs/"+p+"/report.md", nil)
		})

	return reg
}
