package escalation

import (
	"reconhub/internal/store"
)

// Rule mapeia um tipo de finding para ferramentas que devem rodar automaticamente
type Rule struct {
	FindingType string   // tipo de finding que dispara a regra
	Tools       []string // ferramentas a rodar quando este finding é encontrado
	Description string   // descrição da escalation
}

// EscalationRules define o mapeamento de findings para escalations automáticas
var EscalationRules = []Rule{
	{
		FindingType: "jwt-token-in-js",
		Tools:       []string{"scan-jwt-analyzer"},
		Description: "JWT encontrado em JS → análise de segurança de JWT",
	},
	{
		FindingType: "js-file-discovered",
		Tools:       []string{"js-secret-hunter", "scan-jwt-analyzer"},
		Description: "Arquivo JS descoberto → busca de secrets e JWTs",
	},
	{
		FindingType: "admin-panel-detected",
		Tools:       []string{"scan-auth-flow"},
		Description: "Painel admin detectado → teste de fluxo de autenticação",
	},
	{
		FindingType: "api-endpoint-detected",
		Tools:       []string{"scan-race-condition", "scan-rate-limit"},
		Description: "Endpoint API detectado → teste de race condition e rate limit",
	},
	{
		FindingType: "open-bucket-found",
		Tools:       []string{"scan-cloud-enum"},
		Description: "Bucket aberto encontrado → enumeração de cloud config",
	},
	{
		FindingType: "git-config-exposed",
		Tools:       []string{"scan-cloud-enum"},
		Description: "Git config exposto → enumeração de outros arquivos sensíveis",
	},
	{
		FindingType: "env-file-exposed",
		Tools:       []string{"scan-cloud-enum"},
		Description: "Arquivo .env exposto → busca por outros arquivos de config",
	},
	{
		FindingType: "waf-detected",
		Tools:       []string{"scan-rate-limit"},
		Description: "WAF detectado → análise de limites de rate limit",
	},
}

// DetectEscalations retorna as ferramentas que devem rodar baseado nos findings detectados
func DetectEscalations(findings []store.Finding) map[string]bool {
	toolsToRun := make(map[string]bool)
	findingTypes := make(map[string]bool)

	// Coleta todos os tipos de findings
	for _, f := range findings {
		findingTypes[f.Type] = true
	}

	// Para cada rule, se o finding_type foi encontrado, adiciona as ferramentas
	for _, rule := range EscalationRules {
		if findingTypes[rule.FindingType] {
			for _, tool := range rule.Tools {
				toolsToRun[tool] = true
			}
		}
	}

	return toolsToRun
}

// HasEscalation retorna true se há alguma escalation esperada baseado nos findings
func HasEscalation(findings []store.Finding) bool {
	escalations := DetectEscalations(findings)
	return len(escalations) > 0
}
