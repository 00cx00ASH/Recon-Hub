package guidance

import (
	"reconhub/internal/intel"
	"reconhub/internal/store"
)

// NextStep recomenda uma ferramenta ou pipeline pra executar depois.
type NextStep struct {
	Type        string `json:"type"`                   // "tool" | "pipeline" | "chain" | "retest"
	Name        string `json:"name"`                   // nome da ferramenta ou pipeline
	Reason      string `json:"reason"`                 // por que recomendar isto
	Category    string `json:"category"`               // "recon", "scanning", "confirmation", "analysis"
	TimeMinutes int    `json:"time_minutes"`           // tempo estimado
	Phase       string `json:"phase"`                  // fase metodológica (recon ativo, scanning, etc)
	SuggestedAt string `json:"suggested_at,omitempty"` // timestamp
	Tag         string `json:"tag,omitempty"`          // "retest", "urgent", etc
}

// SuggestNextSteps recomenda 2-3 próximos passos baseado em job/findings/assets.
func SuggestNextSteps(job *store.Job, findings []*store.Finding, assets []*store.Asset) []NextStep {
	suggestions := []NextStep{}

	// Mapa de que foi testado pra não repetir
	testedTools := map[string]bool{}
	testedTools[job.Tool] = true

	// Analisa findings por tipo e recomenda confirmação/aprofundamento
	findingsByType := groupFindingsByType(findings)

	// Analisa assets por kind e recomenda próxima fase
	assetsByKind := groupAssetsByKind(assets)

	// Detecta chains e recomenda exploração delas
	chains := detectChainsFromFindings(findings)

	// Identifica ferramentas já testadas pra sugerir re-testing em novos alvos
	testedByType := groupToolsByType(findings)

	// Se tool anterior foi recon passivo, sugere recon ativo ou scanning
	if isReconPassive(job.Tool) {
		// Se tem subdomínios, fazer recon ativo + scanning básico
		if assetsByKind["subdomain"] > 0 {
			suggestions = append(suggestions, NextStep{
				Type:        "pipeline",
				Name:        "full-recon",
				Reason:      "Você tem " + countStr(assetsByKind["subdomain"]) + " subdomínios. A pipeline full-recon enfileira recon ativo + 30+ scanners em paralelo.",
				Category:    "automation",
				TimeMinutes: 120,
				Phase:       "enumeração + scanning",
			})

			// Ou rodar só recon ativo primeiro (se preferir algo mais rápido)
			suggestions = append(suggestions, NextStep{
				Type:        "tool",
				Name:        "recon-subdomain-brute",
				Reason:      "Recon ativo: descobre subdomínios não-públicos via brute force de DNS.",
				Category:    "recon",
				TimeMinutes: 30,
				Phase:       "recon ativo",
			})

			// Ou começar scanning direto em um subdomain específico
			suggestions = append(suggestions, NextStep{
				Type:        "tool",
				Name:        "recon-web-enum",
				Reason:      "Content discovery + fingerprint de stack nos subdomínios encontrados.",
				Category:    "recon",
				TimeMinutes: 20,
				Phase:       "enumeração",
			})
		}
	}

	// Se encontrou XSS, sugere confirmar em mais contextos
	if findingsByType["xss"] > 0 {
		if !testedTools["scan-xss-dom"] {
			suggestions = append(suggestions, NextStep{
				Type:        "tool",
				Name:        "scan-xss-dom",
				Reason:      "Você tem XSS refletido. Agora testa XSS DOM-based via navegador headless.",
				Category:    "scanning",
				TimeMinutes: 30,
				Phase:       "vulnerability scanning",
			})
		}
	}

	// Se encontrou SQLi (error-based), sugere blind SQLi
	if findingsByType["sql_injection"] > 0 {
		// scan-sqli-blind será adicionado depois (ainda não existe)
		// Por enquanto: suggestion genérica
		suggestions = append(suggestions, NextStep{
			Type:        "tool",
			Name:        "scan-sqli",
			Reason:      "SQL Injection confirmada. Rodar novamente com diferentes payloads pra confirmar em mais parâmetros.",
			Category:    "scanning",
			TimeMinutes: 25,
			Phase:       "vulnerability scanning",
		})
	}

	// Se encontrou auth/bypass, sugere session/JWT
	if findingsByType["auth_flow"] > 0 || findingsByType["weak_auth"] > 0 {
		if !testedTools["js-jwt-finder"] {
			suggestions = append(suggestions, NextStep{
				Type:        "tool",
				Name:        "js-jwt-finder",
				Reason:      "Auth flow testada. Agora procura por JWT fraco ou alg=none.",
				Category:    "scanning",
				TimeMinutes: 15,
				Phase:       "authentication testing",
			})
		}
	}

	// Se tem endpoints JS, sugere secret hunter
	if assetsByKind["endpoint"] > 5 {
		if !testedTools["js-secret-hunter"] {
			suggestions = append(suggestions, NextStep{
				Type:        "tool",
				Name:        "js-secret-hunter",
				Reason:      "Você descobriu " + countStr(assetsByKind["endpoint"]) + " endpoints. Varre o JS deles pra achar segredos/keys.",
				Category:    "scanning",
				TimeMinutes: 20,
				Phase:       "api/js analysis",
			})
		}
	}

	// Se tem portas abertas, sugere MongoDB ou serviços
	if assetsByKind["port"] > 0 {
		if !testedTools["scan-mongodb"] {
			suggestions = append(suggestions, NextStep{
				Type:        "tool",
				Name:        "scan-mongodb",
				Reason:      "Portas abertas detectadas. Verifica MongoDB sem auth nas portas 27017/27018.",
				Category:    "scanning",
				TimeMinutes: 15,
				Phase:       "infrastructure assessment",
			})
		}
	}

	// Se tem endpoints API/GraphQL, sugere GraphQL scan
	if assetsByKind["graphql"] > 0 || containsStr(findingsByType, "graphql") {
		if !testedTools["scan-graphql"] {
			suggestions = append(suggestions, NextStep{
				Type:        "tool",
				Name:        "scan-graphql",
				Reason:      "GraphQL endpoint encontrado. Testa introspection, campos sensíveis e misconfigs.",
				Category:    "scanning",
				TimeMinutes: 20,
				Phase:       "api scanning",
			})
		}
	}

	// Se detectou chains, prioriza investigação delas no topo da lista
	if len(chains) > 0 && len(suggestions) < 3 {
		suggestions = append([]NextStep{NextStep{
			Type:        "chain",
			Name:        "explorar encadeamentos detectados",
			Reason:      "Encontramos " + countStr(len(chains)) + " possível(is) cadeia(s) de vulnerabilidade. Investigar cada uma pode escalar severidade e impacto — abra a aba Findings, seção 'encadeamentos'.",
			Category:    "confirmation",
			TimeMinutes: 30,
			Phase:       "chain exploitation",
		}}, suggestions...)
	}

	// Se já testou recon passivo, sugere re-escanear com ativo em novos alvos
	if len(testedByType["recon-passive"]) > 0 && assetsByKind["subdomain"] > 0 && !testedTools["recon-subdomain-brute"] {
		suggestions = append(suggestions, NextStep{
			Type:        "tool",
			Name:        "recon-subdomain-brute",
			Reason:      "Já foi feito recon passivo. Agora tenta brute force de DNS nos subdomínios descobertos pra achar os não-públicos.",
			Category:    "recon",
			TimeMinutes: 30,
			Phase:       "recon ativo",
			Tag:         "retest",
		})
	}

	// Se não testou scanning web ainda e tem endpoints, sugere começar
	if assetsByKind["url"] > 3 && !testedTools["scan-xss"] {
		suggestions = append(suggestions, NextStep{
			Type:        "tool",
			Name:        "scan-xss",
			Reason:      "Você descobriu " + countStr(assetsByKind["url"]) + " URLs. Escaneia XSS refletido nelas — típica vulnerabilidade em endpoints públicos.",
			Category:    "scanning",
			TimeMinutes: 20,
			Phase:       "vulnerability scanning",
			Tag:         "novo",
		})
	}

	// Se nenhuma sugestão foi feita, dá uma genérica baseada na metodologia
	if len(suggestions) == 0 {
		suggestions = append(suggestions, NextStep{
			Type:        "pipeline",
			Name:        "full-recon",
			Reason:      "Recon inicial completo: enumera subdomínios, endpoints, e roda 30+ scanners em paralelo.",
			Category:    "automation",
			TimeMinutes: 120,
			Phase:       "full methodology",
		})
	}

	// Limita a top 3 sugestões (mais que isso é overwhelming)
	if len(suggestions) > 3 {
		suggestions = suggestions[:3]
	}

	return suggestions
}

// Helpers

func isReconPassive(tool string) bool {
	passiveTools := map[string]bool{
		"recon-crtsh":        true,
		"recon-passive-enum": true,
		"recon-tech-cve":     true,
		"int-github-audit":   true,
	}
	return passiveTools[tool]
}

func groupFindingsByType(findings []*store.Finding) map[string]int {
	m := make(map[string]int)
	for _, f := range findings {
		m[f.Type]++
	}
	return m
}

func groupAssetsByKind(assets []*store.Asset) map[string]int {
	m := make(map[string]int)
	for _, a := range assets {
		m[a.Kind]++
	}
	return m
}

func countStr(n int) string {
	if n == 0 {
		return "nenhum"
	}
	if n == 1 {
		return "1"
	}
	if n < 10 {
		return string(rune('0' + n))
	}
	if n < 100 {
		return string(rune('0'+n/10)) + string(rune('0'+n%10))
	}
	return "100+"
}

func containsStr(m map[string]int, key string) bool {
	_, ok := m[key]
	return ok
}

func detectChainsFromFindings(findings []*store.Finding) []intel.ChainCandidate {
	return intel.DetectChains(findings)
}

func groupToolsByType(findings []*store.Finding) map[string][]*store.Finding {
	m := make(map[string][]*store.Finding)
	for _, f := range findings {
		toolType := categorizeToolByName(f.Tool)
		m[toolType] = append(m[toolType], f)
	}
	return m
}

func categorizeToolByName(tool string) string {
	if isReconPassive(tool) {
		return "recon-passive"
	}
	activeRecon := map[string]bool{"recon-subdomain-brute": true, "recon-web-enum": true, "recon-infra-enum": true}
	if activeRecon[tool] {
		return "recon-active"
	}
	vulnScan := map[string]bool{"scan-xss": true, "scan-sqli": true, "scan-ssti": true, "scan-open-redirect": true, "scan-ssrf": true}
	if vulnScan[tool] {
		return "vulnerability-scan"
	}
	logicScan := map[string]bool{"scan-auth-flow": true, "scan-cors": true, "scan-idor": true}
	if logicScan[tool] {
		return "logic-scan"
	}
	return "other"
}
