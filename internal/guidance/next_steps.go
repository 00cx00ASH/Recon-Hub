package guidance

import (
	"strconv"

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

// findingConfirmation mapeia um finding_type REAL (que existe em
// intel.knownRisk — garantido por TestFindingConfirmationKeysAreKnown) para a
// ferramenta de confirmação/aprofundamento que faz sentido rodar depois. Só
// entram transições que agregam de verdade: a ferramenta sugerida é DIFERENTE
// da que achou o finding e leva a metodologia adiante (reflexo → execução,
// segredo no JS → auditoria da origem).
type findingConfirmation struct {
	tool   string
	reason string
	phase  string
	mins   int
}

var findingConfirmations = map[string]findingConfirmation{
	"reflected-xss": {
		tool:   "scan-xss-dom",
		reason: "XSS refletido confirmado por texto (os caracteres voltaram sem escapar). O próximo passo é provar EXECUÇÃO real: scan-xss-dom dispara o payload num navegador headless e só confirma se o JS rodar de fato.",
		phase:  "confirmação de XSS",
		mins:   30,
	},
	"reflected-xss-attribute": {
		tool:   "scan-xss-dom",
		reason: "Só a aspa quebrou (contexto de atributo/string JS) — pode ou não executar. scan-xss-dom tenta a execução real num navegador pra tirar a dúvida sem achismo.",
		phase:  "confirmação de XSS",
		mins:   30,
	},
	"secret": {
		tool:   "int-github-audit",
		reason: "Segredo achado por padrão/entropia no JS do alvo. Vale auditar o GitHub da organização: o mesmo segredo (ou outros) costuma estar commitado em repo público — int-github-audit procura isso.",
		phase:  "OSINT / expansão",
		mins:   20,
	},
}

// assetProgression mapeia um asset kind REAL (url, endpoint, subdomain, port,
// package — os que as tools de fato emitem) para o próximo passo da esteira.
type assetProgression struct {
	minCount int
	step     NextStep
}

var assetProgressions = []struct {
	kind string
	prog assetProgression
}{
	{"url", assetProgression{minCount: 3, step: NextStep{
		Type: "tool", Name: "scan-xss", Category: "scanning", TimeMinutes: 20,
		Phase: "vulnerability scanning",
		Tag:   "novo",
	}}},
	{"endpoint", assetProgression{minCount: 5, step: NextStep{
		Type: "tool", Name: "js-secret-hunter", Category: "scanning", TimeMinutes: 20,
		Phase: "api/js analysis",
	}}},
	{"port", assetProgression{minCount: 1, step: NextStep{
		Type: "tool", Name: "scan-mongodb", Category: "scanning", TimeMinutes: 15,
		Phase: "infrastructure assessment",
	}}},
	{"package", assetProgression{minCount: 1, step: NextStep{
		Type: "tool", Name: "scan-dep-confusion", Category: "scanning", TimeMinutes: 15,
		Phase: "supply chain",
	}}},
}

// SuggestNextSteps recomenda até 3 próximos passos baseado em job/findings/assets.
// Ordem de prioridade: (1) encadeamentos detectados, (2) confirmação de findings
// reais, (3) progressão da esteira por assets novos, (4) bootstrap pós-recon.
func SuggestNextSteps(job *store.Job, findings []*store.Finding, assets []*store.Asset) []NextStep {
	suggestions := []NextStep{}

	testedTools := map[string]bool{job.Tool: true}
	for _, f := range findings {
		if f.Tool != "" {
			testedTools[f.Tool] = true
		}
	}

	findingsByType := groupFindingsByType(findings)
	assetsByKind := groupAssetsByKind(assets)
	chains := intel.DetectChains(findings)

	add := func(s NextStep) {
		if s.Type == "tool" && testedTools[s.Name] {
			return // não sugere reexecutar o que já rodou
		}
		for _, existing := range suggestions {
			if existing.Type == s.Type && existing.Name == s.Name {
				return // dedup
			}
		}
		suggestions = append(suggestions, s)
	}

	// (1) Encadeamentos detectados — sempre no topo: é onde a severidade escala.
	if len(chains) > 0 {
		c := chains[0]
		reason := "Detectamos " + countStr(len(chains)) + " possível(is) cadeia(s) de vulnerabilidade"
		if c.Title != "" {
			reason += " (ex: " + c.Title + ")"
		}
		reason += ". Investigar encadeia impacto e escala severidade — abra a aba Findings, seção 'encadeamentos'."
		add(NextStep{
			Type: "chain", Name: "explorar encadeamentos detectados",
			Reason: reason, Category: "confirmation", TimeMinutes: 30,
			Phase: "chain exploitation", Tag: "urgent",
		})
	}

	// (2) Confirmação/aprofundamento de findings reais.
	for ftype := range findingsByType {
		fc, ok := findingConfirmations[ftype]
		if !ok {
			continue
		}
		add(NextStep{
			Type: "tool", Name: fc.tool, Reason: fc.reason,
			Category: "confirmation", TimeMinutes: fc.mins, Phase: fc.phase,
		})
	}

	// (3) Progressão da esteira: assets novos → próxima fase.
	for _, ap := range assetProgressions {
		if assetsByKind[ap.kind] < ap.prog.minCount {
			continue
		}
		s := ap.prog.step
		s.Reason = assetProgressionReason(ap.kind, assetsByKind[ap.kind])
		add(s)
	}

	// (4) Bootstrap: acabou de rodar recon passivo e já tem subdomínios → a
	// pipeline full-recon enfileira recon ativo + scanners em paralelo.
	if isReconPassive(job.Tool) && assetsByKind["subdomain"] > 0 {
		add(NextStep{
			Type: "pipeline", Name: "full-recon",
			Reason:   "Você tem " + countStr(assetsByKind["subdomain"]) + " subdomínio(s). A pipeline full-recon enfileira recon ativo + dezenas de scanners em paralelo sobre todos eles.",
			Category: "automation", TimeMinutes: 120, Phase: "enumeração + scanning",
		})
	}

	// Fallback: nada específico casou — aponta o ponto de partida canônico.
	if len(suggestions) == 0 {
		add(NextStep{
			Type: "pipeline", Name: "full-recon",
			Reason:   "Ponto de partida: full-recon enumera subdomínios e endpoints e roda dezenas de scanners em paralelo, já respeitando o escopo do programa.",
			Category: "automation", TimeMinutes: 120, Phase: "full methodology",
		})
	}

	if len(suggestions) > 3 {
		suggestions = suggestions[:3]
	}
	return suggestions
}

func assetProgressionReason(kind string, n int) string {
	switch kind {
	case "url":
		return "Você descobriu " + countStr(n) + " URL(s). scan-xss escaneia XSS refletido nelas — vulnerabilidade clássica em endpoint público (confirma só quando os caracteres voltam sem escapar)."
	case "endpoint":
		return "Você descobriu " + countStr(n) + " endpoint(s). js-secret-hunter varre o JS deles atrás de segredos/keys expostos."
	case "port":
		return countStr(n) + " porta(s) aberta(s) detectada(s). scan-mongodb checa MongoDB sem auth nas portas 27017/27018."
	case "package":
		return countStr(n) + " dependência(s) identificada(s). scan-dep-confusion checa se algum nome está livre no registro público (build sequestrável)."
	}
	return "Assets novos do tipo " + kind + " — vale avançar a esteira."
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
	return strconv.Itoa(n)
}
