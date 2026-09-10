// Package copilot answers "what should I run next on this program?" — a
// coverage/gap view, not a model. It keeps a static table of which tool
// applies to which discovered asset kind, diffs that against the program's
// job history, and reports every applicable tool nobody has run yet. The
// same computation doubles as a coverage matrix (done vs missing) for the
// dashboard.
package copilot

import (
	"sort"

	"reconhub/internal/registry"
	"reconhub/internal/store"
)

// toolInputKinds maps a tool name to the asset kinds it can be pointed at.
// "program" is a pseudo-kind meaning "needs only the program's own target
// (e.g. the root domain), not a previously discovered asset" — it's what
// unlocks the recon-* tools that start the whole chain, so it's always
// considered present once a program exists.
var toolInputKinds = map[string][]string{
	"recon-passive-enum": {"program"},
	"recon-crtsh":        {"program"},
	"recon-web-enum":     {"program", "subdomain", "url"},
	"recon-infra-enum":   {"program", "subdomain"},

	"scan-subdomain-takeover": {"subdomain"},
	"scan-fuzz":               {"subdomain", "url"},
	"scan-cors":               {"url"},
	"scan-actuator":           {"subdomain", "url"},
	"scan-graphql":            {"subdomain", "url"},
	"scan-open-redirect":      {"url"},
	"scan-cache-poisoning":    {"url"},
	"scan-broken-link-hijack": {"subdomain", "url"},
	"scan-cognito":            {"subdomain", "url"},
	"scan-mongodb":            {"port"},

	"js-secret-hunter":  {"subdomain", "url"},
	"js-ai-key-hunter":  {"subdomain", "url"},
	"js-bucket-scanner": {"subdomain", "url"},
	"js-firebase-enum":  {"subdomain", "url"},
	"js-supabase-probe": {"subdomain", "url"},
	"js-gtm-osint":      {"subdomain", "url"},
	"js-hunter":         {"subdomain", "url"},
	"js-jwt-finder":     {"subdomain", "url"},

	// scan-dep-confusion (precisa de manifesto colado), scan-postman-audit
	// (precisa do id de uma collection específica) e int-github-audit (alvo
	// é login/repo do GitHub) não têm um asset do programa que os destrave
	// automaticamente — ficam de fora do mapa de propósito.
}

// Suggestion is one applicable-but-unused tool for a program.
type Suggestion struct {
	Tool     string   `json:"tool"`
	Kind     string   `json:"kind"` // qual kind de asset (ou "program") destravou isso
	Reason   string   `json:"reason"`
	Examples []string `json:"examples,omitempty"` // até 5 valores de exemplo pra usar como alvo
}

// Coverage is the done/missing view for one program.
type Coverage struct {
	Program     string       `json:"program"`
	Ran         []string     `json:"ran"`     // ferramentas já rodadas nesse programa (qualquer resultado)
	Suggestions []Suggestion `json:"missing"` // aplicáveis pelo que já foi descoberto, nunca rodadas
}

// Compute builds the coverage/suggestion view for a program from its job and
// asset history. reg, when set, filters out suggestions for tools that
// aren't actually registered on this hub — a suggestion for something not
// installed would just be noise.
func Compute(program string, jobs []*store.Job, assets []*store.Asset, reg *registry.Registry) Coverage {
	ran := map[string]bool{}
	for _, j := range jobs {
		ran[j.Tool] = true
	}

	kindPresent := map[string]bool{"program": true}
	kindExamples := map[string][]string{}
	for _, a := range assets {
		kindPresent[a.Kind] = true
		exs := kindExamples[a.Kind]
		if len(exs) >= 5 {
			continue
		}
		dup := false
		for _, e := range exs {
			if e == a.Value {
				dup = true
				break
			}
		}
		if !dup {
			kindExamples[a.Kind] = append(exs, a.Value)
		}
	}

	ranList := make([]string, 0, len(ran))
	for t := range ran {
		ranList = append(ranList, t)
	}
	sort.Strings(ranList)

	var out []Suggestion
	for tool, kinds := range toolInputKinds {
		if ran[tool] {
			continue
		}
		if reg != nil {
			if _, ok := reg.Get(tool); !ok {
				continue
			}
		}
		for _, k := range kinds {
			if kindPresent[k] {
				out = append(out, Suggestion{
					Tool: tool, Kind: k, Examples: kindExamples[k],
					Reason: reasonFor(k),
				})
				break // um motivo já basta, mesmo que mais de um kind aplique
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })

	return Coverage{Program: program, Ran: ranList, Suggestions: out}
}

func reasonFor(kind string) string {
	if kind == "program" {
		return "ainda não rodou — bom primeiro passo pra esse programa"
	}
	return "você já tem " + kind + "(s) descoberto(s) e ainda não rodou essa"
}
