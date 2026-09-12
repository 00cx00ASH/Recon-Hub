package guidance

import (
	"testing"

	"reconhub/internal/intel"
	"reconhub/internal/store"
)

// TestFindingConfirmationKeysAreKnown é a rede de segurança contra o bug que
// existia aqui: chaves de finding_type inventadas ("xss", "sql_injection",
// "auth_flow") que nenhuma tool emite, então a condição nunca disparava.
// Toda chave de findingConfirmations tem que ser um tipo que o hub reconhece.
func TestFindingConfirmationKeysAreKnown(t *testing.T) {
	for ftype := range findingConfirmations {
		if !intel.IsKnownType(ftype) {
			t.Errorf("findingConfirmations usa finding_type %q que NÃO existe em intel.knownRisk — chave inventada não casa com o que as tools emitem", ftype)
		}
	}
}

func suggest(job string, findings []*store.Finding, assets []*store.Asset) []NextStep {
	return SuggestNextSteps(&store.Job{Tool: job}, findings, assets)
}

func hasTool(steps []NextStep, name string) bool {
	for _, s := range steps {
		if s.Name == name {
			return true
		}
	}
	return false
}

func TestReflectedXSSSuggestsDomConfirmation(t *testing.T) {
	steps := suggest("scan-xss",
		[]*store.Finding{{Type: "reflected-xss", Tool: "scan-xss"}}, nil)
	if !hasTool(steps, "scan-xss-dom") {
		t.Fatalf("reflected-xss deveria sugerir scan-xss-dom; veio %+v", steps)
	}
}

func TestSecretSuggestsGithubAudit(t *testing.T) {
	steps := suggest("js-secret-hunter",
		[]*store.Finding{{Type: "secret", Tool: "js-secret-hunter"}}, nil)
	if !hasTool(steps, "int-github-audit") {
		t.Fatalf("secret deveria sugerir int-github-audit; veio %+v", steps)
	}
}

func TestAssetProgressionUrlSuggestsXss(t *testing.T) {
	assets := []*store.Asset{
		{Kind: "url", Value: "https://a.com/1"},
		{Kind: "url", Value: "https://a.com/2"},
		{Kind: "url", Value: "https://a.com/3"},
		{Kind: "url", Value: "https://a.com/4"},
	}
	steps := suggest("recon-web-enum", nil, assets)
	if !hasTool(steps, "scan-xss") {
		t.Fatalf("4 URLs deveriam sugerir scan-xss; veio %+v", steps)
	}
}

func TestChainsPrioritizedFirst(t *testing.T) {
	// open-redirect + oauth-redirect-uri-bypass formam uma cadeia conhecida.
	findings := []*store.Finding{
		{ID: "f1", Type: "open-redirect", Tool: "scan-open-redirect", Asset: "https://login.acme.com/go?next=x"},
		{ID: "f2", Type: "oauth-redirect-uri-bypass", Tool: "scan-auth-flow", Asset: "https://login.acme.com/authorize"},
	}
	steps := suggest("scan-auth-flow", findings, nil)
	if len(steps) == 0 || steps[0].Type != "chain" {
		t.Fatalf("cadeia deveria ser a 1ª sugestão; veio %+v", steps)
	}
}

func TestDoesNotSuggestAlreadyRunTool(t *testing.T) {
	// Se o próprio job foi scan-xss-dom, não faz sentido sugerir scan-xss-dom.
	steps := suggest("scan-xss-dom",
		[]*store.Finding{{Type: "reflected-xss", Tool: "scan-xss-dom"}}, nil)
	if hasTool(steps, "scan-xss-dom") {
		t.Fatalf("não deveria sugerir a tool que já rodou (scan-xss-dom); veio %+v", steps)
	}
}

func TestFallbackWhenNothingMatches(t *testing.T) {
	steps := suggest("scan-cors", nil, nil)
	if len(steps) != 1 || steps[0].Name != "full-recon" {
		t.Fatalf("sem sinais, fallback deveria ser full-recon; veio %+v", steps)
	}
}

func TestPassiveReconWithSubdomainsSuggestsFullRecon(t *testing.T) {
	assets := []*store.Asset{{Kind: "subdomain", Value: "a.acme.com"}}
	steps := suggest("recon-passive-enum", nil, assets)
	if !hasTool(steps, "full-recon") {
		t.Fatalf("recon passivo + subdomínios deveria sugerir full-recon; veio %+v", steps)
	}
}

func TestCapsAtThreeSuggestions(t *testing.T) {
	findings := []*store.Finding{
		{ID: "f1", Type: "open-redirect", Tool: "scan-open-redirect", Asset: "https://login.acme.com/go?next=x"},
		{ID: "f2", Type: "oauth-redirect-uri-bypass", Tool: "scan-auth-flow", Asset: "https://login.acme.com/authorize"},
		{Type: "reflected-xss", Tool: "scan-xss"},
		{Type: "secret", Tool: "js-secret-hunter"},
	}
	assets := []*store.Asset{
		{Kind: "url", Value: "https://a.com/1"}, {Kind: "url", Value: "https://a.com/2"},
		{Kind: "url", Value: "https://a.com/3"}, {Kind: "url", Value: "https://a.com/4"},
		{Kind: "port", Value: "a.com:27017"},
	}
	steps := suggest("recon-web-enum", findings, assets)
	if len(steps) > 3 {
		t.Fatalf("deveria limitar a 3 sugestões; veio %d: %+v", len(steps), steps)
	}
}
