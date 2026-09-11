package intel

import (
	"testing"

	"reconhub/internal/store"
)

func hasChain(chains []ChainCandidate, id string) bool {
	for _, c := range chains {
		if c.ID == id {
			return true
		}
	}
	return false
}

func TestDetectChainsOpenRedirectOAuth(t *testing.T) {
	fs := []*store.Finding{
		{ID: "1", Program: "acme", Tool: "scan-open-redirect", Type: "open-redirect", Asset: "https://login.acme.com/go?next=x"},
		{ID: "2", Program: "acme", Tool: "scan-auth-flow", Type: "oauth-redirect-uri-bypass", Asset: "https://login.acme.com/authorize"},
	}
	chains := DetectChains(fs)
	if !hasChain(chains, "open-redirect-oauth") {
		t.Fatalf("esperava chain open-redirect-oauth, veio %+v", chains)
	}
}

func TestDetectChainsOpenRedirectOAuthDifferentHostNoChain(t *testing.T) {
	fs := []*store.Finding{
		{ID: "1", Program: "acme", Tool: "scan-open-redirect", Type: "open-redirect", Asset: "https://www.acme.com/go?next=x"},
		{ID: "2", Program: "acme", Tool: "scan-auth-flow", Type: "oauth-redirect-uri-bypass", Asset: "https://login.acme.com/authorize"},
	}
	chains := DetectChains(fs)
	if hasChain(chains, "open-redirect-oauth") {
		t.Fatal("hosts diferentes não deveriam disparar a chain")
	}
}

func TestDetectChainsSSRFCloudMetadata(t *testing.T) {
	fs := []*store.Finding{
		{ID: "1", Program: "acme", Tool: "scan-ssrf", Type: "ssrf-confirmed", Asset: "https://api.acme.com/fetch?url=x",
			Meta: []byte(`{"target":"aws-metadata-iam-creds"}`)},
	}
	chains := DetectChains(fs)
	if !hasChain(chains, "ssrf-cloud-metadata") {
		t.Fatalf("esperava chain ssrf-cloud-metadata, veio %+v", chains)
	}
}

func TestDetectChainsSSRFNonMetadataNoChain(t *testing.T) {
	fs := []*store.Finding{
		{ID: "1", Program: "acme", Tool: "scan-ssrf", Type: "ssrf-confirmed", Asset: "https://api.acme.com/fetch?url=x",
			Meta: []byte(`{"target":"internal-service"}`)},
	}
	chains := DetectChains(fs)
	if hasChain(chains, "ssrf-cloud-metadata") {
		t.Fatal("alvo não-metadata não deveria disparar a chain")
	}
}

func TestDetectChainsIDORCredentialLeak(t *testing.T) {
	fs := []*store.Finding{
		{ID: "1", Program: "acme", Tool: "scan-idor", Type: "idor-horizontal", Asset: "https://api.acme.com/users/42/api_key"},
	}
	chains := DetectChains(fs)
	if !hasChain(chains, "idor-credential-leak") {
		t.Fatalf("esperava chain idor-credential-leak, veio %+v", chains)
	}
}

func TestDetectChainsIDORPlainDataNoChain(t *testing.T) {
	fs := []*store.Finding{
		{ID: "1", Program: "acme", Tool: "scan-idor", Type: "idor-horizontal", Asset: "https://api.acme.com/users/42/profile"},
	}
	chains := DetectChains(fs)
	if hasChain(chains, "idor-credential-leak") {
		t.Fatal("URL sem palavra sensível não deveria disparar a chain")
	}
}

func TestDetectChainsCORSCredentialsSensitive(t *testing.T) {
	fs := []*store.Finding{
		{ID: "1", Program: "acme", Tool: "scan-cors", Type: "cors-reflect-credentials", Asset: "https://api.acme.com/data"},
		{ID: "2", Program: "acme", Tool: "scan-idor", Type: "idor-horizontal", Asset: "https://api.acme.com/users/42"},
	}
	chains := DetectChains(fs)
	if !hasChain(chains, "cors-credentials-sensitive-data") {
		t.Fatalf("esperava chain cors-credentials-sensitive-data, veio %+v", chains)
	}
}

func TestDetectChainsCORSWithoutCredentialsNoChain(t *testing.T) {
	fs := []*store.Finding{
		{ID: "1", Program: "acme", Tool: "scan-cors", Type: "cors-wildcard", Asset: "https://api.acme.com/data"},
		{ID: "2", Program: "acme", Tool: "scan-idor", Type: "idor-horizontal", Asset: "https://api.acme.com/users/42"},
	}
	chains := DetectChains(fs)
	if hasChain(chains, "cors-credentials-sensitive-data") {
		t.Fatal("cors-wildcard sem credentials não deveria disparar a chain")
	}
}

func TestDetectChainsTakeoverTrustsAnySubdomain(t *testing.T) {
	fs := []*store.Finding{
		{ID: "1", Program: "acme", Tool: "scan-subdomain-takeover", Type: "subdomain-takeover", Asset: "https://old.acme.com"},
		{ID: "2", Program: "acme", Tool: "scan-cors", Type: "cors-reflect-origin", Asset: "https://app.acme.com",
			Evidence: "Origin: https://attacker.acme.com (qualquer subdomínio (attacker.<reg>)) → ACAO: \"https://attacker.acme.com\""},
	}
	chains := DetectChains(fs)
	if !hasChain(chains, "takeover-trusted-cors-origin") {
		t.Fatalf("esperava chain takeover-trusted-cors-origin, veio %+v", chains)
	}
}

func TestDetectChainsTakeoverWithoutBroadCORSNoChain(t *testing.T) {
	fs := []*store.Finding{
		{ID: "1", Program: "acme", Tool: "scan-subdomain-takeover", Type: "subdomain-takeover", Asset: "https://old.acme.com"},
		{ID: "2", Program: "acme", Tool: "scan-cors", Type: "cors-reflect-origin", Asset: "https://app.acme.com",
			Evidence: "Origin: https://evil.example (origem totalmente estranha) → ACAO: \"https://evil.example\""},
	}
	chains := DetectChains(fs)
	if hasChain(chains, "takeover-trusted-cors-origin") {
		t.Fatal("cors sem o bypass de subdomínio amplo não deveria disparar a chain")
	}
}

func TestDetectChainsNeverCrossesPrograms(t *testing.T) {
	fs := []*store.Finding{
		{ID: "1", Program: "acme", Tool: "scan-open-redirect", Type: "open-redirect", Asset: "https://login.shared.com/go"},
		{ID: "2", Program: "other", Tool: "scan-auth-flow", Type: "oauth-redirect-uri-bypass", Asset: "https://login.shared.com/authorize"},
	}
	chains := DetectChains(fs)
	if hasChain(chains, "open-redirect-oauth") {
		t.Fatal("achados de programas diferentes nunca deveriam combinar, mesmo com o mesmo host")
	}
}

func TestDetectChainsEmptyInput(t *testing.T) {
	if chains := DetectChains(nil); len(chains) != 0 {
		t.Fatalf("esperava nenhuma chain pra input vazio, veio %+v", chains)
	}
}
