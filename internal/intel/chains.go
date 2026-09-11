// Chain-candidate detection: cross-references CONFIRMED findings already in
// the store to flag combinations that change category when read together —
// the same reasoning documented in prose in .claude/agents/bugbounty.md
// ("Playbook de encadeamento"), turned into deterministic code so the hub
// surfaces it without the operator having to remember to ask.
//
// This is pure read-only correlation over data the hub already collected —
// no new request is ever made, no exploitation is attempted. A chain
// candidate is a hint to go confirm manually (open the two findings, check
// if they really compose), never a claim of confirmed impact by itself —
// same PoC-only bar every scanner in this repo holds itself to.
package intel

import (
	"encoding/json"
	"strings"

	"reconhub/internal/store"
)

// ChainCandidate is one detected combination of findings that's worth more
// than the sum of its parts.
type ChainCandidate struct {
	ID          string   `json:"id"` // stable slug, matches one of the patterns below
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`    // suggested COMBINED severity, not either finding's own
	Explanation string   `json:"explanation"` // why this combination matters, what to confirm manually
	FindingIDs  []string `json:"finding_ids"`
}

// DetectChains scans findings for the known dangerous combinations from the
// bugbounty playbook. Findings are grouped by Program (never crosses
// programs, even if the caller passes a mixed set) and, within a program, by
// host — a chain only fires when its pieces sit on hosts that actually
// belong together.
func DetectChains(findings []*store.Finding) []ChainCandidate {
	byProgram := map[string][]*store.Finding{}
	for _, f := range findings {
		byProgram[f.Program] = append(byProgram[f.Program], f)
	}

	var out []ChainCandidate
	for _, fs := range byProgram {
		byHost := map[string][]*store.Finding{}
		for _, f := range fs {
			h := chainHost(f)
			byHost[h] = append(byHost[h], f)
		}
		out = append(out, detectOpenRedirectOAuth(byHost)...)
		out = append(out, detectSSRFCloudMetadata(fs)...)
		out = append(out, detectIDORCredentialLeak(fs)...)
		out = append(out, detectCORSCredentialsSensitive(byHost)...)
		out = append(out, detectTakeoverTrustsAnySubdomain(fs)...)
	}
	return out
}

// chainHost extracts a bare host from a finding's asset, falling back to its
// target — same trimming report.host() already does for the same purpose.
func chainHost(f *store.Finding) string {
	a := f.Asset
	if a == "" {
		a = f.Target
	}
	for _, p := range []string{"https://", "http://", "tcp://", "mongodb://", "gs://"} {
		a = strings.TrimPrefix(a, p)
	}
	if i := strings.IndexAny(a, "/:"); i >= 0 {
		a = a[:i]
	}
	return strings.ToLower(a)
}

func byType(fs []*store.Finding, types ...string) []*store.Finding {
	want := map[string]bool{}
	for _, t := range types {
		want[t] = true
	}
	var out []*store.Finding
	for _, f := range fs {
		if want[f.Type] {
			out = append(out, f)
		}
	}
	return out
}

func metaStr(f *store.Finding, key string) string {
	if len(f.Meta) == 0 {
		return ""
	}
	var m map[string]any
	if json.Unmarshal(f.Meta, &m) != nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

func ids(fs ...*store.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}

// detectOpenRedirectOAuth: scan-open-redirect confirmed something on the SAME
// host scan-auth-flow already proved runs an OAuth/SSO flow (any finding
// from that tool — the bypass itself, or just SAML metadata exposed, both
// mean "this host has SSO machinery"). An open redirect there is worth
// checking as the redirect_uri, not just "a redirect that goes somewhere
// external" — the playbook's own example of a "meh" finding that changes
// category combined.
func detectOpenRedirectOAuth(byHost map[string][]*store.Finding) []ChainCandidate {
	var out []ChainCandidate
	for host, fs := range byHost {
		redirects := byType(fs, "open-redirect", "open-redirect-clientside")
		if len(redirects) == 0 {
			continue
		}
		var authFlow []*store.Finding
		for _, f := range fs {
			if f.Tool == "scan-auth-flow" {
				authFlow = append(authFlow, f)
			}
		}
		if len(authFlow) == 0 {
			continue
		}
		out = append(out, ChainCandidate{
			ID:       "open-redirect-oauth",
			Title:    "Open redirect em host com fluxo OAuth/SSO — " + host,
			Severity: "high",
			Explanation: "scan-open-redirect confirmou um redirect não validado no mesmo host onde scan-auth-flow " +
				"já provou existir um fluxo OAuth/SSO. Confirme manualmente se o parâmetro do redirect é (ou pode " +
				"virar) o redirect_uri do fluxo — se for, isso deixa de ser \"só\" um open redirect e vira desvio " +
				"de redirect_uri rumo a account takeover.",
			FindingIDs: ids(append(redirects, authFlow...)...),
		})
	}
	return out
}

// detectSSRFCloudMetadata: an ssrf-confirmed finding whose injected target is
// literally a cloud metadata endpoint (meta.target from scan-ssrf's own
// target list — aws-metadata*, gcp-metadata, azure-metadata) is worth
// escalating past its own reported severity: reading the metadata endpoint
// is one hop away from stealing the instance/service-account's IAM
// credentials, not just an SSRF PoC.
func detectSSRFCloudMetadata(fs []*store.Finding) []ChainCandidate {
	var out []ChainCandidate
	for _, f := range byType(fs, "ssrf-confirmed") {
		label := strings.ToLower(metaStr(f, "target"))
		if !strings.Contains(label, "metadata") {
			continue
		}
		out = append(out, ChainCandidate{
			ID:       "ssrf-cloud-metadata",
			Title:    "SSRF confirmado no endpoint de metadata cloud — " + chainHost(f),
			Severity: "critical",
			Explanation: "O SSRF confirmado apontou pro endpoint de metadata do provedor cloud (169.254.169.254), " +
				"não só um recurso interno qualquer. Confirme se dá pra ler credencial de IAM/service account a " +
				"partir daqui (ex: /latest/meta-data/iam/security-credentials/ na AWS) — isso é roubo de credencial " +
				"cloud, não só leitura de recurso interno.",
			FindingIDs: ids(f),
		})
	}
	return out
}

// sensitiveURLWords are keywords that, in a URL path/query touched by an
// IDOR, suggest the horizontally-leaked resource is a credential rather than
// plain personal data — scan-idor deliberately never stores the response
// body (see CLAUDE.md), so this is a heuristic off the URL alone, never a
// confirmation. Flag it, don't claim it.
var sensitiveURLWords = []string{
	"token", "apikey", "api_key", "api-key", "secret", "password", "passwd",
	"credential", "session", "sessionid", "auth", "privatekey", "private_key",
}

// detectIDORCredentialLeak: an idor-horizontal finding whose URL suggests the
// leaked resource is a credential, not plain personal data — the playbook's
// distinction between "vazamento de dado" (medium) and "takeover de conta"
// (critical).
func detectIDORCredentialLeak(fs []*store.Finding) []ChainCandidate {
	var out []ChainCandidate
	for _, f := range byType(fs, "idor-horizontal") {
		low := strings.ToLower(f.Asset)
		for _, w := range sensitiveURLWords {
			if !strings.Contains(low, w) {
				continue
			}
			out = append(out, ChainCandidate{
				ID:       "idor-credential-leak",
				Title:    "IDOR num endpoint com nome sugestivo de credencial — " + chainHost(f),
				Severity: "critical",
				Explanation: "O IDOR horizontal confirmado é num endpoint cuja URL sugere credencial (\"" + w + "\"), " +
					"não dado pessoal comum. scan-idor nunca guarda o corpo da resposta (só status+tamanho) — abra " +
					"a URL com a sessão cruzada e confirme manualmente o que vem no corpo. Se for token/chave de " +
					"verdade, isso é account takeover, não vazamento de dado — mude a severidade na triagem.",
				FindingIDs: ids(f),
			})
			break
		}
	}
	return out
}

// detectCORSCredentialsSensitive: a CORS finding that reflects the origin
// (or wildcards it) WITH credentials on a host that also confirmedly serves
// sensitive data (idor-horizontal or a GraphQL sensitive field) — the
// playbook's "não é só um header errado" case, where the two together prove
// a concrete exfiltration path via a malicious third-party site.
func detectCORSCredentialsSensitive(byHost map[string][]*store.Finding) []ChainCandidate {
	var out []ChainCandidate
	for host, fs := range byHost {
		creds := byType(fs, "cors-reflect-credentials", "cors-wildcard-credentials")
		if len(creds) == 0 {
			continue
		}
		sensitive := byType(fs, "idor-horizontal", "graphql-sensitive-field")
		if len(sensitive) == 0 {
			continue
		}
		out = append(out, ChainCandidate{
			ID:       "cors-credentials-sensitive-data",
			Title:    "CORS com credentials + endpoint sensível confirmado — " + host,
			Severity: "critical",
			Explanation: "O mesmo host tem CORS refletindo origem (ou wildcard) com Access-Control-Allow-Credentials: " +
				"true E um endpoint confirmado devolvendo dado sensível (IDOR ou campo GraphQL sensível). Combinados, " +
				"isso é um caminho concreto de exfiltração via site malicioso de terceiro — o PoC de reprodução " +
				"precisa mostrar as DUAS pontas juntas (origem maliciosa + o dado sendo lido), não cada achado " +
				"isolado.",
			FindingIDs: ids(append(creds, sensitive...)...),
		})
	}
	return out
}

// takeoverBroadCORSMarkers are the exact "how" labels scan-cors uses (see
// tools/scan-cors/cors.go testOrigins) for the two probes that test "does
// this app trust ANY subdomain of the registrable domain", embedded in the
// evidence text scan-cors emits. If one of these fired, the app's CORS check
// isn't pinned to a specific origin — it trusts the whole subdomain family.
var takeoverBroadCORSMarkers = []string{"subdomínio arbitrário", "qualquer subdomínio"}

// detectTakeoverTrustsAnySubdomain: a subdomain-takeover/dangling-cname
// finding in a program where scan-cors ALSO proved some host trusts any
// subdomain of the registrable domain as a valid CORS origin — taking over
// the dangling subdomain doesn't just give you that one host, it gives you a
// CORS-trusted origin against whatever else the app protects with that
// broad check.
func detectTakeoverTrustsAnySubdomain(fs []*store.Finding) []ChainCandidate {
	takeovers := byType(fs, "subdomain-takeover", "dangling-cname")
	if len(takeovers) == 0 {
		return nil
	}
	var broadCORS []*store.Finding
	for _, f := range fs {
		if !strings.HasPrefix(f.Type, "cors-") {
			continue
		}
		for _, marker := range takeoverBroadCORSMarkers {
			if strings.Contains(f.Evidence, marker) {
				broadCORS = append(broadCORS, f)
				break
			}
		}
	}
	if len(broadCORS) == 0 {
		return nil
	}
	var out []ChainCandidate
	for _, t := range takeovers {
		out = append(out, ChainCandidate{
			ID:       "takeover-trusted-cors-origin",
			Title:    "Subdomain takeover vira origem CORS confiável — " + chainHost(t),
			Severity: "critical",
			Explanation: "Esse subdomínio órfão é sequestrável (CNAME dangling), E scan-cors já provou que outro " +
				"host desse mesmo programa aceita QUALQUER subdomínio do domínio registrável como origem CORS " +
				"válida (bypass de regex confirmado). Sequestrar esse subdomínio não fica isolado nele: vira uma " +
				"origem CORS confiável contra o resto da aplicação — sequestra a confiança do domínio principal, " +
				"não só o subdomínio órfão.",
			FindingIDs: ids(append(append([]*store.Finding{}, t), broadCORS...)...),
		})
	}
	return out
}
