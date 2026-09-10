package main

import (
	"regexp"
	"strings"
)

// ids holds the Cognito identifiers scraped from a page/bundle.
type ids struct {
	Region          string
	UserPoolID      string   // <region>_<alnum>
	IdentityPoolID  string   // <region>:<uuid>
	AppClientIDs    []string // 26-char client ids
	IdentityRegions []string // regions seen for cognito-identity
	UserPoolRegions []string // regions seen for cognito-idp
}

func (i ids) empty() bool {
	return i.UserPoolID == "" && i.IdentityPoolID == "" && len(i.AppClientIDs) == 0
}

var (
	reUserPoolID   = regexp.MustCompile(`\b([a-z]{2}-[a-z]+-\d)_([A-Za-z0-9]{6,})\b`)
	reIdentityPool = regexp.MustCompile(`\b([a-z]{2}-[a-z]+-\d):([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`)
	reIdpHost      = regexp.MustCompile(`cognito-idp\.([a-z]{2}-[a-z]+-\d)\.amazonaws\.com`)
	reIdentityHost = regexp.MustCompile(`cognito-identity\.([a-z]{2}-[a-z]+-\d)\.amazonaws\.com`)
	// amplify aws-exports keys
	reAmplifyIdentity = regexp.MustCompile(`(?i)(?:aws_cognito_identity_pool_id|identityPoolId)["'\s:=]+["']([a-z]{2}-[a-z]+-\d:[0-9a-f-]{36})["']`)
	reAmplifyUserPool = regexp.MustCompile(`(?i)(?:aws_user_pools_id|userPoolId)["'\s:=]+["']([a-z]{2}-[a-z]+-\d_[A-Za-z0-9]{6,})["']`)
	reAmplifyClient   = regexp.MustCompile(`(?i)(?:aws_user_pools_web_client_id|userPoolWebClientId|clientId|ClientId)["'\s:=]+["']([a-z0-9]{26})["']`)
)

// extractIdentifiers scrapes Cognito identifiers from source text.
func extractIdentifiers(body string) ids {
	var out ids

	if m := reAmplifyUserPool.FindStringSubmatch(body); m != nil {
		out.UserPoolID = m[1]
	} else if m := reUserPoolID.FindStringSubmatch(body); m != nil {
		out.UserPoolID = m[1] + "_" + m[2]
	}
	if m := reAmplifyIdentity.FindStringSubmatch(body); m != nil {
		out.IdentityPoolID = m[1]
	} else if m := reIdentityPool.FindStringSubmatch(body); m != nil {
		out.IdentityPoolID = m[1] + ":" + m[2]
	}

	seenC := map[string]bool{}
	for _, m := range reAmplifyClient.FindAllStringSubmatch(body, -1) {
		if !seenC[m[1]] {
			seenC[m[1]] = true
			out.AppClientIDs = append(out.AppClientIDs, m[1])
		}
	}

	for _, m := range reIdpHost.FindAllStringSubmatch(body, -1) {
		out.UserPoolRegions = appendUniq(out.UserPoolRegions, m[1])
	}
	for _, m := range reIdentityHost.FindAllStringSubmatch(body, -1) {
		out.IdentityRegions = appendUniq(out.IdentityRegions, m[1])
	}

	// region: prefer the one embedded in a pool id
	switch {
	case out.UserPoolID != "":
		out.Region = strings.SplitN(out.UserPoolID, "_", 2)[0]
	case out.IdentityPoolID != "":
		out.Region = strings.SplitN(out.IdentityPoolID, ":", 2)[0]
	case len(out.UserPoolRegions) > 0:
		out.Region = out.UserPoolRegions[0]
	case len(out.IdentityRegions) > 0:
		out.Region = out.IdentityRegions[0]
	}
	return out
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

// regionOf returns the region prefix of a pool id (user or identity).
func regionOf(poolID string) string {
	if i := strings.IndexAny(poolID, "_:"); i > 0 {
		return poolID[:i]
	}
	return ""
}

// --- response classification (cognito-identity JSON API) ---

type idpVerdict struct {
	kind string // open-identity-getid | identity-getid-denied | identity-absent | unknown
	note string
}

func classifyGetId(status int, body string) idpVerdict {
	low := strings.ToLower(body)
	switch {
	case status == 200 && strings.Contains(body, "IdentityId"):
		return idpVerdict{"open-identity-getid", "GetId anônimo retornou um IdentityId — o Identity Pool aceita acesso não autenticado"}
	case strings.Contains(low, "resourcenotfound"):
		return idpVerdict{"identity-absent", "Identity Pool não existe"}
	case strings.Contains(low, "notauthorized"):
		return idpVerdict{"identity-getid-denied", "GetId negado — acesso não autenticado desativado (bom)"}
	case strings.Contains(low, "invalididentitypool"):
		return idpVerdict{"identity-absent", "IdentityPoolId inválido"}
	default:
		return idpVerdict{"unknown", strings.TrimSpace(firstLine(body))}
	}
}

type credsVerdict struct {
	kind string // open-identity-credentials | credentials-denied | no-unauth-role | unknown
	akid string
	note string
}

func classifyGetCreds(status int, body string) credsVerdict {
	low := strings.ToLower(body)
	switch {
	case status == 200 && strings.Contains(body, "SecretKey"):
		return credsVerdict{"open-identity-credentials", extractAKID(body),
			"GetCredentialsForIdentity anônimo retornou credenciais AWS temporárias"}
	case strings.Contains(low, "notauthorized"), strings.Contains(low, "access to identity") && strings.Contains(low, "forbidden"):
		return credsVerdict{"credentials-denied", "", "credenciais negadas"}
	case strings.Contains(low, "invalididentitypoolconfiguration"), strings.Contains(low, "unauthenticated identities"):
		return credsVerdict{"no-unauth-role", "", "pool sem role para identidades não autenticadas (bom)"}
	default:
		return credsVerdict{"unknown", "", strings.TrimSpace(firstLine(body))}
	}
}

var reAKID = regexp.MustCompile(`"AccessKeyId"\s*:\s*"(ASIA[A-Z0-9]{16})"`)

func extractAKID(body string) string {
	if m := reAKID.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	if len(s) > 200 {
		return s[:200]
	}
	return s
}
