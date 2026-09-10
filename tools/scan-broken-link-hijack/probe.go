package main

import "strings"

// probeResult is what main gathered about a candidate reference's target.
type probeResult struct {
	resolves bool // the URL's host resolves in DNS
	status   int  // HTTP status of a GET to the reference URL (0 = no response)
	body     string
}

// verdict is the classifier output.
type verdict struct {
	kind     string // broken-link-hijack | dangling-dns | (empty = not vulnerable)
	severity string
	note     string
}

// decide turns a probe result into a verdict for a given hijack kind.
func decide(k hijackKind, p probeResult) (verdict, bool) {
	// A non-resolving host means the whole domain is up for grabs — strongest case.
	if !p.resolves {
		return verdict{"dangling-dns", "high",
			"o host do link não resolve (NXDOMAIN) — o domínio/subdomínio pode ser registrado por qualquer um"}, true
	}

	body := strings.ToLower(p.body)
	switch k.probe {
	case "github-user":
		if p.status == 404 {
			return verdict{"broken-link-hijack", k.sev,
				"usuário/org '" + k.target + "' não existe no GitHub — registrável, e aí o link passa a servir conteúdo do atacante"}, true
		}
	case "github-repo":
		if p.status == 404 {
			return verdict{"broken-link-hijack", "medium",
				"repositório '" + k.target + "' retorna 404 — se o dono também não existir, é registrável"}, true
		}
	case "npm":
		if p.status == 404 {
			return verdict{"broken-link-hijack", k.sev,
				"pacote npm '" + k.target + "' não existe no registro — publicável (o script no <script src> passa a ser do atacante)"}, true
		}
	case "s3":
		switch {
		case strings.Contains(p.body, "NoSuchBucket"):
			return verdict{"broken-link-hijack", k.sev,
				"bucket S3 '" + k.target + "' não existe (NoSuchBucket) — criável na mesma região"}, true
		case strings.Contains(p.body, "AllAccessDisabled"), strings.Contains(p.body, "PermanentRedirect"),
			strings.Contains(p.body, "InvalidBucketName"):
			// existe / inválido — não é hijack
		case p.status == 404:
			return verdict{"broken-link-hijack", "medium",
				"URL de bucket S3 '" + k.target + "' responde 404 sem corpo de erro claro — verifique se o bucket existe"}, true
		}
	case "fingerprint":
		if k.marker != "" && strings.Contains(body, k.marker) {
			return verdict{"broken-link-hijack", k.sev,
				k.platform + ": a resposta traz a marca de site não reclamado (\"" + k.marker + "\") — registrável no provedor"}, true
		}
	case "social":
		if p.status == 404 || strings.Contains(body, "page isn") || strings.Contains(body, "doesn't exist") ||
			strings.Contains(body, "não está disponível") || strings.Contains(body, "sorry, this page") {
			return verdict{"broken-link-hijack", k.sev,
				"handle '" + k.target + "' em " + k.platform + " não existe — registrável"}, true
		}
	}
	return verdict{}, false
}
