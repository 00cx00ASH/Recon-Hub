package main

import "strings"

// looksLikeSAMLMetadata: assinatura mínima de um documento de metadata SAML
// de verdade — evita reportar "achou SAML" quando o caminho só devolveu uma
// página de erro 200 genérica (soft-404), algo comum o bastante pra valer
// essa checagem antes de emitir o asset.
func looksLikeSAMLMetadata(body string) bool {
	b := strings.ToLower(body)
	return strings.Contains(b, "entitydescriptor") &&
		(strings.Contains(b, "urn:oasis:names:tc:saml") || strings.Contains(b, "idpssodescriptor") || strings.Contains(b, "spssodescriptor"))
}
