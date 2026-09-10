package main

import "testing"

func TestLooksLikeSAMLMetadata(t *testing.T) {
	real := `<?xml version="1.0"?><md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.test"><md:IDPSSODescriptor>...</md:IDPSSODescriptor></md:EntityDescriptor>`
	if !looksLikeSAMLMetadata(real) {
		t.Fatal("deveria reconhecer um EntityDescriptor real")
	}
	if looksLikeSAMLMetadata("<html><body>404 not found</body></html>") {
		t.Fatal("não deveria confirmar numa página de erro genérica")
	}
	if looksLikeSAMLMetadata("essa página até menciona EntityDescriptor mas não é XML de verdade") {
		t.Fatal("uma menção solta à palavra não deveria bastar sem os outros marcadores")
	}
}
