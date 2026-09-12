package main

import "testing"

func TestAWSMetadataConfirm(t *testing.T) {
	body := `ami-id
instance-id
local-hostname
placement/
public-keys/
security-credentials/`
	tg := ssrfTargets()[0]
	if tg.Label != "aws-metadata" {
		t.Fatalf("esperava aws-metadata primeiro, veio %s", tg.Label)
	}
	if !tg.confirm(body) {
		t.Fatal("deveria confirmar com o corpo típico do IMDS")
	}
}

func TestAWSMetadataConfirmRejectsNormalPage(t *testing.T) {
	tg := ssrfTargets()[0]
	if tg.confirm("<html><body>404 not found</body></html>") {
		t.Fatal("não deveria confirmar numa página comum")
	}
	// 1 palavra batendo por coincidência não deve bastar (precisa de >=2)
	if tg.confirm("nosso plano de instance-id é ótimo") {
		t.Fatal("1 hit isolado não deveria confirmar (exige >=2 chaves)")
	}
}

func TestStripReflectedPreventsPayloadSelfConfirm(t *testing.T) {
	// aws-metadata-iam-creds e gcp-metadata têm chaves de confirmação que
	// são, elas mesmas, substrings da URL injetada ("security-credentials",
	// "computeMetadata") — uma página que só ecoa a query string (canonical
	// link, __NEXT_DATA__, mensagem de erro citando a URL inválida) não pode
	// confirmar sozinha.
	for _, label := range []string{"aws-metadata-iam-creds", "gcp-metadata"} {
		var tg ssrfTarget
		for _, c := range ssrfTargets() {
			if c.Label == label {
				tg = c
			}
		}
		if tg.confirm == nil {
			t.Fatalf("%s sem confirm()", label)
		}
		reflected := `<link rel="canonical" href="https://app.example.com/img?src=` + tg.URL + `">`
		if tg.confirm(stripReflected(reflected, tg.URL)) {
			t.Fatalf("%s: confirmou mesmo após stripReflected — a URL ecoada não deveria bastar", label)
		}
	}
}

func TestStripReflected(t *testing.T) {
	payload := "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
	body := `<link rel="canonical" href="https://app.example.com/img?src=` + payload + `">`
	if got := stripReflected(body, payload); got == body {
		t.Fatal("stripReflected não removeu a ocorrência literal")
	}
	body2 := `<link rel="canonical" href="https://app.example.com/img?src=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam%2Fsecurity-credentials%2F">`
	if got := stripReflected(body2, payload); got == body2 {
		t.Fatal("stripReflected não removeu a ocorrência URL-encoded")
	}
}

func TestEtcPasswdConfirm(t *testing.T) {
	var fileTg ssrfTarget
	for _, tg := range ssrfTargets() {
		if tg.Label == "file-etc-passwd" {
			fileTg = tg
		}
	}
	if fileTg.confirm == nil {
		t.Fatal("file-etc-passwd sem confirm()")
	}
	if !fileTg.confirm("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n") {
		t.Fatal("deveria confirmar com um /etc/passwd real")
	}
	if fileTg.confirm("permission denied") {
		t.Fatal("não deveria confirmar sem o padrão root:...:0:0:")
	}
}

func TestLocalhostTargetsHaveNoConfirm(t *testing.T) {
	for _, tg := range ssrfTargets() {
		if tg.Label == "localhost" || tg.Label == "localhost-name" || tg.Label == "ipv6-loopback" {
			if tg.confirm != nil {
				t.Fatalf("%s não deveria ter assinatura de conteúdo — vira candidato, não finding confirmado sozinho", tg.Label)
			}
		}
	}
}

func TestBuiltinParamsNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range builtinParams {
		if seen[p] {
			t.Fatalf("parâmetro duplicado na lista embutida: %s", p)
		}
		seen[p] = true
	}
	if len(builtinParams) < 10 {
		t.Fatalf("lista embutida suspeitosamente curta: %d", len(builtinParams))
	}
}
