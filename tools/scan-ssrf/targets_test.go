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
