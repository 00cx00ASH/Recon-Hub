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
	loopbackLabels := map[string]bool{
		"localhost": true, "localhost-name": true, "ipv6-loopback": true,
		"localhost-decimal": true, "localhost-hex": true,
	}
	for _, tg := range ssrfTargets() {
		if loopbackLabels[tg.Label] && tg.confirm != nil {
			t.Fatalf("%s não deveria ter assinatura de conteúdo — vira candidato, não finding confirmado sozinho", tg.Label)
		}
	}
}

func TestNewCloudMetadataTargetsHaveConfirm(t *testing.T) {
	want := map[string]bool{"alibaba-metadata": true, "oci-metadata": true, "k8s-api-server": true}
	found := map[string]bool{}
	for _, tg := range ssrfTargets() {
		if want[tg.Label] {
			found[tg.Label] = true
			if tg.confirm == nil {
				t.Errorf("%s deveria ter confirm() — tem assinatura de conteúdo conhecida", tg.Label)
			}
			if tg.Sev != "critical" {
				t.Errorf("%s deveria ser critical (metadata/API de cluster), veio %s", tg.Label, tg.Sev)
			}
		}
	}
	for label := range want {
		if !found[label] {
			t.Errorf("faltou o alvo %q", label)
		}
	}
}

func TestAlibabaMetadataConfirm(t *testing.T) {
	var tg ssrfTarget
	for _, t2 := range ssrfTargets() {
		if t2.Label == "alibaba-metadata" {
			tg = t2
		}
	}
	body := "dsn-id\nhostname\nimage-id\ninstance-id\nowner-account-id\nregion-id\nserial-number\n"
	if !tg.confirm(body) {
		t.Fatal("deveria confirmar com o corpo típico do metadata da Alibaba Cloud")
	}
	if tg.confirm("<html><body>404 not found</body></html>") {
		t.Fatal("não deveria confirmar numa página comum")
	}
}

func TestOCIMetadataConfirm(t *testing.T) {
	var tg ssrfTarget
	for _, t2 := range ssrfTargets() {
		if t2.Label == "oci-metadata" {
			tg = t2
		}
	}
	body := `{"availabilityDomain":"AD-1","compartmentId":"ocid1.compartment.oc1..x","displayName":"instance1"}`
	if !tg.confirm(body) {
		t.Fatal("deveria confirmar com o corpo típico do metadata da OCI")
	}
	if tg.confirm("<html><body>404 not found</body></html>") {
		t.Fatal("não deveria confirmar numa página comum")
	}
}

func TestK8sAPIServerConfirm(t *testing.T) {
	var tg ssrfTarget
	for _, t2 := range ssrfTargets() {
		if t2.Label == "k8s-api-server" {
			tg = t2
		}
	}
	body := `{"kind":"Status","apiVersion":"v1","status":"Failure","message":"forbidden: User \"system:anonymous\" cannot get path \"/version\""}`
	if !tg.confirm(body) {
		t.Fatal("deveria confirmar com o JSON de erro típico do API server sem token")
	}
	if tg.confirm("<html><body>404 not found</body></html>") {
		t.Fatal("não deveria confirmar numa página comum")
	}
}

// TestConfirmNeverTriggersOnReflectedURLAlone é o teste de regressão pro bug
// real achado em triagem: aws-metadata-iam-creds usava "security-credentials"
// como assinatura, mas essa string faz parte da PRÓPRIA URL injetada
// (.../iam/security-credentials/) — qualquer página que ecoe a URL/query
// nula parte (canonical tag, mensagem de erro "invalid request: <url>")
// confirmava sozinha, sem o servidor nunca ter buscado o recurso de verdade.
func TestConfirmNeverTriggersOnReflectedURLAlone(t *testing.T) {
	for _, tg := range ssrfTargets() {
		if tg.confirm == nil {
			continue
		}
		reflectedOnly := `<html><head><link rel="canonical" href="` + tg.URL + `"></head>` +
			`<body>invalid request: ` + tg.URL + `</body></html>`
		if tg.confirm(reflectedOnly) {
			t.Errorf("target %q confirma com um corpo que só reflete a URL injetada de volta (%q) — "+
				"isso é falso positivo garantido em qualquer página que ecoe o parâmetro/query string, "+
				"sem o servidor jamais ter buscado o recurso interno", tg.Label, tg.URL)
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
