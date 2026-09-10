package copilot

import (
	"testing"

	"reconhub/internal/store"
)

func TestComputeFreshProgramSuggestsRecon(t *testing.T) {
	cov := Compute("acme", nil, nil, nil)
	if len(cov.Ran) != 0 {
		t.Fatalf("Ran = %v, quer vazio", cov.Ran)
	}
	found := map[string]bool{}
	for _, s := range cov.Suggestions {
		found[s.Tool] = true
		if s.Kind != "program" {
			t.Errorf("%s: kind = %q, num programa novo só deveria vir 'program'", s.Tool, s.Kind)
		}
	}
	for _, want := range []string{"recon-passive-enum", "recon-crtsh", "recon-web-enum", "recon-infra-enum"} {
		if !found[want] {
			t.Errorf("faltou sugerir %s pra um programa recém-criado", want)
		}
	}
	// nada que dependa de subdomain/url deveria aparecer ainda
	for _, notWant := range []string{"scan-fuzz", "js-secret-hunter", "scan-subdomain-takeover"} {
		if found[notWant] {
			t.Errorf("%s não deveria ser sugerido sem nenhum asset descoberto", notWant)
		}
	}
}

func TestComputeSubdomainUnlocksScanTools(t *testing.T) {
	assets := []*store.Asset{
		{Kind: "subdomain", Value: "api.acme.com"},
		{Kind: "subdomain", Value: "www.acme.com"},
	}
	cov := Compute("acme", nil, assets, nil)
	byTool := map[string]Suggestion{}
	for _, s := range cov.Suggestions {
		byTool[s.Tool] = s
	}
	if s, ok := byTool["scan-fuzz"]; !ok || s.Kind != "subdomain" {
		t.Fatalf("scan-fuzz deveria ser sugerido por subdomain: %+v (ok=%v)", s, ok)
	}
	if len(byTool["scan-fuzz"].Examples) != 2 {
		t.Errorf("examples = %v, quer os 2 subdomínios", byTool["scan-fuzz"].Examples)
	}
	if _, ok := byTool["scan-mongodb"]; ok {
		t.Error("scan-mongodb precisa de kind=port, não deveria aparecer só com subdomain")
	}
}

func TestComputeAlreadyRanIsExcluded(t *testing.T) {
	jobs := []*store.Job{{Tool: "recon-crtsh"}, {Tool: "scan-fuzz"}}
	assets := []*store.Asset{{Kind: "subdomain", Value: "api.acme.com"}}
	cov := Compute("acme", jobs, assets, nil)
	if len(cov.Ran) != 2 {
		t.Fatalf("Ran = %v", cov.Ran)
	}
	for _, s := range cov.Suggestions {
		if s.Tool == "recon-crtsh" || s.Tool == "scan-fuzz" {
			t.Errorf("%s já rodou — não deveria estar em Suggestions", s.Tool)
		}
	}
	// recon-passive-enum ainda não rodou, continua sugerido
	found := false
	for _, s := range cov.Suggestions {
		if s.Tool == "recon-passive-enum" {
			found = true
		}
	}
	if !found {
		t.Error("recon-passive-enum não rodou ainda, deveria seguir sugerido")
	}
}

func TestComputePortUnlocksMongo(t *testing.T) {
	assets := []*store.Asset{{Kind: "port", Value: "tcp://10.0.0.5:27017"}}
	cov := Compute("acme", nil, assets, nil)
	found := false
	for _, s := range cov.Suggestions {
		if s.Tool == "scan-mongodb" {
			found = true
		}
	}
	if !found {
		t.Error("scan-mongodb deveria ser sugerido quando há assets kind=port")
	}
}
