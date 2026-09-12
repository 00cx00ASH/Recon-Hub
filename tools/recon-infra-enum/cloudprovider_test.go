package main

import (
	"net"
	"testing"
)

func TestProviderFromPTRMatchesKnownSuffixes(t *testing.T) {
	cases := map[string]string{
		"ec2-1-2-3-4.compute-1.amazonaws.com": "AWS",
		"1.2.3.4.bc.googleusercontent.com":    "GCP",
		"myvm.westus.cloudapp.azure.com":      "Azure",
		"myapp.azurewebsites.net":             "Azure",
		"host.digitalocean.com":               "DigitalOcean",
		"li123-45.members.linode.com":         "Linode/Akamai Connected Cloud",
		"myinstance.oraclecloud.com":          "Oracle Cloud",
		"ns1.ovh.net":                         "OVH",
		"myapp.herokuapp.com":                 "Heroku (AWS)",
		"static.myhetzner.com.hetzner.com":    "Hetzner",
	}
	for ptr, want := range cases {
		provider, first := providerFromPTR([]string{ptr})
		if provider != want {
			t.Errorf("providerFromPTR(%q) = %q, quer %q", ptr, provider, want)
		}
		if first != ptr {
			t.Errorf("firstPTR deveria preservar o nome original (lowercased/sem ponto final), veio %q", first)
		}
	}
}

func TestProviderFromPTRNoMatchReturnsEmpty(t *testing.T) {
	provider, first := providerFromPTR([]string{"host.someprivatecompany.internal"})
	if provider != "" {
		t.Errorf("PTR sem suffix conhecido não deveria casar provedor nenhum, veio %q", provider)
	}
	if first != "host.someprivatecompany.internal" {
		t.Errorf("mesmo sem match, firstPTR deveria vir preenchido: %q", first)
	}
}

func TestProviderFromPTREmptyList(t *testing.T) {
	provider, first := providerFromPTR(nil)
	if provider != "" || first != "" {
		t.Errorf("lista vazia deveria devolver tudo vazio, veio provider=%q first=%q", provider, first)
	}
}

func TestProviderFromIPMatchesCloudflareRange(t *testing.T) {
	if got := providerFromIP(net.ParseIP("104.16.5.5")); got != "Cloudflare" {
		t.Errorf("104.16.5.5 está dentro de 104.16.0.0/13 (Cloudflare) — veio %q", got)
	}
	if got := providerFromIP(net.ParseIP("8.8.8.8")); got != "" {
		t.Errorf("8.8.8.8 (Google DNS) não deveria casar Cloudflare — veio %q", got)
	}
}

func TestMustParseCIDRsSkipsInvalid(t *testing.T) {
	got := mustParseCIDRs([]string{"10.0.0.0/8", "not-a-cidr", "192.168.0.0/16"})
	if len(got) != 2 {
		t.Fatalf("esperava 2 CIDRs válidos parseados (1 inválido descartado), veio %d", len(got))
	}
}

func TestCloudflareRangesAllParsedSuccessfully(t *testing.T) {
	// se algum CIDR do literal estiver malformado, mustParseCIDRs silenciosamente
	// o descarta — este teste garante que a lista embutida bate 1:1 com o que
	// foi parseado, ou seja, nenhuma entrada foi digitada errado.
	const wantCount = 15
	if len(cloudflareRanges) != wantCount {
		t.Fatalf("esperava %d ranges do Cloudflare parseados com sucesso, veio %d — alguma entrada malformada na lista?", wantCount, len(cloudflareRanges))
	}
}
