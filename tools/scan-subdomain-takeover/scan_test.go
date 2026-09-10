package main

import (
	"reflect"
	"sort"
	"testing"
)

var (
	fpGitHub = &Fingerprint{Service: "GitHub Pages", CNAME: []string{"github.io"},
		Fingerprint: []string{"There isn't a GitHub Pages site here."}, NXDomain: false}
	fpAzure = &Fingerprint{Service: "Microsoft Azure", CNAME: []string{"azurewebsites.net"},
		Fingerprint: []string{"404 Web Site not found"}, NXDomain: true}
)

func TestDecide(t *testing.T) {
	cases := []struct {
		name        string
		cname       string
		fp          *Fingerprint
		resolves    bool
		httpChecked bool
		status      int
		body        string
		want        resultKind
		wantSignal  string
	}{
		{"nxdomain + serviço conhecido", "x.github.io", fpGitHub, false, false, 0, "", kindVuln, "nxdomain"},
		{"nxdomain + serviço desconhecido", "x.exemplo-nao-existe.net", nil, false, false, 0, "", kindDangling, "nxdomain"},
		{"resolve, sem fingerprint de CNAME", "x.exemplo.com", nil, true, false, 0, "", kindNone, ""},
		{"corpo casa fingerprint", "x.github.io", fpGitHub, true, true, 404, "Blah There isn't a GitHub Pages site here. blah", kindVuln, "fingerprint"},
		{"CNAME casa, corpo não confirma", "x.github.io", fpGitHub, true, true, 404, "site normal", kindLikely, "cname"},
		{"CNAME casa, sem resposta HTTP", "x.github.io", fpGitHub, true, true, 0, "", kindLikely, "cname"},
		{"serviço nxdomain-type que resolve e não confirma", "x.azurewebsites.net", fpAzure, true, true, 200, "site de verdade", kindNone, ""},
		{"http desativado, serviço não-nxdomain", "x.github.io", fpGitHub, true, false, 0, "", kindLikely, "cname"},
		{"http desativado, serviço nxdomain-type que resolve", "x.azurewebsites.net", fpAzure, true, false, 0, "", kindNone, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := decide("host.exemplo.com", c.cname, c.fp, c.resolves, c.httpChecked, c.status, c.body)
			if got.kind != c.want {
				t.Fatalf("kind = %d, quer %d (%s)", got.kind, c.want, got.evidence)
			}
			if c.wantSignal != "" && got.signal != c.wantSignal {
				t.Fatalf("signal = %q, quer %q", got.signal, c.wantSignal)
			}
			if got.kind != kindNone && got.evidence == "" {
				t.Fatal("finding sem evidence")
			}
		})
	}
}

func TestMatchCNAME(t *testing.T) {
	fps := []Fingerprint{*fpGitHub, *fpAzure}
	if fp := matchCNAME("abc.GITHUB.IO", fps); fp == nil || fp.Service != "GitHub Pages" {
		t.Fatalf("github: %+v", fp)
	}
	if fp := matchCNAME("nada.exemplo.com", fps); fp != nil {
		t.Fatalf("esperava nil, veio %+v", fp)
	}
}

func TestMatchBody(t *testing.T) {
	if !matchBody("... There isn't a GitHub Pages site here. ...", fpGitHub) {
		t.Fatal("deveria casar")
	}
	if matchBody("outra coisa", fpGitHub) {
		t.Fatal("não deveria casar")
	}
	if matchBody("", fpGitHub) || matchBody("x", &Fingerprint{}) {
		t.Fatal("corpo/fingerprint vazio não casa")
	}
}

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"  HTTPS://Sub.Exemplo.com/path  ": "sub.exemplo.com",
		"*.exemplo.com":                    "exemplo.com",
		"host.com:8443":                    "host.com",
		"trailing.dot.":                    "trailing.dot",
	} {
		if got := clean(in); got != want {
			t.Errorf("clean(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestAddSubs(t *testing.T) {
	dst := map[string]struct{}{}
	addSubs(dst, "a.exemplo.com, b.exemplo.com\nc.exemplo.com")
	addSubs(dst, []any{"d.exemplo.com", "  ", "https://e.exemplo.com/x"})
	got := sortedKeys(dst)
	want := []string{"a.exemplo.com", "b.exemplo.com", "c.exemplo.com", "d.exemplo.com", "e.exemplo.com"}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}
