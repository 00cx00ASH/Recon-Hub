package main

import (
	"reflect"
	"sort"
	"testing"
)

// Estas fixtures usam o formato REAL de cada fonte (documentado/observado nas
// APIs públicas). Antes desse refactor (que separou parse de fetch em cada
// srcX), essa lógica só era exercitada batendo na rede de verdade —
// impossível de validar num ambiente que bloqueia esses domínios por
// política (ex: este sandbox, que nega crt.sh/certspotter/hackertarget/etc.
// no proxy de egress). Testar o parser com uma resposta capturada é mais
// rigoroso que bater na API ao vivo: cobre exatamente os formatos abaixo,
// de forma determinística e repetível, sem depender da disponibilidade de
// terceiros.

func TestParseCrtshHosts(t *testing.T) {
	b := []byte(`[
		{"common_name":"www.example.com","name_value":"www.example.com"},
		{"common_name":"api.example.com","name_value":"api.example.com\nwww.api.example.com\n*.internal.example.com"}
	]`)
	out, ok := parseCrtshHosts(b)
	if !ok {
		t.Fatal("parse deveria ter funcionado")
	}
	hosts := map[string]bool{}
	for _, raw := range out {
		if h := normalizeHost(raw, "example.com"); h != "" {
			hosts[h] = true
		}
	}
	for _, want := range []string{"www.example.com", "api.example.com", "www.api.example.com"} {
		if !hosts[want] {
			t.Errorf("faltou %q em %v", want, hosts)
		}
	}
}

func TestParseCrtshHostsInvalid(t *testing.T) {
	if _, ok := parseCrtshHosts([]byte("not json")); ok {
		t.Error("esperava ok=false pra JSON inválido")
	}
}

func TestParseCertspotterHosts(t *testing.T) {
	b := []byte(`[
		{"id":"1","dns_names":["example.com","www.example.com"]},
		{"id":"2","dns_names":["api.example.com"]}
	]`)
	got, err := parseCertspotterHosts(b)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"example.com", "www.example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}

func TestParseHackerTargetHosts(t *testing.T) {
	// formato real: CSV "host,ip" uma linha por resultado
	text := "www.example.com,93.184.216.34\napi.example.com,93.184.216.35\n"
	got := parseHackerTargetHosts(text)
	want := []string{"www.example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}

func TestParseAlienVaultHosts(t *testing.T) {
	b := []byte(`{
		"passive_dns": [
			{"hostname": "www.example.com", "address": "93.184.216.34"},
			{"hostname": "api.example.com", "address": "93.184.216.35"}
		]
	}`)
	got, err := parseAlienVaultHosts(b)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"www.example.com", "api.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}

func TestParseAnubisHosts(t *testing.T) {
	// jldc.me devolve um array JSON simples de hostnames
	b := []byte(`["www.example.com","api.example.com","example.com"]`)
	got, err := parseAnubisHosts(b)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(got)
	want := []string{"api.example.com", "example.com", "www.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}

func TestParseAnubisHostsInvalid(t *testing.T) {
	if _, err := parseAnubisHosts([]byte("<html>not found</html>")); err == nil {
		t.Error("esperava erro pra JSON inválido")
	}
}
