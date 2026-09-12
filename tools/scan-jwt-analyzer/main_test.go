package main

import "testing"

func TestDecodeJWT(t *testing.T) {
	validJWT := "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJyb290In0.signature"
	header, payload, _, err := decodeJWT(validJWT)
	if err != nil {
		t.Fatalf("falha ao decodificar JWT válido: %v", err)
	}
	if header["alg"] != "HS256" {
		t.Errorf("esperava alg=HS256, recebeu %v", header["alg"])
	}
	if payload["sub"] != "root" {
		t.Errorf("esperava sub=root, recebeu %v", payload["sub"])
	}
}

func TestCheckAlgNone(t *testing.T) {
	header := map[string]interface{}{"alg": "none"}
	finding := checkAlgNone(header)
	if finding == nil {
		t.Fatal("esperava finding para alg=none")
	}
	if finding.Severity != "critical" {
		t.Errorf("severidade deveria ser critical, recebeu %s", finding.Severity)
	}
}

func TestCheckWeakAlg(t *testing.T) {
	header := map[string]interface{}{"alg": "HS256"}
	finding := checkWeakAlg(header)
	if finding == nil {
		t.Fatal("esperava finding para HS256")
	}
	if finding.Severity != "high" {
		t.Errorf("severidade deveria ser high, recebeu %s", finding.Severity)
	}
}
