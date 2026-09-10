package main

import (
	"flag"
	"testing"
)

// TestParseAnywhereFlagAfterPositional regressão: achado rodando o hub de
// verdade — `run example-echo acme.com -program acme` silenciosamente
// ignorava -program porque flag.FlagSet.Parse para no primeiro argumento
// não-flag. O job saía sem program, e -program acme em qualquer filtro
// posterior (jobs/findings/coverage) não encontrava nada.
func TestParseAnywhereFlagAfterPositional(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	program := fs.String("program", "", "")
	rest := parseAnywhere(fs, []string{"example-echo", "acme.com", "-program", "acme"})
	if *program != "acme" {
		t.Fatalf("-program depois dos posicionais não foi capturado: %q", *program)
	}
	if len(rest) != 2 || rest[0] != "example-echo" || rest[1] != "acme.com" {
		t.Fatalf("positional = %v", rest)
	}
}

func TestParseAnywhereFlagBeforePositional(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	program := fs.String("program", "", "")
	rest := parseAnywhere(fs, []string{"-program", "acme", "example-echo", "acme.com"})
	if *program != "acme" || len(rest) != 2 {
		t.Fatalf("program=%q rest=%v", *program, rest)
	}
}

func TestParseAnywhereEqualsForm(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	program := fs.String("program", "", "")
	rest := parseAnywhere(fs, []string{"example-echo", "-program=acme", "acme.com"})
	if *program != "acme" {
		t.Fatalf("-program=acme não capturado: %q", *program)
	}
	if len(rest) != 2 || rest[0] != "example-echo" || rest[1] != "acme.com" {
		t.Fatalf("positional = %v", rest)
	}
}

func TestParseAnywhereRepeatedFlag(t *testing.T) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	params := paramFlags{}
	fs.Var(params, "param", "")
	rest := parseAnywhere(fs, []string{"tool", "target", "-param", "a=1", "-param", "b=2"})
	if params["a"] != "1" || params["b"] != "2" {
		t.Fatalf("params = %v", params)
	}
	if len(rest) != 2 {
		t.Fatalf("positional = %v", rest)
	}
}

func TestParamFlagsSet(t *testing.T) {
	p := paramFlags{}
	if err := p.Set("max=3000"); err != nil {
		t.Fatal(err)
	}
	if err := p.Set(" wordlist = builtin/web-content-common "); err != nil {
		t.Fatal(err)
	}
	if p["max"] != "3000" || p["wordlist"] != "builtin/web-content-common" {
		t.Fatalf("params = %v", p)
	}
	if err := p.Set("sem-igual"); err == nil {
		t.Error("esperava erro sem '='")
	}
}

func TestTrim(t *testing.T) {
	if got := trim("curto", 10); got != "curto" {
		t.Errorf("trim curto = %q", got)
	}
	if got := trim("um-titulo-bem-comprido-de-verdade", 10); got != "um-titulo…" {
		t.Errorf("trim longo = %q", got)
	}
}

func TestQS(t *testing.T) {
	if got := qs(map[string]string{}); got != "" {
		t.Errorf("vazio deveria dar string vazia, veio %q", got)
	}
	got := qs(map[string]string{"program": "acme", "severity": ""})
	if got != "?program=acme" {
		t.Errorf("qs = %q, quer ?program=acme (severity vazio deveria ser omitido)", got)
	}
}

func TestIsTerminalJob(t *testing.T) {
	for _, s := range []string{"succeeded", "failed", "canceled"} {
		if !isTerminalJob(s) {
			t.Errorf("%q deveria ser terminal", s)
		}
	}
	for _, s := range []string{"queued", "running", ""} {
		if isTerminalJob(s) {
			t.Errorf("%q não deveria ser terminal", s)
		}
	}
}
