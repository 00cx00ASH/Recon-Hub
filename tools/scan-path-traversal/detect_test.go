package main

import "testing"

func TestClassifyConfirmsOnPasswdSignatureDifferential(t *testing.T) {
	baseline := "<html><body>arquivo não encontrado</body></html>"
	injected := "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
	sev, ftype, sig, ok := classify(baseline, injected)
	if !ok {
		t.Fatal("deveria confirmar path traversal quando /etc/passwd vaza na resposta")
	}
	if ftype != "path-traversal" || sev != "high" {
		t.Fatalf("esperava path-traversal/high, veio %s/%s", ftype, sev)
	}
	if sig == "" {
		t.Fatal("deveria reportar a assinatura que bateu")
	}
}

func TestClassifyConfirmsOnWinIni(t *testing.T) {
	baseline := "ok"
	injected := "; for 16-bit app support\n[fonts]\n[extensions]\n"
	if _, _, _, ok := classify(baseline, injected); !ok {
		t.Fatal("deveria confirmar via assinatura de win.ini")
	}
}

func TestClassifyNoFalsePositiveWhenSignatureAlsoInBaseline(t *testing.T) {
	// Se a "assinatura" já está no baseline (ex: a página sempre cita isso),
	// NÃO é traversal — o diferencial é o que prova.
	both := "root:x:0:0: (exemplo na documentação desta página)"
	if _, _, _, ok := classify(both, both); ok {
		t.Fatal("assinatura presente no baseline não pode virar finding (falso positivo)")
	}
}

func TestClassifyNoFalsePositiveOnPlainPage(t *testing.T) {
	if _, _, _, ok := classify("home", "página normal sem nada de sistema"); ok {
		t.Fatal("página comum não pode confirmar traversal")
	}
}

func TestWithParamRawPreservesEncoding(t *testing.T) {
	// O payload pré-encodado tem que chegar verbatim (não re-encodado).
	u := withParamRaw("https://x.com/a?b=1", "file", "%2e%2e%2fetc%2fpasswd")
	want := "file=%2e%2e%2fetc%2fpasswd"
	if !contains(u, want) {
		t.Fatalf("payload pré-encodado deveria passar verbatim; url=%s", u)
	}
	// e o param pré-existente deve continuar lá
	if !contains(u, "b=1") {
		t.Fatalf("param pré-existente sumiu; url=%s", u)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
