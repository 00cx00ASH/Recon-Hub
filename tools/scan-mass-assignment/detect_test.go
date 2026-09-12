package main

import "testing"

func TestConfirmsWhenPrivilegedFieldBound(t *testing.T) {
	// o servidor serializou o objeto COM nosso campo role ligado ao sentinela,
	// e o campo de controle bogus NÃO voltou — bind seletivo, prova de MA.
	body := []byte(`{"id":42,"name":"teste","role":"RHSENT123"}`)
	confirmed, echo, parsed := classifyMassAssignment(body, "role", "RHSENT123", "RHCTL999")
	if !parsed {
		t.Fatal("resposta era JSON — deveria parsear")
	}
	if echo {
		t.Fatal("controle não voltou — não é eco")
	}
	if !confirmed {
		t.Fatal("campo privilegiado com valor sentinela sob a chave deveria confirmar mass assignment")
	}
}

func TestConfirmsNestedField(t *testing.T) {
	body := []byte(`{"data":{"user":{"id":1,"is_admin":"RHSENT123"}}}`)
	confirmed, _, _ := classifyMassAssignment(body, "is_admin", "RHSENT123", "RHCTL999")
	if !confirmed {
		t.Fatal("bind confirmado mesmo aninhado — o servidor ligou o campo ao objeto")
	}
}

func TestRejectsEchoEndpoint(t *testing.T) {
	// endpoint que devolve o corpo inteiro de volta: o campo de CONTROLE bogus
	// também volta. Reflexo cego, não bind — NÃO reportar (seria FP).
	body := []byte(`{"received":{"role":"RHSENT123","rh_ctl_x":"RHCTL999"}}`)
	confirmed, echo, _ := classifyMassAssignment(body, "role", "RHSENT123", "RHCTL999")
	if confirmed {
		t.Fatal("endpoint que ecoa o corpo inteiro não pode confirmar MA — é FP de reflexo")
	}
	if !echo {
		t.Fatal("deveria sinalizar eco (controle voltou)")
	}
}

func TestRejectsFieldNotBound(t *testing.T) {
	// app com bind por schema fixo: ignora nosso campo extra. A resposta tem
	// role, mas com o valor REAL, não o sentinela — não confirma.
	body := []byte(`{"id":42,"name":"teste","role":"user"}`)
	confirmed, echo, parsed := classifyMassAssignment(body, "role", "RHSENT123", "RHCTL999")
	if !parsed {
		t.Fatal("era JSON")
	}
	if echo {
		t.Fatal("controle não voltou — não é eco")
	}
	if confirmed {
		t.Fatal("role com valor REAL (não o sentinela) não prova bind do nosso input")
	}
}

func TestRejectsNameOnlyNoValue(t *testing.T) {
	// o nome do campo aparece refletido numa mensagem, mas não como chave com o
	// valor sentinela — não é bind.
	body := []byte(`{"error":"campo 'role' não permitido","status":"rejected"}`)
	confirmed, _, _ := classifyMassAssignment(body, "role", "RHSENT123", "RHCTL999")
	if confirmed {
		t.Fatal("nome do campo numa mensagem de erro não é bind")
	}
}

func TestRejectsNonJSON(t *testing.T) {
	confirmed, echo, parsed := classifyMassAssignment([]byte("<html>ok</html>"), "role", "RHSENT123", "RHCTL999")
	if parsed || confirmed || echo {
		t.Fatal("resposta não-JSON não permite confirmação estrutural")
	}
}

func TestControlValueElsewhereStillEcho(t *testing.T) {
	// o controle voltou sob OUTRA chave (o servidor realmente reflete tudo) —
	// ainda é eco, mesmo que o campo privilegiado também tenha voltado.
	body := []byte(`{"role":"RHSENT123","debug_echo":"RHCTL999"}`)
	confirmed, echo, _ := classifyMassAssignment(body, "role", "RHSENT123", "RHCTL999")
	if confirmed {
		t.Fatal("controle presente em qualquer lugar = eco; não confirmar")
	}
	if !echo {
		t.Fatal("deveria sinalizar eco")
	}
}
