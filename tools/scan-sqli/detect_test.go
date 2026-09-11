package main

import "testing"

func TestClassifyMySQLErrorLeaked(t *testing.T) {
	baseline := `<html><body>produto: Camiseta</body></html>`
	injected := `<html><body>Warning: mysql_fetch_array() expects parameter 1 to be resource</body></html>`
	sev, ftype, sig, ok := classify(baseline, injected)
	if !ok || sev != "high" || ftype != "sqli-error-based" {
		t.Fatalf("esperava high/sqli-error-based, veio sev=%q ftype=%q ok=%v (sig=%q)", sev, ftype, ok, sig)
	}
}

func TestClassifyPostgresErrorLeaked(t *testing.T) {
	baseline := `<html><body>ok</body></html>`
	injected := `<html><body>ERROR: unterminated quoted string at or near "'"</body></html>`
	sev, ftype, _, ok := classify(baseline, injected)
	if !ok || sev != "high" || ftype != "sqli-error-based" {
		t.Fatalf("esperava high/sqli-error-based (postgres), veio sev=%q ftype=%q ok=%v", sev, ftype, ok)
	}
}

func TestClassifyDB2ErrorLeaked(t *testing.T) {
	baseline := `<html><body>ok</body></html>`
	injected := `<html><body>DB2 SQL error: SQLCODE=-104, SQLSTATE=42601, SQL0104N an unexpected token</body></html>`
	sev, ftype, _, ok := classify(baseline, injected)
	if !ok || sev != "high" || ftype != "sqli-error-based" {
		t.Fatalf("esperava high/sqli-error-based (DB2), veio sev=%q ftype=%q ok=%v", sev, ftype, ok)
	}
}

func TestClassifyAccessJetErrorLeaked(t *testing.T) {
	baseline := `<html><body>ok</body></html>`
	injected := `<html><body>Microsoft Access Driver: syntax error in query expression</body></html>`
	sev, ftype, _, ok := classify(baseline, injected)
	if !ok || sev != "high" || ftype != "sqli-error-based" {
		t.Fatalf("esperava high/sqli-error-based (Access/Jet), veio sev=%q ftype=%q ok=%v", sev, ftype, ok)
	}
}

func TestClassifyH2ErrorLeaked(t *testing.T) {
	baseline := `<html><body>ok</body></html>`
	injected := `<html><body>org.h2.jdbc.JdbcSQLSyntaxErrorException: Syntax error in SQL statement</body></html>`
	sev, ftype, _, ok := classify(baseline, injected)
	if !ok || sev != "high" || ftype != "sqli-error-based" {
		t.Fatalf("esperava high/sqli-error-based (H2), veio sev=%q ftype=%q ok=%v", sev, ftype, ok)
	}
}

func TestClassifyCaseInsensitive(t *testing.T) {
	baseline := `ok`
	injected := `YOU HAVE AN ERROR IN YOUR SQL SYNTAX; check the manual`
	_, _, _, ok := classify(baseline, injected)
	if !ok {
		t.Fatal("assinatura em maiúsculas devia ser detectada (case-insensitive)")
	}
}

func TestClassifyErrorAlsoInBaselineIsNotAFinding(t *testing.T) {
	// página de documentação que sempre menciona "sql syntax error" —
	// não é causada pelo nosso payload, não deve virar finding.
	baseline := `<html><body>Aprenda sobre SQL syntax error e como evitar</body></html>`
	injected := `<html><body>Aprenda sobre SQL syntax error e como evitar</body></html>`
	_, _, _, ok := classify(baseline, injected)
	if ok {
		t.Fatal("assinatura presente em AMBAS as respostas não devia virar finding — não foi o payload que causou")
	}
}

func TestClassifyNoErrorSignature(t *testing.T) {
	baseline := `<html><body>produto não encontrado</body></html>`
	injected := `<html><body>produto não encontrado</body></html>`
	_, _, _, ok := classify(baseline, injected)
	if ok {
		t.Fatal("sem assinatura de erro conhecida não devia virar finding")
	}
}

func TestClassifyGenericErrorPageIsNotAFinding(t *testing.T) {
	// um 500 genérico (sem menção a SQL) não é prova de SQLi — a
	// diferença de status/tamanho sozinha não basta, precisa da
	// assinatura específica.
	baseline := `<html><body>ok</body></html>`
	injected := `<html><body>Internal Server Error — algo deu errado</body></html>`
	_, _, _, ok := classify(baseline, injected)
	if ok {
		t.Fatal("erro genérico sem assinatura de banco não devia virar finding")
	}
}

func TestProbePayloadsAreMinimalFootprint(t *testing.T) {
	for _, p := range probePayloads {
		if len(p) > 2 {
			t.Fatalf("payload %q não é um probe mínimo (1-2 chars de quebra de sintaxe) — nada de time-based/booleano/SLEEP/UNION aqui", p)
		}
	}
	if len(probePayloads) < 2 {
		t.Fatal("esperava mais de uma variante — filtros seletivos (só escapam aspa dupla, por exemplo) não devem fazer o scanner desistir cedo demais")
	}
}
