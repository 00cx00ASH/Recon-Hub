package main

import "strings"

// probePayloads are the two characters that break SQL string literals in
// virtually every backend (single- and double-quoted strings). Deliberately
// NOT time-based (SLEEP/WAITFOR — adds real load to the target) and NOT
// boolean-differential extraction (1=1 vs 1=2 chained requests trying to
// read data) — this tool stops at "the app leaked a raw DB error when we
// broke its query", the same minimal-footprint bar every other scanner in
// this repo holds itself to. Confirming further (that it's actually
// exploitable, how far) is deliberately left to the operator.
var probePayloads = []string{`'`, `"`}

// errorSignatures are known, specific DB/ORM error strings — not "the
// response changed", which would be noisy on any app with per-request
// variation. Matching a specific signature is what makes this safe to
// auto-report: a generic 500 page never matches any of these.
var errorSignatures = []string{
	// MySQL / MariaDB
	"you have an error in your sql syntax",
	"warning: mysql_",
	"mysqli_sql_exception",
	"mysql server version for the right syntax",
	"unknown column",
	"com.mysql.jdbc.exceptions",
	// PostgreSQL
	"pg_query(): query failed",
	"pg_exec(): query failed",
	"postgresql query failed",
	"unterminated quoted string",
	"syntax error at or near",
	"org.postgresql.util.psqlexception",
	// MSSQL
	"unclosed quotation mark after the character string",
	"microsoft ole db provider for sql server",
	"system.data.sqlclient.sqlexception",
	"incorrect syntax near",
	// Oracle
	"ora-01756",
	"ora-00933",
	"ora-00936",
	"oracle.jdbc.driver",
	// SQLite
	"sqlite3::sqlexception",
	"sqlite_error",
	"unrecognized token:",
	`near "'"`,
	// genérico / ORM
	"sql syntax error",
	"sqlstate[",
	"java.sql.sqlexception",
	"system.data.oledb",
	"error in your sql syntax",
	"ado.net",
	"pdoexception",
	"odbc sql server driver",
	"sequelize.databaseerror",
	"activerecord::statementinvalid",
}

// classify decides whether injecting payload proved SQL injection: an error
// signature is present in the injected response but ABSENT from the
// baseline (unmodified) response — that differential is what rules out
// pages that just happen to always mention "SQL syntax" somewhere (docs
// pages, generic error boilerplate). sev is always "high": unsanitized
// input reaching a DB query, confirmed via real error disclosure, is a
// reportable finding on its face — no ambiguous "medium" tier here like
// scan-xss's attribute-context case, because there's no weaker-but-real
// signal to fall back to for SQLi the way there is for XSS.
func classify(baseline, injected string) (sev, ftype, signature string, ok bool) {
	lowInjected := strings.ToLower(injected)
	lowBaseline := strings.ToLower(baseline)
	for _, sig := range errorSignatures {
		if strings.Contains(lowInjected, sig) && !strings.Contains(lowBaseline, sig) {
			return "high", "sqli-error-based", sig, true
		}
	}
	return "", "", "", false
}
