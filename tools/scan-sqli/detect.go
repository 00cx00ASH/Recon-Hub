package main

import "strings"

// probePayloads are the characters/short sequences that break SQL syntax in
// virtually every backend, tried one at a time per (URL, param) until one
// triggers an error (see main.go's worker loop — same "one hit, stop" as
// every other list-of-variants in this repo). Deliberately NOT time-based
// (SLEEP/WAITFOR — adds real load to the target) and NOT boolean-differential
// extraction (1=1 vs 1=2 chained requests trying to read data) — this tool
// stops at "the app leaked a raw DB error when we broke its query", the same
// minimal-footprint bar every other scanner in this repo holds itself to.
// Confirming further (that it's actually exploitable, how far) is
// deliberately left to the operator.
//
//   - `'` / `"` — breaks single-/double-quoted string literals, the most
//     common case (name=, search=, comment=…).
//   - `\'` — a lone backslash before the quote: if the app does its own
//     naive escaping (doubling quotes, or its own regex) rather than
//     parameterized queries, a backslash can itself need escaping and
//     produces a DIFFERENT syntax error than a bare quote would.
//   - `)` — breaks a numeric/unquoted value used inside a function call or
//     an `IN (...)` list — a context the quote-based payloads above never
//     touch, since they only break STRING literals, not numeric ones.
var probePayloads = []string{`'`, `"`, `\'`, `)`}

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
	// MariaDB (variante do MySQL com assinatura própria em alguns drivers)
	"mariadb server version",
	// IBM DB2
	"sql0104n",
	"sql0007n",
	"com.ibm.db2.jcc",
	"db2 sql error",
	// Sybase / SAP ASE
	"sybase message",
	"com.sybase.jdbc",
	// Firebird
	"firebird.dyn",
	"dynamic sql error",
	"org.firebirdsql.jdbc",
	// H2 (embutido em vários apps Java)
	"org.h2.jdbc",
	"syntax error in sql statement",
	// Microsoft Access / Jet
	"microsoft jet database engine",
	"microsoft access driver",
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
