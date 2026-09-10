package main

import (
	"encoding/json"
	"strings"
)

// endpointGuesses returns candidate GraphQL paths for a base URL.
func endpointGuesses(base string) []string {
	base = strings.TrimRight(base, "/")
	paths := []string{
		"/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/v2/graphql",
		"/query", "/api/query", "/gql", "/api", "/graphql-api", "/graphql/console",
		"/graphiql", "/playground", "/api/graphiql", "/subscriptions", "/index.php?graphql",
	}
	out := make([]string, 0, len(paths)+1)
	// if the base already points at something graphql-ish, keep it
	if strings.Contains(strings.ToLower(base), "graphql") || strings.HasSuffix(base, "/query") {
		out = append(out, base)
	}
	for _, p := range paths {
		out = append(out, base+p)
	}
	return out
}

const probeQuery = `{"query":"query{__typename}"}`

// minimal introspection — enough to enumerate types + root fields
const introspectionQuery = `{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { kind name fields { name } } } }"}`

// looksGraphQL decides whether an HTTP response is a GraphQL endpoint.
func looksGraphQL(status int, ctype, body string) bool {
	if strings.Contains(strings.ToLower(ctype), "html") && !strings.Contains(body, "\"data\"") {
		// could still be graphiql
		l := strings.ToLower(body)
		return strings.Contains(l, "graphiql") || strings.Contains(l, "graphql playground") || strings.Contains(l, "apollo")
	}
	var m map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &m) != nil {
		return false
	}
	_, hasData := m["data"]
	_, hasErrors := m["errors"]
	if hasData {
		return strings.Contains(body, "__typename") || strings.Contains(body, "\"Query\"") || len(m["data"]) > 2
	}
	if hasErrors {
		le := strings.ToLower(string(m["errors"]))
		return strings.Contains(le, "graphql") || strings.Contains(le, "query") ||
			strings.Contains(le, "must provide") || strings.Contains(le, "syntax error") ||
			strings.Contains(le, "cannot query field")
	}
	return false
}

// schema is the parsed introspection result.
type schema struct {
	QueryType     string
	MutationType  string
	SubType       string
	Types         int
	Queries       []string
	Mutations     []string
	Subscriptions []string
}

func parseIntrospection(body string) (schema, bool) {
	var r struct {
		Data struct {
			Schema struct {
				QueryType        *struct{ Name string } `json:"queryType"`
				MutationType     *struct{ Name string } `json:"mutationType"`
				SubscriptionType *struct{ Name string } `json:"subscriptionType"`
				Types            []struct {
					Kind   string `json:"kind"`
					Name   string `json:"name"`
					Fields []struct {
						Name string `json:"name"`
					} `json:"fields"`
				} `json:"types"`
			} `json:"__schema"`
		} `json:"data"`
	}
	if json.Unmarshal([]byte(body), &r) != nil {
		return schema{}, false
	}
	s := r.Data.Schema
	if s.QueryType == nil && len(s.Types) == 0 {
		return schema{}, false
	}
	var out schema
	out.Types = len(s.Types)
	if s.QueryType != nil {
		out.QueryType = s.QueryType.Name
	}
	if s.MutationType != nil {
		out.MutationType = s.MutationType.Name
	}
	if s.SubscriptionType != nil {
		out.SubType = s.SubscriptionType.Name
	}
	for _, ty := range s.Types {
		switch ty.Name {
		case out.QueryType:
			for _, f := range ty.Fields {
				out.Queries = append(out.Queries, f.Name)
			}
		case out.MutationType:
			for _, f := range ty.Fields {
				out.Mutations = append(out.Mutations, f.Name)
			}
		case out.SubType:
			for _, f := range ty.Fields {
				out.Subscriptions = append(out.Subscriptions, f.Name)
			}
		}
	}
	return out, true
}

// sensitiveFields flags root fields whose names suggest secrets/PII/privilege.
var sensitiveNeedles = []string{
	"password", "passwd", "secret", "token", "apikey", "api_key", "privatekey",
	"private_key", "ssn", "creditcard", "credit_card", "cardnumber", "cvv",
	"session", "auth", "credential", "otp", "mfa", "recovery",
}

var dangerousMutationNeedles = []string{
	"delete", "drop", "truncate", "reset", "impersonat", "sudo", "grant",
	"role", "makeadmin", "make_admin", "createadmin", "promote", "disable",
	"bypass", "override", "exec", "runquery", "raw", "sql", "wipe", "purge",
}

func flagFields(names []string, needles []string) []string {
	var out []string
	for _, n := range names {
		ln := strings.ToLower(n)
		for _, nd := range needles {
			if strings.Contains(ln, nd) {
				out = append(out, n)
				break
			}
		}
	}
	return out
}

// misconfig checks derived from a response.
type miscFinding struct {
	kind string
	sev  string
	note string
}

func checkGetEnabled(status int, body string) bool {
	return status == 200 && (strings.Contains(body, "\"data\"") || looksGraphQL(status, "application/json", body))
}

func checkBatching(status int, body string) bool {
	// server accepted an array of ops and returned an array
	b := strings.TrimSpace(body)
	return status == 200 && strings.HasPrefix(b, "[") && strings.Contains(b, "__typename")
}

func checkFieldSuggestions(body string) bool {
	l := strings.ToLower(body)
	return strings.Contains(l, "did you mean") || strings.Contains(l, "cannot query field") && strings.Contains(l, "did you mean")
}

func checkErrorLeak(body string) (bool, string) {
	l := strings.ToLower(body)
	for _, m := range []string{"stack trace", "stacktrace", "at java.", "at org.", "traceback (most recent",
		"node_modules", " line ", "syntax error at or near", "pg::", "sequelize", "sqlstate", ".rb:", ".py\", line"} {
		if strings.Contains(l, m) {
			return true, m
		}
	}
	return false, ""
}
