package main

import (
	"sort"
	"strings"
	"testing"
)

func TestEndpointGuesses(t *testing.T) {
	g := endpointGuesses("https://api.example.com")
	joined := strings.Join(g, " ")
	for _, want := range []string{"https://api.example.com/graphql", "https://api.example.com/query", "https://api.example.com/graphiql"} {
		if !strings.Contains(joined, want) {
			t.Errorf("faltou %q", want)
		}
	}
	// base já graphql-ish é mantida
	g2 := endpointGuesses("https://api.example.com/graphql")
	if g2[0] != "https://api.example.com/graphql" {
		t.Errorf("base graphql-ish devia vir 1ª: %v", g2[0])
	}
}

func TestLooksGraphQL(t *testing.T) {
	if !looksGraphQL(200, "application/json", `{"data":{"__typename":"Query"}}`) {
		t.Error("resposta com __typename")
	}
	if !looksGraphQL(400, "application/json", `{"errors":[{"message":"Cannot query field \"x\" on type \"Query\""}]}`) {
		t.Error("erro típico de graphql")
	}
	if !looksGraphQL(200, "text/html", `<title>GraphiQL</title>`) {
		t.Error("graphiql html")
	}
	if looksGraphQL(200, "application/json", `{"foo":"bar"}`) {
		t.Error("json qualquer não é graphql")
	}
	if looksGraphQL(404, "text/html", `<h1>Not Found</h1>`) {
		t.Error("404 html")
	}
}

func TestParseIntrospection(t *testing.T) {
	body := `{"data":{"__schema":{
	  "queryType":{"name":"Query"},
	  "mutationType":{"name":"Mutation"},
	  "subscriptionType":null,
	  "types":[
	    {"kind":"OBJECT","name":"Query","fields":[{"name":"me"},{"name":"userPassword"},{"name":"posts"}]},
	    {"kind":"OBJECT","name":"Mutation","fields":[{"name":"createPost"},{"name":"deleteUser"},{"name":"updateUserRole"}]},
	    {"kind":"SCALAR","name":"String"}
	  ]
	}}}`
	s, ok := parseIntrospection(body)
	if !ok {
		t.Fatal("deveria parsear")
	}
	if s.QueryType != "Query" || s.MutationType != "Mutation" || s.Types != 3 {
		t.Errorf("schema = %+v", s)
	}
	sort.Strings(s.Queries)
	if strings.Join(s.Queries, ",") != "me,posts,userPassword" {
		t.Errorf("queries = %v", s.Queries)
	}
	sens := flagFields(append(append([]string{}, s.Queries...), s.Mutations...), sensitiveNeedles)
	if len(sens) != 1 || sens[0] != "userPassword" {
		t.Errorf("sensitive = %v", sens)
	}
	dang := flagFields(s.Mutations, dangerousMutationNeedles)
	sort.Strings(dang)
	if strings.Join(dang, ",") != "deleteUser,updateUserRole" {
		t.Errorf("dangerous = %v", dang)
	}
}

func TestParseIntrospectionDisabled(t *testing.T) {
	if _, ok := parseIntrospection(`{"errors":[{"message":"GraphQL introspection is not allowed"}]}`); ok {
		t.Error("introspection desabilitada não deveria parsear")
	}
}

func TestMisconfigChecks(t *testing.T) {
	if !checkGetEnabled(200, `{"data":{"__typename":"Query"}}`) {
		t.Error("GET habilitado")
	}
	if !checkBatching(200, `[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]`) {
		t.Error("batching")
	}
	if checkBatching(200, `{"data":{"__typename":"Query"}}`) {
		t.Error("resposta não-array não é batching")
	}
	if !checkFieldSuggestions(`{"errors":[{"message":"Cannot query field \"nam\" on type \"User\". Did you mean \"name\"?"}]}`) {
		t.Error("field suggestions")
	}
	if leak, _ := checkErrorLeak(`{"errors":[{"message":"error","extensions":{"exception":{"stacktrace":["at org.hibernate..."]}}}]}`); !leak {
		t.Error("stack trace leak")
	}
	if leak, _ := checkErrorLeak(`{"errors":[{"message":"Unauthorized"}]}`); leak {
		t.Error("erro limpo não vaza")
	}
}
