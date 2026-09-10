package main

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// mkJWT builds an unsigned JWT with the given claims (payload only matters here).
func mkJWT(claims map[string]any) string {
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pb, _ := json.Marshal(claims)
	pay := base64.RawURLEncoding.EncodeToString(pb)
	return hdr + "." + pay + ".c2ln"
}

func TestExtractCreds(t *testing.T) {
	anon := mkJWT(map[string]any{"iss": "supabase", "ref": "abcdefghijklmnopqrst", "role": "anon", "exp": 2000000000})
	body := `
	window.__ENV = {
	  NEXT_PUBLIC_SUPABASE_URL: "https://abcdefghijklmnopqrst.supabase.co",
	  NEXT_PUBLIC_SUPABASE_ANON_KEY: "` + anon + `"
	};`
	c := extractCreds(body)
	if c.URL != "https://abcdefghijklmnopqrst.supabase.co" {
		t.Errorf("URL = %q", c.URL)
	}
	if c.Key != anon || c.Ref != "abcdefghijklmnopqrst" {
		t.Errorf("Key/Ref = %q / %q", c.Key, c.Ref)
	}
}

func TestExtractCredsServiceRolePreferred(t *testing.T) {
	anon := mkJWT(map[string]any{"ref": "aaaaaaaaaaaaaaaaaaaa", "role": "anon"})
	svc := mkJWT(map[string]any{"ref": "aaaaaaaaaaaaaaaaaaaa", "role": "service_role"})
	body := "k1='" + anon + "'; k2='" + svc + "';"
	c := extractCreds(body)
	if keyRole(c.Key) != "service_role" {
		t.Errorf("deveria preferir a service_role key, role=%q", keyRole(c.Key))
	}
}

func TestDecodeJWT(t *testing.T) {
	tok := mkJWT(map[string]any{"role": "authenticated", "sub": "u1"})
	claims, err := decodeJWT(tok)
	if err != nil {
		t.Fatal(err)
	}
	if claims["role"] != "authenticated" || claims["sub"] != "u1" {
		t.Errorf("claims = %v", claims)
	}
	if _, err := decodeJWT("not.a"); err == nil {
		t.Error("token de 2 partes deveria falhar")
	}
}

func TestParseOpenAPITables(t *testing.T) {
	doc := `{"swagger":"2.0","definitions":{"users":{},"orders":{},"secrets":{}},
	         "paths":{"/":{},"/users":{},"/rpc/do_thing":{}}}`
	got := parseOpenAPITables(doc)
	sort.Strings(got)
	want := []string{"orders", "secrets", "users"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, quer %v", got, want)
	}
}

func TestClassifyTable(t *testing.T) {
	if v := classifyTable(200, `[{"id":1,"email":"a@b.c","token":"x"}]`); v.kind != "anon-read" || v.severity != "high" || v.rows != 1 {
		t.Errorf("linhas -> %+v", v)
	}
	if v := classifyTable(200, `[]`); v.kind != "anon-read-empty" || v.severity != "medium" {
		t.Errorf("vazio -> %+v", v)
	}
	if v := classifyTable(401, `{"message":"permission denied for table users","code":"42501"}`); v.kind != "rls-enforced" {
		t.Errorf("rls -> %+v", v)
	}
	if v := classifyTable(404, `{"code":"42P01","message":"relation \"x\" does not exist"}`); v.kind != "not-found" {
		t.Errorf("404 -> %+v", v)
	}
}

func TestClassifyTableColumns(t *testing.T) {
	v := classifyTable(200, `[{"z":1,"a":2,"m":3}]`)
	if strings.Join(v.cols, ",") != "a,m,z" {
		t.Errorf("colunas deviam vir ordenadas: %v", v.cols)
	}
}
