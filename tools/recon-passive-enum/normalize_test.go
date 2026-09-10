package main

import (
	"reflect"
	"sort"
	"testing"
)

func TestCleanRoot(t *testing.T) {
	cases := map[string]string{
		"https://www.Example.com/path?q=1": "www.example.com",
		"*.example.com":                    "example.com",
		"EXAMPLE.COM.":                     "example.com",
		"  example.com  ":                  "example.com",
		"http://a.b.c:8080/x":              "a.b.c",
	}
	for in, want := range cases {
		if got := cleanRoot(in); got != want {
			t.Errorf("cleanRoot(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	root := "example.com"
	ok := map[string]string{
		"api.example.com":     "api.example.com",
		"*.cdn.example.com":   "cdn.example.com",
		"A.B.Example.com.":    "a.b.example.com",
		"example.com":         "example.com",
		"%2a.dev.example.com": "dev.example.com",
	}
	for in, want := range ok {
		if got := normalizeHost(in, root); got != want {
			t.Errorf("normalizeHost(%q) = %q, quer %q", in, got, want)
		}
	}
	bad := []string{
		"api.notexample.com", "example.org", "foo bar.example.com",
		"user@example.com", "", "http://x.example.com", "-.example.com",
		"a..example.com",
	}
	for _, in := range bad {
		if got := normalizeHost(in, root); got != "" {
			t.Errorf("normalizeHost(%q) = %q, quer vazio", in, got)
		}
	}
}

func TestHostsFromText(t *testing.T) {
	root := "example.com"
	text := `host,ip
	a.example.com,1.2.3.4
	<td>b.example.com</td>
	https://c.d.example.com/login
	unrelated.example.org
	EXAMPLE.COM`
	got := hostsFromText(text, root)
	sort.Strings(got)
	want := []string{"a.example.com", "b.example.com", "c.d.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, quer %v", got, want)
	}
}

func TestParseSourceList(t *testing.T) {
	if parseSourceList("") != nil {
		t.Error("vazio -> nil (todas)")
	}
	m := parseSourceList("crtsh, wayback")
	if !m["crtsh"] || !m["wayback"] || m["anubis"] {
		t.Errorf("%v", m)
	}
}
