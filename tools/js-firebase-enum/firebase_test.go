package main

import (
	"sort"
	"testing"
)

func TestExtractConfigJS(t *testing.T) {
	body := `
	const firebaseConfig = {
	  apiKey: "AIzaSyDUMMYdummyDUMMYdummyDUMMYdummy1234567",
	  authDomain: "my-proj.firebaseapp.com",
	  databaseURL: "https://my-proj-default-rtdb.firebaseio.com/",
	  projectId: "my-proj",
	  storageBucket: "my-proj.appspot.com",
	  messagingSenderId: "123456789012",
	  appId: "1:123456789012:web:abcdef123456"
	};`
	c := extractConfig(body)
	if c.APIKey == "" || c.ProjectID != "my-proj" {
		t.Fatalf("config mal extraído: %+v", c)
	}
	if c.DatabaseURL != "https://my-proj-default-rtdb.firebaseio.com" {
		t.Errorf("databaseURL não normalizada: %q", c.DatabaseURL)
	}
}

func TestExtractConfigJSON(t *testing.T) {
	body := `{"apiKey":"AIzaXXX","authDomain":"foo.firebaseapp.com","projectId":"","appId":"1:2:web:3"}`
	c := extractConfig(body)
	if c.ProjectID != "foo" { // derivado do authDomain
		t.Errorf("projectId derivado errado: %q", c.ProjectID)
	}
	if c.StorageBucket != "foo.appspot.com" { // derivado do projectId
		t.Errorf("bucket derivado errado: %q", c.StorageBucket)
	}
}

func TestExtractConfigEmpty(t *testing.T) {
	if !extractConfig(`<html><body>nada aqui</body></html>`).empty() {
		t.Error("deveria ser empty()")
	}
}

func TestCandidateRTDBs(t *testing.T) {
	c := fbConfig{ProjectID: "proj", DatabaseURL: "https://proj-default-rtdb.firebaseio.com"}
	got := candidateRTDBs(c)
	if got[0] != "https://proj-default-rtdb.firebaseio.com" {
		t.Errorf("o databaseURL explícito devia vir 1º: %v", got)
	}
	// sem duplicar
	seen := map[string]int{}
	for _, u := range got {
		seen[u]++
		if seen[u] > 1 {
			t.Errorf("duplicado: %s", u)
		}
	}
}

func TestRtdbProject(t *testing.T) {
	cases := map[string]string{
		"https://abc-default-rtdb.firebaseio.com":                    "abc",
		"https://abc.firebaseio.com/":                                "abc",
		"https://abc-default-rtdb.europe-west1.firebasedatabase.app": "abc",
		"https://notfirebase.example.com":                            "",
	}
	for in, want := range cases {
		if got := rtdbProject(in); got != want {
			t.Errorf("rtdbProject(%q) = %q, quer %q", in, got, want)
		}
	}
}

func TestClassifyRTDB(t *testing.T) {
	if v := classifyRTDB(200, `{"users":true,"config":true}`); v.kind != "open-rtdb-read" || v.severity != "high" {
		t.Errorf("200 c/ dados → %+v", v)
	}
	if v := classifyRTDB(200, `null`); v.severity != "medium" {
		t.Errorf("200 null → %+v, quer medium", v)
	}
	if v := classifyRTDB(401, `{"error":"Permission denied"}`); v.kind != "rtdb-locked" {
		t.Errorf("401 → %+v", v)
	}
	if v := classifyRTDB(404, `404 page not found`); v.kind != "rtdb-absent" {
		t.Errorf("404 → %+v", v)
	}
}

func TestClassifyFirestore(t *testing.T) {
	if k, s, _ := classifyFirestore(200, `{"documents":[{"name":"x"}]}`); k != "open-firestore-read" || s != "high" {
		t.Errorf("200 c/ docs → %s/%s", k, s)
	}
	if k, _, _ := classifyFirestore(403, `{"error":{"status":"PERMISSION_DENIED"}}`); k != "firestore-locked" {
		t.Errorf("403 → %s", k)
	}
}

func TestClassifyStorage(t *testing.T) {
	if k, s, _ := classifyStorage(200, `{"items":[{"name":"a.jpg"}]}`); k != "open-storage-list" || s != "high" {
		t.Errorf("200 c/ items → %s/%s", k, s)
	}
	if k, _, _ := classifyStorage(403, `Permission denied.`); k != "storage-locked" {
		t.Errorf("403 → %s", k)
	}
	if k, _, _ := classifyStorage(404, `Not Found`); k != "storage-absent" {
		t.Errorf("404 → %s", k)
	}
}

func TestTopKeys(t *testing.T) {
	got := topKeys(`{"a":1,"b":2,"c":3}`)
	sort.Strings(got)
	if len(got) != 3 || got[0] != "a" {
		t.Errorf("topKeys = %v", got)
	}
	if topKeys(`"just a string"`) != nil {
		t.Error("string simples não tem topKeys")
	}
}
