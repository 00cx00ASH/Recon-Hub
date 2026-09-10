package main

import (
	"sort"
	"testing"
)

func TestPortSet(t *testing.T) {
	if p := portSet("top100"); len(p) < 100 || !sorted(p) {
		t.Errorf("top100: len %d sorted %v", len(p), sorted(p))
	}
	if p := portSet("web"); !containsInt(p, 443) || !containsInt(p, 8080) {
		t.Errorf("web = %v", p)
	}
	got := portSet("22,80, 8000-8003 , 22")
	sort.Ints(got)
	want := []int{22, 80, 8000, 8001, 8002, 8003}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if p := portSet("nonsense,-5,99999"); len(p) != 0 {
		t.Errorf("spec inválido -> %v", p)
	}
}

func TestIdentify(t *testing.T) {
	s, prod := identify(22, "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13")
	if s != "ssh" || prod != "OpenSSH_9.6p1" {
		t.Errorf("ssh: %s / %s", s, prod)
	}
	s, prod = identify(80, "HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: text/html\r\n")
	if s != "http" || prod != "nginx/1.25.3" {
		t.Errorf("http: %s / %s", s, prod)
	}
	s, _ = identify(6379, "+PONG")
	if s != "redis" {
		t.Errorf("redis: %s", s)
	}
	s, prod = identify(11211, "VERSION 1.6.21")
	if s != "memcached" || prod != "1.6.21" {
		t.Errorf("memcached: %s / %s", s, prod)
	}
	s, _ = identify(3306, "\x4a\x00\x00\x00\x0a8.0.36-0ubuntu")
	if s != "mysql" {
		t.Errorf("mysql: %s", s)
	}
}

func TestNotable(t *testing.T) {
	for _, svc := range []string{"redis", "mongodb", "docker", "kube-apiserver", "rdp", "elasticsearch"} {
		if ok, sev, _ := notable(svc, 0); !ok || sev != "medium" {
			t.Errorf("%s deveria ser notável", svc)
		}
	}
	if ok, _, _ := notable("http", 80); ok {
		t.Error("http comum não é notável")
	}
}

func TestClean(t *testing.T) {
	got := clean([]byte("hello\x00\x01world\r\n  \ttab"))
	if got != "helloworld tab" {
		t.Errorf("clean = %q", got)
	}
}

func TestExpandTargets(t *testing.T) {
	hs, isCIDR := expandTargets("10.0.0.0/30", 1024)
	if !isCIDR {
		t.Fatal("deveria ser CIDR")
	}
	// /30 = 4 addrs, menos rede+broadcast = 2 usáveis
	if len(hs) != 2 || hs[0] != "10.0.0.1" || hs[1] != "10.0.0.2" {
		t.Errorf("hosts = %v", hs)
	}
	hs2, isC2 := expandTargets("example.com:8080", 1024)
	if isC2 || len(hs2) != 1 || hs2[0] != "example.com" {
		t.Errorf("host único = %v (cidr %v)", hs2, isC2)
	}
	hs3, _ := expandTargets("10.0.0.0/24", 10)
	if len(hs3) != 10 {
		t.Errorf("cap deveria limitar a 10, got %d", len(hs3))
	}
}

func TestCleanHost(t *testing.T) {
	cases := map[string]string{
		"https://db.example.com:5432/x": "db.example.com",
		"MONGODB://10.0.0.5":            "10.0.0.5",
		"  host.local.  ":               "host.local",
	}
	for in, want := range cases {
		if got := cleanHost(in); got != want {
			t.Errorf("cleanHost(%q) = %q, quer %q", in, got, want)
		}
	}
}

func sorted(p []int) bool {
	for i := 1; i < len(p); i++ {
		if p[i-1] > p[i] {
			return false
		}
	}
	return true
}

func containsInt(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
