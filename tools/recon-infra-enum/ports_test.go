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

// TestIdentifyServerHeaderOnRealisticCleanedBanner é o teste de regressão
// pro bug real: reServer exigia "\r\n" literal antes de "Server:", mas o
// banner que chega em identify() na vida real JÁ passou por clean() (grab()
// sempre devolve clean(buf[:n])) — que troca \r\n por espaço. O teste
// antigo (acima) só "passava" porque chamava identify() com string CRUA
// direto, nunca testando o formato que realmente chega em produção.
func TestIdentifyServerHeaderOnRealisticCleanedBanner(t *testing.T) {
	cleaned := clean([]byte("HTTP/1.1 200 OK\r\nServer: nginx/1.25.3\r\nContent-Type: text/html\r\n"))
	s, prod := identify(80, cleaned)
	if s != "http" || prod != "nginx/1.25.3" {
		t.Fatalf("banner realista (pós-clean) deveria extrair nginx/1.25.3, veio %s / %q (banner=%q)", s, prod, cleaned)
	}

	cleaned2 := clean([]byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\nDate: Mon, 01 Jan 2024\r\n"))
	_, prod2 := identify(80, cleaned2)
	if prod2 != "Apache/2.4.41 (Ubuntu)" {
		t.Fatalf("Server com espaço no valor (parênteses) deveria vir inteiro, veio %q", prod2)
	}
}

func TestIdentifyJenkinsViaHeader(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nX-Jenkins: 2.401.3\r\nContent-Type: text/html\r\n"
	s, prod := identify(8080, clean([]byte(raw)))
	if s != "jenkins" || prod != "2.401.3" {
		t.Fatalf("esperava jenkins/2.401.3, veio %s/%q", s, prod)
	}
}

func TestNotable(t *testing.T) {
	for _, svc := range []string{
		"redis", "mongodb", "docker", "kube-apiserver", "rdp", "elasticsearch",
		// serviços que já estavam em svc[] (mapa porta->nome) mas nunca
		// tinham entrada em notable() — parte do gap real corrigido aqui.
		"jenkins", "solr", "prometheus", "alertmanager", "activemq", "yarn",
		"hdfs", "hdfs-namenode", "spark", "webmin", "arangodb", "neo4j",
		"neo4j-https", "sap", "rethinkdb", "git",
	} {
		if ok, sev, _ := notable(svc, 0); !ok || sev != "medium" {
			t.Errorf("%s deveria ser notável", svc)
		}
	}
	if ok, _, _ := notable("http", 80); ok {
		t.Error("http comum não é notável")
	}
}

// TestSvcServiceNamesAllReachableInNotableOrIntentionallyNot é uma checagem
// estrutural: todo valor em svc[] que corresponde a um dos serviços listados
// em notable() precisa estar de fato alcançável (bug real corrigido aqui:
// "jenkins" existia em notable() sem NENHUM caminho em identify() que
// pudesse setar service="jenkins" — dead code disfarçado de cobertura).
func TestJenkinsIsReachableFromIdentify(t *testing.T) {
	s, _ := identify(8080, clean([]byte("HTTP/1.1 200 OK\r\nX-Jenkins: 2.401\r\n")))
	if ok, _, _ := notable(s, 8080); !ok {
		t.Fatal("identify() detectou jenkins mas notable() não reconhece o service resultante — desalinhado de novo")
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
