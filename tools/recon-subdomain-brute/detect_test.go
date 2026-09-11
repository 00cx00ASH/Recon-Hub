package main

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestIsWildcardHitFiltersOnlyExactWildcardIPs(t *testing.T) {
	wildcard := map[string]bool{"1.2.3.4": true}
	if !isWildcardHit([]string{"1.2.3.4"}, wildcard) {
		t.Error("IP igual ao wildcard deveria ser filtrado")
	}
	if isWildcardHit([]string{"5.6.7.8"}, wildcard) {
		t.Error("IP diferente do wildcard NÃO deveria ser filtrado — é um achado real")
	}
	if isWildcardHit(nil, wildcard) {
		t.Error("sem IPs não é hit nenhum")
	}
	if isWildcardHit([]string{"1.2.3.4"}, nil) {
		t.Error("sem wildcard detectado, nada é filtrado")
	}
}

func TestIntersect(t *testing.T) {
	a := map[string]bool{"1.1.1.1": true, "2.2.2.2": true}
	b := map[string]bool{"2.2.2.2": true, "3.3.3.3": true}
	got := intersect(a, b)
	if len(got) != 1 || !got["2.2.2.2"] {
		t.Fatalf("esperava só 2.2.2.2 em comum, veio %v", got)
	}
}

func TestBuildResolverDefaultsToSystemResolver(t *testing.T) {
	r := buildResolver("")
	if r != net.DefaultResolver {
		t.Error("sem 'resolver' configurado deveria usar net.DefaultResolver")
	}
}

func TestBuildResolverCustomAddsDefaultPort(t *testing.T) {
	r := buildResolver("1.1.1.1")
	if r == net.DefaultResolver {
		t.Fatal("com 'resolver' configurado não deveria ser o default")
	}
	if !r.PreferGo {
		t.Error("resolver customizado precisa de PreferGo pra usar o Dial próprio")
	}
}

func TestRandLabelIsUniqueEnough(t *testing.T) {
	a, b := randLabel(), randLabel()
	if a == b {
		t.Fatal("dois randLabel() seguidos vieram iguais — entropia insuficiente")
	}
	if len(a) < 10 {
		t.Fatalf("label curto demais pra evitar colisão com prefixo real: %q", a)
	}
}

func TestResolveOneTimesOutCleanly(t *testing.T) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			<-ctx.Done() // nunca responde — força o timeout
			return nil, ctx.Err()
		},
	}
	_, err := resolveOne(context.Background(), r, "nunca-resolve.invalid.test", 50*time.Millisecond)
	if err == nil {
		t.Fatal("resolver que nunca responde deveria estourar o timeout com erro")
	}
}
