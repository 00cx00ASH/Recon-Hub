package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWithBlockRotationNoopWithoutControlURL(t *testing.T) {
	base := http.DefaultTransport
	got := withBlockRotation(base, nil)
	if got != http.RoundTripper(base) {
		t.Fatal("sem RECONHUB_PROXY_CONTROL_URL deveria devolver o RoundTripper original, sem envolver")
	}
}

// fakeTorControl simula o suficiente do protocolo de controle do Tor pra
// confirmar que torNewCircuit manda AUTHENTICATE/SIGNAL NEWNYM/QUIT e lê a
// resposta "250" — sem precisar de um daemon Tor de verdade no teste.
func fakeTorControl(t *testing.T) (addr string, gotCommands func() string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	var mu sync.Mutex
	var received string
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				mu.Lock()
				received = string(buf[:n])
				mu.Unlock()
				conn.Write([]byte("250 OK\r\n250 OK\r\n250 closing connection\r\n"))
			}()
		}
	}()
	return ln.Addr().String(), func() string {
		mu.Lock()
		defer mu.Unlock()
		return received
	}
}

func TestTorNewCircuitSpeaksControlProtocol(t *testing.T) {
	addr, gotCommands := fakeTorControl(t)
	if err := torNewCircuit(addr); err != nil {
		t.Fatalf("torNewCircuit: %v", err)
	}
	cmds := gotCommands()
	if !strings.Contains(cmds, "AUTHENTICATE") || !strings.Contains(cmds, "SIGNAL NEWNYM") {
		t.Fatalf("comandos enviados não batem: %q", cmds)
	}
}

func TestTorNewCircuitFailsOnUnexpectedResponse(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		conn.Read(buf)
		conn.Write([]byte("510 unrecognized command\r\n"))
	}()
	if err := torNewCircuit(ln.Addr().String()); err == nil {
		t.Fatal("resposta sem 250 deveria dar erro")
	}
}

func TestTorNewCircuitFailsWhenNothingListens(t *testing.T) {
	// porta fechada — simula um SOCKS5 que não é o sidecar de Tor deste
	// repo (sem control port aberto em 9051).
	if err := torNewCircuit("127.0.0.1:1"); err == nil {
		t.Fatal("control port inexistente deveria dar erro")
	}
}

func TestBlockRotatorTriggersAfterThreshold(t *testing.T) {
	controlAddr, _ := fakeTorControl(t)
	t.Setenv("RECONHUB_PROXY_CONTROL_URL", controlAddr)
	t.Setenv("RECONHUB_PROXY_BLOCK_THRESHOLD", "3")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	var mu sync.Mutex
	var msgs []string
	rt := withBlockRotation(http.DefaultTransport, func(m string) {
		mu.Lock()
		msgs = append(msgs, m)
		mu.Unlock()
	})
	client := &http.Client{Transport: rt}

	for i := 0; i < 3; i++ {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	mu.Lock()
	got := append([]string(nil), msgs...)
	mu.Unlock()
	if len(got) != 1 || !strings.Contains(got[0], "circuito Tor trocado automaticamente") {
		t.Fatalf("esperava exatamente 1 rotação após 3 bloqueios (threshold=3), veio: %v", got)
	}
}

func TestBlockRotatorResetsStreakOnNonBlockedResponse(t *testing.T) {
	controlAddr, _ := fakeTorControl(t)
	t.Setenv("RECONHUB_PROXY_CONTROL_URL", controlAddr)
	t.Setenv("RECONHUB_PROXY_BLOCK_THRESHOLD", "3")

	statuses := []int{403, 403, 200, 403, 403} // nunca 3 seguidos
	i := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(statuses[i])
		i++
	}))
	defer srv.Close()

	var mu sync.Mutex
	var msgs []string
	rt := withBlockRotation(http.DefaultTransport, func(m string) {
		mu.Lock()
		msgs = append(msgs, m)
		mu.Unlock()
	})
	client := &http.Client{Transport: rt}
	for range statuses {
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	mu.Lock()
	got := len(msgs)
	mu.Unlock()
	if got != 0 {
		t.Fatalf("streak deveria ter resetado no 200 — não esperava rotação, veio %d", got)
	}
}

func TestBlockRotatorRespectsCooldown(t *testing.T) {
	controlAddr, _ := fakeTorControl(t)
	t.Setenv("RECONHUB_PROXY_CONTROL_URL", controlAddr)
	t.Setenv("RECONHUB_PROXY_BLOCK_THRESHOLD", "2")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	rt := &blockRotator{
		RoundTripper: http.DefaultTransport,
		threshold:    2,
		controlAddr:  controlAddr,
		cooldown:     time.Hour, // nunca deveria rotacionar 2x no teste
	}
	var mu sync.Mutex
	rotations := 0
	rt.onRotate = func(string) {
		mu.Lock()
		rotations++
		mu.Unlock()
	}
	client := &http.Client{Transport: rt}
	for i := 0; i < 6; i++ { // 3 streaks de 2 seguidas
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	mu.Lock()
	got := rotations
	mu.Unlock()
	if got != 1 {
		t.Fatalf("cooldown longo deveria limitar a 1 rotação, veio %d", got)
	}
}
