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

func TestWithBlockRotationWrapsEvenWithoutControlURL(t *testing.T) {
	// Sem RECONHUB_PROXY_CONTROL_URL ainda embrulha — pra RESPEITAR o rate
	// limit (backoff no 429/503) mesmo sem Tor. Só não rotaciona circuito.
	t.Setenv("RECONHUB_PROXY_CONTROL_URL", "")
	base := http.DefaultTransport
	got := withBlockRotation(base, nil)
	br, ok := got.(*blockRotator)
	if !ok {
		t.Fatal("deveria embrulhar num *blockRotator pra respeitar rate limit, com ou sem Tor")
	}
	if br.controlAddr != "" {
		t.Fatalf("sem control URL, controlAddr deveria ser vazio (sem rotação); veio %q", br.controlAddr)
	}
	if br.maxBackoff <= 0 {
		t.Fatal("maxBackoff deveria ter default > 0 (respeito a rate limit ligado por padrão)")
	}
}

func TestParseRetryAfter(t *testing.T) {
	if d := parseRetryAfter("5"); d != 5*time.Second {
		t.Errorf("Retry-After: 5 → %s, quer 5s", d)
	}
	if d := parseRetryAfter(""); d != 0 {
		t.Errorf("vazio → %s, quer 0", d)
	}
	if d := parseRetryAfter("-3"); d != 0 {
		t.Errorf("negativo → %s, quer 0", d)
	}
	if d := parseRetryAfter("lixo"); d != 0 {
		t.Errorf("inválido → %s, quer 0", d)
	}
	// data no passado → 0
	if d := parseRetryAfter("Mon, 02 Jan 2006 15:04:05 GMT"); d != 0 {
		t.Errorf("data no passado → %s, quer 0", d)
	}
}

func TestBackoffForCapsAtMax(t *testing.T) {
	b := &blockRotator{maxBackoff: 3 * time.Second}
	resp := &http.Response{StatusCode: 429, Header: http.Header{"Retry-After": []string{"9999"}}}
	if d := b.backoffFor(resp); d != 3*time.Second {
		t.Fatalf("Retry-After hostil deveria ser limitado a maxBackoff (3s); veio %s", d)
	}
	// 200 nunca gera backoff
	if d := b.backoffFor(&http.Response{StatusCode: 200, Header: http.Header{}}); d != 0 {
		t.Fatalf("200 não deveria gerar backoff; veio %s", d)
	}
	// maxBackoff 0 = respeito desligado (opt-out)
	b0 := &blockRotator{maxBackoff: 0}
	if d := b0.backoffFor(resp); d != 0 {
		t.Fatalf("maxBackoff=0 deveria desligar o backoff; veio %s", d)
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
