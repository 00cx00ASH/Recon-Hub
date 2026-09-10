package main

import (
	"bufio"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

// startFakeServer sobe um listener TCP que decide como reagir ao corpo
// recebido:
//   - respondFast: sempre lê exatamente Content-Length bytes e responde 200
//     na hora (simula um componente que prioriza Content-Length).
//   - !respondFast: se Transfer-Encoding: chunked estiver presente, tenta ler
//     o corpo como chunked de verdade — como o probe manda um chunk
//     incompleto de propósito, essa leitura nunca fecha, então o servidor
//     simplesmente não escreve nada (silêncio = o timeout do cliente que vai
//     detectar).
func startFakeServer(t *testing.T, respondFast bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				var contentLength int
				var chunked bool
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					line = strings.TrimRight(line, "\r\n")
					if line == "" {
						break // fim dos headers
					}
					low := strings.ToLower(line)
					if strings.HasPrefix(low, "content-length:") {
						fieldsAfterColon := strings.TrimSpace(line[len("Content-Length:"):])
						for _, ch := range fieldsAfterColon {
							if ch < '0' || ch > '9' {
								break
							}
							contentLength = contentLength*10 + int(ch-'0')
						}
					}
					if strings.HasPrefix(low, "transfer-encoding:") {
						chunked = true
					}
				}

				if respondFast || !chunked {
					// lê exatamente contentLength bytes (interpretação por CL) e responde
					buf := make([]byte, contentLength)
					_, _ = r.Read(buf)
					_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
					return
				}

				// interpretação por TE: tenta ler um corpo chunked "de
				// verdade" — com o payload de teste isso nunca completa. Um
				// parser chunked real ficaria bloqueado num Read() esperando
				// mais bytes; aqui simulamos isso com um sleep mais longo que
				// o read-timeout do cliente do teste, sem escrever resposta
				// nenhuma (silêncio proposital) — é exatamente o hang que o
				// probe de timing existe pra detectar.
				time.Sleep(2 * time.Second)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

func TestSendAndTimeDetectsHangOnTEParser(t *testing.T) {
	addr := startFakeServer(t, false) // simula um back-end que prioriza TE
	u, _ := url.Parse("http://" + addr + "/")

	base, baseTimedOut, _ := sendAndTime(u, baselineRequest(u.Host, "/"), 2*time.Second, 2*time.Second)
	if baseTimedOut {
		t.Fatalf("baseline não deveria travar (sem Transfer-Encoding): elapsed=%s", base)
	}

	_, clteTimedOut, _ := sendAndTime(u, clteRequest(u.Host, "/"), 500*time.Millisecond, 2*time.Second)
	if !clteTimedOut {
		t.Fatal("esperava timeout no probe CL.TE contra um servidor que prioriza TE (chunked incompleto trava a leitura)")
	}
}

func TestSendAndTimeFastOnCLParser(t *testing.T) {
	addr := startFakeServer(t, true) // simula um componente que só olha Content-Length
	u, _ := url.Parse("http://" + addr + "/")

	_, baseTimedOut, status := sendAndTime(u, baselineRequest(u.Host, "/"), 2*time.Second, 2*time.Second)
	if baseTimedOut {
		t.Fatal("baseline não deveria travar")
	}
	if !strings.Contains(status, "200") {
		t.Fatalf("esperava 200 na linha de status, veio %q", status)
	}

	_, clteTimedOut, status2 := sendAndTime(u, clteRequest(u.Host, "/"), 2*time.Second, 2*time.Second)
	if clteTimedOut {
		t.Fatal("um servidor baseado em Content-Length deveria responder rápido mesmo ao probe CL.TE (lê só os 4 bytes e responde)")
	}
	if !strings.Contains(status2, "200") {
		t.Fatalf("esperava 200, veio %q", status2)
	}
}
