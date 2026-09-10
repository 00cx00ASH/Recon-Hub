package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Os payloads abaixo são os testes de timing canônicos de request smuggling
// (PortSwigger Web Security Academy) — a técnica é deliberadamente "segura":
// nunca faz pipeline de uma 2ª requisição real na mesma conexão pra provar o
// desync (isso arriscaria ler a resposta de outro usuário de verdade). Só
// mede quanto tempo o servidor demora pra responder a um corpo propositalmente
// ambíguo entre Content-Length e Transfer-Encoding, numa conexão isolada que
// é sempre fechada logo depois.

// clteBody: Content-Length diz 4 bytes ("1\r\nA"), mas o corpo chunked
// continua depois disso ("\r\nX"). Um parser que usa TE (chunked) vai ficar
// esperando o resto do chunk que nunca chega SE algo na frente já cortou em
// CL=4 — o sinal de vulnerabilidade é a demora.
const clteBody = "1\r\nA\r\nX"

// teclBody: Content-Length diz 6 bytes (o corpo inteiro, "0\r\n\r\nX"), mas o
// terminador chunked ("0\r\n\r\n") já fecha o corpo depois de 5 bytes — sobra
// "X" solto. Um parser que usa TE vai achar que uma 2ª requisição começou
// com "X" e ficar esperando o resto dela pra sempre.
const teclBody = "0\r\n\r\nX"

func craftRequest(host, path, contentLength, transferEncoding, body string, keepAlive bool) string {
	var b strings.Builder
	b.WriteString("POST " + path + " HTTP/1.1\r\n")
	b.WriteString("Host: " + host + "\r\n")
	b.WriteString("Content-Type: application/x-www-form-urlencoded\r\n")
	if contentLength != "" {
		b.WriteString("Content-Length: " + contentLength + "\r\n")
	}
	if transferEncoding != "" {
		b.WriteString("Transfer-Encoding: " + transferEncoding + "\r\n")
	}
	if keepAlive {
		b.WriteString("Connection: keep-alive\r\n")
	} else {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}

func baselineRequest(host, path string) string {
	body := "x=1"
	return craftRequest(host, path, fmt.Sprintf("%d", len(body)), "", body, false)
}

func clteRequest(host, path string) string {
	return craftRequest(host, path, "4", "chunked", clteBody, true)
}

func teclRequest(host, path string) string {
	return craftRequest(host, path, "6", "chunked", teclBody, true)
}

// dial abre uma conexão nova (nunca reaproveitada entre probes — cada teste
// começa limpo, sem depender de estado deixado por um probe anterior).
func dial(u *url.URL, timeout time.Duration) (net.Conn, error) {
	host := u.Host
	if !strings.Contains(host, ":") {
		if u.Scheme == "https" {
			host += ":443"
		} else {
			host += ":80"
		}
	}
	d := &net.Dialer{Timeout: timeout}
	if u.Scheme == "https" {
		sni := host
		if i := strings.LastIndexByte(host, ':'); i >= 0 {
			sni = host[:i]
		}
		return tls.DialWithDialer(d, "tcp", host, &tls.Config{InsecureSkipVerify: true, ServerName: sni})
	}
	return d.Dial("tcp", host)
}

// sendAndTime escreve raw na conexão e mede quanto tempo até o 1º byte da
// resposta (ou até o readTimeout estourar). A conexão é sempre fechada no
// fim — nenhum probe encadeia com outra requisição real.
func sendAndTime(u *url.URL, raw string, readTimeout, dialTimeout time.Duration) (elapsed time.Duration, timedOut bool, status string) {
	conn, err := dial(u, dialTimeout)
	if err != nil {
		return 0, false, ""
	}
	defer conn.Close()

	start := time.Now()
	if _, err := conn.Write([]byte(raw)); err != nil {
		return time.Since(start), false, ""
	}
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	r := bufio.NewReader(conn)
	line, err := r.ReadString('\n')
	elapsed = time.Since(start)
	if err != nil {
		// timeout ou conexão fechada sem resposta — é exatamente o sinal que
		// o teste de timing procura, não um erro a esconder.
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return elapsed, true, ""
		}
		return elapsed, false, ""
	}
	return elapsed, false, strings.TrimSpace(line)
}
