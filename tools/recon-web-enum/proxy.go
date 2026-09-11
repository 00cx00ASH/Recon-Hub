package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// applyProxy wires t to route through RECONHUB_PROXY_URL when set — the
// operator configures it once per project in the shared auth panel (Proxy
// field), injected the same way as RECONHUB_AUTH_*. Supports http://,
// https:// (Go's native CONNECT-tunnel proxying) and socks5:// (hand-rolled
// below: the project favors zero external deps, and the SOCKS5 handshake is
// small enough not to need a library — this is exactly what lets an operator
// route through Tor's local SOCKS port to rotate the exit IP after a block,
// without needing a paid rotating-proxy service).
func applyProxy(t *http.Transport, dialTimeout time.Duration) {
	raw := os.Getenv("RECONHUB_PROXY_URL")
	if raw == "" {
		return
	}
	u, err := url.Parse(raw)
	if err != nil {
		return
	}
	switch u.Scheme {
	case "http", "https":
		t.Proxy = http.ProxyURL(u)
	case "socks5":
		t.DialContext = socks5DialContext(u, dialTimeout)
	}
}

func socks5DialContext(proxyURL *url.URL, dialTimeout time.Duration) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: dialTimeout}
		conn, err := d.DialContext(ctx, "tcp", proxyURL.Host)
		if err != nil {
			return nil, fmt.Errorf("conectar no proxy socks5 %s: %w", proxyURL.Host, err)
		}
		if err := socks5Handshake(conn, proxyURL, addr, dialTimeout); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// socks5Handshake speaks just enough of RFC 1928 (+ username/password auth,
// RFC 1929) to CONNECT through a SOCKS5 proxy: no-auth or user/pass, IPv4/
// IPv6/domain-name target. Enough for Tor (no auth) and most SOCKS5
// providers (user/pass).
func socks5Handshake(conn net.Conn, proxyURL *url.URL, targetAddr string, handshakeTimeout time.Duration) error {
	// sem isso, um proxy que aceita a conexão TCP mas nunca responde ao
	// handshake (mal configurado, ou caiu no meio) trava a goroutine pra
	// sempre — o timeout do http.Client não alcança essa fase porque o
	// DialContext já teria retornado antes. Solta o deadline no fim: dali
	// pra frente o tráfego proxiado segue as regras normais do transport.
	if handshakeTimeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(handshakeTimeout))
		defer conn.SetDeadline(time.Time{})
	}
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("endereço de destino inválido %q: %w", targetAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return fmt.Errorf("porta de destino inválida %q", portStr)
	}

	user := proxyURL.User.Username()
	pass, hasPass := proxyURL.User.Password()

	methods := []byte{0x00} // no-auth
	if user != "" {
		methods = append(methods, 0x02) // user/pass
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		return fmt.Errorf("socks5 greeting: %w", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(conn, sel); err != nil {
		return fmt.Errorf("socks5 greeting response: %w", err)
	}
	if sel[0] != 0x05 {
		return fmt.Errorf("proxy não fala SOCKS5 (versão %d)", sel[0])
	}
	switch sel[1] {
	case 0x00:
		// sem auth, segue direto pro CONNECT
	case 0x02:
		if user == "" {
			return fmt.Errorf("proxy exige usuário/senha e o auth.proxy configurado não tem nenhum")
		}
		req := []byte{0x01, byte(len(user))}
		req = append(req, user...)
		if hasPass {
			req = append(req, byte(len(pass)))
			req = append(req, pass...)
		} else {
			req = append(req, 0x00)
		}
		if _, err := conn.Write(req); err != nil {
			return fmt.Errorf("socks5 auth: %w", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			return fmt.Errorf("socks5 auth response: %w", err)
		}
		if authResp[1] != 0x00 {
			return fmt.Errorf("proxy socks5 rejeitou usuário/senha")
		}
	case 0xff:
		return fmt.Errorf("proxy socks5 recusou todos os métodos de autenticação oferecidos")
	default:
		return fmt.Errorf("método de auth socks5 inesperado (0x%02x)", sel[1])
	}

	req := []byte{0x05, 0x01, 0x00} // ver, CONNECT, reserved
	if ip4 := net.ParseIP(host).To4(); ip4 != nil {
		req = append(req, 0x01)
		req = append(req, ip4...)
	} else if ip6 := net.ParseIP(host).To16(); ip6 != nil {
		req = append(req, 0x04)
		req = append(req, ip6...)
	} else {
		if len(host) > 255 {
			return fmt.Errorf("hostname longo demais pro SOCKS5: %q", host)
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socks5 connect: %w", err)
	}

	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fmt.Errorf("socks5 connect response: %w", err)
	}
	if head[1] != 0x00 {
		return fmt.Errorf("socks5 CONNECT falhou (código 0x%02x — %s)", head[1], socks5ReplyText(head[1]))
	}
	// consome o endereço "bound" que o servidor devolve (tamanho varia por tipo)
	var skip int
	switch head[3] {
	case 0x01:
		skip = net.IPv4len + 2
	case 0x04:
		skip = net.IPv6len + 2
	case 0x03:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(conn, lb); err != nil {
			return fmt.Errorf("socks5 bound addr len: %w", err)
		}
		skip = int(lb[0]) + 2
	default:
		return fmt.Errorf("tipo de endereço socks5 desconhecido (0x%02x)", head[3])
	}
	if skip > 0 {
		if _, err := io.ReadFull(conn, make([]byte, skip)); err != nil {
			return fmt.Errorf("socks5 bound addr: %w", err)
		}
	}
	return nil
}

func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "erro geral do servidor"
	case 0x02:
		return "conexão não permitida pelo ruleset"
	case 0x03:
		return "rede inalcançável"
	case 0x04:
		return "host inalcançável"
	case 0x05:
		return "conexão recusada"
	case 0x06:
		return "TTL expirado"
	case 0x07:
		return "comando não suportado"
	case 0x08:
		return "tipo de endereço não suportado"
	default:
		return "erro desconhecido"
	}
}
