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
	"strings"
	"sync"
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

// --- rotação automática de circuito (NEWNYM) ---

// withBlockRotation envolve rt pra contar respostas HTTP que parecem
// bloqueio (403/429) e pedir um circuito Tor novo (IP de saída novo)
// quando o streak cruza um threshold — automatiza o que antes exigia rodar
// `docker compose exec tor ... SIGNAL NEWNYM` na mão. É um no-op (devolve
// rt sem alterar) quando RECONHUB_PROXY_CONTROL_URL não está setada — a
// engine só injeta essa env var quando o Proxy do programa é socks5://
// (ver internal/project/auth.go), então chamar isso sem Tor configurado
// não muda nada. Chame sempre, logo depois de applyProxy.
func withBlockRotation(rt http.RoundTripper, onRotate func(string)) http.RoundTripper {
	// addr vazio = sem sidecar de Tor: ainda assim RESPEITAMOS o rate limit do
	// alvo (backoff no 429/503), só não temos como BYPASSAR (rotacionar
	// circuito). Por isso não retorna `rt` cru aqui como antes — o respeito ao
	// rate limit vale sempre, independente de Tor estar configurado ou não.
	addr := strings.TrimSpace(os.Getenv("RECONHUB_PROXY_CONTROL_URL"))
	threshold := 5
	if v := os.Getenv("RECONHUB_PROXY_BLOCK_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			threshold = n
		}
	}
	// teto do backoff por 429/503 — honra Retry-After mas nunca dorme mais que
	// isso (um Retry-After hostil tipo 9999 não pode travar o scan por horas).
	// 0 desliga o respeito a rate limit (opt-out explícito do operador).
	maxBackoff := 30 * time.Second
	if v := os.Getenv("RECONHUB_RATELIMIT_MAX_BACKOFF_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			maxBackoff = time.Duration(n) * time.Millisecond
		}
	}
	return &blockRotator{
		RoundTripper: rt,
		threshold:    threshold,
		controlAddr:  addr,
		cooldown:     20 * time.Second,
		maxBackoff:   maxBackoff,
		onRotate:     onRotate,
	}
}

type blockRotator struct {
	http.RoundTripper
	mu          sync.Mutex
	streak      int
	threshold   int
	controlAddr string
	cooldown    time.Duration
	maxBackoff  time.Duration
	lastRotate  time.Time
	onRotate    func(string)
}

func (b *blockRotator) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := b.RoundTripper.RoundTrip(req)
	if err != nil || resp == nil {
		return resp, err
	}
	// RESPEITAR o alvo: num 429/503, espera antes de devolver a resposta ao
	// worker que chamou — isso pausa naturalmente quem disparou a requisição
	// (o RoundTrip só retorna depois do sleep), honrando Retry-After quando o
	// servidor manda, limitado a maxBackoff. Vale com ou sem Tor.
	if d := b.backoffFor(resp); d > 0 {
		b.log(fmt.Sprintf("rate limit do alvo (HTTP %d) — aguardando %s antes de seguir", resp.StatusCode, d.Round(time.Millisecond)))
		time.Sleep(d)
	}
	// BYPASSAR (só com Tor): conta o streak de bloqueio e rotaciona circuito.
	b.observe(resp.StatusCode)
	return resp, err
}

// backoffFor devolve quanto esperar por causa de rate limit. Só 429/503
// contam; honra Retry-After (segundos ou HTTP-date), cai num padrão educado
// quando o servidor não diz, e nunca passa de maxBackoff.
func (b *blockRotator) backoffFor(resp *http.Response) time.Duration {
	if b.maxBackoff <= 0 {
		return 0
	}
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable {
		return 0
	}
	d := parseRetryAfter(resp.Header.Get("Retry-After"))
	if d <= 0 {
		d = 2 * time.Second // servidor não disse quanto — espera educada padrão
	}
	if d > b.maxBackoff {
		d = b.maxBackoff
	}
	return d
}

// parseRetryAfter interpreta o header Retry-After nos dois formatos do HTTP:
// um número de segundos, ou uma data absoluta. Devolve 0 pra vazio/inválido
// ou data no passado. Função pura (testável sem rede).
func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

func (b *blockRotator) observe(status int) {
	blocked := status == http.StatusForbidden || status == http.StatusTooManyRequests
	b.mu.Lock()
	if blocked {
		b.streak++
	} else {
		b.streak = 0
	}
	rotate := blocked && b.streak >= b.threshold && time.Since(b.lastRotate) > b.cooldown
	if rotate {
		b.streak = 0
		b.lastRotate = time.Now()
	}
	b.mu.Unlock()
	if !rotate {
		return
	}
	if err := torNewCircuit(b.controlAddr); err != nil {
		b.log(fmt.Sprintf("tentativa de trocar de circuito Tor falhou: %v", err))
	} else {
		b.log(fmt.Sprintf("bloqueio detectado (status %d) — circuito Tor trocado automaticamente", status))
	}
}

func (b *blockRotator) log(msg string) {
	if b.onRotate != nil {
		b.onRotate(msg)
	}
}

// torNewCircuit fala só o suficiente do protocolo de controle do Tor pra
// pedir um circuito novo: conecta, AUTHENTICATE "" (só é seguro porque o
// control port nunca é alcançável fora do container — ver
// docker/tor/torrc: CookieAuthentication 0 + ControlPort em 127.0.0.1),
// SIGNAL NEWNYM, QUIT. Um SOCKS5 que não seja o sidecar de Tor deste repo
// simplesmente falha aqui (porta fechada ou resposta inesperada) — sem
// travar o scan, só sem rotação automática.
func torNewCircuit(addr string) error {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("AUTHENTICATE \"\"\r\nSIGNAL NEWNYM\r\nQUIT\r\n")); err != nil {
		return err
	}
	buf := make([]byte, 512)
	n, rerr := conn.Read(buf)
	if n == 0 && rerr != nil {
		return rerr
	}
	if !strings.Contains(string(buf[:n]), "250") {
		return fmt.Errorf("resposta inesperada do control port: %s", strings.TrimSpace(string(buf[:n])))
	}
	return nil
}
