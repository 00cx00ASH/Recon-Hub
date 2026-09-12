// scan-mass-assignment — mass assignment / over-posting (OWASP API3:2023,
// Broken Object Property Level Authorization). Testa se um endpoint que aceita
// um corpo JSON liga ("binda") campos privilegiados que o cliente não deveria
// poder setar — role, is_admin, verified, balance, etc. — só por mandá-los
// como campos extras no corpo. Cada sonda vai com um valor SENTINELA aleatório
// (nunca "admin"/"true"), então a ferramenta prova que o campo é BINDÁVEL sem
// NUNCA escalar privilégio de verdade (PoC-only): confirma comparando a
// resposta — o sentinela tem que voltar ligado à chave no objeto serializado
// pelo servidor, E um campo de controle bogus no mesmo corpo NÃO pode voltar
// (senão é eco cego do corpo, não bind). É o par de escrita do scan-privesc
// (que é leitura/execução de função); aqui é setar propriedade privilegiada.
// Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

type payload struct {
	Target string         `json:"target"`
	Params map[string]any `json:"params"`
	JobID  string         `json:"job_id"`
}

type ev struct {
	Type        string         `json:"type"`
	Level       string         `json:"level,omitempty"`
	Msg         string         `json:"msg,omitempty"`
	Kind        string         `json:"kind,omitempty"`
	Value       string         `json:"value,omitempty"`
	Severity    string         `json:"severity,omitempty"`
	FindingType string         `json:"finding_type,omitempty"`
	Title       string         `json:"title,omitempty"`
	Asset       string         `json:"asset,omitempty"`
	Evidence    string         `json:"evidence,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
	OK          bool           `json:"ok,omitempty"`
}

var (
	out    = bufio.NewWriter(os.Stdout)
	pretty bool
)

func emit(e ev) {
	if pretty {
		switch e.Type {
		case "finding":
			fmt.Fprintf(out, "[%s] %s\n        %s\n", strings.ToUpper(e.Severity), e.Title, e.Evidence)
		case "done":
			fmt.Fprintln(out, "done: "+e.Msg)
		case "error":
			fmt.Fprintln(out, "erro: "+e.Msg)
		default:
			lv := e.Level
			if lv == "" {
				lv = "info"
			}
			fmt.Fprintf(out, "[%s] %s\n", lv, e.Msg)
		}
	} else {
		b, _ := json.Marshal(e)
		out.Write(b)
		out.WriteByte('\n')
	}
	out.Flush()
}

func main() {
	var (
		flagTarget = flag.String("target", "", "URL do endpoint que aceita um corpo JSON (ex: .../api/users, .../api/account)")
		flagMethod = flag.String("method", "", "método HTTP do endpoint (POST/PUT/PATCH) — default POST")
		flagBody   = flag.String("body", "", "corpo JSON legítimo base (objeto) ao qual os campos privilegiados são somados")
		flagCType  = flag.String("content-type", "", "Content-Type do corpo — default application/json")
		flagCookie = flag.String("cookie", "", "Cookie da sessão de teste (conta comum, NUNCA admin/produção)")
		flagBearer = flag.String("bearer", "", "Bearer token da sessão de teste")
		flagFields = flag.String("fields", "", "lista CSV de campos privilegiados a testar (default: lista embutida)")
		flagPaceMs = flag.Int("pace-ms", 0, "pausa entre requisições em ms (0 = param/300)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout por requisição (0 = param/10000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 10000)) * time.Millisecond
	pace := time.Duration(pick(*flagPaceMs, intParam(pl.Params, "pace_ms"), 300)) * time.Millisecond

	target := normURL(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	if target == "" {
		emit(ev{Type: "error", Msg: "informe target — a URL do endpoint (que aceita corpo JSON) a testar"})
		os.Exit(2)
	}

	method := strings.ToUpper(firstNonEmpty(*flagMethod, strParam(pl.Params, "method"), os.Getenv("RECONHUB_PARAM_METHOD"), "POST"))
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		emit(ev{Type: "error", Msg: "method deve ser POST, PUT ou PATCH (mass assignment é sobre escrita de propriedade) — recebido: " + method})
		os.Exit(2)
	}
	contentType := firstNonEmpty(*flagCType, strParam(pl.Params, "content_type"), "application/json")
	cookie := firstNonEmpty(*flagCookie, strParam(pl.Params, "cookie"), os.Getenv("RECONHUB_PARAM_COOKIE"), os.Getenv("RECONHUB_AUTH_COOKIE"))
	bearer := firstNonEmpty(*flagBearer, strParam(pl.Params, "bearer"), os.Getenv("RECONHUB_PARAM_BEARER"), os.Getenv("RECONHUB_AUTH_BEARER"))

	// corpo base legítimo: os campos privilegiados são somados a ELE. Vazio vira
	// {} — funciona pra endpoint de criação que aceita objeto vazio, mas o ideal
	// é o operador colar um corpo válido (o que o app espera).
	base := map[string]any{}
	if raw := firstNonEmpty(*flagBody, strParam(pl.Params, "body")); raw != "" {
		if err := json.Unmarshal([]byte(raw), &base); err != nil {
			emit(ev{Type: "error", Msg: "body precisa ser um objeto JSON válido (ex: {\"name\":\"x\"}): " + err.Error()})
			os.Exit(2)
		}
	}

	fields := privilegedFields
	if csv := firstNonEmpty(*flagFields, strParam(pl.Params, "fields")); csv != "" {
		fields = splitCSV(csv)
	}

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
	}
	applyProxy(transport, timeout)
	client := &http.Client{
		Timeout:   timeout,
		Transport: withBlockRotation(transport, func(msg string) { emit(ev{Type: "log", Level: "info", Msg: msg}) }),
	}

	emit(ev{Type: "asset", Kind: "url", Value: target})
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("testando %d campos privilegiados via %s em %s (valores sentinela aleatórios — nunca escala de verdade)", len(fields), method, target)})

	hits := 0
	for i, field := range fields {
		if i > 0 {
			time.Sleep(pace)
		}
		fieldSentinel := "RHMA" + randToken()
		controlField := "rh_ctl_" + randToken()
		controlSentinel := "RHCTL" + randToken()

		body := cloneMap(base)
		body[field] = fieldSentinel
		body[controlField] = controlSentinel
		raw, err := json.Marshal(body)
		if err != nil {
			continue
		}

		respBody, status, err := sendProbe(client, method, target, contentType, cookie, bearer, raw)
		if err != nil {
			emit(ev{Type: "log", Level: "warn", Msg: "campo " + field + ": requisição falhou: " + err.Error()})
			continue
		}
		confirmed, echo, parsed := classifyMassAssignment(respBody, field, fieldSentinel, controlSentinel)
		if echo {
			emit(ev{Type: "log", Level: "info", Msg: "endpoint reflete o corpo inteiro de volta (campo de controle bogus voltou na resposta) — qualquer 'bind' aqui seria eco, não mass assignment real. Parando pra não gerar falso positivo."})
			break
		}
		if !parsed {
			emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("campo %s: resposta (status %d) não é JSON — sem como confirmar bind estruturalmente", field, status)})
			continue
		}
		if confirmed {
			hits++
			emit(ev{
				Type: "finding", Severity: "high", FindingType: "mass-assignment",
				Title:    "Mass assignment: o servidor bindou o campo privilegiado `" + field + "` do corpo (" + hostOf(target) + ")",
				Asset:    target,
				Evidence: fmt.Sprintf("enviei um %s em %s com o campo extra `%s` setado pra um valor sentinela aleatório; o servidor DEVOLVEU esse valor ligado à chave `%s` no objeto que serializou (status %d), enquanto um campo de controle bogus no MESMO corpo NÃO voltou. Isso prova que o bind automático aceita `%s` do cliente — não é eco cego do corpo. A escalada real (setar `%s` pra um valor de privilégio de verdade) é o passo manual seguinte, não feita aqui.", method, target, field, field, status, field, field),
				Meta: map[string]any{
					"field": field, "method": method, "status": status,
					"confirmed_by": "sentinel-value-bound-not-echoed",
				},
			})
		}
	}

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d campo(s) privilegiado(s) mass-assignable confirmado(s)", hits)})
}

// sendProbe manda o corpo JSON pelo método dado e devolve o corpo da resposta
// (limitado) + status. Lê o corpo porque a confirmação depende dele (o valor
// sentinela ligado à chave), mas nunca guarda dado real: o que procuramos é o
// nosso próprio token aleatório de volta.
func sendProbe(c *http.Client, method, u, contentType, cookie, bearer string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequest(method, u, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "recon-hub/scan-mass-assignment")
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	return b, resp.StatusCode, nil
}

func hostOf(u string) string {
	if p, err := url.Parse(u); err == nil {
		return strings.ToLower(p.Host)
	}
	return ""
}

// randToken devolve um token hex aleatório curto pros valores/nomes sentinela.
func randToken() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		// fallback determinístico-o-suficiente; o token só precisa ser único
		// na execução, não criptograficamente forte.
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func cloneMap(m map[string]any) map[string]any {
	c := make(map[string]any, len(m)+2)
	for k, v := range m {
		c[k] = v
	}
	return c
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// --- helpers (iguais aos das outras tools) ---

func readPayload() payload {
	var p payload
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) != 0 {
		return p
	}
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if s := strings.TrimSpace(string(b)); s != "" {
		_ = json.Unmarshal([]byte(s), &p)
	}
	return p
}

func normURL(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	if _, err := url.Parse(s); err != nil {
		return ""
	}
	return s
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func strParam(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func intParam(m map[string]any, k string) int {
	switch v := m[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n, _ := strconv.Atoi(v)
		return n
	}
	return 0
}

func pick(vs ...int) int {
	for _, v := range vs {
		if v > 0 {
			return v
		}
	}
	if len(vs) > 0 {
		return vs[len(vs)-1]
	}
	return 0
}
