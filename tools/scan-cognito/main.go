// scan-cognito — acha identificadores de AWS Cognito no HTML/JS (User Pool ID,
// Identity Pool ID, app client IDs) e testa, só com leitura, se o Identity Pool
// entrega credenciais AWS a usuários NÃO autenticados (e confirma via
// sts:GetCallerIdentity). Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
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
	"regexp"
	"strconv"
	"strings"
	"sync"
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
	mu     sync.Mutex
	out    = bufio.NewWriter(os.Stdout)
	pretty bool
	client *http.Client
	finds  int
)

func emit(e ev) {
	mu.Lock()
	defer mu.Unlock()
	if e.Type == "finding" {
		finds++
	}
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
		flagTarget = flag.String("target", "", "URL da página")
		flagURLs   = flag.String("urls", "", "várias URLs por vírgula/linha")
		flagURLsF  = flag.String("urls-file", "", "arquivo, uma URL por linha")
		flagUP     = flag.String("user-pool-id", "", "User Pool ID (pula a extração)")
		flagIP     = flag.String("identity-pool-id", "", "Identity Pool ID (pula a extração)")
		flagRegion = flag.String("region", "", "região AWS (se não vier do pool id)")
		flagSignup = flag.Bool("test-signup", false, "testar se o app client aceita SignUp anônimo (não cria conta)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout req (0 = param/12000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 12000)) * time.Millisecond
	testSignup := *flagSignup || boolParam(pl.Params, "test_signup")

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
		DialContext:       (&net.Dialer{Timeout: timeout}).DialContext,
	}
	applyProxy(transport, timeout)
	client = &http.Client{
		Timeout:   timeout,
		Transport: withBlockRotation(transport, func(msg string) { emit(ev{Type: "log", Level: "info", Msg: msg}) }),
	}

	// identificadores diretos?
	direct := ids{
		UserPoolID:     firstNonEmpty(*flagUP, strParam(pl.Params, "user_pool_id"), os.Getenv("RECONHUB_PARAM_USER_POOL_ID")),
		IdentityPoolID: firstNonEmpty(*flagIP, strParam(pl.Params, "identity_pool_id"), os.Getenv("RECONHUB_PARAM_IDENTITY_POOL_ID")),
		Region:         firstNonEmpty(*flagRegion, strParam(pl.Params, "region")),
	}
	if direct.Region == "" {
		direct.Region = firstNonEmpty(regionOf(direct.UserPoolID), regionOf(direct.IdentityPoolID))
	}

	type finding struct {
		i      ids
		origin string
	}
	var configs []finding

	if !direct.empty() {
		configs = append(configs, finding{direct, "parâmetros"})
	}

	var pages []string
	seen := map[string]bool{}
	add := func(s string) {
		if u := normURL(s); u != "" && !seen[u] {
			seen[u] = true
			pages = append(pages, u)
		}
	}
	add(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	for _, s := range splitList(firstNonEmpty(*flagURLs, strParam(pl.Params, "urls"), os.Getenv("RECONHUB_PARAM_URLS"))) {
		add(s)
	}
	if f := firstNonEmpty(*flagURLsF, strParam(pl.Params, "urls_file"), os.Getenv("RECONHUB_PARAM_URLS_FILE")); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			for _, s := range splitList(string(b)) {
				add(s)
			}
		}
	}

	if direct.empty() && len(pages) == 0 {
		emit(ev{Type: "error", Msg: "informe target (URL) ou params.user_pool_id / identity_pool_id"})
		os.Exit(2)
	}

	for _, p := range pages {
		emit(ev{Type: "log", Level: "info", Msg: "lendo " + p})
		i := harvest(p)
		if i.empty() {
			emit(ev{Type: "log", Level: "info", Msg: "  sem Cognito em " + p})
			continue
		}
		configs = append(configs, finding{i, p})
	}
	if len(configs) == 0 {
		emit(ev{Type: "done", OK: true, Msg: "nenhum identificador Cognito encontrado"})
		return
	}

	for _, cfg := range configs {
		auditCognito(cfg.i, cfg.origin, testSignup)
	}
	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d config(s), %d finding(s)", len(configs), finds)})
}

func auditCognito(i ids, origin string, testSignup bool) {
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf(
		"Cognito em %s — região=%s userPool=%q identityPool=%q clients=%d",
		origin, i.Region, i.UserPoolID, i.IdentityPoolID, len(i.AppClientIDs))})
	emit(ev{Type: "finding", Severity: "info", FindingType: "cognito-identifiers-exposed",
		Title:    "identificadores Cognito expostos: " + nz(i.UserPoolID, i.IdentityPoolID),
		Asset:    nz(i.UserPoolID, i.IdentityPoolID),
		Evidence: "encontrados no cliente em " + origin + " (esperado; habilita as sondagens abaixo)",
		Meta: map[string]any{
			"origin": origin, "region": i.Region, "user_pool_id": i.UserPoolID,
			"identity_pool_id": i.IdentityPoolID, "app_client_ids": i.AppClientIDs,
		}})

	if i.IdentityPoolID != "" {
		auditIdentityPool(i)
	}
	if i.UserPoolID != "" {
		if len(i.AppClientIDs) > 0 {
			emit(ev{Type: "asset", Kind: "endpoint", Value: "cognito-user-pool:" + i.UserPoolID})
		}
		if testSignup {
			for _, cid := range i.AppClientIDs {
				auditSignup(i.Region, cid, i.UserPoolID)
			}
		}
	}
}

func auditIdentityPool(i ids) {
	region := nz(i.Region, regionOf(i.IdentityPoolID))
	if region == "" {
		return
	}
	endpoint := "https://cognito-identity." + region + ".amazonaws.com/"
	emit(ev{Type: "asset", Kind: "endpoint", Value: "cognito-identity-pool:" + i.IdentityPoolID})

	st, body, err := awsJSON(client, endpoint, "AWSCognitoIdentityService.GetId",
		mustJSON(map[string]string{"IdentityPoolId": i.IdentityPoolID}))
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "GetId falhou: " + err.Error()})
		return
	}
	v := classifyGetId(st, body)
	switch v.kind {
	case "identity-getid-denied":
		emit(ev{Type: "finding", Severity: "info", FindingType: "cognito-identity-locked",
			Title: "Identity Pool sem acesso anônimo: " + i.IdentityPoolID,
			Asset: i.IdentityPoolID, Evidence: v.note})
		return
	case "identity-absent", "unknown":
		emit(ev{Type: "log", Level: "info", Msg: "GetId (" + strconv.Itoa(st) + "): " + v.note})
		return
	}

	var gi struct{ IdentityId string }
	_ = json.Unmarshal([]byte(body), &gi)
	if gi.IdentityId == "" {
		return
	}

	st2, body2, err := awsJSON(client, endpoint, "AWSCognitoIdentityService.GetCredentialsForIdentity",
		mustJSON(map[string]string{"IdentityId": gi.IdentityId}))
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "GetCredentialsForIdentity falhou: " + err.Error()})
		return
	}
	cv := classifyGetCreds(st2, body2)
	switch cv.kind {
	case "no-unauth-role":
		emit(ev{Type: "finding", Severity: "info", FindingType: "cognito-identity-getid-open",
			Title:    "Identity Pool: GetId anônimo permitido, mas sem role não autenticada: " + i.IdentityPoolID,
			Asset:    i.IdentityPoolID,
			Evidence: "GetId retornou IdentityId " + gi.IdentityId + "; GetCredentialsForIdentity: " + cv.note})
		return
	case "credentials-denied", "unknown":
		emit(ev{Type: "log", Level: "info", Msg: "GetCredentialsForIdentity (" + strconv.Itoa(st2) + "): " + cv.note})
		return
	}

	// open-identity-credentials
	var cr struct {
		Credentials tempCreds
	}
	_ = json.Unmarshal([]byte(body2), &cr)
	evd := "GetCredentialsForIdentity anônimo retornou credenciais AWS temporárias (AccessKeyId " + cv.akid + ")"
	meta := map[string]any{
		"identity_pool_id": i.IdentityPoolID, "region": region,
		"access_key_id": cv.akid, "identity_id": gi.IdentityId,
	}
	if cr.Credentials.SecretKey != "" {
		if arn, acct, err := stsCallerIdentity(client, cr.Credentials); err == nil {
			evd += fmt.Sprintf(" — confirmado via sts:GetCallerIdentity: ARN=%s conta=%s", arn, acct)
			meta["sts_arn"] = arn
			meta["aws_account"] = acct
		} else {
			evd += " — sts:GetCallerIdentity: " + err.Error()
		}
	}
	emit(ev{Type: "finding", Severity: "high", FindingType: "open-cognito-identity-pool",
		Title:    "Identity Pool entrega credenciais AWS a usuários não autenticados: " + i.IdentityPoolID,
		Asset:    i.IdentityPoolID,
		Evidence: evd + ". Verifique as permissões da role não autenticada (S3, DynamoDB, etc).",
		Meta:     meta})
}

func auditSignup(region, clientID, userPool string) {
	if region == "" || clientID == "" {
		return
	}
	endpoint := "https://cognito-idp." + region + ".amazonaws.com/"
	// senha deliberadamente inválida -> nada é criado; só revela se SignUp é aceito
	st, body, err := awsJSON(client, endpoint, "AWSCognitoIdentityProviderService.SignUp",
		mustJSON(map[string]string{
			"ClientId": clientID,
			"Username": "reconhub-probe-" + randHex(6),
			"Password": "a", // rejeitada pela política -> conta não é criada
		}))
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "SignUp probe falhou: " + err.Error()})
		return
	}
	low := strings.ToLower(body)
	switch {
	case strings.Contains(low, "invalidpasswordexception"),
		strings.Contains(low, "invalidparameterexception") && strings.Contains(low, "password"):
		emit(ev{Type: "finding", Severity: "medium", FindingType: "cognito-open-signup",
			Title:    "Cognito User Pool aceita SignUp anônimo (app client " + clientID + ")",
			Asset:    "cognito-user-pool:" + userPool,
			Evidence: "SignUp com senha inválida foi rejeitado só pela política de senha (" + strings.TrimSpace(firstLine(body)) + ") — com uma senha válida, qualquer um cria conta. Nenhuma conta foi criada nesta checagem.",
			Meta:     map[string]any{"user_pool_id": userPool, "client_id": clientID, "http_status": st}})
	case strings.Contains(low, "notauthorizedexception"):
		emit(ev{Type: "finding", Severity: "info", FindingType: "cognito-signup-disabled",
			Title:    "Cognito User Pool: SignUp desabilitado no app client " + clientID,
			Asset:    "cognito-user-pool:" + userPool,
			Evidence: strings.TrimSpace(firstLine(body))})
	default:
		emit(ev{Type: "log", Level: "info", Msg: "SignUp probe (" + strconv.Itoa(st) + "): " + strings.TrimSpace(firstLine(body))})
	}
}

// harvest fetches page + <script src> and merges Cognito identifiers.
func harvest(pageURL string) ids {
	body, err := fetch(pageURL)
	if err != nil {
		emit(ev{Type: "log", Level: "warn", Msg: "  " + pageURL + ": " + err.Error()})
		return ids{}
	}
	acc := extractIdentifiers(body)
	n := 0
	for _, m := range scriptSrcRe.FindAllStringSubmatch(body, -1) {
		if acc.UserPoolID != "" && acc.IdentityPoolID != "" && len(acc.AppClientIDs) > 0 {
			break
		}
		if n >= 30 {
			break
		}
		abs := resolveRef(pageURL, m[1])
		if abs == "" || !strings.Contains(abs, ".js") {
			continue
		}
		n++
		if js, err := fetch(abs); err == nil {
			acc = mergeIDs(acc, extractIdentifiers(js))
		}
	}
	return acc
}

func mergeIDs(a, b ids) ids {
	if a.UserPoolID == "" {
		a.UserPoolID = b.UserPoolID
	}
	if a.IdentityPoolID == "" {
		a.IdentityPoolID = b.IdentityPoolID
	}
	for _, c := range b.AppClientIDs {
		a.AppClientIDs = appendUniq(a.AppClientIDs, c)
	}
	for _, r := range b.UserPoolRegions {
		a.UserPoolRegions = appendUniq(a.UserPoolRegions, r)
	}
	for _, r := range b.IdentityRegions {
		a.IdentityRegions = appendUniq(a.IdentityRegions, r)
	}
	if a.Region == "" {
		a.Region = b.Region
	}
	if a.Region == "" {
		a.Region = firstNonEmpty(regionOf(a.UserPoolID), regionOf(a.IdentityPoolID))
	}
	return a
}

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src=["']([^"']+)["']`)

// --- helpers ---

// applyAuth attaches the operator's shared auth context for this program —
// set once via PUT /api/programs/{name}/auth (internal/project.Auth),
// injected by the engine as env vars — to a request, but ONLY when it's
// going to the same host as the job's own target. Deliberately NOT used by
// aws.go's requests: those go to AWS's own STS/Cognito endpoints with their
// own SigV4 signing, a completely different auth scheme — the target's
// session cookie/token has no business going there.
func applyAuth(req *http.Request) {
	if !sameHostAsTarget(req.URL.Host) {
		return
	}
	if v := os.Getenv("RECONHUB_AUTH_COOKIE"); v != "" {
		req.Header.Set("Cookie", v)
	}
	if v := os.Getenv("RECONHUB_AUTH_BEARER"); v != "" {
		req.Header.Set("Authorization", "Bearer "+v)
	}
	if v := os.Getenv("RECONHUB_AUTH_HEADERS"); v != "" {
		var extra map[string]string
		if json.Unmarshal([]byte(v), &extra) == nil {
			for k, val := range extra {
				req.Header.Set(k, val)
			}
		}
	}
}

// sameHostAsTarget reports whether host matches RECONHUB_TARGET's host
// (port ignored). No RECONHUB_TARGET set (e.g. running outside the hub)
// doesn't block — there's nothing to compare against.
func sameHostAsTarget(host string) bool {
	t := strings.TrimSpace(os.Getenv("RECONHUB_TARGET"))
	if t == "" {
		return true
	}
	th := t
	if u, err := url.Parse(t); err == nil && u.Host != "" {
		th = u.Host
	}
	strip := func(h string) string {
		if i := strings.LastIndexByte(h, ':'); i >= 0 {
			h = h[:i]
		}
		return strings.ToLower(h)
	}
	return strip(host) == strip(th)
}

func fetch(u string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "recon-hub/scan-cognito")
	req.Header.Set("Accept", "text/html,application/javascript,*/*")
	applyAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return string(b), nil
}

func resolveRef(base, ref string) string {
	b, err := url.Parse(base)
	if err != nil {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return b.ResolveReference(r).String()
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strconv.FormatInt(time.Now().UnixNano(), 16)
	}
	return hex.EncodeToString(b)
}

func readPayload() payload {
	var p payload
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) != 0 {
		return p
	}
	b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4<<20))
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
	return s
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if t := strings.TrimSpace(v); t != "" {
			return t
		}
	}
	return ""
}

func nz(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func strParam(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func boolParam(m map[string]any, k string) bool {
	switch v := m[k].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}

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
