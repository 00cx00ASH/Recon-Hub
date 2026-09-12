// recon-subdomain-brute — enumeração ATIVA de subdomínio: gera candidatos
// prefixo+domínio a partir de uma wordlist e resolve DNS de verdade.
// Complementa recon-passive-enum/recon-crtsh (100% passivos — só acham o
// que já foi publicado em algum lugar, como Certificate Transparency); este
// aqui acha o que NUNCA apareceu publicamente, só existe no DNS do alvo.
//
// Detecta DNS wildcard (catch-all) ANTES de gastar a wordlist inteira — ver
// detect.go — pra não devolver milhares de "achados" que são só o
// catch-all do domínio respondendo pra QUALQUER prefixo.
//
// Não fala HTTP com o alvo — só resolução DNS — então não usa
// proxy.go/applyProxy: mesma exceção documentada em docs/TOOL_CONTRACT.md
// pra ferramentas que não usam http.Client de verdade (ex: scan-mongodb,
// que fala wire protocol cru).
//
// Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type payload struct {
	Target string         `json:"target"`
	Params map[string]any `json:"params"`
}

type ev struct {
	Type  string         `json:"type"`
	Level string         `json:"level,omitempty"`
	Msg   string         `json:"msg,omitempty"`
	Kind  string         `json:"kind,omitempty"`
	Value string         `json:"value,omitempty"`
	Meta  map[string]any `json:"meta,omitempty"`
	OK    bool           `json:"ok,omitempty"`
}

var (
	mu     sync.Mutex
	out    = bufio.NewWriter(os.Stdout)
	pretty bool
)

func emit(e ev) {
	mu.Lock()
	defer mu.Unlock()
	if pretty {
		switch e.Type {
		case "asset":
			fmt.Fprintln(out, "  "+e.Value)
		case "done":
			fmt.Fprintln(out, "done: "+e.Msg)
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

// embedded fallback — usado só se nenhuma wordlist for resolvida. Prefixos
// clássicos cobrindo infra, dev/staging, API, admin, storage, monitoring,
// e serviços de infra comumente expostos por engano.
var builtinWords = []string{
	"www", "mail", "webmail", "smtp", "pop", "pop3", "imap", "ftp",
	"sftp", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
	"mx", "mx1", "mx2", "autodiscover", "autoconfig", "remote", "vpn", "vpn1",
	"ssh", "rdp", "citrix", "ras", "gateway", "proxy", "firewall", "router",
	"switch", "api", "api1", "api2", "apiv1", "apiv2", "api-dev", "api-staging",
	"api-prod", "api-test", "apis", "rest", "restapi", "graphql", "grpc", "ws",
	"wss", "socket", "websocket", "gateway-api", "dev", "dev1", "dev2", "develop",
	"development", "staging", "stage", "stg", "test", "test1", "test2", "testing",
	"qa", "qa1", "uat", "preprod", "pre-prod", "sandbox", "sandboxes", "demo",
	"beta", "alpha", "canary", "preview", "next", "admin", "administrator", "admins",
	"panel", "cpanel", "whm", "webadmin", "adminpanel", "portal", "dashboard", "manage",
	"management", "console", "control", "cms", "backend", "back-office", "backoffice", "internal",
	"intranet", "extranet", "private", "secure", "cdn", "cdn1", "cdn2", "static",
	"static1", "assets", "media", "img", "images", "photos", "video", "videos",
	"files", "file", "upload", "uploads", "download", "downloads", "s3", "storage",
	"backup", "backups", "archive", "archives", "cache", "auth", "auth1", "sso",
	"login", "signin", "signup", "register", "oauth", "oauth2", "idp", "identity",
	"accounts", "account", "user", "users", "profile", "session", "token", "grafana",
	"kibana", "prometheus", "metrics", "status", "statuspage", "monitor", "monitoring", "health",
	"healthcheck", "logs", "logging", "elk", "sentry", "jenkins", "ci", "cd",
	"cicd", "build", "builds", "pipeline", "git", "gitlab", "github", "bitbucket",
	"svn", "repo", "repository", "jira", "confluence", "wiki", "docs", "documentation",
	"help", "support", "kb", "knowledgebase", "faq", "blog", "news", "press",
	"careers", "jobs", "shop", "store", "cart", "checkout", "payment", "payments",
	"billing", "invoice", "invoicing", "crm", "erp", "hr", "finance", "legal",
	"m", "mobile", "app", "apps", "webapp", "web", "old", "old-site",
	"new", "new-site", "legacy", "archive-site", "origin", "edge", "lb", "loadbalancer",
	"node", "node1", "node2", "worker", "workers", "queue", "db", "database",
	"mysql", "postgres", "postgresql", "redis", "mongo", "mongodb", "elastic", "elasticsearch",
	"kafka", "rabbitmq", "consul", "zookeeper", "vault", "etcd", "k8s", "kubernetes",
	"docker", "registry", "image-registry", "chat", "chatbot", "support-chat", "socket-io", "push",
	"notifications", "notify", "webhook", "webhooks", "events", "event", "analytics", "stats",
	"statistics", "tracking", "tag", "tags", "pixel", "ads", "adserver", "marketing",
	"partner", "partners", "affiliate", "affiliates", "reseller", "vendor", "vendors", "supplier",
	"b2b", "b2c", "sandbox-api", "mock", "mockapi", "stub", "demo-api", "public",
	"public-api", "external", "extern", "corp", "corporate", "office", "office365", "sharepoint",
	"onedrive", "teams", "slack", "zoom", "meet", "video-call", "webinar", "survey",
	"forms", "form", "feedback", "review", "reviews", "rating", "ratings", "search",
	"elastic-search", "solr", "es", "cache1", "cache2", "cluster", "cluster1", "zone1",
	"zone2", "region1", "region2", "eu", "us", "apac", "uat1", "uat2",
	"integration", "integrations", "connector", "connectors", "sync", "migrate", "migration", "tools",
	"utils", "util", "scripts", "cron", "jobs-runner", "scheduler", "worker-queue",
}

func main() {
	var (
		flagTarget = flag.String("target", "", "domínio raiz alvo")
		flagWL     = flag.String("wordlist", "", "caminho de wordlist de prefixos")
		flagWords  = flag.String("words", "", "prefixos extra (csv)")
		flagResolv = flag.String("resolver", "", "DNS server ip[:porta] (default: resolver do sistema)")
		flagConc   = flag.Int("concurrency", 0, "workers (0 = param/50)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout por resolução em ms (0 = param/3000)")
		flagMaxW   = flag.Int("max-words", 0, "teto de prefixos testados (0 = param/20000)")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	domain := cleanHost(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	if domain == "" {
		emit(ev{Type: "error", Msg: "informe o domínio raiz alvo"})
		os.Exit(2)
	}
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 3000)) * time.Millisecond
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 50)
	maxWords := pick(*flagMaxW, intParam(pl.Params, "max_words"), 20000)
	resolverAddr := firstNonEmpty(*flagResolv, strParam(pl.Params, "resolver"), os.Getenv("RECONHUB_PARAM_RESOLVER"))
	resolver := buildResolver(resolverAddr)

	wlPath := firstNonEmpty(*flagWL, strParam(pl.Params, "wordlist"), os.Getenv("RECONHUB_PARAM_WORDLIST"))
	words := builtinWords
	wlSrc := "embutida"
	if wlPath != "" {
		if lines, err := readLines(wlPath); err == nil && len(lines) > 0 {
			words = lines
			wlSrc = wlPath
		} else if err != nil {
			emit(ev{Type: "log", Level: "warn", Msg: "wordlist '" + wlPath + "' não lida (" + err.Error() + ") — usando lista embutida"})
		}
	}
	words = mergeWords(*flagWords+"\n"+strParam(pl.Params, "words"), words)
	if len(words) > maxWords {
		words = words[:maxWords]
	}

	ctx := context.Background()

	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("checando DNS wildcard em %s antes de testar %d prefixo(s) (wordlist=%s)", domain, len(words), wlSrc)})
	wildcard := detectWildcard(ctx, resolver, domain, timeout)
	if len(wildcard) > 0 {
		ips := make([]string, 0, len(wildcard))
		for ip := range wildcard {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		emit(ev{Type: "log", Level: "warn", Msg: fmt.Sprintf(
			"DNS wildcard detectado (catch-all responde pra qualquer prefixo com %s) — subdomínios que resolverem só pra esse IP são filtrados, não é falso positivo do wordlist",
			strings.Join(ips, ","))})
	}

	type hit struct {
		host string
		ips  []string
	}
	var (
		wg               sync.WaitGroup
		ch               = make(chan string)
		mu2              sync.Mutex
		done, found, dup int
		hits             = map[string]bool{}
	)
	worker := func() {
		defer wg.Done()
		for w := range ch {
			host := w + "." + domain
			ips, err := resolveOne(ctx, resolver, host, timeout)
			mu2.Lock()
			done++
			d := done
			mu2.Unlock()
			if d%100 == 0 || d == len(words) {
				emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d prefixos", d, len(words))})
			}
			if err != nil || len(ips) == 0 {
				continue
			}
			if isWildcardHit(ips, wildcard) {
				continue
			}
			mu2.Lock()
			if hits[host] {
				dup++
				mu2.Unlock()
				continue
			}
			hits[host] = true
			found++
			mu2.Unlock()
			sort.Strings(ips)
			emit(ev{Type: "asset", Kind: "subdomain", Value: host, Meta: map[string]any{"ip": ips}})
		}
	}
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go worker()
	}
	for _, w := range words {
		ch <- w
	}
	close(ch)
	wg.Wait()

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d prefixo(s) testado(s), %d subdomínio(s) resolvido(s)", len(words), found)})
}

// --- helpers ---

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

func cleanHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "*.")
	if i := strings.IndexAny(s, "/:"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		out = append(out, ln)
	}
	return out, nil
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t'
	})
}

// mergeWords mescla prefixos extra (csv/linha) com a wordlist base,
// deduplicando preservando ordem.
func mergeWords(extra string, base []string) []string {
	seen := map[string]bool{}
	var merged []string
	add := func(s string) {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		merged = append(merged, s)
	}
	for _, s := range splitList(extra) {
		add(s)
	}
	for _, s := range base {
		add(s)
	}
	return merged
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
