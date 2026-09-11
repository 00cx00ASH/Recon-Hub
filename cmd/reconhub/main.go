// Command reconhub is the recon-hub orchestrator: it loads tool manifests,
// runs them as jobs, streams their output, stores findings, and serves the
// dashboard.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"reconhub/internal/api"
	"reconhub/internal/auth"
	"reconhub/internal/bus"
	"reconhub/internal/config"
	"reconhub/internal/engine"
	"reconhub/internal/monitor"
	"reconhub/internal/pipeline"
	"reconhub/internal/project"
	"reconhub/internal/registry"
	"reconhub/internal/scope"
	"reconhub/internal/scopetemplate"
	"reconhub/internal/store"
	"reconhub/internal/wordlist"
)

func main() {
	cfgPath := flag.String("config", envOr("RECONHUB_CONFIG", ""), "path to config.json")
	addr := flag.String("addr", "", "override listen address (host:port)")
	tokenFlag := flag.String("token", "", "API token (overrides env, config and the saved token file)")
	regenToken := flag.Bool("regen-token", false, "discard any existing token and generate a new one")
	noAuth := flag.Bool("no-auth", false, "disable the API token entirely (leaves the hub open)")
	noPortFallback := flag.Bool("no-port-fallback", false, "fail if the exact -addr port is taken (default: try the next free one)")
	storeFlag := flag.String("store", "", `storage backend: "files" (default) or "sqlite" (needs -tags sqlite build)`)
	migrateStore := flag.Bool("migrate-store", false, "import ./data (FileStore) into the SQLite database, then exit")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if *addr != "" {
		cfg.Addr = *addr
	}

	// Bind the port first — before touching data/, generating tokens or loading
	// anything — so we never print a token URL for a server that won't come up.
	// If the configured port is taken (a stale run, a Docker container…), walk
	// forward to the next free one instead of dying. -no-port-fallback forces
	// the exact port.
	ln, err := listenWithFallback(cfg.Addr, !*noPortFallback)
	if err != nil {
		if isAddrInUse(err) {
			p := portOf(cfg.Addr)
			if *noPortFallback {
				log.Printf("porta %s ocupada (--no-port-fallback)", cfg.Addr)
			} else {
				log.Printf("porta %s e as 20 seguintes estão todas ocupadas", cfg.Addr)
			}
			log.Printf("  veja quem é:  ss -ltnp | grep :%s   (ou: ps aux | grep reconhub · docker compose ps)", p)
			os.Exit(1)
		}
		log.Fatalf("listen %s: %v", cfg.Addr, err)
	}
	// a porta efetiva pode ter mudado
	cfg.Addr = ln.Addr().String()

	for _, d := range []string{cfg.DataDir, cfg.ToolsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			log.Fatalf("mkdir %s: %v", d, err)
		}
	}

	token, err := auth.Resolve(cfg.DataDir, *tokenFlag, os.Getenv("RECONHUB_TOKEN"), cfg.Token, *noAuth, *regenToken)
	if err != nil {
		log.Fatalf("token: %v", err)
	}

	backend := firstNonEmpty(*storeFlag, os.Getenv("RECONHUB_STORE"), cfg.Store)
	if *migrateStore {
		if err := store.Migrate(cfg.DataDir, cfg.SQLitePath); err != nil {
			log.Fatalf("migrate-store: %v", err)
		}
		log.Printf("migração concluída: %s (aponte o hub pra este arquivo com -store sqlite)",
			firstNonEmpty(cfg.SQLitePath, cfg.DataDir+"/reconhub.db"))
		return
	}
	st, err := store.New(cfg.DataDir, backend, cfg.SQLitePath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()
	if backend == "sqlite" {
		log.Printf("store: sqlite (%s)", firstNonEmpty(cfg.SQLitePath, cfg.DataDir+"/reconhub.db"))
	}

	reg, err := registry.Load(cfg.ToolsDir)
	if err != nil {
		log.Fatalf("registry: %v", err)
	}
	names := make([]string, 0, len(reg.List()))
	for _, t := range reg.List() {
		names = append(names, t.Name)
	}
	log.Printf("registry: %d ferramenta(s) de %s %v", len(names), cfg.ToolsDir, names)

	pipes, err := pipeline.Load(cfg.PipelinesDir)
	if err != nil {
		log.Fatalf("pipelines: %v", err)
	}
	pnames := make([]string, 0, len(pipes.List()))
	for _, p := range pipes.List() {
		pnames = append(pnames, p.Name)
	}
	log.Printf("pipelines: %d de %s %v", len(pnames), cfg.PipelinesDir, pnames)

	programs, err := scope.Load(cfg.ProgramsDir)
	if err != nil {
		log.Fatalf("programs: %v", err)
	}
	gnames := make([]string, 0, len(programs.List()))
	for _, p := range programs.List() {
		gnames = append(gnames, p.Name)
	}
	log.Printf("programs: %d de %s %v", len(gnames), cfg.ProgramsDir, gnames)
	for _, p := range programs.List() {
		if err := project.Init(cfg.DataDir, p.Name); err != nil {
			log.Printf("project init (%s): %v", p.Name, err)
		}
	}

	scopeTemplates, err := scopetemplate.Load(cfg.ScopeTemplatesDir)
	if err != nil {
		log.Fatalf("scope-templates: %v", err)
	}
	log.Printf("scope-templates: %d de %s", len(scopeTemplates.List()), cfg.ScopeTemplatesDir)

	wls, _ := wordlist.Load(cfg.WordlistsDir, cfg.SeclistsDir)
	log.Printf("wordlists: %d indexadas (%s%s)", len(wls.List()), cfg.WordlistsDir,
		map[bool]string{true: " + SecLists", false: ""}[cfg.SeclistsDir != ""])

	eng := engine.New(st, reg, bus.New(), cfg.MaxConcurrent)
	eng.Wordlists = wls
	eng.OnJobDone = func(job *store.Job) {
		if strings.TrimSpace(job.Program) == "" {
			return
		}
		if _, err := project.SyncFromStore(cfg.DataDir, job.Program, programs, st, reg); err != nil {
			log.Printf("project sync (%s): %v", job.Program, err)
		}
	}
	eng.AuthLookup = func(program string) []string {
		a, err := project.LoadAuth(cfg.DataDir, program)
		if err != nil || a.Empty() {
			return nil
		}
		var env []string
		if a.Cookie != "" {
			env = append(env, "RECONHUB_AUTH_COOKIE="+a.Cookie)
		}
		if a.Bearer != "" {
			env = append(env, "RECONHUB_AUTH_BEARER="+a.Bearer)
		}
		if len(a.Headers) > 0 {
			if b, merr := json.Marshal(a.Headers); merr == nil {
				env = append(env, "RECONHUB_AUTH_HEADERS="+string(b))
			}
		}
		if a.Proxy != "" {
			env = append(env, "RECONHUB_PROXY_URL="+a.Proxy)
		}
		return env
	}

	watches, err := monitor.Load(cfg.WatchesDir)
	if err != nil {
		log.Fatalf("watches: %v", err)
	}
	mh := monHub{pipes: pipes, progs: programs, st: st, eng: eng}
	mon := monitor.New(watches, mh, 30*time.Second)
	mon.FindingsForBrief = mh.briefs
	log.Printf("monitor: %d watch(es) de %s", len(watches.List()), cfg.WatchesDir)

	srv := &api.Server{
		Store:          st,
		Reg:            reg,
		Pipelines:      pipes,
		Programs:       programs,
		ScopeTemplates: scopeTemplates,
		Wordlists:      wls,
		Watches:        watches,
		Monitor:        mon,
		Engine:         eng,
		Token:          token,
		WebDir:         cfg.WebDir,
		DocsFile:       cfg.DocsFile,
		DataDir:        cfg.DataDir,
	}

	httpSrv := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	monCtx, monStop := context.WithCancel(context.Background())
	go mon.Run(monCtx)

	go func() {
		log.Printf("recon-hub ouvindo em http://%s", cfg.Addr)
		logAuth(token, cfg.Addr)
		if err := httpSrv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("http: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("encerrando…")
	monStop()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(ctx)
}

// logAuth reports the token situation. It only prints the token value when the
// hub generated it or read it from disk (the operator has no other way to learn
// it); a value the operator supplied is never echoed to the log.
func logAuth(t auth.Token, addr string) {
	// 0.0.0.0 / :: is a bind address, not something you open in a browser.
	browse := addr
	for _, p := range []string{"0.0.0.0:", "[::]:", ":"} {
		if strings.HasPrefix(addr, p) {
			browse = "127.0.0.1:" + strings.TrimPrefix(addr, p)
			break
		}
	}

	switch t.Source {
	case "disabled":
		log.Printf("AVISO: --no-auth — a API está ABERTA a quem alcançar %s", addr)
		log.Printf("abra:  http://%s/", browse)
	case "generated", "file":
		abs, _ := filepath.Abs(t.FilePath)
		verb := "gerado e salvo em"
		if t.Source == "file" {
			verb = "lido de"
		}
		log.Printf("token %s %s", verb, abs)
		log.Printf("┌─────────────────────────────────────────────────────────────")
		log.Printf("│ abra no navegador:  http://%s/#token=%s", browse, t.Value)
		log.Printf("│ (o token vai no #fragment — não é enviado ao servidor nem logado de novo)")
		log.Printf("└─────────────────────────────────────────────────────────────")
	default: // flag | env | config
		log.Printf("token via %s (não exibido) — abra http://%s/ e cole o token no campo do topo", t.Source, browse)
	}
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func isAddrInUse(err error) bool {
	return err != nil && (errors.Is(err, syscall.EADDRINUSE) ||
		strings.Contains(err.Error(), "address already in use"))
}

func portOf(addr string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil {
		return p
	}
	return addr
}

// listenWithFallback binds addr; if the port is taken and fallback is allowed,
// it tries the next 20 ports and returns the first that binds.
func listenWithFallback(addr string, fallback bool) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err == nil || !fallback || !isAddrInUse(err) {
		return ln, err
	}
	host, portStr, splitErr := net.SplitHostPort(addr)
	if splitErr != nil {
		return nil, err
	}
	base, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		return nil, err
	}
	for p := base + 1; p <= base+20; p++ {
		try := net.JoinHostPort(host, strconv.Itoa(p))
		if l, e := net.Listen("tcp", try); e == nil {
			log.Printf("porta %d ocupada — usando %d", base, p)
			return l, nil
		}
	}
	return nil, err
}

// monHub adapts the engine + store + registries to monitor.Hub.
type monHub struct {
	pipes *pipeline.Registry
	progs *scope.Registry
	st    store.Store
	eng   *engine.Engine
}

func (h monHub) Pipeline(name string) (pipeline.Pipeline, bool) { return h.pipes.Get(name) }

func (h monHub) Program(name string) (*scope.Program, error) {
	if strings.TrimSpace(name) == "" {
		return nil, nil
	}
	p, ok := h.progs.Get(name)
	if !ok {
		return nil, errors.New("programa desconhecido: " + name)
	}
	return &p, nil
}

func (h monHub) Submit(pl pipeline.Pipeline, target string, prog *scope.Program) (string, error) {
	run, err := h.eng.SubmitPipeline(pl, target, prog)
	if err != nil {
		return "", err
	}
	return run.ID, nil
}

func (h monHub) RunStatus(id string) (string, bool) {
	run, ok := h.st.GetPipelineRun(id)
	if !ok {
		return "", false
	}
	switch run.Status {
	case store.StatusSucceeded, store.StatusFailed, store.StatusCanceled:
		return run.Status, true
	}
	return run.Status, false
}

func (h monHub) FindingKeys(id string) []string {
	run, ok := h.st.GetPipelineRun(id)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range run.Steps {
		if s.JobID == "" {
			continue
		}
		fs, _ := h.st.ListFindings(store.FindingFilter{JobID: s.JobID, Limit: 100000})
		for _, f := range fs {
			if k := f.Key(); !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	return out
}

// jsAssetKinds are the asset kinds tools emit from parsing JS bundles
// (js-hunter's endpoints, recon-web-enum's crawled urls, …) — what a
// watch's JS-diff check compares between runs.
var jsAssetKinds = map[string]bool{"endpoint": true, "url": true}

func (h monHub) JSAssets(id string) []string {
	run, ok := h.st.GetPipelineRun(id)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, s := range run.Steps {
		if s.JobID == "" {
			continue
		}
		as, _ := h.st.ListAssets(store.AssetFilter{JobID: s.JobID, Limit: 100000})
		for _, a := range as {
			if !jsAssetKinds[a.Kind] || seen[a.Value] {
				continue
			}
			seen[a.Value] = true
			out = append(out, a.Value)
		}
	}
	return out
}

var sevWeight = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func (h monHub) briefs(id string, keys []string) []monitor.FindingBrief {
	want := make(map[string]bool, len(keys))
	for _, k := range keys {
		want[k] = true
	}
	run, ok := h.st.GetPipelineRun(id)
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []monitor.FindingBrief
	for _, s := range run.Steps {
		if s.JobID == "" {
			continue
		}
		fs, _ := h.st.ListFindings(store.FindingFilter{JobID: s.JobID, Limit: 100000})
		for _, f := range fs {
			k := f.Key()
			if want[k] && !seen[k] {
				seen[k] = true
				out = append(out, monitor.FindingBrief{
					Severity: f.Severity, Type: f.Type, Title: f.Title, Asset: f.Asset,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		wi, wj := sevWeight[out[i].Severity], sevWeight[out[j].Severity]
		if wi != wj {
			return wi < wj
		}
		return out[i].Title < out[j].Title
	})
	return out
}
