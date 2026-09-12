// recon-infra-enum — port scan TCP (connect) + banner grab + fingerprint de
// serviço. Marca serviços sensíveis expostos (redis, mongodb, docker API,
// kube-apiserver, rdp, elastic, …). Aceita host, IP ou CIDR (limitado).
// Contrato NDJSON do recon-hub no stdout.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
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
		case "asset":
			fmt.Fprintln(out, "  ["+e.Kind+"] "+e.Value)
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
		flagTarget  = flag.String("target", "", "host, IP ou CIDR")
		flagHosts   = flag.String("hosts", "", "vários alvos por vírgula/linha")
		flagHostsF  = flag.String("hosts-file", "", "arquivo, um alvo por linha")
		flagPorts   = flag.String("ports", "", "top100 | top1000 | web | db | csv/ranges")
		flagConc    = flag.Int("concurrency", 0, "conexões simultâneas (0 = param/300)")
		flagTOms    = flag.Int("timeout-ms", 0, "timeout por conexão (0 = param/1500)")
		flagBanner  = flag.Bool("no-banner", false, "não fazer banner grab")
		flagNoCloud = flag.Bool("no-cloud-detect", false, "não tentar identificar o provedor cloud/CDN")
		flagMaxCIDR = flag.Int("max-hosts", 0, "teto de hosts por CIDR (0 = param/1024)")
		flagPretty  = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 1500)) * time.Millisecond
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 300)
	maxCIDR := pick(*flagMaxCIDR, intParam(pl.Params, "max_hosts"), 1024)
	doBanner := !*flagBanner && !boolParam(pl.Params, "no_banner")
	doCloud := !*flagNoCloud && !boolParam(pl.Params, "no_cloud_detect")
	ports := portSet(firstNonEmpty(*flagPorts, strParam(pl.Params, "ports"), os.Getenv("RECONHUB_PARAM_PORTS")))
	if len(ports) == 0 {
		emit(ev{Type: "error", Msg: "nenhuma porta válida no spec"})
		os.Exit(2)
	}

	seen := map[string]bool{}
	var hosts []string
	add := func(s string) {
		exp, isCIDR := expandTargets(s, maxCIDR)
		for _, h := range exp {
			if h != "" && !seen[h] {
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
		if isCIDR {
			emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%s → %d host(s)", s, len(exp))})
		}
	}
	add(firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET")))
	for _, s := range splitList(firstNonEmpty(*flagHosts, strParam(pl.Params, "hosts"), os.Getenv("RECONHUB_PARAM_HOSTS"))) {
		add(s)
	}
	if f := firstNonEmpty(*flagHostsF, strParam(pl.Params, "hosts_file"), os.Getenv("RECONHUB_PARAM_HOSTS_FILE")); f != "" {
		if b, err := os.ReadFile(f); err == nil {
			for _, s := range splitList(string(b)) {
				add(s)
			}
		}
	}
	if len(hosts) == 0 {
		emit(ev{Type: "error", Msg: "informe target ou params.hosts"})
		os.Exit(2)
	}
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d host(s) × %d porta(s) = %d conexões (timeout %s)",
		len(hosts), len(ports), len(hosts)*len(ports), timeout)})

	// fingerprint de provedor cloud/CDN por host — UMA vez por host (não por
	// porta), em paralelo mas com teto próprio (é resolução DNS/PTR, bem mais
	// barata que o port scan, mas sem motivo pra usar toda a concorrência do
	// scan de portas nisso).
	cloudByHost := map[string]cloudInfo{}
	if doCloud {
		cloudConc := conc
		if cloudConc > 50 {
			cloudConc = 50
		}
		var wgc sync.WaitGroup
		var muc sync.Mutex
		chc := make(chan string, cloudConc)
		for i := 0; i < cloudConc; i++ {
			wgc.Add(1)
			go func() {
				defer wgc.Done()
				for h := range chc {
					info := detectCloud(h, timeout)
					muc.Lock()
					cloudByHost[h] = info
					muc.Unlock()
				}
			}()
		}
		for _, h := range hosts {
			chc <- h
		}
		close(chc)
		wgc.Wait()
		for _, h := range hosts {
			if info := cloudByHost[h]; info.Provider != "" {
				emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%s → %s%s", h, info.Provider, ptrNote(info.PTR))})
			}
		}
	}

	type job struct {
		host string
		port int
	}
	ch := make(chan job, conc)
	var wg sync.WaitGroup
	var mu2 sync.Mutex
	var done, openCount int
	nJobs := len(hosts) * len(ports)

	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				addr := hostPort(j.host, j.port)
				conn, err := net.DialTimeout("tcp", addr, timeout)
				mu2.Lock()
				done++
				d := done
				mu2.Unlock()
				if d%2000 == 0 {
					emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d", d, nJobs)})
				}
				if err != nil {
					continue
				}

				banner := ""
				if doBanner {
					banner = grab(conn, j.port, timeout)
				}
				conn.Close()

				service, product := identify(j.port, banner)
				mu2.Lock()
				openCount++
				mu2.Unlock()

				emit(ev{Type: "asset", Kind: "port", Value: "tcp://" + addr})
				meta := map[string]any{"host": j.host, "port": j.port, "service": service}
				if product != "" {
					meta["product"] = product
				}
				if banner != "" {
					meta["banner"] = banner
				}
				if info := cloudByHost[j.host]; info.Provider != "" {
					meta["cloud_provider"] = info.Provider
				}
				emit(ev{Type: "finding", Severity: "info", FindingType: "open-port",
					Title:    fmt.Sprintf("%s: %s", j.host, portLabel(j.port, service, product)),
					Asset:    "tcp://" + addr,
					Evidence: bannerEvidence(banner),
					Meta:     meta})

				if ok, sev, note := notable(service, j.port); ok {
					evd := note
					if banner != "" {
						evd += " · banner: " + banner
					}
					emit(ev{Type: "finding", Severity: sev, FindingType: "exposed-service",
						Title:    fmt.Sprintf("serviço sensível exposto: %s em %s", service, addr),
						Asset:    "tcp://" + addr,
						Evidence: evd,
						Meta:     meta})
				}
			}
		}()
	}
	for _, h := range hosts {
		for _, p := range ports {
			ch <- job{h, p}
		}
	}
	close(ch)
	wg.Wait()

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d host(s), %d porta(s) aberta(s), %d finding(s)", len(hosts), openCount, finds)})
}

func ptrNote(ptr string) string {
	if ptr == "" {
		return ""
	}
	return " (PTR " + ptr + ")"
}

func bannerEvidence(b string) string {
	if b == "" {
		return "sem banner"
	}
	return "banner: " + b
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
