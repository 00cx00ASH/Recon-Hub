// scan-subdomain-takeover — detecta CNAME dangling / subdomain takeover.
//
// Para cada host: resolve o CNAME, casa contra fingerprints de serviços
// conhecidos e, se pedido, confirma pelo corpo HTTP. Fala o contrato NDJSON do
// recon-hub no stdout (log / progress / finding / done).
//
// Entradas (precedência): stdin JSON {target,params} > flags > env RECONHUB_*.
// Uso avulso:  echo ” | go run . -target exemplo.com -subs a.exemplo.com,b.exemplo.com
package main

import (
	"bufio"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed fingerprints.json
var fingerprintsJSON []byte

// Fingerprint identifica um serviço passível de takeover.
type Fingerprint struct {
	Service     string   `json:"service"`
	CNAME       []string `json:"cname"`       // padrões de substring no CNAME
	Fingerprint []string `json:"fingerprint"` // substrings no corpo HTTP que indicam "reclamável"
	NXDomain    bool     `json:"nxdomain"`    // vulnerável quando o alvo do CNAME dá NXDOMAIN
}

type payload struct {
	Target string         `json:"target"`
	Params map[string]any `json:"params"`
	JobID  string         `json:"job_id"`
}

func main() {
	var (
		flagTarget = flag.String("target", "", "host/apex a checar (fallback do stdin/env)")
		flagSubs   = flag.String("subs", "", "subdomínios separados por vírgula")
		flagSubsF  = flag.String("subs-file", "", "arquivo, um subdomínio por linha")
		flagConc   = flag.Int("concurrency", 0, "workers (0 = param/default 20)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout DNS/HTTP em ms (0 = param/default 7000)")
		flagNoHTTP = flag.Bool("no-http", false, "não confirmar via GET")
		flagOnlyOK = flag.Bool("only-confirmed", false, "só reportar takeover/dangling confirmado (esconde os avisos low)")
		flagPretty = flag.Bool("pretty", false, "saída legível em vez de NDJSON")
	)
	flag.Parse()

	out := newEmitter(*flagPretty)
	defer out.flush()

	var fps []Fingerprint
	if err := json.Unmarshal(fingerprintsJSON, &fps); err != nil {
		out.emit(event{Type: "error", Msg: "fingerprints.json inválido: " + err.Error()})
		os.Exit(1)
	}

	pl := readPayload()
	target := firstNonEmpty(pl.Target, *flagTarget, os.Getenv("RECONHUB_TARGET"))

	conc := *flagConc
	timeoutMS := *flagTOms
	httpCheck := !*flagNoHTTP
	onlyConfirmed := *flagOnlyOK
	subs := map[string]struct{}{}

	if pl.Params != nil {
		if conc == 0 {
			if v, ok := numParam(pl.Params, "concurrency"); ok {
				conc = v
			}
		}
		if timeoutMS == 0 {
			if v, ok := numParam(pl.Params, "timeout_ms"); ok {
				timeoutMS = v
			}
		}
		if v, ok := pl.Params["http"].(bool); ok && !*flagNoHTTP {
			httpCheck = v
		}
		if v, ok := pl.Params["only_confirmed"].(bool); ok && !*flagOnlyOK {
			onlyConfirmed = v
		}
		addSubs(subs, pl.Params["subdomains"])
		if s, _ := pl.Params["subdomains_file"].(string); s != "" && *flagSubsF == "" {
			*flagSubsF = s
		}
	}
	if *flagSubsF == "" {
		*flagSubsF = os.Getenv("RECONHUB_PARAM_SUBDOMAINS_FILE")
	}
	if conc <= 0 {
		conc = 20
	}
	if timeoutMS <= 0 {
		timeoutMS = 7000
	}
	for _, s := range strings.Split(*flagSubs, ",") {
		if s = clean(s); s != "" {
			subs[s] = struct{}{}
		}
	}
	if *flagSubsF != "" {
		if f, err := os.Open(*flagSubsF); err == nil {
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				if s := clean(sc.Text()); s != "" {
					subs[s] = struct{}{}
				}
			}
			f.Close()
		} else {
			out.emit(event{Type: "log", Level: "warn", Msg: "subs-file: " + err.Error()})
		}
	}
	if len(subs) == 0 && target != "" {
		subs[clean(target)] = struct{}{}
	}
	if len(subs) == 0 {
		out.emit(event{Type: "error", Msg: "nada para checar: informe target ou params.subdomains"})
		os.Exit(2)
	}

	hosts := sortedKeys(subs)
	timeout := time.Duration(timeoutMS) * time.Millisecond
	if conc > len(hosts) {
		conc = len(hosts)
	}
	out.emit(event{Type: "log", Level: "info",
		Msg: fmt.Sprintf("checando %d host(s) contra %d fingerprint(s) — %d worker(s), timeout %s", len(hosts), len(fps), conc, timeout)})

	sc := &scanner{
		fps:       fps,
		httpCheck: httpCheck,
		dns:       newDNSResolver(timeout),
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				DisableKeepAlives:   true,
				MaxIdleConnsPerHost: 1,
				DialContext:         (&net.Dialer{Timeout: timeout}).DialContext,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}

	var (
		wg          sync.WaitGroup
		jobs        = make(chan string)
		mu          sync.Mutex
		done        int
		hits, notes int // hits = takeover/dangling confirmado; notes = CNAME p/ serviço conhecido
	)
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				res := sc.check(h)

				mu.Lock()
				done++
				d := done
				switch res.kind {
				case kindVuln, kindDangling:
					hits++
				case kindLikely:
					notes++
				}
				mu.Unlock()

				if d%25 == 0 || d == len(hosts) {
					out.progress(fmt.Sprintf("%d/%d", d, len(hosts)), d, len(hosts))
				}
				emitResult(out, h, res, onlyConfirmed)
			}
		}()
	}
	for _, h := range hosts {
		jobs <- h
	}
	close(jobs)
	wg.Wait()

	msg := fmt.Sprintf("%d host(s), %d takeover/dangling", len(hosts), hits)
	if !onlyConfirmed {
		msg += fmt.Sprintf(", %d CNAME p/ serviço conhecido", notes)
	}
	out.emit(event{Type: "done", OK: true, Msg: msg})
}

// emitResult mapeia o veredito para um evento do contrato:
//
//	kindVuln     -> finding high  "subdomain-takeover"   (NXDOMAIN de serviço reclamável, ou corpo casa)
//	kindDangling -> finding medium "dangling-cname"      (NXDOMAIN, serviço desconhecido)
//	kindLikely   -> finding low   "cname-known-service"  (só um aviso; suprimido por only_confirmed)
func emitResult(out *emitter, host string, r result, onlyConfirmed bool) {
	switch r.kind {
	case kindVuln:
		out.emit(event{
			Type: "finding", Severity: "high", FindingType: "subdomain-takeover",
			Title:    fmt.Sprintf("Subdomain takeover: %s → %s", host, orUnknown(r.service)),
			Asset:    host,
			Evidence: r.evidence,
			Meta: map[string]any{
				"service": r.service, "cname": r.cname, "chain": r.chain,
				"http_status": r.status, "signal": r.signal,
			},
		})
	case kindDangling:
		out.emit(event{
			Type: "finding", Severity: "medium", FindingType: "dangling-cname",
			Title:    fmt.Sprintf("CNAME dangling: %s → %s (NXDOMAIN)", host, r.cname),
			Asset:    host,
			Evidence: r.evidence,
			Meta:     map[string]any{"cname": r.cname, "chain": r.chain, "signal": r.signal},
		})
	case kindLikely:
		if onlyConfirmed {
			return
		}
		out.emit(event{
			Type: "finding", Severity: "low", FindingType: "cname-known-service",
			Title:    fmt.Sprintf("CNAME para serviço conhecido: %s → %s", host, r.service),
			Asset:    host,
			Evidence: r.evidence + " — verifique manualmente se o recurso está livre",
			Meta: map[string]any{
				"service": r.service, "cname": r.cname, "chain": r.chain,
				"http_status": r.status, "signal": r.signal,
			},
		})
	case kindError:
		out.emit(event{Type: "log", Level: "warn", Msg: host + ": " + r.evidence})
	}
}
