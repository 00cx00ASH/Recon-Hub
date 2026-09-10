// scan-mongodb — procura MongoDB acessível SEM autenticação. Fala o wire
// protocol (OP_MSG) direto: handshake `hello`, depois `listDatabases`. Se este
// funcionar sem credenciais, lista os bancos, as coleções e as CHAVES de um
// documento de amostra (nunca os valores). Contrato NDJSON no stdout.
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
)

func emit(e ev) {
	mu.Lock()
	defer mu.Unlock()
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
		flagTarget = flag.String("target", "", "host (ou host:porta)")
		flagHosts  = flag.String("hosts", "", "vários hosts por vírgula/linha")
		flagHostsF = flag.String("hosts-file", "", "arquivo, um host por linha")
		flagPorts  = flag.String("ports", "", "portas a testar (default 27017,27018)")
		flagConc   = flag.Int("concurrency", 0, "hosts em paralelo (0 = param/16)")
		flagTOms   = flag.Int("timeout-ms", 0, "timeout por conexão/comando (0 = param/6000)")
		flagSample = flag.Bool("sample", false, "ler as CHAVES de 1 documento por coleção de amostra")
		flagPretty = flag.Bool("pretty", false, "saída legível")
	)
	flag.Parse()
	pretty = *flagPretty
	defer out.Flush()

	pl := readPayload()
	timeout := time.Duration(pick(*flagTOms, intParam(pl.Params, "timeout_ms"), 6000)) * time.Millisecond
	conc := pick(*flagConc, intParam(pl.Params, "concurrency"), 16)
	doSample := *flagSample || boolParam(pl.Params, "sample")

	ports := parsePorts(firstNonEmpty(*flagPorts, strParam(pl.Params, "ports"), os.Getenv("RECONHUB_PARAM_PORTS")))
	if len(ports) == 0 {
		ports = []int{27017, 27018}
	}

	seen := map[string]bool{}
	var hosts []string
	add := func(s string) {
		h := cleanHost(s)
		if h != "" && !seen[h] {
			seen[h] = true
			hosts = append(hosts, h)
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
	emit(ev{Type: "log", Level: "info", Msg: fmt.Sprintf("%d host(s) × portas %v", len(hosts), ports)})

	type job struct{ host string }
	var (
		wg          sync.WaitGroup
		ch          = make(chan job)
		mu2         sync.Mutex
		done, finds int
	)
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				f := scanHost(j.host, ports, timeout, doSample)
				mu2.Lock()
				done++
				d := done
				finds += f
				mu2.Unlock()
				emit(ev{Type: "progress", Msg: fmt.Sprintf("%d/%d hosts", d, len(hosts))})
			}
		}()
	}
	for _, h := range hosts {
		ch <- job{h}
	}
	close(ch)
	wg.Wait()

	emit(ev{Type: "done", OK: true, Msg: fmt.Sprintf("%d host(s), %d finding(s)", len(hosts), finds)})
}

func scanHost(host string, ports []int, timeout time.Duration, doSample bool) int {
	finds := 0
	for _, port := range ports {
		addr := net.JoinHostPort(host, strconv.Itoa(port))

		// porta aberta?
		cc, err := net.DialTimeout("tcp", addr, timeout)
		if err != nil {
			continue
		}
		cc.Close()

		conn, err := dialMongo(addr, timeout)
		if err != nil {
			continue
		}
		hi, err := conn.hello()
		if err != nil {
			conn.close()
			emit(ev{Type: "log", Level: "info", Msg: addr + ": porta aberta mas não respondeu ao handshake MongoDB (" + err.Error() + ")"})
			continue
		}
		emit(ev{Type: "asset", Kind: "endpoint", Value: "mongodb://" + addr})
		version, _ := hi["version"].(string)
		setName, _ := hi["setName"].(string)
		meta := map[string]any{"host": host, "port": port, "version": version, "replica_set": setName}

		ldb, lerr := conn.listDatabases()
		switch {
		case lerr == nil && cmdOK(ldb):
			finds++
			dbs := dbNames(ldb)
			emitOpenMongo(addr, version, setName, dbs, meta)
			enumerate(conn, addr, dbs, doSample)
		case lerr == nil && isAuthError(ldb):
			emit(ev{Type: "finding", Severity: "info", FindingType: "mongodb-auth-required",
				Title: "MongoDB acessível mas exige autenticação: " + addr,
				Asset: "mongodb://" + addr,
				Evidence: fmt.Sprintf("handshake OK (versão %s%s), mas listDatabases retornou %q — auth está ativa (bom)",
					orDash(version), setSuffix(setName), errText(ldb)),
				Meta: meta})
		case lerr == nil:
			emit(ev{Type: "log", Level: "warn", Msg: addr + ": listDatabases falhou: " + errText(ldb)})
		default:
			emit(ev{Type: "log", Level: "warn", Msg: addr + ": listDatabases erro: " + lerr.Error()})
		}
		conn.close()
	}
	return finds
}

func emitOpenMongo(addr, version, setName string, dbs []string, meta map[string]any) {
	meta["databases"] = dbs
	emit(ev{
		Type: "finding", Severity: "critical", FindingType: "mongodb-no-auth",
		Title: "MongoDB SEM autenticação: " + addr,
		Asset: "mongodb://" + addr,
		Evidence: fmt.Sprintf("listDatabases funcionou sem credenciais (versão %s%s). Bancos: %s",
			orDash(version), setSuffix(setName), strings.Join(trimList(dbs, 30), ", ")),
		Meta: meta,
	})
}

func enumerate(conn *mongoConn, addr string, dbs []string, doSample bool) {
	sampled := false
	for _, db := range dbs {
		if systemDB(db) {
			continue
		}
		lc, err := conn.listCollections(db)
		if err != nil || !cmdOK(lc) {
			continue
		}
		colls := collNames(lc)
		emit(ev{Type: "asset", Kind: "endpoint", Value: "mongodb://" + addr + "/" + db})
		ev2 := ev{Type: "finding", Severity: "high", FindingType: "mongodb-database-exposed",
			Title:    fmt.Sprintf("banco '%s' legível sem auth em %s (%d coleção/ões)", db, addr, len(colls)),
			Asset:    "mongodb://" + addr + "/" + db,
			Evidence: "coleções: " + strings.Join(trimList(colls, 40), ", "),
			Meta:     map[string]any{"database": db, "collections": colls}}

		if doSample && !sampled && len(colls) > 0 {
			if fd, err := conn.findOne(db, colls[0]); err == nil && cmdOK(fd) {
				keys := firstDocKeys(fd)
				if len(keys) > 0 {
					ev2.Evidence += fmt.Sprintf(" · amostra de '%s': campos %s (valores NÃO lidos)", colls[0], strings.Join(trimList(keys, 25), ", "))
					ev2.Meta["sample_collection"] = colls[0]
					ev2.Meta["sample_fields"] = keys
					sampled = true
				}
			}
		}
		emit(ev2)
	}
}

// --- helpers ---

func parsePorts(s string) []int {
	var out []int
	for _, p := range splitList(s) {
		if n, err := strconv.Atoi(strings.TrimSpace(p)); err == nil && n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}

func cleanHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "mongodb://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.TrimPrefix(s, "https://")
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		s = s[:i]
	}
	// strip an explicit :port here — ports come from the ports param
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.Trim(s, ".")
}

func setSuffix(setName string) string {
	if setName == "" {
		return ""
	}
	return ", replica set " + setName
}

func orDash(s string) string {
	if s == "" {
		return "?"
	}
	return s
}

func trimList(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return append(s[:n:n], "…")
}

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
