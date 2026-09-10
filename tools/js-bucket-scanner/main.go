// js-bucket-scanner — acha referências a cloud storage no HTML/JS/source maps de
// uma página e testa cada bucket (LIST anônimo, privado ou inexistente).
//
// Entradas (precedência): stdin JSON {target,params} > flags > env RECONHUB_*.
// Emite eventos `asset` kind=bucket e `finding` conforme a exposição.
package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var scriptSrcRe = regexp.MustCompile(`(?i)<script[^>]+src\s*=\s*["']([^"']+)["']`)

type target struct {
	client  *http.Client
	probe   *http.Client
	doJS    bool
	doMaps  bool
	timeout time.Duration
}

func main() {
	cfg := parseConfig()
	out := newEmitter(cfg.pretty)
	defer out.flush()
	flushBeforeExit = out.flush

	if len(cfg.urls) == 0 {
		out.emit(event{Type: "error", Msg: "nada para varrer: informe target ou params.urls"})
		exit(2)
	}

	tc := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	tr := &http.Transport{TLSClientConfig: tc, DisableKeepAlives: true,
		DialContext: dialer(cfg.timeout)}
	t := &target{
		doJS: cfg.js, doMaps: cfg.maps, timeout: cfg.timeout,
		client: &http.Client{Timeout: cfg.timeout, Transport: tr},
		probe: &http.Client{Timeout: cfg.timeout, Transport: tr,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}

	out.emit(event{Type: "log", Level: "info",
		Msg: fmt.Sprintf("varrendo %d URL(s) — js=%v maps=%v", len(cfg.urls), cfg.js, cfg.maps)})

	// 1. coletar corpos (HTML + JS + maps) e extrair buckets
	found := map[string]bucketRef{}
	for _, u := range cfg.urls {
		for _, body := range t.gather(u, out) {
			for _, b := range extractBuckets(body) {
				if _, ok := found[b.id()]; !ok {
					found[b.id()] = b
					out.emit(event{Type: "asset", Kind: "bucket", Value: b.Provider + ":" + b.Name})
					out.emit(event{Type: "log", Level: "info", Msg: "bucket referenciado: " + b.Provider + ":" + b.Name})
				}
			}
		}
	}
	if len(found) == 0 {
		out.emit(event{Type: "done", OK: true, Msg: "nenhuma referência a bucket encontrada"})
		return
	}

	// 2. probar cada bucket
	list := make([]bucketRef, 0, len(found))
	for _, b := range found {
		list = append(list, b)
	}

	var (
		wg                  sync.WaitGroup
		jobs                = make(chan bucketRef)
		mu                  sync.Mutex
		open, missing, priv int
	)
	for i := 0; i < cfg.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range jobs {
				ex := t.probeBucket(b)
				mu.Lock()
				switch ex.State {
				case "open":
					open++
				case "missing":
					missing++
				case "private":
					priv++
				}
				mu.Unlock()
				emitExposure(out, b, ex, cfg.onlyExposed)
			}
		}()
	}
	for _, b := range list {
		jobs <- b
	}
	close(jobs)
	wg.Wait()

	out.emit(event{Type: "done", OK: true, Msg: fmt.Sprintf(
		"%d bucket(s): %d aberto(s), %d inexistente(s), %d privado(s)", len(list), open, missing, priv)})
}

// gather returns the bodies of pageURL plus its scripts and (optionally) maps.
func (t *target) gather(pageURL string, out *emitter) []string {
	var bodies []string
	base, err := url.Parse(pageURL)
	if err != nil {
		out.emit(event{Type: "log", Level: "warn", Msg: "URL inválida: " + pageURL})
		return bodies
	}

	html, _, ok := t.get(t.client, pageURL)
	if !ok {
		out.emit(event{Type: "log", Level: "warn", Msg: "sem resposta de " + pageURL})
		return bodies
	}
	bodies = append(bodies, html)
	if !t.doJS {
		return bodies
	}

	scripts := map[string]bool{}
	for _, m := range scriptSrcRe.FindAllStringSubmatch(html, -1) {
		if abs := resolve(base, m[1]); abs != "" {
			scripts[abs] = true
		}
	}
	for s := range scripts {
		js, _, ok := t.get(t.client, s)
		if !ok {
			continue
		}
		bodies = append(bodies, js)
		if t.doMaps {
			if mapBody := t.fetchMap(s, js); mapBody != "" {
				bodies = append(bodies, mapBody)
			}
		}
	}
	out.emit(event{Type: "log", Level: "info",
		Msg: fmt.Sprintf("%s: %d script(s)", pageURL, len(scripts))})
	return bodies
}

var sourceMapRe = regexp.MustCompile(`(?m)//# sourceMappingURL=(\S+)`)

func (t *target) fetchMap(jsURL, jsBody string) string {
	mapURL := jsURL + ".map"
	if m := sourceMapRe.FindStringSubmatch(jsBody); len(m) == 2 && !strings.HasPrefix(m[1], "data:") {
		if b, err := url.Parse(jsURL); err == nil {
			if abs := resolve(b, m[1]); abs != "" {
				mapURL = abs
			}
		}
	}
	body, status, ok := t.get(t.client, mapURL)
	if ok && status == 200 {
		return body
	}
	return ""
}

// applyAuth attaches the operator's shared auth context for this program —
// set once via PUT /api/programs/{name}/auth (internal/project.Auth),
// injected by the engine as env vars — to a request, but ONLY when it's
// going to the same host as the job's own target. get() below is shared
// between fetching the target's own page/JS and probing cloud-storage
// bucket URLs (S3, GCS, …) — the host check is what keeps the target's
// session cookie/token from leaking to those unrelated third-party hosts.
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

func (t *target) get(c *http.Client, u string) (body string, status int, ok bool) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return "", 0, false
	}
	req.Header.Set("User-Agent", "recon-hub/js-bucket-scanner")
	applyAuth(req)
	resp, err := c.Do(req)
	if err != nil {
		return "", 0, false
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	resp.Body.Close()
	return string(b), resp.StatusCode, true
}

// probeBucket issues one LIST-style request and classifies the response.
func (t *target) probeBucket(b bucketRef) exposure {
	u := probeURL(b)
	body, status, ok := t.get(t.probe, u)
	if !ok {
		return exposure{"unknown", "sem resposta de " + u}
	}
	if len(body) > 4096 {
		body = body[:4096]
	}
	return classify(b.Provider, status, body)
}

func probeURL(b bucketRef) string {
	const q = "/?list-type=2&max-keys=3"
	reg := func(def string) string {
		if b.Region != "" {
			return b.Region
		}
		return def
	}
	switch b.Provider {
	case "gcs":
		return "https://storage.googleapis.com/" + b.Name + "?list-type=2&max-keys=3"
	case "azure-blob":
		return "https://" + b.Name + ".blob.core.windows.net/?comp=list"
	case "r2":
		return "https://" + b.Name + ".r2.dev" + q
	case "do-spaces":
		return "https://" + b.Name + "." + reg("nyc3") + ".digitaloceanspaces.com" + q
	case "wasabi":
		return "https://" + b.Name + ".s3." + reg("us-east-1") + ".wasabisys.com" + q
	case "backblaze":
		return "https://" + b.Name + ".s3." + reg("us-west-002") + ".backblazeb2.com" + q
	case "linode":
		return "https://" + b.Name + "." + reg("us-east-1") + ".linodeobjects.com" + q
	case "scaleway":
		return "https://" + b.Name + ".s3." + reg("fr-par") + ".scw.cloud" + q
	case "alibaba-oss":
		return "https://" + b.Name + ".oss-" + reg("us-east-1") + ".aliyuncs.com" + q
	case "ibm-cos":
		return "https://" + b.Name + ".s3." + reg("us") + ".cloud-object-storage.appdomain.cloud" + q
	default: // aws-s3
		return "https://" + b.Name + ".s3.amazonaws.com" + q
	}
}

func emitExposure(out *emitter, b bucketRef, ex exposure, onlyExposed bool) {
	ref := b.Provider + ":" + b.Name
	meta := map[string]any{"provider": b.Provider, "bucket": b.Name, "region": b.Region, "state": ex.State}
	switch ex.State {
	case "open":
		out.emit(event{Type: "finding", Severity: "high", FindingType: "open-bucket",
			Title: "Bucket com LIST anônimo: " + ref, Asset: ref, Evidence: ex.Detail, Meta: meta})
	case "missing":
		out.emit(event{Type: "finding", Severity: "medium", FindingType: "bucket-takeover",
			Title: "Bucket referenciado não existe: " + ref, Asset: ref, Evidence: ex.Detail, Meta: meta})
	case "private":
		if onlyExposed {
			return
		}
		out.emit(event{Type: "finding", Severity: "info", FindingType: "bucket-reference",
			Title: "Bucket existe (privado): " + ref, Asset: ref, Evidence: ex.Detail, Meta: meta})
	default:
		out.emit(event{Type: "log", Level: "warn", Msg: ref + ": " + ex.Detail})
	}
}

func resolve(base *url.URL, ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || strings.HasPrefix(ref, "data:") || strings.HasPrefix(ref, "javascript:") {
		return ""
	}
	u, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(u)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	return abs.String()
}
