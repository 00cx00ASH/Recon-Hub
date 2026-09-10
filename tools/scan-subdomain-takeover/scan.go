package main

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

type resultKind int

const (
	kindNone     resultKind = iota // nada de interessante
	kindVuln                       // takeover confirmado (NXDOMAIN de serviço, ou corpo casa)
	kindLikely                     // CNAME casa serviço conhecido mas sem confirmação
	kindDangling                   // alvo do CNAME dá NXDOMAIN, serviço desconhecido
	kindError                      // erro ao checar
)

type result struct {
	kind     resultKind
	service  string
	cname    string
	chain    []string
	status   int
	signal   string // nxdomain | fingerprint | cname
	evidence string
}

type scanner struct {
	fps       []Fingerprint
	httpCheck bool
	dns       *dnsResolver
	client    *http.Client
}

// check faz a parte de IO (DNS + HTTP) e delega a decisão a decide.
func (s *scanner) check(host string) result {
	host = clean(host)

	chain, lastRcode, err := s.dns.cnameChain(host)
	if err != nil && len(chain) == 0 {
		return result{kind: kindError, evidence: "DNS: " + err.Error()}
	}
	if len(chain) == 0 {
		return result{kind: kindNone} // host sem CNAME
	}
	target := chain[len(chain)-1]
	fp := matchCNAMEChain(chain, s.fps)

	cnameResolves := lastRcode != dns.RcodeNameError && s.dns.resolves(target)

	status, body := 0, ""
	httpDone := false
	if s.httpCheck && cnameResolves && fp != nil {
		status, body = s.probe(host)
		httpDone = true
	}

	res := decide(host, target, fp, cnameResolves, httpDone, status, body)
	res.chain = chain
	if res.kind != kindNone && len(chain) > 1 {
		res.evidence += " [cadeia: " + strings.Join(chain, " → ") + "]"
	}
	return res
}

// decide é pura: dados os fatos coletados, classifica o host.
func decide(host, cname string, fp *Fingerprint, cnameResolves, httpChecked bool, status int, body string) result {
	if !cnameResolves {
		if fp != nil {
			return result{
				kind: kindVuln, service: fp.Service, cname: cname, status: status, signal: "nxdomain",
				evidence: fmt.Sprintf("CNAME %s → %s; alvo retorna NXDOMAIN e %s é reclamável", host, cname, fp.Service),
			}
		}
		return result{
			kind: kindDangling, cname: cname, signal: "nxdomain",
			evidence: fmt.Sprintf("CNAME %s → %s; alvo do CNAME retorna NXDOMAIN", host, cname),
		}
	}

	if fp == nil {
		return result{kind: kindNone}
	}

	// serviço conhecido, alvo resolve.
	if !httpChecked {
		if fp.NXDomain {
			// serviço só é vulnerável via NXDOMAIN — e ele resolve. Não é takeover.
			return result{kind: kindNone}
		}
		return result{
			kind: kindLikely, service: fp.Service, cname: cname, signal: "cname",
			evidence: fmt.Sprintf("CNAME %s → %s casa com %s (verificação HTTP desativada)", host, cname, fp.Service),
		}
	}

	if matchBody(body, fp) {
		return result{
			kind: kindVuln, service: fp.Service, cname: cname, status: status, signal: "fingerprint",
			evidence: fmt.Sprintf("CNAME %s → %s; HTTP %d e o corpo casa o fingerprint de %s", host, cname, status, fp.Service),
		}
	}
	if fp.NXDomain {
		// Serviço só é vulnerável via NXDOMAIN; o alvo resolve e o corpo não
		// confirmou — alguém provavelmente já é dono. Não sinaliza.
		return result{kind: kindNone}
	}
	if status == 0 {
		return result{
			kind: kindLikely, service: fp.Service, cname: cname, signal: "cname",
			evidence: fmt.Sprintf("CNAME %s → %s casa com %s; host não respondeu HTTP", host, cname, fp.Service),
		}
	}
	return result{
		kind: kindLikely, service: fp.Service, cname: cname, status: status, signal: "cname",
		evidence: fmt.Sprintf("CNAME %s → %s casa com %s; HTTP %d mas o corpo não confirma", host, cname, fp.Service, status),
	}
}

// probe tenta https:// e depois http://, devolve status e até 64 KiB de corpo.
func (s *scanner) probe(host string) (int, string) {
	for _, scheme := range []string{"https://", "http://"} {
		req, err := http.NewRequest(http.MethodGet, scheme+host, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "recon-hub/scan-subdomain-takeover")
		resp, err := s.client.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	return 0, ""
}

func matchCNAMEChain(chain []string, fps []Fingerprint) *Fingerprint {
	for _, name := range chain {
		if fp := matchCNAME(name, fps); fp != nil {
			return fp
		}
	}
	return nil
}

func matchCNAME(cname string, fps []Fingerprint) *Fingerprint {
	lc := strings.ToLower(cname)
	for i := range fps {
		for _, pat := range fps[i].CNAME {
			if pat != "" && strings.Contains(lc, strings.ToLower(pat)) {
				return &fps[i]
			}
		}
	}
	return nil
}

func matchBody(body string, fp *Fingerprint) bool {
	if fp == nil || len(fp.Fingerprint) == 0 || body == "" {
		return false
	}
	lb := strings.ToLower(body)
	for _, needle := range fp.Fingerprint {
		if needle != "" && strings.Contains(lb, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}
