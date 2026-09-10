package main

import (
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const maxCNAMEHops = 10

// dnsResolver queries CNAME / A / AAAA records directly, so a broken chain
// (CNAME target that NXDOMAINs) is visible instead of being swallowed the way
// net.LookupCNAME would.
type dnsResolver struct {
	udp *dns.Client
	tcp *dns.Client
	ns  []string // "host:port"
}

func newDNSResolver(timeout time.Duration) *dnsResolver {
	var ns []string
	if cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf"); err == nil {
		port := cfg.Port
		if port == "" {
			port = "53"
		}
		for _, s := range cfg.Servers {
			ns = append(ns, net.JoinHostPort(s, port))
		}
	}
	if len(ns) == 0 {
		ns = []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}
	}
	return &dnsResolver{
		udp: &dns.Client{Net: "udp", Timeout: timeout},
		tcp: &dns.Client{Net: "tcp", Timeout: timeout},
		ns:  ns,
	}
}

// ask sends one question to each configured nameserver until one answers.
func (d *dnsResolver) ask(name string, qtype uint16) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true

	var lastErr error
	for _, srv := range d.ns {
		in, _, err := d.udp.Exchange(m, srv)
		if err != nil {
			lastErr = err
			continue
		}
		if in.Truncated {
			if in2, _, err2 := d.tcp.Exchange(m, srv); err2 == nil {
				return in2, nil
			}
		}
		return in, nil
	}
	return nil, lastErr
}

// cnameChain follows CNAME records from host. It returns the ordered list of
// CNAME *targets* (host itself excluded) and the rcode of the final lookup.
// An empty chain means host has no CNAME.
func (d *dnsResolver) cnameChain(host string) (chain []string, lastRcode int, err error) {
	name := host
	seen := map[string]bool{strings.ToLower(dns.Fqdn(host)): true}

	for hop := 0; hop < maxCNAMEHops; hop++ {
		msg, e := d.ask(name, dns.TypeCNAME)
		if e != nil {
			return chain, dns.RcodeServerFailure, e
		}
		lastRcode = msg.Rcode
		if msg.Rcode == dns.RcodeNameError { // NXDOMAIN
			return chain, lastRcode, nil
		}

		var target string
		for _, rr := range msg.Answer {
			if cn, ok := rr.(*dns.CNAME); ok {
				target = strings.TrimSuffix(cn.Target, ".")
				break
			}
		}
		if target == "" {
			return chain, lastRcode, nil // no further CNAME
		}
		chain = append(chain, target)

		key := strings.ToLower(dns.Fqdn(target))
		if seen[key] {
			return chain, lastRcode, nil // CNAME loop
		}
		seen[key] = true
		name = target
	}
	return chain, lastRcode, nil
}

// resolves reports whether name has an A/AAAA address. NXDOMAIN and NODATA both
// count as "does not resolve".
func (d *dnsResolver) resolves(name string) bool {
	for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg, err := d.ask(name, qt)
		if err != nil {
			continue
		}
		if msg.Rcode == dns.RcodeNameError {
			return false
		}
		for _, rr := range msg.Answer {
			switch rr.(type) {
			case *dns.A, *dns.AAAA:
				return true
			}
		}
	}
	return false
}
