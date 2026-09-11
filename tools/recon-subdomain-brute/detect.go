package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"time"
)

// wildcardProbeCount random, virtually-guaranteed-nonexistent labels
// resolved BEFORE the real wordlist run. If they all resolve and share an
// IP, the domain has a DNS wildcard (catch-all): every possible subdomain
// "exists" from DNS's point of view, and brute-forcing without accounting
// for this would report thousands of fake subdomains that are really just
// the catch-all answering for anything. This is the #1 failure mode of a
// naive subdomain bruteforcer — real tools (subfinder, puredns, gobuster
// dns) all do this same check first.
const wildcardProbeCount = 3

func randLabel() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "rhx" + hex.EncodeToString(b[:])
}

// detectWildcard resolves wildcardProbeCount random subdomains of domain.
// If ALL resolve and share at least one IP, that shared set is the
// wildcard's signature (nil = no wildcard detected, either because a probe
// didn't resolve at all or the probes didn't agree on any IP).
func detectWildcard(ctx context.Context, r *net.Resolver, domain string, timeout time.Duration) map[string]bool {
	var common map[string]bool
	for i := 0; i < wildcardProbeCount; i++ {
		ips, err := resolveOne(ctx, r, randLabel()+"."+domain, timeout)
		if err != nil || len(ips) == 0 {
			return nil
		}
		set := map[string]bool{}
		for _, ip := range ips {
			set[ip] = true
		}
		if common == nil {
			common = set
			continue
		}
		common = intersect(common, set)
		if len(common) == 0 {
			return nil
		}
	}
	return common
}

func intersect(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}

// resolveOne resolves host to its A/AAAA IPs, bounded by timeout.
func resolveOne(ctx context.Context, r *net.Resolver, host string, timeout time.Duration) ([]string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return r.LookupHost(cctx, host)
}

// isWildcardHit reports whether ips is fully explained by the wildcard's
// signature — every IP the candidate resolved to is also one of the
// wildcard's IPs. A candidate that resolves to something OUTSIDE that set
// is still a real, distinct finding even on a wildcarded domain (a
// wildcard doesn't rule out a genuine subdomain configured to point
// somewhere else).
func isWildcardHit(ips []string, wildcard map[string]bool) bool {
	if len(wildcard) == 0 || len(ips) == 0 {
		return false
	}
	for _, ip := range ips {
		if !wildcard[ip] {
			return false
		}
	}
	return true
}

// buildResolver returns net.DefaultResolver, or a resolver pinned to a
// specific DNS server (ip or ip:port, default port 53) when the operator
// sets one via params.resolver — useful when the target's own authoritative
// nameservers rate-limit the system resolver's usual upstream.
func buildResolver(server string) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, network, server)
		},
	}
}
