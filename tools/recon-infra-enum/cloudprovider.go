package main

import (
	"context"
	"net"
	"strings"
	"time"
)

// cloudflareRanges is Cloudflare's own published edge-IP list
// (https://www.cloudflare.com/ips-v4/) — small and famously stable, worth
// hardcoding because, unlike most cloud/CDN traffic, a Cloudflare edge node
// doesn't reliably reveal itself via reverse DNS (the PTR is often silent,
// or belongs to the ORIGIN behind the proxy, not Cloudflare). Every other
// provider below is detected via PTR suffix instead of a hardcoded CIDR
// list on purpose: AWS/GCP/Azure/Akamai publish enormous range files that
// change constantly — embedding a snapshot here would go stale fast and,
// worse, risks confidently mislabeling a host based on data that was never
// verified against the real, current allocation. PTR is live: it's the
// provider's own DNS answering right now, not a guess from a stale list.
var cloudflareRanges = mustParseCIDRs([]string{
	"173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
	"141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
	"197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
	"104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
})

func mustParseCIDRs(cidrs []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}

// ptrProviderSuffix maps a reverse-DNS suffix to the provider/CDN it
// belongs to. Order doesn't matter — matched by strings.HasSuffix against
// the lowercased PTR name.
var ptrProviderSuffix = []struct{ suffix, provider string }{
	{"amazonaws.com", "AWS"},
	{"googleusercontent.com", "GCP"},
	{"cloud.google.com", "GCP"},
	{"azure.com", "Azure"},
	{"cloudapp.net", "Azure"},
	{"cloudapp.azure.com", "Azure"},
	{"azurewebsites.net", "Azure"},
	{"trafficmanager.net", "Azure"},
	{"digitalocean.com", "DigitalOcean"},
	{"linode.com", "Linode/Akamai Connected Cloud"},
	{"oraclecloud.com", "Oracle Cloud"},
	{"ovh.net", "OVH"},
	{"ovh.ca", "OVH"},
	{"fastly.net", "Fastly"},
	{"akamai.net", "Akamai"},
	{"akamaitechnologies.com", "Akamai"},
	{"akamaiedge.net", "Akamai"},
	{"herokuapp.com", "Heroku (AWS)"},
	{"herokudns.com", "Heroku (AWS)"},
	{"hetzner.com", "Hetzner"},
	{"your-server.de", "Hetzner"},
	{"vultr.com", "Vultr"},
	{"scw.cloud", "Scaleway"},
}

type cloudInfo struct {
	Provider string
	IP       string
	PTR      string
}

// detectCloud resolves host to an IP, tries reverse DNS (the primary,
// always-current signal), and falls back to Cloudflare's small stable CIDR
// list only when PTR comes up empty or unrecognized. Best-effort: a
// zero-value cloudInfo (Provider == "") means "couldn't tell", never
// "confirmed not cloud" — plenty of real cloud hosts have no matching PTR
// and aren't in the Cloudflare list. Treat a hit as a hint to prioritize
// investigation (which metadata endpoint to try, which misconfig is
// statistically likely), never as proof of anything on its own.
func detectCloud(host string, timeout time.Duration) cloudInfo {
	ip := host
	if net.ParseIP(host) == nil {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		addrs, err := net.DefaultResolver.LookupHost(ctx, host)
		cancel()
		if err != nil || len(addrs) == 0 {
			return cloudInfo{}
		}
		ip = addrs[0]
	}
	info := cloudInfo{IP: ip}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	names, err := net.DefaultResolver.LookupAddr(ctx, ip)
	cancel()
	if err == nil {
		provider, ptr := providerFromPTR(names)
		info.PTR = ptr
		if provider != "" {
			info.Provider = provider
			return info
		}
	}

	if parsed := net.ParseIP(ip); parsed != nil {
		if providerFromIP(parsed) != "" {
			info.Provider = providerFromIP(parsed)
		}
	}
	return info
}

// providerFromPTR checks a set of reverse-DNS names against
// ptrProviderSuffix and returns the first match, plus the first name seen
// (kept even without a match, so the caller can still show *some* PTR in
// its log even when it's not a recognized provider). Split out from
// detectCloud so it's testable without a real DNS resolver.
func providerFromPTR(names []string) (provider, firstPTR string) {
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(n, "."))
		if firstPTR == "" {
			firstPTR = n
		}
		for _, m := range ptrProviderSuffix {
			if strings.HasSuffix(n, m.suffix) {
				return m.provider, firstPTR
			}
		}
	}
	return "", firstPTR
}

// providerFromIP checks ip against the (small, Cloudflare-only) hardcoded
// CIDR fallback. Split out from detectCloud for the same testability
// reason as providerFromPTR.
func providerFromIP(ip net.IP) string {
	for _, r := range cloudflareRanges {
		if r.Contains(ip) {
			return "Cloudflare"
		}
	}
	return ""
}
