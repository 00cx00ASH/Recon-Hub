package main

import (
	"net"
	"strings"
)

// expandTargets turns a spec (host, IP, or CIDR) into a list of hosts.
// CIDR is capped at maxHosts to keep scans bounded.
func expandTargets(spec string, maxHosts int) ([]string, bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, false
	}
	if !strings.Contains(spec, "/") {
		return []string{cleanHost(spec)}, false
	}
	_, ipnet, err := net.ParseCIDR(spec)
	if err != nil {
		return []string{cleanHost(spec)}, false
	}
	var out []string
	capped := false
	ip := ipnet.IP.Mask(ipnet.Mask)
	for ipCopy := cloneIP(ip); ipnet.Contains(ipCopy); incIP(ipCopy) {
		out = append(out, ipCopy.String())
		if len(out) >= maxHosts {
			capped = true
			break
		}
	}
	// drop network + broadcast for a fully-enumerated IPv4 block
	if !capped && len(out) > 2 && ipnet.IP.To4() != nil {
		ones, bits := ipnet.Mask.Size()
		if bits-ones >= 2 {
			out = out[1 : len(out)-1]
		}
	}
	return out, true
}

func cloneIP(ip net.IP) net.IP {
	c := make(net.IP, len(ip))
	copy(c, ip)
	return c
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func cleanHost(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	for _, p := range []string{"http://", "https://", "tcp://", "mongodb://"} {
		s = strings.TrimPrefix(s, p)
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return strings.Trim(s, ".")
}
