package intel

import (
	"net/url"
	"sort"
	"strings"

	"reconhub/internal/store"
)

// GroupKey is a coarser identity than store.Finding.Key(): (tool, type,
// host-of-asset). It collapses near-duplicate findings that differ only by
// path/query — e.g. scan-fuzz hitting the same soft-403 pattern on
// /admin/x and /admin/y is one story, not two — without touching the
// storage-level dedup/count semantics, which stay exact-key on purpose (the
// operator's Count and LastSeen must reflect reality, not a fuzzy cluster).
func GroupKey(f *store.Finding) string {
	return f.Tool + "\x00" + f.Type + "\x00" + hostOf(f.Asset)
}

// hostOf extracts a bare host from an asset value that may be a full URL
// ("https://a.com/x?y=1"), a bare host, or a "host:port". Falls back to the
// input unchanged if nothing host-shaped can be pulled out.
func hostOf(asset string) string {
	a := strings.TrimSpace(asset)
	if a == "" {
		return ""
	}
	if u, err := url.Parse(a); err == nil && u.Host != "" {
		return strings.ToLower(u.Host)
	}
	h := strings.ToLower(a)
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i+1:], "]") {
		h = h[:i] // corta :porta — mas não mexe num IPv6 sem colchetes
	}
	return h
}

// Group is a cluster of findings that share a GroupKey.
type Group struct {
	Key        string   `json:"key"`
	Tool       string   `json:"tool"`
	Type       string   `json:"type"`
	Host       string   `json:"host"`
	Severity   string   `json:"severity"` // a mais severa do grupo
	Titles     []string `json:"titles"`   // até 5 títulos distintos, pra dar contexto
	FindingIDs []string `json:"finding_ids"`
	Total      int      `json:"total"` // quantos findings distintos foram agrupados
}

// GroupSimilar clusters findings by GroupKey and returns only the clusters
// with more than one member — grouping only earns its place on screen when
// there's actually something to collapse. Sorted most-severe first.
func GroupSimilar(findings []*store.Finding) []Group {
	idx := map[string]*Group{}
	var order []string
	for _, f := range findings {
		k := GroupKey(f)
		g, ok := idx[k]
		if !ok {
			g = &Group{Key: k, Tool: f.Tool, Type: f.Type, Host: hostOf(f.Asset), Severity: f.Severity}
			idx[k] = g
			order = append(order, k)
		}
		if severityWeight[strings.ToLower(f.Severity)] > severityWeight[strings.ToLower(g.Severity)] {
			g.Severity = f.Severity
		}
		if len(g.Titles) < 5 {
			dup := false
			for _, t := range g.Titles {
				if t == f.Title {
					dup = true
					break
				}
			}
			if !dup {
				g.Titles = append(g.Titles, f.Title)
			}
		}
		g.FindingIDs = append(g.FindingIDs, f.ID)
		g.Total++
	}

	out := make([]Group, 0, len(order))
	for _, k := range order {
		if g := idx[k]; g.Total > 1 {
			out = append(out, *g)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return severityWeight[strings.ToLower(out[i].Severity)] > severityWeight[strings.ToLower(out[j].Severity)]
	})
	return out
}
