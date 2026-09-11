// Package report turns stored findings into a bug-bounty-ready report
// (Markdown or standalone HTML). Each finding gets a submission section:
// title, severity, affected asset, description, steps to reproduce, impact,
// remediation and references — from a per-type knowledge base (templates.go),
// with a generic fallback so nothing is dropped.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"sort"
	"strings"
	"time"
)

// Item is the subset of store.Finding the report needs (kept dep-free).
type Item struct {
	Type     string
	Severity string
	Title    string
	Asset    string
	Evidence string
	Tool     string
	Target   string
	Count    int
	FirstAt  time.Time
	LastAt   time.Time
	Meta     map[string]any
}

// Section is one rendered finding.
type Section struct {
	ID          string   `json:"id"` // e.g. "F-01"
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Severity    string   `json:"severity"`
	Asset       string   `json:"asset"`
	CWE         string   `json:"cwe,omitempty"`
	Description string   `json:"description"`
	Repro       []string `json:"repro"`
	Impact      string   `json:"impact"`
	Remediation string   `json:"remediation"`
	Refs        []string `json:"refs,omitempty"`
	Evidence    string   `json:"evidence,omitempty"`
	Tool        string   `json:"tool,omitempty"`
	Occurrences int      `json:"occurrences,omitempty"`
	FirstSeen   string   `json:"first_seen,omitempty"`
	LastSeen    string   `json:"last_seen,omitempty"`
	Templated   bool     `json:"templated"`
}

// ChainCandidate is a combination of two or more findings in this report
// that's worth more read together than either is alone — see
// internal/intel.DetectChains, which computes these; report only knows how
// to render what it's handed (kept dependency-free from intel, same as the
// rest of this package). Assets names the affected hosts/URLs so a reader
// can find the matching sections above without needing raw finding IDs,
// which don't survive into the rendered report (sections get sequential
// F-01/F-02 IDs instead).
type ChainCandidate struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Explanation string   `json:"explanation"`
	Assets      []string `json:"assets,omitempty"`
}

// Report is the assembled document.
type Report struct {
	Program         string           `json:"program,omitempty"`
	Target          string           `json:"target,omitempty"`
	Generated       string           `json:"generated_at"`
	Counts          map[string]int   `json:"counts_by_severity"`
	Total           int              `json:"total"`
	Sections        []Section        `json:"sections"`
	ChainCandidates []ChainCandidate `json:"chain_candidates,omitempty"`
	skipped         int              // findings with no reportable value (info + no template)
}

var sevRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

func sevWeight(s string) int {
	if r, ok := sevRank[strings.ToLower(s)]; ok {
		return r
	}
	return 5
}

// Build assembles a report from findings. `includeInfo` keeps info-severity
// findings that have no template (as short notes); by default they're dropped.
func Build(program, target string, items []Item, includeInfo bool) Report {
	r := Report{
		Program:   program,
		Target:    target,
		Generated: time.Now().UTC().Format(time.RFC3339),
		Counts:    map[string]int{},
	}

	// most severe first, then by type, then by asset
	sort.SliceStable(items, func(i, j int) bool {
		if wi, wj := sevWeight(items[i].Severity), sevWeight(items[j].Severity); wi != wj {
			return wi < wj
		}
		if items[i].Type != items[j].Type {
			return items[i].Type < items[j].Type
		}
		return items[i].Asset < items[j].Asset
	})

	n := 0
	for _, it := range items {
		t, ok := lookup(it.Type)
		sevLow := strings.ToLower(it.Severity)
		if !ok && sevLow == "info" && !includeInfo {
			r.skipped++
			continue
		}
		n++
		sec := Section{
			ID:          fmt.Sprintf("F-%02d", n),
			Type:        it.Type,
			Severity:    sevLow,
			Asset:       it.Asset,
			Evidence:    it.Evidence,
			Tool:        it.Tool,
			Occurrences: it.Count,
			Templated:   ok,
		}
		if !it.FirstAt.IsZero() {
			sec.FirstSeen = it.FirstAt.UTC().Format("2006-01-02")
		}
		if !it.LastAt.IsZero() {
			sec.LastSeen = it.LastAt.UTC().Format("2006-01-02")
		}
		if ok {
			sec.Name = t.Name
			sec.CWE = t.CWE
			sec.Description = t.Description
			sec.Impact = t.Impact
			sec.Remediation = t.Remediation
			sec.Refs = t.Refs
			if t.Repro != nil {
				sec.Repro = t.Repro(it)
			} else {
				sec.Repro = genericRepro(it)
			}
		} else {
			sec.Name = fallbackName(it)
			sec.Description = "Finding reportado pela ferramenta `" + it.Tool + "` (tipo `" + it.Type + "`). " +
				"Sem template dedicado — a evidência abaixo é a base da análise."
			sec.Impact = "A avaliar com base na evidência e no contexto do alvo."
			sec.Remediation = "A definir conforme a causa raiz identificada na reprodução."
			sec.Repro = genericRepro(it)
		}
		r.Sections = append(r.Sections, sec)
		r.Counts[sevLow]++
	}
	r.Total = len(r.Sections)
	return r
}

// Skipped reports how many info-only findings were left out.
func (r Report) Skipped() int { return r.skipped }

func fallbackName(it Item) string {
	if it.Title != "" {
		return it.Title
	}
	return strings.ReplaceAll(it.Type, "-", " ")
}

// --- Markdown ---

// Markdown renders the report for pasting into a platform (HackerOne, Intigriti…).
func (r Report) Markdown() string {
	var b strings.Builder
	title := "Relatório de recon"
	if r.Program != "" {
		title += " — " + r.Program
	} else if r.Target != "" {
		title += " — " + r.Target
	}
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "_Gerado em %s pelo recon-hub._\n\n", r.Generated)

	fmt.Fprintf(&b, "## Resumo\n\n")
	fmt.Fprintf(&b, "**%d finding(s)** reportável(is)", r.Total)
	if len(r.Counts) > 0 {
		fmt.Fprintf(&b, " — %s", severityLine(r.Counts))
	}
	b.WriteString(".\n\n")
	if r.skipped > 0 {
		fmt.Fprintf(&b, "_(%d finding(s) informativo(s) sem impacto direto foram omitidos.)_\n\n", r.skipped)
	}

	if len(r.ChainCandidates) > 0 {
		fmt.Fprintf(&b, "## Possíveis encadeamentos\n\n")
		b.WriteString("_Achado isolado às vezes é descartável, mas combinado com outro pode mudar de categoria — " +
			"confirme manualmente antes de reportar, isto aqui é um candidato, não uma confirmação de impacto._\n\n")
		for _, c := range r.ChainCandidates {
			fmt.Fprintf(&b, "**%s** (%s) — %s\n\n", c.Title, badge(c.Severity), c.Explanation)
			if len(c.Assets) > 0 {
				fmt.Fprintf(&b, "Assets envolvidos: %s\n\n", strings.Join(c.Assets, ", "))
			}
		}
	}

	if r.Total > 0 {
		b.WriteString("| # | Severidade | Finding | Asset |\n|---|---|---|---|\n")
		for _, s := range r.Sections {
			fmt.Fprintf(&b, "| %s | %s | %s | `%s` |\n", s.ID, badge(s.Severity), s.Name, s.Asset)
		}
		b.WriteString("\n")
	}

	for _, s := range r.Sections {
		fmt.Fprintf(&b, "---\n\n## %s — %s\n\n", s.ID, s.Name)
		fmt.Fprintf(&b, "- **Severidade:** %s\n", badge(s.Severity))
		if s.Asset != "" {
			fmt.Fprintf(&b, "- **Asset afetado:** `%s`\n", s.Asset)
		}
		if s.CWE != "" {
			fmt.Fprintf(&b, "- **Classe:** %s\n", s.CWE)
		}
		if s.Occurrences > 1 {
			fmt.Fprintf(&b, "- **Ocorrências:** %d\n", s.Occurrences)
		}
		if s.FirstSeen != "" {
			fmt.Fprintf(&b, "- **Detectado:** %s", s.FirstSeen)
			if s.LastSeen != "" && s.LastSeen != s.FirstSeen {
				fmt.Fprintf(&b, " (visto até %s)", s.LastSeen)
			}
			b.WriteString("\n")
		}
		if s.Tool != "" {
			fmt.Fprintf(&b, "- **Ferramenta:** `%s`\n", s.Tool)
		}
		b.WriteString("\n")

		fmt.Fprintf(&b, "### Descrição\n\n%s\n\n", s.Description)

		b.WriteString("### Passos para reproduzir\n\n")
		for i, step := range s.Repro {
			fmt.Fprintf(&b, "%d. %s\n", i+1, step)
		}
		b.WriteString("\n")

		if s.Evidence != "" {
			fmt.Fprintf(&b, "### Evidência\n\n```\n%s\n```\n\n", s.Evidence)
		}
		fmt.Fprintf(&b, "### Impacto\n\n%s\n\n", s.Impact)
		fmt.Fprintf(&b, "### Correção\n\n%s\n\n", s.Remediation)
		if len(s.Refs) > 0 {
			b.WriteString("### Referências\n\n")
			for _, ref := range s.Refs {
				fmt.Fprintf(&b, "- %s\n", ref)
			}
			b.WriteString("\n")
		}
		if !s.Templated {
			b.WriteString("> _Sem template dedicado para este tipo — revise descrição, impacto e correção antes de submeter._\n\n")
		}
	}
	return b.String()
}

func severityLine(c map[string]int) string {
	order := []string{"critical", "high", "medium", "low", "info"}
	var parts []string
	for _, k := range order {
		if c[k] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", c[k], k))
		}
	}
	return strings.Join(parts, ", ")
}

func badge(sev string) string {
	switch sev {
	case "critical":
		return "🔴 Critical"
	case "high":
		return "🟠 High"
	case "medium":
		return "🟡 Medium"
	case "low":
		return "🔵 Low"
	default:
		return "⚪ Info"
	}
}

// --- HTML ---

// HTML renders a self-contained page (dark, printable to PDF).
func (r Report) HTML() string {
	var b strings.Builder
	title := "Relatório de recon"
	if r.Program != "" {
		title += " — " + r.Program
	} else if r.Target != "" {
		title += " — " + r.Target
	}
	b.WriteString(`<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	fmt.Fprintf(&b, "<title>%s</title>", html.EscapeString(title))
	b.WriteString(`<style>
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font:15px/1.6 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
main{max-width:860px;margin:0 auto;padding:2.4rem 1.4rem 5rem}
h1{font-size:1.7rem;margin:.2rem 0 .3rem}
h2{font-size:1.25rem;margin:2.2rem 0 .6rem;border-bottom:1px solid #2a2f3a;padding-bottom:.3rem}
h3{font-size:1rem;margin:1.2rem 0 .4rem;color:#9aa4b2;text-transform:uppercase;letter-spacing:.04em}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
code{background:#1b1f27;padding:.1rem .35rem;border-radius:3px;font-size:.86em}
pre{background:#1b1f27;border:1px solid #2a2f3a;border-radius:6px;padding:.8rem;overflow-x:auto;font-size:.82rem}
a{color:#7aa2f7}
.muted{color:#8b93a1}
table{border-collapse:collapse;width:100%;margin:.6rem 0;font-size:.9rem}
th,td{border:1px solid #2a2f3a;padding:.45rem .6rem;text-align:left;vertical-align:top}
th{background:#161a22;color:#9aa4b2}
.sev{display:inline-block;font-size:.72rem;font-weight:700;padding:.12rem .5rem;border-radius:999px;letter-spacing:.03em}
.critical{background:#7f1d1d;color:#fecaca}.high{background:#7c2d12;color:#fed7aa}
.medium{background:#78350f;color:#fde68a}.low{background:#1e3a8a;color:#bfdbfe}.info{background:#334155;color:#cbd5e1}
.card{border:1px solid #2a2f3a;border-radius:8px;padding:1rem 1.2rem;margin:1.4rem 0}
.meta{list-style:none;padding:0;margin:.2rem 0 .6rem;font-size:.88rem;color:#b6bdc9}
.meta li{margin:.15rem 0}
ol{padding-left:1.3rem}ol li{margin:.35rem 0}
.notmpl{border-left:3px solid #78350f;background:#1b1710;padding:.5rem .8rem;font-size:.85rem;color:#fde68a;border-radius:0 4px 4px 0}
@media print{body{background:#fff;color:#111}main{max-width:none}pre,code{background:#f4f4f5}h2{border-color:#ddd}th,td,.card{border-color:#ccc}th{background:#f4f4f5}}
</style></head><body><main>`)

	fmt.Fprintf(&b, "<h1>%s</h1>", html.EscapeString(title))
	fmt.Fprintf(&b, `<p class="muted">Gerado em %s pelo recon-hub.</p>`, r.Generated)

	fmt.Fprintf(&b, "<h2>Resumo</h2><p><b>%d finding(s)</b> reportável(is)", r.Total)
	if len(r.Counts) > 0 {
		fmt.Fprintf(&b, " — %s", html.EscapeString(severityLine(r.Counts)))
	}
	b.WriteString(".</p>")
	if r.skipped > 0 {
		fmt.Fprintf(&b, `<p class="muted">%d finding(s) informativo(s) omitido(s).</p>`, r.skipped)
	}

	if len(r.ChainCandidates) > 0 {
		b.WriteString("<h2>Possíveis encadeamentos</h2>")
		b.WriteString(`<p class="muted">Achado isolado às vezes é descartável, mas combinado com outro pode mudar de categoria — confirme manualmente antes de reportar, isto aqui é um candidato, não uma confirmação de impacto.</p>`)
		for _, c := range r.ChainCandidates {
			b.WriteString(`<div class="card">`)
			fmt.Fprintf(&b, `<p><b>%s</b> <span class="sev %s">%s</span></p>`,
				html.EscapeString(c.Title), c.Severity, strings.ToUpper(c.Severity))
			fmt.Fprintf(&b, "<p>%s</p>", html.EscapeString(c.Explanation))
			if len(c.Assets) > 0 {
				fmt.Fprintf(&b, "<p class=\"muted\">Assets envolvidos: %s</p>", html.EscapeString(strings.Join(c.Assets, ", ")))
			}
			b.WriteString("</div>")
		}
	}

	if r.Total > 0 {
		b.WriteString("<table><thead><tr><th>#</th><th>Sev</th><th>Finding</th><th>Asset</th></tr></thead><tbody>")
		for _, s := range r.Sections {
			fmt.Fprintf(&b, `<tr><td>%s</td><td><span class="sev %s">%s</span></td><td>%s</td><td><code>%s</code></td></tr>`,
				s.ID, s.Severity, strings.ToUpper(s.Severity), html.EscapeString(s.Name), html.EscapeString(s.Asset))
		}
		b.WriteString("</tbody></table>")
	}

	for _, s := range r.Sections {
		b.WriteString(`<div class="card">`)
		fmt.Fprintf(&b, `<h2 style="border:0;margin-top:0">%s — %s</h2>`, s.ID, html.EscapeString(s.Name))
		b.WriteString(`<ul class="meta">`)
		fmt.Fprintf(&b, `<li><b>Severidade:</b> <span class="sev %s">%s</span></li>`, s.Severity, strings.ToUpper(s.Severity))
		if s.Asset != "" {
			fmt.Fprintf(&b, "<li><b>Asset afetado:</b> <code>%s</code></li>", html.EscapeString(s.Asset))
		}
		if s.CWE != "" {
			fmt.Fprintf(&b, "<li><b>Classe:</b> %s</li>", html.EscapeString(s.CWE))
		}
		if s.Occurrences > 1 {
			fmt.Fprintf(&b, "<li><b>Ocorrências:</b> %d</li>", s.Occurrences)
		}
		if s.FirstSeen != "" {
			fmt.Fprintf(&b, "<li><b>Detectado:</b> %s</li>", s.FirstSeen)
		}
		if s.Tool != "" {
			fmt.Fprintf(&b, "<li><b>Ferramenta:</b> <code>%s</code></li>", html.EscapeString(s.Tool))
		}
		b.WriteString("</ul>")

		fmt.Fprintf(&b, "<h3>Descrição</h3><p>%s</p>", html.EscapeString(s.Description))
		b.WriteString("<h3>Passos para reproduzir</h3><ol>")
		for _, step := range s.Repro {
			fmt.Fprintf(&b, "<li>%s</li>", mdInline(step))
		}
		b.WriteString("</ol>")
		if s.Evidence != "" {
			fmt.Fprintf(&b, "<h3>Evidência</h3><pre>%s</pre>", html.EscapeString(s.Evidence))
		}
		fmt.Fprintf(&b, "<h3>Impacto</h3><p>%s</p>", html.EscapeString(s.Impact))
		fmt.Fprintf(&b, "<h3>Correção</h3><p>%s</p>", html.EscapeString(s.Remediation))
		if len(s.Refs) > 0 {
			b.WriteString("<h3>Referências</h3><ul>")
			for _, ref := range s.Refs {
				e := html.EscapeString(ref)
				fmt.Fprintf(&b, `<li><a href="%s">%s</a></li>`, e, e)
			}
			b.WriteString("</ul>")
		}
		if !s.Templated {
			b.WriteString(`<p class="notmpl">Sem template dedicado — revise antes de submeter.</p>`)
		}
		b.WriteString("</div>")
	}
	b.WriteString("</main></body></html>")
	return b.String()
}

// mdInline does a tiny `code` → <code> and **b** → <b> for repro steps in HTML.
func mdInline(s string) string {
	s = html.EscapeString(s)
	s = replacePairs(s, "`", "<code>", "</code>")
	s = replacePairs(s, "**", "<b>", "</b>")
	s = strings.ReplaceAll(s, "\n", "<br>")
	return s
}

func replacePairs(s, delim, open, close string) string {
	parts := strings.Split(s, delim)
	if len(parts) < 3 {
		return s
	}
	var b strings.Builder
	for i, p := range parts {
		if i == 0 {
			b.WriteString(p)
			continue
		}
		if i%2 == 1 {
			b.WriteString(open)
			b.WriteString(p)
			b.WriteString(close)
		} else {
			b.WriteString(p)
		}
	}
	return b.String()
}

// --- small helpers used by templates ---

func host(f Item) string {
	a := f.Asset
	for _, p := range []string{"https://", "http://", "tcp://", "mongodb://", "gs://"} {
		a = strings.TrimPrefix(a, p)
	}
	if i := strings.IndexAny(a, "/:"); i >= 0 {
		a = a[:i]
	}
	return a
}

func shortEvidence(f Item) string {
	e := f.Evidence
	if i := strings.Index(e, " — "); i > 0 && i < 120 {
		return e[i+len(" — "):]
	}
	if len(e) > 120 {
		return e[:120] + "…"
	}
	return e
}

func claimTarget(f Item) string {
	if f.Meta != nil {
		if v, ok := f.Meta["claim_target"].(string); ok && v != "" {
			return v
		}
		if v, ok := f.Meta["target"].(string); ok && v != "" {
			return v
		}
	}
	return host(f)
}

func orDash(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func probeHeader(probe string) string {
	probe = strings.TrimPrefix(probe, "header ")
	if probe == "" {
		return "X-Forwarded-Host"
	}
	return probe
}

// MetaFromRaw decodes a store.Finding.Meta (json.RawMessage) into a map.
func MetaFromRaw(raw []byte) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}
