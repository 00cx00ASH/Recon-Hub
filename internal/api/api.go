// Package api exposes the orchestrator over HTTP and serves the dashboard.
package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"reconhub/internal/auth"
	"reconhub/internal/copilot"
	"reconhub/internal/engine"
	"reconhub/internal/intel"
	"reconhub/internal/monitor"
	"reconhub/internal/pipeline"
	"reconhub/internal/project"
	"reconhub/internal/registry"
	"reconhub/internal/report"
	"reconhub/internal/scope"
	"reconhub/internal/store"
	"reconhub/internal/wordlist"
)

// Server holds the dependencies every handler needs.
type Server struct {
	Store     store.Store
	Reg       *registry.Registry
	Pipelines *pipeline.Registry
	Programs  *scope.Registry
	Wordlists *wordlist.Registry
	Watches   *monitor.Registry
	Monitor   *monitor.Monitor
	Engine    *engine.Engine
	Token     auth.Token
	WebDir    string
	DocsFile  string
	DataDir   string // root of ./data — projects/<program>/ lives under here
}

// resolveProgram looks up a program by name. An empty name is fine (nil, nil).
func (s *Server) resolveProgram(name string) (*scope.Program, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, nil
	}
	if s.Programs == nil {
		return nil, errNoPrograms
	}
	p, ok := s.Programs.Get(name)
	if !ok {
		return nil, errUnknownProgram
	}
	return &p, nil
}

// scopeExempt lists tools whose "target" is never the program's own domain —
// checking it against in_scope/out_of_scope would be meaningless (and would
// wrongly block legitimate runs).
var scopeExempt = map[string]bool{
	"int-github-audit":   true, // target is an org/repo or username
	"scan-postman-net":   true, // target is a Postman workspace/collection ID
	"scan-postman-audit": true, // target is a Postman workspace/collection ID
}

// inScope reports whether target is allowed to run under prog for the given
// tool. A nil program (no program selected) or an exempt tool always passes.
// A target that doesn't look like a hostname (no dot — e.g. a pasted blob, a
// search query, a file path used by "paste"/"file" modes) also passes: scope
// is defined in terms of hosts, so it has nothing to say about those.
func inScope(tool string, prog *scope.Program, target string) bool {
	if prog == nil || scopeExempt[tool] {
		return true
	}
	h := scope.Host(target)
	if !strings.Contains(h, ".") {
		return true
	}
	return prog.Contains(target)
}

// outOfScopeMsg builds a 403 message that shows the target and the program's
// actual in-scope patterns, so a user who set an empty or mismatched scope can
// see immediately why everything is being rejected.
func outOfScopeMsg(target string, prog *scope.Program) string {
	in := strings.Join(prog.InScope, ", ")
	if strings.TrimSpace(in) == "" {
		in = "(vazio — defina o in-scope na aba Projetos)"
	}
	return fmt.Sprintf("alvo %q fora do escopo do programa %q. In-scope: %s", target, prog.Name, in)
}

var (
	errNoPrograms     = &apiErr{"nenhum programa configurado em ./programs"}
	errUnknownProgram = &apiErr{"programa desconhecido"}
)

type apiErr struct{ msg string }

func (e *apiErr) Error() string { return e.msg }

// Handler builds the full router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/tools", s.auth(s.listTools))
	mux.HandleFunc("GET /api/tools/{name}", s.auth(s.getTool))
	mux.HandleFunc("GET /api/tools/{name}/readme", s.auth(s.getToolReadme))
	mux.HandleFunc("POST /api/jobs", s.auth(s.createJob))
	mux.HandleFunc("GET /api/jobs", s.auth(s.listJobs))
	mux.HandleFunc("GET /api/jobs/{id}", s.auth(s.getJob))
	mux.HandleFunc("POST /api/jobs/{id}/cancel", s.auth(s.cancelJob))
	mux.HandleFunc("GET /api/jobs/{id}/events", s.authSSE(s.jobEvents))
	mux.HandleFunc("GET /api/findings", s.auth(s.listFindings))
	mux.HandleFunc("GET /api/search", s.auth(s.search))
	mux.HandleFunc("POST /api/findings/{id}/triage", s.auth(s.triageFinding))
	mux.HandleFunc("GET /api/findings/{id}/draft.md", s.authSSE(s.findingDraft)) // authSSE: baixável por link
	mux.HandleFunc("GET /api/intel/findings", s.auth(s.intelFindings))
	mux.HandleFunc("GET /api/assets", s.auth(s.listAssets))

	mux.HandleFunc("GET /api/report", s.auth(s.reportJSON))
	mux.HandleFunc("GET /api/report.md", s.authSSE(s.reportMD))     // authSSE: baixável por link
	mux.HandleFunc("GET /api/report.html", s.authSSE(s.reportHTML)) // idem
	mux.HandleFunc("GET /api/programs/{name}/report.md", s.authSSE(s.reportMD))
	mux.HandleFunc("GET /api/programs/{name}/report.html", s.authSSE(s.reportHTML))

	mux.HandleFunc("GET /api/wordlists", s.auth(s.listWordlists))

	mux.HandleFunc("GET /api/programs", s.auth(s.listPrograms))
	mux.HandleFunc("POST /api/programs", s.auth(s.createProgram))
	mux.HandleFunc("GET /api/programs/{name}", s.auth(s.getProgram))
	mux.HandleFunc("PUT /api/programs/{name}", s.auth(s.updateProgram))
	mux.HandleFunc("DELETE /api/programs/{name}", s.auth(s.deleteProgram))
	mux.HandleFunc("GET /api/programs/{name}/export", s.authSSE(s.exportProgram)) // authSSE: aceita ?access_token= (download via link)

	// projeto: pasta física em data/projects/<name>/ — notas + snapshot sincronizado
	mux.HandleFunc("GET /api/programs/{name}/summary", s.auth(s.projectSummary))
	mux.HandleFunc("POST /api/programs/{name}/sync", s.auth(s.syncProject))
	mux.HandleFunc("GET /api/programs/{name}/notes", s.auth(s.getNotes))
	mux.HandleFunc("PUT /api/programs/{name}/notes", s.auth(s.putNotes))
	mux.HandleFunc("GET /api/programs/{name}/coverage", s.auth(s.programCoverage))
	mux.HandleFunc("GET /api/programs/{name}/auth", s.auth(s.getAuth))
	mux.HandleFunc("PUT /api/programs/{name}/auth", s.auth(s.putAuth))

	mux.HandleFunc("GET /api/watches", s.auth(s.listWatches))
	mux.HandleFunc("POST /api/watches", s.auth(s.createWatch))
	mux.HandleFunc("GET /api/watches/{name}", s.auth(s.getWatch))
	mux.HandleFunc("POST /api/watches/{name}/run", s.auth(s.runWatch))

	mux.HandleFunc("GET /api/pipelines", s.auth(s.listPipelines))
	mux.HandleFunc("POST /api/pipeline-runs", s.auth(s.createPipelineRun))
	mux.HandleFunc("GET /api/pipeline-runs", s.auth(s.listPipelineRuns))
	mux.HandleFunc("GET /api/pipeline-runs/{id}", s.auth(s.getPipelineRun))
	mux.HandleFunc("POST /api/pipeline-runs/{id}/cancel", s.auth(s.cancelPipelineRun))
	mux.HandleFunc("GET /api/pipeline-runs/{id}/events", s.authSSE(s.pipelineRunEvents))

	mux.HandleFunc("GET /api/docs", s.auth(s.docs))

	if s.WebDir != "" {
		mux.Handle("GET /", http.FileServer(http.Dir(s.WebDir)))
	}
	return withCORS(mux)
}

// auth guards a JSON endpoint with the bearer token, when one is configured.
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc { return s.guard(h, false) }

// authSSE is like auth but also accepts ?access_token= because EventSource
// cannot set request headers.
func (s *Server) authSSE(h http.HandlerFunc) http.HandlerFunc { return s.guard(h, true) }

func (s *Server) guard(h http.HandlerFunc, allowQuery bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Token.Enabled() && !s.Token.Matches(auth.FromRequest(r, allowQuery)) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="recon-hub"`)
			writeErr(w, http.StatusUnauthorized, "token inválido ou ausente")
			return
		}
		h(w, r)
	}
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "time": time.Now().UTC()})
}

// docs returns the project README as raw Markdown for the dashboard "Docs" tab.
func (s *Server) docs(w http.ResponseWriter, r *http.Request) {
	if s.DocsFile == "" {
		writeErr(w, http.StatusNotFound, "docs_file não configurado")
		return
	}
	b, err := os.ReadFile(s.DocsFile)
	if err != nil {
		writeErr(w, http.StatusNotFound, "README não encontrado em "+s.DocsFile)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func (s *Server) listTools(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"tools": s.Reg.List()})
}

func (s *Server) getTool(w http.ResponseWriter, r *http.Request) {
	t, ok := s.Reg.Get(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "ferramenta não encontrada")
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// getToolReadme serves tools/<name>/README.md as plain Markdown.
func (s *Server) getToolReadme(w http.ResponseWriter, r *http.Request) {
	t, ok := s.Reg.Get(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "ferramenta não encontrada")
		return
	}
	b, err := os.ReadFile(filepath.Join(t.Dir, "README.md"))
	if err != nil {
		writeErr(w, http.StatusNotFound, "esta ferramenta não tem README.md")
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

type createJobReq struct {
	Tool    string         `json:"tool"`
	Target  string         `json:"target"`
	Program string         `json:"program"`
	Params  map[string]any `json:"params"`
}

func (s *Server) createJob(w http.ResponseWriter, r *http.Request) {
	var req createJobReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "corpo JSON inválido")
		return
	}
	req.Tool = strings.TrimSpace(req.Tool)
	req.Target = strings.TrimSpace(req.Target)
	if req.Tool == "" || req.Target == "" {
		writeErr(w, http.StatusBadRequest, "\"tool\" e \"target\" são obrigatórios")
		return
	}
	prog, err := s.resolveProgram(req.Program)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	name := ""
	if prog != nil {
		name = prog.Name
		if !inScope(req.Tool, prog, req.Target) {
			writeErr(w, http.StatusForbidden, outOfScopeMsg(req.Target, prog))
			return
		}
	}
	job, err := s.Engine.Submit(req.Tool, req.Target, name, req.Params)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, job)
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	jobs, _ := s.Store.ListJobs(store.JobFilter{
		Tool:    q.Get("tool"),
		Program: q.Get("program"),
		Status:  q.Get("status"),
		Target:  q.Get("target"),
		Limit:   limit,
	})
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
}

func (s *Server) getJob(w http.ResponseWriter, r *http.Request) {
	job, ok := s.Store.GetJob(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "job não encontrado")
		return
	}
	events, _ := s.Store.ListEvents(job.ID, 0)
	writeJSON(w, http.StatusOK, map[string]any{"job": job, "events": events})
}

func (s *Server) cancelJob(w http.ResponseWriter, r *http.Request) {
	if s.Engine.Cancel(r.PathValue("id")) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	writeErr(w, http.StatusConflict, "job não está em execução")
}

// searchHit is one match from the global search bar — a finding, an asset,
// or a hit inside a project's notes. Kind + the id/job_id it carries is
// enough for the frontend to jump straight to the right tab and row.
type searchHit struct {
	Kind    string `json:"kind"` // finding | asset | note
	Program string `json:"program,omitempty"`
	Title   string `json:"title"`
	Detail  string `json:"detail,omitempty"`
	ID      string `json:"id,omitempty"`
	JobID   string `json:"job_id,omitempty"`
	Tool    string `json:"tool,omitempty"`
}

// search looks across findings, assets and project notes for a substring —
// case-insensitive, no index, just a linear scan. That's the right trade
// for what this hub actually holds (one operator's recon data, not a
// multi-tenant SaaS): simple beats fast here, and it's still instant at
// the sizes this ever reaches.
func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 60
	}
	if len(q) < 2 {
		writeJSON(w, http.StatusOK, map[string]any{"results": []searchHit{}, "query": q})
		return
	}

	hits := []searchHit{}
	fs, _ := s.Store.ListFindings(store.FindingFilter{Limit: 1000000})
	for _, f := range fs {
		if len(hits) >= limit {
			break
		}
		if strings.Contains(strings.ToLower(f.Title), q) || strings.Contains(strings.ToLower(f.Type), q) ||
			strings.Contains(strings.ToLower(f.Asset), q) || strings.Contains(strings.ToLower(f.Evidence), q) {
			hits = append(hits, searchHit{
				Kind: "finding", Program: f.Program, Title: f.Title, Detail: f.Asset,
				ID: f.ID, JobID: f.JobID, Tool: f.Tool,
			})
		}
	}
	as, _ := s.Store.ListAssets(store.AssetFilter{Limit: 1000000})
	for _, a := range as {
		if len(hits) >= limit {
			break
		}
		if strings.Contains(strings.ToLower(a.Value), q) {
			hits = append(hits, searchHit{
				Kind: "asset", Program: a.Program, Title: a.Value, Detail: a.Kind,
				JobID: a.JobID, Tool: a.Tool,
			})
		}
	}
	if s.Programs != nil {
		for _, p := range s.Programs.List() {
			if len(hits) >= limit {
				break
			}
			notes, err := project.ReadNotes(s.DataDir, p.Name)
			if err != nil || notes == "" {
				continue
			}
			if low := strings.ToLower(notes); strings.Contains(low, q) {
				hits = append(hits, searchHit{Kind: "note", Program: p.Name, Title: "notas de " + p.Name, Detail: snippetAround(notes, low, q)})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": hits, "query": q})
}

// snippetAround pulls ~60 chars of context around the first match, so a
// note hit shows *where*, not just *that* it matched. low is the
// lowercased text (already computed by the caller, so the search doesn't
// lowercase the whole note body twice).
func snippetAround(text, low, q string) string {
	i := strings.Index(low, q)
	if i < 0 {
		return ""
	}
	start := i - 30
	if start < 0 {
		start = 0
	}
	end := i + len(q) + 30
	if end > len(text) {
		end = len(text)
	}
	snippet := strings.TrimSpace(text[start:end])
	if start > 0 {
		snippet = "…" + snippet
	}
	if end < len(text) {
		snippet += "…"
	}
	return snippet
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 500
	}
	fs, _ := s.Store.ListFindings(store.FindingFilter{
		JobID:    q.Get("job"),
		Tool:     q.Get("tool"),
		Program:  q.Get("program"),
		Target:   q.Get("target"),
		Severity: q.Get("severity"),
		Type:     q.Get("type"),
		Limit:    limit,
	})
	writeJSON(w, http.StatusOK, map[string]any{"findings": fs})
}

// findingDraft renders ONE finding as a submission-ready report (same
// engine as /api/report.md — report.Build/Markdown — just scoped to a
// single item, with includeInfo forced on so even an info-severity finding
// gets its own full section instead of being silently dropped). It's the
// "generate a draft I can paste into HackerOne/Intigriti" button next to a
// finding: no direct integration with either platform (their hacker-facing
// APIs for creating a report were never confirmed to exist), so this is
// the honest version of that — draft, not auto-submit.
func (s *Server) findingDraft(w http.ResponseWriter, r *http.Request) {
	f, ok := s.Store.GetFinding(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "finding não encontrado")
		return
	}
	all, _ := s.Store.ListFindings(store.FindingFilter{Limit: 1000000})
	assessment := intel.Assess(f, intel.BuildHistory(all))

	item := report.Item{
		Type: f.Type, Severity: f.Severity, Title: f.Title, Asset: f.Asset,
		Evidence: f.Evidence, Tool: f.Tool, Target: f.Target, Count: f.Count,
		FirstAt: f.CreatedAt, LastAt: f.LastSeen,
		Meta: report.MetaFromRaw(f.Meta),
	}
	rep := report.Build(f.Program, f.Target, []report.Item{item}, true)
	md := rep.Markdown()
	md += "---\n\n_Prioridade sugerida pelo recon-hub: " + strconv.Itoa(assessment.Score) + "/100 — " + assessment.Action + "._\n"
	if assessment.Advice != "" {
		md += "_" + assessment.Advice + "_\n"
	}

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	if r.URL.Query().Get("dl") != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="draft-`+f.ID[:min(8, len(f.ID))]+`.md"`)
	}
	_, _ = w.Write([]byte(md))
}

// triageFinding records the operator's verdict on a finding — this is the
// feedback intel.BuildHistory learns from.
func (s *Server) triageFinding(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Verdict string `json:"verdict"`
		// Reason é opcional: por que esse veredito, não só qual — não entra
		// no score (isso continua sendo pura contagem confirmed/false_positive
		// por tool+type), mas fica junto do finding pra reler depois.
		Reason string `json:"reason"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "corpo JSON inválido")
		return
	}
	if !intel.ValidVerdict(body.Verdict) {
		writeErr(w, http.StatusBadRequest, "verdict inválido — use confirmed, false_positive ou ignored")
		return
	}
	f, err := s.Store.SetFindingTriage(r.PathValue("id"), body.Verdict, strings.TrimSpace(body.Reason))
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, f)
}

// intelRow is one finding joined with its triage assessment, for a client
// that wants to render score/action without a second round trip.
type intelRow struct {
	*store.Finding
	Score      int     `json:"score"`
	Action     string  `json:"action"`
	Why        string  `json:"why"`
	Advice     string  `json:"advice,omitempty"`
	Confidence float64 `json:"confidence"`
	SampleSize int     `json:"sample_size"`
}

// intelFindings returns findings (same filters as /api/findings) joined with
// their priority assessment, sorted most-urgent first. History is built from
// every triaged finding in the store — not just the filtered subset — so the
// score for a program-scoped view still benefits from what you've learned
// triaging other programs.
func (s *Server) intelFindings(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 500
	}
	fs, _ := s.Store.ListFindings(store.FindingFilter{
		JobID:    q.Get("job"),
		Tool:     q.Get("tool"),
		Program:  q.Get("program"),
		Target:   q.Get("target"),
		Severity: q.Get("severity"),
		Type:     q.Get("type"),
		Limit:    limit,
	})
	all, _ := s.Store.ListFindings(store.FindingFilter{Limit: 1000000})
	history := intel.BuildHistory(all)

	assessed := intel.AssessAll(fs, history)
	byID := make(map[string]*store.Finding, len(fs))
	for _, f := range fs {
		byID[f.ID] = f
	}

	rows := make([]intelRow, 0, len(assessed))
	for _, a := range assessed {
		f, ok := byID[a.FindingID]
		if !ok {
			continue
		}
		rows = append(rows, intelRow{
			Finding: f, Score: a.Score, Action: a.Action, Why: a.Why,
			Advice: a.Advice, Confidence: a.Confidence, SampleSize: a.SampleSize,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"findings": rows, "groups": intel.GroupSimilar(fs)})
}

// buildReport gathers findings per the request filters and assembles a report.
func (s *Server) buildReport(r *http.Request) report.Report {
	q := r.URL.Query()
	prog := q.Get("program")
	if p := r.PathValue("name"); p != "" {
		prog = p
	}
	target := q.Get("target")
	fs, _ := s.Store.ListFindings(store.FindingFilter{
		Program:  prog,
		Target:   target,
		JobID:    q.Get("job"),
		Tool:     q.Get("tool"),
		Type:     q.Get("type"),
		Severity: q.Get("severity"),
		Limit:    1000000,
	})
	items := make([]report.Item, 0, len(fs))
	for _, f := range fs {
		items = append(items, report.Item{
			Type: f.Type, Severity: f.Severity, Title: f.Title, Asset: f.Asset,
			Evidence: f.Evidence, Tool: f.Tool, Target: f.Target, Count: f.Count,
			FirstAt: f.CreatedAt, LastAt: f.LastSeen,
			Meta: report.MetaFromRaw(f.Meta),
		})
	}
	includeInfo := q.Get("include_info") == "1" || q.Get("include_info") == "true"
	return report.Build(prog, target, items, includeInfo)
}

func (s *Server) reportJSON(w http.ResponseWriter, r *http.Request) {
	rep := s.buildReport(r)
	writeJSON(w, http.StatusOK, rep)
}

func (s *Server) reportMD(w http.ResponseWriter, r *http.Request) {
	rep := s.buildReport(r)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+reportName(rep, "md")+`"`)
	_, _ = w.Write([]byte(rep.Markdown()))
}

func (s *Server) reportHTML(w http.ResponseWriter, r *http.Request) {
	rep := s.buildReport(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Query().Get("dl") != "" {
		w.Header().Set("Content-Disposition", `attachment; filename="`+reportName(rep, "html")+`"`)
	}
	_, _ = w.Write([]byte(rep.HTML()))
}

func reportName(rep report.Report, ext string) string {
	base := rep.Program
	if base == "" {
		base = rep.Target
	}
	if base == "" {
		base = "recon"
	}
	base = strings.Map(func(r rune) rune {
		if r == '.' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, base)
	return "report-" + base + "." + ext
}

func (s *Server) listAssets(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 2000
	}
	as, _ := s.Store.ListAssets(store.AssetFilter{
		JobID:   q.Get("job"),
		Tool:    q.Get("tool"),
		Program: q.Get("program"),
		Kind:    q.Get("kind"),
		Limit:   limit,
	})
	writeJSON(w, http.StatusOK, map[string]any{"assets": as})
}

func (s *Server) listWordlists(w http.ResponseWriter, r *http.Request) {
	var list []wordlist.List
	if s.Wordlists != nil {
		list = s.Wordlists.List()
	}
	writeJSON(w, http.StatusOK, map[string]any{"wordlists": list})
}

func (s *Server) listPrograms(w http.ResponseWriter, r *http.Request) {
	var list []scope.Program
	if s.Programs != nil {
		list = s.Programs.List()
	}
	writeJSON(w, http.StatusOK, map[string]any{"programs": list})
}

func (s *Server) getProgram(w http.ResponseWriter, r *http.Request) {
	p, err := s.resolveProgram(r.PathValue("name"))
	if err != nil || p == nil {
		writeErr(w, http.StatusNotFound, "programa não encontrado")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// --- watches (monitor) ---

func (s *Server) listWatches(w http.ResponseWriter, r *http.Request) {
	var list []monitor.Watch
	if s.Watches != nil {
		list = s.Watches.List()
	}
	writeJSON(w, http.StatusOK, map[string]any{"watches": list})
}

func (s *Server) getWatch(w http.ResponseWriter, r *http.Request) {
	if s.Watches == nil {
		writeErr(w, http.StatusServiceUnavailable, "monitor indisponível")
		return
	}
	wt, ok := s.Watches.Get(r.PathValue("name"))
	if !ok {
		writeErr(w, http.StatusNotFound, "watch não encontrado")
		return
	}
	runs, _ := s.Store.ListPipelineRuns(store.PipelineRunFilter{Pipeline: wt.Pipeline, Limit: 200})
	hist := runs[:0:0]
	for _, run := range runs {
		if run.Target == wt.Target {
			hist = append(hist, run)
		}
		if len(hist) >= 20 {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"watch": wt, "runs": hist})
}

func (s *Server) createWatch(w http.ResponseWriter, r *http.Request) {
	if s.Watches == nil {
		writeErr(w, http.StatusServiceUnavailable, "monitor indisponível")
		return
	}
	var wt monitor.Watch
	if err := json.NewDecoder(r.Body).Decode(&wt); err != nil {
		writeErr(w, http.StatusBadRequest, "corpo JSON inválido")
		return
	}
	if _, ok := s.Pipelines.Get(wt.Pipeline); !ok {
		writeErr(w, http.StatusBadRequest, "pipeline desconhecida: "+wt.Pipeline)
		return
	}
	if !monitor.ValidWebhookType(wt.WebhookType) {
		writeErr(w, http.StatusBadRequest, "webhook_type inválido — use discord, slack, telegram ou generic")
		return
	}
	if wt.Program != "" {
		prog, err := s.resolveProgram(wt.Program)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "programa desconhecido: "+wt.Program)
			return
		}
		if pl, ok := s.Pipelines.Get(wt.Pipeline); ok && len(pl.Steps) > 0 && !inScope(pl.Steps[0].Tool, prog, wt.Target) {
			writeErr(w, http.StatusForbidden, fmt.Sprintf("alvo %q fora do escopo do programa %q — um watch recorrente fora do escopo ficaria escaneando indevidamente", wt.Target, prog.Name))
			return
		}
	}
	if err := s.Watches.Save(wt); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, _ := s.Watches.Get(strings.ToLower(strings.TrimSpace(wt.Name)))
	writeJSON(w, http.StatusCreated, saved)
}

func (s *Server) runWatch(w http.ResponseWriter, r *http.Request) {
	if s.Monitor == nil {
		writeErr(w, http.StatusServiceUnavailable, "monitor indisponível")
		return
	}
	if err := s.Monitor.Trigger(r.PathValue("name")); err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "watch": r.PathValue("name")})
}

func (s *Server) createProgram(w http.ResponseWriter, r *http.Request) {
	if s.Programs == nil {
		writeErr(w, http.StatusServiceUnavailable, "registro de programas indisponível")
		return
	}
	var p scope.Program
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "corpo JSON inválido")
		return
	}
	if err := s.Programs.Save(p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, _ := s.Programs.Get(strings.ToLower(strings.TrimSpace(p.Name)))
	_ = project.Init(s.DataDir, saved.Name) // pasta do projeto — best-effort, um sync futuro a recria de qualquer jeito
	writeJSON(w, http.StatusCreated, saved)
}

// updateProgram edits an existing program's scope (in_scope/out_of_scope,
// platform, url) — the name in the URL is authoritative, so a typo you
// only notice after creating the project doesn't mean starting over.
func (s *Server) updateProgram(w http.ResponseWriter, r *http.Request) {
	if s.Programs == nil {
		writeErr(w, http.StatusServiceUnavailable, "registro de programas indisponível")
		return
	}
	name := r.PathValue("name")
	var p scope.Program
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeErr(w, http.StatusBadRequest, "corpo JSON inválido")
		return
	}
	if err := s.Programs.Update(name, p); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, _ := s.Programs.Get(strings.ToLower(strings.TrimSpace(name)))
	writeJSON(w, http.StatusOK, saved)
}

// deleteProgram removes a program's scope definition. Jobs/findings/assets
// and the data/projects/<name>/ folder already tied to that name are left
// alone — only the in_scope/out_of_scope definition goes away.
func (s *Server) deleteProgram(w http.ResponseWriter, r *http.Request) {
	if s.Programs == nil {
		writeErr(w, http.StatusServiceUnavailable, "registro de programas indisponível")
		return
	}
	if err := s.Programs.Delete(r.PathValue("name")); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- projeto (pasta física em data/projects/<name>/) ---

// syncProject rebuilds the project's snapshot (summary, report, assets) from
// current store state and returns the fresh summary.
func (s *Server) syncProject(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.resolveProgram(name); err != nil {
		writeErr(w, http.StatusNotFound, "programa não encontrado")
		return
	}
	sum, err := project.SyncFromStore(s.DataDir, name, s.Programs, s.Store, s.Reg)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

// projectSummary is a sync + read in one call — it always returns fresh
// counts, so there's no separate "stale" state for the caller to worry about.
func (s *Server) projectSummary(w http.ResponseWriter, r *http.Request) {
	s.syncProject(w, r)
}

func (s *Server) getNotes(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.resolveProgram(name); err != nil {
		writeErr(w, http.StatusNotFound, "programa não encontrado")
		return
	}
	txt, err := project.ReadNotes(s.DataDir, name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"program": name, "notes": txt})
}

// programCoverage reports which tools have run for a program and which
// applicable ones (given what's been discovered) haven't — the "o que fazer
// agora" view.
func (s *Server) programCoverage(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.resolveProgram(name); err != nil {
		writeErr(w, http.StatusNotFound, "programa não encontrado")
		return
	}
	jobs, _ := s.Store.ListJobs(store.JobFilter{Program: name, Limit: 1000000})
	assets, _ := s.Store.ListAssets(store.AssetFilter{Program: name, Limit: 1000000})
	writeJSON(w, http.StatusOK, copilot.Compute(name, jobs, assets, s.Reg))
}

// getAuth returns the program's stored auth context (cookie/bearer/extra
// headers) verbatim — the operator set it themselves, same trust level as
// their own token protecting this API.
func (s *Server) getAuth(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.resolveProgram(name); err != nil {
		writeErr(w, http.StatusNotFound, "programa não encontrado")
		return
	}
	a, err := project.LoadAuth(s.DataDir, name)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, a)
}

// putAuth stores the auth context that every job run against this program
// (via the shared session) gets injected as RECONHUB_AUTH_* env vars.
func (s *Server) putAuth(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.resolveProgram(name); err != nil {
		writeErr(w, http.StatusNotFound, "programa não encontrado")
		return
	}
	var a project.Auth
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		writeErr(w, http.StatusBadRequest, "corpo JSON inválido")
		return
	}
	if err := project.SaveAuth(s.DataDir, name, a); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) putNotes(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.resolveProgram(name); err != nil {
		writeErr(w, http.StatusNotFound, "programa não encontrado")
		return
	}
	var body struct {
		Notes string `json:"notes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "corpo JSON inválido")
		return
	}
	if err := project.WriteNotes(s.DataDir, name, body.Notes); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// exportProgram bundles everything recorded under a program into one JSON.
func (s *Server) exportProgram(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p, err := s.resolveProgram(name)
	if err != nil || p == nil {
		writeErr(w, http.StatusNotFound, "programa não encontrado")
		return
	}
	jobs, _ := s.Store.ListJobs(store.JobFilter{Program: name, Limit: 100000})
	findings, _ := s.Store.ListFindings(store.FindingFilter{Program: name, Limit: 100000})
	assets, _ := s.Store.ListAssets(store.AssetFilter{Program: name, Limit: 1000000})
	runs, _ := s.Store.ListPipelineRuns(store.PipelineRunFilter{Program: name, Limit: 100000})

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`-export.json"`)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"program":       p,
		"exported_at":   time.Now().UTC(),
		"jobs":          jobs,
		"pipeline_runs": runs,
		"findings":      findings,
		"assets":        assets,
	})
}

func (s *Server) jobEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.Store.GetJob(id); !ok {
		writeErr(w, http.StatusNotFound, "job não encontrado")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming não suportado")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	// Subscribe before reading the backlog so nothing is missed in the gap;
	// dedupe by Seq so nothing in the backlog is sent twice.
	ch, cancel := s.Engine.Bus().Subscribe(id)
	defer cancel()

	sinceSeq := 0
	if v := r.Header.Get("Last-Event-ID"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			sinceSeq = n
		}
	}
	last := sinceSeq
	backlog, _ := s.Store.ListEvents(id, sinceSeq)
	for _, ev := range backlog {
		writeSSE(w, ev)
		last = ev.Seq
	}
	flusher.Flush()

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	ctx := r.Context()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if ev.Seq <= last {
				continue
			}
			writeSSE(w, ev)
			last = ev.Seq
			flusher.Flush()
		}
	}
}

func writeSSE(w http.ResponseWriter, ev store.Event) {
	b, _ := json.Marshal(ev)
	_, _ = w.Write([]byte("id: " + strconv.Itoa(ev.Seq) + "\ndata: "))
	_, _ = w.Write(b)
	_, _ = w.Write([]byte("\n\n"))
}

// --- pipelines ---

func (s *Server) listPipelines(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"pipelines": s.Pipelines.List()})
}

type createPipelineRunReq struct {
	Pipeline string `json:"pipeline"`
	Target   string `json:"target"`
	Program  string `json:"program"`
}

func (s *Server) createPipelineRun(w http.ResponseWriter, r *http.Request) {
	var req createPipelineRunReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "corpo JSON inválido")
		return
	}
	pl, ok := s.Pipelines.Get(strings.TrimSpace(req.Pipeline))
	if !ok {
		writeErr(w, http.StatusBadRequest, "pipeline desconhecida")
		return
	}
	prog, err := s.resolveProgram(req.Program)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if prog != nil && len(pl.Steps) > 0 && !inScope(pl.Steps[0].Tool, prog, req.Target) {
		writeErr(w, http.StatusForbidden, outOfScopeMsg(req.Target, prog))
		return
	}
	run, err := s.Engine.SubmitPipeline(pl, req.Target, prog)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (s *Server) listPipelineRuns(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = 100
	}
	runs, _ := s.Store.ListPipelineRuns(store.PipelineRunFilter{
		Pipeline: q.Get("pipeline"),
		Program:  q.Get("program"),
		Status:   q.Get("status"),
		Limit:    limit,
	})
	writeJSON(w, http.StatusOK, map[string]any{"runs": runs})
}

func (s *Server) getPipelineRun(w http.ResponseWriter, r *http.Request) {
	run, ok := s.Store.GetPipelineRun(r.PathValue("id"))
	if !ok {
		writeErr(w, http.StatusNotFound, "run não encontrada")
		return
	}
	jobs := make([]*store.Job, 0, len(run.Steps))
	for _, st := range run.Steps {
		if st.JobID == "" {
			continue
		}
		if j, ok := s.Store.GetJob(st.JobID); ok {
			jobs = append(jobs, j)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"run": run, "jobs": jobs})
}

func (s *Server) cancelPipelineRun(w http.ResponseWriter, r *http.Request) {
	if s.Engine.CancelPipeline(r.PathValue("id")) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	writeErr(w, http.StatusConflict, "nenhum step em execução")
}

func (s *Server) pipelineRunEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.Store.GetPipelineRun(id); !ok {
		writeErr(w, http.StatusNotFound, "run não encontrada")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, http.StatusInternalServerError, "streaming não suportado")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, cancel := s.Engine.Bus().Subscribe("pipe:" + id)
	defer cancel()

	// Pipeline events are live-only (not persisted); a reconnecting client
	// re-reads GET /api/pipeline-runs/{id} for current state.
	seq := 0
	send := func(ev store.Event) {
		seq++
		ev.Seq = seq
		writeSSE(w, ev)
		flusher.Flush()
	}
	send(store.Event{Type: "log", Msg: "conectado ao stream da pipeline", Time: time.Now().UTC()})

	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ping.C:
			_, _ = w.Write([]byte(": ping\n\n"))
			flusher.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			send(ev)
		}
	}
}
