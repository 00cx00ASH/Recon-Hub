// Package api exposes the orchestrator over HTTP and serves the dashboard.
package api

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"reconhub/internal/auth"
	"reconhub/internal/engine"
	"reconhub/internal/monitor"
	"reconhub/internal/pipeline"
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
	mux.HandleFunc("GET /api/programs/{name}/export", s.authSSE(s.exportProgram)) // authSSE: aceita ?access_token= (download via link)

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
	if wt.Program != "" {
		if _, err := s.resolveProgram(wt.Program); err != nil {
			writeErr(w, http.StatusBadRequest, "programa desconhecido: "+wt.Program)
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
	writeJSON(w, http.StatusCreated, saved)
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
