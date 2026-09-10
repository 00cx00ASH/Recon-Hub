package main

import (
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"reconhub/internal/copilot"
	"reconhub/internal/monitor"
	"reconhub/internal/pipeline"
	"reconhub/internal/scope"
	"reconhub/internal/store"
)

// --- tools / programs / pipelines: simple listings ---

type toolInfo struct {
	Name     string `json:"name"`
	Category string `json:"category"`
	Language string `json:"language"`
	Summary  string `json:"summary"`
}

func cmdTools(h *hubClient, _ []string) error {
	var res struct {
		Tools []toolInfo `json:"tools"`
	}
	if err := h.get("/api/tools", &res); err != nil {
		return err
	}
	for _, t := range res.Tools {
		fmt.Printf("%-26s %-8s %s\n", t.Name, t.Category, t.Summary)
	}
	fmt.Printf("\n%d ferramenta(s)\n", len(res.Tools))
	return nil
}

func cmdPrograms(h *hubClient, _ []string) error {
	var res struct {
		Programs []scope.Program `json:"programs"`
	}
	if err := h.get("/api/programs", &res); err != nil {
		return err
	}
	for _, p := range res.Programs {
		fmt.Printf("%-20s in_scope=%v out_of_scope=%v\n", p.Name, p.InScope, p.OutOfScope)
	}
	return nil
}

func cmdPipelines(h *hubClient, _ []string) error {
	var res struct {
		Pipelines []pipeline.Pipeline `json:"pipelines"`
	}
	if err := h.get("/api/pipelines", &res); err != nil {
		return err
	}
	for _, p := range res.Pipelines {
		fmt.Printf("%-22s %d step(s) — %s\n", p.Name, len(p.Steps), p.Description)
	}
	return nil
}

func cmdWatches(h *hubClient, _ []string) error {
	var res struct {
		Watches []monitor.Watch `json:"watches"`
	}
	if err := h.get("/api/watches", &res); err != nil {
		return err
	}
	for _, w := range res.Watches {
		state := "nunca rodou"
		if w.LastRunAt != nil {
			state = fmt.Sprintf("última run %s (+%d novo(s))", w.LastRunAt.Local().Format("02/01 15:04"), w.LastNew)
		}
		en := "habilitado"
		if !w.Enabled {
			en = "desabilitado"
		}
		fmt.Printf("%-20s %-18s → %-16s a cada %-6s [%s] %s\n", w.Name, w.Pipeline, w.Target, w.Every, en, state)
	}
	return nil
}

// --- flag helpers ---

// parseAnywhere lets flags appear before, after, or interleaved with
// positional args. flag.FlagSet.Parse alone stops at the first non-flag
// token, which surprises anyone used to GNU-style CLIs — typing
// `run tool target -program x` would silently drop -program because
// "target" isn't a flag. Flags must already be registered on fs (via
// fs.String/fs.Int/etc) before calling this; it introspects fs to know
// which "-name" tokens are real flags vs. positional args.
func parseAnywhere(fs *flag.FlagSet, args []string) []string {
	names := map[string]bool{}
	fs.VisitAll(func(f *flag.Flag) { names[f.Name] = true })

	var flagArgs, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 1 && a[0] == '-' {
			name := strings.TrimLeft(a, "-")
			hasValue := true
			if eq := strings.IndexByte(name, '='); eq >= 0 {
				name = name[:eq]
				hasValue = false // valor já vem colado (-flag=valor)
			}
			if names[name] {
				flagArgs = append(flagArgs, a)
				if hasValue && i+1 < len(args) {
					flagArgs = append(flagArgs, args[i+1])
					i++
				}
				continue
			}
		}
		positional = append(positional, a)
	}
	fs.Parse(flagArgs)
	return positional
}

// paramFlags collects repeated -param key=value into a map.
type paramFlags map[string]any

func (p paramFlags) String() string { return "" }
func (p paramFlags) Set(kv string) error {
	k, v, ok := strings.Cut(kv, "=")
	if !ok {
		return fmt.Errorf("-param espera key=value, veio %q", kv)
	}
	p[strings.TrimSpace(k)] = strings.TrimSpace(v)
	return nil
}

// --- run: dispara 1 ferramenta e acompanha até terminar ---

func cmdRun(h *hubClient, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	program := fs.String("program", "", "projeto/escopo")
	params := paramFlags{}
	fs.Var(params, "param", "chave=valor (repetível)")
	rest := parseAnywhere(fs, args)
	if len(rest) < 2 {
		return fmt.Errorf("uso: reconhub-cli run <ferramenta> <alvo> [-program X] [-param k=v]...")
	}
	tool, target := rest[0], rest[1]

	var job store.Job
	body := map[string]any{"tool": tool, "target": target, "program": *program, "params": map[string]any(params)}
	if err := h.post("/api/jobs", body, &job); err != nil {
		return err
	}
	fmt.Printf("job %s (%s → %s)\n", job.ID, tool, target)
	return followJob(h, job.ID)
}

// followJob polls a job until it reaches a terminal status, printing each
// new event as it appears (no SSE client — polling keeps this dependency-free
// and is plenty responsive for a terminal tool).
func followJob(h *hubClient, id string) error {
	seen := 0
	for {
		var res struct {
			Job    store.Job     `json:"job"`
			Events []store.Event `json:"events"`
		}
		if err := h.get("/api/jobs/"+id, &res); err != nil {
			return err
		}
		for _, e := range res.Events[seen:] {
			printEvent(e)
		}
		seen = len(res.Events)
		if isTerminalJob(res.Job.Status) {
			fmt.Printf("\n%s — %d finding(s)\n", res.Job.Status, res.Job.Findings)
			if res.Job.Error != "" {
				fmt.Println("erro:", res.Job.Error)
			}
			return nil
		}
		time.Sleep(1500 * time.Millisecond)
	}
}

func printEvent(e store.Event) {
	switch e.Type {
	case "finding":
		fmt.Printf("  [finding] %s\n", e.Msg)
	case "asset":
		fmt.Printf("  [asset] %s\n", e.Msg)
	case "log":
		lv := e.Level
		if lv == "" {
			lv = "info"
		}
		fmt.Printf("  [%s] %s\n", lv, e.Msg)
	case "progress":
		fmt.Printf("  [%%] %s\n", e.Msg)
	}
}

func isTerminalJob(status string) bool {
	switch status {
	case store.StatusSucceeded, store.StatusFailed, store.StatusCanceled:
		return true
	}
	return false
}

// --- jobs / job ---

func cmdJobs(h *hubClient, args []string) error {
	fs := flag.NewFlagSet("jobs", flag.ExitOnError)
	tool := fs.String("tool", "", "filtra por ferramenta")
	program := fs.String("program", "", "filtra por programa")
	status := fs.String("status", "", "filtra por status")
	limit := fs.Int("limit", 30, "teto de resultados")
	parseAnywhere(fs, args)

	var res struct {
		Jobs []store.Job `json:"jobs"`
	}
	q := qs(map[string]string{"tool": *tool, "program": *program, "status": *status, "limit": strconv.Itoa(*limit)})
	if err := h.get("/api/jobs"+q, &res); err != nil {
		return err
	}
	for _, j := range res.Jobs {
		fmt.Printf("%-20s %-9s %-22s %-24s %2d finding(s)  %s\n",
			j.CreatedAt.Local().Format("02/01 15:04:05"), j.Status, j.Tool, j.Target, j.Findings, j.ID)
	}
	return nil
}

func cmdJob(h *hubClient, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("uso: reconhub-cli job <id>")
	}
	var res struct {
		Job    store.Job     `json:"job"`
		Events []store.Event `json:"events"`
	}
	if err := h.get("/api/jobs/"+args[0], &res); err != nil {
		return err
	}
	j := res.Job
	fmt.Printf("%s  %s → %s  [%s]\n", j.ID, j.Tool, j.Target, j.Status)
	if j.Program != "" {
		fmt.Println("programa:", j.Program)
	}
	for _, e := range res.Events {
		printEvent(e)
	}
	return nil
}

// --- pipeline ---

func cmdPipeline(h *hubClient, args []string) error {
	fs := flag.NewFlagSet("pipeline", flag.ExitOnError)
	program := fs.String("program", "", "projeto/escopo")
	rest := parseAnywhere(fs, args)
	if len(rest) < 2 {
		return fmt.Errorf("uso: reconhub-cli pipeline <nome> <alvo> [-program X]")
	}
	name, target := rest[0], rest[1]

	var run store.PipelineRun
	body := map[string]any{"pipeline": name, "target": target, "program": *program}
	if err := h.post("/api/pipeline-runs", body, &run); err != nil {
		return err
	}
	fmt.Printf("run %s (%s → %s)\n", run.ID, name, target)
	return followPipelineRun(h, run.ID)
}

func followPipelineRun(h *hubClient, id string) error {
	printed := map[string]bool{}
	for {
		var res struct {
			Run store.PipelineRun `json:"run"`
		}
		if err := h.get("/api/pipeline-runs/"+id, &res); err != nil {
			return err
		}
		for _, s := range res.Run.Steps {
			key := s.Tool + "#" + fmt.Sprint(s.Index)
			if s.Status != "queued" && s.Status != "running" && !printed[key] {
				printed[key] = true
				fmt.Printf("  step %-22s %s\n", s.Tool, s.Status)
			}
		}
		if isTerminalJob(res.Run.Status) {
			fmt.Printf("\n%s — %d finding(s)\n", res.Run.Status, res.Run.Findings)
			if res.Run.Error != "" {
				fmt.Println("erro:", res.Run.Error)
			}
			return nil
		}
		time.Sleep(2 * time.Second)
	}
}

// --- findings / triage ---

// intelFinding mirrors internal/api's intelRow JSON shape (finding fields
// flattened alongside score/action/why/advice) without importing the
// unexported api package type.
type intelFinding struct {
	store.Finding
	Score      int     `json:"score"`
	Action     string  `json:"action"`
	Why        string  `json:"why"`
	Advice     string  `json:"advice,omitempty"`
	Confidence float64 `json:"confidence"`
	SampleSize int     `json:"sample_size"`
}

func cmdFindings(h *hubClient, args []string) error {
	fs := flag.NewFlagSet("findings", flag.ExitOnError)
	program := fs.String("program", "", "filtra por programa")
	severity := fs.String("severity", "", "filtra por severidade")
	toolFlag := fs.String("tool", "", "filtra por ferramenta")
	limit := fs.Int("limit", 50, "teto de resultados")
	parseAnywhere(fs, args)

	var res struct {
		Findings []intelFinding `json:"findings"`
	}
	q := qs(map[string]string{
		"program": *program, "severity": *severity, "tool": *toolFlag, "limit": strconv.Itoa(*limit),
	})
	if err := h.get("/api/intel/findings"+q, &res); err != nil {
		return err
	}
	for _, f := range res.Findings {
		fmt.Printf("%3d %-24s [%-8s] %-40s %s\n", f.Score, f.Action, f.Severity, trim(f.Title, 40), f.ID)
	}
	fmt.Printf("\n%d finding(s)\n", len(res.Findings))
	return nil
}

func cmdTriage(h *hubClient, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("uso: reconhub-cli triage <finding-id> <confirmed|false_positive|ignored>")
	}
	id, verdict := args[0], args[1]
	var f store.Finding
	if err := h.post("/api/findings/"+id+"/triage", map[string]any{"verdict": verdict}, &f); err != nil {
		return err
	}
	fmt.Printf("%s → %s (%s)\n", f.ID, f.Triage, f.Title)
	return nil
}

// --- coverage ---

func cmdCoverage(h *hubClient, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("uso: reconhub-cli coverage <programa>")
	}
	var cov copilot.Coverage
	if err := h.get("/api/programs/"+args[0]+"/coverage", &cov); err != nil {
		return err
	}
	fmt.Printf("já rodou (%d): %s\n", len(cov.Ran), strings.Join(cov.Ran, ", "))
	fmt.Println("sugestões:")
	for _, s := range cov.Suggestions {
		fmt.Printf("  %-24s %s", s.Tool, s.Reason)
		if len(s.Examples) > 0 {
			fmt.Printf("  (ex: %s)", strings.Join(s.Examples, ", "))
		}
		fmt.Println()
	}
	return nil
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
