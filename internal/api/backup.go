package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"reconhub/internal/monitor"
	"reconhub/internal/project"
	"reconhub/internal/scope"
	"reconhub/internal/scopetemplate"
	"reconhub/internal/store"
)

// backupVersion identifies the bundle schema. A restore accepts any version
// it recognizes; new fields are additive (omitempty), so an older bundle
// missing a field just restores nothing for that category — never an error.
const backupVersion = "1"

// Backup is a full, self-contained snapshot of everything the hub has
// recorded — the whole-instance counterpart of exportProgram (one program).
// It exists so a user can recover after losing the data volume (a wiped
// Docker.raw, a pruned volume, a new machine): export one file, keep it
// somewhere safe, import it back into a fresh instance.
//
// Auth (per-program cookies/bearer/proxy) is DELIBERATELY excluded unless
// ?secrets=1 is passed: auth.json holds real credentials for someone else's
// application, is gitignored and 0600, and is kept out of every other
// snapshot on purpose (see project.Auth). A plain backup is safe to store
// anywhere; a ?secrets=1 backup is as sensitive as the access token itself.
type Backup struct {
	Version        string                   `json:"version"`
	ExportedAt     time.Time                `json:"exported_at"`
	Programs       []scope.Program          `json:"programs,omitempty"`
	ScopeTemplates []scopetemplate.Template `json:"scope_templates,omitempty"`
	Watches        []monitor.Watch          `json:"watches,omitempty"`
	Findings       []*store.Finding         `json:"findings,omitempty"`
	Assets         []*store.Asset           `json:"assets,omitempty"`
	Jobs           []*store.Job             `json:"jobs,omitempty"`
	PipelineRuns   []*store.PipelineRun     `json:"pipeline_runs,omitempty"`
	Notes          map[string]string        `json:"notes,omitempty"`   // program -> notes.md
	Lessons        string                   `json:"lessons,omitempty"` // cross-program lessons.md
	Auth           map[string]project.Auth  `json:"auth,omitempty"`    // program -> auth (only with ?secrets=1)
}

// collectBackup gathers the whole instance into one Backup. withSecrets
// controls whether per-program auth is included.
func (s *Server) collectBackup(withSecrets bool) Backup {
	b := Backup{Version: backupVersion, ExportedAt: time.Now().UTC()}

	if s.Programs != nil {
		b.Programs = s.Programs.List()
	}
	if s.ScopeTemplates != nil {
		b.ScopeTemplates = s.ScopeTemplates.List()
	}
	if s.Watches != nil {
		b.Watches = s.Watches.List()
	}
	if s.Store != nil {
		b.Findings, _ = s.Store.ListFindings(store.FindingFilter{Limit: 1000000})
		b.Assets, _ = s.Store.ListAssets(store.AssetFilter{Limit: 1000000})
		b.Jobs, _ = s.Store.ListJobs(store.JobFilter{Limit: 1000000})
		b.PipelineRuns, _ = s.Store.ListPipelineRuns(store.PipelineRunFilter{Limit: 1000000})
	}

	// Per-program notes + (optionally) auth, and the shared lessons file.
	if s.DataDir != "" {
		if txt, err := project.ReadLessons(s.DataDir); err == nil && strings.TrimSpace(txt) != "" {
			b.Lessons = txt
		}
		for _, p := range b.Programs {
			if txt, err := project.ReadNotes(s.DataDir, p.Name); err == nil && strings.TrimSpace(txt) != "" {
				if b.Notes == nil {
					b.Notes = map[string]string{}
				}
				b.Notes[p.Name] = txt
			}
			if withSecrets {
				if a, err := project.LoadAuth(s.DataDir, p.Name); err == nil && !a.Empty() {
					if b.Auth == nil {
						b.Auth = map[string]project.Auth{}
					}
					b.Auth[p.Name] = a
				}
			}
		}
	}
	return b
}

// exportBackup streams the whole instance as one downloadable JSON file.
// authSSE-wrapped: accepts ?access_token= so a plain browser link downloads
// it. ?secrets=1 additionally bundles per-program auth (see Backup).
func (s *Server) exportBackup(w http.ResponseWriter, r *http.Request) {
	withSecrets := r.URL.Query().Get("secrets") == "1"
	b := s.collectBackup(withSecrets)

	fname := "reconhub-backup-" + time.Now().UTC().Format("2006-01-02") + ".json"
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+fname+`"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(b)
}

// BackupRestoreCount is the added/skipped tally for one category of a restore.
type BackupRestoreCount struct {
	Added   int `json:"added"`
	Skipped int `json:"skipped"`
}

// BackupRestoreSummary reports what an import did, category by category.
// Everything is additive and never destructive: an entity that already
// exists is skipped, never overwritten, so re-importing the same bundle is
// idempotent and importing into a live instance can only ADD what's missing.
type BackupRestoreSummary struct {
	Version        string             `json:"version"`
	Programs       BackupRestoreCount `json:"programs"`
	ScopeTemplates BackupRestoreCount `json:"scope_templates"`
	Watches        BackupRestoreCount `json:"watches"`
	Findings       BackupRestoreCount `json:"findings"`
	Assets         BackupRestoreCount `json:"assets"`
	Jobs           BackupRestoreCount `json:"jobs"`
	PipelineRuns   BackupRestoreCount `json:"pipeline_runs"`
	Notes          BackupRestoreCount `json:"notes"`
	Lessons        BackupRestoreCount `json:"lessons"`
	Auth           BackupRestoreCount `json:"auth"`
	Warnings       []string           `json:"warnings,omitempty"`
}

// restoreBackup applies a bundle additively. It never overwrites or deletes:
// a program/template/watch that already exists is skipped; findings/assets
// dedup by their content key (store.AddFinding/AddAsset), so re-adding is a
// no-op bump; jobs/pipeline-runs are skipped if their id already exists;
// notes/lessons/auth are written only when the target is currently empty, so
// live text is never clobbered by a restore.
func (s *Server) restoreBackup(b Backup) BackupRestoreSummary {
	sum := BackupRestoreSummary{Version: b.Version}
	warn := func(format string, a ...any) { sum.Warnings = append(sum.Warnings, fmt.Sprintf(format, a...)) }

	// Programs first — notes/auth restore below depends on the program's name.
	if s.Programs != nil {
		for _, p := range b.Programs {
			if _, ok := s.Programs.Get(strings.ToLower(strings.TrimSpace(p.Name))); ok {
				sum.Programs.Skipped++
				continue
			}
			if err := s.Programs.Save(p); err != nil {
				warn("programa %q: %v", p.Name, err)
				continue
			}
			sum.Programs.Added++
		}
	} else if len(b.Programs) > 0 {
		warn("registro de programas indisponível — %d programa(s) não restaurado(s)", len(b.Programs))
	}

	if s.ScopeTemplates != nil {
		for _, t := range b.ScopeTemplates {
			if _, ok := s.ScopeTemplates.Get(strings.ToLower(strings.TrimSpace(t.Name))); ok {
				sum.ScopeTemplates.Skipped++
				continue
			}
			if err := s.ScopeTemplates.Save(t); err != nil {
				warn("template %q: %v", t.Name, err)
				continue
			}
			sum.ScopeTemplates.Added++
		}
	} else if len(b.ScopeTemplates) > 0 {
		warn("registro de templates indisponível — %d template(s) não restaurado(s)", len(b.ScopeTemplates))
	}

	if s.Watches != nil {
		for _, wt := range b.Watches {
			if _, ok := s.Watches.Get(strings.ToLower(strings.TrimSpace(wt.Name))); ok {
				sum.Watches.Skipped++
				continue
			}
			if err := s.Watches.Save(wt); err != nil {
				warn("watch %q: %v", wt.Name, err)
				continue
			}
			sum.Watches.Added++
		}
	} else if len(b.Watches) > 0 {
		warn("registro de watches indisponível — %d watch(es) não restaurado(s)", len(b.Watches))
	}

	if s.Store != nil {
		// Jobs before findings/assets so a finding's JobID points at a real
		// job once restored. Skip any id that already exists (CreateJob errors
		// on a duplicate id; we never want to overwrite a live job).
		for _, j := range b.Jobs {
			if _, ok := s.Store.GetJob(j.ID); ok {
				sum.Jobs.Skipped++
				continue
			}
			if err := s.Store.CreateJob(j); err != nil {
				warn("job %s: %v", j.ID, err)
				continue
			}
			sum.Jobs.Added++
		}
		for _, pr := range b.PipelineRuns {
			if _, ok := s.Store.GetPipelineRun(pr.ID); ok {
				sum.PipelineRuns.Skipped++
				continue
			}
			if err := s.Store.CreatePipelineRun(pr); err != nil {
				warn("pipeline-run %s: %v", pr.ID, err)
				continue
			}
			sum.PipelineRuns.Added++
		}
		for _, f := range b.Findings {
			isNew, err := s.Store.AddFinding(f)
			if err != nil {
				warn("finding %s: %v", f.ID, err)
				continue
			}
			if isNew {
				sum.Findings.Added++
			} else {
				sum.Findings.Skipped++
			}
		}
		for _, a := range b.Assets {
			isNew, err := s.Store.AddAsset(a)
			if err != nil {
				warn("asset %s: %v", a.Value, err)
				continue
			}
			if isNew {
				sum.Assets.Added++
			} else {
				sum.Assets.Skipped++
			}
		}
	}

	// Free-text files: write only when the target is currently empty, so a
	// restore into a live instance never clobbers notes/lessons someone has
	// been editing. A fresh (recovered) instance is empty, so it all lands.
	if s.DataDir != "" {
		for name, txt := range b.Notes {
			if cur, _ := project.ReadNotes(s.DataDir, name); strings.TrimSpace(cur) != "" {
				sum.Notes.Skipped++
				continue
			}
			if err := project.WriteNotes(s.DataDir, name, txt); err != nil {
				warn("notas de %q: %v", name, err)
				continue
			}
			sum.Notes.Added++
		}
		if strings.TrimSpace(b.Lessons) != "" {
			if cur, _ := project.ReadLessons(s.DataDir); strings.TrimSpace(cur) != "" {
				sum.Lessons.Skipped++
			} else if err := project.WriteLessons(s.DataDir, b.Lessons); err != nil {
				warn("lições: %v", err)
			} else {
				sum.Lessons.Added++
			}
		}
		for name, a := range b.Auth {
			if cur, _ := project.LoadAuth(s.DataDir, name); !cur.Empty() {
				sum.Auth.Skipped++
				continue
			}
			if err := project.SaveAuth(s.DataDir, name, a); err != nil {
				warn("auth de %q: %v", name, err)
				continue
			}
			sum.Auth.Added++
		}
	}

	return sum
}

// importBackup restores a bundle produced by exportBackup. Additive and
// idempotent (see restoreBackup): it only ADDS what's missing, so it's safe
// to run against a live instance and safe to run twice.
func (s *Server) importBackup(w http.ResponseWriter, r *http.Request) {
	var b Backup
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		writeErr(w, http.StatusBadRequest, "corpo JSON inválido — esperado um arquivo de backup do recon-hub")
		return
	}
	if b.Version != "" && b.Version != backupVersion {
		writeErr(w, http.StatusBadRequest, "versão de backup não suportada: "+b.Version+" (esperado "+backupVersion+")")
		return
	}
	writeJSON(w, http.StatusOK, s.restoreBackup(b))
}
