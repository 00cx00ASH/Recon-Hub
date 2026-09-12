package config

import (
	"encoding/json"
	"fmt"
	"os"
)

// Config is the runtime configuration for the orchestrator.
type Config struct {
	Addr              string `json:"addr"`
	ToolsDir          string `json:"tools_dir"`
	PipelinesDir      string `json:"pipelines_dir"`
	ProgramsDir       string `json:"programs_dir"`
	ScopeTemplatesDir string `json:"scope_templates_dir"`
	WatchesDir        string `json:"watches_dir"`
	WordlistsDir      string `json:"wordlists_dir"`
	SeclistsDir       string `json:"seclists_dir"` // caminho de um checkout do SecLists (opcional)
	DataDir           string `json:"data_dir"`
	Store             string `json:"store"`       // "files" (default) | "sqlite"
	SQLitePath        string `json:"sqlite_path"` // default: <data_dir>/reconhub.db
	WebDir            string `json:"web_dir"`
	DocsFile          string `json:"docs_file"`
	Token             string `json:"token"`
	MaxConcurrent     int    `json:"max_concurrent"`
}

// Default returns the built-in configuration used when no file is supplied.
func Default() Config {
	return Config{
		Addr:              "127.0.0.1:7878",
		ToolsDir:          "./tools",
		PipelinesDir:      "./pipelines",
		ProgramsDir:       "./programs",
		ScopeTemplatesDir: "./scope-templates",
		WatchesDir:        "./watches",
		WordlistsDir:      "./wordlists",
		SeclistsDir:       "",
		DataDir:           "./data",
		Store:             "files",
		SQLitePath:        "",
		WebDir:            "./web",
		DocsFile:          "./README.md",
		Token:             "",
		MaxConcurrent:     4,
	}
}

// Load reads a JSON config file, falling back to defaults for any missing field.
// An empty path returns the defaults unchanged.
func Load(path string) (Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, fmt.Errorf("parse config: %w", err)
	}
	if c.MaxConcurrent < 1 {
		c.MaxConcurrent = 1
	}
	return c, nil
}
