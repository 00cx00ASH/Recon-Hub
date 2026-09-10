package main

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

type dep struct {
	Name      string
	Ecosystem string // npm | pypi | cargo | composer
	Section   string // dependencies | dev | peer | optional
	Version   string
}

// ecosystemFor guesses the ecosystem from a manifest filename.
func ecosystemFor(name string) string {
	base := strings.ToLower(name)
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	switch {
	case base == "package.json":
		return "npm"
	case base == "cargo.toml":
		return "cargo"
	case base == "composer.json":
		return "composer"
	case base == "pyproject.toml", base == "setup.py", strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"), base == "pipfile":
		return "pypi"
	}
	return ""
}

// sniffEcosystem guesses from content when the filename is unknown.
func sniffEcosystem(content string) string {
	t := strings.TrimSpace(content)
	switch {
	case strings.Contains(t, "\"dependencies\"") && strings.Contains(t, "{"):
		if strings.Contains(t, "\"require\"") {
			return "composer"
		}
		return "npm"
	case strings.Contains(t, "[dependencies]") || strings.Contains(t, "[dev-dependencies]"):
		return "cargo"
	case regexp.MustCompile(`(?m)^\s*[A-Za-z0-9._-]+\s*(==|>=|~=|<=|!=|>|<|\[)`).MatchString(t):
		return "pypi"
	}
	return ""
}

// parseManifest dispatches to the ecosystem parser and dedups by name.
func parseManifest(ecosystem, content string) []dep {
	var out []dep
	switch ecosystem {
	case "npm":
		out = parseNPM(content)
	case "pypi":
		out = parsePyPI(content)
	case "cargo":
		out = parseCargo(content)
	case "composer":
		out = parseComposer(content)
	}
	seen := map[string]bool{}
	uniq := out[:0]
	for _, d := range out {
		if d.Name == "" || seen[d.Name] {
			continue
		}
		seen[d.Name] = true
		uniq = append(uniq, d)
	}
	sort.Slice(uniq, func(i, j int) bool { return uniq[i].Name < uniq[j].Name })
	return uniq
}

var npmSections = map[string]string{
	"dependencies":         "dependencies",
	"devDependencies":      "dev",
	"peerDependencies":     "peer",
	"optionalDependencies": "optional",
}

func parseNPM(content string) []dep {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &m); err != nil {
		return nil
	}
	var out []dep
	for key, section := range npmSections {
		raw, ok := m[key]
		if !ok {
			continue
		}
		var deps map[string]string
		if json.Unmarshal(raw, &deps) != nil {
			continue
		}
		for name, ver := range deps {
			if !isConfusableNPM(name, ver) {
				continue
			}
			out = append(out, dep{Name: name, Ecosystem: "npm", Section: section, Version: ver})
		}
	}
	return out
}

// isConfusableNPM drops specs that resolve to something other than the public
// registry (git/url/file/workspace/local link).
func isConfusableNPM(name, ver string) bool {
	if name == "" {
		return false
	}
	v := strings.TrimSpace(strings.ToLower(ver))
	for _, p := range []string{"file:", "link:", "workspace:", "git+", "git:", "github:", "http://", "https://", "portal:"} {
		if strings.HasPrefix(v, p) {
			return false
		}
	}
	if strings.Contains(v, "/") && !strings.HasPrefix(v, "npm:") {
		// e.g. "user/repo" shorthand for GitHub
		return false
	}
	return true
}

var pyprojectRe = regexp.MustCompile(`(?m)^\s*\[(project|build-system|tool\.[a-z]+)`)
var poetryDepSecRe = regexp.MustCompile(`^\[tool\.poetry(?:\.[a-z-]+)?\.dependencies\]$`)

func parsePyPI(content string) []dep {
	// pyproject.toml / TOML: don't treat its "key = value" lines as requirements.
	if pyprojectRe.MatchString(content) || regexp.MustCompile(`(?m)^\s*dependencies\s*=\s*\[`).MatchString(content) {
		return parsePyproject(content)
	}
	// requirements.txt style: one spec per line
	var out []dep
	for _, ln := range strings.Split(content, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "-") {
			continue
		}
		if strings.Contains(ln, "://") || strings.HasPrefix(ln, "git+") {
			continue
		}
		if n := pyName(ln); n != "" {
			out = append(out, dep{Name: n, Ecosystem: "pypi", Section: "requirements"})
		}
	}
	return out
}

func parsePyproject(content string) []dep {
	var out []dep
	// PEP 621: dependencies = [ "a>=1", "b" ]  (and [project.optional-dependencies])
	for _, item := range tomlArray(content, "dependencies") {
		if n := pyName(item); n != "" {
			out = append(out, dep{Name: n, Ecosystem: "pypi", Section: "dependencies"})
		}
	}
	// Poetry: [tool.poetry.dependencies] with name = "^1.2" lines
	inPoetry := false
	kv := regexp.MustCompile(`^([A-Za-z0-9._-]+)\s*=`)
	for _, ln := range strings.Split(content, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "[") {
			inPoetry = poetryDepSecRe.MatchString(ln)
			continue
		}
		if !inPoetry || ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		if strings.Contains(ln, "path =") || strings.Contains(ln, "git =") || strings.Contains(ln, "url =") {
			continue
		}
		m := kv.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		n := strings.ToLower(strings.ReplaceAll(m[1], "_", "-"))
		if n == "python" {
			continue
		}
		out = append(out, dep{Name: n, Ecosystem: "pypi", Section: "poetry"})
	}
	return out
}

var pyNameRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)`)

func pyName(spec string) string {
	spec = strings.TrimSpace(strings.Trim(spec, `"',`))
	spec = strings.SplitN(spec, ";", 2)[0] // drop env markers
	spec = strings.SplitN(spec, "[", 2)[0] // drop extras
	m := pyNameRe.FindStringSubmatch(spec)
	if m == nil {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(m[1], "_", "-"))
}

func parseCargo(content string) []dep {
	var out []dep
	sec := ""
	depSec := regexp.MustCompile(`^\[(?:.+\.)?(dependencies|dev-dependencies|build-dependencies)\]$`)
	kv := regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*=\s*(.+)$`)
	for _, ln := range strings.Split(content, "\n") {
		ln = strings.TrimSpace(ln)
		if strings.HasPrefix(ln, "#") || ln == "" {
			continue
		}
		if strings.HasPrefix(ln, "[") {
			if m := depSec.FindStringSubmatch(ln); m != nil {
				sec = m[1]
			} else {
				sec = ""
			}
			continue
		}
		if sec == "" {
			continue
		}
		m := kv.FindStringSubmatch(ln)
		if m == nil {
			continue
		}
		name, rhs := m[1], strings.TrimSpace(m[2])
		if strings.Contains(rhs, "path =") || strings.Contains(rhs, "git =") {
			continue // local / git dep, not confusable
		}
		ver := strings.Trim(rhs, `"`)
		if strings.HasPrefix(rhs, "{") {
			if vm := regexp.MustCompile(`version\s*=\s*"([^"]+)"`).FindStringSubmatch(rhs); vm != nil {
				ver = vm[1]
			} else {
				ver = ""
			}
			if pm := regexp.MustCompile(`package\s*=\s*"([^"]+)"`).FindStringSubmatch(rhs); pm != nil {
				name = pm[1] // renamed dep -> real crate name
			}
		}
		out = append(out, dep{Name: strings.ToLower(name), Ecosystem: "cargo", Section: sec, Version: ver})
	}
	return out
}

func parseComposer(content string) []dep {
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(content), &m); err != nil {
		return nil
	}
	var out []dep
	for key, section := range map[string]string{"require": "require", "require-dev": "dev"} {
		raw, ok := m[key]
		if !ok {
			continue
		}
		var deps map[string]string
		if json.Unmarshal(raw, &deps) != nil {
			continue
		}
		for name, ver := range deps {
			ln := strings.ToLower(name)
			if ln == "php" || strings.HasPrefix(ln, "ext-") || strings.HasPrefix(ln, "lib-") || !strings.Contains(name, "/") {
				continue
			}
			out = append(out, dep{Name: name, Ecosystem: "composer", Section: section, Version: ver})
		}
	}
	return out
}

// tomlArray pulls a simple `key = [ "a", "b" ]` array (single or multi-line).
func tomlArray(content, key string) []string {
	re := regexp.MustCompile(`(?s)` + regexp.QuoteMeta(key) + `\s*=\s*\[(.*?)\]`)
	m := re.FindStringSubmatch(content)
	if m == nil {
		return nil
	}
	var out []string
	for _, part := range strings.Split(m[1], ",") {
		part = strings.TrimSpace(strings.Trim(strings.TrimSpace(part), `"'`))
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// --- verdict ---

type verdict struct {
	severity string
	ftype    string
	note     string
}

// classifyResult turns a registry lookup outcome into a finding verdict.
// status: "claimed" | "unclaimed" | "unknown"; scopeEmpty only meaningful for npm scoped.
func classifyResult(d dep, status string, scopeEmpty bool) (verdict, bool) {
	if status != "unclaimed" {
		return verdict{}, false
	}
	scoped := strings.HasPrefix(d.Name, "@")
	switch {
	case scoped && scopeEmpty:
		return verdict{"high", "dependency-confusion",
			"pacote com escopo cujo escopo inteiro não existe no registro público — atacante pode registrar o escopo e publicar"}, true
	case scoped:
		return verdict{"medium", "dependency-confusion",
			"pacote com escopo ausente do registro público (o escopo existe) — risco se o build cai pro registro público"}, true
	case d.Ecosystem == "composer":
		return verdict{"medium", "dependency-confusion",
			"vendor/pacote ausente do Packagist — confusável se o repositório privado não tiver prioridade"}, true
	default:
		return verdict{"high", "dependency-confusion",
			"nome ausente do registro público — atacante pode publicar esse nome e sequestrar o build interno"}, true
	}
}
