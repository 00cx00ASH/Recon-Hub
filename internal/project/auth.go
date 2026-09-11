package project

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
)

// Auth is operator-supplied authentication material attached to every tool
// request run against this program — a shared logged-in session, so a job
// doesn't scan anonymously when the interesting surface sits behind login.
//
// It lives in data/projects/<name>/auth.json — under data/, which is
// gitignored, unlike programs/<name>.json (committed scope config). These
// are real credentials for someone else's application; they must never end
// up in git by accident, so this file is written 0600 and kept out of the
// project.json/summary.json/report.md snapshot entirely (SyncFromStore never
// touches it).
type Auth struct {
	Cookie  string            `json:"cookie,omitempty"`  // valor cru do header Cookie
	Bearer  string            `json:"bearer,omitempty"`  // vira Authorization: Bearer <token>
	Headers map[string]string `json:"headers,omitempty"` // headers extras (ex: X-Api-Key)
	// Proxy roteia as requisições da ferramenta por http://, https:// ou
	// socks5:// (ex: socks5://127.0.0.1:9050 pro Tor do próprio container —
	// ver docker-compose.yml). Único jeito de trocar de IP no meio de um
	// programa sem reconfigurar nada manualmente: pedir um circuito novo ao
	// Tor derruba a sessão SOCKS atual e a próxima conexão sai por outro nó.
	Proxy string `json:"proxy,omitempty"`
}

// TorControlAddr derives the Tor control-port address from a configured
// socks5:// proxy, by convention: same host, port 9051 (docker/tor/torrc
// ships SOCKSPort 9050 + ControlPort 9051 on the same sidecar). Returns ""
// for any other scheme (http/https proxies) or no proxy at all — automatic
// circuit rotation (SIGNAL NEWNYM) only makes sense for Tor. A socks5://
// proxy that ISN'T this repo's Tor sidecar just fails the control-port
// handshake harmlessly at runtime (logged, never fatal) — see
// tools/*/proxy.go's torNewCircuit.
func TorControlAddr(proxyRaw string) string {
	if proxyRaw == "" {
		return ""
	}
	u, err := url.Parse(proxyRaw)
	if err != nil || u.Scheme != "socks5" || u.Hostname() == "" {
		return ""
	}
	return net.JoinHostPort(u.Hostname(), "9051")
}

// Empty reports whether there's nothing to inject.
func (a Auth) Empty() bool {
	return a.Cookie == "" && a.Bearer == "" && len(a.Headers) == 0 && a.Proxy == ""
}

func authFile(dataDir, name string) (string, error) {
	dir := Dir(dataDir, name)
	if dir == "" {
		return "", fmt.Errorf("nome de projeto inválido: %q", name)
	}
	return filepath.Join(dir, "auth.json"), nil
}

// SaveAuth writes the auth context, creating the project folder if needed.
func SaveAuth(dataDir, name string, a Auth) error {
	if a.Proxy != "" {
		u, perr := url.Parse(a.Proxy)
		if perr != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
			return fmt.Errorf("proxy inválido — use http://, https:// ou socks5://host:porta (ex: socks5://127.0.0.1:9050 pro Tor)")
		}
	}
	path, err := authFile(dataDir, name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// LoadAuth reads the auth context; a missing file returns the zero value
// (Empty() == true), not an error — most programs won't have one set.
func LoadAuth(dataDir, name string) (Auth, error) {
	path, err := authFile(dataDir, name)
	if err != nil {
		return Auth{}, err
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Auth{}, nil
	}
	if err != nil {
		return Auth{}, err
	}
	var a Auth
	if err := json.Unmarshal(b, &a); err != nil {
		return Auth{}, err
	}
	return a, nil
}
