// Package auth resolves and verifies the single API token that guards the
// orchestrator. The token can be supplied by flag, environment, config file or a
// persisted file under the data directory; if none of those exist one is
// generated and saved so a fresh checkout is closed by default.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Token is a resolved API token plus a note on where it came from.
type Token struct {
	Value    string // empty means auth is disabled
	Source   string // flag | env | config | file | generated | disabled
	FilePath string // set when Source is file or generated
}

// Enabled reports whether callers must present the token.
func (t Token) Enabled() bool { return t.Value != "" }

// Matches compares got against the token in constant time. A disabled token
// matches anything.
func (t Token) Matches(got string) bool {
	if t.Value == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(t.Value)) == 1
}

// FromRequest extracts the presented token from the Authorization header
// ("Bearer <token>") or, when allowQuery is true, the access_token query
// parameter (EventSource cannot set headers).
func FromRequest(r *http.Request, allowQuery bool) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[len("Bearer "):])
	}
	if allowQuery {
		return r.URL.Query().Get("access_token")
	}
	return ""
}

// Generate returns a new 256-bit token as 64 hex characters.
func Generate() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// Resolve chooses the token by precedence:
//
//	flag  >  env (RECONHUB_TOKEN)  >  config value  >  <dataDir>/token  >  generate+persist
//
// disableAuth returns a disabled Token regardless of the other inputs.
// regen ignores every existing source and writes a fresh token.
func Resolve(dataDir, flagVal, envVal, cfgVal string, disableAuth, regen bool) (Token, error) {
	if disableAuth {
		return Token{Source: "disabled"}, nil
	}
	path := filepath.Join(dataDir, "token")

	if !regen {
		for _, c := range []struct{ v, src string }{
			{flagVal, "flag"},
			{envVal, "env"},
			{cfgVal, "config"},
		} {
			if v := strings.TrimSpace(c.v); v != "" {
				return Token{Value: v, Source: c.src}, nil
			}
		}
		switch b, err := os.ReadFile(path); {
		case err == nil:
			if v := strings.TrimSpace(string(b)); v != "" {
				return Token{Value: v, Source: "file", FilePath: path}, nil
			}
		case !errors.Is(err, os.ErrNotExist):
			return Token{}, err
		}
	}

	v, err := Generate()
	if err != nil {
		return Token{}, err
	}
	if err := os.WriteFile(path, []byte(v+"\n"), 0o600); err != nil {
		return Token{}, err
	}
	return Token{Value: v, Source: "generated", FilePath: path}, nil
}
