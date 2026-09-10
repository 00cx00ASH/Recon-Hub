//go:build !sqlite

package store

import "fmt"

// New opens the configured storage backend. In the default build only the
// file backend is compiled in; pass -tags sqlite to enable SQLite.
func New(dataDir, backend, sqlitePath string) (Store, error) {
	switch backend {
	case "", "files", "file":
		return Open(dataDir)
	case "sqlite":
		return nil, fmt.Errorf("backend \"sqlite\" pedido, mas este binário foi compilado sem ele — recompile com:  go build -tags sqlite ./cmd/reconhub")
	default:
		return nil, fmt.Errorf("backend de store desconhecido: %q (use \"files\" ou \"sqlite\")", backend)
	}
}

// Migrate is only available in the sqlite build.
func Migrate(dataDir, sqlitePath string) error {
	return fmt.Errorf("migração para SQLite exige o binário compilado com -tags sqlite")
}
