// Package loader reads the Rust libsignal fixtures under tests/interop/fixtures/, whose sha256 and upstream paths MANIFEST.toml records and check_fixtures.sh enforces.
package loader

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// fixturesRoot returns the absolute path to tests/interop/fixtures/, computed
// from this source file's location. Using runtime.Caller keeps the path
// correct regardless of which package's tests are running.
func fixturesRoot() (string, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("loader: runtime.Caller failed; cannot locate fixtures root")
	}
	// .../tests/interop/loader/loader.go → .../tests/interop/fixtures
	dir := filepath.Dir(file)
	root := filepath.Join(dir, "..", "fixtures")
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("loader: abs(fixtures): %w", err)
	}
	if _, err := os.Stat(abs); err != nil {
		return "", fmt.Errorf("loader: fixtures root %q not present: %w", abs, err)
	}
	return abs, nil
}

// Read returns the raw bytes of the fixture at the given relative path under
// tests/interop/fixtures/. The path uses forward slashes regardless of host
// platform; "/" separators are translated to filepath.Separator before the
// lookup. The path must NOT escape the fixtures root via "..".
func Read(relative string) ([]byte, error) {
	if relative == "" {
		return nil, fmt.Errorf("loader: empty fixture path")
	}
	if strings.Contains(relative, "..") {
		return nil, fmt.Errorf("loader: fixture path %q must not contain '..'", relative)
	}
	root, err := fixturesRoot()
	if err != nil {
		return nil, err
	}
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("loader: open root %q: %w", root, err)
	}
	defer func() { _ = rootFS.Close() }() // read-only; close error is irrelevant once data is read
	parts := strings.Split(relative, "/")
	data, err := rootFS.ReadFile(filepath.Join(parts...))
	if err != nil {
		return nil, fmt.Errorf("loader: read %q: %w", relative, err)
	}
	return data, nil
}

// MustRead is the panic-on-error variant of Read intended for use inside
// tests where a missing fixture is a fatal setup failure, not a runtime
// error to be propagated.
func MustRead(relative string) []byte {
	data, err := Read(relative)
	if err != nil {
		panic(err)
	}
	return data
}
