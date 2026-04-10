// Package libsignal provides the library version.
package libsignal

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var version string

// Version returns the library version string.
func Version() string {
	return strings.TrimSpace(version)
}
