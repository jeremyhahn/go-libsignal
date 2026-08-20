// Byte and hex helpers shared by the conformance tests.
//
// They live in their own file, untagged, because they perform no
// cryptography themselves -- tests that are excluded from the FIPS gate
// (docs/FIPS.md) and tests that are not both need them.

package interop

import (
	"encoding/hex"
	"testing"
)

// hexBytes encodes an ASCII string into lower-case hex.
func hexBytes(s string) string {
	return hex.EncodeToString([]byte(s))
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", s, err)
	}
	return b
}

func bytesEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
