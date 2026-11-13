package chain

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
)

// TestDeriveMessageKeysFromSeed_EmptySeed checks that an empty seed, which
// becomes a zero Secret borrowed as nil, derives no message keys.
func TestDeriveMessageKeysFromSeed_EmptySeed(t *testing.T) {
	for _, salt := range [][]byte{nil, make([]byte, 32)} {
		keys, err := DeriveMessageKeysFromSeed(kdf.DeriveSecrets, []byte{}, salt, 0)
		if !errors.Is(err, ErrEmptySeed) || keys != nil {
			t.Fatalf("salt=%x: want ErrEmptySeed, got %v, %v", salt, keys, err)
		}
	}
	keys, err := DeriveMessageKeysFromSeed(kdf.DeriveSecrets, make([]byte, 32), nil, 0)
	if err != nil {
		t.Fatalf("non-empty seed: %v", err)
	}
	keys.Zeroize()
}
