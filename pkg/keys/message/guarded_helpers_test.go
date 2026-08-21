package message

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// mustGuard moves a copy of the given bytes into guarded memory, for building
// the KeysStructure values these tests exercise. It returns the zero Secret for
// empty input, matching the convention of the persisted-state structures.
func mustGuard(t *testing.T, data []byte) secret.Secret {
	t.Helper()
	guarded, err := secret.NewValue(append([]byte(nil), data...))
	if err != nil {
		t.Fatalf("secret.NewValue: %v", err)
	}
	return guarded
}

// mustStructFromKeys is NewStructFromKeys for the tests that only care about
// the happy path, with the structure released when the test ends.
func mustStructFromKeys(t *testing.T, keys *Keys) *KeysStructure {
	t.Helper()
	structure, err := NewStructFromKeys(keys)
	if err != nil {
		t.Fatalf("NewStructFromKeys: %v", err)
	}
	t.Cleanup(structure.Zeroize)
	return structure
}

// mustKeysFromStruct is NewKeysFromStruct for the tests that only care about
// the happy path.
func mustKeysFromStruct(t *testing.T, structure *KeysStructure) *Keys {
	t.Helper()
	keys, err := NewKeysFromStruct(structure)
	if err != nil {
		t.Fatalf("NewKeysFromStruct: %v", err)
	}
	t.Cleanup(keys.Zeroize)
	return keys
}
