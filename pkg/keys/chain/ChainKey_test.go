package chain

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

func TestNewKey(t *testing.T) {
	// Make a copy for comparison since NewKey zeroizes the source.
	original := []byte("test-key")
	input := make([]byte, len(original))
	copy(input, original)

	key := NewKey(kdf.DeriveSecrets, input, 0)
	if key == nil {
		t.Fatal("expected non-nil chain key")
	}
	if !bytes.Equal(key.Key(), original) {
		t.Fatal("Key mismatch")
	}
	if key.Index() != 0 {
		t.Fatalf("expected index 0, got %d", key.Index())
	}
}

func TestKey_Current(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("k"), 5)
	if key.Current() != key {
		t.Fatal("Current should return the same key")
	}
}

func TestKey_SetKey(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("old"), 0)
	key.SetKey([]byte("new"))
	if !bytes.Equal(key.Key(), []byte("new")) {
		t.Fatal("SetKey did not update key")
	}
}

func TestKey_SetIndex(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("k"), 0)
	key.SetIndex(42)
	if key.Index() != 42 {
		t.Fatalf("expected index 42, got %d", key.Index())
	}
}

func TestKey_NextKey(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("some-chain-key-material-32bytes!"), 0)

	// Capture key bytes before NextKey since it destroys the old key.
	oldKeyBytes := make([]byte, len(key.Key()))
	copy(oldKeyBytes, key.Key())

	next := key.NextKey()
	if next == nil {
		t.Fatal("NextKey should not return nil")
	}
	if next.Index() != 1 {
		t.Fatalf("expected next index 1, got %d", next.Index())
	}
	if bytes.Equal(next.Key(), oldKeyBytes) {
		t.Fatal("next key should differ from current key")
	}
}

func TestKey_NextKey_Chained(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("chain-key-material-32-bytes-ok!?"), 0)
	k1 := key.NextKey()
	k2 := k1.NextKey()
	k3 := k2.NextKey()
	if k3.Index() != 3 {
		t.Fatalf("expected index 3 after 3 ratchets, got %d", k3.Index())
	}
}

func TestKey_BaseMaterial(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("base-material-key"), 0)
	mat := key.BaseMaterial([]byte{0x01})
	if len(mat) == 0 {
		t.Fatal("BaseMaterial should return non-empty bytes")
	}
	// HMAC-SHA256 output is 32 bytes
	if len(mat) != 32 {
		t.Fatalf("expected 32 bytes from HMAC-SHA256, got %d", len(mat))
	}
}

func TestKey_BaseMaterial_DifferentSeeds(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("chain-key-material-32-bytes-ok!?"), 0)
	m1 := key.BaseMaterial([]byte{0x01})
	m2 := key.BaseMaterial([]byte{0x02})
	if bytes.Equal(m1, m2) {
		t.Fatal("different seeds should produce different base material")
	}
}

func TestKey_MessageKeys(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("chain-key-for-message-keys-test!"), 5)
	msgKeys, err := key.MessageKeys()
	if err != nil {
		t.Fatalf("MessageKeys failed: %v", err)
	}
	if msgKeys == nil {
		t.Fatal("expected non-nil message keys")
	}
	if len(msgKeys.CipherKey()) != 32 {
		t.Fatalf("expected 32-byte cipher key, got %d", len(msgKeys.CipherKey()))
	}
	if len(msgKeys.MacKey()) != 32 {
		t.Fatalf("expected 32-byte mac key, got %d", len(msgKeys.MacKey()))
	}
	if len(msgKeys.Iv()) != 16 {
		t.Fatalf("expected 16-byte IV, got %d", len(msgKeys.Iv()))
	}
	if msgKeys.Index() != 5 {
		t.Fatalf("expected message key index 5, got %d", msgKeys.Index())
	}
}

func TestNewKeyFromStruct(t *testing.T) {
	expected := []byte("struct-key")
	structure := &KeyStructure{
		Key:   mustGuard(t, expected),
		Index: 10,
	}
	defer structure.Zeroize()

	key, err := NewKeyFromStruct(structure, kdf.DeriveSecrets)
	if err != nil {
		t.Fatalf("NewKeyFromStruct: %v", err)
	}
	if !bytes.Equal(key.Key(), expected) {
		t.Fatal("Key mismatch from struct")
	}
	if key.Index() != 10 {
		t.Fatalf("expected index 10, got %d", key.Index())
	}
	// The clone must be independent: the source structure keeps its material,
	// and destroying it must not disturb the key built from it.
	if !secrettest.Matches(t, &structure.Key, expected) {
		t.Fatal("NewKeyFromStruct consumed the source structure's material")
	}
}

// TestNewKeyFromStruct_NoMaterial covers the error path: a structure with no
// chain key must be rejected rather than yielding a Key that cannot ratchet.
func TestNewKeyFromStruct_NoMaterial(t *testing.T) {
	for name, structure := range map[string]*KeyStructure{
		"nil structure": nil,
		"zero key":      {Index: 3},
	} {
		t.Run(name, func(t *testing.T) {
			key, err := NewKeyFromStruct(structure, kdf.DeriveSecrets)
			if key != nil {
				t.Fatal("expected no key")
			}
			var missing *MissingKeyError
			if !errors.As(err, &missing) {
				t.Fatalf("expected *MissingKeyError, got %#v", err)
			}
		})
	}
}

func TestNewStructFromKey(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("key-data"), 7)
	structure, err := NewStructFromKey(key)
	if err != nil {
		t.Fatalf("NewStructFromKey: %v", err)
	}
	defer structure.Zeroize()

	if !secrettest.Matches(t, &structure.Key, []byte("key-data")) {
		t.Fatal("Key mismatch in structure")
	}
	if structure.Index != 7 {
		t.Fatalf("expected index 7, got %d", structure.Index)
	}
	// The structure holds its own clone, not a view into the live key.
	key.Zeroize()
	if !secrettest.Matches(t, &structure.Key, []byte("key-data")) {
		t.Fatal("structure shares guarded memory with the live key")
	}
}

// TestNewStructFromKey_DestroyedKey covers the error path: a key whose guarded
// material is already gone cannot be serialized.
func TestNewStructFromKey_DestroyedKey(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("key-data"), 7)
	key.Zeroize()

	structure, err := NewStructFromKey(key)
	if structure != nil {
		t.Fatal("expected no structure")
	}
	if !errors.Is(err, secret.ErrSecretDestroyed) {
		t.Fatalf("expected ErrSecretDestroyed, got %#v", err)
	}
}

func TestKey_NextKey_DestroysOldKey(t *testing.T) {
	keyMaterial := make([]byte, 32)
	copy(keyMaterial, []byte("chain-key-material-32-bytes-ok!?"))
	key := NewKey(kdf.DeriveSecrets, keyMaterial, 0)

	_ = key.NextKey()

	// The old key's guarded memory should be destroyed.
	if !key.key.IsDestroyed() {
		t.Fatal("NextKey should destroy the old chain key's guarded memory")
	}
}

func TestKey_Zeroize(t *testing.T) {
	keyMaterial := make([]byte, 32)
	copy(keyMaterial, []byte("key-to-zeroize-for-testing-32b!?"))
	key := NewKey(kdf.DeriveSecrets, keyMaterial, 0)

	// Verify the key is non-zero initially.
	hasNonZero := false
	for _, b := range key.Key() {
		if b != 0 {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Fatal("key should be non-zero before Zeroize")
	}

	key.Zeroize()

	// The key's guarded memory should be destroyed after Zeroize.
	if !key.key.IsDestroyed() {
		t.Fatal("Zeroize should destroy the guarded memory")
	}
}

func TestKey_Zeroize_EmptyKey(t *testing.T) {
	// Zeroize on an empty key should not panic.
	key := NewKey(kdf.DeriveSecrets, []byte{}, 0)
	key.Zeroize()
}

func TestKeyFromStruct_RoundTrip(t *testing.T) {
	original := NewKey(kdf.DeriveSecrets, []byte("round-trip-key"), 15)
	structure, err := NewStructFromKey(original)
	if err != nil {
		t.Fatalf("NewStructFromKey: %v", err)
	}
	defer structure.Zeroize()

	reconstructed, err := NewKeyFromStruct(structure, kdf.DeriveSecrets)
	if err != nil {
		t.Fatalf("NewKeyFromStruct: %v", err)
	}
	if !bytes.Equal(reconstructed.Key(), original.Key()) {
		t.Fatal("round-trip key mismatch")
	}
	if reconstructed.Index() != original.Index() {
		t.Fatal("round-trip index mismatch")
	}
}

func TestKey_MessageKeys_ZeroizesIntermediateMaterial(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("chain-key-for-message-keys-test!"), 0)

	// MessageKeys should succeed and produce valid keys.
	msgKeys, err := key.MessageKeys()
	if err != nil {
		t.Fatalf("MessageKeys failed: %v", err)
	}

	// The message keys themselves should be non-zero (functional).
	if len(msgKeys.CipherKey()) != 32 {
		t.Fatalf("expected 32-byte cipher key, got %d", len(msgKeys.CipherKey()))
	}
	if len(msgKeys.MacKey()) != 32 {
		t.Fatalf("expected 32-byte mac key, got %d", len(msgKeys.MacKey()))
	}
	if len(msgKeys.Iv()) != 16 {
		t.Fatalf("expected 16-byte IV, got %d", len(msgKeys.Iv()))
	}
}

func TestKey_Zeroize_Idempotent(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("idempotent-test"), 0)
	key.Zeroize()
	// Calling Zeroize again should not panic.
	key.Zeroize()
}

func TestKey_SetKey_DestroysOld(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("original"), 0)
	oldSecret := key.key

	key.SetKey([]byte("replacement"))

	if !oldSecret.IsDestroyed() {
		t.Fatal("SetKey should destroy the old guarded memory")
	}
	if !bytes.Equal(key.Key(), []byte("replacement")) {
		t.Fatal("SetKey should set new key material")
	}
}
