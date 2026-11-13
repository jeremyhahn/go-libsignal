package message

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

func TestNewKeys(t *testing.T) {
	// Keep reference copies since NewKeys zeroizes source slices.
	expectedCipher := []byte("cipherkey-32-bytes-long-exactly!")
	expectedMac := []byte("mackey-also-32-bytes-long-exact!")
	expectedIV := []byte("iv-16-bytes-lon!")
	index := uint32(42)

	cipher := make([]byte, len(expectedCipher))
	copy(cipher, expectedCipher)
	mac := make([]byte, len(expectedMac))
	copy(mac, expectedMac)
	iv := make([]byte, len(expectedIV))
	copy(iv, expectedIV)

	keys := NewKeys(cipher, mac, iv, index)
	if keys == nil {
		t.Fatal("expected non-nil Keys")
	}
	if !bytes.Equal(mustCopy(keys.CipherKey()), expectedCipher) {
		t.Fatal("CipherKey mismatch")
	}
	if !bytes.Equal(mustCopy(keys.MacKey()), expectedMac) {
		t.Fatal("MacKey mismatch")
	}
	if !bytes.Equal(mustCopy(keys.Iv()), expectedIV) {
		t.Fatal("Iv mismatch")
	}
	if keys.Index() != index {
		t.Fatalf("expected index %d, got %d", index, keys.Index())
	}
}

func TestNewKeys_ZeroIndex(t *testing.T) {
	keys := NewKeys([]byte{1}, []byte{2}, []byte{3}, 0)
	if keys.Index() != 0 {
		t.Fatalf("expected index 0, got %d", keys.Index())
	}
}

func TestNewKeysFromStruct(t *testing.T) {
	expectedCipher := fixedKey("cipher", 32)
	expectedMac := fixedKey("mac", 32)
	expectedIV := fixedKey("iv", 16)

	structure := &KeysStructure{
		CipherKey: mustGuard(t, expectedCipher),
		MacKey:    mustGuard(t, expectedMac),
		IV:        mustGuard(t, expectedIV),
		Index:     99,
	}
	defer structure.Zeroize()

	keys := mustKeysFromStruct(t, structure)
	if !bytes.Equal(mustCopy(keys.CipherKey()), expectedCipher) {
		t.Fatal("CipherKey mismatch")
	}
	if !bytes.Equal(mustCopy(keys.MacKey()), expectedMac) {
		t.Fatal("MacKey mismatch")
	}
	if !bytes.Equal(mustCopy(keys.Iv()), expectedIV) {
		t.Fatal("IV mismatch")
	}
	if keys.Index() != 99 {
		t.Fatalf("expected index 99, got %d", keys.Index())
	}
	// The clones must be independent: the source structure keeps its material.
	if !secrettest.Matches(t, &structure.CipherKey, expectedCipher) {
		t.Fatal("NewKeysFromStruct consumed the source structure's material")
	}
}

// TestNewKeysFromStruct_MissingComponent covers the error path: the
// derived-keys form is only meaningful with all three components present, so a
// structure missing one must be rejected rather than half-built.
func TestNewKeysFromStruct_MissingComponent(t *testing.T) {
	full := func(t *testing.T) *KeysStructure {
		return &KeysStructure{
			CipherKey: mustGuard(t, fixedKey("cipher", 32)),
			MacKey:    mustGuard(t, fixedKey("mac", 32)),
			IV:        mustGuard(t, fixedKey("iv", 16)),
			Index:     1,
		}
	}
	for name, drop := range map[string]func(*KeysStructure){
		"cipher key": func(s *KeysStructure) { s.CipherKey.Destroy() },
		"mac key":    func(s *KeysStructure) { s.MacKey.Destroy() },
		"iv":         func(s *KeysStructure) { s.IV.Destroy() },
	} {
		t.Run(name, func(t *testing.T) {
			structure := full(t)
			defer structure.Zeroize()
			drop(structure)

			keys, err := NewKeysFromStruct(structure)
			if keys != nil {
				t.Fatal("expected no keys")
			}
			var missing *MissingKeyError
			if !errors.As(err, &missing) {
				t.Fatalf("expected *MissingKeyError, got %#v", err)
			}
			if missing.Field != name {
				t.Fatalf("Field = %q, want %q", missing.Field, name)
			}
		})
	}

	t.Run("nil structure", func(t *testing.T) {
		keys, err := NewKeysFromStruct(nil)
		if keys != nil {
			t.Fatal("expected no keys")
		}
		var missing *MissingKeyError
		if !errors.As(err, &missing) {
			t.Fatalf("expected *MissingKeyError, got %#v", err)
		}
	})
}

func TestNewStructFromKeys(t *testing.T) {
	keys := NewKeys([]byte("c"), []byte("m"), []byte("i"), 7)
	structure := mustStructFromKeys(t, keys)
	if !secrettest.Matches(t, &structure.CipherKey, []byte("c")) {
		t.Fatal("CipherKey mismatch in structure")
	}
	if !secrettest.Matches(t, &structure.MacKey, []byte("m")) {
		t.Fatal("MacKey mismatch in structure")
	}
	if !secrettest.Matches(t, &structure.IV, []byte("i")) {
		t.Fatal("IV mismatch in structure")
	}
	if structure.Index != 7 {
		t.Fatalf("expected index 7, got %d", structure.Index)
	}
	// The structure holds its own clones, not views into the live keys.
	keys.Zeroize()
	if !secrettest.Matches(t, &structure.CipherKey, []byte("c")) {
		t.Fatal("structure shares guarded memory with the live keys")
	}
}

// TestNewStructFromKeys_DestroyedKeys covers the error path: keys whose guarded
// material is already gone cannot be serialized.
func TestNewStructFromKeys_DestroyedKeys(t *testing.T) {
	keys := NewKeys([]byte("c"), []byte("m"), []byte("i"), 7)
	keys.Zeroize()

	structure, err := NewStructFromKeys(keys)
	if structure != nil {
		t.Fatal("expected no structure")
	}
	if !errors.Is(err, secret.ErrSecretDestroyed) {
		t.Fatalf("expected ErrSecretDestroyed, got %#v", err)
	}
}

func TestNewKeysFromStruct_RoundTrip(t *testing.T) {
	original := NewKeys(fixedKey("cipher32", 32), fixedKey("mac32key", 32), fixedKey("iv16", 16), 100)
	structure := mustStructFromKeys(t, original)
	reconstructed := mustKeysFromStruct(t, structure)

	if !bytes.Equal(mustCopy(reconstructed.CipherKey()), mustCopy(original.CipherKey())) {
		t.Fatal("round-trip CipherKey mismatch")
	}
	if !bytes.Equal(mustCopy(reconstructed.MacKey()), mustCopy(original.MacKey())) {
		t.Fatal("round-trip MacKey mismatch")
	}
	if !bytes.Equal(mustCopy(reconstructed.Iv()), mustCopy(original.Iv())) {
		t.Fatal("round-trip IV mismatch")
	}
	if reconstructed.Index() != original.Index() {
		t.Fatal("round-trip Index mismatch")
	}
}

func TestConstants(t *testing.T) {
	if DerivedSecretsSize != 80 {
		t.Fatalf("expected DerivedSecretsSize 80, got %d", DerivedSecretsSize)
	}
	if CipherKeyLength != 32 {
		t.Fatalf("expected CipherKeyLength 32, got %d", CipherKeyLength)
	}
	if MacKeyLength != 32 {
		t.Fatalf("expected MacKeyLength 32, got %d", MacKeyLength)
	}
	if IVLength != 16 {
		t.Fatalf("expected IVLength 16, got %d", IVLength)
	}
	if KdfInfo != "WhisperMessageKeys" {
		t.Fatalf("expected KdfInfo 'WhisperMessageKeys', got %q", KdfInfo)
	}
}

func TestKeys_Zeroize(t *testing.T) {
	keys := NewKeys(fixedKey("cipher-key", 32), fixedKey("mac-key", 32), fixedKey("iv-data", 16), 0)

	// Verify keys are non-zero initially.
	if len(mustCopy(keys.CipherKey())) == 0 {
		t.Fatal("cipher key should be non-empty before Zeroize")
	}

	keys.Zeroize()

	if !keys.cipherKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy cipher key guarded memory")
	}
	if !keys.macKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy mac key guarded memory")
	}
	if !keys.iv.IsDestroyed() {
		t.Fatal("Zeroize should destroy iv guarded memory")
	}
}

func TestKeys_Zeroize_DestroySeedMaterial(t *testing.T) {
	keys := NewKeys(fixedKey("cipher-key", 32), fixedKey("mac-key", 32), fixedKey("iv-data", 16), 0)
	keys.SetSeedMaterial([]byte("seed-material-32-bytes-long-xxxx"))

	if mustCopy(keys.SeedMaterial()) == nil {
		t.Fatal("seed material should be set before Zeroize")
	}

	keys.Zeroize()

	if !keys.seedMaterial.IsDestroyed() {
		t.Fatal("Zeroize should destroy seed material guarded memory")
	}
	// A destroyed seed is an error, not an absent one: a nil copy here would
	// let a caller skip the PQR re-derivation.
	if seed, err := keys.SeedMaterial(); !errors.Is(err, secret.ErrSecretDestroyed) || seed != nil {
		t.Fatalf("SeedMaterial() after Zeroize = %v, %v; want nil, ErrSecretDestroyed", seed, err)
	}
}

func TestKeys_Zeroize_Idempotent(t *testing.T) {
	keys := NewKeys([]byte("c"), []byte("m"), []byte("i"), 0)
	keys.Zeroize()
	// Calling Zeroize again should not panic.
	keys.Zeroize()
}

func TestNewKeys_NilCipherKey_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic when cipher key is nil")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic string, got %T: %v", r, r)
		}
		if len(msg) == 0 {
			t.Fatal("expected non-empty panic message")
		}
	}()
	NewKeys(nil, fixedKey("mac", 32), fixedKey("iv", 16), 0)
}

func TestNewKeys_NilMacKey_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic when mac key is nil")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic string, got %T: %v", r, r)
		}
		if len(msg) == 0 {
			t.Fatal("expected non-empty panic message")
		}
	}()
	NewKeys(fixedKey("cipher", 32), nil, fixedKey("iv", 16), 0)
}

func TestNewKeys_NilIV_Panics(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic when iv is nil")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected panic string, got %T: %v", r, r)
		}
		if len(msg) == 0 {
			t.Fatal("expected non-empty panic message")
		}
	}()
	NewKeys(fixedKey("cipher", 32), fixedKey("mac", 32), nil, 0)
}

func TestSeedMaterial_NilByDefault(t *testing.T) {
	keys := NewKeys(fixedKey("cipher", 32), fixedKey("mac", 32), fixedKey("iv", 16), 1)
	if mustCopy(keys.SeedMaterial()) != nil {
		t.Fatalf("expected nil SeedMaterial by default, got %v", mustCopy(keys.SeedMaterial()))
	}
}

func TestSetSeedMaterial(t *testing.T) {
	keys := NewKeys(fixedKey("cipher", 32), fixedKey("mac", 32), fixedKey("iv", 16), 1)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	keys.SetSeedMaterial(seed)

	got := mustCopy(keys.SeedMaterial())
	if !bytes.Equal(got, seed) {
		t.Fatalf("SeedMaterial mismatch: got %v, want %v", got, seed)
	}
}

func TestSetSeedMaterial_Overwrite(t *testing.T) {
	keys := NewKeys(fixedKey("cipher", 32), fixedKey("mac", 32), fixedKey("iv", 16), 1)
	first := []byte("first-seed-material-32-bytes-xxx")
	second := []byte("second-seed-material-32-bytes-xx")

	keys.SetSeedMaterial(first)
	prev := keys.seedMaterial

	keys.SetSeedMaterial(second)

	// The previous secret must be destroyed when overwritten.
	if !prev.IsDestroyed() {
		t.Fatal("SetSeedMaterial must destroy the previous secret on overwrite")
	}
	if !bytes.Equal(mustCopy(keys.SeedMaterial()), second) {
		t.Fatal("SetSeedMaterial should overwrite previous value")
	}
}

func TestSetSeedMaterial_NilClearsPrevious(t *testing.T) {
	keys := NewKeys(fixedKey("cipher", 32), fixedKey("mac", 32), fixedKey("iv", 16), 1)
	keys.SetSeedMaterial([]byte("some-seed-material-32-bytes-xxxx"))
	prev := keys.seedMaterial

	keys.SetSeedMaterial(nil)

	// The previous secret must be destroyed when set to nil.
	if !prev.IsDestroyed() {
		t.Fatal("SetSeedMaterial(nil) must destroy the previous secret")
	}
	if mustCopy(keys.SeedMaterial()) != nil {
		t.Fatal("SeedMaterial() should return nil after SetSeedMaterial(nil)")
	}
	if keys.seedMaterial != nil {
		t.Fatal("seedMaterial field should be nil after SetSeedMaterial(nil)")
	}
}

func TestNewKeysFromStruct_WithSeedMaterial(t *testing.T) {
	seed := []byte("seed-material-32-bytes-long-xxxx")
	structure := &KeysStructure{
		CipherKey:    mustGuard(t, fixedKey("cipher", 32)),
		MacKey:       mustGuard(t, fixedKey("mac", 32)),
		IV:           mustGuard(t, fixedKey("iv", 16)),
		Index:        5,
		SeedMaterial: mustGuard(t, seed),
	}
	defer structure.Zeroize()

	keys := mustKeysFromStruct(t, structure)

	if !bytes.Equal(mustCopy(keys.SeedMaterial()), seed) {
		t.Fatalf("SeedMaterial not propagated from struct: got %v, want %v", mustCopy(keys.SeedMaterial()), seed)
	}
	// Confirm source struct is not consumed (clone semantics).
	if !secrettest.Matches(t, &structure.SeedMaterial, seed) {
		t.Fatal("NewKeysFromStruct must not consume source SeedMaterial")
	}
}

func TestNewStructFromKeys_WithSeedMaterial(t *testing.T) {
	seed := []byte("seed-material-32-bytes-long-xxxx")
	keys := NewKeys(fixedKey("cipher", 32), fixedKey("mac", 32), fixedKey("iv", 16), 3)
	keys.SetSeedMaterial(seed)

	structure := mustStructFromKeys(t, keys)

	if !secrettest.Matches(t, &structure.SeedMaterial, seed) {
		t.Fatalf("SeedMaterial not copied to struct")
	}
	// Confirm the struct holds an independent clone: releasing the live keys
	// must leave the structure's copy intact.
	keys.Zeroize()
	if !secrettest.Matches(t, &structure.SeedMaterial, seed) {
		t.Fatal("NewStructFromKeys must return an independent copy of SeedMaterial")
	}
}

func TestNewStructFromKeys_NoSeedMaterial(t *testing.T) {
	keys := NewKeys(fixedKey("cipher", 32), fixedKey("mac", 32), fixedKey("iv", 16), 0)
	structure := mustStructFromKeys(t, keys)
	if !secrettest.Empty(&structure.SeedMaterial) {
		t.Fatalf("expected no SeedMaterial in struct when not set")
	}
}

func TestSeedMaterial_RoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i * 3)
	}
	original := NewKeys(fixedKey("cipher-32-bytes-padded-xxxxxxxxx", 32), fixedKey("mac-32-bytes-padded-xxxxxxxxxxxxx", 32), []byte("iv-16-bytes-pad!"), 77)
	original.SetSeedMaterial(seed)

	structure := mustStructFromKeys(t, original)
	reconstructed := mustKeysFromStruct(t, structure)

	if !bytes.Equal(mustCopy(reconstructed.SeedMaterial()), seed) {
		t.Fatal("SeedMaterial round-trip mismatch")
	}
	if reconstructed.Index() != 77 {
		t.Fatalf("Index round-trip mismatch: got %d", reconstructed.Index())
	}
}

// TestNewSeedOnlyKeys verifies that NewSeedOnlyKeys creates a Keys with
// seed material set and nil cipher/mac/iv, matching Rust's
// MessageKeyGenerator::Seed variant at rust/protocol/src/ratchet/keys.rs:29.
func TestNewSeedOnlyKeys(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	keys := NewSeedOnlyKeys(7, seed)
	if keys == nil {
		t.Fatal("expected non-nil Keys")
	}
	if keys.Index() != 7 {
		t.Fatalf("expected index 7, got %d", keys.Index())
	}
	if !bytes.Equal(mustCopy(keys.SeedMaterial()), seed) {
		t.Fatal("SeedMaterial mismatch in NewSeedOnlyKeys")
	}
	// cipher/mac/iv must be nil in seed-only form.
	if keys.cipherKey != nil {
		t.Fatal("cipherKey must be nil for seed-only key")
	}
	if keys.macKey != nil {
		t.Fatal("macKey must be nil for seed-only key")
	}
	if keys.iv != nil {
		t.Fatal("iv must be nil for seed-only key")
	}
}

// TestNewSeedOnlyKeys_NilInput verifies that NewSeedOnlyKeys with nil seed
// produces a key with empty (but non-nil) seed material, since
// make([]byte, 0) is non-nil and secret.New accepts empty slices.
func TestNewSeedOnlyKeys_NilInput(t *testing.T) {
	// nil seed is silently treated as empty seed (len 0) because of the copy.
	keys := NewSeedOnlyKeys(0, nil)
	if keys == nil {
		t.Fatal("expected non-nil Keys even for nil seed input")
	}
	// A seed-only key whose seed is empty has no key at all: SeedMaterial
	// reports the short seed rather than returning an empty copy.
	var lengthErr *KeyLengthError
	if seed, err := keys.SeedMaterial(); !errors.As(err, &lengthErr) || seed != nil {
		t.Fatalf("SeedMaterial() = %v, %v; want nil, KeyLengthError", seed, err)
	}
}

// TestNewStructFromKeys_SeedOnlyForm verifies that NewStructFromKeys writes
// seed-only form (cipher/mac/iv empty) when seed material is present.
// Matches Rust MessageKeyGenerator::into_pb Seed variant at
// rust/protocol/src/ratchet/keys.rs:54-60.
func TestNewStructFromKeys_SeedOnlyForm(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 10)
	}
	keys := NewSeedOnlyKeys(3, seed)
	structure := mustStructFromKeys(t, keys)

	if !secrettest.Empty(&structure.CipherKey) {
		t.Fatalf("expected empty CipherKey in seed-only form")
	}
	if !secrettest.Empty(&structure.MacKey) {
		t.Fatalf("expected empty MacKey in seed-only form")
	}
	if !secrettest.Empty(&structure.IV) {
		t.Fatalf("expected empty IV in seed-only form")
	}
	if !secrettest.Matches(t, &structure.SeedMaterial, seed) {
		t.Fatal("SeedMaterial mismatch in seed-only structure")
	}
	if structure.Index != 3 {
		t.Fatalf("expected index 3, got %d", structure.Index)
	}
}

// TestNewKeysFromStruct_SeedOnlyBranch verifies that NewKeysFromStruct returns
// a seed-only Keys (nil cipher/mac/iv) when SeedMaterial is non-empty and
// cipher/mac/iv are absent. Matches Rust MessageKeyGenerator::from_pb Seed branch
// at rust/protocol/src/ratchet/keys.rs:85-86.
func TestNewKeysFromStruct_SeedOnlyBranch(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 20)
	}
	structure := &KeysStructure{
		Index:        9,
		SeedMaterial: mustGuard(t, seed),
		// CipherKey, MacKey, IV intentionally absent (seed-only form).
	}
	defer structure.Zeroize()

	keys := mustKeysFromStruct(t, structure)

	if keys.cipherKey != nil {
		t.Fatal("cipherKey must be nil in seed-only branch of NewKeysFromStruct")
	}
	if keys.macKey != nil {
		t.Fatal("macKey must be nil in seed-only branch of NewKeysFromStruct")
	}
	if keys.iv != nil {
		t.Fatal("iv must be nil in seed-only branch of NewKeysFromStruct")
	}
	if !bytes.Equal(mustCopy(keys.SeedMaterial()), seed) {
		t.Fatal("SeedMaterial mismatch from seed-only branch")
	}
	if keys.Index() != 9 {
		t.Fatalf("expected index 9, got %d", keys.Index())
	}
}
