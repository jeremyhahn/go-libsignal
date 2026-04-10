package message

import (
	"bytes"
	"testing"
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
	if !bytes.Equal(keys.CipherKey(), expectedCipher) {
		t.Fatal("CipherKey mismatch")
	}
	if !bytes.Equal(keys.MacKey(), expectedMac) {
		t.Fatal("MacKey mismatch")
	}
	if !bytes.Equal(keys.Iv(), expectedIV) {
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
	expectedCipher := []byte("cipher")
	expectedMac := []byte("mac")
	expectedIV := []byte("iv")

	structure := &KeysStructure{
		CipherKey: append([]byte(nil), expectedCipher...),
		MacKey:    append([]byte(nil), expectedMac...),
		IV:        append([]byte(nil), expectedIV...),
		Index:     99,
	}
	keys := NewKeysFromStruct(structure)
	if !bytes.Equal(keys.CipherKey(), expectedCipher) {
		t.Fatal("CipherKey mismatch")
	}
	if !bytes.Equal(keys.MacKey(), expectedMac) {
		t.Fatal("MacKey mismatch")
	}
	if !bytes.Equal(keys.Iv(), expectedIV) {
		t.Fatal("IV mismatch")
	}
	if keys.Index() != 99 {
		t.Fatalf("expected index 99, got %d", keys.Index())
	}
}

func TestNewStructFromKeys(t *testing.T) {
	keys := NewKeys([]byte("c"), []byte("m"), []byte("i"), 7)
	structure := NewStructFromKeys(keys)
	if !bytes.Equal(structure.CipherKey, []byte("c")) {
		t.Fatal("CipherKey mismatch in structure")
	}
	if !bytes.Equal(structure.MacKey, []byte("m")) {
		t.Fatal("MacKey mismatch in structure")
	}
	if !bytes.Equal(structure.IV, []byte("i")) {
		t.Fatal("IV mismatch in structure")
	}
	if structure.Index != 7 {
		t.Fatalf("expected index 7, got %d", structure.Index)
	}
}

func TestNewKeysFromStruct_RoundTrip(t *testing.T) {
	original := NewKeys([]byte("cipher32"), []byte("mac32key"), []byte("iv16"), 100)
	structure := NewStructFromKeys(original)
	reconstructed := NewKeysFromStruct(structure)

	if !bytes.Equal(reconstructed.CipherKey(), original.CipherKey()) {
		t.Fatal("round-trip CipherKey mismatch")
	}
	if !bytes.Equal(reconstructed.MacKey(), original.MacKey()) {
		t.Fatal("round-trip MacKey mismatch")
	}
	if !bytes.Equal(reconstructed.Iv(), original.Iv()) {
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
	keys := NewKeys([]byte("cipher-key"), []byte("mac-key"), []byte("iv-data"), 0)

	// Verify keys are non-zero initially.
	if len(keys.CipherKey()) == 0 {
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
	keys := NewKeys([]byte("cipher-key"), []byte("mac-key"), []byte("iv-data"), 0)
	keys.SetSeedMaterial([]byte("seed-material-32-bytes-long-xxxx"))

	if keys.SeedMaterial() == nil {
		t.Fatal("seed material should be set before Zeroize")
	}

	keys.Zeroize()

	if !keys.seedMaterial.IsDestroyed() {
		t.Fatal("Zeroize should destroy seed material guarded memory")
	}
	// SeedMaterial() returns nil after destruction.
	if keys.SeedMaterial() != nil {
		t.Fatal("SeedMaterial() should return nil after Zeroize")
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
	NewKeys(nil, []byte("mac"), []byte("iv"), 0)
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
	NewKeys([]byte("cipher"), nil, []byte("iv"), 0)
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
	NewKeys([]byte("cipher"), []byte("mac"), nil, 0)
}

func TestSeedMaterial_NilByDefault(t *testing.T) {
	keys := NewKeys([]byte("cipher"), []byte("mac"), []byte("iv"), 1)
	if keys.SeedMaterial() != nil {
		t.Fatalf("expected nil SeedMaterial by default, got %v", keys.SeedMaterial())
	}
}

func TestSetSeedMaterial(t *testing.T) {
	keys := NewKeys([]byte("cipher"), []byte("mac"), []byte("iv"), 1)
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}

	keys.SetSeedMaterial(seed)

	got := keys.SeedMaterial()
	if !bytes.Equal(got, seed) {
		t.Fatalf("SeedMaterial mismatch: got %v, want %v", got, seed)
	}
}

func TestSetSeedMaterial_Overwrite(t *testing.T) {
	keys := NewKeys([]byte("cipher"), []byte("mac"), []byte("iv"), 1)
	first := []byte("first-seed-material-32-bytes-xxx")
	second := []byte("second-seed-material-32-bytes-xx")

	keys.SetSeedMaterial(first)
	prev := keys.seedMaterial

	keys.SetSeedMaterial(second)

	// The previous secret must be destroyed when overwritten.
	if !prev.IsDestroyed() {
		t.Fatal("SetSeedMaterial must destroy the previous secret on overwrite")
	}
	if !bytes.Equal(keys.SeedMaterial(), second) {
		t.Fatal("SetSeedMaterial should overwrite previous value")
	}
}

func TestSetSeedMaterial_NilClearsPrevious(t *testing.T) {
	keys := NewKeys([]byte("cipher"), []byte("mac"), []byte("iv"), 1)
	keys.SetSeedMaterial([]byte("some-seed-material-32-bytes-xxxx"))
	prev := keys.seedMaterial

	keys.SetSeedMaterial(nil)

	// The previous secret must be destroyed when set to nil.
	if !prev.IsDestroyed() {
		t.Fatal("SetSeedMaterial(nil) must destroy the previous secret")
	}
	if keys.SeedMaterial() != nil {
		t.Fatal("SeedMaterial() should return nil after SetSeedMaterial(nil)")
	}
	if keys.seedMaterial != nil {
		t.Fatal("seedMaterial field should be nil after SetSeedMaterial(nil)")
	}
}

func TestNewKeysFromStruct_WithSeedMaterial(t *testing.T) {
	seed := []byte("seed-material-32-bytes-long-xxxx")
	structure := &KeysStructure{
		CipherKey:    []byte("cipher"),
		MacKey:       []byte("mac"),
		IV:           []byte("iv"),
		Index:        5,
		SeedMaterial: append([]byte(nil), seed...),
	}

	keys := NewKeysFromStruct(structure)

	if !bytes.Equal(keys.SeedMaterial(), seed) {
		t.Fatalf("SeedMaterial not propagated from struct: got %v, want %v", keys.SeedMaterial(), seed)
	}
	// Confirm source struct is not mutated (copy semantics).
	if !bytes.Equal(structure.SeedMaterial, seed) {
		t.Fatal("NewKeysFromStruct must not mutate source SeedMaterial")
	}
}

func TestNewStructFromKeys_WithSeedMaterial(t *testing.T) {
	seed := []byte("seed-material-32-bytes-long-xxxx")
	keys := NewKeys([]byte("cipher"), []byte("mac"), []byte("iv"), 3)
	keys.SetSeedMaterial(seed)

	structure := NewStructFromKeys(keys)

	if !bytes.Equal(structure.SeedMaterial, seed) {
		t.Fatalf("SeedMaterial not copied to struct: got %v, want %v", structure.SeedMaterial, seed)
	}
	// Confirm the struct holds an independent copy (mutation must not affect keys).
	structure.SeedMaterial[0] ^= 0xFF
	if bytes.Equal(keys.SeedMaterial(), structure.SeedMaterial) {
		t.Fatal("NewStructFromKeys must return an independent copy of SeedMaterial")
	}
}

func TestNewStructFromKeys_NoSeedMaterial(t *testing.T) {
	keys := NewKeys([]byte("cipher"), []byte("mac"), []byte("iv"), 0)
	structure := NewStructFromKeys(keys)
	if structure.SeedMaterial != nil {
		t.Fatalf("expected nil SeedMaterial in struct when not set, got %v", structure.SeedMaterial)
	}
}

func TestSeedMaterial_RoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i * 3)
	}
	original := NewKeys([]byte("cipher-32-bytes-padded-xxxxxxxxx"), []byte("mac-32-bytes-padded-xxxxxxxxxxxxx"), []byte("iv-16-bytes-pad!"), 77)
	original.SetSeedMaterial(seed)

	structure := NewStructFromKeys(original)
	reconstructed := NewKeysFromStruct(structure)

	if !bytes.Equal(reconstructed.SeedMaterial(), seed) {
		t.Fatal("SeedMaterial round-trip mismatch")
	}
	if reconstructed.Index() != 77 {
		t.Fatalf("Index round-trip mismatch: got %d", reconstructed.Index())
	}
}
