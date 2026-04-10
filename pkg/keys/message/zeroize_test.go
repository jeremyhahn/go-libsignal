package message

import (
	"bytes"
	"testing"
)

// TestKeysZeroize verifies that Zeroize destroys all guarded memory fields
// (cipherKey, macKey, iv, and seedMaterial) in a Keys instance.
func TestKeysZeroize(t *testing.T) {
	keys := NewKeys(
		[]byte{0x01, 0x02, 0x03},
		[]byte{0x04, 0x05, 0x06},
		[]byte{0x07, 0x08, 0x09},
		42,
	)

	// Set seed material to exercise its Zeroize branch too.
	keys.SetSeedMaterial([]byte{0xAA, 0xBB, 0xCC})

	// Verify all fields are alive before Zeroize.
	if keys.cipherKey == nil || keys.cipherKey.IsDestroyed() {
		t.Fatal("cipherKey should be alive before Zeroize")
	}
	if keys.macKey == nil || keys.macKey.IsDestroyed() {
		t.Fatal("macKey should be alive before Zeroize")
	}
	if keys.iv == nil || keys.iv.IsDestroyed() {
		t.Fatal("iv should be alive before Zeroize")
	}
	if keys.seedMaterial == nil || keys.seedMaterial.IsDestroyed() {
		t.Fatal("seedMaterial should be alive before Zeroize")
	}

	keys.Zeroize()

	// All fields should be destroyed after Zeroize.
	if !keys.cipherKey.IsDestroyed() {
		t.Error("cipherKey should be destroyed after Zeroize")
	}
	if !keys.macKey.IsDestroyed() {
		t.Error("macKey should be destroyed after Zeroize")
	}
	if !keys.iv.IsDestroyed() {
		t.Error("iv should be destroyed after Zeroize")
	}
	if !keys.seedMaterial.IsDestroyed() {
		t.Error("seedMaterial should be destroyed after Zeroize")
	}
}

// TestKeysZeroizeIdempotent verifies that calling Zeroize multiple times
// does not panic. All fields guard against double-destroy.
func TestKeysZeroizeIdempotent(t *testing.T) {
	keys := NewKeys([]byte{1}, []byte{2}, []byte{3}, 0)
	keys.Zeroize()
	// Second call must not panic.
	keys.Zeroize()
}

// TestKeysZeroizeNilFields verifies that Zeroize is safe when internal
// secret fields are nil (e.g., partially constructed struct).
func TestKeysZeroizeNilFields(t *testing.T) {
	// Zero-valued struct - all secret pointers are nil.
	keys := &Keys{}
	// Must not panic.
	keys.Zeroize()
}

// TestNewKeysFromStruct_WithSeedMaterialZeroize verifies the branch where
// SeedMaterial is non-empty, triggering the guarded seed allocation.
func TestNewKeysFromStruct_WithSeedMaterialZeroize(t *testing.T) {
	expectedSeed := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}
	structure := &KeysStructure{
		CipherKey:    []byte{0xAA, 0xBB},
		MacKey:       []byte{0xCC, 0xDD},
		IV:           []byte{0xEE, 0xFF},
		Index:        7,
		SeedMaterial: expectedSeed,
	}

	keys := NewKeysFromStruct(structure)

	if keys.Index() != 7 {
		t.Errorf("Index() = %d, want 7", keys.Index())
	}

	// Verify seed material was stored.
	seedMat := keys.SeedMaterial()
	if seedMat == nil {
		t.Fatal("SeedMaterial() should not be nil when structure contains seed")
	}
	if !bytes.Equal(seedMat, expectedSeed) {
		t.Errorf("SeedMaterial() = %v, want %v", seedMat, expectedSeed)
	}
}

// TestNewKeysFromStruct_EmptySeedMaterial verifies that an empty SeedMaterial
// field does not trigger the guarded seed allocation branch.
func TestNewKeysFromStruct_EmptySeedMaterial(t *testing.T) {
	structure := &KeysStructure{
		CipherKey:    []byte{0x01},
		MacKey:       []byte{0x02},
		IV:           []byte{0x03},
		Index:        0,
		SeedMaterial: nil,
	}

	keys := NewKeysFromStruct(structure)

	// SeedMaterial should be nil since the structure had none.
	if keys.SeedMaterial() != nil {
		t.Error("SeedMaterial() should be nil when structure had no seed material")
	}
}

// TestSetSeedMaterial_NilInput exercises the nil guard in SetSeedMaterial
// which returns early without allocating when seed is nil.
func TestSetSeedMaterial_NilInput(t *testing.T) {
	keys := NewKeys([]byte{1}, []byte{2}, []byte{3}, 0)

	// First set real seed material.
	keys.SetSeedMaterial([]byte{0xAA, 0xBB})
	if keys.SeedMaterial() == nil {
		t.Fatal("SeedMaterial should be non-nil after setting valid seed")
	}

	// Now set nil - this should destroy the existing seed and not allocate a new one.
	keys.SetSeedMaterial(nil)

	if keys.SeedMaterial() != nil {
		t.Error("SeedMaterial() should be nil after SetSeedMaterial(nil)")
	}
}

// TestKeysStructureZeroize verifies that KeysStructure.Zeroize overwrites all
// sensitive byte fields with zeros to prevent key material from lingering.
func TestKeysStructureZeroize(t *testing.T) {
	structure := &KeysStructure{
		CipherKey:    []byte{0xAA, 0xBB, 0xCC},
		MacKey:       []byte{0x11, 0x22, 0x33},
		IV:           []byte{0xFF, 0xEE, 0xDD},
		Index:        42,
		SeedMaterial: []byte{0x55, 0x66, 0x77},
	}

	structure.Zeroize()

	for i, b := range structure.CipherKey {
		if b != 0 {
			t.Errorf("CipherKey[%d] = 0x%02X, want 0x00 after Zeroize", i, b)
		}
	}
	for i, b := range structure.MacKey {
		if b != 0 {
			t.Errorf("MacKey[%d] = 0x%02X, want 0x00 after Zeroize", i, b)
		}
	}
	for i, b := range structure.IV {
		if b != 0 {
			t.Errorf("IV[%d] = 0x%02X, want 0x00 after Zeroize", i, b)
		}
	}
	for i, b := range structure.SeedMaterial {
		if b != 0 {
			t.Errorf("SeedMaterial[%d] = 0x%02X, want 0x00 after Zeroize", i, b)
		}
	}
}

// TestKeysStructureZeroizeNilFields verifies Zeroize is safe when fields are nil.
func TestKeysStructureZeroizeNilFields(t *testing.T) {
	structure := &KeysStructure{
		CipherKey:    nil,
		MacKey:       nil,
		IV:           nil,
		SeedMaterial: nil,
	}
	// Must not panic.
	structure.Zeroize()
}
