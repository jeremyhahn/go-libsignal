package message

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
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
		CipherKey:    mustGuard(t, []byte{0xAA, 0xBB}),
		MacKey:       mustGuard(t, []byte{0xCC, 0xDD}),
		IV:           mustGuard(t, []byte{0xEE, 0xFF}),
		Index:        7,
		SeedMaterial: mustGuard(t, expectedSeed),
	}
	defer structure.Zeroize()

	keys := mustKeysFromStruct(t, structure)

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
		CipherKey: mustGuard(t, []byte{0x01}),
		MacKey:    mustGuard(t, []byte{0x02}),
		IV:        mustGuard(t, []byte{0x03}),
		Index:     0,
		// SeedMaterial intentionally left as the zero Secret.
	}
	defer structure.Zeroize()

	keys := mustKeysFromStruct(t, structure)

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

// TestKeysStructureZeroize verifies that KeysStructure.Zeroize releases every
// guarded field, so no key material survives serialization, and that calling it
// again is safe.
func TestKeysStructureZeroize(t *testing.T) {
	structure := &KeysStructure{
		CipherKey:    mustGuard(t, []byte{0xAA, 0xBB, 0xCC}),
		MacKey:       mustGuard(t, []byte{0x11, 0x22, 0x33}),
		IV:           mustGuard(t, []byte{0xFF, 0xEE, 0xDD}),
		Index:        42,
		SeedMaterial: mustGuard(t, []byte{0x55, 0x66, 0x77}),
	}

	structure.Zeroize()

	for name, field := range map[string]*secret.Secret{
		"CipherKey":    &structure.CipherKey,
		"MacKey":       &structure.MacKey,
		"IV":           &structure.IV,
		"SeedMaterial": &structure.SeedMaterial,
	} {
		if got := secrettest.Bytes(field); got != nil {
			t.Errorf("%s still readable after Zeroize: %x", name, got)
		}
	}

	structure.Zeroize() // idempotent
}

// TestKeysStructureZeroizeNilFields verifies Zeroize is safe on a structure
// that never held any material.
func TestKeysStructureZeroizeNilFields(t *testing.T) {
	structure := &KeysStructure{}
	// Must not panic.
	structure.Zeroize()
}
