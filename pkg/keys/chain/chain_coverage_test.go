package chain

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// TestMessageKeysWithSeed verifies that MessageKeysWithSeed returns valid message
// keys with seed material attached for later SPQR re-derivation.
func TestMessageKeysWithSeed(t *testing.T) {
	key := NewKey(kdf.DeriveSecrets, []byte("chain-key-for-seed-test-32bytes!"), 3)
	keys, err := key.MessageKeysWithSeed()
	if err != nil {
		t.Fatalf("MessageKeysWithSeed failed: %v", err)
	}
	if keys == nil {
		t.Fatal("expected non-nil message keys")
	}

	// Verify the derived key fields are present and correctly sized.
	if len(mustCopy(keys.CipherKey())) != 32 {
		t.Fatalf("expected 32-byte cipher key, got %d", len(mustCopy(keys.CipherKey())))
	}
	if len(mustCopy(keys.MacKey())) != 32 {
		t.Fatalf("expected 32-byte mac key, got %d", len(mustCopy(keys.MacKey())))
	}
	if len(mustCopy(keys.Iv())) != 16 {
		t.Fatalf("expected 16-byte IV, got %d", len(mustCopy(keys.Iv())))
	}
	if keys.Index() != 3 {
		t.Fatalf("expected index 3, got %d", keys.Index())
	}

	// Verify the seed material is attached and non-empty.
	seedMat := mustCopy(keys.SeedMaterial())
	if len(seedMat) == 0 {
		t.Fatal("expected non-empty seed material")
	}
	// Seed material is the HMAC-SHA256 output from BaseMaterial, so 32 bytes.
	if len(seedMat) != 32 {
		t.Fatalf("expected 32-byte seed material, got %d", len(seedMat))
	}
}

// TestMessageKeysWithSeed_SeedIsBaseMaterial verifies that the seed material
// stored on the returned Keys matches what BaseMaterial(messageKeySeed) returns.
func TestMessageKeysWithSeed_SeedIsBaseMaterial(t *testing.T) {
	keyBytes := []byte("seed-material-test-key-32-bytes!")
	key := NewKey(kdf.DeriveSecrets, keyBytes, 7)

	// Compute the expected base material. Since NewKey zeroizes the input, we use
	// a second key with the same material for comparison.
	refKey := NewKey(kdf.DeriveSecrets, []byte("seed-material-test-key-32-bytes!"), 7)
	expectedSeed := refKey.BaseMaterial(messageKeySeed)

	msgKeys, err := key.MessageKeysWithSeed()
	if err != nil {
		t.Fatalf("MessageKeysWithSeed failed: %v", err)
	}

	if !bytes.Equal(mustCopy(msgKeys.SeedMaterial()), expectedSeed) {
		t.Fatal("seed material does not match BaseMaterial(messageKeySeed)")
	}
}

// TestMessageKeysWithSeed_ConsistentWithMessageKeys verifies that the keys
// derived by MessageKeysWithSeed match those from MessageKeys, since both
// go through the same nil-salt path.
func TestMessageKeysWithSeed_ConsistentWithMessageKeys(t *testing.T) {
	keyMat := []byte("consistent-chain-key-material-32")
	key1 := NewKey(kdf.DeriveSecrets, keyMat, 5)

	// A second identical key for MessageKeys comparison.
	key2 := NewKey(kdf.DeriveSecrets, []byte("consistent-chain-key-material-32"), 5)

	keysWithSeed, err := key1.MessageKeysWithSeed()
	if err != nil {
		t.Fatalf("MessageKeysWithSeed failed: %v", err)
	}
	keysPlain, err := key2.MessageKeys()
	if err != nil {
		t.Fatalf("MessageKeys failed: %v", err)
	}

	// Both should produce the same cipher key, mac key, and IV since they use
	// the same input key material with a nil salt.
	if !bytes.Equal(mustCopy(keysWithSeed.CipherKey()), mustCopy(keysPlain.CipherKey())) {
		t.Error("CipherKey mismatch between MessageKeysWithSeed and MessageKeys")
	}
	if !bytes.Equal(mustCopy(keysWithSeed.MacKey()), mustCopy(keysPlain.MacKey())) {
		t.Error("MacKey mismatch between MessageKeysWithSeed and MessageKeys")
	}
	if !bytes.Equal(mustCopy(keysWithSeed.Iv()), mustCopy(keysPlain.Iv())) {
		t.Error("IV mismatch between MessageKeysWithSeed and MessageKeys")
	}
}

// TestDeriveMessageKeysFromSeed verifies the public wrapper for seed-based
// key derivation with a non-nil PQR salt.
func TestDeriveMessageKeysFromSeed(t *testing.T) {
	inputKeyMaterial := make([]byte, 32)
	for i := range inputKeyMaterial {
		inputKeyMaterial[i] = byte(i + 1)
	}

	pqrSalt := make([]byte, 32)
	for i := range pqrSalt {
		pqrSalt[i] = byte(i + 100)
	}

	keys, err := DeriveMessageKeysFromSeed(kdf.DeriveSecrets, inputKeyMaterial, pqrSalt, 10)
	if err != nil {
		t.Fatalf("DeriveMessageKeysFromSeed failed: %v", err)
	}
	if keys == nil {
		t.Fatal("expected non-nil message keys")
	}
	if len(mustCopy(keys.CipherKey())) != 32 {
		t.Fatalf("expected 32-byte cipher key, got %d", len(mustCopy(keys.CipherKey())))
	}
	if len(mustCopy(keys.MacKey())) != 32 {
		t.Fatalf("expected 32-byte mac key, got %d", len(mustCopy(keys.MacKey())))
	}
	if len(mustCopy(keys.Iv())) != 16 {
		t.Fatalf("expected 16-byte IV, got %d", len(mustCopy(keys.Iv())))
	}
	if keys.Index() != 10 {
		t.Fatalf("expected index 10, got %d", keys.Index())
	}
}

// TestDeriveMessageKeysFromSeed_NilSalt verifies that DeriveMessageKeysFromSeed
// works correctly when the PQR salt is nil (no post-quantum contribution).
func TestDeriveMessageKeysFromSeed_NilSalt(t *testing.T) {
	inputKeyMaterial := make([]byte, 32)
	for i := range inputKeyMaterial {
		inputKeyMaterial[i] = byte(i + 1)
	}

	keys, err := DeriveMessageKeysFromSeed(kdf.DeriveSecrets, inputKeyMaterial, nil, 0)
	if err != nil {
		t.Fatalf("DeriveMessageKeysFromSeed with nil salt failed: %v", err)
	}
	if keys == nil {
		t.Fatal("expected non-nil keys")
	}
	if len(mustCopy(keys.CipherKey())) != 32 {
		t.Fatalf("expected 32-byte cipher key, got %d", len(mustCopy(keys.CipherKey())))
	}
}

// TestDeriveMessageKeysFromSeed_DifferentSaltsProduceDifferentKeys verifies
// that the PQR salt contributes to the derived key material.
func TestDeriveMessageKeysFromSeed_DifferentSaltsProduceDifferentKeys(t *testing.T) {
	// Derive two sets of keys from the same input but different PQR salts.
	ikm1 := make([]byte, 32)
	for i := range ikm1 {
		ikm1[i] = byte(i + 1)
	}
	ikm2 := make([]byte, 32)
	for i := range ikm2 {
		ikm2[i] = byte(i + 1)
	}

	salt1 := []byte("salt-one-32-bytes-for-testing-ok")
	salt2 := []byte("salt-two-32-bytes-for-testing-ok")

	keys1, err := DeriveMessageKeysFromSeed(kdf.DeriveSecrets, ikm1, salt1, 0)
	if err != nil {
		t.Fatalf("DeriveMessageKeysFromSeed (salt1) failed: %v", err)
	}
	keys2, err := DeriveMessageKeysFromSeed(kdf.DeriveSecrets, ikm2, salt2, 0)
	if err != nil {
		t.Fatalf("DeriveMessageKeysFromSeed (salt2) failed: %v", err)
	}

	if bytes.Equal(mustCopy(keys1.CipherKey()), mustCopy(keys2.CipherKey())) {
		t.Error("different PQR salts should produce different cipher keys")
	}
}

// TestDeriveMessageKeysFromSeed_KDFError verifies that a KDF returning an error
// is propagated correctly through deriveMessageKeysFromSeed.
func TestDeriveMessageKeysFromSeed_KDFError(t *testing.T) {
	// errorKDF always returns an error to exercise the error branch in
	// deriveMessageKeysFromSeed.
	errorKDF := func(inputKeyMaterial, salt, info []byte, outputLength int) ([]byte, error) {
		return nil, errors.New("simulated KDF failure")
	}

	inputKeyMaterial := make([]byte, 32)
	_, err := DeriveMessageKeysFromSeed(kdf.HKDF(errorKDF), inputKeyMaterial, nil, 0)
	if err == nil {
		t.Fatal("expected error from KDF failure, got nil")
	}
}

// TestSetKey_WithNilExistingKey exercises the nil check in SetKey when the key
// was constructed without prior key material and the internal key is nil.
// This verifies SetKey safely replaces existing key material.
func TestSetKey_ReplaceWithNewMaterial(t *testing.T) {
	// Start with a valid key.
	key := NewKey(kdf.DeriveSecrets, []byte("initial-key"), 0)

	// Replace multiple times to ensure old keys are always destroyed.
	key.SetKey([]byte("second-key-material"))
	if !bytes.Equal(key.Key(), []byte("second-key-material")) {
		t.Fatal("SetKey did not update key on second call")
	}

	key.SetKey([]byte("third-key-material"))
	if !bytes.Equal(key.Key(), []byte("third-key-material")) {
		t.Fatal("SetKey did not update key on third call")
	}
}

// TestMessageKeysWithSalt_WithPQRSalt verifies that MessageKeysWithSalt
// produces different keys when a non-nil PQR salt is provided.
func TestMessageKeysWithSalt_WithPQRSalt(t *testing.T) {
	keyMat := []byte("messagekeys-salt-test-key-32byte")

	key1 := NewKey(kdf.DeriveSecrets, keyMat, 1)
	key2 := NewKey(kdf.DeriveSecrets, []byte("messagekeys-salt-test-key-32byte"), 1)

	keysNoSalt, err := key1.MessageKeysWithSalt(nil)
	if err != nil {
		t.Fatalf("MessageKeysWithSalt(nil) failed: %v", err)
	}

	pqrSalt := []byte("pqr-salt-for-spqr-rederivation!")
	keysWithSalt, err := key2.MessageKeysWithSalt(pqrSalt)
	if err != nil {
		t.Fatalf("MessageKeysWithSalt(pqrSalt) failed: %v", err)
	}

	// The PQR salt should change the derived keys.
	if bytes.Equal(mustCopy(keysNoSalt.CipherKey()), mustCopy(keysWithSalt.CipherKey())) {
		t.Error("PQR salt should alter derived cipher key")
	}
}

// TestKeyStructureZeroize verifies that Zeroize releases the guarded chain key
// and that doing so twice is safe.
func TestKeyStructureZeroize(t *testing.T) {
	ks := &KeyStructure{
		Key:   mustGuard(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}),
		Index: 7,
	}

	ks.Zeroize()

	if !secrettest.Empty(&ks.Key) {
		t.Errorf("Key still readable after Zeroize")
	}
	ks.Zeroize() // idempotent
}

// TestKeyStructureZeroizeEmptyKey verifies Zeroize is safe on a structure that
// never held any material.
func TestKeyStructureZeroizeEmptyKey(t *testing.T) {
	ks := &KeyStructure{Index: 0}
	ks.Zeroize() // must not panic
}
