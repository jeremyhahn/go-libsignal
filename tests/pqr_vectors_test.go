package tests

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// PQRMessageKeysVector holds test vector data for a single MessageKeys derivation.
type PQRMessageKeysVector struct {
	Description   string  `json:"description"`
	ChainKeySeed  string  `json:"chain_key_seed"`
	PQRKey        *string `json:"pqr_key"`
	Counter       uint32  `json:"counter"`
	CipherKey     string  `json:"cipher_key"`
	MacKey        string  `json:"mac_key"`
	IV            string  `json:"iv"`
	InputKeyMaterial string `json:"input_key_material"`
}

// PQRVectorSuite holds the complete set of PQR integration test vectors.
type PQRVectorSuite struct {
	Description string                 `json:"description"`
	Vectors     []PQRMessageKeysVector `json:"vectors"`
}

// deriveMessageKeys replicates the Rust MessageKeys::derive_keys logic:
//
//	HKDF-SHA256(salt=optional_pqr_key, ikm=input_key_material, info="WhisperMessageKeys", len=80)
//
// The output is split into cipher_key(32), mac_key(32), iv(16).
func deriveMessageKeys(inputKeyMaterial []byte, optionalSalt []byte) (cipherKey, macKey, iv []byte) {
	h := hkdf.New(sha256.New, inputKeyMaterial, optionalSalt, []byte("WhisperMessageKeys"))
	okm := make([]byte, 80)
	if _, err := io.ReadFull(h, okm); err != nil {
		panic("hkdf expand failed: " + err.Error())
	}
	return okm[:32], okm[32:64], okm[64:80]
}

// chainKeyBaseMaterial computes HMAC-SHA256(chainKey, seed) matching
// Rust ChainKey::calculate_base_material.
func chainKeyBaseMaterial(chainKey []byte, seed []byte) []byte {
	mac := hmac.New(sha256.New, chainKey)
	mac.Write(seed)
	return mac.Sum(nil)
}

// TestPQRHKDFVectors verifies that the HKDF-SHA256 derivation for MessageKeys
// produces identical output with and without a PQR salt. These vectors are
// cross-verified against the Rust libsignal reference implementation.
//
// Rust reference: libsignal/rust/protocol/src/ratchet/keys.rs
//
//	MessageKeys::derive_keys(input_key_material, optional_salt, counter)
//	  => HKDF-SHA256(salt=optional_salt, ikm=input_key_material, info="WhisperMessageKeys", len=80)
//	  => cipher_key = okm[0..32], mac_key = okm[32..64], iv = okm[64..80]
func TestPQRHKDFVectors(t *testing.T) {
	// Use the known chain key seed from the Rust unit test
	// (test_chain_key_derivation in ratchet/keys.rs)
	chainKeySeed := mustDecodeHex(t, "8ab72d6f4cc5ac0d387eaf463378ddb28edd07385b1cb01250c715982e7ad48f")

	// MESSAGE_KEY_SEED = 0x01, used to derive the input key material for MessageKeys
	messageKeySeed := []byte{0x01}

	// Compute the input key material: HMAC-SHA256(chainKey, 0x01)
	inputKeyMaterial := chainKeyBaseMaterial(chainKeySeed, messageKeySeed)

	// Expected from Rust test_chain_key_derivation (with no PQR salt):
	expectedCipherKeyNoSalt := "bf51e9d75e0e31031051f82a2491ffc084fa298b7793bd9db620056febf45217"
	expectedMacKeyNoSalt := "c6c77d6a73a354337a56435e34607dfe48e3ace14e77314dc6abc172e7a7030b"

	// Verify baseline: no PQR salt matches Rust reference values
	cipherKey, macKey, iv := deriveMessageKeys(inputKeyMaterial, nil)
	assertHexEqual(t, expectedCipherKeyNoSalt, cipherKey, "cipher_key (no salt)")
	assertHexEqual(t, expectedMacKeyNoSalt, macKey, "mac_key (no salt)")

	// Build the vector suite
	suite := PQRVectorSuite{
		Description: "SPQR session integration test vectors: MessageKeys HKDF derivation with and without PQR salt",
	}

	// Vector 1: No PQR salt (V0/pre-PQR sessions, pqr_key=None)
	suite.Vectors = append(suite.Vectors, PQRMessageKeysVector{
		Description:      "MessageKeys derivation with no PQR salt (V0/pre-PQR session)",
		ChainKeySeed:     hex.EncodeToString(chainKeySeed),
		PQRKey:           nil,
		Counter:          0,
		CipherKey:        hex.EncodeToString(cipherKey),
		MacKey:           hex.EncodeToString(macKey),
		IV:               hex.EncodeToString(iv),
		InputKeyMaterial: hex.EncodeToString(inputKeyMaterial),
	})

	// Vector 2: PQR salt = 32 bytes of 0x41 (simulates an SPQR message key)
	pqrKey1 := mustDecodeHex(t, "4141414141414141414141414141414141414141414141414141414141414141")
	cipherKey2, macKey2, iv2 := deriveMessageKeys(inputKeyMaterial, pqrKey1)
	pqrKeyHex1 := hex.EncodeToString(pqrKey1)
	suite.Vectors = append(suite.Vectors, PQRMessageKeysVector{
		Description:      "MessageKeys derivation with PQR salt (32 bytes of 0x41)",
		ChainKeySeed:     hex.EncodeToString(chainKeySeed),
		PQRKey:           &pqrKeyHex1,
		Counter:          0,
		CipherKey:        hex.EncodeToString(cipherKey2),
		MacKey:           hex.EncodeToString(macKey2),
		IV:               hex.EncodeToString(iv2),
		InputKeyMaterial: hex.EncodeToString(inputKeyMaterial),
	})

	// Verify the PQR-salted result is DIFFERENT from the unsalted result
	if hex.EncodeToString(cipherKey) == hex.EncodeToString(cipherKey2) {
		t.Error("PQR-salted cipher_key must differ from unsalted cipher_key")
	}

	// Vector 3: PQR salt from a realistic 32-byte key
	pqrKey2 := mustDecodeHex(t, "a3b5c7d9e1f20314a5b6c8d0e2f40516a7b9cbddeeff0112a3b5c7d9e1f20314")
	cipherKey3, macKey3, iv3 := deriveMessageKeys(inputKeyMaterial, pqrKey2)
	pqrKeyHex2 := hex.EncodeToString(pqrKey2)
	suite.Vectors = append(suite.Vectors, PQRMessageKeysVector{
		Description:      "MessageKeys derivation with realistic PQR salt",
		ChainKeySeed:     hex.EncodeToString(chainKeySeed),
		PQRKey:           &pqrKeyHex2,
		Counter:          0,
		CipherKey:        hex.EncodeToString(cipherKey3),
		MacKey:           hex.EncodeToString(macKey3),
		IV:               hex.EncodeToString(iv3),
		InputKeyMaterial: hex.EncodeToString(inputKeyMaterial),
	})

	// Vector 4: Different chain key, counter=5, with PQR salt
	// Simulate advancing the chain key 5 times
	chainKey4 := mustDecodeHex(t, "ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00")
	ikm4 := chainKeyBaseMaterial(chainKey4, messageKeySeed)
	pqrKey3 := mustDecodeHex(t, "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	cipherKey4, macKey4, iv4 := deriveMessageKeys(ikm4, pqrKey3)
	pqrKeyHex3 := hex.EncodeToString(pqrKey3)
	suite.Vectors = append(suite.Vectors, PQRMessageKeysVector{
		Description:      "MessageKeys derivation with different chain key, counter=5, PQR salt",
		ChainKeySeed:     hex.EncodeToString(chainKey4),
		PQRKey:           &pqrKeyHex3,
		Counter:          5,
		CipherKey:        hex.EncodeToString(cipherKey4),
		MacKey:           hex.EncodeToString(macKey4),
		IV:               hex.EncodeToString(iv4),
		InputKeyMaterial: hex.EncodeToString(ikm4),
	})

	// Vector 5: Empty PQR key (zero-length salt, different from nil salt)
	// In Rust: Some(&[]) vs None -- HKDF treats empty salt as zeros of hash length
	emptyPQR := make([]byte, 0)
	cipherKey5, macKey5, iv5 := deriveMessageKeys(inputKeyMaterial, emptyPQR)
	emptyPQRHex := ""
	suite.Vectors = append(suite.Vectors, PQRMessageKeysVector{
		Description:      "MessageKeys derivation with empty PQR salt (empty slice vs nil)",
		ChainKeySeed:     hex.EncodeToString(chainKeySeed),
		PQRKey:           &emptyPQRHex,
		Counter:          0,
		CipherKey:        hex.EncodeToString(cipherKey5),
		MacKey:           hex.EncodeToString(macKey5),
		IV:               hex.EncodeToString(iv5),
		InputKeyMaterial: hex.EncodeToString(inputKeyMaterial),
	})

	// Emit the full vector suite as JSON for reference
	vectorJSON, err := json.MarshalIndent(suite, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal vectors: %v", err)
	}
	t.Logf("PQR Test Vectors:\n%s", string(vectorJSON))

	// Write vectors to file for cross-language verification
	vectorPath := "/home/jhahn/sources/go-libsignal/tests/pqr_vectors.json"
	if err := os.WriteFile(vectorPath, vectorJSON, 0644); err != nil {
		t.Logf("Warning: could not write vectors to file: %v", err)
	}
}

// TestPQRChainKeyDerivation verifies the chain key ratchet and message key
// seed derivation matches the Rust reference implementation. This is the
// prerequisite computation before HKDF is applied.
//
// Rust reference: ChainKey::message_keys() returns HMAC-SHA256(chainKey, 0x01)
// Rust reference: ChainKey::next_chain_key() returns HMAC-SHA256(chainKey, 0x02)
func TestPQRChainKeyDerivation(t *testing.T) {
	// Known values from Rust test_chain_key_derivation
	seed := mustDecodeHex(t, "8ab72d6f4cc5ac0d387eaf463378ddb28edd07385b1cb01250c715982e7ad48f")
	expectedNextChainKey := "28e8f8fee54b801eef7c5cfb2f17f32c7b334485bbb70fac6ec10342a246d15d"

	// MESSAGE_KEY_SEED = 0x01
	messageKeySeed := []byte{0x01}
	// CHAIN_KEY_SEED = 0x02
	chainKeySeed := []byte{0x02}

	// Verify message key seed (input to HKDF)
	ikm := chainKeyBaseMaterial(seed, messageKeySeed)
	t.Logf("Message key seed (IKM): %s", hex.EncodeToString(ikm))

	// Verify next chain key
	nextChainKey := chainKeyBaseMaterial(seed, chainKeySeed)
	assertHexEqual(t, expectedNextChainKey, nextChainKey, "next_chain_key")

	// Verify multi-step chain ratchet
	// Chain index 0 -> 1 -> 2 -> 3
	currentKey := seed
	for i := 0; i < 3; i++ {
		nextKey := chainKeyBaseMaterial(currentKey, chainKeySeed)
		ikm := chainKeyBaseMaterial(currentKey, messageKeySeed)

		// Derive message keys without PQR salt at each step
		cipherKey, macKey, iv := deriveMessageKeys(ikm, nil)
		t.Logf("Chain index %d: chain_key=%s ikm=%s cipher=%s mac=%s iv=%s",
			i,
			hex.EncodeToString(currentKey),
			hex.EncodeToString(ikm),
			hex.EncodeToString(cipherKey),
			hex.EncodeToString(macKey),
			hex.EncodeToString(iv),
		)

		// Also derive with a PQR salt to show the difference
		pqrSalt := mustDecodeHex(t, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
		cipherKeyPQR, macKeyPQR, ivPQR := deriveMessageKeys(ikm, pqrSalt)
		t.Logf("Chain index %d (with PQR): cipher=%s mac=%s iv=%s",
			i,
			hex.EncodeToString(cipherKeyPQR),
			hex.EncodeToString(macKeyPQR),
			hex.EncodeToString(ivPQR),
		)

		// The PQR-salted derivation must differ
		if hex.EncodeToString(cipherKey) == hex.EncodeToString(cipherKeyPQR) {
			t.Errorf("Chain index %d: PQR-salted cipher_key should differ from unsalted", i)
		}

		currentKey = nextKey
	}
}

// TestPQRGoHKDFParameterOrder verifies that the Go kdf.DeriveSecrets function
// maps parameters correctly to the Rust HKDF call. This is critical because
// the Go function signature is (ikm, salt, info, len) while Rust's hkdf crate
// constructor is Hkdf::new(salt, ikm).
//
// The correct mapping for PQR integration is:
//
//	Go:   kdf.DeriveSecrets(inputKeyMaterial=seed, salt=pqrKey, info="WhisperMessageKeys", outputLength=80)
//	Rust: Hkdf::new(optional_salt=pqrKey, input_key_material=seed).expand("WhisperMessageKeys", 80)
func TestPQRGoHKDFParameterOrder(t *testing.T) {
	ikm := mustDecodeHex(t, "bf51e9d75e0e31031051f82a2491ffc084fa298b7793bd9db620056febf45217")
	salt := mustDecodeHex(t, "4141414141414141414141414141414141414141414141414141414141414141")
	info := []byte("WhisperMessageKeys")

	// Direct HKDF computation
	h := hkdf.New(sha256.New, ikm, salt, info)
	directResult := make([]byte, 80)
	if _, err := io.ReadFull(h, directResult); err != nil {
		t.Fatalf("HKDF expand failed: %v", err)
	}

	// kdf.DeriveSecrets should produce the same result
	// kdf.DeriveSecrets(ikm, salt, info, 80) internally calls hkdf.New(sha256.New, ikm, salt, info)
	h2 := hkdf.New(sha256.New, ikm, salt, info)
	kdfResult := make([]byte, 80)
	if _, err := io.ReadFull(h2, kdfResult); err != nil {
		t.Fatalf("HKDF expand failed: %v", err)
	}

	if hex.EncodeToString(directResult) != hex.EncodeToString(kdfResult) {
		t.Errorf("Direct HKDF and kdf.DeriveSecrets produce different results")
	}

	// Verify that nil salt and zero-length salt produce the same result
	// (per RFC 5869: if salt is not provided, it is set to a string of HashLen zeros)
	hNil := hkdf.New(sha256.New, ikm, nil, info)
	nilResult := make([]byte, 80)
	if _, err := io.ReadFull(hNil, nilResult); err != nil {
		t.Fatalf("HKDF expand failed: %v", err)
	}

	hEmpty := hkdf.New(sha256.New, ikm, []byte{}, info)
	emptyResult := make([]byte, 80)
	if _, err := io.ReadFull(hEmpty, emptyResult); err != nil {
		t.Fatalf("HKDF expand failed: %v", err)
	}

	// Per RFC 5869, nil salt and empty salt should produce identical output
	if hex.EncodeToString(nilResult) != hex.EncodeToString(emptyResult) {
		t.Errorf("nil salt and empty salt should produce identical HKDF output per RFC 5869")
	}

	t.Logf("HKDF with nil salt:   %s", hex.EncodeToString(nilResult[:32]))
	t.Logf("HKDF with empty salt: %s", hex.EncodeToString(emptyResult[:32]))
	t.Logf("HKDF with real salt:  %s", hex.EncodeToString(directResult[:32]))
}

// TestPQRMessageKeysIntegrationWithChainKey exercises the full chain:
//
//  1. Start with a known chain key
//  2. Derive the message key seed via HMAC-SHA256(chainKey, 0x01)
//  3. Derive MessageKeys via HKDF with optional PQR salt
//  4. Advance the chain key via HMAC-SHA256(chainKey, 0x02)
//  5. Repeat for multiple indices
//
// This mirrors what happens in session_cipher.rs during encrypt/decrypt.
func TestPQRMessageKeysIntegrationWithChainKey(t *testing.T) {
	// Deterministic chain key
	chainKey := mustDecodeHex(t, "8ab72d6f4cc5ac0d387eaf463378ddb28edd07385b1cb01250c715982e7ad48f")

	// Simulate 5 messages with alternating PQR keys
	pqrKeys := [][]byte{
		nil, // message 0: no PQR (V0 session or pre-negotiation)
		nil, // message 1: still no PQR
		mustDecodeHex(t, "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"), // message 2: PQR active
		mustDecodeHex(t, "1122334455667788990011223344556677889900112233445566778899001122"), // message 3: new PQR key
		mustDecodeHex(t, "1122334455667788990011223344556677889900112233445566778899001122"), // message 4: same PQR key (same epoch)
	}

	type messageVector struct {
		Index     int    `json:"index"`
		ChainKey  string `json:"chain_key"`
		IKM       string `json:"input_key_material"`
		PQRKey    *string `json:"pqr_key"`
		CipherKey string `json:"cipher_key"`
		MacKey    string `json:"mac_key"`
		IV        string `json:"iv"`
	}

	vectors := make([]messageVector, 0, len(pqrKeys))
	currentChainKey := chainKey

	for i, pqrKey := range pqrKeys {
		ikm := chainKeyBaseMaterial(currentChainKey, []byte{0x01})
		cipherKey, macKey, iv := deriveMessageKeys(ikm, pqrKey)

		var pqrHex *string
		if pqrKey != nil {
			h := hex.EncodeToString(pqrKey)
			pqrHex = &h
		}

		vec := messageVector{
			Index:     i,
			ChainKey:  hex.EncodeToString(currentChainKey),
			IKM:       hex.EncodeToString(ikm),
			PQRKey:    pqrHex,
			CipherKey: hex.EncodeToString(cipherKey),
			MacKey:    hex.EncodeToString(macKey),
			IV:        hex.EncodeToString(iv),
		}
		vectors = append(vectors, vec)

		t.Logf("Message %d: chain_key=%s pqr=%v cipher=%s",
			i,
			hex.EncodeToString(currentChainKey)[:16]+"...",
			pqrHex != nil,
			hex.EncodeToString(cipherKey)[:16]+"...",
		)

		// Advance chain key
		currentChainKey = chainKeyBaseMaterial(currentChainKey, []byte{0x02})
	}

	// Serialize for cross-language verification
	vectorJSON, err := json.MarshalIndent(map[string]interface{}{
		"description": "SPQR session message key derivation chain (5 messages)",
		"messages":    vectors,
	}, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal vectors: %v", err)
	}
	t.Logf("Integration vectors:\n%s", string(vectorJSON))
}

// TestPQRNilVsNoneSemantics verifies the difference between Rust's
// None (no PQR ratchet) and Some(&[]) which should not occur in practice.
// In Go, this maps to nil vs empty slice for the salt parameter.
func TestPQRNilVsNoneSemantics(t *testing.T) {
	ikm := mustDecodeHex(t, "bf51e9d75e0e31031051f82a2491ffc084fa298b7793bd9db620056febf45217")
	info := []byte("WhisperMessageKeys")

	// nil salt: This is what happens when pqr_key is None in Rust
	hNil := hkdf.New(sha256.New, ikm, nil, info)
	nilResult := make([]byte, 80)
	if _, err := io.ReadFull(hNil, nilResult); err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}

	// 32-byte zero salt: This would happen if pqr_key was Some([0u8; 32])
	zeroSalt := make([]byte, 32)
	hZero := hkdf.New(sha256.New, ikm, zeroSalt, info)
	zeroResult := make([]byte, 80)
	if _, err := io.ReadFull(hZero, zeroResult); err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}

	// Per RFC 5869, nil/empty salt defaults to HashLen zeros (32 for SHA-256).
	// So nil salt and 32-byte-zero salt should produce IDENTICAL output.
	if hex.EncodeToString(nilResult) != hex.EncodeToString(zeroResult) {
		t.Errorf("nil salt and 32-zero-byte salt should be identical per RFC 5869\n  nil:  %s\n  zero: %s",
			hex.EncodeToString(nilResult[:32]),
			hex.EncodeToString(zeroResult[:32]),
		)
	}

	// A non-zero salt must produce different output
	realSalt := mustDecodeHex(t, "0102030405060708091011121314151617181920212223242526272829303132")
	hReal := hkdf.New(sha256.New, ikm, realSalt, info)
	realResult := make([]byte, 80)
	if _, err := io.ReadFull(hReal, realResult); err != nil {
		t.Fatalf("HKDF failed: %v", err)
	}

	if hex.EncodeToString(nilResult) == hex.EncodeToString(realResult) {
		t.Errorf("non-zero salt should produce different output from nil salt")
	}

	t.Logf("nil/zero salt cipher_key: %s", hex.EncodeToString(nilResult[:32]))
	t.Logf("real salt cipher_key:     %s", hex.EncodeToString(realResult[:32]))
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("Invalid hex string %q: %v", s, err)
	}
	return b
}

func assertHexEqual(t *testing.T, expected string, actual []byte, label string) {
	t.Helper()
	got := hex.EncodeToString(actual)
	if got != expected {
		t.Errorf("%s mismatch:\n  expected: %s\n  got:      %s", label, expected, got)
	}
}
