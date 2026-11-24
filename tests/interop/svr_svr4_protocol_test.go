//go:build !fips140only

// FIPS 140-3 exemption (docs/FIPS.md): the Rust SVR4 fixture uses short HKDF passwords, so the fips140only tag drops this file.

// SVR4 KDF parity with Rust svrb output_to_encryption, plus EncryptSecret and DecryptSecret round-trips.

package interop

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"

	"github.com/jeremyhahn/go-libsignal/pkg/svr"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

// svr4ProtocolVector is one entry from the fixture file.
type svr4ProtocolVector struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Inputs      json.RawMessage `json:"inputs"`
	Expected    json.RawMessage `json:"expected"`
}

type svr4ProtocolFixture struct {
	Source  string               `json:"source"`
	Purpose string               `json:"purpose"`
	Vectors []svr4ProtocolVector `json:"vectors"`
}

// svr4KDF is the svrb HKDF-SHA256 KDF: no salt, ikm input1||input2, expand info.
func svr4KDF(info []byte, input1, input2 []byte, outLen int) []byte {
	concat := append(append([]byte{}, input1...), input2...)
	h := hkdf.New(sha256.New, concat, nil, info)
	out := make([]byte, outLen)
	if _, err := io.ReadFull(h, out); err != nil {
		panic("svr4KDF: HKDF expansion failed: " + err.Error())
	}
	return out
}

// mustDecodeHex decodes a hex string; panics on failure (test setup).
func mustDecodeHexSVR(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}

// TestSVR4_EncryptionKeyKAT checks encryption_key(zeros, ones) matches Rust svrb lib.rs:581-586.
func TestSVR4_EncryptionKeyKAT(t *testing.T) {
	raw := loader.MustRead("svr/svr4_protocol.json")

	var fix svr4ProtocolFixture
	if err := json.Unmarshal(raw, &fix); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}
	if len(fix.Vectors) == 0 {
		t.Fatal("fixture has no vectors")
	}

	for _, vec := range fix.Vectors {
		vec := vec
		t.Run(vec.Name, func(t *testing.T) {
			switch vec.Name {
			case "encryption_key_zeros_ones":
				testEncryptionKeyZerosOnes(t, vec)
			case "password_to_uniform_input_known":
				testPasswordToUniformInput(t, vec, "746573742d70617373776f7264")
			case "password_to_uniform_input_empty":
				testPasswordToUniformInput(t, vec, "")
			case "encrypt_decrypt_secret_round_trip":
				testEncryptDecryptSecretRoundTrip(t, vec)
			default:
				t.Logf("unhandled vector %q — skipping", vec.Name)
			}
		})
	}
}

// testEncryptionKeyZerosOnes exercises the encryption_key KDF with all-zeros
// s_enc and all-ones k_auth, mirroring Rust svrb::test::output_to_encryption.
// It verifies the KDF label "Signal_SVR_EncryptionKey_20240823" and the
// HKDF-SHA256 construction are byte-identical to Rust.
func testEncryptionKeyZerosOnes(t *testing.T, vec svr4ProtocolVector) {
	t.Helper()

	var inputs struct {
		SEnc  string `json:"s_enc"`
		KAuth string `json:"k_auth"`
	}
	if err := json.Unmarshal(vec.Inputs, &inputs); err != nil {
		t.Fatalf("unmarshal inputs: %v", err)
	}
	var expected struct {
		EncryptionKey string `json:"encryption_key"`
	}
	if err := json.Unmarshal(vec.Expected, &expected); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}

	sEnc := mustDecodeHexSVR(t, inputs.SEnc)
	kAuth := mustDecodeHexSVR(t, inputs.KAuth)
	want := mustDecodeHexSVR(t, expected.EncryptionKey)

	// Drive the KDF via the same construction Go pkg/svr uses internally.
	// info = "Signal_SVR_EncryptionKey_20240823", IKM = s_enc || k_auth.
	got := svr4KDF([]byte("Signal_SVR_EncryptionKey_20240823"), sEnc, kAuth, 32)

	if !bytes.Equal(got, want) {
		t.Fatalf("encryption_key mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// testPasswordToUniformInput verifies that the passwordToUniformInput KDF
// produces the pinned output for the given password hex (empty string = empty
// password). Uses KDF label "Signal_SVR_InputFromPassword_20240823".
func testPasswordToUniformInput(t *testing.T, vec svr4ProtocolVector, passwordHex string) {
	t.Helper()

	var expected struct {
		UniformInput string `json:"uniform_input"`
	}
	if err := json.Unmarshal(vec.Expected, &expected); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}

	var password []byte
	if passwordHex != "" {
		var err error
		password, err = hex.DecodeString(passwordHex)
		if err != nil {
			t.Fatalf("hex decode password: %v", err)
		}
	}

	want := mustDecodeHexSVR(t, expected.UniformInput)

	// Mirrors Rust: Kdf::make(b"Signal_SVR_InputFromPassword_20240823", passwd, b"")
	got := svr4KDF([]byte("Signal_SVR_InputFromPassword_20240823"), password, nil, 64)

	if !bytes.Equal(got, want) {
		t.Fatalf("passwordToUniformInput mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// testEncryptDecryptSecretRoundTrip checks EncryptSecret and DecryptSecret round-trip through AES-256-GCM-SIV.
func testEncryptDecryptSecretRoundTrip(t *testing.T, vec svr4ProtocolVector) {
	t.Helper()

	var inputs struct {
		Key    string `json:"key"`
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(vec.Inputs, &inputs); err != nil {
		t.Fatalf("unmarshal inputs: %v", err)
	}
	var expected struct {
		PlaintextAfterDecrypt string `json:"plaintext_after_decrypt"`
	}
	if err := json.Unmarshal(vec.Expected, &expected); err != nil {
		t.Fatalf("unmarshal expected: %v", err)
	}

	keyBytes := mustDecodeHexSVR(t, inputs.Key)
	secretBytes := mustDecodeHexSVR(t, inputs.Secret)
	want := mustDecodeHexSVR(t, expected.PlaintextAfterDecrypt)

	var key [32]byte
	copy(key[:], keyBytes)

	var secret svr.Secret
	copy(secret[:], secretBytes)

	encrypted, err := svr.EncryptSecret(key, secret)
	if err != nil {
		t.Fatalf("EncryptSecret: %v", err)
	}

	decrypted, err := svr.DecryptSecret(key, encrypted)
	if err != nil {
		t.Fatalf("DecryptSecret: %v", err)
	}

	if !bytes.Equal(decrypted[:], want) {
		t.Fatalf("decrypted secret mismatch:\n  got  %x\n  want %x", decrypted[:], want)
	}

	// Confirm that tampering with the ciphertext causes decryption to fail.
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[0] ^= 0xFF
	if _, err := svr.DecryptSecret(key, tampered); err == nil {
		t.Fatal("DecryptSecret: expected error for tampered ciphertext, got nil")
	}

	// Confirm that a wrong key causes decryption to fail.
	var wrongKey [32]byte
	copy(wrongKey[:], keyBytes)
	wrongKey[0] ^= 0xFF
	if _, err := svr.DecryptSecret(wrongKey, encrypted); err == nil {
		t.Fatal("DecryptSecret: expected error for wrong key, got nil")
	}
}
