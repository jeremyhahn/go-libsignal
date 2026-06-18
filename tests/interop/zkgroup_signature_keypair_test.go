// Conformance test: zkgroup raw SignatureKeyPair byte-identical to Rust.
//
// Mirrors rust/zkgroup/src/crypto/signature.rs::tests::test_signature:
//
//   1. let mut sho = Sho::new(b"Test_Signature", TEST_ARRAY_32);
//   2. let key_pair = KeyPair::generate(&mut sho);
//   3. let signature = key_pair.sign(TEST_ARRAY_32_1, &mut sho);
//   4. assert signature == EXPECTED_HEX
//
// In Go, KeyPair::sign is a method on SignatureKeyPair that takes
// randomness as an argument. Rust derives that randomness by squeezing
// 32 more bytes from the SAME SHO that generate consumed; we replicate
// that exact ordering so the byte output matches.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type signatureKeypairFixture struct {
	ShoLabel             string `json:"sho_label"`
	GroupKeySeed         string `json:"group_key_seed"`
	MessageSeed          string `json:"message_seed"`
	ExpectedSignatureHex string `json:"expected_signature_hex"`
}

// TestZkgroup_SignatureKeyPair_KAT proves that Go's GenerateSignatureKeyPair +
// SignatureKeyPair.Sign chain produces a byte-identical 64-byte signature
// to Rust libsignal for the canonical test_signature inputs.
func TestZkgroup_SignatureKeyPair_KAT(t *testing.T) {
	raw := loader.MustRead("zkgroup/signature_keypair_known_answers.json")
	var fx signatureKeypairFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	wantSig, err := hex.DecodeString(strings.ReplaceAll(fx.ExpectedSignatureHex, " ", ""))
	if err != nil {
		t.Fatalf("decode expected signature: %v", err)
	}
	if len(wantSig) != 64 {
		t.Fatalf("expected 64-byte signature, got %d bytes", len(wantSig))
	}

	groupKey := fillRange(0)  // TEST_ARRAY_32
	message := fillRange(100) // TEST_ARRAY_32_1

	// Step 1: Initialize the SHO and absorb the group key.
	sho := zkcredential.NewShoHmacSha256Ext(fx.ShoLabel)
	sho.AbsorbAndRatchet(groupKey[:])

	// Step 2: Generate the key pair from the SHO state. This consumes
	// 64 bytes from the SHO (Scalar derivation via squeeze-and-ratchet).
	kp, err := zkgroup.GenerateSignatureKeyPair(sho)
	if err != nil {
		t.Fatalf("GenerateSignatureKeyPair: %v", err)
	}

	// Step 3: Squeeze the 32-byte signing randomness from the SAME SHO.
	// This must come AFTER the GenerateSignatureKeyPair squeeze so the
	// SHO transcript matches Rust's KeyPair::generate(...) +
	// KeyPair::sign(message, sho) sequence.
	randomness := sho.SqueezeAndRatchet(32)

	// Step 4: Sign and assert byte-equality.
	gotSig, err := kp.Sign(message[:], randomness)
	if err != nil {
		t.Fatalf("SignatureKeyPair.Sign: %v", err)
	}
	if hex.EncodeToString(gotSig) != hex.EncodeToString(wantSig) {
		t.Fatalf("signature mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(gotSig), hex.EncodeToString(wantSig))
	}

	// Verify round-trips on the public key.
	pub := kp.GetPublicKey()
	if err := pub.Verify(message[:], gotSig); err != nil {
		t.Fatalf("Verify rejected its own signature: %v", err)
	}

	// Negative: tampered message must reject.
	tampered := message
	tampered[0] ^= 0x01
	if err := pub.Verify(tampered[:], gotSig); err == nil {
		t.Fatal("Verify accepted signature on tampered message")
	}
}
