// SignatureKeyPair must match Rust signature.rs test_signature; signing randomness comes from the same SHO after key generation.

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

	// Squeeze signing randomness from the same SHO after key generation, as Rust does.
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
