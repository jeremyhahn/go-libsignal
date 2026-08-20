//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 2 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package ecc

// VXEdDSA internal-consistency tests.
//
// Rust libsignal has no VXEdDSA test vectors because VXEdDSA is only used
// internally to derive VRF outputs and the Rust test suite does not expose a
// deterministic sign API for it. These tests therefore verify INTERNAL
// CONSISTENCY of the Go implementation rather than cross-implementation KAT
// parity:
//
//  1. For N deterministic (seed, message) tuples, sign each message and
//     verify the resulting signature. Every verification must succeed.
//  2. For each signature, flip every bit in every byte of the 96-byte
//     signature blob and assert that verification rejects all 768 corrupted
//     variants.
//
// This mirrors the XEdDSA KAT pattern in xeddsa_kat_test.go:
// TestXEdDSA_KAT_RustVector/single_bit_flip_always_rejected.

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// consistencyTuple is one (private key, message) pair for which we verify
// sign→verify round-trip and exhaustive single-bit-flip rejection.
type consistencyTuple struct {
	name    string
	privKey [32]byte
	message []byte
}

// vxeddsaConsistencyTuples returns 20 deterministic (seed, message) tuples.
// Seeds are derived by hashing a counter through SHA-256 to produce realistic
// key material spread across the Curve25519 scalar space. Messages cover a
// range of lengths and content patterns to exercise different code paths.
func vxeddsaConsistencyTuples() []consistencyTuple {
	tuples := make([]consistencyTuple, 0, 20)

	for i := uint64(0); i < 20; i++ {
		// Derive a deterministic 32-byte private key from the counter.
		var seedInput [8]byte
		binary.LittleEndian.PutUint64(seedInput[:], i)
		privKeyBytes := sha256.Sum256(seedInput[:])

		var privKey [32]byte
		copy(privKey[:], privKeyBytes[:])
		// Clamp per Curve25519 spec (scalar clamping is applied internally by
		// SetBytesWithClamping, but we clamp here to match how real keys are
		// generated, ensuring public-key derivation is consistent).
		privKey[0] &= 248
		privKey[31] &= 127
		privKey[31] |= 64

		// Message derived from the counter: vary length (0 to 63 bytes) and
		// content to exercise different hash-to-point inputs.
		msgLen := int(i * 3) // 0, 3, 6, ... 57 bytes
		msg := make([]byte, msgLen)
		for j := range msg {
			msg[j] = byte((i*7 + uint64(j)*13) & 0xFF)
		}

		tuples = append(tuples, consistencyTuple{
			name:    string([]byte{'t', 'u', 'p', 'l', 'e', '_', byte('0' + i/10), byte('0' + i%10)}),
			privKey: privKey,
			message: msg,
		})
	}
	return tuples
}

// TestVXEdDSAConsistency_SignVerifyRoundTrip verifies that for each of the 20
// deterministic (key, message) tuples, sign followed by verify always succeeds
// and the VRF output matches.
func TestVXEdDSAConsistency_SignVerifyRoundTrip(t *testing.T) {
	tuples := vxeddsaConsistencyTuples()
	if len(tuples) != 20 {
		t.Fatalf("expected 20 tuples, got %d", len(tuples))
	}

	for _, tc := range tuples {
		t.Run(tc.name, func(t *testing.T) {
			privKey := tc.privKey

			var pubKey [32]byte
			curve25519.ScalarBaseMult(&pubKey, &privKey)

			priv := NewDjbECPrivateKey(privKey)
			pub := NewDjbECPublicKey(pubKey)

			sig, vrfSign, err := VXEdDSASign(priv, tc.message)
			if err != nil {
				t.Fatalf("VXEdDSASign failed: %v", err)
			}
			if len(sig) != VXEdDSASignatureSize {
				t.Fatalf("signature length = %d, want %d", len(sig), VXEdDSASignatureSize)
			}
			if len(vrfSign) != VRFOutputSize {
				t.Fatalf("VRF output length = %d, want %d", len(vrfSign), VRFOutputSize)
			}

			valid, vrfVerify, err := VXEdDSAVerify(pub, tc.message, sig)
			if err != nil {
				t.Fatalf("VXEdDSAVerify returned error: %v", err)
			}
			if !valid {
				t.Fatal("VXEdDSAVerify rejected a valid signature")
			}

			// VRF output from sign and verify must be identical.
			for i := range vrfSign {
				if vrfSign[i] != vrfVerify[i] {
					t.Fatalf("VRF output mismatch at byte %d: sign=%02x verify=%02x",
						i, vrfSign[i], vrfVerify[i])
				}
			}
		})
	}
}

// TestVXEdDSAConsistency_SingleBitFlipAlwaysRejected verifies that flipping
// any single bit in a valid 96-byte VXEdDSA signature causes verification to
// fail. This mirrors the exhaustive bit-flip loop in
// TestXEdDSA_KAT_RustVector/single_bit_flip_always_rejected.
//
// The test runs the full 768-flip loop (96 bytes × 8 bits) for each of the
// 20 deterministic tuples, giving 15,360 rejection assertions total.
func TestVXEdDSAConsistency_SingleBitFlipAlwaysRejected(t *testing.T) {
	tuples := vxeddsaConsistencyTuples()

	for _, tc := range tuples {
		t.Run(tc.name, func(t *testing.T) {
			privKey := tc.privKey

			var pubKey [32]byte
			curve25519.ScalarBaseMult(&pubKey, &privKey)

			priv := NewDjbECPrivateKey(privKey)
			pub := NewDjbECPublicKey(pubKey)

			sig, _, err := VXEdDSASign(priv, tc.message)
			if err != nil {
				t.Fatalf("VXEdDSASign failed: %v", err)
			}

			// Confirm the unmodified signature is valid first.
			valid, _, err := VXEdDSAVerify(pub, tc.message, sig)
			if err != nil {
				t.Fatalf("baseline VXEdDSAVerify error: %v", err)
			}
			if !valid {
				t.Fatal("baseline signature invalid before bit flip")
			}

			// Flip each of the 768 bits (96 bytes × 8 bits) and assert rejection.
			for byteIdx := 0; byteIdx < VXEdDSASignatureSize; byteIdx++ {
				for bitIdx := uint(0); bitIdx < 8; bitIdx++ {
					corrupted := make([]byte, VXEdDSASignatureSize)
					copy(corrupted, sig)
					corrupted[byteIdx] ^= 1 << bitIdx

					valid, _, _ := VXEdDSAVerify(pub, tc.message, corrupted)
					if valid {
						t.Errorf(
							"bit flip accepted: byte=%d bit=%d sig_byte_orig=0x%02x sig_byte_flip=0x%02x",
							byteIdx, bitIdx, sig[byteIdx], corrupted[byteIdx],
						)
					}
				}
			}
		})
	}
}

// TestVXEdDSAConsistency_VRFIsDeterministic verifies that for each tuple,
// signing the same message twice (with different random nonces) produces
// identical VRF outputs. The VRF property requires that v = hash_5(cV) is
// fully determined by (private_key, message), not the nonce.
func TestVXEdDSAConsistency_VRFIsDeterministic(t *testing.T) {
	tuples := vxeddsaConsistencyTuples()

	for _, tc := range tuples {
		t.Run(tc.name, func(t *testing.T) {
			priv := NewDjbECPrivateKey(tc.privKey)

			_, vrf1, err := VXEdDSASign(priv, tc.message)
			if err != nil {
				t.Fatalf("VXEdDSASign (1) failed: %v", err)
			}
			_, vrf2, err := VXEdDSASign(priv, tc.message)
			if err != nil {
				t.Fatalf("VXEdDSASign (2) failed: %v", err)
			}

			for i := range vrf1 {
				if vrf1[i] != vrf2[i] {
					t.Fatalf("VRF not deterministic at byte %d: %02x != %02x",
						i, vrf1[i], vrf2[i])
				}
			}
		})
	}
}
