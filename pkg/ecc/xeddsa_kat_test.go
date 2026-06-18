package ecc

// XEdDSA Known-Answer Test (KAT) ported from the Rust libsignal reference.
// Source: rust/core/src/curve/curve25519.rs:242-296 (test_signature).
//
// The test pins exact byte vectors from the Rust implementation and verifies:
//  1. The signature is accepted for the correct public key and message.
//  2. Every single-bit flip in the 64-byte signature causes verification to fail.
//
// This guards against regressions in sign-bit embedding, scalar canonicalization,
// and the Montgomery-to-Edwards conversion inside verify().

import "testing"

// TestXEdDSA_KAT_RustVector exercises the exact byte vectors from the Rust
// libsignal test_signature KAT (curve25519.rs:242-296).
//
// alice_identity_public is the raw 32-byte Curve25519 public key.
// The message is alice_ephemeral_public: a 33-byte DJB-prefixed public key
// (0x05 || 32 bytes), matching the Rust &[&alice_ephemeral_public] call.
// alice_signature is the 64-byte XEdDSA signature to verify.
func TestXEdDSA_KAT_RustVector(t *testing.T) {
	// Verbatim bytes from rust/core/src/curve/curve25519.rs:243-263.
	aliceIdentityPublic := [32]byte{
		0xab, 0x7e, 0x71, 0x7d, 0x4a, 0x16, 0x3b, 0x7d,
		0x9a, 0x1d, 0x80, 0x71, 0xdf, 0xe9, 0xdc, 0xf8,
		0xcd, 0xcd, 0x1c, 0xea, 0x33, 0x39, 0xb6, 0x35,
		0x6b, 0xe8, 0x4d, 0x88, 0x7e, 0x32, 0x2c, 0x64,
	}

	// alice_ephemeral_public includes the 0x05 DJB type prefix (PUBLIC_KEY_LENGTH+1 = 33).
	aliceEphemeralPublic := []byte{
		0x05, 0xed, 0xce, 0x9d, 0x9c, 0x41, 0x5c, 0xa7,
		0x8c, 0xb7, 0x25, 0x2e, 0x72, 0xc2, 0xc4, 0xa5,
		0x54, 0xd3, 0xeb, 0x29, 0x48, 0x5a, 0x0e, 0x1d,
		0x50, 0x31, 0x18, 0xd1, 0xa8, 0x2d, 0x99, 0xfb, 0x4a,
	}

	aliceSignature := [64]byte{
		0x5d, 0xe8, 0x8c, 0xa9, 0xa8, 0x9b, 0x4a, 0x11,
		0x5d, 0xa7, 0x91, 0x09, 0xc6, 0x7c, 0x9c, 0x74,
		0x64, 0xa3, 0xe4, 0x18, 0x02, 0x74, 0xf1, 0xcb,
		0x8c, 0x63, 0xc2, 0x98, 0x4e, 0x28, 0x6d, 0xfb,
		0xed, 0xe8, 0x2d, 0xeb, 0x9d, 0xcd, 0x9f, 0xae,
		0x0b, 0xfb, 0xb8, 0x21, 0x56, 0x9b, 0x3d, 0x90,
		0x01, 0xbd, 0x81, 0x30, 0xcd, 0x11, 0xd4, 0x86,
		0xce, 0xf0, 0x47, 0xbd, 0x60, 0xb8, 0x6e, 0x88,
	}

	pubKey := NewDjbECPublicKey(aliceIdentityPublic)

	t.Run("valid_signature_accepted", func(t *testing.T) {
		if !VerifySignature(pubKey, aliceEphemeralPublic, aliceSignature) {
			t.Fatal("KAT: valid XEdDSA signature rejected")
		}
	})

	// For each of the 512 bits in the 64-byte signature, flip the bit and
	// assert verification fails (no false accept). Matches Rust loop at
	// curve25519.rs:282-295 which iterates bytes and XORs 0x01 per byte.
	// We extend to individual bits for stronger coverage.
	t.Run("single_bit_flip_always_rejected", func(t *testing.T) {
		for byteIdx := 0; byteIdx < 64; byteIdx++ {
			for bitIdx := uint(0); bitIdx < 8; bitIdx++ {
				corrupted := aliceSignature
				corrupted[byteIdx] ^= 1 << bitIdx
				if VerifySignature(pubKey, aliceEphemeralPublic, corrupted) {
					t.Fatalf(
						"KAT: signature with bit %d of byte %d flipped was incorrectly accepted",
						bitIdx, byteIdx,
					)
				}
			}
		}
	})
}
