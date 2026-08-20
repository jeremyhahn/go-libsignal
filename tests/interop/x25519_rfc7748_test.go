//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 3 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the vectors are RFC 7748 sections 5.2 and 6.1, which exist to pin that
// algorithm, so the fips140only build tag drops this file from the FIPS
// gate. `make test` and `make coverage` still run it.

// X25519 conformance test using the RFC 7748 reference vectors.
//
// X25519 (Curve25519 ECDH) is the foundational scalar-multiplication
// primitive used by every Signal protocol DH step: identity-key DH,
// signed-prekey DH, ephemeral DH, and the four DH handshakes inside
// PQXDH. Go's pkg/ecc relies on golang.org/x/crypto/curve25519 for
// these operations; this test validates the underlying primitive
// against RFC 7748 §5.2 and §6.1.
//
// Vectors are reproduced verbatim from RFC 7748. They are NOT tracked
// by the fixture manifest because the IETF RFC is the source of truth.

package interop

import (
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/curve25519"
)

type rfc7748Case struct {
	Name        string
	ScalarHex   string
	UCoordHex   string
	ExpectedHex string
}

var rfc7748Cases = []rfc7748Case{
	{
		// RFC 7748 §5.2 — first scalar*u test.
		Name:        "rfc7748_5_2_first_test",
		ScalarHex:   "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
		UCoordHex:   "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
		ExpectedHex: "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
	},
	{
		// RFC 7748 §5.2 — second scalar*u test.
		Name:        "rfc7748_5_2_second_test",
		ScalarHex:   "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
		UCoordHex:   "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
		ExpectedHex: "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
	},
}

// rfc7748AppendixA tests the iterated scalar multiplication that RFC 7748
// §5.2 specifies for higher-confidence validation. We cap the iteration
// count at 1 (the lowest published intermediate) and 1000 (the next
// published intermediate) — the 1,000,000-iteration target is omitted
// because it is too slow for a unit test and adds nothing the lower
// counts do not (the same primitive is exercised).
type rfc7748IteratedCase struct {
	Name        string
	Iterations  int
	ExpectedHex string
}

var rfc7748IteratedCases = []rfc7748IteratedCase{
	{
		Name:        "rfc7748_5_2_iter_1",
		Iterations:  1,
		ExpectedHex: "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
	},
	{
		Name:        "rfc7748_5_2_iter_1000",
		Iterations:  1000,
		ExpectedHex: "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
	},
}

// TestX25519_RFC7748_ScalarMult runs the §5.2 single-shot vectors.
func TestX25519_RFC7748_ScalarMult(t *testing.T) {
	for _, tc := range rfc7748Cases {
		t.Run(tc.Name, func(t *testing.T) {
			scalar := mustHexNoSpace(t, tc.ScalarHex)
			u := mustHexNoSpace(t, tc.UCoordHex)
			want := mustHexNoSpace(t, tc.ExpectedHex)

			got, err := curve25519.X25519(scalar, u)
			if err != nil {
				t.Fatalf("X25519: %v", err)
			}
			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Fatalf("X25519 mismatch:\n  got  %s\n  want %s",
					hex.EncodeToString(got), hex.EncodeToString(want))
			}
		})
	}
}

// TestX25519_RFC7748_Iterated runs the §5.2 iterated-scalar test for the
// 1- and 1000-iteration markers.
func TestX25519_RFC7748_Iterated(t *testing.T) {
	for _, tc := range rfc7748IteratedCases {
		t.Run(tc.Name, func(t *testing.T) {
			// Initial k = u = 9 (with the rest of the encoding zeroed).
			k := make([]byte, 32)
			u := make([]byte, 32)
			k[0] = 9
			u[0] = 9

			for i := 0; i < tc.Iterations; i++ {
				next, err := curve25519.X25519(k, u)
				if err != nil {
					t.Fatalf("iter %d: %v", i, err)
				}
				u = k
				k = next
			}

			want := mustHexNoSpace(t, tc.ExpectedHex)
			if hex.EncodeToString(k) != hex.EncodeToString(want) {
				t.Fatalf("iterated X25519 mismatch (%d iters):\n  got  %s\n  want %s",
					tc.Iterations, hex.EncodeToString(k), hex.EncodeToString(want))
			}
		})
	}
}

// TestX25519_RFC7748_DH validates the §6.1 Diffie-Hellman example: two
// parties with published private keys derive the same shared secret.
func TestX25519_RFC7748_DH(t *testing.T) {
	alicePriv := mustHexNoSpace(t, strings.ReplaceAll(
		"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", " ", ""))
	bobPriv := mustHexNoSpace(t, strings.ReplaceAll(
		"5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb", " ", ""))

	alicePub, err := curve25519.X25519(alicePriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("alice pub: %v", err)
	}
	bobPub, err := curve25519.X25519(bobPriv, curve25519.Basepoint)
	if err != nil {
		t.Fatalf("bob pub: %v", err)
	}

	expectedAlicePub := mustHexNoSpace(t, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	expectedBobPub := mustHexNoSpace(t, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	expectedShared := mustHexNoSpace(t, "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

	if hex.EncodeToString(alicePub) != hex.EncodeToString(expectedAlicePub) {
		t.Fatalf("alice public key mismatch:\n  got  %x\n  want %x", alicePub, expectedAlicePub)
	}
	if hex.EncodeToString(bobPub) != hex.EncodeToString(expectedBobPub) {
		t.Fatalf("bob public key mismatch:\n  got  %x\n  want %x", bobPub, expectedBobPub)
	}

	aliceShared, err := curve25519.X25519(alicePriv, bobPub)
	if err != nil {
		t.Fatalf("alice shared: %v", err)
	}
	bobShared, err := curve25519.X25519(bobPriv, alicePub)
	if err != nil {
		t.Fatalf("bob shared: %v", err)
	}
	if hex.EncodeToString(aliceShared) != hex.EncodeToString(expectedShared) {
		t.Fatalf("alice shared mismatch:\n  got  %x\n  want %x", aliceShared, expectedShared)
	}
	if hex.EncodeToString(bobShared) != hex.EncodeToString(expectedShared) {
		t.Fatalf("bob shared mismatch:\n  got  %x\n  want %x", bobShared, expectedShared)
	}
}
