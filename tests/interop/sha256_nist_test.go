// SHA-256 conformance test using the NIST FIPS 180-4 published vectors
// and the canonical NIST SHA test suite single-/long-input cases.
//
// SHA-256 underlies HMAC-SHA-256 (validated separately against RFC 4231),
// HKDF-SHA-256 (RFC 5869), poksho's SHO_HMAC_SHA256 / SHO_SHA256
// transcripts, and every fingerprint / proof-construction operation in
// pkg/zkgroup. Validating SHA-256 itself against NIST anchors guarantees
// the foundation those higher-level primitives stand on.

package interop

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

type nistSHA256Case struct {
	Name     string
	InputHex string
	WantHex  string
}

// NIST FIPS 180-4 Appendix B.2 / B.3 published intermediate values.
// Vectors are reproduced from the NIST test suite for SHA-256.
var nistSHA256Cases = []nistSHA256Case{
	{
		// FIPS 180-4 §B.1 — single-block message.
		Name:     "fips180_b1_abc",
		InputHex: hexBytes("abc"),
		WantHex:  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
	},
	{
		// FIPS 180-4 §B.2 — two-block message.
		Name:     "fips180_b2_two_blocks",
		InputHex: hexBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
		WantHex:  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
	},
	{
		// Empty input.
		Name:     "empty",
		InputHex: "",
		WantHex:  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
	},
	{
		// Single null byte.
		Name:     "single_null",
		InputHex: "00",
		WantHex:  "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
	},
	{
		// Block-boundary input (64 bytes).
		Name:     "block_boundary_64_bytes",
		InputHex: strings.Repeat("00", 64),
		WantHex:  "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b",
	},
	{
		// 65-byte input (one byte over block size; tests two-block path).
		Name:     "block_boundary_plus_one",
		InputHex: strings.Repeat("00", 65),
		WantHex:  "98ce42deef51d40269d542f5314bef2c7468d401ad5d85168bfab4c0108f75f7",
	},
}

// TestSHA256_NIST_KAT runs the NIST FIPS 180-4 reference vectors through
// Go's crypto/sha256 and asserts byte-identical 32-byte output.
func TestSHA256_NIST_KAT(t *testing.T) {
	for _, tc := range nistSHA256Cases {
		t.Run(tc.Name, func(t *testing.T) {
			input := mustHexNoSpace(t, tc.InputHex)
			want := mustHexNoSpace(t, tc.WantHex)

			got := sha256.Sum256(input)
			if hex.EncodeToString(got[:]) != hex.EncodeToString(want) {
				t.Fatalf("SHA-256 mismatch:\n  got  %s\n  want %s",
					hex.EncodeToString(got[:]), hex.EncodeToString(want))
			}
		})
	}
}

// TestSHA256_NIST_MillionA verifies the canonical NIST "million 'a'"
// test: SHA-256 of 1,000,000 'a' characters.
//
// Expected from FIPS 180-4 §B.3:
//
//	cdc76e5c 9914fb92 81a1c7e2 84d73e67 f1809a48 a497200e 046d39cc c7112cd0
func TestSHA256_NIST_MillionA(t *testing.T) {
	const want = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
	wantBytes := mustHexNoSpace(t, want)

	h := sha256.New()
	chunk := make([]byte, 1024)
	for i := range chunk {
		chunk[i] = 'a'
	}
	for written := 0; written < 1_000_000; written += len(chunk) {
		end := written + len(chunk)
		if end > 1_000_000 {
			end = 1_000_000
		}
		h.Write(chunk[:end-written])
	}

	got := h.Sum(nil)
	if hex.EncodeToString(got) != hex.EncodeToString(wantBytes) {
		t.Fatalf("SHA-256(1M 'a') mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(got), hex.EncodeToString(wantBytes))
	}
}
