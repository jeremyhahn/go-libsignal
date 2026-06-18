// AES-256-GCM-SIV conformance test using the RFC 8452 reference vectors.
//
// AES-GCM-SIV is the AEAD used by zkgroup's GroupSecretParams.EncryptBlob.
// A Rust↔Go byte-format divergence on group blob encryption was surfaced
// in the previous turn (see tests/interop/zkgroup_blob_encryption_test.go);
// this RFC 8452 KAT isolates whether the bug lives in the AES-GCM-SIV
// primitive itself or in higher-level zkgroup blob_key derivation /
// output framing.
//
// Vectors are reproduced verbatim from RFC 8452 §C.2 (AES-256 cases). They
// are NOT tracked by the fixture manifest because the IETF RFC is the
// source of truth.

package interop

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
)

type rfc8452Case struct {
	Name        string
	KeyHex      string
	NonceHex    string
	AADHex      string
	PTHex       string
	ExpectedHex string // ciphertext || 16-byte tag
}

// rfc8452_256 contains the AES-256 §C.2 single-block-and-multi-block
// vectors from RFC 8452. We cover the empty/short/non-empty plaintext
// + AAD permutations that exercise the polyval, S2V, and CTR paths.
var rfc8452_256 = []rfc8452Case{
	{
		Name:        "rfc8452_C2_test1",
		KeyHex:      "0100000000000000000000000000000000000000000000000000000000000000",
		NonceHex:    "030000000000000000000000",
		AADHex:      "",
		PTHex:       "",
		ExpectedHex: "07f5f4169bbf55a8400cd47ea6fd400f",
	},
	{
		Name:        "rfc8452_C2_test2",
		KeyHex:      "0100000000000000000000000000000000000000000000000000000000000000",
		NonceHex:    "030000000000000000000000",
		AADHex:      "",
		PTHex:       "0100000000000000",
		ExpectedHex: "c2ef328e5c71c83b" + "843122130f7364b761e0b97427e3df28",
	},
	{
		Name:     "rfc8452_C2_test3",
		KeyHex:   "0100000000000000000000000000000000000000000000000000000000000000",
		NonceHex: "030000000000000000000000",
		AADHex:   "",
		PTHex:    "010000000000000000000000",
		// 12-byte ciphertext + 16-byte tag = 28 bytes total.
		ExpectedHex: "9aab2aeb3faa0a34aea8e2b1" +
			"8ca50da9ae6559e48fd10f6e5c9ca17e",
	},
	{
		Name:     "rfc8452_C2_test4",
		KeyHex:   "0100000000000000000000000000000000000000000000000000000000000000",
		NonceHex: "030000000000000000000000",
		AADHex:   "",
		PTHex:    "01000000000000000000000000000000",
		ExpectedHex: "85a01b63025ba19b7fd3ddfc033b3e76" +
			"c9eac6fa700942702e90862383c6c366",
	},
	{
		Name:        "rfc8452_C2_test5",
		KeyHex:      "0100000000000000000000000000000000000000000000000000000000000000",
		NonceHex:    "030000000000000000000000",
		AADHex:      "01",
		PTHex:       "0200000000000000",
		ExpectedHex: "1de22967237a8132" + "91213f267e3b452f02d01ae33e4ec854",
	},
	{
		// RFC 8452 §C.2 sixth AES-256 vector: 16-byte PT with 1-byte AAD.
		// Exercises the full AES-256 keystream block alongside non-empty
		// AAD POLYVAL absorption — the path most likely to surface tag-
		// derivation or counter-offset bugs that the empty-AAD vectors miss.
		Name:        "rfc8452_C2_test6",
		KeyHex:      "0100000000000000000000000000000000000000000000000000000000000000",
		NonceHex:    "030000000000000000000000",
		AADHex:      "01",
		PTHex:       "02000000000000000000000000000000",
		ExpectedHex: "c91545823cc24f17dbb0e9e807d5ec17" + "b292d28ff61189e8e49f3875ef91aff7",
	},
}

// TestAESGCMSIV_RFC8452_AES256 runs every RFC 8452 §C.2 vector through
// pkg/cipher.AESGCMSIVEncrypt and asserts byte-identical Seal output.
// A pass here proves the AES-GCM-SIV primitive itself is spec-compliant,
// localizing any zkgroup blob divergence to the higher-level blob_key
// derivation or output framing.
func TestAESGCMSIV_RFC8452_AES256(t *testing.T) {
	for _, tc := range rfc8452_256 {
		t.Run(tc.Name, func(t *testing.T) {
			key := mustHexNoSpace(t, tc.KeyHex)
			nonce := mustHexNoSpace(t, tc.NonceHex)
			var aad []byte
			if tc.AADHex != "" {
				aad = mustHexNoSpace(t, tc.AADHex)
			}
			var pt []byte
			if tc.PTHex != "" {
				pt = mustHexNoSpace(t, tc.PTHex)
			}
			want := mustHexNoSpace(t, strings.ReplaceAll(tc.ExpectedHex, " ", ""))

			got, err := cipher.AESGCMSIVEncrypt(key, nonce, pt, aad)
			if err != nil {
				t.Fatalf("AESGCMSIVEncrypt: %v", err)
			}
			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Fatalf("AES-GCM-SIV mismatch:\n  got  %s\n  want %s",
					hex.EncodeToString(got), hex.EncodeToString(want))
			}

			// Round-trip: Open must succeed and recover the plaintext.
			gotPT, err := cipher.AESGCMSIVDecrypt(key, nonce, got, aad)
			if err != nil {
				t.Fatalf("AESGCMSIVDecrypt: %v", err)
			}
			if hex.EncodeToString(gotPT) != tc.PTHex {
				t.Fatalf("Decrypt round-trip mismatch:\n  got  %s\n  want %s",
					hex.EncodeToString(gotPT), tc.PTHex)
			}
		})
	}
}
