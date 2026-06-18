// HKDF-SHA-256 conformance test using the RFC 5869 reference vectors.
//
// HKDF is the workhorse KDF in go-libsignal: every chain-key step,
// every account-keys derivation, every backup-id derivation, every
// sealed-sender envelope key, and every PQXDH transcript expansion
// flows through HKDF-SHA-256. This test validates Go's
// golang.org/x/crypto/hkdf against the RFC 5869 appendix A vectors,
// which the Rust libsignal stack also relies on transitively via the
// hkdf crate.
//
// Vectors are reproduced verbatim from RFC 5869 §A.1 (test case 1)
// and §A.2 (test case 2). They are NOT tracked by the fixture manifest
// because the IETF RFC, not Rust libsignal, is the source of truth
// for them.

package interop

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"golang.org/x/crypto/hkdf"
)

type rfc5869Case struct {
	Name    string
	IKMHex  string
	SaltHex string
	InfoHex string
	L       int // output length in bytes
	PRKHex  string
	OKMHex  string
}

// RFC 5869 appendix A test cases for SHA-256.
var rfc5869Cases = []rfc5869Case{
	{
		// §A.1 — Basic test case with SHA-256
		Name:    "rfc5869_a1",
		IKMHex:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		SaltHex: "000102030405060708090a0b0c",
		InfoHex: "f0f1f2f3f4f5f6f7f8f9",
		L:       42,
		PRKHex: "077709362c2e32df0ddc3f0dc47bba63" +
			"90b6c73bb50f9c3122ec844ad7c2b3e5",
		OKMHex: "3cb25f25faacd57a90434f64d0362f2a" +
			"2d2d0a90cf1a5a4c5db02d56ecc4c5bf" +
			"34007208d5b887185865",
	},
	{
		// §A.2 — Test with longer inputs/outputs
		Name: "rfc5869_a2",
		IKMHex: "000102030405060708090a0b0c0d0e0f" +
			"101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f" +
			"303132333435363738393a3b3c3d3e3f" +
			"404142434445464748494a4b4c4d4e4f",
		SaltHex: "606162636465666768696a6b6c6d6e6f" +
			"707172737475767778797a7b7c7d7e7f" +
			"808182838485868788898a8b8c8d8e8f" +
			"909192939495969798999a9b9c9d9e9f" +
			"a0a1a2a3a4a5a6a7a8a9aaabacadaeaf",
		InfoHex: "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf" +
			"c0c1c2c3c4c5c6c7c8c9cacbcccdcecf" +
			"d0d1d2d3d4d5d6d7d8d9dadbdcdddedf" +
			"e0e1e2e3e4e5e6e7e8e9eaebecedeeef" +
			"f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
		L: 82,
		PRKHex: "06a6b88c5853361a06104c9ceb35b45c" +
			"ef760014904671014a193f40c15fc244",
		OKMHex: "b11e398dc80327a1c8e7f78c596a4934" +
			"4f012eda2d4efad8a050cc4c19afa97c" +
			"59045a99cac7827271cb41c65e590e09" +
			"da3275600c2f09b8367793a9aca3db71" +
			"cc30c58179ec3e87c14c01d5c1f3434f" +
			"1d87",
	},
	{
		// §A.3 — Test with zero-length salt/info
		Name:    "rfc5869_a3",
		IKMHex:  "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
		SaltHex: "",
		InfoHex: "",
		L:       42,
		PRKHex: "19ef24a32c717b167f33a91d6f648bdf" +
			"96596776afdb6377ac434c1c293ccb04",
		OKMHex: "8da4e775a563c18f715f802a063c5a31" +
			"b8a11f5c5ee1879ec3454e5f3c738d2d" +
			"9d201395faa4b61a96c8",
	},
}

func mustHexNoSpace(t *testing.T, s string) []byte {
	t.Helper()
	clean := strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("decode hex %q: %v", s, err)
	}
	return b
}

// TestHKDFSHA256_RFC5869 runs every appendix-A test case through Go's
// golang.org/x/crypto/hkdf and asserts byte-identical PRK and OKM
// outputs. A pass here means the HKDF primitive in this repository
// matches the RFC, which is the same anchor Rust libsignal relies on
// transitively through the `hkdf` crate.
func TestHKDFSHA256_RFC5869(t *testing.T) {
	for _, tc := range rfc5869Cases {
		t.Run(tc.Name, func(t *testing.T) {
			ikm := mustHexNoSpace(t, tc.IKMHex)
			var salt, info []byte
			if tc.SaltHex != "" {
				salt = mustHexNoSpace(t, tc.SaltHex)
			}
			if tc.InfoHex != "" {
				info = mustHexNoSpace(t, tc.InfoHex)
			}
			wantPRK := mustHexNoSpace(t, tc.PRKHex)
			wantOKM := mustHexNoSpace(t, tc.OKMHex)

			// Validate PRK via hkdf.Extract (when supported by the
			// Go version), and the full Extract+Expand pipeline.
			gotPRK := hkdf.Extract(sha256.New, ikm, salt)
			if hex.EncodeToString(gotPRK) != hex.EncodeToString(wantPRK) {
				t.Fatalf("PRK mismatch:\n  got  %s\n  want %s",
					hex.EncodeToString(gotPRK), hex.EncodeToString(wantPRK))
			}

			r := hkdf.New(sha256.New, ikm, salt, info)
			okm := make([]byte, tc.L)
			if _, err := io.ReadFull(r, okm); err != nil {
				t.Fatalf("ReadFull(hkdf): %v", err)
			}
			if hex.EncodeToString(okm) != hex.EncodeToString(wantOKM) {
				t.Fatalf("OKM mismatch:\n  got  %s\n  want %s",
					hex.EncodeToString(okm), hex.EncodeToString(wantOKM))
			}
		})
	}
}
