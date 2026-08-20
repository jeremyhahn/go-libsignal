//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 1 test in this file exercises HMAC-SHA256 under keys below 112 bits. FIPS
// 140-3 does not approve that, but RFC 4231 fixes the key of every test
// case, and several are shorter than 14 bytes, so the fips140only build tag
// drops this file from the FIPS gate. `make test` and `make coverage` still
// run it.

// HMAC-SHA-256 conformance test using the RFC 4231 reference vectors.
//
// HMAC is used pervasively by go-libsignal (every HKDF call, every
// sealed-sender authenticator, every chain-key derivation). The Rust
// reference relies on the `hmac` crate, which itself is validated
// against RFC 4231; we mirror that by validating Go's standard-library
// crypto/hmac against the same RFC reference. A pass here transitively
// proves that the lower-level HMAC primitive in both stacks agrees on
// every byte.
//
// Vectors are reproduced verbatim from RFC 4231 section 4. They are NOT
// tracked by the fixture manifest because the IETF RFC, not Rust
// libsignal, is the source of truth for them.

package interop

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

type rfc4231Case struct {
	Name    string
	KeyHex  string
	DataHex string
	// HMAC-SHA-256 result, hex-encoded.
	HMACSHA256Hex string
}

// RFC 4231 §4.2-§4.7 test cases. Test 5 is omitted (it requires HMAC
// truncation and is exercised separately via the truncated-tag tests in
// individual packages).
var rfc4231Cases = []rfc4231Case{
	{
		Name:    "rfc4231_test1",
		KeyHex:  strings.Repeat("0b", 20),
		DataHex: hexBytes("Hi There"),
		HMACSHA256Hex: "b0344c61d8db38535ca8afceaf0bf12b" +
			"881dc200c9833da726e9376c2e32cff7",
	},
	{
		Name:    "rfc4231_test2_jefe",
		KeyHex:  hexBytes("Jefe"),
		DataHex: hexBytes("what do ya want for nothing?"),
		HMACSHA256Hex: "5bdcc146bf60754e6a042426089575c7" +
			"5a003f089d2739839dec58b964ec3843",
	},
	{
		Name:    "rfc4231_test3_aaaa_dddd",
		KeyHex:  strings.Repeat("aa", 20),
		DataHex: strings.Repeat("dd", 50),
		HMACSHA256Hex: "773ea91e36800e46854db8ebd09181a7" +
			"2959098b3ef8c122d9635514ced565fe",
	},
	{
		Name: "rfc4231_test4_counted_key",
		KeyHex: "0102030405060708090a0b0c0d0e0f10" +
			"111213141516171819",
		DataHex: strings.Repeat("cd", 50),
		HMACSHA256Hex: "82558a389a443c0ea4cc819899f2083a" +
			"85f0faa3e578f8077a2e3ff46729665b",
	},
	{
		Name:    "rfc4231_test6_long_key_short_msg",
		KeyHex:  strings.Repeat("aa", 131),
		DataHex: hexBytes("Test Using Larger Than Block-Size Key - Hash Key First"),
		HMACSHA256Hex: "60e431591ee0b67f0d8a26aacbf5b77f" +
			"8e0bc6213728c5140546040f0ee37f54",
	},
	{
		Name:   "rfc4231_test7_long_key_long_msg",
		KeyHex: strings.Repeat("aa", 131),
		DataHex: hexBytes(
			"This is a test using a larger than block-size key and a larger " +
				"than block-size data. The key needs to be hashed before being used " +
				"by the HMAC algorithm."),
		HMACSHA256Hex: "9b09ffa71b942fcb27635fbcd5b0e944" +
			"bfdc63644f0713938a7f51535c3a35e2",
	},
}

// TestHMACSHA256_RFC4231 runs every reproduced RFC 4231 vector through
// Go's stdlib crypto/hmac+crypto/sha256 and asserts byte-identical tag
// output. A pass here means the HMAC primitive used pervasively by
// pkg/cipher, pkg/kdf, pkg/ratchet, pkg/sealed, and pkg/zkgroup is
// spec-compliant.
func TestHMACSHA256_RFC4231(t *testing.T) {
	for _, tc := range rfc4231Cases {
		t.Run(tc.Name, func(t *testing.T) {
			key, err := hex.DecodeString(tc.KeyHex)
			if err != nil {
				t.Fatalf("decode key: %v", err)
			}
			data, err := hex.DecodeString(tc.DataHex)
			if err != nil {
				t.Fatalf("decode data: %v", err)
			}
			want, err := hex.DecodeString(strings.ReplaceAll(tc.HMACSHA256Hex, " ", ""))
			if err != nil {
				t.Fatalf("decode want: %v", err)
			}

			mac := hmac.New(sha256.New, key)
			mac.Write(data)
			got := mac.Sum(nil)

			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Fatalf("HMAC-SHA-256 mismatch:\n  got  %s\n  want %s",
					hex.EncodeToString(got), hex.EncodeToString(want))
			}

			// Constant-time verification path also returns true on the
			// matching tag and false on a corrupted tag.
			if !hmac.Equal(got, want) {
				t.Fatal("hmac.Equal returned false on identical tags")
			}
			corrupted := make([]byte, len(want))
			copy(corrupted, want)
			corrupted[0] ^= 0x01
			if hmac.Equal(got, corrupted) {
				t.Fatal("hmac.Equal returned true on tag with one bit flipped")
			}
		})
	}
}
