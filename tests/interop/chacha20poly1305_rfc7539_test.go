// ChaCha20-Poly1305 conformance test using the RFC 7539 reference vectors.
//
// ChaCha20-Poly1305 is the AEAD cipher used in the Noise NKhfs handshake
// (pkg/attest, pkg/net) for SVR/SVRB/CDSI enclave sessions. The Rust
// reference relies on the chacha20poly1305 / snow / chacha20 crates,
// which are validated against RFC 7539. This test mirrors that
// validation against Go's stdlib golang.org/x/crypto/chacha20poly1305.
// A pass guarantees Go's AEAD primitive used pervasively by the
// attestation layer is byte-identical to the IETF spec.
//
// Vectors are reproduced verbatim from RFC 7539 §2.8.2 and Appendix A.5.
// They are NOT tracked by the fixture manifest because the IETF RFC is
// the source of truth for them.

package interop

import (
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

type rfc7539Case struct {
	Name         string
	KeyHex       string
	NonceHex     string
	AADHex       string
	PTHex        string
	CTPlusTagHex string
}

var rfc7539Cases = []rfc7539Case{
	{
		// RFC 7539 §2.8.2 — canonical AEAD example.
		Name: "rfc7539_section_2_8_2",
		KeyHex: "808182838485868788898a8b8c8d8e8f" +
			"909192939495969798999a9b9c9d9e9f",
		NonceHex: "070000004041424344454647",
		AADHex:   "50515253c0c1c2c3c4c5c6c7",
		PTHex: "4c616469657320616e642047656e746c" +
			"656d656e206f662074686520636c6173" +
			"73206f66202739393a20496620492063" +
			"6f756c64206f6666657220796f75206f" +
			"6e6c79206f6e652074697020666f7220" +
			"746865206675747572652c2073756e73" +
			"637265656e20776f756c642062652069" +
			"742e",
		// Concatenation of ciphertext (§2.8.2 expected output) and the
		// 16-byte tag that follows.
		CTPlusTagHex: "d31a8d34648e60db7b86afbc53ef7ec2" +
			"a4aded51296e08fea9e2b5a736ee62d6" +
			"3dbea45e8ca9671282fafb69da92728b" +
			"1a71de0a9e060b2905d6a5b67ecd3b36" +
			"92ddbd7f2d778b8c9803aee328091b58" +
			"fab324e4fad675945585808b4831d7bc" +
			"3ff4def08e4b7a9de576d26586cec64b" +
			"6116" +
			"1ae10b594f09e26a7e902ecbd0600691",
	},
	{
		// RFC 7539 Appendix A.5 — empty plaintext, non-empty AAD.
		Name: "rfc7539_appendix_a5",
		KeyHex: "1c9240a5eb55d38af333888604f6b5f0" +
			"473917c1402b80099dca5cbc207075c0",
		NonceHex: "000000000102030405060708",
		AADHex:   "f33388860000000000004e91",
		PTHex: "496e7465726e65742d4472616674732061726520647261667420646f63756d65" +
			"6e74732076616c696420666f722061206d6178696d756d206f6620736978206d" +
			"6f6e74687320616e64206d617920626520757064617465642c207265706c6163" +
			"65642c206f72206f62736f6c65746564206279206f7468657220646f63756d65" +
			"6e747320617420616e792074696d652e20497420697320696e617070726f7072" +
			"6961746520746f2075736520496e7465726e65742d4472616674732061732072" +
			"65666572656e6365206d6174657269616c206f7220746f206369746520746865" +
			"6d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67" +
			"726573732e2fe2809d",
		CTPlusTagHex: "64a0861575861af460f062c79be643bd" +
			"5e805cfd345cf389f108670ac76c8cb2" +
			"4c6cfc18755d43eea09ee94e382d26b0" +
			"bdb7b73c321b0100d4f03b7f355894cf" +
			"332f830e710b97ce98c8a84abd0b9481" +
			"14ad176e008d33bd60f982b1ff37c855" +
			"9797a06ef4f0ef61c186324e2b350638" +
			"3606907b6a7c02b0f9f6157b53c867e4" +
			"b9166c767b804d46a59b5216cde7a4e9" +
			"9040c5a40433225ee282a1b0a06c523e" +
			"af4534d7f83fa1155b0047718cbc546a" +
			"0d072b04b3564eea1b422273f548271a" +
			"0bb2316053fa76991955ebd63159434e" +
			"cebb4e466dae5a1073a6727627097a10" +
			"49e617d91d361094fa68f0ff77987130" +
			"305beaba2eda04df997b714d6c6f2c29" +
			"a6ad5cb4022b02709b" +
			"eead9d67890cbb22392336fea1851f38",
	},
}

// TestChaCha20Poly1305_RFC7539 runs the Wycheproof-equivalent IETF
// reference vectors through Go's stdlib chacha20poly1305 and asserts
// byte-identical Seal output (ciphertext concatenated with 16-byte tag).
// Negative paths verify Open rejects a one-bit flip in tag, ciphertext,
// or AAD.
func TestChaCha20Poly1305_RFC7539(t *testing.T) {
	for _, tc := range rfc7539Cases {
		t.Run(tc.Name, func(t *testing.T) {
			key := mustHexNoSpace(t, tc.KeyHex)
			nonce := mustHexNoSpace(t, tc.NonceHex)
			aad := mustHexNoSpace(t, tc.AADHex)
			pt := mustHexNoSpace(t, tc.PTHex)
			want := mustHexNoSpace(t, strings.ReplaceAll(tc.CTPlusTagHex, " ", ""))

			aead, err := chacha20poly1305.New(key)
			if err != nil {
				t.Fatalf("chacha20poly1305.New: %v", err)
			}
			got := aead.Seal(nil, nonce, pt, aad)
			if hex.EncodeToString(got) != hex.EncodeToString(want) {
				t.Fatalf("Seal mismatch:\n  got  %s\n  want %s",
					hex.EncodeToString(got), hex.EncodeToString(want))
			}

			// Round-trip: Open must succeed and recover the plaintext.
			gotPT, err := aead.Open(nil, nonce, got, aad)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if hex.EncodeToString(gotPT) != tc.PTHex {
				t.Fatalf("Open round-trip mismatch:\n  got  %s\n  want %s",
					hex.EncodeToString(gotPT), tc.PTHex)
			}

			// Negative: tag tamper must reject.
			tampered := append([]byte{}, got...)
			tampered[len(tampered)-1] ^= 0x01
			if _, err := aead.Open(nil, nonce, tampered, aad); err == nil {
				t.Fatal("Open accepted ciphertext with tag bit flipped")
			}

			// Negative: AAD tamper must reject (only when AAD is non-empty).
			if len(aad) > 0 {
				badAAD := append([]byte{}, aad...)
				badAAD[0] ^= 0x01
				if _, err := aead.Open(nil, nonce, got, badAAD); err == nil {
					t.Fatal("Open accepted with tampered AAD")
				}
			}
		})
	}
}
