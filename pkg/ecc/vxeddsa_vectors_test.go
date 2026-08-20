//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 4 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH key agreement specification (section 2.1) requires it, so the
// fips140only build tag drops this file from the FIPS gate. `make test` and
// `make coverage` still run it.

package ecc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/curve25519"
)

// deterministicVector holds a fully deterministic VXEdDSA test vector.
// By fixing the private key, message, and random bytes, the signature and
// VRF output are fully reproducible. These vectors serve as regression
// anchors for the implementation.
type deterministicVector struct {
	name    string
	privHex string // 32-byte Curve25519 private key
	msgHex  string // message bytes
	rndHex  string // 64-byte random input
	sigHex  string // expected 96-byte signature (V || h || s)
	vrfHex  string // expected 32-byte VRF output
	pubHex  string // expected Montgomery public key (derived)
	edPub   string // expected Edwards public key (sign bit 0)
	negated bool   // whether calculateEdwardsKeyPair negates the scalar
}

// regressionVectors returns the set of deterministic test vectors generated
// from the current implementation. Each vector covers a different combination
// of key material, message content, and random input.
//
// Vector selection rationale:
//   - vector0: C library key, empty message, all-zero random
//   - vector1: C library key, "This is unique." message, sequential random
//   - vector2: key requiring sign negation, ASCII message, all-0xFF random
//   - vector3: minimal key requiring negation, binary message, 0xAA random
//   - vector4: key requiring negation, 256-byte zero message, zero random
//   - vector5: key without negation, 4-byte zero message, 0x42 random
func regressionVectors() []deterministicVector {
	return []deterministicVector{
		{
			name:    "empty_msg_zero_random",
			privHex: "38611d253bea85a203805343b74a936d3b13b9e3121453e9740b6b827e337e5d",
			msgHex:  "",
			rndHex:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			sigHex:  "b7b8c693ce00db51e6fadaee97b198fd1dd0bb8a78b73152d243669399bf3b44587dfd3535335bc85f8cc941359399866efbd988c4cd4e0c6cad82f793e69f0286da68f578615d14e3209f1429ccc619d47378adef1df412c3758cd76ea38205",
			vrfHex:  "fca55012e3ec6213bbe1c8c41f1e7acee4c7a49b0677a461d819d5cfbb3380ac",
			pubHex:  "21f7345f56d9602f1523298f4f6fcecb14dde2d5b9a9b48bca8242681492b920",
			edPub:   "902b3d1a52582b23a596530066849b3ce6e57e68d4e753ca414e29ccd8137520",
			negated: false,
		},
		{
			name:    "clib_key_unique_msg_sequential_random",
			privHex: "38611d253bea85a203805343b74a936d3b13b9e3121453e9740b6b827e337e5d",
			msgHex:  "5468697320697320756e697175652e",
			rndHex:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
			sigHex:  "cc5a78c05c050bfcae98aedb843c686d9d9d2746369a2e55a0ba04d6ad298511d0337e08ea79169cd7c4d52046dcc2cb4219d539e3c947ff9b08fca99d31d00b4c9645d7642f5201458a33b96c24869c4222be28bac5d7451c782fd9d75df50e",
			vrfHex:  "75ad49bc955f38dcf65fb672086bd509cb4b4c41047db17efdafeebc330371e6",
			pubHex:  "21f7345f56d9602f1523298f4f6fcecb14dde2d5b9a9b48bca8242681492b920",
			edPub:   "902b3d1a52582b23a596530066849b3ce6e57e68d4e753ca414e29ccd8137520",
			negated: false,
		},
		{
			name:    "negated_key_hello_ff_random",
			privHex: "a8abdc5739edc070c2fd0b39a15c8d5c366afc8e7a3fcbdb5c62c6c2c8f4e8b0",
			msgHex:  "48656c6c6f2c20576f726c6421",
			rndHex:  "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			sigHex:  "aae19baef48f145ec6dd38320fb6b984ed97d0ad2d315f5b893c106e5e73c47af79b78aa966b6e63ebb00405f172866b687f45ec48457ad65c815bf2ef826802b798b24373815642134786878efeace64db4a46393a68045c793b14548827501",
			vrfHex:  "b701f12ac6cfcc0a699d0ce540e192ac48995c4ed324a9a5ba4624497d37ca60",
			pubHex:  "1b334c6a90c0c600edf6224ed122469f1fbdece87abed24063e13c1470ce9a74",
			edPub:   "4853fa61801d474f27f4f19df1ae54f51852d957acb338a42bb2f79541508104",
			negated: true,
		},
		{
			name:    "minimal_key_negated_binary_msg",
			privHex: "0100000000000000000000000000000000000000000000000000000000000040",
			msgHex:  "0001020304050607",
			rndHex:  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			sigHex:  "c5eef3b2c39e3e541433e6772c9a2dfc88f18bf07f2ad2d79db614a03095dfee853ae9e61bebfece1e974aa41b05adf365fac3eb5fb03da57ed8af8db5a8980158873bcec4a1a40ab115f9a0c4de4b7cf6f251aa4a94bee07e0c9a1035a11a0a",
			vrfHex:  "938b1a7f2b621df8d53e339b37d5ef6686c2dd91c8c4329dcfe96172197a35d1",
			pubHex:  "2fe57da347cd62431528daac5fbb290730fff684afc4cfc2ed90995f58cb3b74",
			edPub:   "693e47972caf527c7883ad1b39822f026f47db2ab0e1919955b8993aa0441151",
			negated: true,
		},
		{
			name:    "negated_key_256byte_zero_msg",
			privHex: "702b4167ee78736619f8a23ac04071a4b2a822c29224758d5e8c4e3f6aa7ce48",
			msgHex:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			rndHex:  "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			sigHex:  "883bb958f2287a84442ef19017f9a614d7285cd0e790fe0e6ba76915485f0c2512f462464d7630c5df3487dde0a2dccdc2df12437fa3cc7689e2b4b76b08c100e7b27d23a4123570462b8a592588689797a45ed6f5a56ef8dd656c01dbb5b400",
			vrfHex:  "9c2efccd40e25b38844d24d406a35a54e93fbe08dbc244673e4012f66d9f8e7b",
			pubHex:  "b64beaf6fb29e1051c81e54339d0c9e7543e66219dde746513b9024d30774843",
			edPub:   "2566cfae61d592ff396e581d8047ea62950f91fcbc776844f34f1d2970e00961",
			negated: true,
		},
		{
			name:    "non_negated_4byte_zero_42_random",
			privHex: "d85fcb5eabcebfb172b6cf1070a858bf568b8b5a6f26cddd4b4c6e4f5361f458",
			msgHex:  "00000000",
			rndHex:  "42424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242",
			sigHex:  "111c7c2ab6004341ed12bbfa26f8bd00a090ed2bf2e70f13d04b85bbeb9033e94d5902d24f416225441b8414594ea5babeb9741ad0254c486bb248f3677cf4074fe2c614d9695947020576534daec82251f7135cc68ab681895d2f10486ad009",
			vrfHex:  "060fd0e8eb2c974b923a475a0671b75c086b299a4b4933435db31bd2d3e94aad",
			pubHex:  "f49553bcf0ada37cbac6ecef1da661872aff81699339c16c8e341055d5152f01",
			edPub:   "b8576dbc38f486fb6d82925d5e3ba32a4931b0b5896857faabde1a4b5b39ce47",
			negated: false,
		},
	}
}

// TestVXEdDSA_DeterministicVectors verifies that the VXEdDSA implementation
// produces exactly the expected signature and VRF output for fixed inputs.
// These vectors lock down the implementation behavior and detect any changes
// that would break cross-implementation compatibility.
func TestVXEdDSA_DeterministicVectors(t *testing.T) {
	vectors := regressionVectors()

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			privBytes, err := hex.DecodeString(v.privHex)
			if err != nil {
				t.Fatalf("failed to decode privHex: %v", err)
			}
			var privKey [32]byte
			copy(privKey[:], privBytes)

			message, err := hex.DecodeString(v.msgHex)
			if err != nil {
				t.Fatalf("failed to decode msgHex: %v", err)
			}

			rndBytes, err := hex.DecodeString(v.rndHex)
			if err != nil {
				t.Fatalf("failed to decode rndHex: %v", err)
			}
			var random [64]byte
			copy(random[:], rndBytes)

			expectedSig, err := hex.DecodeString(v.sigHex)
			if err != nil {
				t.Fatalf("failed to decode sigHex: %v", err)
			}

			expectedVRF, err := hex.DecodeString(v.vrfHex)
			if err != nil {
				t.Fatalf("failed to decode vrfHex: %v", err)
			}

			expectedPub, err := hex.DecodeString(v.pubHex)
			if err != nil {
				t.Fatalf("failed to decode pubHex: %v", err)
			}

			expectedEdPub, err := hex.DecodeString(v.edPub)
			if err != nil {
				t.Fatalf("failed to decode edPub: %v", err)
			}

			// Verify derived public key matches
			var derivedPub [32]byte
			curve25519.ScalarBaseMult(&derivedPub, &privKey)
			if !bytes.Equal(derivedPub[:], expectedPub) {
				t.Fatalf("derived public key mismatch:\n  got:      %x\n  expected: %x",
					derivedPub, expectedPub)
			}

			// Verify Edwards key derivation
			edKpResult := calculateEdwardsKeyPair(&privKey)
			edPubBytes := edKpResult.PublicKey
			if !bytes.Equal(edPubBytes, expectedEdPub) {
				t.Fatalf("Edwards public key mismatch:\n  got:      %x\n  expected: %x",
					edPubBytes, expectedEdPub)
			}

			// Sign with deterministic inputs
			sig, vrf, err := vxeddsaSign(&privKey, message, random)
			if err != nil {
				t.Fatalf("vxeddsaSign failed: %v", err)
			}

			// Verify signature bytes match exactly
			if !bytes.Equal(sig[:], expectedSig) {
				t.Fatalf("signature mismatch:\n  got:      %x\n  expected: %x",
					sig[:], expectedSig)
			}

			// Verify VRF output matches exactly
			if !bytes.Equal(vrf, expectedVRF) {
				t.Fatalf("VRF output mismatch:\n  got:      %x\n  expected: %x",
					vrf, expectedVRF)
			}

			// Verify the signature passes verification
			valid, vrfVerify := vxeddsaVerify(derivedPub, message, sig)
			if !valid {
				t.Fatal("generated signature did not pass verification")
			}

			// Verify VRF from verification matches VRF from signing
			if !bytes.Equal(vrf, vrfVerify) {
				t.Fatalf("VRF mismatch between sign (%x) and verify (%x)", vrf, vrfVerify)
			}
		})
	}
}

// TestVXEdDSA_DeterministicVectors_SignBitNegation verifies that vectors
// requiring scalar negation in calculateEdwardsKeyPair are correctly
// identified and produce consistent results.
func TestVXEdDSA_DeterministicVectors_SignBitNegation(t *testing.T) {
	vectors := regressionVectors()

	seenNegated := false
	seenNonNegated := false

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			privBytes, err := hex.DecodeString(v.privHex)
			if err != nil {
				t.Fatalf("failed to decode privHex: %v", err)
			}
			var privKey [32]byte
			copy(privKey[:], privBytes)

			edKpResult := calculateEdwardsKeyPair(&privKey)

			// Edwards public key must always have sign bit 0
			if edKpResult.PublicKey[31]&0x80 != 0 {
				t.Fatal("Edwards public key has non-zero sign bit")
			}

			if v.negated {
				seenNegated = true
			} else {
				seenNonNegated = true
			}
		})
	}

	if !seenNegated {
		t.Fatal("test vectors must include at least one key requiring negation")
	}
	if !seenNonNegated {
		t.Fatal("test vectors must include at least one key not requiring negation")
	}
}

// TestXEdDSA_VXEdDSA_Consistency verifies that the XEdDSA component of a
// VXEdDSA signature is consistent with standalone XEdDSA verification.
// Specifically, for the same key and message, the Edwards public key derived
// during VXEdDSA signing must match the one used in XEdDSA, and standalone
// XEdDSA signatures must verify with the same key.
func TestXEdDSA_VXEdDSA_Consistency(t *testing.T) {
	vectors := regressionVectors()

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			privBytes, err := hex.DecodeString(v.privHex)
			if err != nil {
				t.Fatalf("failed to decode privHex: %v", err)
			}
			var privKey [32]byte
			copy(privKey[:], privBytes)

			message, err := hex.DecodeString(v.msgHex)
			if err != nil {
				t.Fatalf("failed to decode msgHex: %v", err)
			}

			// Derive Montgomery public key
			var pubKey [32]byte
			curve25519.ScalarBaseMult(&pubKey, &privKey)

			priv := NewDjbECPrivateKey(privKey)
			pub := NewDjbECPublicKey(pubKey)

			// XEdDSA sign and verify
			xeddsaSig, err := CalculateSignature(priv, message)
			if err != nil {
				t.Fatalf("CalculateSignature failed: %v", err)
			}
			if !VerifySignature(pub, message, xeddsaSig) {
				t.Fatal("XEdDSA signature failed verification with same key")
			}

			// VXEdDSA sign and verify
			vxSig, vrfSign, err := VXEdDSASign(priv, message)
			if err != nil {
				t.Fatalf("VXEdDSASign failed: %v", err)
			}
			valid, vrfVerify, err := VXEdDSAVerify(pub, message, vxSig)
			if err != nil {
				t.Fatalf("VXEdDSAVerify returned error: %v", err)
			}
			if !valid {
				t.Fatal("VXEdDSA signature failed verification")
			}
			if !bytes.Equal(vrfSign, vrfVerify) {
				t.Fatal("VRF output mismatch between sign and verify")
			}

			// The V point (first 32 bytes of VXEdDSA signature) should be
			// deterministic for the same (key, message) pair, regardless of
			// random input. Sign again and compare V points.
			vxSig2, _, err := VXEdDSASign(priv, message)
			if err != nil {
				t.Fatalf("VXEdDSASign (second) failed: %v", err)
			}

			// V is the first 32 bytes of the signature
			if !bytes.Equal(vxSig[:32], vxSig2[:32]) {
				t.Fatal("V point is not deterministic for same (key, message)")
			}

			// The h and s portions should differ (different random nonces)
			// but both signatures must verify.
			valid2, _, err := VXEdDSAVerify(pub, message, vxSig2)
			if err != nil {
				t.Fatalf("VXEdDSAVerify (second) returned error: %v", err)
			}
			if !valid2 {
				t.Fatal("second VXEdDSA signature failed verification")
			}
		})
	}
}

// TestVXEdDSA_VRFUniqueness100Messages verifies the VRF uniqueness property:
// for a fixed private key, VRF(k, m) must produce unique outputs for all
// distinct messages. This tests 200 messages to ensure no collisions.
func TestVXEdDSA_VRFUniqueness100Messages(t *testing.T) {
	privHex := "38611d253bea85a203805343b74a936d3b13b9e3121453e9740b6b827e337e5d"
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}
	var privKey [32]byte
	copy(privKey[:], privBytes)

	priv := NewDjbECPrivateKey(privKey)

	const numMessages = 200
	vrfOutputs := make(map[string]int, numMessages)

	for i := 0; i < numMessages; i++ {
		message := []byte(fmt.Sprintf("message-%d", i))
		_, vrf, err := VXEdDSASign(priv, message)
		if err != nil {
			t.Fatalf("VXEdDSASign failed for message %d: %v", i, err)
		}

		vrfHex := hex.EncodeToString(vrf)
		if prevIdx, exists := vrfOutputs[vrfHex]; exists {
			t.Fatalf("VRF collision: message %d and message %d produced same VRF output %s",
				prevIdx, i, vrfHex)
		}
		vrfOutputs[vrfHex] = i
	}

	if len(vrfOutputs) != numMessages {
		t.Fatalf("expected %d unique VRF outputs, got %d", numMessages, len(vrfOutputs))
	}
}

// TestVXEdDSA_VRFDeterminism100Messages verifies that VRF output is
// deterministic: signing the same message twice with the same key must
// produce identical VRF output, even though signatures differ.
func TestVXEdDSA_VRFDeterminism100Messages(t *testing.T) {
	privHex := "a8abdc5739edc070c2fd0b39a15c8d5c366afc8e7a3fcbdb5c62c6c2c8f4e8b0"
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}
	var privKey [32]byte
	copy(privKey[:], privBytes)

	priv := NewDjbECPrivateKey(privKey)

	for i := 0; i < 100; i++ {
		message := []byte(fmt.Sprintf("determinism-check-%d", i))

		_, vrf1, err := VXEdDSASign(priv, message)
		if err != nil {
			t.Fatalf("VXEdDSASign (first) failed for message %d: %v", i, err)
		}

		_, vrf2, err := VXEdDSASign(priv, message)
		if err != nil {
			t.Fatalf("VXEdDSASign (second) failed for message %d: %v", i, err)
		}

		if !bytes.Equal(vrf1, vrf2) {
			t.Fatalf("VRF output not deterministic for message %d:\n  first:  %x\n  second: %x",
				i, vrf1, vrf2)
		}
	}
}

// TestVXEdDSA_EdgeCase_LargeMessage verifies that VXEdDSA correctly handles
// a 1MB message without error.
func TestVXEdDSA_EdgeCase_LargeMessage(t *testing.T) {
	privHex := "38611d253bea85a203805343b74a936d3b13b9e3121453e9740b6b827e337e5d"
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}
	var privKey [32]byte
	copy(privKey[:], privBytes)

	// 1 MB message with patterned data
	message := make([]byte, 1<<20)
	for i := range message {
		message[i] = byte(i % 251) // prime modulus for good distribution
	}

	var random [64]byte
	sig, vrf, err := vxeddsaSign(&privKey, message, random)
	if err != nil {
		t.Fatalf("vxeddsaSign failed on 1MB message: %v", err)
	}

	if len(sig) != VXEdDSASignatureSize {
		t.Fatalf("expected %d-byte signature, got %d", VXEdDSASignatureSize, len(sig))
	}
	if len(vrf) != VRFOutputSize {
		t.Fatalf("expected %d-byte VRF output, got %d", VRFOutputSize, len(vrf))
	}

	// Verify the signature
	var pubKey [32]byte
	curve25519.ScalarBaseMult(&pubKey, &privKey)
	valid, vrfVerify := vxeddsaVerify(pubKey, message, sig)
	if !valid {
		t.Fatal("verification failed for 1MB message signature")
	}
	if !bytes.Equal(vrf, vrfVerify) {
		t.Fatal("VRF mismatch for 1MB message")
	}
}

// TestVXEdDSA_EdgeCase_AllZeroMessage verifies that a message consisting
// entirely of zero bytes is handled correctly and produces valid signatures.
func TestVXEdDSA_EdgeCase_AllZeroMessage(t *testing.T) {
	privHex := "d85fcb5eabcebfb172b6cf1070a858bf568b8b5a6f26cddd4b4c6e4f5361f458"
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}
	var privKey [32]byte
	copy(privKey[:], privBytes)

	// Different lengths of all-zero messages should produce different VRF outputs
	lengths := []int{0, 1, 4, 32, 64, 128, 256}
	vrfOutputs := make(map[string]int, len(lengths))

	for _, length := range lengths {
		message := make([]byte, length)
		var random [64]byte

		sig, vrf, err := vxeddsaSign(&privKey, message, random)
		if err != nil {
			t.Fatalf("vxeddsaSign failed for %d-byte zero message: %v", length, err)
		}

		var pubKey [32]byte
		curve25519.ScalarBaseMult(&pubKey, &privKey)
		valid, vrfVerify := vxeddsaVerify(pubKey, message, sig)
		if !valid {
			t.Fatalf("verification failed for %d-byte zero message", length)
		}
		if !bytes.Equal(vrf, vrfVerify) {
			t.Fatalf("VRF mismatch for %d-byte zero message", length)
		}

		vrfHex := hex.EncodeToString(vrf)
		if prevLen, exists := vrfOutputs[vrfHex]; exists {
			t.Fatalf("VRF collision: %d-byte and %d-byte zero messages produced same output",
				prevLen, length)
		}
		vrfOutputs[vrfHex] = length
	}
}

// TestVXEdDSA_EdgeCase_SingleBitDifference verifies that messages differing
// by a single bit produce completely different VRF outputs, demonstrating
// the hash function's avalanche effect.
func TestVXEdDSA_EdgeCase_SingleBitDifference(t *testing.T) {
	privHex := "38611d253bea85a203805343b74a936d3b13b9e3121453e9740b6b827e337e5d"
	privBytes, err := hex.DecodeString(privHex)
	if err != nil {
		t.Fatalf("failed to decode private key: %v", err)
	}
	var privKey [32]byte
	copy(privKey[:], privBytes)

	priv := NewDjbECPrivateKey(privKey)

	baseMsg := make([]byte, 32)
	_, baseVRF, err := VXEdDSASign(priv, baseMsg)
	if err != nil {
		t.Fatalf("VXEdDSASign failed for base message: %v", err)
	}

	// Flip each bit position in the first byte
	for bit := 0; bit < 8; bit++ {
		modified := make([]byte, 32)
		modified[0] = 1 << uint(bit)

		_, modVRF, err := VXEdDSASign(priv, modified)
		if err != nil {
			t.Fatalf("VXEdDSASign failed for bit %d: %v", bit, err)
		}

		if bytes.Equal(baseVRF, modVRF) {
			t.Fatalf("VRF output identical for single-bit difference at bit %d", bit)
		}
	}
}

// TestVXEdDSA_CrossVerifyDeterministicVectors verifies that each deterministic
// vector's signature can be verified using the corresponding public key
// through the public API, confirming end-to-end consistency.
func TestVXEdDSA_CrossVerifyDeterministicVectors(t *testing.T) {
	vectors := regressionVectors()

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			pubBytes, err := hex.DecodeString(v.pubHex)
			if err != nil {
				t.Fatalf("failed to decode pubHex: %v", err)
			}
			var pubKey [32]byte
			copy(pubKey[:], pubBytes)

			message, err := hex.DecodeString(v.msgHex)
			if err != nil {
				t.Fatalf("failed to decode msgHex: %v", err)
			}

			sigBytes, err := hex.DecodeString(v.sigHex)
			if err != nil {
				t.Fatalf("failed to decode sigHex: %v", err)
			}

			expectedVRF, err := hex.DecodeString(v.vrfHex)
			if err != nil {
				t.Fatalf("failed to decode vrfHex: %v", err)
			}

			pub := NewDjbECPublicKey(pubKey)

			valid, vrf, err := VXEdDSAVerify(pub, message, sigBytes)
			if err != nil {
				t.Fatalf("VXEdDSAVerify returned error: %v", err)
			}
			if !valid {
				t.Fatal("VXEdDSAVerify rejected a known-good signature")
			}
			if !bytes.Equal(vrf, expectedVRF) {
				t.Fatalf("VRF output mismatch:\n  got:      %x\n  expected: %x",
					vrf, expectedVRF)
			}
		})
	}
}

// TestVXEdDSA_CrossVerifyRejectsWrongVector verifies that each vector's
// signature is rejected when verified against a different vector's public key.
func TestVXEdDSA_CrossVerifyRejectsWrongVector(t *testing.T) {
	vectors := regressionVectors()

	for i := 0; i < len(vectors); i++ {
		for j := 0; j < len(vectors); j++ {
			// Skip when same key is used (vectors 0 and 1 share the same key)
			if vectors[i].pubHex == vectors[j].pubHex {
				continue
			}

			t.Run(fmt.Sprintf("%s_with_%s_key", vectors[i].name, vectors[j].name), func(t *testing.T) {
				wrongPubBytes, err := hex.DecodeString(vectors[j].pubHex)
				if err != nil {
					t.Fatalf("failed to decode pubHex: %v", err)
				}
				var wrongPubKey [32]byte
				copy(wrongPubKey[:], wrongPubBytes)

				message, err := hex.DecodeString(vectors[i].msgHex)
				if err != nil {
					t.Fatalf("failed to decode msgHex: %v", err)
				}

				sigBytes, err := hex.DecodeString(vectors[i].sigHex)
				if err != nil {
					t.Fatalf("failed to decode sigHex: %v", err)
				}

				wrongPub := NewDjbECPublicKey(wrongPubKey)
				valid, _, err := VXEdDSAVerify(wrongPub, message, sigBytes)
				if err != nil {
					t.Fatalf("VXEdDSAVerify returned error: %v", err)
				}
				if valid {
					t.Fatal("VXEdDSAVerify accepted signature with wrong public key")
				}
			})
		}
	}
}
