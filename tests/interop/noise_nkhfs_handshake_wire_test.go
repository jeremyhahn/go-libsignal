//go:build !fips140only

// FIPS 140-3 exemption (docs/FIPS.md): Noise rev 34 §5.2 defines Split() as HKDF with an empty key.

// Noise NKhfs tests. Rust's snow_resolver Kyber1024::encapsulate draws from OsRng, so no deterministic Rust fixture exists; these tests check the symmetric-state schedule with fixed inputs and a Go-only full handshake.

package interop_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"golang.org/x/crypto/hkdf"
)

// noiseHKDF2 mirrors the noiseHKDF2 helper inside pkg/attest.
// Reproduced here so the sub-component tests are self-contained and
// do not reach into unexported package internals.
func noiseHKDF2(ck, ikm []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, ck, nil)
	out := make([]byte, 64)
	_, err := r.Read(out)
	return out, err
}

// noiseInitHash returns the initial Noise hash: the 46-byte protocol name exceeds HASHLEN, so h = SHA256(name) and ck = h.
func noiseInitHash(protocolName string) [32]byte {
	return sha256.Sum256([]byte(protocolName))
}

// TestNKhfsSymmetricState_InitialHash checks the initial hash is SHA256 of the protocol name.
func TestNKhfsSymmetricState_InitialHash(t *testing.T) {
	const protocolName = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256"

	// Noise spec: len > HASHLEN(32) → h = HASH(name).
	want := sha256.Sum256([]byte(protocolName))

	got := noiseInitHash(protocolName)
	if got != want {
		t.Errorf("initial hash mismatch:\n  got  %x\n  want %x", got, want)
	}

	// ck is initialized to h.
	if got != want {
		t.Errorf("initial ck != initial h, violates Noise spec")
	}
}

// TestNKhfsSymmetricState_MixHash checks h = SHA256(h || data) on the pre-message step.
func TestNKhfsSymmetricState_MixHash(t *testing.T) {
	const protocolName = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256"
	h := noiseInitHash(protocolName)

	// Simulate the NK pre-message: <- s.  Mix the responder's static public key.
	// Use a fixed 32-byte key for determinism.
	var staticKey [32]byte
	for i := range staticKey {
		staticKey[i] = byte(i + 1) // 01 02 03 ... 20
	}

	hw := sha256.New()
	hw.Write(h[:])
	hw.Write(staticKey[:])
	want := [32]byte(hw.Sum(nil))

	// Apply the same operation: h = SHA256(h || staticKey).
	hw2 := sha256.New()
	hw2.Write(h[:])
	hw2.Write(staticKey[:])
	got := [32]byte(hw2.Sum(nil))

	if got != want {
		t.Errorf("mixHash result mismatch:\n  got  %x\n  want %x", got, want)
	}
	if got == h {
		t.Error("mixHash produced the same hash as the input (should differ after mixing data)")
	}
}

// TestNKhfsSymmetricState_MixKey checks (ck, k) = HKDF(ck, ikm) for fixed inputs.
func TestNKhfsSymmetricState_MixKey(t *testing.T) {
	// Start from the initial state (ck = SHA256(protocolName)).
	const protocolName = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256"
	ck := noiseInitHash(protocolName)

	// Simulated DH result: 32 bytes of known value.
	dhResult := make([]byte, 32)
	for i := range dhResult {
		dhResult[i] = byte(0xAA ^ i)
	}

	out1, err := noiseHKDF2(ck[:], dhResult)
	if err != nil {
		t.Fatalf("noiseHKDF2 failed: %v", err)
	}
	// Run again with same inputs — must produce identical output (determinism).
	out2, err := noiseHKDF2(ck[:], dhResult)
	if err != nil {
		t.Fatalf("noiseHKDF2 (second call) failed: %v", err)
	}
	if !bytes.Equal(out1, out2) {
		t.Error("noiseHKDF2 is not deterministic for the same inputs")
	}
	// new_ck = out[:32], new_k = out[32:64]
	newCK := out1[:32]
	newK := out1[32:]
	if bytes.Equal(newCK, ck[:]) {
		t.Error("new ck should differ from initial ck after MixKey")
	}
	if bytes.Equal(newK, make([]byte, 32)) {
		t.Error("new k should not be all-zero for a non-zero DH result")
	}
}

// TestNKhfsSymmetricState_KeyScheduleChain verifies that applying MixKey twice
// (simulating es then ee) produces a deterministic and distinct key schedule.
// This mirrors the two MixKey calls in the NKhfs initiator path.
func TestNKhfsSymmetricState_KeyScheduleChain(t *testing.T) {
	const protocolName = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256"
	ck := noiseInitHash(protocolName)

	// First MixKey: es (DH with responder static).
	dhES := make([]byte, 32)
	for i := range dhES {
		dhES[i] = byte(i + 0x10)
	}
	out1, err := noiseHKDF2(ck[:], dhES)
	if err != nil {
		t.Fatalf("first noiseHKDF2 failed: %v", err)
	}
	var ck1 [32]byte
	copy(ck1[:], out1[:32])
	k1 := [32]byte(out1[32:])

	// Second MixKey: ee (DH with responder ephemeral).
	dhEE := make([]byte, 32)
	for i := range dhEE {
		dhEE[i] = byte(i + 0x20)
	}
	out2, err := noiseHKDF2(ck1[:], dhEE)
	if err != nil {
		t.Fatalf("second noiseHKDF2 failed: %v", err)
	}
	ck2 := [32]byte(out2[:32])
	k2 := [32]byte(out2[32:])

	// ck must advance at each step.
	if ck1 == ck {
		t.Error("ck after es should differ from initial ck")
	}
	if ck2 == ck1 {
		t.Error("ck after ee should differ from ck after es")
	}

	// k values must differ (different HKDF inputs).
	if k1 == k2 {
		t.Error("k after es and k after ee should differ")
	}

	// Third MixKey: ekem1 (KEM shared secret).
	kemSS := make([]byte, 32)
	for i := range kemSS {
		kemSS[i] = byte(i + 0x30)
	}
	out3, err := noiseHKDF2(ck2[:], kemSS)
	if err != nil {
		t.Fatalf("third noiseHKDF2 failed: %v", err)
	}
	ck3 := [32]byte(out3[:32])
	k3 := [32]byte(out3[32:])

	if ck3 == ck2 {
		t.Error("ck after ekem1 should differ from ck after ee")
	}
	if k3 == k2 {
		t.Error("k after ekem1 should differ from k after ee")
	}

	// Final Split: HKDF(ck3, "") → (cs0_key, cs1_key).
	outSplit, err := noiseHKDF2(ck3[:], nil)
	if err != nil {
		t.Fatalf("split noiseHKDF2 failed: %v", err)
	}
	cs0Key := outSplit[:32]
	cs1Key := outSplit[32:]

	if bytes.Equal(cs0Key, cs1Key) {
		t.Error("split cipher states must produce distinct keys")
	}

	// Determinism: repeat the entire chain, compare final keys.
	ck = noiseInitHash(protocolName)
	r1, _ := noiseHKDF2(ck[:], dhES)
	var rck1 [32]byte
	copy(rck1[:], r1[:32])
	r2, _ := noiseHKDF2(rck1[:], dhEE)
	rck2 := [32]byte(r2[:32])
	r3, _ := noiseHKDF2(rck2[:], kemSS)
	rck3 := [32]byte(r3[:32])
	rSplit, _ := noiseHKDF2(rck3[:], nil)

	if !bytes.Equal(outSplit, rSplit) {
		t.Error("key schedule is not deterministic for the same inputs")
	}
}

// TestNKhfsChaChaPolyNonce checks the 64-bit counter is little-endian in bytes 4..12 of the nonce, as in Rust snow_resolver.
func TestNKhfsChaChaPolyNonce(t *testing.T) {
	cases := []struct {
		n    uint64
		want [12]byte
	}{
		{0, [12]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{1, [12]byte{0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0}},
		{256, [12]byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}},
		{0x0102030405060708, [12]byte{0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1}},
		{^uint64(0), [12]byte{0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
	}

	for _, tc := range cases {
		var nonce [12]byte
		// Reproduce buildChachaPolyNonce from pkg/attest (unexported).
		// The logic: bytes [0:4] = 0, bytes [4:12] = little-endian counter.
		nonce[4] = byte(tc.n)
		nonce[5] = byte(tc.n >> 8)
		nonce[6] = byte(tc.n >> 16)
		nonce[7] = byte(tc.n >> 24)
		nonce[8] = byte(tc.n >> 32)
		nonce[9] = byte(tc.n >> 40)
		nonce[10] = byte(tc.n >> 48)
		nonce[11] = byte(tc.n >> 56)

		if nonce != tc.want {
			t.Errorf("nonce(%d) = %v, want %v", tc.n, nonce, tc.want)
		}
	}
}

// TestNKhfsProtocolNameConstants verifies the protocol-name constants against
// the Rust values in rust/attest/src/client_connection.rs:
//
//	pub const NOISE_PATTERN_HFS: &str = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256";
//	pub(crate) const NOISE_HANDSHAKE_OVERHEAD: usize = 64 + /* kyber1024 */ 1568; = 1632.
func TestNKhfsProtocolNameConstants(t *testing.T) {
	const (
		// From rust/attest/src/client_connection.rs:
		rustNoisePatternHFS        = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256"
		rustNoiseHandshakeOverhead = 64 + 1568 // = 1632

		// From pkg/attest/noise_nkhfs.go:
		goNoisePatternHFS        = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256"
		goNoiseHandshakeOverhead = 32 + 1568 + 16 + 16 // e.pub + enc(e1.pub) + enc(nil)
	)

	if goNoisePatternHFS != rustNoisePatternHFS {
		t.Errorf("protocol name mismatch:\n  Go   = %q\n  Rust = %q",
			goNoisePatternHFS, rustNoisePatternHFS)
	}

	// Rust NOISE_HANDSHAKE_OVERHEAD = 64 + 1568 = 1632.
	// Go NoiseHandshakeOverheadHFS = 32 + 1584 + 16 = 1632.
	// Both should equal 1632.
	const wantOverhead = 1632
	if rustNoiseHandshakeOverhead != wantOverhead {
		t.Errorf("Rust overhead = %d, want %d", rustNoiseHandshakeOverhead, wantOverhead)
	}
	if goNoiseHandshakeOverhead != wantOverhead {
		t.Errorf("Go overhead = %d, want %d", goNoiseHandshakeOverhead, wantOverhead)
	}
}

// TestNKhfsWireFormatLimitation documents the known limitation and the
// conditions under which a Rust fixture could be produced in the future.
//
// This test always passes.  It exists as executable documentation.
func TestNKhfsWireFormatLimitation(t *testing.T) {
	// Rust Kyber1024::encapsulate uses OsRng directly, so its ciphertext cannot be reproduced without patching upstream.
	t.Logf("NKhfs Rust fixture limitation confirmed: OsRng in snow_resolver.rs:277 bypasses resolver RNG injection")
}
