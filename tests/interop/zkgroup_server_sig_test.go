// Conformance test: zkgroup ServerSecretParams.Sign byte-identical to
// Rust's test_server_sigs.
//
// Mirrors rust/zkgroup/tests/integration_tests.rs::test_server_sigs:
//   - generate ServerSecretParams from TEST_ARRAY_32 (0..31)
//   - sign TEST_ARRAY_32_1 (100..131) using TEST_ARRAY_32_2 (200..231) as
//     randomness
//   - assert the resulting 64-byte Schnorr-style signature matches the
//     pinned EXPECTED_SIGNATURE hex literal
//   - verify the signature with the public key
//
// A pass here proves Go's zkgroup ServerSecretParams generation, the new
// SignatureKeyPair.Sign method, the underlying poksho.Sign primitive,
// the SHO transcript construction, and the Ristretto255 scalar/point
// arithmetic all produce byte-identical output to Rust libsignal.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type serverSigSection struct {
	ExpectedSignatureHex string `json:"expected_signature_hex"`
}

type serverSigFixture struct {
	ServerSig serverSigSection `json:"server_sig"`
}

// fillRange returns a 32-byte array whose i-th byte equals start+i (no
// overflow because 0..31 + start fits in a byte for start ∈ {0, 100, 200}).
func fillRange(start byte) [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = start + byte(i)
	}
	return out
}

// TestZkgroup_ServerSign_KAT proves Go's ServerSecretParams.Sign output
// is byte-identical to Rust's test_server_sigs expected vector.
func TestZkgroup_ServerSign_KAT(t *testing.T) {
	raw := loader.MustRead("zkgroup/server_sig_known_answers.json")
	var fx serverSigFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	want, err := hex.DecodeString(fx.ServerSig.ExpectedSignatureHex)
	if err != nil {
		t.Fatalf("decode expected signature: %v", err)
	}

	testArray32 := fillRange(0)
	testArray32_1 := fillRange(100)
	testArray32_2 := fillRange(200)

	server, err := zkgroup.GenerateServerSecretParams(testArray32)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}

	got, err := server.Sign(testArray32_2, testArray32_1[:])
	if err != nil {
		t.Fatalf("ServerSecretParams.Sign: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(want) {
		t.Fatalf("ServerSecretParams.Sign mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(got), hex.EncodeToString(want))
	}

	// Round-trip verify: the public key derived from the same params must
	// accept the signature.
	pub := server.SigKeyPair.GetPublicKey()
	if err := pub.Verify(testArray32_1[:], got); err != nil {
		t.Fatalf("public key Verify rejected its own signature: %v", err)
	}

	// Negative: a one-bit flip in the message must cause Verify to fail.
	tampered := testArray32_1
	tampered[0] ^= 0x01
	if err := pub.Verify(tampered[:], got); err == nil {
		t.Fatal("Verify accepted signature on tampered message")
	}

	// Negative: a one-bit flip in the signature must cause Verify to fail.
	badSig := make([]byte, len(got))
	copy(badSig, got)
	badSig[0] ^= 0x01
	if err := pub.Verify(testArray32_1[:], badSig); err == nil {
		t.Fatal("Verify accepted tampered signature")
	}
}
