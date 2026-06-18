// Conformance test: zkgroup ProfileKeyCommitment byte-identical to Rust.
//
// Mirrors rust/zkgroup/src/crypto/profile_key_commitment.rs::tests::test_commitment:
//
//	let profile_key = ProfileKeyStruct::new(TEST_ARRAY_32, TEST_ARRAY_16);
//	let c1 = CommitmentWithSecretNonce::new(profile_key, TEST_ARRAY_16);
//	let c2 = CommitmentWithSecretNonce::new(profile_key, TEST_ARRAY_16);
//	assert!(c1 == c2);
//
// The Rust test verifies determinism (same inputs → same output). The Go KAT
// additionally pins the exact byte values of J1‖J2‖J3 (three compressed
// Ristretto255 points, 96 bytes total) so any future drift in the computation
// is caught as a byte-level regression.

package interop

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkgroup"
	"github.com/jeremyhahn/go-libsignal/tests/interop/loader"
)

type profileKeyCommitmentFixture struct {
	ExpectedCommitmentHex string `json:"expected_commitment_hex"`
}

// TestZkgroup_ProfileKeyCommitment_KAT verifies that Go's
// NewProfileKeyCommitmentWithSecretNonce produces a commitment whose J1‖J2‖J3
// bytes are byte-identical to the Rust reference for the canonical
// TEST_ARRAY_32 profile key and TEST_ARRAY_16 UUID inputs.
//
// Source: rust/zkgroup/src/crypto/profile_key_commitment.rs::tests::test_commitment
// Fixture: tests/interop/fixtures/zkgroup/profile_key_commitment_known_answers.json
func TestZkgroup_ProfileKeyCommitment_KAT(t *testing.T) {
	raw := loader.MustRead("zkgroup/profile_key_commitment_known_answers.json")
	var fx profileKeyCommitmentFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}

	want, err := hex.DecodeString(fx.ExpectedCommitmentHex)
	if err != nil {
		t.Fatalf("decode expected commitment: %v", err)
	}
	if len(want) != 96 {
		t.Fatalf("expected 96-byte commitment (3×32), got %d bytes", len(want))
	}

	profileKeyBytes := fillRange(0) // TEST_ARRAY_32 (0x00..0x1f)
	uidBytes := fillRange16(0)      // TEST_ARRAY_16 (0x00..0x0f)

	// Rust: ProfileKeyStruct::new(TEST_ARRAY_32, TEST_ARRAY_16).
	pkStruct := zkgroup.NewProfileKeyStruct(profileKeyBytes, uidBytes)

	// Rust: CommitmentWithSecretNonce::new(profile_key, TEST_ARRAY_16).
	c1 := zkgroup.NewProfileKeyCommitmentWithSecretNonce(pkStruct, uidBytes)
	c2 := zkgroup.NewProfileKeyCommitmentWithSecretNonce(pkStruct, uidBytes)

	// Determinism: two calls with same input must produce byte-identical results.
	got1 := encodeCommitment(c1.GetCommitment())
	got2 := encodeCommitment(c2.GetCommitment())
	if hex.EncodeToString(got1) != hex.EncodeToString(got2) {
		t.Fatal("commitment is not deterministic: c1 != c2")
	}

	// KAT: compare against Rust-pinned fixture bytes.
	if hex.EncodeToString(got1) != hex.EncodeToString(want) {
		t.Fatalf("commitment mismatch:\n  got  %s\n  want %s",
			hex.EncodeToString(got1), hex.EncodeToString(want))
	}
}

// TestZkgroup_ProfileKeyCommitment_DifferentInputsProduceDifferentOutputs verifies
// that changing the UUID bytes produces a distinct commitment, confirming that
// the UID is a meaningful binding input (not ignored).
func TestZkgroup_ProfileKeyCommitment_DifferentInputsProduceDifferentOutputs(t *testing.T) {
	profileKeyBytes := fillRange(0) // TEST_ARRAY_32
	uid1 := fillRange16(0)          // TEST_ARRAY_16
	uid2 := fillRange16(1)          // TEST_ARRAY_16 shifted by 1

	pkStruct := zkgroup.NewProfileKeyStruct(profileKeyBytes, uid1)

	c1 := zkgroup.NewProfileKeyCommitmentWithSecretNonce(pkStruct, uid1)
	c2 := zkgroup.NewProfileKeyCommitmentWithSecretNonce(pkStruct, uid2)

	got1 := encodeCommitment(c1.GetCommitment())
	got2 := encodeCommitment(c2.GetCommitment())

	if hex.EncodeToString(got1) == hex.EncodeToString(got2) {
		t.Fatal("commitments for different UIDs must differ")
	}
}

// encodeCommitment serializes a ProfileKeyCommitmentInternal as J1‖J2‖J3 (96 bytes).
func encodeCommitment(c *zkgroup.ProfileKeyCommitmentInternal) []byte {
	out := make([]byte, 0, 96)
	out = append(out, c.J1.Bytes()...)
	out = append(out, c.J2.Bytes()...)
	out = append(out, c.J3.Bytes()...)
	return out
}
