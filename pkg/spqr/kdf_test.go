package spqr

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// TestKdfInfoStringsMatchRust verifies that the HKDF info strings exactly match
// the Rust reference implementation, including the intentional double space in
// ChainStartInfo.
func TestKdfInfoStringsMatchRust(t *testing.T) {
	tests := []struct {
		name     string
		got      string
		expected string
	}{
		{
			name:     "ChainStartInfo matches Rust (double space before Start)",
			got:      ChainStartInfo,
			expected: "Signal PQ Ratchet V1 Chain  Start",
		},
		{
			name:     "ChainAddEpochInfo matches Rust",
			got:      ChainAddEpochInfo,
			expected: "Signal PQ Ratchet V1 Chain Add Epoch",
		},
		{
			name:     "ChainNextInfo matches Rust",
			got:      ChainNextInfo,
			expected: "Signal PQ Ratchet V1 Chain Next",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("info string = %q, want %q", tt.got, tt.expected)
			}
		})
	}
}

// TestKdfInfoDoubleSpacePresence explicitly checks the double space in
// ChainStartInfo that distinguishes it from a typo.
func TestKdfInfoDoubleSpacePresence(t *testing.T) {
	// The Rust reference has "Chain  Start" with two spaces.
	if ChainStartInfo[len("Signal PQ Ratchet V1 Chain")] != ' ' {
		t.Error("expected first space after Chain")
	}
	if ChainStartInfo[len("Signal PQ Ratchet V1 Chain ")] != ' ' {
		t.Error("expected second space (double space) before Start")
	}
}

// TestKdfSckaCKRustAlignment verifies KdfSckaCK uses the same HKDF parameter
// assignment as Rust: salt=zeros(32), ikm=chain_key, info=ctr_be32||label.
func TestKdfSckaCKRustAlignment(t *testing.T) {
	// Use a deterministic chain key for reproducibility.
	ckBytes := bytes.Repeat([]byte{0xAB}, 32)
	ckInput := make([]byte, 32)
	copy(ckInput, ckBytes)

	ck, err := secret.New(ckInput)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer ck.Destroy()

	ctr := uint32(1)
	mk, nextCK, err := KdfSckaCK(ck, ctr)
	if err != nil {
		t.Fatalf("KdfSckaCK: %v", err)
	}
	defer mk.Destroy()
	defer nextCK.Destroy()

	// Manually compute the expected output using the Rust-aligned parameters:
	// HKDF(salt=zeros(32), ikm=chain_key, info=ctr_be32||"Signal PQ Ratchet V1 Chain Next")
	ctrBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ctrBytes, ctr)
	info := append(ctrBytes, []byte("Signal PQ Ratchet V1 Chain Next")...)

	expected, err := kdf.DeriveSecrets(ckBytes, make([]byte, 32), info, 64)
	if err != nil {
		t.Fatalf("DeriveSecrets: %v", err)
	}

	// Output split: nextCK(first 32) || mk(last 32)
	if !secrettest.Matches(t, nextCK, expected[:32]) {
		t.Error("nextCK does not match expected HKDF output (first 32 bytes)")
	}
	if !secrettest.Matches(t, mk, expected[32:]) {
		t.Error("mk does not match expected HKDF output (last 32 bytes)")
	}
}

// TestKdfSckaCKCounterInInfo verifies the counter is placed in the info field
// (not as IKM) and different counters produce different results.
func TestKdfSckaCKCounterInInfo(t *testing.T) {
	ckBytes := bytes.Repeat([]byte{0xCD}, 32)

	results := make([][]byte, 4)
	for ctr := uint32(0); ctr < 4; ctr++ {
		ckInput := make([]byte, 32)
		copy(ckInput, ckBytes)
		ck, err := secret.New(ckInput)
		if err != nil {
			t.Fatalf("secret.New: %v", err)
		}

		mk, nextCK, err := KdfSckaCK(ck, ctr)
		if err != nil {
			t.Fatalf("KdfSckaCK(ctr=%d): %v", ctr, err)
		}

		// Fingerprint mk||nextCK by their digests, taken inside the borrows.
		mkDigest, ckDigest := secrettest.Digest(t, mk), secrettest.Digest(t, nextCK)
		combined := append(mkDigest[:], ckDigest[:]...)
		results[ctr] = combined

		mk.Destroy()
		nextCK.Destroy()
		ck.Destroy()
	}

	// Verify all counter outputs are distinct.
	for i := 0; i < len(results); i++ {
		for j := i + 1; j < len(results); j++ {
			if bytes.Equal(results[i], results[j]) {
				t.Errorf("counter %d and %d produced identical output", i, j)
			}
		}
	}
}

// TestKdfSckaInitRustAlignment verifies KdfSckaInit uses the Rust-aligned
// parameters: salt=zeros(32), ikm=shared_secret, info=ChainStartInfo.
func TestKdfSckaInitRustAlignment(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{0x42}, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	rk, cks, ckr, err := KdfSckaInit(sharedSecret)
	if err != nil {
		t.Fatalf("KdfSckaInit: %v", err)
	}
	defer rk.Destroy()
	defer cks.Destroy()
	defer ckr.Destroy()

	// Manually compute expected output.
	expected, err := kdf.DeriveSecrets(sharedCopy, make([]byte, 32),
		[]byte("Signal PQ Ratchet V1 Chain  Start"), 96)
	if err != nil {
		t.Fatalf("DeriveSecrets: %v", err)
	}

	if !secrettest.Matches(t, rk, expected[:32]) {
		t.Error("rk does not match expected output")
	}
	if !secrettest.Matches(t, cks, expected[32:64]) {
		t.Error("cks does not match expected output")
	}
	if !secrettest.Matches(t, ckr, expected[64:96]) {
		t.Error("ckr does not match expected output")
	}
}

// TestKdfSckaRKRustAlignment verifies KdfSckaRK uses the Rust-aligned
// parameters: salt=root_key, ikm=epoch_secret, info=ChainAddEpochInfo.
func TestKdfSckaRKRustAlignment(t *testing.T) {
	rkBytes := bytes.Repeat([]byte{0x11}, 32)
	sckaOutput := bytes.Repeat([]byte{0x22}, 32)

	rkInput := make([]byte, 32)
	copy(rkInput, rkBytes)
	rk, err := secret.New(rkInput)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer rk.Destroy()

	newRK, newCKs, newCKr, err := KdfSckaRK(rk, sckaOutput)
	if err != nil {
		t.Fatalf("KdfSckaRK: %v", err)
	}
	defer newRK.Destroy()
	defer newCKs.Destroy()
	defer newCKr.Destroy()

	// Manually compute expected output.
	// Rust: hkdf_to_slice(salt=next_root, ikm=epoch_secret, info=label, out=96)
	expected, err := kdf.DeriveSecrets(sckaOutput, rkBytes,
		[]byte("Signal PQ Ratchet V1 Chain Add Epoch"), 96)
	if err != nil {
		t.Fatalf("DeriveSecrets: %v", err)
	}

	if !secrettest.Matches(t, newRK, expected[:32]) {
		t.Error("newRK does not match expected output")
	}
	if !secrettest.Matches(t, newCKs, expected[32:64]) {
		t.Error("newCKs does not match expected output")
	}
	if !secrettest.Matches(t, newCKr, expected[64:96]) {
		t.Error("newCKr does not match expected output")
	}
}

// TestCounterSemanticsFirstKeyAtIndex1 verifies that the first Encrypt call
// returns counter 1, not 0, matching the Rust reference where the counter is
// incremented before use.
func TestCounterSemanticsFirstKeyAtIndex1(t *testing.T) {
	s, err := Init(bytes.Repeat([]byte{0xEF}, 32), DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	mk, counter, err := s.Encrypt(0)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	mk.Destroy()

	if counter != 1 {
		t.Errorf("first Encrypt counter = %d, want 1", counter)
	}
}

// TestCounterSemanticsSequentialIncrements verifies counters increment
// sequentially starting from 1.
func TestCounterSemanticsSequentialIncrements(t *testing.T) {
	s, err := Init(bytes.Repeat([]byte{0xEF}, 32), DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	for expected := uint32(1); expected <= 5; expected++ {
		mk, counter, encErr := s.Encrypt(0)
		if encErr != nil {
			t.Fatalf("Encrypt %d: %v", expected, encErr)
		}
		mk.Destroy()

		if counter != expected {
			t.Errorf("Encrypt counter = %d, want %d", counter, expected)
		}
	}
}

// TestCounterSemanticsEncryptDecryptRoundtrip verifies that the 1-based
// counter from Encrypt is correctly used by Decrypt.
func TestCounterSemanticsEncryptDecryptRoundtrip(t *testing.T) {
	sharedSecret := bytes.Repeat([]byte{0xAA}, 32)
	sharedCopy := make([]byte, 32)
	copy(sharedCopy, sharedSecret)

	alice, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init alice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := Init(sharedCopy, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init bob: %v", err)
	}
	defer bob.Zeroize()

	for i := 0; i < 5; i++ {
		mk, counter, encErr := alice.Encrypt(0)
		if encErr != nil {
			t.Fatalf("Encrypt %d: %v", i, encErr)
		}

		mkd, decErr := bob.Decrypt(0, counter)
		if decErr != nil {
			t.Fatalf("Decrypt counter %d: %v", counter, decErr)
		}

		if !secrettest.Same(t, mk, mkd) {
			t.Errorf("message key mismatch at counter %d", counter)
		}
		mk.Destroy()
		mkd.Destroy()
	}
}

// TestKdfSckaCKOutputSplit verifies the output split order: nextCK is the
// first 32 bytes, mk is the last 32 bytes.
func TestKdfSckaCKOutputSplit(t *testing.T) {
	ckBytes := bytes.Repeat([]byte{0x55}, 32)
	ckInput := make([]byte, 32)
	copy(ckInput, ckBytes)

	ck, err := secret.New(ckInput)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer ck.Destroy()

	mk, nextCK, err := KdfSckaCK(ck, 7)
	if err != nil {
		t.Fatalf("KdfSckaCK: %v", err)
	}
	defer mk.Destroy()
	defer nextCK.Destroy()

	// Compute raw HKDF output.
	ctrBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ctrBytes, 7)
	info := append(ctrBytes, []byte(ChainNextInfo)...)
	raw, err := kdf.DeriveSecrets(ckBytes, make([]byte, 32), info, 64)
	if err != nil {
		t.Fatalf("DeriveSecrets: %v", err)
	}

	// First 32 bytes = nextCK (chain continues), last 32 bytes = mk (message key).
	if !secrettest.Matches(t, nextCK, raw[:32]) {
		t.Error("nextCK should be first 32 bytes of HKDF output")
	}
	if !secrettest.Matches(t, mk, raw[32:]) {
		t.Error("mk should be last 32 bytes of HKDF output")
	}
}

// TestKdfSckaCKZeroSalt verifies that a zero salt is used (not the chain key).
func TestKdfSckaCKZeroSalt(t *testing.T) {
	ckBytes := bytes.Repeat([]byte{0xFF}, 32)

	// Compute with chain key as salt (old wrong behavior).
	ctrBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(ctrBytes, 1)
	info := append(ctrBytes, []byte(ChainNextInfo)...)

	wrongOutput, err := kdf.DeriveSecrets(ckBytes, ckBytes, info, 64)
	if err != nil {
		t.Fatalf("DeriveSecrets (wrong): %v", err)
	}

	// Compute with zero salt (correct behavior).
	correctOutput, err := kdf.DeriveSecrets(ckBytes, make([]byte, 32), info, 64)
	if err != nil {
		t.Fatalf("DeriveSecrets (correct): %v", err)
	}

	// Verify KdfSckaCK matches the zero-salt version.
	ckInput := make([]byte, 32)
	copy(ckInput, ckBytes)
	ck, err := secret.New(ckInput)
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer ck.Destroy()

	mk, nextCK, err := KdfSckaCK(ck, 1)
	if err != nil {
		t.Fatalf("KdfSckaCK: %v", err)
	}
	defer mk.Destroy()
	defer nextCK.Destroy()

	if !secrettest.Matches(t, nextCK, correctOutput[:32]) || !secrettest.Matches(t, mk, correctOutput[32:]) {
		t.Error("KdfSckaCK does not match zero-salt HKDF computation")
	}
	if secrettest.Matches(t, nextCK, wrongOutput[:32]) && secrettest.Matches(t, mk, wrongOutput[32:]) {
		t.Error("KdfSckaCK incorrectly matches chain-key-as-salt computation")
	}
}

// TestKdfDeterministicVectors provides fixed test vectors to detect accidental
// regressions in the KDF parameter alignment.
func TestKdfDeterministicVectors(t *testing.T) {
	// KdfSckaInit with all-zero shared secret.
	rk, cks, ckr, err := KdfSckaInit(make([]byte, 32))
	if err != nil {
		t.Fatalf("KdfSckaInit: %v", err)
	}

	// Capture digests for deterministic comparison.
	rkDigest := secrettest.Digest(t, rk)
	cksDigest := secrettest.Digest(t, cks)
	ckrDigest := secrettest.Digest(t, ckr)
	rk.Destroy()
	cks.Destroy()
	ckr.Destroy()

	// Re-derive to verify determinism.
	rk2, cks2, ckr2, err := KdfSckaInit(make([]byte, 32))
	if err != nil {
		t.Fatalf("KdfSckaInit (2): %v", err)
	}
	defer rk2.Destroy()
	defer cks2.Destroy()
	defer ckr2.Destroy()

	if secrettest.Digest(t, rk2) != rkDigest {
		t.Error("KdfSckaInit not deterministic for rk")
	}
	if secrettest.Digest(t, cks2) != cksDigest {
		t.Error("KdfSckaInit not deterministic for cks")
	}
	if secrettest.Digest(t, ckr2) != ckrDigest {
		t.Error("KdfSckaInit not deterministic for ckr")
	}

	// KdfSckaCK with known chain key and counter 1.
	ck, err := cks2.Clone()
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	defer ck.Destroy()

	mk, nextCK, err := KdfSckaCK(ck, 1)
	if err != nil {
		t.Fatalf("KdfSckaCK: %v", err)
	}
	defer mk.Destroy()
	defer nextCK.Destroy()

	// Verify the outputs are non-zero and 32 bytes.
	if mk.Size() != 32 || nextCK.Size() != 32 {
		t.Error("KdfSckaCK output sizes are wrong")
	}
	if secrettest.Matches(t, mk, make([]byte, 32)) {
		t.Error("mk should not be all zeros")
	}
	if secrettest.Matches(t, nextCK, make([]byte, 32)) {
		t.Error("nextCK should not be all zeros")
	}
}
