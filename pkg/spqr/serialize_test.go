package spqr

import (
	"bytes"
	"errors"
	"testing"
)

func TestSerializeDeserializeRoundTrip(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
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

	// Build up some state: encrypt a few messages.
	for i := 0; i < 3; i++ {
		mk, counter, encErr := alice.Encrypt(0)
		if encErr != nil {
			t.Fatalf("Encrypt %d: %v", i, encErr)
		}
		mkd, decErr := bob.Decrypt(0, counter)
		if decErr != nil {
			t.Fatalf("Decrypt %d: %v", i, decErr)
		}
		mk.Destroy()
		mkd.Destroy()
	}

	// Serialize alice.
	data, err := alice.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("serialized data is empty")
	}

	// Deserialize and verify.
	restored, err := Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer restored.Zeroize()

	if restored.epoch != alice.epoch {
		t.Errorf("epoch: got %d, want %d", restored.epoch, alice.epoch)
	}
	if restored.sendEpoch != alice.sendEpoch {
		t.Errorf("sendEpoch: got %d, want %d", restored.sendEpoch, alice.sendEpoch)
	}
	if restored.direction != alice.direction {
		t.Errorf("direction: got %v, want %v", restored.direction, alice.direction)
	}
	if !bytes.Equal(restored.rootKey.Bytes(), alice.rootKey.Bytes()) {
		t.Error("rootKey mismatch after round trip")
	}
	if len(restored.chains) != len(alice.chains) {
		t.Fatalf("chains count: got %d, want %d", len(restored.chains), len(alice.chains))
	}

	for epoch, origChain := range alice.chains {
		restoredChain, ok := restored.chains[epoch]
		if !ok {
			t.Fatalf("chain epoch %d missing after round trip", epoch)
		}
		if restoredChain.sendCounter != origChain.sendCounter {
			t.Errorf("epoch %d sendCounter: got %d, want %d", epoch, restoredChain.sendCounter, origChain.sendCounter)
		}
		if restoredChain.recvCounter != origChain.recvCounter {
			t.Errorf("epoch %d recvCounter: got %d, want %d", epoch, restoredChain.recvCounter, origChain.recvCounter)
		}
		if origChain.sendKey != nil && !origChain.sendKey.IsDestroyed() {
			if restoredChain.sendKey == nil || restoredChain.sendKey.IsDestroyed() {
				t.Errorf("epoch %d sendKey missing after round trip", epoch)
			} else if !bytes.Equal(restoredChain.sendKey.Bytes(), origChain.sendKey.Bytes()) {
				t.Errorf("epoch %d sendKey mismatch", epoch)
			}
		}
		if origChain.recvKey != nil && !origChain.recvKey.IsDestroyed() {
			if restoredChain.recvKey == nil || restoredChain.recvKey.IsDestroyed() {
				t.Errorf("epoch %d recvKey missing after round trip", epoch)
			} else if !bytes.Equal(restoredChain.recvKey.Bytes(), origChain.recvKey.Bytes()) {
				t.Errorf("epoch %d recvKey mismatch", epoch)
			}
		}
	}

	// Verify the restored state is functional: encrypt and decrypt should match.
	mk1, ctr1, err := alice.Encrypt(0)
	if err != nil {
		t.Fatalf("Encrypt on original: %v", err)
	}
	mk2, ctr2, err := restored.Encrypt(0)
	if err != nil {
		t.Fatalf("Encrypt on restored: %v", err)
	}
	if ctr1 != ctr2 {
		t.Errorf("counter mismatch: original=%d, restored=%d", ctr1, ctr2)
	}
	if !bytes.Equal(mk1.Bytes(), mk2.Bytes()) {
		t.Error("message key mismatch between original and restored")
	}
	mk1.Destroy()
	mk2.Destroy()
}

func TestSerializeEmptyState(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	data, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	restored, err := Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer restored.Zeroize()

	if restored.epoch != 0 {
		t.Errorf("epoch: got %d, want 0", restored.epoch)
	}
	if restored.sendEpoch != 0 {
		t.Errorf("sendEpoch: got %d, want 0", restored.sendEpoch)
	}
	if restored.direction != DirectionA2B {
		t.Errorf("direction: got %v, want A2B", restored.direction)
	}
	if len(restored.chains) != 1 {
		t.Errorf("chains count: got %d, want 1", len(restored.chains))
	}
	if len(restored.skippedKeys) != 0 {
		t.Errorf("skippedKeys count: got %d, want 0", len(restored.skippedKeys))
	}
	if !bytes.Equal(restored.rootKey.Bytes(), s.rootKey.Bytes()) {
		t.Error("rootKey mismatch")
	}
}

func TestSerializeWithSkippedKeys(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
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

	// Alice sends 5 messages.
	for i := 0; i < 5; i++ {
		mk, _, encErr := alice.Encrypt(0)
		if encErr != nil {
			t.Fatalf("Encrypt %d: %v", i, encErr)
		}
		mk.Destroy()
	}

	// Bob decrypts counter 5, skipping 1-4.
	mk, err := bob.Decrypt(0, 5)
	if err != nil {
		t.Fatalf("Decrypt(0, 5): %v", err)
	}
	mk.Destroy()

	if bob.SkippedKeyCount() != 4 {
		t.Fatalf("expected 4 skipped keys, got %d", bob.SkippedKeyCount())
	}

	// Serialize bob's state with skipped keys.
	data, err := bob.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	restored, err := Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer restored.Zeroize()

	if restored.SkippedKeyCount() != 4 {
		t.Fatalf("restored skippedKeys count: got %d, want 4", restored.SkippedKeyCount())
	}

	// Verify the skipped keys are functionally correct by retrieving them.
	for ctr := uint32(1); ctr <= 4; ctr++ {
		origMK, origErr := bob.Decrypt(0, ctr)
		restoredMK, restoredErr := restored.Decrypt(0, ctr)
		if origErr != nil {
			t.Fatalf("bob.Decrypt(0, %d): %v", ctr, origErr)
		}
		if restoredErr != nil {
			t.Fatalf("restored.Decrypt(0, %d): %v", ctr, restoredErr)
		}
		if !bytes.Equal(origMK.Bytes(), restoredMK.Bytes()) {
			t.Errorf("skipped key mismatch at counter %d", ctr)
		}
		origMK.Destroy()
		restoredMK.Destroy()
	}
}

func TestDeserializeInvalidData(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"nil data", nil},
		{"empty data", []byte{}},
		{"one byte", []byte{0x01}},
		{"header too short", make([]byte, headerSize-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Deserialize(tt.data)
			if err == nil {
				t.Fatal("expected error for invalid data")
			}
			var deserErr *ErrDeserialize
			if !errors.As(err, &deserErr) {
				t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
			}
		})
	}
}

func TestDeserializeInvalidVersion(t *testing.T) {
	// Create valid serialized data, then corrupt the version byte.
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	data, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Set version to 0xFF.
	data[0] = 0xFF
	_, err = Deserialize(data)
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
	var deserErr *ErrDeserialize
	if !errors.As(err, &deserErr) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

func TestDeserializeInvalidDirection(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	data, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Set direction to invalid value.
	data[1] = 0x05
	_, err = Deserialize(data)
	if err == nil {
		t.Fatal("expected error for invalid direction")
	}
	var deserErr *ErrDeserialize
	if !errors.As(err, &deserErr) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

func TestDeserializeTrailingData(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	data, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Append extra byte.
	data = append(data, 0x00)
	_, err = Deserialize(data)
	if err == nil {
		t.Fatal("expected error for trailing data")
	}
	var deserErr *ErrDeserialize
	if !errors.As(err, &deserErr) {
		t.Errorf("expected *ErrDeserialize, got %T: %v", err, err)
	}
}

func TestDeserializeTruncatedChain(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	data, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Truncate in the middle of chain data.
	truncated := data[:headerSize+5]
	_, err = Deserialize(truncated)
	if err == nil {
		t.Fatal("expected error for truncated chain data")
	}
}

func TestDeserializeTruncatedSkippedKey(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	bob, err := Init(sharedSecret, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer bob.Zeroize()

	// Create skipped keys.
	mk, decErr := bob.Decrypt(0, 3)
	if decErr != nil {
		t.Fatalf("Decrypt(0, 3): %v", decErr)
	}
	mk.Destroy()

	data, serErr := bob.Serialize()
	if serErr != nil {
		t.Fatalf("Serialize: %v", serErr)
	}

	// Truncate within the skipped key section.
	truncated := data[:len(data)-10]
	_, err = Deserialize(truncated)
	if err == nil {
		t.Fatal("expected error for truncated skipped key data")
	}
}

func TestSerializeDestroyedRootKey(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}

	s.rootKey.Destroy()
	_, err = s.Serialize()
	if err == nil {
		t.Fatal("expected error for destroyed root key")
	}
	var serErr *ErrSerialize
	if !errors.As(err, &serErr) {
		t.Errorf("expected *ErrSerialize, got %T: %v", err, err)
	}
}

func TestSerializeIdempotent(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionB2A, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	data1, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize 1: %v", err)
	}
	data2, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize 2: %v", err)
	}

	if !bytes.Equal(data1, data2) {
		t.Error("consecutive serializations should produce identical output")
	}
}

func TestSerializeMultiEpoch(t *testing.T) {
	sharedSecret := randomBytes(t, 32)
	s, err := Init(sharedSecret, DirectionA2B, maxJump)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer s.Zeroize()

	// Advance to epoch 1.
	if err := s.ReceiveKey(randomBytes(t, 32), 1); err != nil {
		t.Fatalf("ReceiveKey(1): %v", err)
	}

	// Encrypt at epoch 1 to advance sendEpoch.
	mk, _, encErr := s.Encrypt(1)
	if encErr != nil {
		t.Fatalf("Encrypt(1): %v", encErr)
	}
	mk.Destroy()

	data, err := s.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	restored, err := Deserialize(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	defer restored.Zeroize()

	if restored.epoch != 1 {
		t.Errorf("epoch: got %d, want 1", restored.epoch)
	}
	if restored.sendEpoch != 1 {
		t.Errorf("sendEpoch: got %d, want 1", restored.sendEpoch)
	}
	if len(restored.chains) != len(s.chains) {
		t.Errorf("chains count: got %d, want %d", len(restored.chains), len(s.chains))
	}
}

func TestErrorStringsSerialize(t *testing.T) {
	serErr := &ErrSerialize{Reason: "test reason"}
	if serErr.Error() != "spqr: serialization failed: test reason" {
		t.Errorf("unexpected error string: %s", serErr.Error())
	}

	deserErr := &ErrDeserialize{Reason: "bad data"}
	if deserErr.Error() != "spqr: deserialization failed: bad data" {
		t.Errorf("unexpected error string: %s", deserErr.Error())
	}
}
