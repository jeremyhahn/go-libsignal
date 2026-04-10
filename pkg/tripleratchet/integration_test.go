package tripleratchet

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
)

// =============================================================================
// Full Triple Ratchet Integration Tests
// =============================================================================

// TestTripleRatchet_FullExchange verifies that Alice and Bob can exchange
// messages through the Triple Ratchet using both EC and PQ ratchets,
// producing matching keys and correct plaintext recovery.
func TestTripleRatchet_FullExchange(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	// Exchange multiple messages in alternating directions.
	messages := []struct {
		sender   string
		text     string
		aliceSnd bool // true = Alice sends, false = Bob sends
	}{
		{"Alice", "Hello Bob, starting key exchange.", true},
		{"Alice", "Sending second message to advance ratchet.", true},
		{"Alice", "Third message, PQ chunks should be progressing.", true},
		{"Bob", "Hey Alice, responding to you.", false},
		{"Alice", "Fourth from Alice after Bob replied.", true},
		{"Bob", "Second from Bob, chains advancing.", false},
		{"Alice", "Fifth from Alice.", true},
		{"Bob", "Third from Bob.", false},
	}

	for i, msg := range messages {
		var ct []byte
		var err error

		if msg.aliceSnd {
			ct, err = alice.Encrypt([]byte(msg.text))
			if err != nil {
				t.Fatalf("message %d (%s -> Bob): Encrypt: %v", i, msg.sender, err)
			}

			pt, decErr := bob.Decrypt(ct)
			if decErr != nil {
				t.Fatalf("message %d (%s -> Bob): Decrypt: %v", i, msg.sender, decErr)
			}

			if !bytes.Equal(pt, []byte(msg.text)) {
				t.Errorf("message %d: got %q, want %q", i, pt, msg.text)
			}
		} else {
			ct, err = bob.Encrypt([]byte(msg.text))
			if err != nil {
				t.Fatalf("message %d (%s -> Alice): Encrypt: %v", i, msg.sender, err)
			}

			pt, decErr := alice.Decrypt(ct)
			if decErr != nil {
				t.Fatalf("message %d (%s -> Alice): Decrypt: %v", i, msg.sender, decErr)
			}

			if !bytes.Equal(pt, []byte(msg.text)) {
				t.Errorf("message %d: got %q, want %q", i, pt, msg.text)
			}
		}
	}
}

// TestTripleRatchet_EpochTransition verifies that the Triple Ratchet
// correctly transitions between PQ epochs when the Braid produces an
// output key, advancing the SPQR chain via KdfSckaRK.
func TestTripleRatchet_EpochTransition(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	// Both should start in epoch 0 with valid root keys.
	if alice.pqEpoch != 0 {
		t.Fatalf("Alice initial pqEpoch = %d, want 0", alice.pqEpoch)
	}
	if bob.pqEpoch != 0 {
		t.Fatalf("Bob initial pqEpoch = %d, want 0", bob.pqEpoch)
	}

	// Send several messages in epoch 0.
	for i := 0; i < 5; i++ {
		ct, err := alice.Encrypt([]byte("epoch 0 message"))
		if err != nil {
			t.Fatalf("Epoch 0 Encrypt %d: %v", i, err)
		}

		pt, err := bob.Decrypt(ct)
		if err != nil {
			t.Fatalf("Epoch 0 Decrypt %d: %v", i, err)
		}

		if !bytes.Equal(pt, []byte("epoch 0 message")) {
			t.Errorf("message %d mismatch", i)
		}
	}

	// Simulate Braid producing an epoch secret, advancing both sides.
	epochSecret := make([]byte, 32)
	if _, err := rand.Read(epochSecret); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	aliceES := make([]byte, len(epochSecret))
	copy(aliceES, epochSecret)
	if err := alice.advancePQEpoch(aliceES); err != nil {
		t.Fatalf("alice advancePQEpoch: %v", err)
	}

	bobES := make([]byte, len(epochSecret))
	copy(bobES, epochSecret)
	if err := bob.advancePQEpoch(bobES); err != nil {
		t.Fatalf("bob advancePQEpoch: %v", err)
	}

	// Verify epoch advancement.
	if alice.pqEpoch != 1 {
		t.Errorf("Alice pqEpoch after advance = %d, want 1", alice.pqEpoch)
	}
	if bob.pqEpoch != 1 {
		t.Errorf("Bob pqEpoch after advance = %d, want 1", bob.pqEpoch)
	}

	// Send messages in the new epoch.
	for i := 0; i < 5; i++ {
		plaintext := []byte("epoch 1 message")
		ct, err := alice.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Epoch 1 Encrypt %d: %v", i, err)
		}

		pt, err := bob.Decrypt(ct)
		if err != nil {
			t.Fatalf("Epoch 1 Decrypt %d: %v", i, err)
		}

		if !bytes.Equal(pt, plaintext) {
			t.Errorf("epoch 1 message %d mismatch", i)
		}
	}
}

// TestTripleRatchet_ChainKeyIndependence verifies that the send and receive
// chain keys advance independently, allowing unidirectional message bursts.
func TestTripleRatchet_ChainKeyIndependence(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	// Record initial chain key states (copies).
	aliceSendBefore := make([]byte, alice.sendChainKey.Size())
	copy(aliceSendBefore, alice.sendChainKey.Bytes())
	aliceRecvBefore := make([]byte, alice.recvChainKey.Size())
	copy(aliceRecvBefore, alice.recvChainKey.Bytes())

	// Alice sends 5 messages. Her sendChainKey should advance, recvChainKey should not.
	for i := 0; i < 5; i++ {
		ct, err := alice.Encrypt([]byte("burst message"))
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}

		_, err = bob.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt %d: %v", i, err)
		}
	}

	if bytes.Equal(alice.sendChainKey.Bytes(), aliceSendBefore) {
		t.Error("Alice's sendChainKey should have advanced after sending")
	}
	// Alice's recvChainKey should NOT advance when she only sends.
	// recvChainKey only advances during Decrypt.
	if !bytes.Equal(alice.recvChainKey.Bytes(), aliceRecvBefore) {
		t.Error("Alice's recvChainKey should not advance when only sending")
	}
}

// TestTripleRatchet_LargePayload verifies the Triple Ratchet handles
// larger plaintext payloads correctly through encryption and decryption.
func TestTripleRatchet_LargePayload(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	// Create a large payload (4KB).
	plaintext := make([]byte, 4096)
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	ct, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt large payload: %v", err)
	}

	pt, err := bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt large payload: %v", err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Error("large payload roundtrip failed")
	}
}

// TestTripleRatchet_SPQRChainKeySymmetry verifies that Alice and Bob derive
// symmetric chain keys from the shared secret, with the send/recv swap
// applied correctly.
func TestTripleRatchet_SPQRChainKeySymmetry(t *testing.T) {
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Derive keys the same way the constructors do.
	_, cks, ckr, err := spqr.KdfSckaInit(sharedSecret)
	if err != nil {
		t.Fatalf("KdfSckaInit: %v", err)
	}

	aliceCipher := newMockECCipher()
	bobCipher := newMockECCipher()

	alice, err := NewAlice(aliceCipher, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := NewBob(bobCipher, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}
	defer bob.Zeroize()

	// Alice's sendChainKey should match Bob's recvChainKey (= cks).
	if !bytes.Equal(alice.sendChainKey.Bytes(), cks.Bytes()) {
		t.Error("Alice's sendChainKey should equal cks from KdfSckaInit")
	}
	if !bytes.Equal(bob.recvChainKey.Bytes(), cks.Bytes()) {
		t.Error("Bob's recvChainKey should equal cks from KdfSckaInit")
	}

	// Alice's recvChainKey should match Bob's sendChainKey (= ckr).
	if !bytes.Equal(alice.recvChainKey.Bytes(), ckr.Bytes()) {
		t.Error("Alice's recvChainKey should equal ckr from KdfSckaInit")
	}
	if !bytes.Equal(bob.sendChainKey.Bytes(), ckr.Bytes()) {
		t.Error("Bob's sendChainKey should equal ckr from KdfSckaInit")
	}
}

// TestTripleRatchet_BraidEpochStartsAtOne verifies that the Braid epoch
// is correctly initialized at 1 (not 0) for both Alice and Bob, and that
// the SPQR chain keys are independent of the Braid epoch numbering.
func TestTripleRatchet_BraidEpochStartsAtOne(t *testing.T) {
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	alice, err := NewAlice(&mockECCipher{}, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := NewBob(&mockECCipher{}, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}
	defer bob.Zeroize()

	// Per spec Section 2.6: epoch=1 at initialization.
	if alice.Epoch() != 1 {
		t.Errorf("Alice initial epoch = %d, want 1", alice.Epoch())
	}
	if bob.Epoch() != 1 {
		t.Errorf("Bob initial epoch = %d, want 1", bob.Epoch())
	}

	// Verify chain keys are non-nil regardless of epoch.
	if alice.sendChainKey == nil || alice.sendChainKey.Size() == 0 {
		t.Error("Alice sendChainKey should be initialized")
	}
	if bob.recvChainKey == nil || bob.recvChainKey.Size() == 0 {
		t.Error("Bob recvChainKey should be initialized")
	}
}

// TestTripleRatchet_HybridKDFProducesDifferentKeysPerMessage verifies that
// each message gets a unique set of encryption keys, even when the PQ key
// is the same, because the SPQR chain key advances per message.
func TestTripleRatchet_HybridKDFProducesDifferentKeysPerMessage(t *testing.T) {
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	_, cks, _, err := spqr.KdfSckaInit(sharedSecret)
	if err != nil {
		t.Fatalf("KdfSckaInit: %v", err)
	}

	ecMK := make([]byte, 32)
	if _, err := rand.Read(ecMK); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Derive two successive PQ message keys from the chain.
	pqMK1, nextCK, err := spqr.KdfSckaCK(cks, 0)
	if err != nil {
		t.Fatalf("KdfSckaCK: %v", err)
	}

	pqMK2, _, err := spqr.KdfSckaCK(nextCK, 1)
	if err != nil {
		t.Fatalf("KdfSckaCK: %v", err)
	}

	// The two PQ message keys must be different.
	if bytes.Equal(pqMK1.Bytes(), pqMK2.Bytes()) {
		t.Fatal("successive PQ message keys should differ")
	}

	// Hybrid KDF with same EC key but different PQ keys should produce
	// different encryption keys.
	keys1, err := KDFHybrid(ecMK, pqMK1.Bytes())
	if err != nil {
		t.Fatalf("KDFHybrid 1: %v", err)
	}

	keys2, err := KDFHybrid(ecMK, pqMK2.Bytes())
	if err != nil {
		t.Fatalf("KDFHybrid 2: %v", err)
	}

	if bytes.Equal(keys1.CipherKey.Bytes(), keys2.CipherKey.Bytes()) {
		t.Error("different PQ keys should produce different CipherKeys")
	}
	if bytes.Equal(keys1.MacKey.Bytes(), keys2.MacKey.Bytes()) {
		t.Error("different PQ keys should produce different MacKeys")
	}
	if bytes.Equal(keys1.IV.Bytes(), keys2.IV.Bytes()) {
		t.Error("different PQ keys should produce different IVs")
	}
}

// TestTripleRatchet_MACIntegrityAcrossMultipleMessages verifies that the
// MAC authentication correctly protects each message independently, so
// tampering with one message does not affect others.
func TestTripleRatchet_MACIntegrityAcrossMultipleMessages(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	// Send 3 valid messages.
	var ciphertexts [][]byte
	for i := 0; i < 3; i++ {
		ct, err := alice.Encrypt([]byte("message"))
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}
		ciphertexts = append(ciphertexts, ct)
	}

	// Decrypt the first message successfully.
	pt, err := bob.Decrypt(ciphertexts[0])
	if err != nil {
		t.Fatalf("Decrypt first: %v", err)
	}
	if !bytes.Equal(pt, []byte("message")) {
		t.Error("first message decryption mismatch")
	}

	// Parse the second message to tamper with the ciphertext portion specifically.
	header, ctBytes, err := deserializeCompositeMessage(ciphertexts[1])
	if err != nil {
		t.Fatalf("deserializeCompositeMessage: %v", err)
	}

	// Flip a byte in the encrypted payload (before the MAC tag).
	if len(ctBytes) <= HMACSize {
		t.Fatal("ciphertext too short to contain payload and MAC")
	}
	ctBytes[0] ^= 0xFF

	// Re-serialize with tampered ciphertext.
	tampered, err := serializeCompositeMessage(header, ctBytes)
	if err != nil {
		t.Fatalf("serializeCompositeMessage: %v", err)
	}

	// Decrypting tampered message should fail with MAC or decryption error.
	_, err = bob.Decrypt(tampered)
	if err == nil {
		t.Fatal("expected error for tampered message")
	}
}

// TestTripleRatchet_ZeroizePreventsSensitiveDataLeak verifies that after
// calling Zeroize, all sensitive key material is cleared.
func TestTripleRatchet_ZeroizePreventsSensitiveDataLeak(t *testing.T) {
	alice, bob := setupAliceBob(t)

	// Exchange a message to populate state.
	ct, err := alice.Encrypt([]byte("test"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	_, err = bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	alice.Zeroize()
	bob.Zeroize()

	// After Zeroize, all secret fields should be destroyed.
	if !alice.rootKey.IsDestroyed() {
		t.Error("alice.rootKey should be destroyed after Zeroize")
	}
	if !alice.sendChainKey.IsDestroyed() {
		t.Error("alice.sendChainKey should be destroyed after Zeroize")
	}
	if !alice.recvChainKey.IsDestroyed() {
		t.Error("alice.recvChainKey should be destroyed after Zeroize")
	}
	if !bob.rootKey.IsDestroyed() {
		t.Error("bob.rootKey should be destroyed after Zeroize")
	}
	if !bob.sendChainKey.IsDestroyed() {
		t.Error("bob.sendChainKey should be destroyed after Zeroize")
	}
	if !bob.recvChainKey.IsDestroyed() {
		t.Error("bob.recvChainKey should be destroyed after Zeroize")
	}
}

// TestTripleRatchet_CompositeMessageRoundTrip verifies the full
// serialization/deserialization pipeline for composite messages with
// various SCKA message types.
func TestTripleRatchet_CompositeMessageRoundTrip(t *testing.T) {
	types := []mlkembraid.MessageType{
		mlkembraid.MessageTypeNone,
		mlkembraid.MessageTypeHdr,
		mlkembraid.MessageTypeEk,
		mlkembraid.MessageTypeCt1,
		mlkembraid.MessageTypeCt2,
	}

	for _, mt := range types {
		t.Run(mt.String(), func(t *testing.T) {
			header := &CompositeHeader{
				ECHeader: []byte("ec-header-data-with-ratchet-info"),
				SCKAMsg: &mlkembraid.Message{
					Epoch: 42,
					Type:  mt,
					Data:  []byte("chunk-data"),
				},
			}

			ciphertext := []byte("encrypted-payload-with-mac-tag-appended")

			msg, err := serializeCompositeMessage(header, ciphertext)
			if err != nil {
				t.Fatalf("serialize: %v", err)
			}

			restoredHeader, restoredCT, err := deserializeCompositeMessage(msg)
			if err != nil {
				t.Fatalf("deserialize: %v", err)
			}

			if !bytes.Equal(restoredHeader.ECHeader, header.ECHeader) {
				t.Error("ECHeader mismatch")
			}
			if restoredHeader.SCKAMsg.Epoch != 42 {
				t.Errorf("Epoch = %d, want 42", restoredHeader.SCKAMsg.Epoch)
			}
			if restoredHeader.SCKAMsg.Type != mt {
				t.Errorf("Type = %d, want %d", restoredHeader.SCKAMsg.Type, mt)
			}
			if !bytes.Equal(restoredCT, ciphertext) {
				t.Error("ciphertext mismatch")
			}
		})
	}
}

// TestTripleRatchet_ECCipherKeyContributesToHybridKDF verifies that
// different EC message keys produce different hybrid output even with
// the same PQ key, confirming EC key material contributes to the output.
func TestTripleRatchet_ECCipherKeyContributesToHybridKDF(t *testing.T) {
	pqKey := make([]byte, 32)
	if _, err := rand.Read(pqKey); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	ecMK1 := make([]byte, 32)
	ecMK2 := make([]byte, 32)
	if _, err := rand.Read(ecMK1); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if _, err := rand.Read(ecMK2); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	keys1, err := KDFHybrid(ecMK1, pqKey)
	if err != nil {
		t.Fatalf("KDFHybrid 1: %v", err)
	}

	keys2, err := KDFHybrid(ecMK2, pqKey)
	if err != nil {
		t.Fatalf("KDFHybrid 2: %v", err)
	}

	if bytes.Equal(keys1.CipherKey.Bytes(), keys2.CipherKey.Bytes()) {
		t.Error("different EC keys with same PQ key should produce different CipherKeys")
	}
}

// TestTripleRatchet_SPQRIndependentFromBraidEpoch verifies that the SPQR
// chain key derivation used in the Triple Ratchet is completely independent
// from the Braid's epoch numbering.
func TestTripleRatchet_SPQRIndependentFromBraidEpoch(t *testing.T) {
	sharedSecret := make([]byte, 32)
	if _, err := rand.Read(sharedSecret); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Derive SPQR chain keys directly.
	_, cks, ckr, err := spqr.KdfSckaInit(sharedSecret)
	if err != nil {
		t.Fatalf("KdfSckaInit: %v", err)
	}

	// Derive message keys from the chain.
	mk1, nextCK1, err := spqr.KdfSckaCK(cks, 0)
	if err != nil {
		t.Fatalf("KdfSckaCK(cks): %v", err)
	}

	mk2, _, err := spqr.KdfSckaCK(ckr, 0)
	if err != nil {
		t.Fatalf("KdfSckaCK(ckr): %v", err)
	}

	// Message keys should be non-nil, 32 bytes, and different from each other.
	if mk1.Size() != 32 || mk2.Size() != 32 {
		t.Fatal("message keys should be 32 bytes")
	}
	if bytes.Equal(mk1.Bytes(), mk2.Bytes()) {
		t.Error("send and recv message keys should differ")
	}

	// The next chain key should differ from the message key.
	if bytes.Equal(mk1.Bytes(), nextCK1.Bytes()) {
		t.Error("message key and next chain key should differ")
	}
}
