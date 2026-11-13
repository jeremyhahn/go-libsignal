//go:build legacy_x3dh

package ratchet

import (
	"testing"
)

// TestIsSender verifies the isSender comparison logic.
func TestIsSender(t *testing.T) {
	kp1 := genKP(t)
	kp2 := genKP(t)

	// isSender should return a deterministic boolean based on key ordering.
	result1 := isSender(kp1.PublicKey(), kp2.PublicKey())
	result2 := isSender(kp2.PublicKey(), kp1.PublicKey())

	// Exactly one should be true (unless keys are equal, which is astronomically unlikely).
	if result1 == result2 {
		t.Fatal("isSender should return opposite results for swapped keys")
	}
}

// TestIsSenderSameKey verifies isSender returns false when keys are identical.
func TestIsSenderSameKey(t *testing.T) {
	kp := genKP(t)
	result := isSender(kp.PublicKey(), kp.PublicKey())
	if result {
		t.Fatal("isSender should return false for identical keys")
	}
}

// TestCalculateLegacySenderSession verifies the legacy X3DH sender session path.
func TestCalculateLegacySenderSession(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourBaseKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirSignedPreKey := genKP(t)
	theirRatchetKey := genKP(t)

	params := NewSenderParameters(
		ourIdentity,
		ourBaseKey,
		theirIdentity.PublicKey(),
		theirSignedPreKey.PublicKey(),
		theirRatchetKey.PublicKey(),
		nil,
	)

	sessionKeys, err := CalculateLegacySenderSession(params)
	if err != nil {
		t.Fatal(err)
	}
	if sessionKeys == nil {
		t.Fatal("session keys should not be nil")
	}
	if sessionKeys.RootKey == nil {
		t.Fatal("root key should not be nil")
	}
	if sessionKeys.ChainKey == nil {
		t.Fatal("chain key should not be nil")
	}
}

// TestCalculateLegacyReceiverSession verifies the legacy X3DH receiver session path.
func TestCalculateLegacyReceiverSession(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourSignedPreKey := genKP(t)
	ourRatchetKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirBaseKey := genKP(t)

	params := NewReceiverParameters(
		ourIdentity,
		ourSignedPreKey,
		nil,
		ourRatchetKey,
		theirBaseKey.PublicKey(),
		theirIdentity.PublicKey(),
	)

	sessionKeys, err := CalculateLegacyReceiverSession(params)
	if err != nil {
		t.Fatal(err)
	}
	if sessionKeys == nil {
		t.Fatal("session keys should not be nil")
	}
	if sessionKeys.RootKey == nil {
		t.Fatal("root key should not be nil")
	}
	if sessionKeys.ChainKey == nil {
		t.Fatal("chain key should not be nil")
	}
}

// TestSenderReceiverSessionAgreement verifies that a sender and receiver
// derive the same session keys using the same key material (legacy X3DH path).
func TestSenderReceiverSessionAgreement(t *testing.T) {
	aliceIdentity := genIDKeyPair(t)
	aliceBaseKey := genKP(t)

	bobIdentity := genIDKeyPair(t)
	bobSignedPreKey := genKP(t)
	bobOneTimePreKey := genKP(t)

	// Alice is sender (legacy X3DH)
	senderParams := NewSenderParameters(
		aliceIdentity,
		aliceBaseKey,
		bobIdentity.PublicKey(),
		bobSignedPreKey.PublicKey(),
		bobSignedPreKey.PublicKey(), // ratchet key = signed pre key
		bobOneTimePreKey.PublicKey(),
	)

	senderKeys, err := CalculateLegacySenderSession(senderParams)
	if err != nil {
		t.Fatal(err)
	}

	// Bob is receiver (legacy X3DH)
	receiverParams := NewReceiverParameters(
		bobIdentity,
		bobSignedPreKey,
		bobOneTimePreKey,
		bobSignedPreKey, // ratchet key = signed pre key
		aliceBaseKey.PublicKey(),
		aliceIdentity.PublicKey(),
	)

	receiverKeys, err := CalculateLegacyReceiverSession(receiverParams)
	if err != nil {
		t.Fatal(err)
	}

	// Both should produce the same root key.
	senderRootBytes := mustCopy(senderKeys.RootKey.Bytes())
	receiverRootBytes := mustCopy(receiverKeys.RootKey.Bytes())

	if len(senderRootBytes) != len(receiverRootBytes) {
		t.Fatal("root key lengths should match")
	}
	for i := range senderRootBytes {
		if senderRootBytes[i] != receiverRootBytes[i] {
			t.Fatal("root keys should match between sender and receiver")
		}
	}

	// Both should produce the same chain key.
	senderChainKey := senderKeys.ChainKey.Key()
	receiverChainKey := receiverKeys.ChainKey.Key()

	if len(senderChainKey) != len(receiverChainKey) {
		t.Fatal("chain key lengths should match")
	}
	for i := range senderChainKey {
		if senderChainKey[i] != receiverChainKey[i] {
			t.Fatal("chain keys should match between sender and receiver")
		}
	}
}

// TestCalculateSymmetricSession verifies symmetric session calculation.
func TestCalculateSymmetricSession(t *testing.T) {
	aliceIdentity := genIDKeyPair(t)
	aliceBaseKey := genKP(t)
	aliceRatchetKey := genKP(t)

	bobIdentity := genIDKeyPair(t)
	bobBaseKey := genKP(t)
	bobRatchetKey := genKP(t)

	params := &SymmetricParameters{
		OurBaseKey:         aliceBaseKey,
		OurRatchetKey:      aliceRatchetKey,
		OurIdentityKeyPair: aliceIdentity,
		TheirBaseKey:       bobBaseKey.PublicKey(),
		TheirRatchetKey:    bobRatchetKey.PublicKey(),
		TheirIdentityKey:   bobIdentity.PublicKey(),
	}

	sessionKeys, err := CalculateSymmetricSession(params)
	if err != nil {
		t.Fatal(err)
	}
	if sessionKeys == nil {
		t.Fatal("session keys should not be nil")
	}
}

// TestCalculateSymmetricSessionBothDirections verifies that when Alice
// and Bob calculate symmetric sessions, both paths produce valid keys.
func TestCalculateSymmetricSessionBothDirections(t *testing.T) {
	aliceIdentity := genIDKeyPair(t)
	aliceBaseKey := genKP(t)
	aliceRatchetKey := genKP(t)

	bobIdentity := genIDKeyPair(t)
	bobBaseKey := genKP(t)
	bobRatchetKey := genKP(t)

	aliceParams := &SymmetricParameters{
		OurBaseKey:         aliceBaseKey,
		OurRatchetKey:      aliceRatchetKey,
		OurIdentityKeyPair: aliceIdentity,
		TheirBaseKey:       bobBaseKey.PublicKey(),
		TheirRatchetKey:    bobRatchetKey.PublicKey(),
		TheirIdentityKey:   bobIdentity.PublicKey(),
	}

	bobParams := &SymmetricParameters{
		OurBaseKey:         bobBaseKey,
		OurRatchetKey:      bobRatchetKey,
		OurIdentityKeyPair: bobIdentity,
		TheirBaseKey:       aliceBaseKey.PublicKey(),
		TheirRatchetKey:    aliceRatchetKey.PublicKey(),
		TheirIdentityKey:   aliceIdentity.PublicKey(),
	}

	aliceSession, err := CalculateSymmetricSession(aliceParams)
	if err != nil {
		t.Fatal(err)
	}

	bobSession, err := CalculateSymmetricSession(bobParams)
	if err != nil {
		t.Fatal(err)
	}

	// Both sessions should produce the same root key.
	aliceRoot := mustCopy(aliceSession.RootKey.Bytes())
	bobRoot := mustCopy(bobSession.RootKey.Bytes())
	if len(aliceRoot) != len(bobRoot) {
		t.Fatal("root key lengths should match for symmetric session")
	}
	for i := range aliceRoot {
		if aliceRoot[i] != bobRoot[i] {
			t.Fatal("symmetric session root keys should match")
		}
	}
}

// TestLegacySession_NoInitialPQRKey verifies that legacy X3DH sessions
// (used for symmetric sessions) do not produce an InitialPQRKey since they
// use the 64-byte derivation path.
func TestLegacySession_NoInitialPQRKey(t *testing.T) {
	aliceIdentity := genIDKeyPair(t)
	aliceBaseKey := genKP(t)

	bobIdentity := genIDKeyPair(t)
	bobSignedPreKey := genKP(t)

	senderParams := NewSenderParameters(
		aliceIdentity,
		aliceBaseKey,
		bobIdentity.PublicKey(),
		bobSignedPreKey.PublicKey(),
		bobSignedPreKey.PublicKey(),
		nil,
	)

	senderKeys, err := CalculateLegacySenderSession(senderParams)
	if err != nil {
		t.Fatal(err)
	}

	// Legacy X3DH sessions derive 64 bytes (root + chain only), no PQR key.
	if senderKeys.InitialPQRKey != nil {
		t.Fatal("legacy X3DH session should not produce InitialPQRKey")
	}
}
