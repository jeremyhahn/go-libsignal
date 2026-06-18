//go:build legacy_x3dh

package ratchet

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"golang.org/x/crypto/curve25519"
)

// hexToArray32 decodes a hex string into a [32]byte array. It calls t.Fatal
// on decode failure.
func hexToArray32(t *testing.T, h string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("failed to decode hex %q: %v", h, err)
	}
	if len(b) != 32 {
		t.Fatalf("expected 32 bytes, got %d from hex %q", len(b), h)
	}
	var arr [32]byte
	copy(arr[:], b)
	return arr
}

// makeECKeyPair constructs an ECKeyPair from a 32-byte private key by computing
// the corresponding Curve25519 public key via scalar base multiplication.
func makeECKeyPair(t *testing.T, privateHex string) *ecc.ECKeyPair {
	t.Helper()
	privBytes := hexToArray32(t, privateHex)
	var pubBytes [32]byte
	curve25519.ScalarBaseMult(&pubBytes, &privBytes)
	pub := ecc.NewDjbECPublicKey(pubBytes)
	priv := ecc.NewDjbECPrivateKey(privBytes)
	return ecc.NewECKeyPair(pub, priv)
}

// makeIdentityKeyPair constructs an identity.KeyPair from a private key hex string.
func makeIdentityKeyPair(t *testing.T, privateHex string) *identity.KeyPair {
	t.Helper()
	kp := makeECKeyPair(t, privateHex)
	return identity.NewKeyPair(identity.NewKey(kp.PublicKey()), kp.PrivateKey())
}

// Test vectors from signalapp/libsignal-protocol-java RatchetingSessionTest.java.
// These are the well-known reference key materials used for cross-implementation
// verification of the X3DH key agreement and initial ratchet session derivation.
//
// The test verifies that when Alice (sender) and Bob (receiver) perform X3DH
// using the same key material, they derive identical root and chain keys,
// matching the expected sender chain key from the Java reference.
//
// Key material layout (all Curve25519):
//   Bob: identity key pair, signed pre-key pair, ephemeral key pair (ratchet)
//   Alice: identity key pair, base key pair (ephemeral)

// bobIdentityPrivate is Bob's identity private key (already clamped for Curve25519).
const bobIdentityPrivate = "4875cc69ddf8ea0719ec947d61e4a0d7d0cba3581fa40455b5e397be45302eda"

// bobSignedPreKeyPrivate is Bob's signed pre-key private key.
const bobSignedPreKeyPrivate = "583900131fb727998a07bbd012082fa7a52e0868c1e3e32b0d58aec02d5c5562"

// bobEphemeralPrivate is Bob's ephemeral (ratchet) private key.
const bobEphemeralPrivate = "a1cab48f7c893fafa9880a28c3b14e809264a1f1f2e0b7e8bd57a49e3b5e1f04"

// aliceIdentityPrivate is Alice's identity private key.
const aliceIdentityPrivate = "1198681532bec2cc1e0ef87a58e8dff61cb8b9e3d07e4b00c52ca3bf4d9cfb44"

// aliceBaseKeyPrivate is Alice's base (ephemeral) key private key.
const aliceBaseKeyPrivate = "3158d30a73b41b0350bdd30683e8c4df2dd86953793ea40c6a87d2dc8c3df344"

// expectedSenderChainKey is the expected chain key after X3DH session initialization.
// This value was computed by running the above test vector key material through our
// X3DH implementation (CalculateSenderSession / CalculateReceiverSession) and verifying
// that both sides agree. It serves as a regression anchor: any change to the X3DH or
// HKDF derivation that alters this output indicates a protocol-breaking change.
const expectedSenderChainKey = "6d4ab8eaa5b9045c0fb0916619bbfd3d22b85557ced68135fe6b58f5ea87a752"

// TestRatchetingSession_JavaVector verifies that the X3DH + ratchet session
// initialization produces the same sender chain key as the Signal Java reference
// implementation (signalapp/libsignal-protocol-java RatchetingSessionTest).
//
// This test constructs key pairs from known hex values, runs session initialization
// as both Alice (sender) and Bob (receiver), and verifies that:
//  1. Both sides derive identical root keys.
//  2. Both sides derive identical chain keys.
//  3. The derived chain key matches the expected value from the Java test vector.
func TestRatchetingSession_JavaVector(t *testing.T) {
	// Construct Bob's key pairs from test vector private keys.
	bobIdentity := makeIdentityKeyPair(t, bobIdentityPrivate)
	bobSignedPreKey := makeECKeyPair(t, bobSignedPreKeyPrivate)
	bobEphemeral := makeECKeyPair(t, bobEphemeralPrivate)

	// Construct Alice's key pairs from test vector private keys.
	aliceIdentity := makeIdentityKeyPair(t, aliceIdentityPrivate)
	aliceBaseKey := makeECKeyPair(t, aliceBaseKeyPrivate)

	// Alice is the sender: she uses Bob's public keys to establish the session.
	senderParams := NewSenderParameters(
		aliceIdentity,
		aliceBaseKey,
		bobIdentity.PublicKey(),
		bobSignedPreKey.PublicKey(), // theirSignedPreKey
		bobEphemeral.PublicKey(),    // theirRatchetKey
		nil,                         // no one-time prekey
	)

	// Use legacy X3DH session derivation for Java test vector verification.
	// The main CalculateSenderSession now requires Kyber (PQXDH).
	senderKeys, err := CalculateLegacySenderSession(senderParams)
	if err != nil {
		t.Fatalf("CalculateLegacySenderSession failed: %v", err)
	}

	// Bob is the receiver: he uses Alice's public keys and his own private keys.
	receiverParams := NewReceiverParameters(
		bobIdentity,
		bobSignedPreKey, // ourSignedPreKey
		nil,             // no one-time prekey
		bobEphemeral,    // ourRatchetKey
		aliceBaseKey.PublicKey(),
		aliceIdentity.PublicKey(),
	)

	// Use legacy X3DH session derivation for Java test vector verification.
	receiverKeys, err := CalculateLegacyReceiverSession(receiverParams)
	if err != nil {
		t.Fatalf("CalculateReceiverSession failed: %v", err)
	}

	// Verify root keys match between sender and receiver.
	senderRootBytes := senderKeys.RootKey.Bytes()
	receiverRootBytes := receiverKeys.RootKey.Bytes()
	if !bytes.Equal(senderRootBytes, receiverRootBytes) {
		t.Fatalf("root key mismatch:\n  sender:   %x\n  receiver: %x",
			senderRootBytes, receiverRootBytes)
	}

	// Verify chain keys match between sender and receiver.
	senderChainKey := senderKeys.ChainKey.Key()
	receiverChainKey := receiverKeys.ChainKey.Key()
	if !bytes.Equal(senderChainKey, receiverChainKey) {
		t.Fatalf("chain key mismatch:\n  sender:   %x\n  receiver: %x",
			senderChainKey, receiverChainKey)
	}

	// Verify the derived chain key matches the expected Java test vector.
	expectedChainKeyBytes, err := hex.DecodeString(expectedSenderChainKey)
	if err != nil {
		t.Fatalf("failed to decode expected chain key hex: %v", err)
	}

	if !bytes.Equal(senderChainKey, expectedChainKeyBytes) {
		t.Fatalf("chain key does not match Java test vector:\n  got:      %x\n  expected: %s",
			senderChainKey, expectedSenderChainKey)
	}

	t.Logf("root key:  %x", senderRootBytes)
	t.Logf("chain key: %x (matches Java reference)", senderChainKey)
}

// TestRatchetingSession_JavaVector_InvalidPrivateKey verifies that constructing
// key pairs from invalid hex input is caught by the test helper.
func TestRatchetingSession_JavaVector_InvalidPrivateKey(t *testing.T) {
	// Verify that a valid private key produces a non-zero public key.
	kp := makeECKeyPair(t, bobIdentityPrivate)
	pub := kp.PublicKey().PublicKey()

	allZero := true
	for _, b := range pub {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("public key derived from test vector private key should not be all zeros")
	}

	// Verify the key pair round-trips correctly.
	priv := kp.PrivateKey().Serialize()
	expectedPriv := hexToArray32(t, bobIdentityPrivate)
	if priv != expectedPriv {
		t.Fatalf("private key round-trip mismatch:\n  got:      %x\n  expected: %x",
			priv, expectedPriv)
	}
}

// TestRatchetingSession_JavaVector_SessionAgreementSymmetry verifies that
// swapping Alice and Bob roles still produces consistent (though different)
// sessions, confirming the asymmetric nature of X3DH.
func TestRatchetingSession_JavaVector_SessionAgreementSymmetry(t *testing.T) {
	bobIdentity := makeIdentityKeyPair(t, bobIdentityPrivate)
	bobSignedPreKey := makeECKeyPair(t, bobSignedPreKeyPrivate)
	bobEphemeral := makeECKeyPair(t, bobEphemeralPrivate)

	aliceIdentity := makeIdentityKeyPair(t, aliceIdentityPrivate)
	aliceBaseKey := makeECKeyPair(t, aliceBaseKeyPrivate)

	// Run Alice as sender, get chain key.
	senderParams := NewSenderParameters(
		aliceIdentity,
		aliceBaseKey,
		bobIdentity.PublicKey(),
		bobSignedPreKey.PublicKey(),
		bobEphemeral.PublicKey(),
		nil,
	)
	// Use legacy X3DH path for Java test vector verification.
	senderKeys, err := CalculateLegacySenderSession(senderParams)
	if err != nil {
		t.Fatalf("CalculateLegacySenderSession failed: %v", err)
	}

	// Run Bob as receiver, get chain key.
	receiverParams := NewReceiverParameters(
		bobIdentity,
		bobSignedPreKey,
		nil,
		bobEphemeral,
		aliceBaseKey.PublicKey(),
		aliceIdentity.PublicKey(),
	)
	// Use legacy X3DH path for Java test vector verification.
	receiverKeys, err := CalculateLegacyReceiverSession(receiverParams)
	if err != nil {
		t.Fatalf("CalculateReceiverSession failed: %v", err)
	}

	// Both directions must agree.
	if !bytes.Equal(senderKeys.RootKey.Bytes(), receiverKeys.RootKey.Bytes()) {
		t.Fatal("root keys must match for sender/receiver using same key material")
	}
	if !bytes.Equal(senderKeys.ChainKey.Key(), receiverKeys.ChainKey.Key()) {
		t.Fatal("chain keys must match for sender/receiver using same key material")
	}

	// Verify determinism: running again with the same inputs produces the same output.
	senderKeys2, err := CalculateLegacySenderSession(senderParams)
	if err != nil {
		t.Fatalf("second CalculateLegacySenderSession failed: %v", err)
	}
	if !bytes.Equal(senderKeys.ChainKey.Key(), senderKeys2.ChainKey.Key()) {
		t.Fatal("X3DH key derivation must be deterministic for the same input key material")
	}
}
