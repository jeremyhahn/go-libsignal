//go:build legacy_x3dh

package ratchet

import (
	"testing"
)

// TestReceiverParametersNilOneTimePreKeyLegacy verifies that
// CalculateLegacyReceiverSession works correctly with a nil one-time pre-key,
// which is a valid optional parameter in the legacy X3DH protocol.
func TestReceiverParametersNilOneTimePreKeyLegacy(t *testing.T) {
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

	if params.OurOneTimePreKey() != nil {
		t.Fatal("one time pre key should be nil")
	}

	// Verify that CalculateLegacyReceiverSession works with nil one-time prekey.
	sessionKeys, err := CalculateLegacyReceiverSession(params)
	if err != nil {
		t.Fatal(err)
	}
	if sessionKeys == nil {
		t.Fatal("session keys should not be nil")
	}
}
