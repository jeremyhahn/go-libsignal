//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 1 test in this file exercises X25519. FIPS 140-3 does not approve that,
// but the X3DH specification (section 2.1) and the Double Ratchet
// specification (section 5.2) require it, so the fips140only build tag drops
// this file from the FIPS gate. `make test` and `make coverage` still run
// it.

package tests

import (
	"bytes"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"testing"
)

// TestSerializing tests serialization and deserialization of Signal objects.
func TestSerializing(t *testing.T) {

	// Create a serializer object that will be used to encode/decode data.
	serializer := newSerializer()

	// Create our users who will talk to each other.
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)

	// Create a session builder to create a session between Alice -> Bob.
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	// Create a PreKeyBundle from Bob's prekey records with Kyber keys.
	retrievedPreKey := bob.kyberBundle()

	// Process Bob's retrieved prekey to establish a session.
	if err := alice.sessionBuilder.ProcessBundle(retrievedPreKey); err != nil {
		t.Fatalf("ProcessBundle failed: %v", err)
	}

	// Create a session cipher to encrypt messages to Bob.
	plaintextMessage := []byte("Hello!")
	sessionCipher := session.NewCipherWithLocalAddress(alice.sessionBuilder, alice.address, bob.address)
	if _, err := sessionCipher.Encrypt(plaintextMessage); err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// Serialize our session so it can be stored.
	loadedSession, err := alice.sessionStore.LoadSession(bob.address)
	if err != nil {
		t.Fatalf("LoadSession failed: %v", err)
	}
	serializedSession, err := loadedSession.Serialize()
	if err != nil {
		t.Fatalf("Failed to serialize session: %v", err)
	}

	// Try deserializing our session back into an object.
	deserializedSession, err := record.NewSessionFromBytes(serializedSession, serializer.Session, serializer.State)
	if err != nil {
		t.Fatalf("Failed to deserialize session: %v", err)
	}

	// Re-serialize the deserialized session and verify round-trip integrity.
	// We cannot use pretty.Formatter here because it uses reflection which
	// walks into memguard-protected pages and triggers SIGSEGV.
	reserializedSession, err := deserializedSession.Serialize()
	if err != nil {
		t.Fatalf("Failed to re-serialize deserialized session: %v", err)
	}

	if !bytes.Equal(serializedSession, reserializedSession) {
		t.Fatal("Round-trip serialization mismatch: original and re-serialized sessions differ")
	}

	t.Log("Session serialization round-trip verified successfully")
}
