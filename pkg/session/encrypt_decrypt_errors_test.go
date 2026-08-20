//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 8 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the X3DH specification (section 2.1) and the Double Ratchet
// specification (section 5.2) require it, so the fips140only build tag drops
// this file from the FIPS gate. `make test` and `make coverage` still run
// it.

package session_test

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
)

// ================== Encrypt StoreSession error ==================

// TestEncrypt_StoreSessionError verifies that Encrypt returns an error when
// the session store's StoreSession fails after successful encryption.
// This exercises SessionCipher.go:237-239 (the StoreSession error path when
// there is no unacknowledged pre-key message).
func TestEncrypt_StoreSessionError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Alice and Bob complete a full initial exchange so that the unacknowledged
	// pre-key is cleared. After this, Alice's session is "acknowledged" and
	// subsequent Encrypt calls go through the non-PreKey path.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	firstMsg, err := aliceCipher.Encrypt([]byte("initial message"))
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := firstMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(firstBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes Alice's initial message to establish his session.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	// Bob encrypts a reply to Alice, which acknowledges the session.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	replyMsg, err := bobCipher.Encrypt([]byte("reply"))
	if err != nil {
		t.Fatal(err)
	}
	replyBytes, err := replyMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	replySignal, err := protocol.NewSignalMessageFromBytes(replyBytes,
		serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Alice decrypts Bob's reply; this clears the unacknowledged pre-key state.
	if _, err := aliceCipher.Decrypt(replySignal); err != nil {
		t.Fatalf("Alice decrypt reply: %v", err)
	}

	// Now create a cipher for Alice that uses a StoreSession-erroring store.
	// The inner store has the established session so LoadSession succeeds.
	errStore := &errStoreSessionStore{inner: alice.sessionStore}
	aliceCipherWithErrStore := session.NewCipherFromSession(
		nil,
		bob.address,
		errStore,
		alice.preKeyStore,
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)
	// Wire up Alice's identity store so the cipher can perform identity checks
	// and reach the StoreSession call.
	aliceCipherWithErrStore.SetIdentityStore(alice.identityStore)

	// Alice's next Encrypt call should fail when StoreSession errors.
	_, err = aliceCipherWithErrStore.Encrypt([]byte("should fail on store"))
	if err == nil {
		t.Fatal("expected error from Encrypt() when StoreSession fails")
	}
}

// ================== Encrypt identity store errors ==================

// TestEncrypt_IsTrustedIdentityError verifies that Encrypt returns an error
// when the identity store's IsTrustedIdentity fails during the trust check.
// This exercises SessionCipher.go:225-227 (IsTrustedIdentity error path).
func TestEncrypt_IsTrustedIdentityError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Establish the session: Alice processes Bob's bundle.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	firstMsg, err := aliceCipher.Encrypt([]byte("initial"))
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := firstMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(firstBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes Alice's initial message to establish the session.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	// Bob replies so Alice's session becomes acknowledged (pre-key cleared).
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	replyMsg, err := bobCipher.Encrypt([]byte("reply"))
	if err != nil {
		t.Fatal(err)
	}
	replyBytes, err := replyMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	replySignal, err := protocol.NewSignalMessageFromBytes(replyBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aliceCipher.Decrypt(replySignal); err != nil {
		t.Fatalf("Alice decrypt reply: %v", err)
	}

	// Wire up an identity store that always errors on IsTrustedIdentity.
	errIdStore := &errIsTrustedIdentityStore{inner: alice.identityStore}
	aliceCipher.SetIdentityStore(errIdStore)

	// Encrypt should fail because IsTrustedIdentity returns an error.
	_, err = aliceCipher.Encrypt([]byte("should fail on trust check"))
	if err == nil {
		t.Fatal("expected error from Encrypt() when IsTrustedIdentity fails")
	}
}

// TestEncrypt_SaveIdentityError verifies that Encrypt returns an error when
// the identity store's SaveIdentity fails after a successful trust check.
// This exercises SessionCipher.go:232-234 (SaveIdentity error path).
func TestEncrypt_SaveIdentityError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Establish session.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	firstMsg, err := aliceCipher.Encrypt([]byte("initial"))
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := firstMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(firstBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes Alice's initial message.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	// Bob replies so Alice's session becomes acknowledged.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	replyMsg, err := bobCipher.Encrypt([]byte("reply"))
	if err != nil {
		t.Fatal(err)
	}
	replyBytes, err := replyMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	replySignal, err := protocol.NewSignalMessageFromBytes(replyBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aliceCipher.Decrypt(replySignal); err != nil {
		t.Fatalf("Alice decrypt reply: %v", err)
	}

	// Wire up an identity store: IsTrustedIdentity succeeds, SaveIdentity errors.
	errIdStore := &errSaveIdentityStore{inner: alice.identityStore}
	aliceCipher.SetIdentityStore(errIdStore)

	// Encrypt should fail because SaveIdentity returns an error.
	_, err = aliceCipher.Encrypt([]byte("should fail on save identity"))
	if err == nil {
		t.Fatal("expected error from Encrypt() when SaveIdentity fails")
	}
}

// ================== DecryptAndGetKey identity and store errors ==================

// TestDecryptAndGetKey_IsTrustedIdentityError verifies that DecryptAndGetKey
// returns an error when the identity store's IsTrustedIdentity fails after
// successful decryption.
// This exercises SessionCipher.go:314-316.
func TestDecryptAndGetKey_IsTrustedIdentityError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Establish a full session.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	firstMsg, err := aliceCipher.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := firstMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(firstBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	// Bob encrypts a message for Alice.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	bobMsg, err := bobCipher.Encrypt([]byte("from bob"))
	if err != nil {
		t.Fatal(err)
	}
	bobBytes, err := bobMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	bobSignal, err := protocol.NewSignalMessageFromBytes(bobBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Create Alice's cipher with an IsTrustedIdentity-erroring identity store.
	// The session store is normal so ContainsSession and LoadSession succeed,
	// and decryption succeeds. The error fires in the post-decrypt identity check.
	errIDStore := &errIsTrustedIdentityStore{inner: alice.identityStore}
	aliceCipherWithErrID := session.NewCipherWithIdentity(
		alice.sessionBuilder,
		bob.address,
		errIDStore,
	)

	// Decrypt should fail when IsTrustedIdentity errors after successful decryption.
	_, _, err = aliceCipherWithErrID.DecryptAndGetKey(bobSignal)
	if err == nil {
		t.Fatal("expected error from DecryptAndGetKey() when IsTrustedIdentity fails")
	}
}

// TestDecryptAndGetKey_SaveIdentityError verifies that DecryptAndGetKey
// returns an error when the identity store's SaveIdentity fails after
// successful decryption and trust check.
// This exercises SessionCipher.go:321-323.
func TestDecryptAndGetKey_SaveIdentityError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	firstMsg, err := aliceCipher.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := firstMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(firstBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	// Bob encrypts a message for Alice.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	bobMsg, err := bobCipher.Encrypt([]byte("from bob"))
	if err != nil {
		t.Fatal(err)
	}
	bobBytes, err := bobMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	bobSignal, err := protocol.NewSignalMessageFromBytes(bobBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Pre-trust Alice's record of Bob's identity so IsTrustedIdentity returns true.
	if _, err := alice.identityStore.SaveIdentity(bob.address, bob.identityKeyPair.PublicKey()); err != nil {
		t.Fatal(err)
	}

	// Create Alice's cipher with a SaveIdentity-erroring identity store.
	errIDStore := &errSaveIdentityStore{inner: alice.identityStore}
	aliceCipherWithErrID := session.NewCipherWithIdentity(
		alice.sessionBuilder,
		bob.address,
		errIDStore,
	)

	_, _, err = aliceCipherWithErrID.DecryptAndGetKey(bobSignal)
	if err == nil {
		t.Fatal("expected error from DecryptAndGetKey() when SaveIdentity fails")
	}
}

// TestDecryptAndGetKey_StoreSessionError verifies that DecryptAndGetKey
// returns an error when the session store's StoreSession fails after successful
// decryption.
// This exercises SessionCipher.go:327-329.
func TestDecryptAndGetKey_StoreSessionError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	firstMsg, err := aliceCipher.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := firstMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(firstBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	// Bob encrypts a message for Alice.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	bobMsg, err := bobCipher.Encrypt([]byte("from bob"))
	if err != nil {
		t.Fatal(err)
	}
	bobBytes, err := bobMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	bobSignal, err := protocol.NewSignalMessageFromBytes(bobBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Create a cipher for Alice that uses a StoreSession-erroring session store.
	// LoadSession and ContainsSession work (delegating to inner), but StoreSession fails.
	errStore := &errStoreSessionStore{inner: alice.sessionStore}
	aliceCipherWithErrStore := session.NewCipherFromSession(
		nil,
		bob.address,
		errStore,
		alice.preKeyStore,
		serializer.PreKeySignalMessage,
		serializer.SignalMessage,
	)

	_, _, err = aliceCipherWithErrStore.DecryptAndGetKey(bobSignal)
	if err == nil {
		t.Fatal("expected error from DecryptAndGetKey() when StoreSession fails")
	}
}

// ================== VerifyMacWithAddresses paths ==================

// TestDecryptAndGetKey_WithAddressBinding verifies the VerifyMacWithAddresses
// code path when both localAddress and remoteAddress are set on the cipher.
// This exercises SessionCipher.go:578-585 (the address-bound MAC verification).
//
// UUID-format names are required so SerializeAddresses can embed the binding
// field (proto field 6) into the SignalMessage, matching Rust's behavior.
func TestDecryptAndGetKey_WithAddressBinding(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	// Use valid ServiceId (UUID) format addresses so SerializeAddresses works.
	alice := newTestUser(t, "11111111-1111-1111-1111-111111111111", 1, serializer)
	bob := newTestUser(t, "22222222-2222-2222-2222-222222222222", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Establish full session.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	// Alice encrypts with address binding (both localAddress and remoteAddress set).
	aliceCipher := session.NewCipherWithLocalAddress(alice.sessionBuilder, alice.address, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("address-bound message"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes and decrypts with address binding.
	bobDeferred, err := bob.sessionBuilder.Process(preKeyMsg)
	if err != nil {
		t.Fatalf("Bob Process failed: %v", err)
	}
	if bobDeferred != nil {
		if err := bobDeferred.Complete(); err != nil {
			t.Fatal(err)
		}
	}

	// Bob encrypts a reply with address binding.
	bobCipher := session.NewCipherWithLocalAddress(bob.sessionBuilder, bob.address, alice.address)
	reply, err := bobCipher.Encrypt([]byte("reply with addresses"))
	if err != nil {
		t.Fatal(err)
	}
	replyBytes, err := reply.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	replySignal, err := protocol.NewSignalMessageFromBytes(replyBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Alice decrypts with address binding — exercises VerifyMacWithAddresses
	// at SessionCipher.go:578-582.
	aliceCipherDecrypt := session.NewCipherWithLocalAddress(alice.sessionBuilder, alice.address, bob.address)
	plaintext, _, err := aliceCipherDecrypt.DecryptAndGetKey(replySignal)
	if err != nil {
		t.Fatalf("Alice DecryptAndGetKey with address binding failed: %v", err)
	}
	if string(plaintext) != "reply with addresses" {
		t.Errorf("plaintext = %q, want %q", string(plaintext), "reply with addresses")
	}
}

// TestDecryptAndGetKey_WithAddressBinding_BadMAC verifies that
// VerifyMacWithAddresses returns an error when the address mismatch is detected.
// This exercises SessionCipher.go:582-585.
//
// Valid ServiceId (UUID) format addresses are used so that SerializeAddresses
// embeds address binding in the message. Alice decrypts using a wrong local
// address, causing a mismatch at VerifyMacWithAddresses.
func TestDecryptAndGetKey_WithAddressBinding_BadMAC(t *testing.T) {
	serializer := serialize.NewJSONSerializer()

	// Use valid ServiceId (UUID) format addresses so SerializeAddresses works.
	aliceAddr := protocol.NewSignalAddress("11111111-1111-1111-1111-111111111111", 1)
	bobAddr := protocol.NewSignalAddress("22222222-2222-2222-2222-222222222222", 2)
	charlieAddr := protocol.NewSignalAddress("33333333-3333-3333-3333-333333333333", 3)

	alice := newTestUser(t, aliceAddr.Name(), 1, serializer)
	bob := newTestUser(t, bobAddr.Name(), 2, serializer)

	// Build session builders: Alice targets Bob, Bob targets Alice.
	alice.buildSession(t, bobAddr, serializer)
	bob.buildSession(t, aliceAddr, serializer)

	// Establish session: Alice processes Bob's bundle.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	// Alice sends the first message to set up Bob's session state.
	aliceCipher := session.NewCipherWithLocalAddress(alice.sessionBuilder, aliceAddr, bobAddr)
	msg0, err := aliceCipher.Encrypt([]byte("setup"))
	if err != nil {
		t.Fatal(err)
	}
	msg0Bytes, err := msg0.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msg0Bytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes Alice's initial message.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	// Bob encrypts a reply with ServiceId address binding (bobAddr → aliceAddr).
	bobCipher := session.NewCipherWithLocalAddress(bob.sessionBuilder, bobAddr, aliceAddr)
	reply, err := bobCipher.Encrypt([]byte("bound reply"))
	if err != nil {
		t.Fatal(err)
	}
	replyBytes, err := reply.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	replySignal, err := protocol.NewSignalMessageFromBytes(replyBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Alice decrypts using charlieAddr as her local address — different from aliceAddr.
	// SerializeAddresses(charlieAddr, bobAddr) != message's (bobAddr, aliceAddr),
	// so VerifyMacWithAddresses detects the mismatch at SessionCipher.go:578-585.
	aliceCipherWrongLocal := session.NewCipherWithLocalAddress(alice.sessionBuilder, charlieAddr, bobAddr)
	_, _, err = aliceCipherWrongLocal.DecryptAndGetKey(replySignal)
	if err == nil {
		t.Fatal("expected address-mismatch error when decrypting with wrong local address")
	}
}
