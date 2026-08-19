package tests

// session_extras_test.go extends session_test.go with additional scenarios
// ported from rust/protocol/tests/session.rs at commit 98915c442d.
//
// Scenarios already covered by session_test.go:
//   - TestSessionBuilder       → test_basic_prekey (session.rs:30)
//   - TestSessionRoundtrip     → run_session_interaction (session.rs:2576)
//   - TestSessionOutOfOrder    → out-of-order receive (session.rs context)
//
// New scenarios ported here:
//   - TestSession_BadSignedPreKeySignature → test_bad_signed_pre_key_signature (session.rs:399)
//   - TestSession_OptionalOneTimePrekey    → test_optional_one_time_prekey (session.rs:696)
//   - TestSession_ZeroPreKeyID            → test_zero_is_a_valid_prekey_id (session.rs:2005)
//   - TestSession_BadMessageBundle        → test_bad_message_bundle (session.rs:596)
//   - TestSession_DuplicateMessageRejected→ test_duplicate_message_error_returned (session.rs:3194)

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// TestSession_BadSignedPreKeySignature verifies that a PreKeyBundle with a
// corrupted signed-pre-key signature is rejected by ProcessBundle.
//
// Mirrors rust/protocol/tests/session.rs:399 (test_bad_signed_pre_key_signature).
// The Rust test tries all 512 single-bit flips in the signature; here we
// flip one bit (byte 0 MSB) and verify rejection, then confirm the good
// bundle is still accepted.
func TestSession_BadSignedPreKeySignature(t *testing.T) {
	serializer := newSerializer()
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	goodBundle := bob.kyberBundle()
	goodSig := goodBundle.SignedPreKeySignature()

	// Corrupt one bit of the signature.
	badSig := goodSig
	badSig[0] ^= 0x80

	badBundle := prekey.NewBundleWithKyber(
		goodBundle.RegistrationID(),
		goodBundle.DeviceID(),
		goodBundle.PreKeyID(),
		goodBundle.SignedPreKeyID(),
		goodBundle.PreKey(),
		goodBundle.SignedPreKey(),
		badSig,
		goodBundle.IdentityKey(),
		goodBundle.KyberPreKeyID(),
		goodBundle.KyberPreKey(),
		goodBundle.KyberPreKeySignature(),
	)

	// Bad signature must be rejected.
	if err := alice.sessionBuilder.ProcessBundle(badBundle); err == nil {
		t.Fatal("ProcessBundle accepted a bundle with a corrupted signed-pre-key signature; want error")
	}

	// Good bundle must still be accepted after the rejection.
	if err := alice.sessionBuilder.ProcessBundle(goodBundle); err != nil {
		t.Fatalf("ProcessBundle rejected good bundle after failed attempt: %v", err)
	}
}

// TestSession_OptionalOneTimePrekey verifies that a session can be established
// using a bundle that has no one-time PreKey (only signed PreKey + Kyber key).
//
// Mirrors rust/protocol/tests/session.rs:696 (test_optional_one_time_prekey).
func TestSession_OptionalOneTimePrekey(t *testing.T) {
	serializer := newSerializer()
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	// Build a bundle without a one-time PreKey (nil PreKeyID, nil PreKey).
	fullBundle := bob.kyberBundle()
	bundleNoOTP := prekey.NewBundleWithKyber(
		fullBundle.RegistrationID(),
		fullBundle.DeviceID(),
		nil, // no one-time prekey
		fullBundle.SignedPreKeyID(),
		nil, // no one-time prekey public
		fullBundle.SignedPreKey(),
		fullBundle.SignedPreKeySignature(),
		fullBundle.IdentityKey(),
		fullBundle.KyberPreKeyID(),
		fullBundle.KyberPreKey(),
		fullBundle.KyberPreKeySignature(),
	)

	if err := alice.sessionBuilder.ProcessBundle(bundleNoOTP); err != nil {
		t.Fatalf("ProcessBundle (no one-time prekey): %v", err)
	}

	// Alice can encrypt to Bob.
	aliceCipher := session.NewCipherWithLocalAddress(alice.sessionBuilder, alice.address, bob.address)
	plaintext := []byte("L'homme est condamné à être libre")
	encrypted, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Serialize and deserialize.
	encBytes, err := encrypted.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(encBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes: %v", err)
	}

	// Bob can decrypt.
	bobCipher := session.NewCipherWithLocalAddress(bob.sessionBuilder, bob.address, alice.address)
	decrypted, _, err := bobCipher.DecryptPreKeyMessage(bob.sessionBuilder, preKeyMsg)
	if err != nil {
		t.Fatalf("DecryptPreKeyMessage: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

// TestSession_ZeroPreKeyID verifies that a bundle with prekey ID 0 is valid
// and that a session can be established with it.
//
// Mirrors rust/protocol/tests/session.rs:2005 (test_zero_is_a_valid_prekey_id).
func TestSession_ZeroPreKeyID(t *testing.T) {
	serializer := newSerializer()
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	// Generate a fresh PreKey with ID = 0.
	zeroPreKeys, err := keyhelper.GeneratePreKeys(0, 1, serializer.PreKeyRecord)
	if err != nil {
		t.Fatalf("GeneratePreKeys: %v", err)
	}
	zeroPreKey := zeroPreKeys[0]

	// Store it in Bob's store.
	if err := bob.preKeyStore.StorePreKey(0, zeroPreKey); err != nil {
		t.Fatalf("setup: StorePreKey: %v", err)
	}

	zeroBundle := prekey.NewBundleWithKyber(
		bob.registrationID,
		bob.deviceID,
		&optional.Uint32{Value: 0},
		bob.signedPreKey.ID(),
		zeroPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		bob.kyberPreKey.PublicKey(),
		bob.kyberPreKey.Signature(),
	)

	if err := alice.sessionBuilder.ProcessBundle(zeroBundle); err != nil {
		t.Fatalf("ProcessBundle (prekey ID=0): %v", err)
	}

	aliceCipher := session.NewCipherWithLocalAddress(alice.sessionBuilder, alice.address, bob.address)
	plaintext := []byte("L'homme est condamné à être libre")
	encrypted, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	encBytes, err := encrypted.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(encBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes: %v", err)
	}

	bobCipher := session.NewCipherWithLocalAddress(bob.sessionBuilder, bob.address, alice.address)
	decrypted, _, err := bobCipher.DecryptPreKeyMessage(bob.sessionBuilder, preKeyMsg)
	if err != nil {
		t.Fatalf("DecryptPreKeyMessage: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

// TestSession_BadMessageBundle verifies that a corrupted ciphertext is rejected
// without consuming the prekey, and that the original valid ciphertext is still
// decryptable afterward.
//
// Mirrors rust/protocol/tests/session.rs:596 (test_bad_message_bundle).
func TestSession_BadMessageBundle(t *testing.T) {
	serializer := newSerializer()
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}

	aliceCipher := session.NewCipherWithLocalAddress(alice.sessionBuilder, alice.address, bob.address)
	plaintext := []byte("L'homme est condamné à être libre")
	encrypted, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	encBytes, err := encrypted.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Corrupt the message (flip a bit near the end).
	corrupted := make([]byte, len(encBytes))
	copy(corrupted, encBytes)
	if len(corrupted) >= 10 {
		corrupted[len(corrupted)-10] ^= 0x01
	}

	bobCipher := session.NewCipherWithLocalAddress(bob.sessionBuilder, bob.address, alice.address)

	// Try to parse and decrypt the corrupted bytes.
	// The parse may fail (invalid protobuf) or decrypt may fail (MAC error).
	corruptedMsg, parseErr := protocol.NewPreKeySignalMessageFromBytes(corrupted, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if parseErr == nil {
		// Parsed but should fail to decrypt.
		_, _, decErr := bobCipher.DecryptPreKeyMessage(bob.sessionBuilder, corruptedMsg)
		if decErr == nil {
			t.Fatal("DecryptPreKeyMessage succeeded on corrupted ciphertext; want error")
		}
	}
	// Either parse or decrypt failed — that's the expected outcome.

	// The valid ciphertext must still be decryptable.
	validMsg, err := protocol.NewPreKeySignalMessageFromBytes(encBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes (valid): %v", err)
	}
	decrypted, _, err := bobCipher.DecryptPreKeyMessage(bob.sessionBuilder, validMsg)
	if err != nil {
		t.Fatalf("DecryptPreKeyMessage (valid after corruption attempt): %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

// TestSession_DuplicateMessageRejected verifies that decrypting the same
// PreKeySignalMessage twice returns an error on the second attempt.
//
// Mirrors rust/protocol/tests/session.rs:3194 (test_duplicate_message_error_returned).
// In Rust, the duplicate check applies to any message type; here we exercise it
// via PreKeySignalMessage since Alice's first outbound message after ProcessBundle
// is always a PreKeySignalMessage (the session is unacknowledged).
func TestSession_DuplicateMessageRejected(t *testing.T) {
	serializer := newSerializer()
	alice := newUser("Alice", 1, serializer)
	bob := newUser("Bob", 2, serializer)
	alice.buildSession(bob.address, serializer)
	bob.buildSession(alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}

	aliceCipher := session.NewCipherWithLocalAddress(alice.sessionBuilder, alice.address, bob.address)
	bobCipher := session.NewCipherWithLocalAddress(bob.sessionBuilder, bob.address, alice.address)

	// Alice's first encrypt always wraps in a PreKeySignalMessage while the
	// session is unacknowledged (Bob hasn't replied yet).
	dupPlaintext := []byte("this_will_be_a_dup")
	dupEnc, err := aliceCipher.Encrypt(dupPlaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	dupBytes, err := dupEnc.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	dupMsg, err := protocol.NewPreKeySignalMessageFromBytes(dupBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes: %v", err)
	}

	// First decrypt: must succeed and establish Bob's session.
	plaintext1, _, err := bobCipher.DecryptPreKeyMessage(bob.sessionBuilder, dupMsg)
	if err != nil {
		t.Fatalf("DecryptPreKeyMessage (first): %v", err)
	}
	if string(plaintext1) != string(dupPlaintext) {
		t.Fatalf("first decrypt: got %q; want %q", plaintext1, dupPlaintext)
	}

	// Second decrypt of the same message: must fail (duplicate message).
	_, _, err = bobCipher.DecryptPreKeyMessage(bob.sessionBuilder, dupMsg)
	if err == nil {
		t.Fatal("DecryptPreKeyMessage (second time) succeeded; want error for duplicate message")
	}
	t.Logf("Duplicate message correctly rejected: %v", err)
}
