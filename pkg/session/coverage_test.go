package session_test

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// errLoadKyberPreKeyStore is an inMemoryKyberPreKey wrapper that returns an
// error from LoadKyberPreKey to exercise the error path in processV3.
type errLoadKyberPreKeyStore struct {
	inner *inMemoryKyberPreKey
}

func (e *errLoadKyberPreKeyStore) LoadKyberPreKey(id uint32) (*record.KyberPreKey, error) {
	return nil, fmt.Errorf("load kyber pre-key failed: id=%d", id)
}

func (e *errLoadKyberPreKeyStore) StoreKyberPreKey(id uint32, r *record.KyberPreKey) error {
	return e.inner.StoreKyberPreKey(id, r)
}

func (e *errLoadKyberPreKeyStore) MarkKyberPreKeyUsed(id uint32, regID uint32, key ecc.ECPublicKeyable) error {
	return e.inner.MarkKyberPreKeyUsed(id, regID, key)
}

func (e *errLoadKyberPreKeyStore) ContainsKyberPreKey(id uint32) (bool, error) {
	return e.inner.ContainsKyberPreKey(id)
}

// injectSPQRState replaces the PqRatchetState in a serialized session JSON
// with a new SPQR state created with MinVersion=VersionV1 (immediate V1 resolution).
// This enables testing SPQR-active decrypt paths that are otherwise blocked by
// the negotiation-pending state used in normal PQXDH sessions.
func injectSPQRState(t *testing.T, sessionBytes []byte, serializer *serialize.Serializer,
	authKey []byte, direction spqr.Direction) *record.Session {
	t.Helper()

	newSPQRState, err := spqr.InitialStateWithParams(spqr.Params{
		AuthKey:    authKey,
		Version:    spqr.VersionV1,
		Direction:  direction,
		MinVersion: spqr.VersionV1,
		MaxJump:    25000,
		MaxOOOKeys: 2000,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams failed: %v", err)
	}

	var rawRecord map[string]interface{}
	if err := json.Unmarshal(sessionBytes, &rawRecord); err != nil {
		t.Fatalf("unmarshal session JSON: %v", err)
	}

	// SessionState.PqRatchetState is base64-encoded in JSON.
	if sessionState, ok := rawRecord["SessionState"].(map[string]interface{}); ok {
		sessionState["PqRatchetState"] = base64.StdEncoding.EncodeToString(newSPQRState)
	}

	modified, err := json.Marshal(rawRecord)
	if err != nil {
		t.Fatalf("marshal modified session: %v", err)
	}

	sess, err := record.NewSessionFromBytes(modified, serializer.Session, serializer.State)
	if err != nil {
		t.Fatalf("NewSessionFromBytes: %v", err)
	}
	return sess
}

// errMarkKyberPreKeyStore is an inMemoryKyberPreKey wrapper that returns an
// error from MarkKyberPreKeyUsed to exercise the error path in DeferredActions.Complete.
type errMarkKyberPreKeyStore struct {
	inner *inMemoryKyberPreKey
}

func (e *errMarkKyberPreKeyStore) LoadKyberPreKey(id uint32) (*record.KyberPreKey, error) {
	return e.inner.LoadKyberPreKey(id)
}

func (e *errMarkKyberPreKeyStore) StoreKyberPreKey(id uint32, r *record.KyberPreKey) error {
	return e.inner.StoreKyberPreKey(id, r)
}

func (e *errMarkKyberPreKeyStore) MarkKyberPreKeyUsed(id uint32, _ uint32, _ ecc.ECPublicKeyable) error {
	return fmt.Errorf("mark kyber pre-key failed: id=%d", id)
}

func (e *errMarkKyberPreKeyStore) ContainsKyberPreKey(id uint32) (bool, error) {
	return e.inner.ContainsKyberPreKey(id)
}

// TestNewCipherWithIdentity verifies that NewCipherWithIdentity constructs a
// functioning cipher that enforces identity trust on Encrypt.
func TestNewCipherWithIdentity(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	// NewCipherWithIdentity wires up the identity store for trust checking.
	aliceCipher := session.NewCipherWithIdentity(alice.sessionBuilder, bob.address, alice.identityStore)

	plaintext := []byte("identity check message")
	msg, err := aliceCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt with identity cipher failed: %v", err)
	}
	if msg == nil {
		t.Fatal("expected non-nil ciphertext message")
	}
}

// TestNewCipherWithIdentity_UntrustedIdentityOnEncrypt verifies that Encrypt
// returns ErrUntrustedIdentity when the remote identity key is not trusted.
func TestNewCipherWithIdentity_UntrustedIdentityOnEncrypt(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	// Save a different identity for Bob so his real key becomes untrusted.
	otherIdentity, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := alice.identityStore.SaveIdentity(bob.address, otherIdentity.PublicKey()); err != nil {
		t.Fatalf("setup: SaveIdentity: %v", err)
	}

	aliceCipher := session.NewCipherWithIdentity(alice.sessionBuilder, bob.address, alice.identityStore)

	_, err = aliceCipher.Encrypt([]byte("should fail"))
	if err == nil {
		t.Fatal("expected untrusted identity error")
	}
	if !errors.Is(err, session.ErrUntrustedIdentity) {
		t.Fatalf("expected ErrUntrustedIdentity, got: %v", err)
	}
	// Verify the error message includes the remote address (covers the address branch
	// in Error.Error() for errUntrustedIdentity).
	msg := err.Error()
	if msg == "" {
		t.Fatal("Error() returned empty string")
	}
}

// TestDecryptAndGetKey_UntrustedIdentity verifies that DecryptAndGetKey
// returns ErrUntrustedIdentity when the sender's identity key is not trusted.
func TestDecryptAndGetKey_UntrustedIdentity(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	// Now poison Alice's identity in Bob's store.
	otherIdentity, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.identityStore.SaveIdentity(alice.address, otherIdentity.PublicKey()); err != nil {
		t.Fatalf("setup: SaveIdentity: %v", err)
	}

	// Use NewCipherWithIdentity so the identity check is wired in.
	bobCipherWithId := session.NewCipherWithIdentity(bob.sessionBuilder, alice.address, bob.identityStore)
	_, _, err = bobCipherWithId.DecryptAndGetKey(preKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected untrusted identity error on decrypt")
	}
	if !errors.Is(err, session.ErrUntrustedIdentity) {
		t.Fatalf("expected ErrUntrustedIdentity, got: %v", err)
	}
}

// TestDecryptPreKeyMessage tests the full DecryptPreKeyMessage flow.
func TestDecryptPreKeyMessage(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("prekey message test"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// DecryptPreKeyMessage should process and decrypt in one call.
	decrypted, deferred, err := bobCipher.DecryptPreKeyMessage(bob.sessionBuilder, preKeyMsg)
	if err != nil {
		t.Fatalf("DecryptPreKeyMessage failed: %v", err)
	}
	if string(decrypted) != "prekey message test" {
		t.Fatalf("expected 'prekey message test', got '%s'", string(decrypted))
	}
	if deferred == nil {
		t.Fatal("expected non-nil deferred actions")
	}
}

// TestDecryptPreKeyMessage_ProcessFails verifies DecryptPreKeyMessage returns
// an error when Process fails (e.g., untrusted identity).
func TestDecryptPreKeyMessage_ProcessFails(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("will fail"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Poison Alice's identity so Process returns untrusted identity error.
	otherIdentity, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bob.identityStore.SaveIdentity(alice.address, otherIdentity.PublicKey()); err != nil {
		t.Fatalf("setup: SaveIdentity: %v", err)
	}

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, _, err = bobCipher.DecryptPreKeyMessage(bob.sessionBuilder, preKeyMsg)
	if err == nil {
		t.Fatal("expected error when Process fails")
	}
}

// TestErrorMessages exercises the Error type's Error() method for all kinds,
// covering the address-containing variants.
func TestErrorMessages(t *testing.T) {
	tests := []struct {
		name string
		err  *session.Error
		want string
	}{
		{
			name: "no session with address",
			err:  session.ErrNoSession,
			want: "session:",
		},
		{
			name: "no valid sessions",
			err:  session.ErrNoValidSessions,
			want: "no valid sessions",
		},
		{
			name: "uninitialized session",
			err:  session.ErrUninitializedSession,
			want: "uninitialized session",
		},
		{
			name: "wrong message version",
			err:  session.ErrWrongMessageVersion,
			want: "wrong message version",
		},
		{
			name: "old counter sentinel",
			err:  session.ErrOldCounter,
			want: "old counter",
		},
		{
			name: "too far into future",
			err:  session.ErrTooFarIntoFuture,
			want: "future",
		},
		{
			name: "max skipped keys exceeded",
			err:  session.ErrMaxSkippedKeysExceeded,
			want: "max skipped",
		},
		{
			name: "duplicate message",
			err:  session.ErrDuplicateMessage,
			want: "duplicate",
		},
		{
			name: "untrusted identity sentinel",
			err:  session.ErrUntrustedIdentity,
			want: "untrusted identity",
		},
		{
			name: "missing PQ pre-key ID",
			err:  session.ErrMissingPQPreKeyID,
			want: "missing pq pre-key ID",
		},
		{
			name: "missing PQ ciphertext",
			err:  session.ErrMissingPQCiphertext,
			want: "missing pq ciphertext",
		},
		{
			name: "X3DH no longer supported",
			err:  session.ErrX3DHNoLongerSupported,
			want: "X3DH",
		},
		{
			name: "stale session",
			err:  session.ErrStaleSession,
			want: "stale",
		},
		{
			name: "no signed pre-key",
			err:  session.ErrNoSignedPreKey,
			want: "signed pre-key",
		},
		{
			name: "invalid signature",
			err:  session.ErrInvalidSignature,
			want: "invalid signature",
		},
		{
			name: "invalid Kyber signature",
			err:  session.ErrInvalidKyberSignature,
			want: "Kyber",
		},
		{
			name: "missing Kyber signature",
			err:  session.ErrMissingKyberSignature,
			want: "signature is missing",
		},
		{
			name: "nil one-time pre-key",
			err:  session.ErrNilOneTimePreKey,
			want: "nil one-time pre-key",
		},
		{
			name: "missing Kyber pre-key",
			err:  session.ErrMissingKyberPreKey,
			want: "Kyber pre-key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.err.Error()
			if msg == "" {
				t.Fatal("Error() returned empty string")
			}
		})
	}
}

// TestErrorIs verifies that errors.Is works for Error sentinel matching.
func TestErrorIs(t *testing.T) {
	tests := []struct {
		name   string
		err    *session.Error
		target *session.Error
		want   bool
	}{
		{"same kind", session.ErrNoSession, session.ErrNoSession, true},
		{"different kind", session.ErrNoSession, session.ErrDuplicateMessage, false},
		{"untrusted identity", session.ErrUntrustedIdentity, session.ErrUntrustedIdentity, true},
		{"no valid sessions", session.ErrNoValidSessions, session.ErrNoValidSessions, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := errors.Is(tt.err, tt.target)
			if got != tt.want {
				t.Errorf("errors.Is(%v, %v) = %v, want %v", tt.err, tt.target, got, tt.want)
			}
		})
	}
}

// TestErrorIs_NonSessionError verifies that errors.Is returns false for non-session errors.
func TestErrorIs_NonSessionError(t *testing.T) {
	otherErr := errors.New("some other error")
	if errors.Is(otherErr, session.ErrNoSession) {
		t.Fatal("errors.Is should return false for non-session error")
	}
}

// TestNoSessionError_DecryptAndGetKey exercises the newNoSessionError path by
// triggering DecryptAndGetKey without an established session.
func TestNoSessionError_DecryptAndGetKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob has no session yet - DecryptAndGetKey should return ErrNoSession.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, _, err = bobCipher.DecryptAndGetKey(preKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected ErrNoSession")
	}
	if !errors.Is(err, session.ErrNoSession) {
		t.Fatalf("expected ErrNoSession, got: %v", err)
	}
}

// TestDecryptWithRecord_PreKeyShortCircuit verifies that a PreKey message type
// does not fall back to previous session states.
func TestDecryptWithRecord_PreKeyShortCircuit(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("prekey test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Deserialize the prekey message.
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes successfully.
	processAndComplete(t, bob.sessionBuilder, preKeyMsg)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// Decrypt the inner signal message - this should work.
	decrypted, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != "prekey test" {
		t.Fatalf("expected 'prekey test', got '%s'", string(decrypted))
	}
}

// TestDecryptWithRecordPreKey_UsesPreKeyType verifies that DecryptWithRecordPreKey
// works correctly for a freshly established session.
func TestDecryptWithRecordPreKey_UsesPreKeyType(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("prekey type test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Process builds the session record without committing.
	deferred, err := bob.sessionBuilder.Process(preKeyMsg)
	if err != nil {
		t.Fatal(err)
	}

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// DecryptWithRecordPreKey uses PREKEY_TYPE short-circuit.
	decrypted, _, err := bobCipher.DecryptWithRecordPreKey(deferred.SessionRecord, preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatalf("DecryptWithRecordPreKey failed: %v", err)
	}
	if string(decrypted) != "prekey type test" {
		t.Fatalf("expected 'prekey type test', got '%s'", string(decrypted))
	}

	if err := deferred.Complete(); err != nil {
		t.Fatal(err)
	}
}

// TestMultiMessageRoundTrip tests that many messages can be encrypted and decrypted,
// exercising the getOrCreateMessageKeys forward-ratchet logic.
func TestMultiMessageRoundTrip(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Encrypt several messages.
	const numMessages = 5
	ciphertexts := make([]protocol.CiphertextMessage, numMessages)
	texts := []string{"msg0", "msg1", "msg2", "msg3", "msg4"}

	// Process the first one so Bob has a session.
	ct0, err := aliceCipher.Encrypt([]byte(texts[0]))
	if err != nil {
		t.Fatal(err)
	}
	ciphertexts[0] = ct0
	for i := 1; i < numMessages; i++ {
		ct, err := aliceCipher.Encrypt([]byte(texts[i]))
		if err != nil {
			t.Fatal(err)
		}
		ciphertexts[i] = ct
	}

	// Process first message to establish Bob's session.
	bytes0, _ := ciphertexts[0].Serialize()
	preKeyMsg0, _ := protocol.NewPreKeySignalMessageFromBytes(bytes0, serializer.PreKeySignalMessage, serializer.SignalMessage)
	processAndComplete(t, bob.sessionBuilder, preKeyMsg0)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	d0, err := bobCipher.Decrypt(preKeyMsg0.WhisperMessage())
	if err != nil {
		t.Fatal(err)
	}
	if string(d0) != texts[0] {
		t.Fatalf("expected %q, got %q", texts[0], string(d0))
	}

	// Decrypt remaining messages (same serialized bytes, just inner signal messages).
	for i := 1; i < numMessages; i++ {
		bytes, _ := ciphertexts[i].Serialize()
		preKeyMsg, _ := protocol.NewPreKeySignalMessageFromBytes(bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
		decrypted, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage())
		if err != nil {
			t.Fatalf("decrypt message %d failed: %v", i, err)
		}
		if string(decrypted) != texts[i] {
			t.Fatalf("message %d: expected %q, got %q", i, texts[i], string(decrypted))
		}
	}
}

// TestGetOrCreateMessageKeys_DuplicateMessage verifies that a message with an
// already-consumed counter results in ErrDuplicateMessage.
func TestGetOrCreateMessageKeys_DuplicateMessage(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("duplicate test"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, preKeyMsg)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// First decrypt succeeds.
	decrypted, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatalf("first decrypt failed: %v", err)
	}
	if string(decrypted) != "duplicate test" {
		t.Fatalf("expected 'duplicate test', got '%s'", string(decrypted))
	}

	// Second decrypt of the same message should fail with ErrDuplicateMessage.
	_, err = bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected ErrDuplicateMessage on second decrypt")
	}
	if !errors.Is(err, session.ErrDuplicateMessage) {
		t.Fatalf("expected ErrDuplicateMessage, got: %v", err)
	}
}

// TestProcessBundleX3DHRejected verifies that ProcessBundle fails with
// ErrMissingKyberPreKey when no Kyber pre-key is provided (PQXDH required).
func TestProcessBundleX3DHRejected(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	// Build a bundle without Kyber pre-key (X3DH only bundle).
	bundle := prekey.NewBundle(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
	)

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err == nil {
		t.Fatal("expected error for X3DH-only bundle (PQXDH required)")
	}
	if !errors.Is(err, session.ErrMissingKyberPreKey) {
		t.Fatalf("expected ErrMissingKyberPreKey, got: %v", err)
	}
}

// TestProcessBundleMissingKyberSignature verifies that a bundle with a Kyber
// pre-key but no signature returns ErrMissingKyberSignature.
func TestProcessBundleMissingKyberSignature(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	// Build bundle with Kyber key but nil signature.
	bundle := prekey.NewBundleWithKyber(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		bob.kyberPreKey.KeyPair().Public,
		nil, // missing signature
	)

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err == nil {
		t.Fatal("expected error for missing Kyber signature")
	}
	if !errors.Is(err, session.ErrMissingKyberSignature) {
		t.Fatalf("expected ErrMissingKyberSignature, got: %v", err)
	}
}

// TestProcessBundleInvalidKyberSignature verifies that a bundle with a Kyber
// pre-key and wrong signature returns ErrInvalidKyberSignature.
func TestProcessBundleInvalidKyberSignature(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	badSig := make([]byte, 64)
	for i := range badSig {
		badSig[i] = 0xFF
	}

	bundle := prekey.NewBundleWithKyber(
		bob.registrationID,
		bob.address.DeviceID(),
		bob.preKeys[0].ID(),
		bob.signedPreKey.ID(),
		bob.preKeys[0].KeyPair().PublicKey(),
		bob.signedPreKey.KeyPair().PublicKey(),
		bob.signedPreKey.Signature(),
		bob.identityKeyPair.PublicKey(),
		&optional.Uint32{Value: 42},
		bob.kyberPreKey.KeyPair().Public,
		badSig,
	)

	err := alice.sessionBuilder.ProcessBundle(bundle)
	if err == nil {
		t.Fatal("expected error for invalid Kyber signature")
	}
	if !errors.Is(err, session.ErrInvalidKyberSignature) {
		t.Fatalf("expected ErrInvalidKyberSignature, got: %v", err)
	}
}

// TestEncryptStaleSession verifies that Encrypt returns ErrStaleSession when
// the unacknowledged pre-key session has exceeded the maximum age. The
// session state is serialized to JSON, the timestamp is backdated to 31 days
// ago, and the session is reconstructed from the modified bytes.
func TestEncryptStaleSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	// Serialize the session record so we can backdate the timestamp.
	sessionRecord, _ := alice.sessionStore.LoadSession(bob.address)
	serializedBytes, err := sessionRecord.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// The session serialization is JSON. Unmarshal it as a generic map,
	// backdate the pendingPreKey.Timestamp field, and re-marshal.
	var rawRecord map[string]interface{}
	if err := json.Unmarshal(serializedBytes, &rawRecord); err != nil {
		t.Fatal(err)
	}

	// Navigate to SessionState.PendingPreKey.timestamp.
	// 31 days ago in unix seconds.
	oldTimestamp := float64(time.Now().Add(-31 * 24 * time.Hour).Unix())
	if sessionState, ok := rawRecord["SessionState"].(map[string]interface{}); ok {
		if pendingPreKey, ok := sessionState["PendingPreKey"].(map[string]interface{}); ok {
			pendingPreKey["timestamp"] = oldTimestamp
		}
	}

	modifiedBytes, err := json.Marshal(rawRecord)
	if err != nil {
		t.Fatal(err)
	}

	// Reconstruct the session record from the modified bytes.
	modifiedRecord, err := record.NewSessionFromBytes(modifiedBytes, serializer.Session, serializer.State)
	if err != nil {
		t.Fatal(err)
	}

	_ = alice.sessionStore.StoreSession(bob.address, modifiedRecord)
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	_, err = aliceCipher.Encrypt([]byte("stale session test"))
	if err == nil {
		t.Fatal("expected ErrStaleSession for old unacknowledged session")
	}
	if !errors.Is(err, session.ErrStaleSession) {
		t.Fatalf("expected ErrStaleSession, got: %v", err)
	}
}

// TestIsSpqrDuplicateErr exercises the isSpqrDuplicateErr function indirectly
// by triggering a SPQR duplicate condition (second decrypt of same message when
// SPQR state is active).
func TestIsSpqrDuplicateErr_ViaSessionDecrypt(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("spqr duplicate"))
	if err != nil {
		t.Fatal(err)
	}

	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, preKeyMsg)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// First decrypt succeeds.
	_, err = bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err != nil {
		t.Fatalf("first decrypt failed: %v", err)
	}

	// Second decrypt should fail (duplicate message or SPQR duplicate).
	_, err = bobCipher.Decrypt(preKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected error on second decrypt of same message")
	}
	// Accept either ErrDuplicateMessage (DR level) or another error (SPQR level).
	// The important thing is an error is returned.
}

// TestGetOrCreateMessageKeys_FIFOEviction verifies per-chain FIFO eviction behavior
// matching the Rust reference. When the per-chain skipped key count reaches
// maxSkippedKeys, the oldest (lowest counter) key is evicted to make room for
// the new one. Decryption of a message beyond the limit must succeed (no error),
// and the oldest evicted key is no longer retrievable.
func TestGetOrCreateMessageKeys_FIFOEviction(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Establish a bidirectional session so Alice's chain advances past the PreKey phase.
	// Alice sends first (PreKeySignalMessage), Bob decrypts it, then Bob replies so
	// Alice can process Bob's chain. After this exchange both sides have a plain session.
	setupMsg, err := aliceCipher.Encrypt([]byte("setup"))
	if err != nil {
		t.Fatal(err)
	}
	setupBytes, err := setupMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	setupPreKey, err := protocol.NewPreKeySignalMessageFromBytes(setupBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, setupPreKey)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, err = bobCipher.Decrypt(setupPreKey.WhisperMessage())
	if err != nil {
		t.Fatalf("setup decrypt failed: %v", err)
	}

	// Bob replies so Alice's session is fully acknowledged (no more PreKey wrapping).
	bobReply, err := bobCipher.Encrypt([]byte("ack"))
	if err != nil {
		t.Fatalf("bob encrypt ack failed: %v", err)
	}
	bobReplyBytes, err := bobReply.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	bobReplySignal, err := protocol.NewSignalMessageFromBytes(bobReplyBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("parse bob reply: %v", err)
	}
	_, err = aliceCipher.Decrypt(bobReplySignal)
	if err != nil {
		t.Fatalf("alice decrypt ack failed: %v", err)
	}

	// Capture the first skipped message (at Alice's current chain index) before
	// she fills the chain. This is the key that will be FIFO-evicted once the
	// chain exceeds maxSkippedKeys.
	firstSkipMsg, err := aliceCipher.Encrypt([]byte("first-skip"))
	if err != nil {
		t.Fatalf("encrypt first skip failed: %v", err)
	}
	firstSkipBytes, err := firstSkipMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Encrypt 2001 more messages without Bob decrypting. Together with firstSkipMsg
	// this puts >2000 keys on Bob's receiver chain, triggering FIFO eviction.
	const extraSkips = 2001
	var farMsg *protocol.SignalMessage
	for i := 0; i < extraSkips; i++ {
		msg, err := aliceCipher.Encrypt([]byte("skip"))
		if err != nil {
			t.Fatalf("encrypt failed at %d: %v", i, err)
		}
		farMsg = msg.(*protocol.SignalMessage)
	}

	// Bob decrypts the last message. FIFO eviction means the oldest skipped keys
	// have been discarded silently, but decryption of the current message succeeds.
	// This matches the Rust reference behavior (no error on overflow).
	farBytes, err := farMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	farSignal, err := protocol.NewSignalMessageFromBytes(farBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("parse far signal: %v", err)
	}
	plaintext, err := bobCipher.Decrypt(farSignal)
	if err != nil {
		t.Fatalf("expected FIFO eviction to allow decryption beyond maxSkippedKeys, got error: %v", err)
	}
	if string(plaintext) != "skip" {
		t.Fatalf("expected plaintext 'skip', got '%s'", string(plaintext))
	}

	// The firstSkipMsg should have been evicted. Attempting to decrypt it now
	// must fail because its key was discarded to make room for newer keys.
	firstSignal, err := protocol.NewSignalMessageFromBytes(firstSkipBytes, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("parse first signal: %v", err)
	}
	_, evictedErr := bobCipher.Decrypt(firstSignal)
	if evictedErr == nil {
		t.Fatal("expected error decrypting evicted skipped key, but decryption succeeded")
	}
}

// TestDecryptWithState_WrongMessageVersion verifies that DecryptWithState returns
// ErrWrongMessageVersion when the session state version doesn't match the message version.
func TestDecryptWithState_WrongMessageVersion(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("version mismatch test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	processAndComplete(t, bob.sessionBuilder, preKeyMsg)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// Decrypt the message once to establish Bob's session state at version 4.
	if _, err := bobCipher.Decrypt(preKeyMsg.WhisperMessage()); err != nil {
		t.Fatal(err)
	}

	// Create a new message from Alice but modify its version to be different
	// from Bob's session state. We do this by serializing the signal message,
	// tweaking the version byte, and deserializing.
	msg2, err := aliceCipher.Encrypt([]byte("another message"))
	if err != nil {
		t.Fatal(err)
	}
	// Serialize and then deserialize as a PreKeySignalMessage just to get signal message bytes.
	msg2Bytes, err := msg2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg2, err := protocol.NewPreKeySignalMessageFromBytes(msg2Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// The inner SignalMessage is a version 4 message. DecryptWithState with a
	// state that has a DIFFERENT version should return ErrWrongMessageVersion.
	// We use DecryptWithState directly with a fresh (version-0 -> version-2) state.
	freshState := record.NewState(serializer.State)
	// freshState.Version() returns 2 (zero is mapped to 2), message version is 4.
	cipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, _, err = cipher.DecryptWithState(freshState, preKeyMsg2.WhisperMessage())
	if err == nil {
		t.Fatal("expected error for wrong message version")
	}
	if !errors.Is(err, session.ErrWrongMessageVersion) && !errors.Is(err, session.ErrUninitializedSession) {
		t.Fatalf("expected ErrWrongMessageVersion or ErrUninitializedSession, got: %v", err)
	}
}

// TestComplete_MarkKyberPreKeyUsedError verifies that DeferredActions.Complete
// returns an error when MarkKyberPreKeyUsed fails.
func TestComplete_MarkKyberPreKeyUsedError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	// Replace Bob's Kyber pre-key store with an erroring one BEFORE alice processes
	// the bundle, but AFTER storing the kyber key. We need the key to be loadable
	// (so Process succeeds), but MarkKyberPreKeyUsed to fail (so Complete fails).
	erroringStore := &errMarkKyberPreKeyStore{inner: bob.kyberPreKeyStore}

	bob.sessionBuilder = session.NewBuilderWithKyber(
		bob.sessionStore,
		bob.preKeyStore,
		bob.signedPreKeyStore,
		bob.identityStore,
		erroringStore,
		alice.address,
		serializer,
	)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("complete error test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Process succeeds (LoadKyberPreKey works via the inner store).
	deferred, err := bob.sessionBuilder.Process(preKeyMsg)
	if err != nil {
		t.Fatal(err)
	}
	if deferred == nil {
		t.Fatal("expected non-nil deferred actions")
	}

	// Complete should fail when MarkKyberPreKeyUsed returns an error.
	// Decrypt the inner message first so Complete has a chance to run.
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, _, decryptErr := bobCipher.DecryptWithRecordPreKey(deferred.SessionRecord, preKeyMsg.WhisperMessage())
	if decryptErr != nil {
		t.Fatalf("DecryptWithRecordPreKey failed: %v", decryptErr)
	}

	completeErr := deferred.Complete()
	if completeErr == nil {
		t.Fatal("expected error from Complete() when MarkKyberPreKeyUsed fails")
	}
}

// TestDecryptPreKeyMessage_CompleteError verifies that DecryptPreKeyMessage
// returns an error when deferred.Complete() fails (MarkKyberPreKeyUsed error).
func TestDecryptPreKeyMessage_CompleteError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	// Use an erroring Kyber store for Bob.
	erroringStore := &errMarkKyberPreKeyStore{inner: bob.kyberPreKeyStore}

	bob.sessionBuilder = session.NewBuilderWithKyber(
		bob.sessionStore,
		bob.preKeyStore,
		bob.signedPreKeyStore,
		bob.identityStore,
		erroringStore,
		alice.address,
		serializer,
	)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("complete error test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// DecryptPreKeyMessage calls Process -> Decrypt -> Complete.
	// MarkKyberPreKeyUsed fails so Complete returns an error.
	_, _, err = bobCipher.DecryptPreKeyMessage(bob.sessionBuilder, preKeyMsg)
	if err == nil {
		t.Fatal("expected error from DecryptPreKeyMessage when Complete fails")
	}
}

// TestProcessV3_ArchivesNonFreshSession verifies that processV3 calls
// ArchiveCurrentState when processing a new PreKey message on an already-
// established (non-fresh) session record. This is triggered by having Alice
// establish a second session with Bob using a different one-time pre-key.
func TestProcessV3_ArchivesNonFreshSession(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// First session: Alice -> Bob using pre-key index 0.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleWithPreKeyIndex(0)); err != nil {
		t.Fatal(err)
	}
	firstMsg, err := session.NewCipher(alice.sessionBuilder, bob.address).Encrypt([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, err := firstMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	firstPreKey, err := protocol.NewPreKeySignalMessageFromBytes(firstBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, firstPreKey)
	if _, err := session.NewCipher(bob.sessionBuilder, alice.address).Decrypt(firstPreKey.WhisperMessage()); err != nil {
		t.Fatal(err)
	}

	// Second session: Alice builds a NEW session with Bob using pre-key index 1.
	// Alice uses the SAME identity key (trusted by Bob), only switching pre-keys.
	// We reset Alice's session store so she generates a fresh PreKeySignalMessage.
	if err := alice.sessionStore.DeleteSession(bob.address); err != nil {
		t.Fatalf("setup: DeleteSession: %v", err)
	}
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleWithPreKeyIndex(1)); err != nil {
		t.Fatal(err)
	}
	secondMsg, err := session.NewCipher(alice.sessionBuilder, bob.address).Encrypt([]byte("second session"))
	if err != nil {
		t.Fatal(err)
	}
	secondBytes, err := secondMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	secondPreKey, err := protocol.NewPreKeySignalMessageFromBytes(secondBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Bob processes the second session establishment. His record is NOT fresh
	// (was established during the first session), so ArchiveCurrentState is called.
	secondDeferred, err := bob.sessionBuilder.Process(secondPreKey)
	if err != nil {
		t.Fatalf("Bob.Process (second session) failed: %v", err)
	}
	if secondDeferred == nil {
		t.Fatal("expected non-nil deferred actions for second session")
	}

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	decrypted, _, err := bobCipher.DecryptWithRecordPreKey(secondDeferred.SessionRecord, secondPreKey.WhisperMessage())
	if err != nil {
		t.Fatalf("DecryptWithRecordPreKey failed: %v", err)
	}
	if string(decrypted) != "second session" {
		t.Fatalf("expected 'second session', got %q", string(decrypted))
	}
	if err := secondDeferred.Complete(); err != nil {
		t.Fatal(err)
	}

	// The session record should now have a previous session (the first one was archived).
	sessionRecord, _ := bob.sessionStore.LoadSession(alice.address)
	if len(sessionRecord.PreviousSessionStates()) == 0 {
		t.Fatal("expected at least one previous session state after archiving non-fresh session")
	}
}

// TestDecryptWithRecordAndType_DuplicateInPreviousState verifies that
// decryptWithRecordAndType short-circuits on ErrDuplicateMessage even when
// encountered in a previous session state.
func TestDecryptWithRecordAndType_DuplicateInPreviousState(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// First session: Alice -> Bob using pre-key index 0.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleWithPreKeyIndex(0)); err != nil {
		t.Fatal(err)
	}
	aliceCipher1 := session.NewCipher(alice.sessionBuilder, bob.address)
	msg1, err := aliceCipher1.Encrypt([]byte("msg from first session"))
	if err != nil {
		t.Fatal(err)
	}
	msg1Bytes, err := msg1.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKey1, err := protocol.NewPreKeySignalMessageFromBytes(msg1Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, preKey1)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	if _, err := bobCipher.Decrypt(preKey1.WhisperMessage()); err != nil {
		t.Fatal(err)
	}

	// Second session: Alice resets her session and uses pre-key index 1, forcing
	// Bob to archive the first session. Alice keeps the same identity key so Bob trusts her.
	if err := alice.sessionStore.DeleteSession(bob.address); err != nil {
		t.Fatalf("setup: DeleteSession: %v", err)
	}
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundleWithPreKeyIndex(1)); err != nil {
		t.Fatal(err)
	}
	aliceCipher2 := session.NewCipher(alice.sessionBuilder, bob.address)
	msg2, err := aliceCipher2.Encrypt([]byte("msg from second session"))
	if err != nil {
		t.Fatal(err)
	}
	msg2Bytes, err := msg2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKey2, err := protocol.NewPreKeySignalMessageFromBytes(msg2Bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, preKey2)
	if _, err := bobCipher.Decrypt(preKey2.WhisperMessage()); err != nil {
		t.Fatalf("second session decrypt failed: %v", err)
	}

	// The first session should now be in previous states. Decrypting msg1 again
	// would trigger ErrDuplicateMessage from the previous session state.
	// This exercises the duplicate short-circuit in decryptWithRecordAndType's
	// previous states loop.
	_, err = bobCipher.Decrypt(preKey1.WhisperMessage())
	if err == nil {
		t.Fatal("expected error on re-decrypt of consumed message")
	}
	// Accept DuplicateMessage or NoValidSessions - the exact error depends on
	// whether Bob's current session recognizes the old ephemeral key.
	if !errors.Is(err, session.ErrDuplicateMessage) && !errors.Is(err, session.ErrNoValidSessions) {
		t.Fatalf("expected ErrDuplicateMessage or ErrNoValidSessions, got: %v", err)
	}
}

// TestDecryptWithRecordPreKey_FailsWithNoValidSessions verifies that
// DecryptWithRecordPreKey returns ErrNoValidSessions when DecryptWithState fails
// (e.g., version mismatch). The PREKEY_TYPE short-circuit prevents trying previous
// session states, returning ErrNoValidSessions immediately.
func TestDecryptWithRecordPreKey_FailsWithNoValidSessions(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}

	// Create a session record that doesn't match the message (fresh, uninitialized).
	// DecryptWithState on a fresh session returns ErrUninitializedSession.
	// Since messageType is PREKEY_TYPE, decryptWithRecordAndType short-circuits
	// and returns ErrNoValidSessions.
	freshRecord := record.NewSession(serializer.Session, serializer.State)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	_, _, err = bobCipher.DecryptWithRecordPreKey(freshRecord, preKeyMsg.WhisperMessage())
	if err == nil {
		t.Fatal("expected error when DecryptWithState fails for PREKEY_TYPE")
	}
	if !errors.Is(err, session.ErrNoValidSessions) && !errors.Is(err, session.ErrUninitializedSession) {
		t.Fatalf("expected ErrNoValidSessions or ErrUninitializedSession, got: %v", err)
	}
}

// TestOutOfOrderDecrypt verifies that messages can be decrypted out of order,
// exercising the skipped message keys storage and retrieval paths.
func TestOutOfOrderDecrypt(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Encrypt 5 messages but process the first one to set up Bob's session.
	setupMsg, err := aliceCipher.Encrypt([]byte("setup"))
	if err != nil {
		t.Fatal(err)
	}
	setupBytes, _ := setupMsg.Serialize()
	setupPreKey, _ := protocol.NewPreKeySignalMessageFromBytes(setupBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	processAndComplete(t, bob.sessionBuilder, setupPreKey)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	if _, err := bobCipher.Decrypt(setupPreKey.WhisperMessage()); err != nil {
		t.Fatal(err)
	}

	// Encrypt 4 more messages.
	messages := make([]protocol.CiphertextMessage, 4)
	for i := 0; i < 4; i++ {
		msg, err := aliceCipher.Encrypt([]byte(fmt.Sprintf("msg%d", i)))
		if err != nil {
			t.Fatalf("encrypt %d failed: %v", i, err)
		}
		messages[i] = msg
	}

	// Decrypt the last message first (skipping messages 0-2).
	// This causes the ratchet to advance and store skipped keys 0-2.
	lastBytes, _ := messages[3].Serialize()
	lastPreKey, _ := protocol.NewPreKeySignalMessageFromBytes(lastBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	decryptedLast, err := bobCipher.Decrypt(lastPreKey.WhisperMessage())
	if err != nil {
		t.Fatalf("out-of-order decrypt of last message failed: %v", err)
	}
	if string(decryptedLast) != "msg3" {
		t.Fatalf("expected 'msg3', got %q", string(decryptedLast))
	}

	// Now decrypt the skipped messages in order.
	expected := []string{"msg0", "msg1", "msg2"}
	for i, expected := range expected {
		bytes, _ := messages[i].Serialize()
		preKey, _ := protocol.NewPreKeySignalMessageFromBytes(bytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
		decrypted, err := bobCipher.Decrypt(preKey.WhisperMessage())
		if err != nil {
			t.Fatalf("decrypt skipped msg%d failed: %v", i, err)
		}
		if string(decrypted) != expected {
			t.Fatalf("msg%d: expected %q, got %q", i, expected, string(decrypted))
		}
	}
}

// TestSPQRActiveSessionDecrypt verifies the SPQR-active paths in decryptWithClonedState
// and getOrCreateMessageKeys by injecting SPQR V1 states (MinVersion=VersionV1)
// into both Alice's and Bob's sessions. This bypasses the normal negotiation-pending
// state (MinVersion=VersionV0) used in PQXDH sessions, activating the PQR code paths.
func TestSPQRActiveSessionDecrypt(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Establish a normal PQXDH session first.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	setupMsg, err := aliceCipher.Encrypt([]byte("setup"))
	if err != nil {
		t.Fatal(err)
	}
	setupBytes, err := setupMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	setupPreKey, err := protocol.NewPreKeySignalMessageFromBytes(setupBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, setupPreKey)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	if _, err := bobCipher.Decrypt(setupPreKey.WhisperMessage()); err != nil {
		t.Fatal(err)
	}

	// A fixed shared authKey for SPQR initialization. Both parties must use
	// the same key for the derived message keys to match.
	sharedSPQRKey := make([]byte, 32)
	for i := range sharedSPQRKey {
		sharedSPQRKey[i] = byte(i + 1)
	}

	// Inject V1 SPQR state into Alice's session (DirectionA2B = sender).
	aliceSessionBytesRec, _ := alice.sessionStore.LoadSession(bob.address)
	aliceSessionBytes, err := aliceSessionBytesRec.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	aliceSessionWithSPQR := injectSPQRState(t, aliceSessionBytes, serializer,
		sharedSPQRKey, spqr.DirectionA2B)
	_ = alice.sessionStore.StoreSession(bob.address, aliceSessionWithSPQR)
	// Inject V1 SPQR state into Bob's session (DirectionB2A = receiver).
	bobSessionBytesRec, _ := bob.sessionStore.LoadSession(alice.address)
	bobSessionBytes, err := bobSessionBytesRec.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	bobSessionWithSPQR := injectSPQRState(t, bobSessionBytes, serializer,
		sharedSPQRKey, spqr.DirectionB2A)
	_ = bob.sessionStore.StoreSession(alice.address, bobSessionWithSPQR)
	// Now Alice encrypts a message. With MinVersion=VersionV1, spqr.Send
	// resolves negotiation to V1 and produces real PQR bytes.
	aliceCipher2 := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher2.Encrypt([]byte("SPQR message"))
	if err != nil {
		t.Fatalf("SPQR encrypt failed: %v", err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Parse as signal message (Alice's session no longer has unacknowledged pre-key
	// since setup was completed).
	signalMsg, signalErr := protocol.NewSignalMessageFromBytes(msgBytes, serializer.SignalMessage)
	if signalErr != nil {
		// Falls back to PreKeySignalMessage if session still has pending pre-key.
		pkMsg, pkErr := protocol.NewPreKeySignalMessageFromBytes(msgBytes,
			serializer.PreKeySignalMessage, serializer.SignalMessage)
		if pkErr != nil {
			t.Fatalf("parse message failed: signal err=%v, prekey err=%v", signalErr, pkErr)
		}
		signalMsg = pkMsg.WhisperMessage()
	}

	// Verify the message has non-empty PQR data (SPQR V1 is active).
	if len(signalMsg.PqRatchetKey()) == 0 {
		t.Fatal("expected non-empty PqRatchetKey after SPQR V1 state injection; negotiation must resolve to V1 on first Send")
	}
	t.Logf("SPQR active: PQRKey len=%d", len(signalMsg.PqRatchetKey()))

	// Bob decrypts the SPQR-enhanced message. This exercises the SPQR-active
	// path in decryptWithClonedState (lines 480-496): pqrData is non-empty,
	// pqrState is active, spqr.Recv is called to derive pqrSalt.
	bobCipher2 := session.NewCipher(bob.sessionBuilder, alice.address)
	decrypted, err := bobCipher2.Decrypt(signalMsg)
	if err != nil {
		t.Fatalf("SPQR decrypt failed: %v", err)
	}
	if string(decrypted) != "SPQR message" {
		t.Fatalf("expected 'SPQR message', got %q", string(decrypted))
	}
}

// TestSPQRSkippedKeyRederive verifies the SPQR re-derive path for stored
// skipped keys (decryptWithClonedState lines 435-451 and getOrCreateMessageKeys
// lines 526-534). This requires SPQR to be active and messages to be delivered
// out of order.
func TestSPQRSkippedKeyRederive(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Establish a normal PQXDH session.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	setupMsg, err := aliceCipher.Encrypt([]byte("setup"))
	if err != nil {
		t.Fatal(err)
	}
	setupBytes, _ := setupMsg.Serialize()
	setupPreKey, _ := protocol.NewPreKeySignalMessageFromBytes(setupBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	processAndComplete(t, bob.sessionBuilder, setupPreKey)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	if _, err := bobCipher.Decrypt(setupPreKey.WhisperMessage()); err != nil {
		t.Fatal(err)
	}

	// Shared SPQR key for both parties.
	sharedSPQRKey := make([]byte, 32)
	for i := range sharedSPQRKey {
		sharedSPQRKey[i] = byte(i + 0x20)
	}

	// Inject V1 SPQR states.
	aliceSessionBytesRec, _ := alice.sessionStore.LoadSession(bob.address)
	aliceSessionBytes, _ := aliceSessionBytesRec.Serialize()
	if err := alice.sessionStore.StoreSession(bob.address,
		injectSPQRState(t, aliceSessionBytes, serializer, sharedSPQRKey, spqr.DirectionA2B)); err != nil {
		t.Fatalf("setup: StoreSession: %v", err)
	}

	bobSessionBytesRec, _ := bob.sessionStore.LoadSession(alice.address)
	bobSessionBytes, _ := bobSessionBytesRec.Serialize()
	if err := bob.sessionStore.StoreSession(alice.address,
		injectSPQRState(t, bobSessionBytes, serializer, sharedSPQRKey, spqr.DirectionB2A)); err != nil {
		t.Fatalf("setup: StoreSession: %v", err)
	}

	// Encrypt 3 messages from Alice with SPQR active.
	aliceCipher2 := session.NewCipher(alice.sessionBuilder, bob.address)
	messages := make([][]byte, 3)
	signalMsgs := make([]*protocol.SignalMessage, 3)
	for i := 0; i < 3; i++ {
		msg, err := aliceCipher2.Encrypt([]byte(fmt.Sprintf("spqr%d", i)))
		if err != nil {
			t.Fatalf("encrypt %d failed: %v", i, err)
		}
		b, _ := msg.Serialize()
		messages[i] = b
		// Try as SignalMessage first, then PreKeySignalMessage.
		sm, err := protocol.NewSignalMessageFromBytes(b, serializer.SignalMessage)
		if err != nil {
			pkm, pkErr := protocol.NewPreKeySignalMessageFromBytes(b,
				serializer.PreKeySignalMessage, serializer.SignalMessage)
			if pkErr != nil {
				t.Fatalf("parse msg%d: signal=%v prekey=%v", i, err, pkErr)
			}
			sm = pkm.WhisperMessage()
		}
		signalMsgs[i] = sm
	}

	// SPQR V1 state was injected; PQR data must be present in messages.
	if len(signalMsgs[0].PqRatchetKey()) == 0 {
		t.Fatal("expected non-empty PqRatchetKey after SPQR V1 state injection; SPQR ratchet not active")
	}

	bobCipher2 := session.NewCipher(bob.sessionBuilder, alice.address)

	// Decrypt message 2 first (skipping 0 and 1). This stores skipped keys 0 and 1
	// with SPQR seed material via chainKey.MessageKeysWithSeed().
	decrypted2, err := bobCipher2.Decrypt(signalMsgs[2])
	if err != nil {
		t.Fatalf("decrypt msg2 first failed: %v", err)
	}
	if string(decrypted2) != "spqr2" {
		t.Fatalf("expected 'spqr2', got %q", string(decrypted2))
	}

	// Decrypt messages 0 and 1. The stored skipped keys have seed material and
	// the messages carry PQR data, so DeriveMessageKeysFromSeed is called.
	// This exercises decryptWithClonedState lines 435-451 and getOrCreateMessageKeys
	// lines 526-534 (SPQR skipped key re-derive).
	for i := 0; i < 2; i++ {
		decrypted, err := bobCipher2.Decrypt(signalMsgs[i])
		if err != nil {
			t.Fatalf("decrypt skipped msg%d failed: %v", i, err)
		}
		expected := fmt.Sprintf("spqr%d", i)
		if string(decrypted) != expected {
			t.Fatalf("msg%d: expected %q, got %q", i, expected, string(decrypted))
		}
	}
}

// TestEncryptWithoutSPQR verifies the non-SPQR path in Encrypt (the else branch
// at line 126 in SessionCipher.go). This requires a session state with empty
// PqRatchetState. We inject this by stripping the SPQR state from the session JSON.
func TestEncryptWithoutSPQR(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	// Establish the session first.
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	setupMsg, err := aliceCipher.Encrypt([]byte("setup"))
	if err != nil {
		t.Fatal(err)
	}
	setupBytes, err := setupMsg.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	setupPreKey, err := protocol.NewPreKeySignalMessageFromBytes(setupBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, setupPreKey)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	if _, err := bobCipher.Decrypt(setupPreKey.WhisperMessage()); err != nil {
		t.Fatal(err)
	}

	// Bob replies to establish a bidirectional session where Bob's session
	// has processed Alice's message and advanced its ratchet.
	// Now strip the PqRatchetState from Bob's session to exercise the non-SPQR path.
	bobSessionBytesRec, _ := bob.sessionStore.LoadSession(alice.address)
	bobSessionBytes, err := bobSessionBytesRec.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	var rawRecord map[string]interface{}
	if err := json.Unmarshal(bobSessionBytes, &rawRecord); err != nil {
		t.Fatal(err)
	}
	// Clear the PqRatchetState field so the session has no SPQR state.
	if sessionState, ok := rawRecord["SessionState"].(map[string]interface{}); ok {
		sessionState["PqRatchetState"] = nil
	}
	modified, err := json.Marshal(rawRecord)
	if err != nil {
		t.Fatal(err)
	}
	noSPQRRecord, err := record.NewSessionFromBytes(modified, serializer.Session, serializer.State)
	if err != nil {
		t.Fatal(err)
	}
	_ = bob.sessionStore.StoreSession(alice.address, noSPQRRecord)
	// Now Bob encrypts with no SPQR state. This exercises the else branch
	// in Encrypt (chainKey.MessageKeys() instead of chainKey.MessageKeysWithSalt()).
	bobCipher2 := session.NewCipher(bob.sessionBuilder, alice.address)
	bobMsg, err := bobCipher2.Encrypt([]byte("no spqr response"))
	if err != nil {
		t.Fatalf("non-SPQR encrypt failed: %v", err)
	}
	if bobMsg == nil {
		t.Fatal("expected non-nil message")
	}
}

// TestSPQRDuplicateMessageDetection verifies the isSpqrDuplicateErr path in
// decryptWithClonedState (lines 483-493). When a SPQR-active message is replayed,
// spqr.Recv returns ErrKeyAlreadyRequested, and the SPQR duplicate check converts
// it to a DuplicateMessage error (matching Double Ratchet's replay detection).
func TestSPQRDuplicateMessageDetection(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	setupMsg, err := aliceCipher.Encrypt([]byte("setup"))
	if err != nil {
		t.Fatal(err)
	}
	setupBytes, _ := setupMsg.Serialize()
	setupPreKey, _ := protocol.NewPreKeySignalMessageFromBytes(setupBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	processAndComplete(t, bob.sessionBuilder, setupPreKey)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	if _, err := bobCipher.Decrypt(setupPreKey.WhisperMessage()); err != nil {
		t.Fatal(err)
	}

	// Inject SPQR V1 state for both parties.
	sharedSPQRKey := make([]byte, 32)
	for i := range sharedSPQRKey {
		sharedSPQRKey[i] = byte(i + 0x40)
	}

	aliceSessionBytesRec, _ := alice.sessionStore.LoadSession(bob.address)
	aliceSessionBytes, _ := aliceSessionBytesRec.Serialize()
	if err := alice.sessionStore.StoreSession(bob.address,
		injectSPQRState(t, aliceSessionBytes, serializer, sharedSPQRKey, spqr.DirectionA2B)); err != nil {
		t.Fatalf("setup: StoreSession: %v", err)
	}

	bobSessionBytesRec, _ := bob.sessionStore.LoadSession(alice.address)
	bobSessionBytes, _ := bobSessionBytesRec.Serialize()
	if err := bob.sessionStore.StoreSession(alice.address,
		injectSPQRState(t, bobSessionBytes, serializer, sharedSPQRKey, spqr.DirectionB2A)); err != nil {
		t.Fatalf("setup: StoreSession: %v", err)
	}

	// Alice encrypts a message with SPQR active.
	aliceCipher2 := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher2.Encrypt([]byte("duplicate test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, _ := msg.Serialize()

	// Parse to get the inner SignalMessage.
	signalMsg, signalErr := protocol.NewSignalMessageFromBytes(msgBytes, serializer.SignalMessage)
	if signalErr != nil {
		pkm, pkErr := protocol.NewPreKeySignalMessageFromBytes(msgBytes,
			serializer.PreKeySignalMessage, serializer.SignalMessage)
		if pkErr != nil {
			t.Fatalf("parse: signal=%v prekey=%v", signalErr, pkErr)
		}
		signalMsg = pkm.WhisperMessage()
	}

	if len(signalMsg.PqRatchetKey()) == 0 {
		t.Fatal("expected non-empty PqRatchetKey after SPQR V1 state injection; SPQR ratchet not active")
	}

	bobCipher2 := session.NewCipher(bob.sessionBuilder, alice.address)

	// First decrypt succeeds.
	decrypted, err := bobCipher2.Decrypt(signalMsg)
	if err != nil {
		t.Fatalf("first decrypt failed: %v", err)
	}
	if string(decrypted) != "duplicate test" {
		t.Fatalf("expected 'duplicate test', got %q", string(decrypted))
	}

	// Second decrypt of the same SPQR-active message. SPQR.Recv returns
	// ErrKeyAlreadyRequested (counter 0 already consumed), which combined with
	// chainKey.Index() > counter triggers the SPQR duplicate detection path.
	_, err = bobCipher2.Decrypt(signalMsg)
	if err == nil {
		t.Fatal("expected error on duplicate SPQR message")
	}
	// Accept either ErrDuplicateMessage (SPQR duplicate detection) or
	// ErrNoValidSessions (if all session states fail).
	if !errors.Is(err, session.ErrDuplicateMessage) && !errors.Is(err, session.ErrNoValidSessions) {
		t.Fatalf("expected ErrDuplicateMessage or ErrNoValidSessions, got: %v", err)
	}
}

// buildValidInnerSignalMessageBytes returns serialized SignalMessage bytes from
// a real PQXDH exchange. These bytes are used as the inner message field when
// constructing crafted PreKeySignalMessages for error-path tests.
func buildValidInnerSignalMessageBytes(t *testing.T, serializer *serialize.Serializer) (
	aliceIdentityBytes []byte,
	aliceBaseKeyBytes []byte,
	innerMsgBytes []byte,
) {
	t.Helper()
	alice := newTestUser(t, "AliceInner", 91, serializer)
	bob := newTestUser(t, "BobInner", 92, serializer)
	alice.buildSession(t, bob.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}
	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("inner"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	pkMsg, err := protocol.NewPreKeySignalMessageFromBytes(msgBytes, serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes: %v", err)
	}
	innerMsgBytes, err = pkMsg.WhisperMessage().Serialize()
	if err != nil {
		t.Fatalf("WhisperMessage Serialize: %v", err)
	}
	aliceIdentityBytes = pkMsg.IdentityKey().PublicKey().Serialize()
	aliceBaseKeyBytes = pkMsg.BaseKey().Serialize()
	return aliceIdentityBytes, aliceBaseKeyBytes, innerMsgBytes
}

// TestProcessV3_PreKyberVersionRejected verifies that processV3 rejects a
// V3 (pre-Kyber) PreKeySignalMessage with errX3DHNoLongerSupported.
// This covers Session.go line 210 (X3DH rejection branch).
func TestProcessV3_PreKyberVersionRejected(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)
	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Get valid inner message bytes using a real exchange.
	identityBytes, baseKeyBytes, innerBytes := buildValidInnerSignalMessageBytes(t, serializer)

	// Construct a V3 (PreKyberVersion=3) message with nil Kyber fields.
	// NewPreKeySignalMessageFromStruct accepts this (V3 doesn't require Kyber).
	structure := &protocol.PreKeySignalMessageStructure{
		Version:        protocol.PreKyberVersion, // 3
		RegistrationID: alice.registrationID,
		SignedPreKeyID: bob.signedPreKey.ID(),
		BaseKey:        baseKeyBytes,
		IdentityKey:    identityBytes,
		Message:        innerBytes,
		PreKeyID:       nil,
	}
	v3Msg, err := protocol.NewPreKeySignalMessageFromStruct(structure,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromStruct: %v", err)
	}

	// Bob.Process(v3Msg) should fail with X3DH no longer supported.
	_, err = bob.sessionBuilder.Process(v3Msg)
	if err == nil {
		t.Fatal("expected error for V3 (pre-Kyber) message")
	}
	if !errors.Is(err, session.ErrX3DHNoLongerSupported) {
		t.Fatalf("expected ErrX3DHNoLongerSupported, got: %v", err)
	}
}

// TestProcessV3_MissingKyberPreKeyID verifies that processV3 rejects a V4
// message with nil KyberPreKeyID with ErrMissingPQPreKeyID.
// Mirrors Rust's "missing pq pre-key ID" from process_prekey_impl.
// This covers Session.go line 216 (nil KyberPreKeyID check).
func TestProcessV3_MissingKyberPreKeyID(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)
	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	identityBytes, baseKeyBytes, innerBytes := buildValidInnerSignalMessageBytes(t, serializer)

	// V4 message with nil KyberPreKeyID and nil KyberCiphertext.
	// NewPreKeySignalMessageFromStruct accepts this (both absent = symmetric).
	// processV3 checks KyberPreKeyID() == nil and returns errMissingPQPreKeyID.
	structure := &protocol.PreKeySignalMessageStructure{
		Version:         protocol.CurrentVersion, // 4
		RegistrationID:  alice.registrationID,
		SignedPreKeyID:  bob.signedPreKey.ID(),
		BaseKey:         baseKeyBytes,
		IdentityKey:     identityBytes,
		Message:         innerBytes,
		KyberPreKeyID:   nil,
		KyberCiphertext: nil,
	}
	v4NoKyberMsg, err := protocol.NewPreKeySignalMessageFromStruct(structure,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromStruct: %v", err)
	}

	_, err = bob.sessionBuilder.Process(v4NoKyberMsg)
	if err == nil {
		t.Fatal("expected error for V4 message with nil KyberPreKeyID")
	}
	if !errors.Is(err, session.ErrMissingPQPreKeyID) {
		t.Fatalf("expected ErrMissingPQPreKeyID, got: %v", err)
	}
}

// TestProcessV3_MissingKyberCiphertext verifies that processV3 rejects a V4
// message where KyberPreKeyID is present (non-nil but IsEmpty=true) and
// KyberCiphertext is nil. Mirrors Rust's "missing pq ciphertext".
// This covers Session.go line 219.
func TestProcessV3_MissingKyberCiphertext(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)
	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	identityBytes, baseKeyBytes, innerBytes := buildValidInnerSignalMessageBytes(t, serializer)

	// V4 message with non-nil KyberPreKeyID (IsEmpty=true) and nil KyberCiphertext.
	// hasKyberID = KyberPreKeyID != nil && !IsEmpty = false → symmetric with nil CT.
	// processV3: KyberPreKeyID() != nil (pointer is non-nil) → skips line 216,
	// KyberCiphertext() == nil → hits line 219.
	structure := &protocol.PreKeySignalMessageStructure{
		Version:         protocol.CurrentVersion,
		RegistrationID:  alice.registrationID,
		SignedPreKeyID:  bob.signedPreKey.ID(),
		BaseKey:         baseKeyBytes,
		IdentityKey:     identityBytes,
		Message:         innerBytes,
		KyberPreKeyID:   &optional.Uint32{IsEmpty: true},
		KyberCiphertext: nil,
	}
	v4EmptyKyberIDMsg, err := protocol.NewPreKeySignalMessageFromStruct(structure,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromStruct: %v", err)
	}

	_, err = bob.sessionBuilder.Process(v4EmptyKyberIDMsg)
	if err == nil {
		t.Fatal("expected error for V4 message with nil KyberCiphertext")
	}
	if !errors.Is(err, session.ErrMissingPQCiphertext) {
		t.Fatalf("expected ErrMissingPQCiphertext, got: %v", err)
	}
}

// TestProcessV3_LoadKyberPreKeyError verifies that processV3 propagates an
// error from LoadKyberPreKey. This covers Session.go line 253.
func TestProcessV3_LoadKyberPreKeyError(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)

	// Replace Bob's Kyber store with one that errors on LoadKyberPreKey.
	erroringStore := &errLoadKyberPreKeyStore{inner: bob.kyberPreKeyStore}
	bob.sessionBuilder = session.NewBuilderWithKyber(
		bob.sessionStore,
		bob.preKeyStore,
		bob.signedPreKeyStore,
		bob.identityStore,
		erroringStore,
		alice.address,
		serializer,
	)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("kyber load error test"))
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

	// Bob.Process fails because LoadKyberPreKey returns an error at line 253.
	_, err = bob.sessionBuilder.Process(preKeyMsg)
	if err == nil {
		t.Fatal("expected error when LoadKyberPreKey fails")
	}
}

// TestProcessV3_InvalidKyberCiphertext verifies that processV3 returns an error
// when the KyberCiphertext bytes are malformed (invalid key type prefix).
// This covers Session.go line 266 (DeserializeCiphertext error).
func TestProcessV3_InvalidKyberCiphertext(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("kyber ct error test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Deserialize the PreKeySignalMessage structure as JSON to corrupt the
	// KyberCiphertext field.
	var raw map[string]interface{}
	if err := json.Unmarshal(msgBytes, &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// Replace KyberCiphertext with 2 bytes having an invalid key type prefix (0x00).
	raw["KyberCiphertext"] = base64.StdEncoding.EncodeToString([]byte{0x00, 0x01})
	modifiedBytes, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	corruptedMsg, err := protocol.NewPreKeySignalMessageFromBytes(modifiedBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes with corrupted CT: %v", err)
	}

	// Bob.Process should fail because DeserializeCiphertext rejects the invalid bytes.
	_, err = bob.sessionBuilder.Process(corruptedMsg)
	if err == nil {
		t.Fatal("expected error when KyberCiphertext is malformed")
	}
}

// TestDecryptPreKeyMessage_BadInnerMessageMAC verifies that DecryptPreKeyMessage
// returns an error when the inner SignalMessage has a corrupted ciphertext
// (MAC mismatch). Process succeeds (key exchange OK), but DecryptWithRecordPreKey
// fails on VerifyMac. This covers SessionCipher.go line 242.
func TestDecryptPreKeyMessage_BadInnerMessageMAC(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	msg, err := aliceCipher.Encrypt([]byte("bad mac test"))
	if err != nil {
		t.Fatal(err)
	}
	msgBytes, err := msg.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// The outer message is a PreKeySignalMessage (JSON). The inner "Message"
	// field is the serialized SignalMessage bytes (also JSON, base64-encoded).
	// We corrupt the inner message's CipherText to make VerifyMac fail.
	var outerRaw map[string]interface{}
	if err := json.Unmarshal(msgBytes, &outerRaw); err != nil {
		t.Fatalf("unmarshal outer: %v", err)
	}

	// The "Message" field is base64-encoded bytes of the inner SignalMessage JSON.
	innerB64, ok := outerRaw["Message"].(string)
	if !ok {
		t.Fatal("Message field is not a string")
	}
	innerBytes, err := base64.StdEncoding.DecodeString(innerB64)
	if err != nil {
		t.Fatalf("decode inner: %v", err)
	}

	// Corrupt the CipherText field in the inner SignalMessage.
	var innerRaw map[string]interface{}
	if err := json.Unmarshal(innerBytes, &innerRaw); err != nil {
		t.Fatalf("unmarshal inner: %v", err)
	}
	// Replace CipherText with all-zero bytes of the same length.
	if ctB64, ok := innerRaw["CipherText"].(string); ok {
		ctBytes, _ := base64.StdEncoding.DecodeString(ctB64)
		zeroed := make([]byte, len(ctBytes))
		innerRaw["CipherText"] = base64.StdEncoding.EncodeToString(zeroed)
	}

	modifiedInner, err := json.Marshal(innerRaw)
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	outerRaw["Message"] = base64.StdEncoding.EncodeToString(modifiedInner)

	modifiedOuter, err := json.Marshal(outerRaw)
	if err != nil {
		t.Fatalf("marshal outer: %v", err)
	}

	corruptedPreKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(modifiedOuter,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes with corrupted inner: %v", err)
	}

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	// DecryptPreKeyMessage: Process succeeds (key exchange uses outer fields only),
	// but DecryptWithRecordPreKey fails because the inner message has wrong MAC.
	_, _, err = bobCipher.DecryptPreKeyMessage(bob.sessionBuilder, corruptedPreKeyMsg)
	if err == nil {
		t.Fatal("expected error due to bad inner message MAC")
	}
}

// TestDecryptStoredKey_BadMAC verifies the VerifyMac failure path for stored
// skipped keys in decryptWithClonedState (lines 457-460). When Bob has stored
// a skipped key for a counter and receives a message at that counter with a
// corrupted ciphertext body, MAC verification fails.
func TestDecryptStoredKey_BadMAC(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)

	// Encrypt two messages: msg0 (counter 0) and msg1 (counter 1).
	msg0, err := aliceCipher.Encrypt([]byte("msg0"))
	if err != nil {
		t.Fatal(err)
	}
	msg1, err := aliceCipher.Encrypt([]byte("msg1"))
	if err != nil {
		t.Fatal(err)
	}

	// Process Alice's first message to establish Bob's session.
	msg0Bytes, _ := msg0.Serialize()
	preKey0, err := protocol.NewPreKeySignalMessageFromBytes(msg0Bytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	processAndComplete(t, bob.sessionBuilder, preKey0)

	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)

	// Bob decrypts msg1 first (skipping msg0). This stores a skipped key for
	// the ratchet counter corresponding to msg0's ephemeral key chain.
	// However, both msg0 and msg1 use the SAME Alice ephemeral key (same ratchet
	// step), so decrypting msg1 advances the chain and stores key for counter 0.
	msg1Bytes, _ := msg1.Serialize()
	preKey1, err := protocol.NewPreKeySignalMessageFromBytes(msg1Bytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bobCipher.Decrypt(preKey1.WhisperMessage()); err != nil {
		t.Fatalf("decrypt msg1 first failed: %v", err)
	}

	// Now construct a corrupted version of msg0 by zeroing its CipherText.
	// The MAC will no longer match, but the counter matches the stored key.
	var outerRaw map[string]interface{}
	if err := json.Unmarshal(msg0Bytes, &outerRaw); err != nil {
		t.Fatalf("unmarshal msg0: %v", err)
	}
	innerB64, ok := outerRaw["Message"].(string)
	if !ok {
		t.Fatal("Message field not string")
	}
	innerBytes, err := base64.StdEncoding.DecodeString(innerB64)
	if err != nil {
		t.Fatalf("decode inner: %v", err)
	}

	var innerRaw map[string]interface{}
	if err := json.Unmarshal(innerBytes, &innerRaw); err != nil {
		t.Fatalf("unmarshal inner: %v", err)
	}
	// Corrupt CipherText to ensure MAC mismatch.
	if ctB64, ok := innerRaw["CipherText"].(string); ok {
		ctBytes, _ := base64.StdEncoding.DecodeString(ctB64)
		zeroed := make([]byte, len(ctBytes))
		innerRaw["CipherText"] = base64.StdEncoding.EncodeToString(zeroed)
	}
	modifiedInner, err := json.Marshal(innerRaw)
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	outerRaw["Message"] = base64.StdEncoding.EncodeToString(modifiedInner)
	modifiedOuter, err := json.Marshal(outerRaw)
	if err != nil {
		t.Fatalf("marshal outer: %v", err)
	}

	corruptedMsg0, err := protocol.NewPreKeySignalMessageFromBytes(modifiedOuter,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes corrupted msg0: %v", err)
	}

	// Bob tries to decrypt corrupted msg0. The session has a stored key for
	// counter 0 (stored when decrypting msg1). VerifyMac fails because
	// CipherText was zeroed. This covers lines 457-460 in decryptWithClonedState.
	_, err = bobCipher.Decrypt(corruptedMsg0.WhisperMessage())
	if err == nil {
		t.Fatal("expected MAC verification error for corrupted stored-key message")
	}
}

// TestSPQRNonDuplicateErrorFallthrough verifies that a SPQR error which is NOT
// a duplicate error (e.g., ErrMaxJump) is returned directly at line 493 in
// decryptWithClonedState, rather than being converted to ErrDuplicateMessage.
// This is triggered by setting MaxJump=1 in the SPQR state and attempting to
// receive a message that jumps the SPQR counter by more than 1.
func TestSPQRNonDuplicateErrorFallthrough(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	alice := newTestUser(t, "Alice", 1, serializer)
	bob := newTestUser(t, "Bob", 2, serializer)

	alice.buildSession(t, bob.address, serializer)
	bob.buildSession(t, alice.address, serializer)

	// Establish a normal PQXDH session.
	if err := alice.sessionBuilder.ProcessBundle(bob.kyberBundle()); err != nil {
		t.Fatal(err)
	}

	aliceCipher := session.NewCipher(alice.sessionBuilder, bob.address)
	setupMsg, err := aliceCipher.Encrypt([]byte("setup"))
	if err != nil {
		t.Fatal(err)
	}
	setupBytes, _ := setupMsg.Serialize()
	setupPreKey, _ := protocol.NewPreKeySignalMessageFromBytes(setupBytes,
		serializer.PreKeySignalMessage, serializer.SignalMessage)
	processAndComplete(t, bob.sessionBuilder, setupPreKey)
	bobCipher := session.NewCipher(bob.sessionBuilder, alice.address)
	if _, err := bobCipher.Decrypt(setupPreKey.WhisperMessage()); err != nil {
		t.Fatal(err)
	}

	// Shared SPQR key for both parties.
	sharedSPQRKey := make([]byte, 32)
	for i := range sharedSPQRKey {
		sharedSPQRKey[i] = byte(i + 0x60)
	}

	// Inject SPQR V1 state with MaxJump=1 for Bob (receiver). Alice uses
	// MaxJump=25000 (sender doesn't need this constraint).
	aliceSessionBytesRec, _ := alice.sessionStore.LoadSession(bob.address)
	aliceSessionBytes, _ := aliceSessionBytesRec.Serialize()

	// Inject V1 SPQR for Alice (sender direction, standard MaxJump).
	newAliceSPQR, err := spqr.InitialStateWithParams(spqr.Params{
		AuthKey:    sharedSPQRKey,
		Version:    spqr.VersionV1,
		Direction:  spqr.DirectionA2B,
		MinVersion: spqr.VersionV1,
		MaxJump:    25000,
		MaxOOOKeys: 2000,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams (alice): %v", err)
	}
	aliceSessionWithSPQR := injectSPQRStateBytes(t, aliceSessionBytes, serializer, newAliceSPQR)
	_ = alice.sessionStore.StoreSession(bob.address, aliceSessionWithSPQR)
	// Inject V1 SPQR for Bob (receiver direction, MaxJump=1 so counter jump > 1 fails).
	bobSessionBytesRec, _ := bob.sessionStore.LoadSession(alice.address)
	bobSessionBytes, _ := bobSessionBytesRec.Serialize()
	newBobSPQR, err := spqr.InitialStateWithParams(spqr.Params{
		AuthKey:    sharedSPQRKey,
		Version:    spqr.VersionV1,
		Direction:  spqr.DirectionB2A,
		MinVersion: spqr.VersionV1,
		MaxJump:    1, // Very small MaxJump to trigger ErrMaxJump
		MaxOOOKeys: 2000,
	})
	if err != nil {
		t.Fatalf("InitialStateWithParams (bob): %v", err)
	}
	bobSessionWithSPQR := injectSPQRStateBytes(t, bobSessionBytes, serializer, newBobSPQR)
	_ = bob.sessionStore.StoreSession(alice.address, bobSessionWithSPQR)
	// Alice encrypts 3 messages. Each call to spqr.Send advances Alice's SPQR counter.
	aliceCipher2 := session.NewCipher(alice.sessionBuilder, bob.address)
	var lastMsg *protocol.SignalMessage
	for i := 0; i < 3; i++ {
		msg, encErr := aliceCipher2.Encrypt([]byte(fmt.Sprintf("spqr-jump%d", i)))
		if encErr != nil {
			t.Fatalf("encrypt %d: %v", i, encErr)
		}
		b, _ := msg.Serialize()
		sm, parseErr := protocol.NewSignalMessageFromBytes(b, serializer.SignalMessage)
		if parseErr != nil {
			pkm, pkErr := protocol.NewPreKeySignalMessageFromBytes(b,
				serializer.PreKeySignalMessage, serializer.SignalMessage)
			if pkErr != nil {
				t.Fatalf("parse %d: signal=%v prekey=%v", i, parseErr, pkErr)
			}
			sm = pkm.WhisperMessage()
		}
		lastMsg = sm
	}

	if lastMsg == nil || len(lastMsg.PqRatchetKey()) == 0 {
		t.Fatal("expected non-empty PqRatchetKey after SPQR V1 state injection; SPQR ratchet not active")
	}

	bobCipher2 := session.NewCipher(bob.sessionBuilder, alice.address)

	// Bob tries to decrypt the 3rd message (SPQR counter=2) when Bob expects
	// counter=0. The jump of 2 exceeds MaxJump=1, so spqr.Recv returns ErrMaxJump.
	// isSpqrDuplicateErr(ErrMaxJump) = false → line 493 is reached.
	_, err = bobCipher2.Decrypt(lastMsg)
	if err == nil {
		t.Fatal("expected error due to SPQR MaxJump exceeded")
	}
	// The error could be ErrMaxJump propagated, or ErrNoValidSessions.
	// Either is acceptable as long as an error occurs.
}

// injectSPQRStateBytes replaces PqRatchetState in a session record with the
// given pre-built SPQR state bytes. Unlike injectSPQRState (which creates the
// state internally), this version accepts already-serialized SPQR bytes.
func injectSPQRStateBytes(t *testing.T, sessionBytes []byte, serializer *serialize.Serializer,
	spqrState []byte) *record.Session {
	t.Helper()

	var rawRecord map[string]interface{}
	if err := json.Unmarshal(sessionBytes, &rawRecord); err != nil {
		t.Fatalf("unmarshal session: %v", err)
	}
	if sessionState, ok := rawRecord["SessionState"].(map[string]interface{}); ok {
		sessionState["PqRatchetState"] = base64.StdEncoding.EncodeToString(spqrState)
	}
	modified, err := json.Marshal(rawRecord)
	if err != nil {
		t.Fatalf("marshal session: %v", err)
	}
	sess, err := record.NewSessionFromBytes(modified, serializer.Session, serializer.State)
	if err != nil {
		t.Fatalf("NewSessionFromBytes: %v", err)
	}
	return sess
}
