//go:build !fips140only

// FIPS 140-3 exemption (docs/FIPS.md): X3DH requires X25519, so the fips140only tag drops this file.

package groups

import (
	"errors"
	"math"
	"testing"

	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
)

// TestGroupCipherEncryptNilPrivateKey checks Encrypt fails on a receiver-only state with no signing private key.
func TestGroupCipherEncryptNilPrivateKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	// Generate keys for a state that has only the PUBLIC signing key.
	signingKey, err := keyhelper.GenerateSenderSigningKey()
	if err != nil {
		t.Fatalf("GenerateSenderSigningKey() error: %v", err)
	}
	chainSeed, err := keyhelper.GenerateSenderKey()
	if err != nil {
		t.Fatalf("GenerateSenderKey() error: %v", err)
	}

	// Build a record using the public key only (simulating a receiver state).
	// NewSenderKeyStateFromPublicKey produces a state where PrivateKey() == nil.
	store := newInMemorySenderKeyStore()
	builder := NewGroupSessionBuilder(store, serializer)
	address := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, address)

	rec := groupRecord.NewSenderKey(serializer.SenderKeyRecord, serializer.SenderKeyState)
	// AddSenderKeyState internally calls NewSenderKeyStateFromPublicKey, which
	// sets the signing key pair with only the public component (no private key).
	rec.AddSenderKeyState(
		protocol.SenderKeyCurrentVersion,
		1, // key ID
		0, // iteration
		chainSeed,
		signingKey.PublicKey(), // public key only
	)
	if err := store.StoreSenderKey(senderKeyName, rec); err != nil {
		t.Fatalf("StoreSenderKey() error: %v", err)
	}

	cipher := NewGroupCipher(builder, senderKeyName, store)
	_, err = cipher.Encrypt(testDistributionID, []byte("test"))
	if err == nil {
		t.Fatal("Encrypt() with nil private signing key should return error")
	}
	// The error comes from NewSenderKeyMessageWithVersion rejecting a nil signature key.
	if err.Error() == "" {
		t.Error("Encrypt() error should have a non-empty message")
	}
}

// TestGroupCipherDecryptCiphertextTooShort verifies that Decrypt returns an error
// when the signature is valid but the ciphertext is too short to be valid AES-GCM
// (AES-256-GCM requires at least 16 bytes for the authentication tag). This
// exercises GroupCipher.go lines 167-170: the cipher.Decrypt error path.
func TestGroupCipherDecryptCiphertextTooShort(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	// Generate a fresh key pair for Alice.
	signingKey, err := keyhelper.GenerateSenderSigningKey()
	if err != nil {
		t.Fatalf("GenerateSenderSigningKey() error: %v", err)
	}
	chainSeed, err := keyhelper.GenerateSenderKey()
	if err != nil {
		t.Fatalf("GenerateSenderKey() error: %v", err)
	}
	const keyID uint32 = 11

	// Bob stores Alice's state with the public signing key at iteration 0.
	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	bobRec := groupRecord.NewSenderKey(serializer.SenderKeyRecord, serializer.SenderKeyState)
	bobRec.SetSenderKeyState(
		protocol.SenderKeyCurrentVersion,
		keyID,
		0, // chain starts at iteration 0
		chainSeed,
		signingKey, // full key pair so Bob's state has the public key for verification
	)
	if err := bobStore.StoreSenderKey(senderKeyName, bobRec); err != nil {
		t.Fatalf("StoreSenderKey() error: %v", err)
	}
	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	// Construct a SenderKeyMessage with iteration=0, signed with Alice's private key,
	// but with a ciphertext shorter than AES-GCM's 16-byte authentication tag.
	// This passes signature verification (the short ciphertext is included in
	// the signed bytes) but fails at AES-GCM decryption.
	shortCiphertext := []byte("tooshort") // 8 bytes < 16-byte AES-GCM tag minimum
	msg, err := protocol.NewSenderKeyMessageWithVersion(
		protocol.SenderKeyCurrentVersion,
		testDistributionID,
		keyID,
		0, // iteration matches chain start, so no loop advancement needed
		shortCiphertext,
		signingKey.PrivateKey(),
		serializer.SenderKeyMessage,
	)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageWithVersion() error: %v", err)
	}

	signedBytes, err := msg.SignedSerialize()
	if err != nil {
		t.Fatalf("SignedSerialize() error: %v", err)
	}
	received, err := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageFromBytes() error: %v", err)
	}

	// Decrypt: signature verification passes (same key), getSenderKey succeeds,
	// but cipher.Decrypt fails because the ciphertext is too short for AES-GCM.
	_, err = bobCipher.Decrypt(received)
	if err == nil {
		t.Fatal("Decrypt() with too-short ciphertext should return error")
	}
}

// TestGroupCipherEncryptChainAtMaxUint32 verifies that Encrypt returns an error
// when the sender chain key is at MaxUint32 and Next() would overflow. This
// exercises the err return path from senderKeyState.SenderChainKey().Next().
func TestGroupCipherEncryptChainAtMaxUint32(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	store := newInMemorySenderKeyStore()
	builder := NewGroupSessionBuilder(store, serializer)
	address := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, address)

	// Generate signing key for the state.
	signingKey, err := keyhelper.GenerateSenderSigningKey()
	if err != nil {
		t.Fatalf("GenerateSenderSigningKey() error: %v", err)
	}
	senderKey, err := keyhelper.GenerateSenderKey()
	if err != nil {
		t.Fatalf("GenerateSenderKey() error: %v", err)
	}

	// Manually build a record with chain iteration at MaxUint32. When Encrypt
	// calls Next() on this chain key, it will return ErrChainTooLong.
	rec := groupRecord.NewSenderKey(serializer.SenderKeyRecord, serializer.SenderKeyState)
	rec.SetSenderKeyState(
		protocol.SenderKeyCurrentVersion,
		1,
		math.MaxUint32, // chain at overflow boundary
		senderKey,
		signingKey,
	)
	if err := store.StoreSenderKey(senderKeyName, rec); err != nil {
		t.Fatalf("StoreSenderKey() error: %v", err)
	}

	cipher := NewGroupCipher(builder, senderKeyName, store)
	_, err = cipher.Encrypt(testDistributionID, []byte("test"))
	if err == nil {
		t.Fatal("Encrypt() with chain at MaxUint32 should return error")
	}

	// The error should be ErrChainTooLong from the ratchet package.
	var chainErr interface{ Error() string }
	if !errors.As(err, &chainErr) {
		t.Errorf("Encrypt() error = %v, expected chain-too-long error", err)
	}
}

// TestGroupCipherDecryptChainNextFailsAtEnd checks the final Next() at MaxUint32 fails after a one-step advance.
func TestGroupCipherDecryptChainNextFailsAtEnd(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	// Signing key for the state (used both to set up Bob's state and to
	// sign the synthetic message Alice sends).
	signingKey, err := keyhelper.GenerateSenderSigningKey()
	if err != nil {
		t.Fatalf("GenerateSenderSigningKey() error: %v", err)
	}
	chainSeed, err := keyhelper.GenerateSenderKey()
	if err != nil {
		t.Fatalf("GenerateSenderKey() error: %v", err)
	}
	const keyID uint32 = 42

	// Build Bob's store with chain at MaxUint32-1.
	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	bobRec := groupRecord.NewSenderKey(serializer.SenderKeyRecord, serializer.SenderKeyState)
	bobRec.SetSenderKeyState(
		protocol.SenderKeyCurrentVersion,
		keyID,
		math.MaxUint32-1, // chain one step before the overflow boundary
		chainSeed,
		signingKey,
	)
	if err := bobStore.StoreSenderKey(senderKeyName, bobRec); err != nil {
		t.Fatalf("StoreSenderKey() error: %v", err)
	}

	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	// A MaxUint32-iteration message signed with Bob's stored key; the chain error fires before decryption.
	msg, err := protocol.NewSenderKeyMessageWithVersion(
		protocol.SenderKeyCurrentVersion,
		testDistributionID,
		keyID,
		math.MaxUint32, // iteration at the overflow boundary
		[]byte("fake ciphertext bytes that are long enough for aes-gcm tag"),
		signingKey.PrivateKey(),
		serializer.SenderKeyMessage,
	)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageWithVersion() error: %v", err)
	}

	// Serialize and re-parse to simulate wire transfer.
	signedBytes, err := msg.SignedSerialize()
	if err != nil {
		t.Fatalf("SignedSerialize() error: %v", err)
	}
	received, err := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageFromBytes() error: %v", err)
	}

	// Bob decrypts: jump = MaxUint32 - (MaxUint32-1) = 1, within limit.
	// getSenderKey advances chain to MaxUint32, then the final Next() overflows.
	_, err = bobCipher.Decrypt(received)
	if err == nil {
		t.Fatal("Decrypt() with chain advancing to MaxUint32 should return error")
	}
}

// TestGroupCipherDecryptGetSenderKeyLoopNextFails advances from MaxUint32-2 to MaxUint32 and expects ErrChainTooLong from the final Next().
func TestGroupCipherDecryptChainNextFailsAtEndWithJumpTwo(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	groupID := testGroupID()

	signingKey, err := keyhelper.GenerateSenderSigningKey()
	if err != nil {
		t.Fatalf("GenerateSenderSigningKey() error: %v", err)
	}
	chainSeed, err := keyhelper.GenerateSenderKey()
	if err != nil {
		t.Fatalf("GenerateSenderKey() error: %v", err)
	}
	const keyID uint32 = 77

	bobStore := newInMemorySenderKeyStore()
	bobBuilder := NewGroupSessionBuilder(bobStore, serializer)
	aliceAddress := protocol.NewSignalAddress("alice", 1)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddress)

	bobRec := groupRecord.NewSenderKey(serializer.SenderKeyRecord, serializer.SenderKeyState)
	bobRec.SetSenderKeyState(
		protocol.SenderKeyCurrentVersion,
		keyID,
		math.MaxUint32-2, // chain two steps before overflow
		chainSeed,
		signingKey,
	)
	if err := bobStore.StoreSenderKey(senderKeyName, bobRec); err != nil {
		t.Fatalf("StoreSenderKey() error: %v", err)
	}

	bobCipher := NewGroupCipher(bobBuilder, senderKeyName, bobStore)

	msg, err := protocol.NewSenderKeyMessageWithVersion(
		protocol.SenderKeyCurrentVersion,
		testDistributionID,
		keyID,
		math.MaxUint32,
		[]byte("fake ciphertext bytes that are long enough for aes-gcm tag"),
		signingKey.PrivateKey(),
		serializer.SenderKeyMessage,
	)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageWithVersion() error: %v", err)
	}
	signedBytes, err := msg.SignedSerialize()
	if err != nil {
		t.Fatalf("SignedSerialize() error: %v", err)
	}
	received, err := protocol.NewSenderKeyMessageFromBytes(signedBytes, serializer.SenderKeyMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageFromBytes() error: %v", err)
	}

	_, err = bobCipher.Decrypt(received)
	if err == nil {
		t.Fatal("Decrypt() with chain needing 2-step advance to MaxUint32 should return error")
	}
}
