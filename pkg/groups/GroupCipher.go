package groups

import (
	"encoding/hex"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

// maxForwardJumps limits the forward jump in sender key iteration.
// Unlike the 1:1 session cipher which pre-checks total skipped keys,
// the group cipher iterates up to maxForwardJumps HMAC derivations per
// message. This matches the Rust reference (group_cipher.rs) where
// MAX_FORWARD_JUMPS is the only limit. The per-add eviction in
// AddSenderMessageKey caps stored keys at maxMessageKeys=2000.
const maxForwardJumps = 25000

// NewGroupCipher will return a new group message cipher that can be used for
// encrypt/decrypt operations.
func NewGroupCipher(builder *SessionBuilder, senderKeyID *protocol.SenderKeyName,
	senderKeyStore store.SenderKey) *GroupCipher {

	return &GroupCipher{
		senderKeyID:    senderKeyID,
		senderKeyStore: senderKeyStore,
		sessionBuilder: builder,
	}
}

// GroupCipher is the main entry point for group encrypt/decrypt operations.
// Once a session has been established, this can be used for
// all encrypt/decrypt operations within that session.
type GroupCipher struct {
	senderKeyID    *protocol.SenderKeyName
	senderKeyStore store.SenderKey
	sessionBuilder *SessionBuilder
}

// Encrypt will take the given message in bytes and return encrypted bytes.
// The distributionID identifies the SenderKey distribution for routing.
func (c *GroupCipher) Encrypt(distributionID [16]byte, plaintext []byte) (protocol.CiphertextMessage, error) {
	if c.senderKeyStore == nil {
		return nil, ErrNilSenderKeyStore
	}

	// Load the sender key based on id from our store.
	keyRecord, err := c.senderKeyStore.LoadSenderKey(c.senderKeyID)
	if err != nil {
		return nil, err
	}
	if keyRecord == nil {
		return nil, ErrNilSenderKeyRecord
	}

	senderKeyState, err := keyRecord.SenderKeyState()
	if err != nil {
		return nil, err
	}
	if senderKeyState == nil {
		return nil, ErrNilSenderKeyState
	}

	// Get the message key from the senderkey state.
	chainKey := senderKeyState.SenderChainKey()
	if chainKey == nil {
		return nil, ErrInvalidSenderKeySession
	}
	senderKey, err := chainKey.SenderMessageKey()
	if err != nil {
		return nil, err
	}

	// Encrypt the plaintext.
	ciphertext, err := cipher.Encrypt(senderKey.Iv(), senderKey.CipherKey(), plaintext)
	if err != nil {
		return nil, err
	}

	senderKeyMessage, err := protocol.NewSenderKeyMessageWithVersion(
		senderKeyState.MessageVersion(),
		distributionID,
		senderKeyState.KeyID(),
		senderKey.Iteration(),
		ciphertext,
		senderKeyState.SigningKey().PrivateKey(),
		c.sessionBuilder.serializer.SenderKeyMessage,
	)
	if err != nil {
		return nil, err
	}

	nextChainKey, err := senderKeyState.SenderChainKey().Next()
	if err != nil {
		return nil, err
	}
	senderKeyState.SetSenderChainKey(nextChainKey)
	if err := c.senderKeyStore.StoreSenderKey(c.senderKeyID, keyRecord); err != nil {
		return nil, err
	}

	return senderKeyMessage, nil
}

// Decrypt decrypts the given message using an existing session that
// is stored in the senderKey store. The distribution ID embedded in the
// incoming SenderKeyMessage is used for the store lookup, matching the
// Rust reference implementation (group_decrypt).
func (c *GroupCipher) Decrypt(senderKeyMessage *protocol.SenderKeyMessage) ([]byte, error) {
	if c.senderKeyStore == nil {
		return nil, ErrNilSenderKeyStore
	}

	// Derive the store lookup key from the message's distribution ID,
	// matching the Rust reference which uses skm.distribution_id() for
	// load_sender_key rather than an externally-provided identifier.
	distributionID := senderKeyMessage.DistributionID()
	groupID := distributionIDToGroupID(distributionID)
	lookupName := protocol.NewSenderKeyName(groupID, c.senderKeyID.Sender())

	keyRecord, err := c.senderKeyStore.LoadSenderKey(lookupName)
	if err != nil {
		return nil, err
	}
	if keyRecord == nil {
		return nil, ErrNilSenderKeyRecord
	}

	if keyRecord.IsEmpty() {
		return nil, newNoSenderKeyError(groupID)
	}

	// Get the senderkey state by chain id.
	senderKeyState, err := keyRecord.GetSenderKeyStateByID(senderKeyMessage.KeyID())
	if err != nil {
		return nil, err
	}
	if senderKeyState == nil {
		return nil, ErrNilSenderKeyState
	}

	// Validate message version matches the state's version, matching
	// the Rust reference group_decrypt check.
	messageVersion := senderKeyMessage.Version()
	if messageVersion != senderKeyState.MessageVersion() {
		return nil, newUnrecognizedMessageVersionError(messageVersion)
	}

	// Verify the signature of the senderkey message.
	verified, err := c.verifySignature(senderKeyState.SigningKey().PublicKey(), senderKeyMessage)
	if err != nil {
		return nil, err
	}
	if !verified {
		return nil, &Error{kind: errSignatureVerification}
	}

	senderKey, err := c.getSenderKey(senderKeyState, senderKeyMessage.Iteration())
	if err != nil {
		return nil, err
	}

	// Decrypt the message ciphertext.
	plaintext, err := cipher.Decrypt(senderKey.Iv(), senderKey.CipherKey(), senderKeyMessage.Ciphertext())
	if err != nil {
		return nil, err
	}

	// Store the sender key using the message's distribution ID.
	if err := c.senderKeyStore.StoreSenderKey(lookupName, keyRecord); err != nil {
		return nil, err
	}

	return plaintext, nil
}

// verifySignature will verify the signature of the senderkey message with
// the given public key.
func (c *GroupCipher) verifySignature(signingPubKey ecc.ECPublicKeyable,
	senderKeyMessage *protocol.SenderKeyMessage) (bool, error) {

	serialized, err := senderKeyMessage.Serialize()
	if err != nil {
		return false, err
	}
	return ecc.VerifySignature(signingPubKey, serialized, senderKeyMessage.Signature()), nil
}

func (c *GroupCipher) getSenderKey(senderKeyState *record.SenderKeyState, iteration uint32) (*ratchet.SenderMessageKey, error) {
	senderChainKey := senderKeyState.SenderChainKey()
	if senderChainKey.Iteration() > iteration {
		if senderKeyState.HasSenderMessageKey(iteration) {
			return senderKeyState.RemoveSenderMessageKey(iteration), nil
		}
		return nil, newOldCounterError(senderChainKey.Iteration(), iteration)
	}

	// Guard against uint32 underflow: if iteration < chainIteration the
	// subtraction wraps, producing a very large value that exceeds the limit.
	// The earlier branch (chainIteration > iteration) should catch this, but
	// we defend against it explicitly for safety.
	jump := iteration - senderChainKey.Iteration()
	if jump > maxForwardJumps {
		return nil, &Error{kind: errTooManyFutureMessages}
	}

	for senderChainKey.Iteration() < iteration {
		senderMessageKey, err := senderChainKey.SenderMessageKey()
		if err != nil {
			return nil, err
		}
		senderKeyState.AddSenderMessageKey(senderMessageKey)
		nextKey, err := senderChainKey.Next()
		if err != nil {
			return nil, err
		}
		senderChainKey = nextKey
	}

	nextKey, err := senderChainKey.Next()
	if err != nil {
		return nil, err
	}
	senderKeyState.SetSenderChainKey(nextKey)
	return senderChainKey.SenderMessageKey()
}

// DistributionIDToGroupID formats a 16-byte distribution UUID as a standard
// hyphenated UUID string (8-4-4-4-12 lowercase hex) for use as a
// SenderKeyName group ID. The output is byte-identical to Rust's Uuid::Display
// (std::fmt::Display for uuid::Uuid) applied to the same 16 bytes.
//
// Rust counterpart: uuid::Uuid formatted via Display in
// rust/protocol/src/group_cipher.rs — the distribution_id field is a Uuid
// and its string representation via {} in log statements and error types
// uses this same hyphenated format.
func DistributionIDToGroupID(id [16]byte) string {
	h := hex.EncodeToString(id[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// distributionIDToGroupID is the package-internal alias used by Decrypt and
// Encrypt so callers within this package are not affected by the rename.
func distributionIDToGroupID(id [16]byte) string {
	return DistributionIDToGroupID(id)
}
