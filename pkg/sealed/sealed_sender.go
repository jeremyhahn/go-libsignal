package sealed

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"

	signalcipher "github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/sealedpb"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"google.golang.org/protobuf/proto"
)

const (
	// SealedSenderV1Version is the version byte for sealed sender v1 messages.
	SealedSenderV1Version = 0x11

	// macTruncateLen is the number of bytes to keep from the HMAC output.
	macTruncateLen = 10

	// hkdfOutputLen is the total HKDF output size: chain_key(32) + cipher_key(32) + mac_key(32).
	hkdfOutputLen = 96

	// hkdfInfo is the salt prefix used in sealed sender HKDF derivation.
	// Per the Rust reference, this is used ONLY in the salt construction
	// ("UnidentifiedDelivery" || their_pub || ephemeral_pub), NOT as the
	// HKDF info parameter (which must be empty).
	hkdfInfo = "UnidentifiedDelivery"
)

// SealedSenderDecryptionResult holds the result of decrypting a sealed
// sender message, including the sender identity and the decrypted plaintext.
type SealedSenderDecryptionResult struct {
	SenderUUID string
	SenderE164 *string
	DeviceID   uint32
	Message    []byte
}

// SealedSenderEncrypt encrypts a message using the sealed sender v1 protocol.
// It first encrypts the plaintext using a session cipher, then wraps it in a
// USMC structure, and finally applies the sealed sender encryption layer.
func SealedSenderEncrypt(
	destination *protocol.SignalAddress,
	senderCert *SenderCertificate,
	plaintext []byte,
	sessionStore store.Session,
	identityStore store.IdentityKey,
) ([]byte, error) {
	serializer := serialize.NewProtobufSerializer()

	sessionBuilder := session.NewBuilder(
		sessionStore, nil, nil, identityStore,
		destination, serializer,
	)
	sessionCipher := session.NewCipherWithIdentity(sessionBuilder, destination, identityStore)

	ciphertextMessage, err := sessionCipher.Encrypt(plaintext)
	if err != nil {
		return nil, err
	}

	serializedMsg, err := ciphertextMessage.Serialize()
	if err != nil {
		return nil, err
	}

	// Map protocol ciphertext types to sealed sender message types.
	var usmcType uint32
	switch ciphertextMessage.Type() {
	case protocol.PREKEY_TYPE:
		usmcType = uint32(sealedpb.UnidentifiedSenderMessage_Message_PREKEY_MESSAGE)
	case protocol.WHISPER_TYPE:
		usmcType = uint32(sealedpb.UnidentifiedSenderMessage_Message_MESSAGE)
	default:
		return nil, ErrUnsupportedMessageType
	}

	usmc, err := NewUnidentifiedSenderMessageContent(
		usmcType,
		senderCert,
		serializedMsg,
		ContentHintDefault,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return SealedSenderEncryptFromUSMC(destination, usmc, identityStore)
}

// SealedSenderEncryptFromUSMC encrypts a pre-built USMC for a single recipient
// using the sealed sender v1 protocol.
//
// The protocol performs a two-layer encryption:
//  1. Encrypt our identity public key using an ephemeral ECDH exchange.
//  2. Encrypt the USMC payload using a second ECDH exchange with our identity key.
func SealedSenderEncryptFromUSMC(
	destination *protocol.SignalAddress,
	usmc *UnidentifiedSenderMessageContent,
	identityStore store.IdentityKey,
) ([]byte, error) {
	ourIdentity := identityStore.GetIdentityKeyPair()

	// Step 1: Generate an ephemeral X25519 key pair.
	ephemeral, err := ecc.GenerateKeyPair()
	if err != nil {
		return nil, err
	}

	// Look up the recipient's identity key from our session state.
	theirPublicKey, err := getRecipientIdentityKey(destination, identityStore)
	if err != nil {
		return nil, err
	}
	if theirPublicKey == nil {
		return nil, &V1StructureError{Detail: "no identity key found for recipient"}
	}

	ephemeralPub := ephemeral.PublicKey().Serialize()
	theirPub := theirPublicKey.Serialize()

	// Step 2: First ECDH - ephemeral to their identity key.
	// salt = "UnidentifiedDelivery" || their_pub || ephemeral_pub
	salt1 := buildSalt(theirPub, ephemeralPub)

	ephPrivArr := ephemeral.PrivateKey().Serialize()
	ephPrivSecret, err := secret.New(ephPrivArr[:])
	if err != nil {
		return nil, err
	}
	defer ephPrivSecret.Destroy()

	theirPubRaw := theirPublicKey.PublicKey()
	var ephPriv [32]byte
	copy(ephPriv[:], ephPrivSecret.Bytes())
	defer crypto.ZeroizeArray32(&ephPriv)
	sharedSecret1, dhErr := kdf.CalculateSharedSecret(theirPubRaw, ephPriv)
	if dhErr != nil {
		return nil, dhErr
	}
	defer crypto.ZeroizeArray32(&sharedSecret1)
	sharedSecret1Secret, err := secret.New(sharedSecret1[:])
	if err != nil {
		return nil, err
	}
	defer sharedSecret1Secret.Destroy()

	keys1, err := kdf.DeriveSecrets(sharedSecret1Secret.Bytes(), salt1, nil, hkdfOutputLen)
	if err != nil {
		return nil, err
	}
	keys1Secret, err := secret.New(keys1)
	if err != nil {
		return nil, err
	}
	defer keys1Secret.Destroy()

	chainKey1 := keys1Secret.Bytes()[:32]
	cipherKey1 := keys1Secret.Bytes()[32:64]
	macKey1 := keys1Secret.Bytes()[64:96]

	// Step 3: Encrypt our identity public key with AES-CTR, append truncated HMAC.
	ourIdentityPub := ourIdentity.PublicKey().Serialize()
	encryptedStatic, err := signalcipher.AESCTREncrypt(cipherKey1, ourIdentityPub)
	if err != nil {
		return nil, err
	}
	staticMAC := truncatedHMAC(macKey1, encryptedStatic)
	encryptedStaticWithMAC := append(encryptedStatic, staticMAC...)

	// Step 4: Second ECDH - our identity key to their identity key.
	// salt = chain_key || encrypted_static_with_mac
	// Copy chainKey1 since it references guarded memory.
	chainKey1Copy := make([]byte, 32)
	defer crypto.Zeroize(chainKey1Copy)
	copy(chainKey1Copy, chainKey1)
	salt2 := append(chainKey1Copy, encryptedStaticWithMAC...)

	ourPrivArr := ourIdentity.PrivateKey().Serialize()
	ourPrivSecret, err := secret.New(ourPrivArr[:])
	if err != nil {
		return nil, err
	}
	defer ourPrivSecret.Destroy()

	var ourPriv [32]byte
	copy(ourPriv[:], ourPrivSecret.Bytes())
	defer crypto.ZeroizeArray32(&ourPriv)
	sharedSecret2, dhErr := kdf.CalculateSharedSecret(theirPubRaw, ourPriv)
	if dhErr != nil {
		return nil, dhErr
	}
	defer crypto.ZeroizeArray32(&sharedSecret2)
	sharedSecret2Secret, err := secret.New(sharedSecret2[:])
	if err != nil {
		return nil, err
	}
	defer sharedSecret2Secret.Destroy()

	keys2, err := kdf.DeriveSecrets(sharedSecret2Secret.Bytes(), salt2, nil, hkdfOutputLen)
	if err != nil {
		return nil, err
	}
	keys2Secret, err := secret.New(keys2)
	if err != nil {
		return nil, err
	}
	defer keys2Secret.Destroy()

	// keys2[:32] is chain_key2 (unused)
	cipherKey2 := keys2Secret.Bytes()[32:64]
	macKey2 := keys2Secret.Bytes()[64:96]

	// Step 5: Encrypt the USMC serialized with AES-CTR, append truncated HMAC.
	encryptedMessage, err := signalcipher.AESCTREncrypt(cipherKey2, usmc.Serialize())
	if err != nil {
		return nil, err
	}
	messageMAC := truncatedHMAC(macKey2, encryptedMessage)
	encryptedMessageWithMAC := append(encryptedMessage, messageMAC...)

	// Step 6: Build the protobuf envelope.
	envelope := &sealedpb.UnidentifiedSenderMessage{
		EphemeralPublic:  ephemeralPub,
		EncryptedStatic:  encryptedStaticWithMAC,
		EncryptedMessage: encryptedMessageWithMAC,
	}
	envelopeBytes, err := proto.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	// Step 7: Prepend version byte.
	result := make([]byte, 1+len(envelopeBytes))
	result[0] = SealedSenderV1Version
	copy(result[1:], envelopeBytes)

	return result, nil
}

// SealedSenderDecryptToUSMC decrypts a sealed sender message to extract
// the UnidentifiedSenderMessageContent. This performs the reverse of the
// two-layer encryption without validating the sender certificate.
//
// For v2 messages (version 0x22 or 0x23), use SealedSenderV2DecryptToUSMC
// instead, which requires the recipient's ServiceId. This function dispatches
// to v2 when a recipientServiceId is provided via the optional parameter.
func SealedSenderDecryptToUSMC(
	ciphertext []byte,
	identityStore store.IdentityKey,
	recipientServiceId ...protocol.ServiceId,
) (*UnidentifiedSenderMessageContent, error) {
	if len(ciphertext) < 1 {
		return nil, &V1StructureError{Detail: "ciphertext too short"}
	}

	version := ciphertext[0]

	// Handle v2 messages. The v2 protocol has two formats:
	// - Sent format (multi-recipient): requires a ServiceId to locate per-recipient data
	// - Received format (single-recipient): server has already extracted per-recipient data
	//
	// When a ServiceId is provided, use the sent format parser (SealedSenderV2DecryptToUSMC).
	// When no ServiceId is provided, use the received format parser
	// (SealedSenderV2DecryptReceivedToUSMC), which is what clients normally receive.
	if version == SealedSenderV2VersionUUID || version == SealedSenderV2VersionServiceId {
		if len(recipientServiceId) == 0 {
			return SealedSenderV2DecryptReceivedToUSMC(ciphertext, identityStore)
		}
		return SealedSenderV2DecryptToUSMC(ciphertext, recipientServiceId[0], identityStore)
	}

	// The Rust reference accepts major version 0 or 1 for v1 messages.
	// Major version is the high nibble (version >> 4).
	majorVersion := version >> 4
	if majorVersion != 0 && majorVersion != 1 {
		return nil, ErrUnsupportedVersion
	}

	envelope := &sealedpb.UnidentifiedSenderMessage{}
	if err := proto.Unmarshal(ciphertext[1:], envelope); err != nil {
		return nil, err
	}

	ephemeralPub := envelope.GetEphemeralPublic()
	encryptedStaticWithMAC := envelope.GetEncryptedStatic()
	encryptedMessageWithMAC := envelope.GetEncryptedMessage()

	if len(ephemeralPub) < 1 || len(encryptedStaticWithMAC) <= macTruncateLen || len(encryptedMessageWithMAC) <= macTruncateLen {
		return nil, &V1StructureError{Detail: "invalid sealed sender message structure"}
	}

	ourIdentity := identityStore.GetIdentityKeyPair()

	// Decode the ephemeral public key.
	ephPubKey, err := ecc.DecodePoint(ephemeralPub, 0)
	if err != nil {
		return nil, err
	}

	ourPub := ourIdentity.PublicKey().Serialize()

	// Step 1: First ECDH - ephemeral to our identity key.
	salt1 := buildSalt(ourPub, ephemeralPub)

	ourPrivArr := ourIdentity.PrivateKey().Serialize()
	ourPrivSecret, err := secret.New(ourPrivArr[:])
	if err != nil {
		return nil, err
	}
	defer ourPrivSecret.Destroy()

	ephPubRaw := ephPubKey.PublicKey()
	var ourPriv [32]byte
	copy(ourPriv[:], ourPrivSecret.Bytes())
	defer crypto.ZeroizeArray32(&ourPriv)
	sharedSecret1, dhErr := kdf.CalculateSharedSecret(ephPubRaw, ourPriv)
	if dhErr != nil {
		return nil, dhErr
	}
	defer crypto.ZeroizeArray32(&sharedSecret1)
	sharedSecret1Secret, err := secret.New(sharedSecret1[:])
	if err != nil {
		return nil, err
	}
	defer sharedSecret1Secret.Destroy()

	keys1, err := kdf.DeriveSecrets(sharedSecret1Secret.Bytes(), salt1, nil, hkdfOutputLen)
	if err != nil {
		return nil, err
	}
	keys1Secret, err := secret.New(keys1)
	if err != nil {
		return nil, err
	}
	defer keys1Secret.Destroy()

	chainKey1 := keys1Secret.Bytes()[:32]
	cipherKey1 := keys1Secret.Bytes()[32:64]
	macKey1 := keys1Secret.Bytes()[64:96]

	// Step 2: Verify and decrypt the static key (sender's identity public key).
	encryptedStatic := encryptedStaticWithMAC[:len(encryptedStaticWithMAC)-macTruncateLen]
	theirStaticMAC := encryptedStaticWithMAC[len(encryptedStaticWithMAC)-macTruncateLen:]

	ourStaticMAC := truncatedHMAC(macKey1, encryptedStatic)
	if subtle.ConstantTimeCompare(ourStaticMAC, theirStaticMAC) != 1 {
		return nil, &V1StructureError{Detail: "static key MAC verification failed"}
	}

	staticKeyBytes, err := signalcipher.AESCTRDecrypt(cipherKey1, encryptedStatic)
	if err != nil {
		return nil, err
	}

	theirPubKey, err := ecc.DecodePoint(staticKeyBytes, 0)
	if err != nil {
		return nil, err
	}

	// Step 3: Second ECDH - their identity key to our identity key.
	// Copy chainKey1 since it references guarded memory.
	chainKey1Copy := make([]byte, 32)
	defer crypto.Zeroize(chainKey1Copy)
	copy(chainKey1Copy, chainKey1)
	salt2 := append(chainKey1Copy, encryptedStaticWithMAC...)

	theirPubRaw := theirPubKey.PublicKey()
	copy(ourPriv[:], ourPrivSecret.Bytes())
	sharedSecret2, dhErr := kdf.CalculateSharedSecret(theirPubRaw, ourPriv)
	if dhErr != nil {
		return nil, dhErr
	}
	defer crypto.ZeroizeArray32(&sharedSecret2)
	sharedSecret2Secret, err := secret.New(sharedSecret2[:])
	if err != nil {
		return nil, err
	}
	defer sharedSecret2Secret.Destroy()

	keys2, err := kdf.DeriveSecrets(sharedSecret2Secret.Bytes(), salt2, nil, hkdfOutputLen)
	if err != nil {
		return nil, err
	}
	keys2Secret, err := secret.New(keys2)
	if err != nil {
		return nil, err
	}
	defer keys2Secret.Destroy()

	cipherKey2 := keys2Secret.Bytes()[32:64]
	macKey2 := keys2Secret.Bytes()[64:96]

	// Step 4: Verify and decrypt the message.
	encryptedMessage := encryptedMessageWithMAC[:len(encryptedMessageWithMAC)-macTruncateLen]
	theirMessageMAC := encryptedMessageWithMAC[len(encryptedMessageWithMAC)-macTruncateLen:]

	ourMessageMAC := truncatedHMAC(macKey2, encryptedMessage)
	if subtle.ConstantTimeCompare(ourMessageMAC, theirMessageMAC) != 1 {
		return nil, &V1StructureError{Detail: "message MAC verification failed"}
	}

	messageBytes, err := signalcipher.AESCTRDecrypt(cipherKey2, encryptedMessage)
	if err != nil {
		return nil, err
	}

	usmc, usmcErr := DeserializeUnidentifiedSenderMessageContent(messageBytes)
	if usmcErr != nil {
		return nil, usmcErr
	}

	// Verify the decrypted static key matches the sender's identity key in the
	// certificate. This prevents an attacker from replacing the sender certificate
	// inside the encrypted USMC with a different identity. The Rust reference
	// performs this check with message_key_bytes.ct_eq(&usmc.sender()?.key()?.serialize()).
	senderKeyBytes := usmc.Sender().Key().Serialize()
	if subtle.ConstantTimeCompare(staticKeyBytes, senderKeyBytes) != 1 {
		return nil, ErrSenderKeyMismatch
	}

	return usmc, nil
}

// SealedSenderDecrypt performs full decryption of a sealed sender message,
// including certificate validation and inner session cipher decryption.
func SealedSenderDecrypt(
	ciphertext []byte,
	trustRoot ecc.ECPublicKeyable,
	timestamp uint64,
	localUUID string,
	localE164 *string,
	localDeviceID uint32,
	sessionStore store.Session,
	identityStore store.IdentityKey,
	preKeyStore store.PreKey,
	signedPreKeyStore store.SignedPreKey,
) (*SealedSenderDecryptionResult, error) {
	return SealedSenderDecryptWithKyber(
		ciphertext, trustRoot, timestamp, localUUID, localE164, localDeviceID,
		sessionStore, identityStore, preKeyStore, signedPreKeyStore, nil,
	)
}

// SealedSenderDecryptWithKyber decrypts a sealed sender message with optional
// Kyber pre-key store support for PQXDH sessions.
func SealedSenderDecryptWithKyber(
	ciphertext []byte,
	trustRoot ecc.ECPublicKeyable,
	timestamp uint64,
	localUUID string,
	localE164 *string,
	localDeviceID uint32,
	sessionStore store.Session,
	identityStore store.IdentityKey,
	preKeyStore store.PreKey,
	signedPreKeyStore store.SignedPreKey,
	kyberPreKeyStore store.KyberPreKey,
) (*SealedSenderDecryptionResult, error) {
	// Step 1: Decrypt the outer sealed sender layer.
	usmc, err := SealedSenderDecryptToUSMC(ciphertext, identityStore)
	if err != nil {
		return nil, err
	}

	senderCert := usmc.Sender()

	// Step 2: Validate the sender certificate.
	valid, err := senderCert.Validate(trustRoot, timestamp)
	if err != nil {
		return nil, err
	}
	if !valid {
		return nil, &CertificateError{Detail: "sender certificate validation failed"}
	}

	// Step 3: Check for self-send (matches Rust sealed_sender_decrypt).
	// A message is considered a self-send if the sender's UUID OR E164
	// matches the local identity AND the device ID matches.
	isLocalUUID := senderCert.SenderUUID() == localUUID
	isLocalE164 := false
	if localE164 != nil && *localE164 != "" {
		senderE164 := senderCert.SenderE164()
		if senderE164 != nil && *senderE164 != "" {
			isLocalE164 = *localE164 == *senderE164
		}
	}
	if (isLocalUUID || isLocalE164) && senderCert.SenderDevice() == localDeviceID {
		return nil, ErrSelfSend
	}

	// Step 4: Decrypt the inner message using a session cipher.
	senderAddress := protocol.NewSignalAddress(senderCert.SenderUUID(), senderCert.SenderDevice())

	serializer := serialize.NewProtobufSerializer()

	var plaintext []byte

	// Build session builder with or without Kyber support.
	buildSessionBuilder := func() *session.Builder {
		if kyberPreKeyStore != nil {
			return session.NewBuilderWithKyber(
				sessionStore, preKeyStore, signedPreKeyStore, identityStore,
				kyberPreKeyStore, senderAddress, serializer,
			)
		}
		return session.NewBuilder(
			sessionStore, preKeyStore, signedPreKeyStore, identityStore,
			senderAddress, serializer,
		)
	}

	switch usmc.Type() {
	case uint32(sealedpb.UnidentifiedSenderMessage_Message_PREKEY_MESSAGE):
		// PreKey message: build session and decrypt.
		preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(
			usmc.Contents(),
			serializer.PreKeySignalMessage,
			serializer.SignalMessage,
		)
		if err != nil {
			return nil, err
		}

		sessionBuilder := buildSessionBuilder()
		sessionCipher := session.NewCipherWithIdentity(sessionBuilder, senderAddress, identityStore)
		plaintext, _, err = sessionCipher.DecryptPreKeyMessage(sessionBuilder, preKeyMsg)
		if err != nil {
			return nil, err
		}

	case uint32(sealedpb.UnidentifiedSenderMessage_Message_MESSAGE):
		// Regular Whisper message.
		whisperMsg, err := protocol.NewSignalMessageFromBytes(
			usmc.Contents(),
			serializer.SignalMessage,
		)
		if err != nil {
			return nil, err
		}

		sessionBuilder := buildSessionBuilder()
		sessionCipher := session.NewCipherWithIdentity(sessionBuilder, senderAddress, identityStore)
		plaintext, err = sessionCipher.Decrypt(whisperMsg)
		if err != nil {
			return nil, err
		}

	default:
		return nil, &Error{kind: errUnsupportedMessageType}
	}

	return &SealedSenderDecryptionResult{
		SenderUUID: senderCert.SenderUUID(),
		SenderE164: senderCert.SenderE164(),
		DeviceID:   senderCert.SenderDevice(),
		Message:    plaintext,
	}, nil
}

// buildSalt constructs the salt for sealed sender HKDF:
// "UnidentifiedDelivery" || theirPub || ephemeralPub
func buildSalt(theirPub, ephemeralPub []byte) []byte {
	prefix := []byte(hkdfInfo)
	salt := make([]byte, len(prefix)+len(theirPub)+len(ephemeralPub))
	n := copy(salt, prefix)
	n += copy(salt[n:], theirPub)
	copy(salt[n:], ephemeralPub)
	return salt
}

// truncatedHMAC computes HMAC-SHA256 and returns the first macTruncateLen bytes.
func truncatedHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	full := mac.Sum(nil)
	return full[:macTruncateLen]
}

// getRecipientIdentityKey retrieves the recipient's identity public key from
// the session store (via the identity key saved in the session state).
func getRecipientIdentityKey(
	address *protocol.SignalAddress,
	identityStore store.IdentityKey,
) (ecc.ECPublicKeyable, error) {
	// The identity store does not have a direct "load identity" method,
	// but during session establishment, identity keys are saved.
	// We need the recipient's public key for ECDH. We use the store's
	// identity key pair only for our own key. For the recipient, we rely
	// on the fact that IdentityKey store has saved their identity during
	// session setup. However, the store.IdentityKey interface only exposes
	// IsTrustedIdentity and SaveIdentity, not a direct load.
	//
	// In practice, the recipient's identity key is available from the session
	// record's remote identity key. We cannot access session store from here
	// since we only have the identity store. The caller must ensure the
	// identity is available.
	//
	// For the sealed sender protocol, the "their_pub" used in ECDH is the
	// recipient's identity key. We obtain this from the identity store
	// interface which should be extended, but given the current interface,
	// we return an error asking the caller to use a store that supports
	// loading identities.
	//
	// As a workaround, we accept the identity store which may implement
	// an optional Loader interface.
	type identityLoader interface {
		LoadIdentity(address *protocol.SignalAddress) ecc.ECPublicKeyable
	}
	if loader, ok := identityStore.(identityLoader); ok {
		key := loader.LoadIdentity(address)
		if key != nil {
			return key, nil
		}
	}

	// Fallback: try using a SessionIdentityStore that combines session and identity.
	type sessionIdentityStore interface {
		GetIdentityKey(address *protocol.SignalAddress) (ecc.ECPublicKeyable, error)
	}
	if sis, ok := identityStore.(sessionIdentityStore); ok {
		return sis.GetIdentityKey(address)
	}

	return nil, &IdentityStoreError{}
}
