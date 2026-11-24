package sealed

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"slices"

	signalcipher "github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/sealedpb"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
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

	// v1SaltPrefix starts the v1 HKDF salt "UnidentifiedDelivery" || their_pub || eph_pub; the info is empty.
	v1SaltPrefix = "UnidentifiedDelivery"
)

// SealedSenderDecryptionResult holds the result of decrypting a sealed
// sender message, including the sender identity and the decrypted plaintext.
type SealedSenderDecryptionResult struct {
	SenderUUID string
	SenderE164 *string
	DeviceID   uint32
	Message    []byte
}

// SealedSenderEncrypt encrypts with the session cipher, wraps the result in a USMC and seals it with sealed sender v1.
func SealedSenderEncrypt(
	destination *protocol.SignalAddress,
	senderCert *SenderCertificate,
	plaintext []byte,
	sessionStore store.Session,
	identityStore store.IdentityKey,
) ([]byte, error) {
	// A nil certificate is a CertificateError, not a panic.
	if senderCert == nil {
		return nil, &CertificateError{Detail: "sealed sender encrypt: nil sender certificate"}
	}

	serializer := serialize.NewProtobufSerializer()

	// Pass the sender address so the inner SignalMessage carries address binding, as Rust sealed_sender_encrypt does.
	senderAddr := protocol.NewSignalAddress(senderCert.SenderUUID(), senderCert.SenderDevice())

	sessionBuilder := session.NewBuilder(
		sessionStore, nil, nil, identityStore,
		destination, serializer,
	)
	sessionCipher := session.NewCipherWithIdentityAndLocalAddress(sessionBuilder, senderAddr, destination, identityStore)

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

// SealedSenderEncryptFromUSMC seals a USMC for one recipient with v1: one ECDH layer hides our identity key, a second encrypts the USMC.
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
	copyFromSecret(ephPriv[:], ephPrivSecret)
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

	keys1, err := deriveSaltedFromSecret(sharedSecret1Secret, salt1, hkdfOutputLen)
	if err != nil {
		return nil, err
	}
	keys1Secret, err := secret.New(keys1)
	if err != nil {
		return nil, err
	}
	defer keys1Secret.Destroy()

	// Step 3: Encrypt our identity public key with AES-CTR, append truncated HMAC.
	// The keys are used inside the borrow; chain_key is copied out for salt2.
	ourIdentityPub := ourIdentity.PublicKey().Serialize()
	var encryptedStaticWithMAC []byte
	chainKey1Copy := make([]byte, 32)
	defer crypto.Zeroize(chainKey1Copy)
	err = keys1Secret.WithBytes(func(keys1 []byte) error {
		chainKey1, cipherKey1, macKey1 := keys1[:32], keys1[32:64], keys1[64:96]
		encryptedStatic, encErr := signalcipher.AESCTREncrypt(cipherKey1, ourIdentityPub)
		if encErr != nil {
			return encErr
		}
		staticMAC := truncatedHMAC(macKey1, encryptedStatic)
		encryptedStaticWithMAC = slices.Concat(encryptedStatic, staticMAC)
		copy(chainKey1Copy, chainKey1)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Step 4: Second ECDH - our identity key to their identity key.
	// salt = chain_key || encrypted_static_with_mac
	salt2 := slices.Concat(chainKey1Copy, encryptedStaticWithMAC)

	ourPrivArr := ourIdentity.PrivateKey().Serialize()
	ourPrivSecret, err := secret.New(ourPrivArr[:])
	if err != nil {
		return nil, err
	}
	defer ourPrivSecret.Destroy()

	var ourPriv [32]byte
	copyFromSecret(ourPriv[:], ourPrivSecret)
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

	keys2, err := deriveSaltedFromSecret(sharedSecret2Secret, salt2, hkdfOutputLen)
	if err != nil {
		return nil, err
	}
	keys2Secret, err := secret.New(keys2)
	if err != nil {
		return nil, err
	}
	defer keys2Secret.Destroy()

	// keys2[:32] is the unused chain key; encrypt the USMC with AES-CTR and append the truncated HMAC.
	var encryptedMessageWithMAC []byte
	err = keys2Secret.WithBytes(func(keys2 []byte) error {
		cipherKey2, macKey2 := keys2[32:64], keys2[64:96]
		encryptedMessage, encErr := signalcipher.AESCTREncrypt(cipherKey2, usmc.Serialize())
		if encErr != nil {
			return encErr
		}
		messageMAC := truncatedHMAC(macKey2, encryptedMessage)
		encryptedMessageWithMAC = slices.Concat(encryptedMessage, messageMAC)
		return nil
	})
	if err != nil {
		return nil, err
	}

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

// SealedSenderDecryptToUSMC unseals a message to its USMC without validating the sender certificate; a recipient ServiceId selects the v2 sent format.
func SealedSenderDecryptToUSMC(
	ciphertext []byte,
	identityStore store.IdentityKey,
	recipientServiceId ...protocol.ServiceId,
) (*UnidentifiedSenderMessageContent, error) {
	if len(ciphertext) < 1 {
		return nil, &V1StructureError{Detail: "ciphertext too short"}
	}

	version := ciphertext[0]

	// v2: with a ServiceId parse the multi-recipient sent format, otherwise the received format clients normally get.
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
	copyFromSecret(ourPriv[:], ourPrivSecret)
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

	keys1, err := deriveSaltedFromSecret(sharedSecret1Secret, salt1, hkdfOutputLen)
	if err != nil {
		return nil, err
	}
	keys1Secret, err := secret.New(keys1)
	if err != nil {
		return nil, err
	}
	defer keys1Secret.Destroy()

	// Step 2: Verify and decrypt the static key (sender's identity public key).
	// The keys are used inside the borrow; chain_key is copied out for salt2.
	encryptedStatic := encryptedStaticWithMAC[:len(encryptedStaticWithMAC)-macTruncateLen]
	theirStaticMAC := encryptedStaticWithMAC[len(encryptedStaticWithMAC)-macTruncateLen:]

	var staticKeyBytes []byte
	chainKey1Copy := make([]byte, 32)
	defer crypto.Zeroize(chainKey1Copy)
	err = keys1Secret.WithBytes(func(keys1 []byte) error {
		chainKey1, cipherKey1, macKey1 := keys1[:32], keys1[32:64], keys1[64:96]
		ourStaticMAC := truncatedHMAC(macKey1, encryptedStatic)
		if subtle.ConstantTimeCompare(ourStaticMAC, theirStaticMAC) != 1 {
			return &V1StructureError{Detail: "static key MAC verification failed"}
		}
		var decErr error
		if staticKeyBytes, decErr = signalcipher.AESCTRDecrypt(cipherKey1, encryptedStatic); decErr != nil {
			return decErr
		}
		copy(chainKey1Copy, chainKey1)
		return nil
	})
	if err != nil {
		return nil, err
	}

	theirPubKey, err := ecc.DecodePoint(staticKeyBytes, 0)
	if err != nil {
		return nil, err
	}

	// Step 3: Second ECDH - their identity key to our identity key.
	salt2 := slices.Concat(chainKey1Copy, encryptedStaticWithMAC)

	theirPubRaw := theirPubKey.PublicKey()
	copyFromSecret(ourPriv[:], ourPrivSecret)
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

	keys2, err := deriveSaltedFromSecret(sharedSecret2Secret, salt2, hkdfOutputLen)
	if err != nil {
		return nil, err
	}
	keys2Secret, err := secret.New(keys2)
	if err != nil {
		return nil, err
	}
	defer keys2Secret.Destroy()

	// Step 4: Verify and decrypt the message.
	encryptedMessage := encryptedMessageWithMAC[:len(encryptedMessageWithMAC)-macTruncateLen]
	theirMessageMAC := encryptedMessageWithMAC[len(encryptedMessageWithMAC)-macTruncateLen:]

	var messageBytes []byte
	err = keys2Secret.WithBytes(func(keys2 []byte) error {
		cipherKey2, macKey2 := keys2[32:64], keys2[64:96]
		ourMessageMAC := truncatedHMAC(macKey2, encryptedMessage)
		if subtle.ConstantTimeCompare(ourMessageMAC, theirMessageMAC) != 1 {
			return &V1StructureError{Detail: "message MAC verification failed"}
		}
		var decErr error
		messageBytes, decErr = signalcipher.AESCTRDecrypt(cipherKey2, encryptedMessage)
		return decErr
	})
	if err != nil {
		return nil, err
	}

	usmc, usmcErr := DeserializeUnidentifiedSenderMessageContent(messageBytes)
	if usmcErr != nil {
		return nil, usmcErr
	}

	// The decrypted static key must equal the certificate's identity key, as in Rust.
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

	// A self-send is a local UUID or E164 with the local device ID, as in Rust.
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

		// Pass the local address so the inner verify checks address binding, as Rust does.
		localAddress := protocol.NewSignalAddress(localUUID, localDeviceID)

		sessionBuilder := buildSessionBuilder()
		sessionCipher := session.NewCipherWithIdentityAndLocalAddress(sessionBuilder, localAddress, senderAddress, identityStore)
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

		// Pass the local address here too; messages without a binding field still verify.
		localAddress := protocol.NewSignalAddress(localUUID, localDeviceID)

		sessionBuilder := buildSessionBuilder()
		sessionCipher := session.NewCipherWithIdentityAndLocalAddress(sessionBuilder, localAddress, senderAddress, identityStore)
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
	prefix := []byte(v1SaltPrefix)
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

// getRecipientIdentityKey returns the recipient's identity key from the store, or IdentityStoreError when none is recorded.
func getRecipientIdentityKey(
	address *protocol.SignalAddress,
	identityStore store.IdentityKey,
) (ecc.ECPublicKeyable, error) {
	identityKey, err := identityStore.GetIdentity(address)
	if err != nil {
		return nil, err
	}
	if identityKey == nil {
		return nil, &IdentityStoreError{}
	}
	return identityKey.PublicKey(), nil
}
