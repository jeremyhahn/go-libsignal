package sealed

import (
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	signalcipher "github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"golang.org/x/crypto/curve25519"
)

const (
	// SealedSenderV2VersionUUID is the v2 version byte using UUID-based addressing.
	SealedSenderV2VersionUUID = 0x22

	// SealedSenderV2VersionServiceId is the v2 version byte using ServiceId-based addressing.
	SealedSenderV2VersionServiceId = 0x23

	// v2MSize is the size of the random M value.
	v2MSize = 32

	// v2EncryptedMKeySize is the size of the encrypted M (C_i) per recipient.
	v2EncryptedMKeySize = 32

	// v2AuthTagSize is the size of the authentication tag per recipient.
	v2AuthTagSize = 16

	// v2ServiceIdSize is the fixed-width binary size of a ServiceId.
	v2ServiceIdSize = 17

	// v2NonceSize is the AES-GCM-SIV nonce size (all zeros).
	v2NonceSize = 12

	// v2HKDFRInfo is the HKDF info string for deriving r from M.
	v2HKDFRInfo = "Sealed Sender v2: r (2023-08)"

	// v2HKDFKInfo is the HKDF info string for deriving K from M.
	v2HKDFKInfo = "Sealed Sender v2: K"

	// v2HKDFDHInfo is the HKDF info string for the DH-based key derivation.
	v2HKDFDHInfo = "Sealed Sender v2: DH"

	// v2HKDFDHSenderInfo is the HKDF info for the sender authentication tag.
	v2HKDFDHSenderInfo = "Sealed Sender v2: DH-sender"

	// v2ValidRegistrationIDMask masks the 14-bit registration ID value (bits 0-13).
	// Bit 15 (0x8000) is reserved for the has_more flag in the wire format.
	v2ValidRegistrationIDMask = 0x3FFF

	// v2HasMoreDevicesBit is set in the registration ID u16 when more devices
	// follow for the same recipient in the wire format.
	v2HasMoreDevicesBit = 0x8000

	// v2UUIDSize is the size of a raw UUID (used in version 0x22).
	v2UUIDSize = 16
)

// SealedSenderV2SentMessageRecipient holds per-recipient data in a v2 multi-recipient message.
//
// KeyMaterialOffset and KeyMaterialLength locate this recipient's encrypted-M
// (C_i) ‖ auth-tag (AT_i) region within the full wire-format message, enabling
// server-side multi-recipient delivery (MRM) to extract per-recipient views
// without re-encoding the message. They are populated only when the message is
// parsed via ParseSealedSenderV2SentMessage; v2ParseMessage callers that pass
// only the body bytes will see offsets relative to the body. For excluded
// recipients (no devices) the values are both zero.
type SealedSenderV2SentMessageRecipient struct {
	DeviceIDs       []uint32
	RegistrationIDs []uint16
	EncryptedMKey   []byte // 32 bytes - encrypted random M (C_i)
	AuthTag         []byte // 16 bytes - authentication tag (AT_i)

	// KeyMaterialOffset is the byte offset (within the parser input) where
	// this recipient's C_i ‖ AT_i region begins. See type-level docs.
	KeyMaterialOffset int
	// KeyMaterialLength is the length of the C_i ‖ AT_i region (always
	// v2EncryptedMKeySize + v2AuthTagSize = 48 when non-zero, 0 for
	// excluded recipients).
	KeyMaterialLength int
}

// SealedSenderV2SentMessage represents a parsed v2 multi-recipient sent message.
//
// When the message is parsed via ParseSealedSenderV2SentMessage, fullMessage
// retains the original wire-format bytes (including the leading version byte),
// version records the format version, sharedBytesOffset records the start of
// the shared (e_pub ‖ encrypted_payload) region, and RecipientOrder lists the
// service-ID keys in their parse order. Together these enable server-side MRM
// to compute per-recipient views.
type SealedSenderV2SentMessage struct {
	Recipients       map[string]*SealedSenderV2SentMessageRecipient // keyed by ServiceId string
	EphemeralPublic  []byte
	EncryptedPayload []byte

	// RecipientOrder lists Recipients keys in their parse order. Mirrors
	// the IndexMap iteration order in Rust libsignal so callers that iterate
	// recipients deterministically can do so even though Go maps are
	// unordered.
	RecipientOrder []string

	// fullMessage is the original wire-format buffer when the message was
	// parsed via ParseSealedSenderV2SentMessage; nil otherwise. Read-only.
	fullMessage []byte
	// version is the format version byte (0x22 or 0x23) when fullMessage is
	// set; zero otherwise.
	version byte
	// sharedBytesOffset is the offset within fullMessage where the shared
	// (ephemeral public key + encrypted payload) region begins. Zero when
	// fullMessage is nil.
	sharedBytesOffset int
}

// v2RecipientInput groups the inputs needed for each recipient during encryption.
type v2RecipientInput struct {
	serviceId      protocol.ServiceId
	deviceID       uint32
	registrationID uint16
	identityPubRaw [32]byte // raw 32-byte public key (no type prefix)
}

// v2RecipientOutput holds computed per-recipient data for message serialization.
type v2RecipientOutput struct {
	serviceId  protocol.ServiceId
	deviceIDs  []uint32
	regIDs     []uint16
	encryptedM []byte // 32 bytes (C_i)
	authTag    []byte // 16 bytes (AT_i)
}

// SealedSenderMultiRecipientEncrypt encrypts a USMC for multiple recipients using
// the Sealed Sender v2 multi-recipient protocol.
//
// Each destination address must have a corresponding session at the same index in
// destinationSessions. The excludedRecipients list contains ServiceIds whose
// entries should be omitted from the output (e.g., the sender's own ServiceId).
func SealedSenderMultiRecipientEncrypt(
	destinations []*protocol.SignalAddress,
	destinationSessions []*record.Session,
	excludedRecipients []protocol.ServiceId,
	usmc *UnidentifiedSenderMessageContent,
	identityStore store.IdentityKey,
) ([]byte, error) {
	if len(destinations) != len(destinationSessions) {
		return nil, &V2InputError{Detail: "destinations and sessions must have the same length"}
	}
	if usmc == nil {
		return nil, &V2InputError{Detail: "usmc must not be nil"}
	}

	ourIdentity := identityStore.GetIdentityKeyPair()
	ourPrivArr := ourIdentity.PrivateKey().Serialize()
	ourPrivSecret, err := secret.New(ourPrivArr[:])
	if err != nil {
		return nil, err
	}
	defer ourPrivSecret.Destroy()
	ourPub := ourIdentity.PublicKey().PublicKey().PublicKey() // [32]byte raw

	// Step 1: Generate 32 random bytes M.
	mSecret, err := secret.NewRandom(v2MSize)
	if err != nil {
		return nil, &V2OperationError{Operation: "failed to generate random M", Err: err}
	}
	defer mSecret.Destroy()

	// Step 2: Derive r = HKDF(ikm=M, salt=nil, info="Sealed Sender v2: r (2023-08)", len=32).
	rRaw, err := deriveFromSecret(mSecret, []byte(v2HKDFRInfo), 32)
	if err != nil {
		return nil, &V2OperationError{Operation: "failed to derive r", Err: err}
	}
	rSecret, err := secret.New(rRaw)
	if err != nil {
		return nil, err
	}
	defer rSecret.Destroy()

	// Step 3: Derive K = HKDF(ikm=M, salt=nil, info="Sealed Sender v2: K", len=32).
	kRaw, err := deriveFromSecret(mSecret, []byte(v2HKDFKInfo), 32)
	if err != nil {
		return nil, &V2OperationError{Operation: "failed to derive K", Err: err}
	}
	kSecret, err := secret.New(kRaw)
	if err != nil {
		return nil, err
	}
	defer kSecret.Destroy()

	// Step 4: Create ephemeral key pair E from r (clamp and compute public).
	var ephPriv [32]byte
	copyFromSecret(ephPriv[:], rSecret)
	ephPriv[0] &= 248
	ephPriv[31] &= 127
	ephPriv[31] |= 64
	defer crypto.ZeroizeArray32(&ephPriv)
	ephPrivSecret, err := secret.New(ephPriv[:])
	if err != nil {
		return nil, err
	}
	defer ephPrivSecret.Destroy()

	// Recover ephPriv from guarded memory for ScalarBaseMult.
	var ephPrivForMult [32]byte
	copyFromSecret(ephPrivForMult[:], ephPrivSecret)
	defer crypto.ZeroizeArray32(&ephPrivForMult)
	var ephPub [32]byte
	curve25519.ScalarBaseMult(&ephPub, &ephPrivForMult)

	// Step 5: Encrypt the USMC with AES-256-GCM-SIV(key=K, nonce=zeros(12), aad=empty).
	zeroNonce := make([]byte, v2NonceSize)
	var encryptedPayload []byte
	err = kSecret.WithBytes(func(k []byte) error {
		var aeadErr error
		encryptedPayload, aeadErr = signalcipher.AESGCMSIVEncrypt(k, zeroNonce, usmc.Serialize(), nil)
		return aeadErr
	})
	if err != nil {
		return nil, &V2OperationError{Operation: "failed to encrypt payload", Err: err}
	}

	// Build the excluded set for fast lookup.
	excludedSet := make(map[string]struct{}, len(excludedRecipients))
	for _, excl := range excludedRecipients {
		excludedSet[excl.String()] = struct{}{}
	}

	// Step 6: Group destinations by ServiceId and compute per-recipient data.
	// We need to resolve ServiceId from the address name. The address name is a UUID string;
	// we treat it as an ACI ServiceId for the v2 protocol.
	type recipientGroup struct {
		serviceId protocol.ServiceId
		devices   []v2RecipientInput
	}
	groupOrder := make([]string, 0)
	groups := make(map[string]*recipientGroup)

	for i, dest := range destinations {
		sess := destinationSessions[i]
		if sess == nil {
			return nil, &V2InputError{Detail: fmt.Sprintf("nil session for destination %s", dest.String())}
		}

		// Parse the address name as a ServiceId, auto-detecting ACI vs PNI from
		// the canonical "PNI:<uuid>" prefix. Rust uses ServiceId::parse_from_service_id_string
		// which accepts both prefixed and bare UUID forms. Hard-coding ACI here would
		// silently reject PNI-addressed destinations.
		sid, err := protocol.ServiceIdFromServiceIdString(dest.Name())
		if err != nil {
			return nil, &V2ParseError{Detail: fmt.Sprintf("invalid service ID for %s", dest.Name()), Err: err}
		}

		// Check if excluded.
		if _, excluded := excludedSet[sid.String()]; excluded {
			continue
		}

		// Get the remote identity key from the session.
		remoteIdentity := sess.SessionState().RemoteIdentityKey()
		if remoteIdentity == nil {
			return nil, &V2InputError{Detail: fmt.Sprintf("no remote identity key in session for %s", dest.String())}
		}
		identityPubRaw := remoteIdentity.PublicKey().PublicKey() // [32]byte

		// Validate that the registration ID fits in 14 bits before truncating to
		// uint16. Bit 15 is reserved for the has_more flag in the wire format;
		// bits outside the valid mask indicate corruption or an invalid session
		// state. The full uint32 must be checked first so that values in the
		// range [0x4000, 0xFFFF] are correctly rejected rather than silently
		// masked away by the uint16 truncation.
		fullRegID := sess.SessionState().RemoteRegistrationID()
		if fullRegID & ^uint32(v2ValidRegistrationIDMask) != 0 {
			return nil, ErrInvalidRegistrationID
		}
		regID := uint16(fullRegID)

		key := sid.String()
		grp, exists := groups[key]
		if !exists {
			grp = &recipientGroup{serviceId: sid}
			groups[key] = grp
			groupOrder = append(groupOrder, key)
		}
		grp.devices = append(grp.devices, v2RecipientInput{
			serviceId:      sid,
			deviceID:       dest.DeviceID(),
			registrationID: regID,
			identityPubRaw: identityPubRaw,
		})
	}

	// Step 7: For each recipient group, compute C_i and AT_i.
	recipientOutputs := make([]v2RecipientOutput, 0, len(groups))

	for _, key := range groupOrder {
		grp := groups[key]
		// All devices for a given ServiceId share the same identity key,
		// so we compute C_i and AT_i once per ServiceId.
		ri := grp.devices[0]

		// shared = ECDH(ephPriv, recipientIdentityKey)
		copyFromSecret(ephPrivForMult[:], ephPrivSecret)
		shared, dhErr := kdf.CalculateSharedSecret(ri.identityPubRaw, ephPrivForMult)
		if dhErr != nil {
			return nil, dhErr
		}

		// ikm = shared || ephPub.Serialize() || recipientPub.Serialize()
		// Uses 33-byte serialized keys (0x05 prefix) to match Rust reference.
		ephPubSerialized := v2SerializePublicKey(ephPub)
		recipientPubSerialized := v2SerializePublicKey(ri.identityPubRaw)
		ikmBytes := make([]byte, 32+33+33)
		copy(ikmBytes[0:32], shared[:])
		copy(ikmBytes[32:65], ephPubSerialized)
		copy(ikmBytes[65:98], recipientPubSerialized)
		// Zeroize shared immediately after use -- not via defer which would
		// only execute on function return, leaving secrets in memory across
		// loop iterations.
		crypto.ZeroizeArray32(&shared)

		ikmSecret, err := secret.New(ikmBytes)
		if err != nil {
			return nil, err
		}

		// dhKey = HKDF(ikm, salt=nil, info="Sealed Sender v2: DH", len=32)
		dhKeyRaw, err := deriveFromSecret(ikmSecret, []byte(v2HKDFDHInfo), 32)
		ikmSecret.Destroy()
		if err != nil {
			return nil, &V2OperationError{Operation: "failed to derive DH key", Err: err}
		}
		dhKeySecret, err := secret.New(dhKeyRaw)
		if err != nil {
			return nil, err
		}

		// C_i = dhKey XOR M
		ci := make([]byte, v2EncryptedMKeySize)
		_ = dhKeySecret.WithBytes(func(dhKey []byte) error {
			return mSecret.WithBytes(func(m []byte) error {
				subtle.XORBytes(ci, dhKey, m)
				return nil
			})
		})
		dhKeySecret.Destroy()

		// Sender authentication tag:
		// senderShared = ECDH(ourPriv, recipientPub)
		var ourPrivForDH [32]byte
		copyFromSecret(ourPrivForDH[:], ourPrivSecret)
		senderShared, sdhErr := kdf.CalculateSharedSecret(ri.identityPubRaw, ourPrivForDH)
		crypto.ZeroizeArray32(&ourPrivForDH)
		if sdhErr != nil {
			return nil, sdhErr
		}

		// senderIkm = senderShared || ephPub.Serialize() || C_i || ourPub.Serialize() || recipientPub.Serialize()
		// Uses 33-byte serialized keys (0x05 prefix) to match Rust reference.
		ourPubSerialized := v2SerializePublicKey(ourPub)
		senderIkmBytes := make([]byte, 32+33+32+33+33)
		copy(senderIkmBytes[0:32], senderShared[:])
		copy(senderIkmBytes[32:65], ephPubSerialized)
		copy(senderIkmBytes[65:97], ci)
		copy(senderIkmBytes[97:130], ourPubSerialized)
		copy(senderIkmBytes[130:163], recipientPubSerialized)
		// Zeroize senderShared immediately after use rather than deferring.
		crypto.ZeroizeArray32(&senderShared)

		senderIkmSecret, err := secret.New(senderIkmBytes)
		if err != nil {
			return nil, err
		}

		// AT_i = HKDF(senderIkm, salt=nil, info="Sealed Sender v2: DH-sender", len=16)
		ati, err := deriveFromSecret(senderIkmSecret, []byte(v2HKDFDHSenderInfo), v2AuthTagSize)
		senderIkmSecret.Destroy()
		if err != nil {
			return nil, &V2OperationError{Operation: "failed to derive auth tag", Err: err}
		}

		deviceIDs := make([]uint32, len(grp.devices))
		regIDs := make([]uint16, len(grp.devices))
		for j, d := range grp.devices {
			deviceIDs[j] = d.deviceID
			regIDs[j] = d.registrationID
		}

		recipientOutputs = append(recipientOutputs, v2RecipientOutput{
			serviceId:  grp.serviceId,
			deviceIDs:  deviceIDs,
			regIDs:     regIDs,
			encryptedM: ci,
			authTag:    ati,
		})
	}

	// Step 8: Build binary format including excluded recipients.
	return v2BuildMessageWithExcluded(SealedSenderV2VersionServiceId, recipientOutputs, excludedRecipients, ephPub[:], encryptedPayload)
}

// v2SerializePublicKey returns a 33-byte serialized public key with the 0x05
// DJB type prefix, matching the Rust reference serialize() format.
func v2SerializePublicKey(raw [32]byte) []byte {
	out := make([]byte, 33)
	out[0] = 0x05
	copy(out[1:], raw[:])
	return out
}

// v2BuildMessage serializes a v2 multi-recipient sealed sender message into the
// Rust-compatible wire format. This is the backward-compatible entry point that
// encodes no excluded recipients.
//
// Wire format per recipient entry:
//
//	ServiceId (17 bytes fixed-width binary)
//	For each device:
//	  device_id (1 byte, u8)
//	  registration_id (2 bytes, u16 big-endian, bit 15 = has_more devices)
//	C_i (32 bytes) || AT_i (16 bytes)
func v2BuildMessage(version byte, recipients []v2RecipientOutput, ephPub, encryptedPayload []byte) ([]byte, error) {
	return v2BuildMessageWithExcluded(version, recipients, nil, ephPub, encryptedPayload)
}

// v2BuildMessageWithExcluded serializes a v2 multi-recipient sealed sender message
// including excluded recipients in the Rust-compatible wire format.
//
// Excluded recipients are encoded as: ServiceId (17 bytes) + device_id=0 (1 byte).
// The recipient count varint includes both normal and excluded recipients.
func v2BuildMessageWithExcluded(
	version byte,
	recipients []v2RecipientOutput,
	excludedRecipients []protocol.ServiceId,
	ephPub, encryptedPayload []byte,
) ([]byte, error) {
	// Estimate buffer size.
	totalRecipientCount := len(recipients) + len(excludedRecipients)
	bufSize := 1 + 10 // version + max varint
	for _, r := range recipients {
		// serviceId(17) + per-device(3 bytes each: 1 device_id + 2 reg_id) + C_i(32) + AT_i(16)
		bufSize += v2ServiceIdSize + len(r.deviceIDs)*3 + v2EncryptedMKeySize + v2AuthTagSize
	}
	// excluded: serviceId(17) + device_id_zero(1)
	bufSize += len(excludedRecipients) * (v2ServiceIdSize + 1)
	bufSize += 32 + len(encryptedPayload)

	buf := make([]byte, 0, bufSize)

	// Version byte.
	buf = append(buf, version)

	// Recipient count as varint (includes excluded recipients).
	var varintBuf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(varintBuf[:], uint64(totalRecipientCount))
	buf = append(buf, varintBuf[:n]...)

	// Each recipient with devices.
	for _, r := range recipients {
		// ServiceId: 17 bytes fixed-width binary.
		sid := r.serviceId.FixedWidthBinary()
		buf = append(buf, sid[:]...)

		// Per-device entries: device_id (1 byte u8) + registration_id (u16 big-endian).
		// The has_more bit (0x8000) in the registration ID indicates more devices follow.
		deviceCount := len(r.deviceIDs)
		for j := 0; j < deviceCount; j++ {
			// Device ID as a single byte (u8). Reject values > 255.
			if r.deviceIDs[j] > 255 {
				return nil, ErrDeviceIDOverflow
			}
			buf = append(buf, byte(r.deviceIDs[j]))

			// Registration ID with has_more bit.
			regID := r.regIDs[j] & v2ValidRegistrationIDMask
			if j < deviceCount-1 {
				regID |= v2HasMoreDevicesBit
			}
			var regBuf [2]byte
			binary.BigEndian.PutUint16(regBuf[:], regID)
			buf = append(buf, regBuf[:]...)
		}

		// C_i (32 bytes) || AT_i (16 bytes).
		buf = append(buf, r.encryptedM...)
		buf = append(buf, r.authTag...)
	}

	// Excluded recipients: ServiceId + device_id=0 (no C_i/AT_i).
	for _, excl := range excludedRecipients {
		sid := excl.FixedWidthBinary()
		buf = append(buf, sid[:]...)
		buf = append(buf, 0) // device_id = 0 means no devices / excluded
	}

	// Ephemeral public key (32 bytes).
	buf = append(buf, ephPub...)

	// Encrypted payload.
	buf = append(buf, encryptedPayload...)

	return buf, nil
}

// SealedSenderV2DecryptToUSMC decrypts a sealed sender v2 message to extract
// the UnidentifiedSenderMessageContent. The caller provides the recipient's
// ServiceId so the correct per-recipient data can be located.
//
// This function handles both version 0x22 (UUID) and 0x23 (ServiceId).
func SealedSenderV2DecryptToUSMC(
	ciphertext []byte,
	recipientServiceId protocol.ServiceId,
	identityStore store.IdentityKey,
) (*UnidentifiedSenderMessageContent, error) {
	if len(ciphertext) < 1 {
		return nil, &V2InputError{Detail: "v2 ciphertext too short"}
	}

	version := ciphertext[0]
	if version != SealedSenderV2VersionUUID && version != SealedSenderV2VersionServiceId {
		return nil, &V2InputError{Detail: fmt.Sprintf("unsupported v2 version: 0x%02x", version)}
	}

	// Parse the binary format.
	parsed, err := v2ParseMessage(ciphertext[1:], version)
	if err != nil {
		return nil, &V2OperationError{Operation: "failed to parse v2 message", Err: err}
	}

	// Find our recipient entry.
	recipientKey := recipientServiceId.String()
	recipient, ok := parsed.Recipients[recipientKey]
	if !ok {
		return nil, &V2InputError{Detail: "recipient not found in v2 message"}
	}

	if len(recipient.EncryptedMKey) != v2EncryptedMKeySize {
		return nil, &V2InputError{Detail: "invalid encrypted M key size"}
	}
	if len(recipient.AuthTag) != v2AuthTagSize {
		return nil, &V2InputError{Detail: "invalid auth tag size"}
	}

	ci := recipient.EncryptedMKey
	ati := recipient.AuthTag

	ourIdentity := identityStore.GetIdentityKeyPair()
	ourPrivArr := ourIdentity.PrivateKey().Serialize()
	ourPrivSecret, err := secret.New(ourPrivArr[:])
	if err != nil {
		return nil, err
	}
	defer ourPrivSecret.Destroy()
	ourPub := ourIdentity.PublicKey().PublicKey().PublicKey() // [32]byte raw

	if len(parsed.EphemeralPublic) != 32 {
		return nil, &V2InputError{Detail: "invalid ephemeral public key size"}
	}
	var ephPub [32]byte
	copy(ephPub[:], parsed.EphemeralPublic)

	// Step 1: shared = ECDH(ephPub, ourPriv)
	var ourPriv [32]byte
	copyFromSecret(ourPriv[:], ourPrivSecret)
	defer crypto.ZeroizeArray32(&ourPriv)
	shared, dhErr := kdf.CalculateSharedSecret(ephPub, ourPriv)
	if dhErr != nil {
		return nil, dhErr
	}
	defer crypto.ZeroizeArray32(&shared)
	sharedSecret, err := secret.New(shared[:])
	if err != nil {
		return nil, err
	}
	defer sharedSecret.Destroy()

	// Step 2: M = HKDF(ikm=shared||ephPub.Serialize()||ourPub.Serialize(), info="Sealed Sender v2: DH", len=32) XOR C_i
	// Uses 33-byte serialized keys (0x05 prefix) to match Rust reference.
	ephPubSerialized := v2SerializePublicKey(ephPub)
	ourPubSerialized := v2SerializePublicKey(ourPub)
	ikmBytes := make([]byte, 32+33+33)
	copyFromSecret(ikmBytes[0:32], sharedSecret)
	copy(ikmBytes[32:65], ephPubSerialized)
	copy(ikmBytes[65:98], ourPubSerialized)
	ikmSecret, err := secret.New(ikmBytes)
	if err != nil {
		return nil, err
	}

	dhKeyRaw, err := deriveFromSecret(ikmSecret, []byte(v2HKDFDHInfo), 32)
	ikmSecret.Destroy()
	if err != nil {
		return nil, &V2OperationError{Operation: "failed to derive DH key", Err: err}
	}
	dhKeySecret, err := secret.New(dhKeyRaw)
	if err != nil {
		return nil, err
	}

	var mRecovered [v2MSize]byte
	_ = dhKeySecret.WithBytes(func(dhKey []byte) error {
		subtle.XORBytes(mRecovered[:], dhKey, ci)
		return nil
	})
	dhKeySecret.Destroy()
	defer crypto.ZeroizeArray32(&mRecovered)

	mRecoveredSecret, err := secret.New(mRecovered[:])
	if err != nil {
		return nil, err
	}
	defer mRecoveredSecret.Destroy()

	// Step 3: r = HKDF(ikm=M, info="Sealed Sender v2: r (2023-08)", len=32)
	rRaw, err := deriveFromSecret(mRecoveredSecret, []byte(v2HKDFRInfo), 32)
	if err != nil {
		return nil, &V2OperationError{Operation: "failed to derive r", Err: err}
	}
	rSecret, err := secret.New(rRaw)
	if err != nil {
		return nil, err
	}
	defer rSecret.Destroy()

	// Step 4: K = HKDF(ikm=M, info="Sealed Sender v2: K", len=32)
	kRaw, err := deriveFromSecret(mRecoveredSecret, []byte(v2HKDFKInfo), 32)
	if err != nil {
		return nil, &V2OperationError{Operation: "failed to derive K", Err: err}
	}
	kSecret, err := secret.New(kRaw)
	if err != nil {
		return nil, err
	}
	defer kSecret.Destroy()

	// Step 5: Validate ephemeral key: derive E' from r, verify E'.public == E.public.
	var ephPrivCheck [32]byte
	copyFromSecret(ephPrivCheck[:], rSecret)
	ephPrivCheck[0] &= 248
	ephPrivCheck[31] &= 127
	ephPrivCheck[31] |= 64
	defer crypto.ZeroizeArray32(&ephPrivCheck)
	ephPrivCheckSecret, err := secret.New(ephPrivCheck[:])
	if err != nil {
		return nil, err
	}

	var ephPrivForMult [32]byte
	copyFromSecret(ephPrivForMult[:], ephPrivCheckSecret)
	ephPrivCheckSecret.Destroy()
	defer crypto.ZeroizeArray32(&ephPrivForMult)

	var ephPubCheck [32]byte
	curve25519.ScalarBaseMult(&ephPubCheck, &ephPrivForMult)

	if subtle.ConstantTimeCompare(ephPubCheck[:], ephPub[:]) != 1 {
		return nil, &V2InputError{Detail: "ephemeral public key validation failed"}
	}

	// Step 6: Decrypt payload with AES-256-GCM-SIV(key=K, nonce=zeros(12)).
	zeroNonce := make([]byte, v2NonceSize)
	var usmcBytes []byte
	err = kSecret.WithBytes(func(k []byte) error {
		var aeadErr error
		usmcBytes, aeadErr = signalcipher.AESGCMSIVDecrypt(k, zeroNonce, parsed.EncryptedPayload, nil)
		return aeadErr
	})
	if err != nil {
		return nil, &V2OperationError{Operation: "failed to decrypt payload", Err: err}
	}

	// Step 7: Deserialize the USMC.
	usmcContent, err := DeserializeUnidentifiedSenderMessageContent(usmcBytes)
	if err != nil {
		return nil, &V2OperationError{Operation: "failed to deserialize USMC", Err: err}
	}

	// Step 7.5: Validate that the sender's UUID from the certificate is a
	// well-formed ServiceId, auto-detecting ACI vs PNI from the "PNI:" prefix.
	// Rust uses ServiceId::parse_from_service_id_string which accepts both
	// prefixed and bare UUID forms; PNI-keyed sender certificates must succeed.
	senderUUID := usmcContent.Sender().SenderUUID()
	if senderUUID == "" {
		return nil, &CertificateError{Detail: "sender certificate has empty UUID"}
	}
	if _, sidErr := protocol.ServiceIdFromServiceIdString(senderUUID); sidErr != nil {
		return nil, &V2OperationError{Operation: "sender certificate has invalid ServiceId", Err: sidErr}
	}

	// Step 8: Verify sender authentication tag.
	senderKey := usmcContent.Sender().Key()
	senderPubRaw := senderKey.PublicKey() // [32]byte

	// senderShared = ECDH(ourPriv, senderPub)
	copyFromSecret(ourPriv[:], ourPrivSecret)
	senderShared, sdhErr := kdf.CalculateSharedSecret(senderPubRaw, ourPriv)
	if sdhErr != nil {
		return nil, sdhErr
	}
	defer crypto.ZeroizeArray32(&senderShared)

	// senderIkm = senderShared || ephPub.Serialize() || C_i || senderPub.Serialize() || ourPub.Serialize()
	// Uses 33-byte serialized keys (0x05 prefix) to match Rust reference.
	senderPubSerialized := v2SerializePublicKey(senderPubRaw)
	senderIkmBytes := make([]byte, 32+33+32+33+33)
	copy(senderIkmBytes[0:32], senderShared[:])
	copy(senderIkmBytes[32:65], ephPubSerialized)
	copy(senderIkmBytes[65:97], ci)
	copy(senderIkmBytes[97:130], senderPubSerialized)
	copy(senderIkmBytes[130:163], ourPubSerialized)
	senderIkmSecret, err := secret.New(senderIkmBytes)
	if err != nil {
		return nil, err
	}
	senderSharedSecret, err := secret.New(senderShared[:])
	if err != nil {
		senderIkmSecret.Destroy()
		return nil, err
	}

	expectedAT, err := deriveFromSecret(senderIkmSecret, []byte(v2HKDFDHSenderInfo), v2AuthTagSize)
	senderIkmSecret.Destroy()
	senderSharedSecret.Destroy()
	if err != nil {
		return nil, &V2OperationError{Operation: "failed to derive expected auth tag", Err: err}
	}
	expectedATSecret, err := secret.New(expectedAT)
	if err != nil {
		return nil, err
	}
	defer expectedATSecret.Destroy()

	if !expectedATSecret.EqualTo(ati) {
		return nil, &V2InputError{Detail: "sender authentication tag verification failed"}
	}

	return usmcContent, nil
}

// v2ReceivedMinSize is the minimum size of a v2 received message body (after version byte):
// C(32) + AT(16) + E.pub(32) = 80 bytes, plus at least 1 byte of ciphertext.
const v2ReceivedMinSize = v2EncryptedMKeySize + v2AuthTagSize + 32 + 1

// V2ReceivedMessage represents a parsed v2 single-recipient received message.
// This is the format that servers deliver to individual clients after extracting
// the per-recipient data from the multi-recipient sent format.
//
// Wire format: version(1) || C(32) || AT(16) || E.pub(32) || ciphertext
type V2ReceivedMessage struct {
	Version          byte
	EncryptedMKey    []byte // 32 bytes - C (per-recipient encrypted M)
	AuthTag          []byte // 16 bytes - AT (authentication tag)
	EphemeralPublic  []byte // 32 bytes - E.pub (ephemeral public key)
	EncryptedPayload []byte // remaining bytes - common ciphertext
}

// v2ParseReceivedMessage parses a v2 received (single-recipient) message.
// The received format is: version(1) || C(32) || AT(16) || E.pub(32) || ciphertext.
//
// This is the format described by UnidentifiedSenderMessage::deserialize in the
// Rust reference for v2 messages (major version 2, version bytes 0x22 or 0x23).
func v2ParseReceivedMessage(data []byte) (*V2ReceivedMessage, error) {
	if len(data) < 1 {
		return nil, ErrV2ReceivedMessageTooShort
	}

	version := data[0]
	majorVersion := version >> 4
	if majorVersion != 2 {
		return nil, ErrV2ReceivedUnsupportedVersion
	}

	remaining := data[1:]
	if len(remaining) < v2ReceivedMinSize {
		return nil, ErrV2ReceivedMessageTooShort
	}

	offset := 0

	encryptedMKey := make([]byte, v2EncryptedMKeySize)
	copy(encryptedMKey, remaining[offset:offset+v2EncryptedMKeySize])
	offset += v2EncryptedMKeySize

	authTag := make([]byte, v2AuthTagSize)
	copy(authTag, remaining[offset:offset+v2AuthTagSize])
	offset += v2AuthTagSize

	ephPub := make([]byte, 32)
	copy(ephPub, remaining[offset:offset+32])
	offset += 32

	encryptedPayload := make([]byte, len(remaining)-offset)
	copy(encryptedPayload, remaining[offset:])

	return &V2ReceivedMessage{
		Version:          version,
		EncryptedMKey:    encryptedMKey,
		AuthTag:          authTag,
		EphemeralPublic:  ephPub,
		EncryptedPayload: encryptedPayload,
	}, nil
}

// V2BuildReceivedMessage constructs a v2 received (single-recipient) message
// from the per-recipient data extracted from a sent format message.
// This simulates what the server does when fanning out to individual clients.
//
// The Rust reference always uses SEALED_SENDER_V2_UUID_FULL_VERSION (0x22) for
// the received message format because the ReceivedMessage format has not changed
// since that version. The version parameter is accepted for API compatibility
// but is ignored; 0x22 is always used.
//
// Wire format: version(1) || C(32) || AT(16) || E.pub(32) || ciphertext
func V2BuildReceivedMessage(_ byte, encryptedMKey, authTag, ephPub, encryptedPayload []byte) []byte {
	buf := make([]byte, 0, 1+len(encryptedMKey)+len(authTag)+len(ephPub)+len(encryptedPayload))
	buf = append(buf, SealedSenderV2VersionUUID)
	buf = append(buf, encryptedMKey...)
	buf = append(buf, authTag...)
	buf = append(buf, ephPub...)
	buf = append(buf, encryptedPayload...)
	return buf
}

// SealedSenderV2DecryptReceivedToUSMC decrypts a v2 received (single-recipient)
// message to extract the UnidentifiedSenderMessageContent.
//
// The received format is what servers deliver to individual clients:
//
//	version(1) || C(32) || AT(16) || E.pub(32) || ciphertext
//
// This performs the same cryptographic operations as SealedSenderV2DecryptToUSMC
// but parses the received format instead of the multi-recipient sent format.
func SealedSenderV2DecryptReceivedToUSMC(
	ciphertext []byte,
	identityStore store.IdentityKey,
) (*UnidentifiedSenderMessageContent, error) {
	received, err := v2ParseReceivedMessage(ciphertext)
	if err != nil {
		return nil, err
	}

	ci := received.EncryptedMKey
	ati := received.AuthTag

	ourIdentity := identityStore.GetIdentityKeyPair()
	ourPrivArr := ourIdentity.PrivateKey().Serialize()
	ourPrivSecret, err := secret.New(ourPrivArr[:])
	if err != nil {
		return nil, err
	}
	defer ourPrivSecret.Destroy()
	ourPub := ourIdentity.PublicKey().PublicKey().PublicKey() // [32]byte raw

	var ephPub [32]byte
	copy(ephPub[:], received.EphemeralPublic)

	// Step 1: shared = ECDH(ephPub, ourPriv)
	var ourPriv [32]byte
	copyFromSecret(ourPriv[:], ourPrivSecret)
	defer crypto.ZeroizeArray32(&ourPriv)
	shared, dhErr := kdf.CalculateSharedSecret(ephPub, ourPriv)
	if dhErr != nil {
		return nil, dhErr
	}
	defer crypto.ZeroizeArray32(&shared)
	sharedSecret, err := secret.New(shared[:])
	if err != nil {
		return nil, err
	}
	defer sharedSecret.Destroy()

	// Step 2: M = dhKey XOR C_i
	ephPubSerialized := v2SerializePublicKey(ephPub)
	ourPubSerialized := v2SerializePublicKey(ourPub)
	ikmBytes := make([]byte, 32+33+33)
	copyFromSecret(ikmBytes[0:32], sharedSecret)
	copy(ikmBytes[32:65], ephPubSerialized)
	copy(ikmBytes[65:98], ourPubSerialized)
	ikmSecret, err := secret.New(ikmBytes)
	if err != nil {
		return nil, err
	}

	dhKeyRaw, err := deriveFromSecret(ikmSecret, []byte(v2HKDFDHInfo), 32)
	ikmSecret.Destroy()
	if err != nil {
		return nil, ErrV2ReceivedDecryptFailed
	}
	dhKeySecret, err := secret.New(dhKeyRaw)
	if err != nil {
		return nil, err
	}

	var mRecovered [v2MSize]byte
	_ = dhKeySecret.WithBytes(func(dhKey []byte) error {
		subtle.XORBytes(mRecovered[:], dhKey, ci)
		return nil
	})
	dhKeySecret.Destroy()
	defer crypto.ZeroizeArray32(&mRecovered)

	mRecoveredSecret, err := secret.New(mRecovered[:])
	if err != nil {
		return nil, err
	}
	defer mRecoveredSecret.Destroy()

	// Step 3: r = HKDF(ikm=M, info="Sealed Sender v2: r (2023-08)", len=32)
	rRaw, err := deriveFromSecret(mRecoveredSecret, []byte(v2HKDFRInfo), 32)
	if err != nil {
		return nil, ErrV2ReceivedDecryptFailed
	}
	rSecret, err := secret.New(rRaw)
	if err != nil {
		return nil, err
	}
	defer rSecret.Destroy()

	// Step 4: K = HKDF(ikm=M, info="Sealed Sender v2: K", len=32)
	kRaw, err := deriveFromSecret(mRecoveredSecret, []byte(v2HKDFKInfo), 32)
	if err != nil {
		return nil, ErrV2ReceivedDecryptFailed
	}
	kSecret, err := secret.New(kRaw)
	if err != nil {
		return nil, err
	}
	defer kSecret.Destroy()

	// Step 5: Validate ephemeral key: derive E' from r, verify E'.public == E.public.
	var ephPrivCheck [32]byte
	copyFromSecret(ephPrivCheck[:], rSecret)
	ephPrivCheck[0] &= 248
	ephPrivCheck[31] &= 127
	ephPrivCheck[31] |= 64
	defer crypto.ZeroizeArray32(&ephPrivCheck)
	ephPrivCheckSecret, err := secret.New(ephPrivCheck[:])
	if err != nil {
		return nil, err
	}

	var ephPrivForMult [32]byte
	copyFromSecret(ephPrivForMult[:], ephPrivCheckSecret)
	ephPrivCheckSecret.Destroy()
	defer crypto.ZeroizeArray32(&ephPrivForMult)

	var ephPubCheck [32]byte
	curve25519.ScalarBaseMult(&ephPubCheck, &ephPrivForMult)

	if subtle.ConstantTimeCompare(ephPubCheck[:], ephPub[:]) != 1 {
		return nil, ErrV2ReceivedEphemeralKeyMismatch
	}

	// Step 6: Decrypt payload with AES-256-GCM-SIV(key=K, nonce=zeros(12)).
	zeroNonce := make([]byte, v2NonceSize)
	var usmcBytes []byte
	err = kSecret.WithBytes(func(k []byte) error {
		var aeadErr error
		usmcBytes, aeadErr = signalcipher.AESGCMSIVDecrypt(k, zeroNonce, received.EncryptedPayload, nil)
		return aeadErr
	})
	if err != nil {
		return nil, ErrV2ReceivedDecryptFailed
	}

	// Step 7: Deserialize the USMC.
	usmcContent, err := DeserializeUnidentifiedSenderMessageContent(usmcBytes)
	if err != nil {
		return nil, ErrV2ReceivedDeserializeFailed
	}

	// Step 7.5: Validate that the sender's UUID from the certificate is a
	// well-formed ServiceId, auto-detecting ACI vs PNI from the "PNI:" prefix.
	// Rust uses ServiceId::parse_from_service_id_string which accepts both
	// prefixed and bare UUID forms; PNI-keyed sender certificates must succeed.
	// Without this check, a malformed certificate could pass AT verification
	// (which only binds the identity key) but carry an invalid sender UUID
	// that would cause failures downstream.
	senderUUID := usmcContent.Sender().SenderUUID()
	if senderUUID == "" {
		return nil, ErrV2ReceivedDeserializeFailed
	}
	if _, sidErr := protocol.ServiceIdFromServiceIdString(senderUUID); sidErr != nil {
		return nil, ErrV2ReceivedDeserializeFailed
	}

	// Step 8: Verify sender authentication tag.
	senderKey := usmcContent.Sender().Key()
	senderPubRaw := senderKey.PublicKey() // [32]byte

	copyFromSecret(ourPriv[:], ourPrivSecret)
	senderShared, sdhErr := kdf.CalculateSharedSecret(senderPubRaw, ourPriv)
	if sdhErr != nil {
		return nil, sdhErr
	}
	defer crypto.ZeroizeArray32(&senderShared)

	senderPubSerialized := v2SerializePublicKey(senderPubRaw)
	senderIkmBytes := make([]byte, 32+33+32+33+33)
	copy(senderIkmBytes[0:32], senderShared[:])
	copy(senderIkmBytes[32:65], ephPubSerialized)
	copy(senderIkmBytes[65:97], ci)
	copy(senderIkmBytes[97:130], senderPubSerialized)
	copy(senderIkmBytes[130:163], ourPubSerialized)
	senderIkmSecret, err := secret.New(senderIkmBytes)
	if err != nil {
		return nil, err
	}
	senderSharedSecret, err := secret.New(senderShared[:])
	if err != nil {
		senderIkmSecret.Destroy()
		return nil, err
	}

	expectedAT, err := deriveFromSecret(senderIkmSecret, []byte(v2HKDFDHSenderInfo), v2AuthTagSize)
	senderIkmSecret.Destroy()
	senderSharedSecret.Destroy()
	if err != nil {
		return nil, ErrV2ReceivedAuthTagMismatch
	}
	expectedATSecret, err := secret.New(expectedAT)
	if err != nil {
		return nil, err
	}
	defer expectedATSecret.Destroy()

	if !expectedATSecret.EqualTo(ati) {
		return nil, ErrV2ReceivedAuthTagMismatch
	}

	return usmcContent, nil
}

// v2ParseMessage parses the body (after version byte) of a v2 multi-recipient message.
//
// The wire format uses the Rust reference encoding:
//   - Recipient count as varint (includes excluded recipients)
//   - Per recipient: ServiceId + device entries + C_i + AT_i
//   - Device entries use single-byte device IDs with a has_more bit (0x8000) in
//     the registration ID field
//   - A device_id of 0 signals an excluded recipient (no further device data or C_i/AT_i)
func v2ParseMessage(data []byte, version byte) (*SealedSenderV2SentMessage, error) {
	offset := 0

	// Read recipient count.
	recipientCount, n := binary.Uvarint(data[offset:])
	if n <= 0 {
		return nil, &V2ParseError{Detail: "failed to read recipient count varint"}
	}
	offset += n

	// Rust caps only the IndexMap *preallocation* at 6000; it never rejects
	// a message based on recipient count. We mirror that: use a bounded
	// preallocation but do not return an error for large counts. Callers
	// (e.g. server policy enforcement) may impose their own cap after parsing.
	const v2MaxPreallocRecipients = 6000
	preallocCap := recipientCount
	if preallocCap > v2MaxPreallocRecipients {
		preallocCap = v2MaxPreallocRecipients
	}

	recipients := make(map[string]*SealedSenderV2SentMessageRecipient, preallocCap)
	recipientOrder := make([]string, 0, preallocCap)

	for i := uint64(0); i < recipientCount; i++ {
		// Parse ServiceId based on version.
		var sid protocol.ServiceId
		if version == SealedSenderV2VersionUUID {
			// Version 0x22: raw 16-byte UUID, interpreted as ACI.
			if offset+v2UUIDSize > len(data) {
				return nil, &V2ParseError{Detail: "truncated UUID"}
			}
			var uuidBytes [16]byte
			copy(uuidBytes[:], data[offset:offset+v2UUIDSize])
			sid = protocol.NewACI(uuidBytes)
			offset += v2UUIDSize
		} else {
			// Version 0x23: 17-byte fixed-width ServiceId.
			if offset+v2ServiceIdSize > len(data) {
				return nil, &V2ParseError{Detail: "truncated service ID"}
			}
			var sidBytes [v2ServiceIdSize]byte
			copy(sidBytes[:], data[offset:offset+v2ServiceIdSize])
			offset += v2ServiceIdSize

			var err error
			sid, err = protocol.ServiceIdFromFixedWidthBinary(sidBytes)
			if err != nil {
				return nil, &V2ParseError{Detail: "invalid service ID", Err: err}
			}
		}

		// Read device entries using the has_more bit protocol.
		// Each device entry: device_id (1 byte u8) + registration_id (2 bytes u16 BE).
		// Bit 15 (0x8000) of registration_id = has_more devices for this recipient.
		// A device_id of 0 as the first entry means this is an excluded recipient.
		var deviceIDs []uint32
		var regIDs []uint16

		for {
			// Read device_id (single byte).
			if offset >= len(data) {
				return nil, &V2ParseError{Detail: "truncated device ID"}
			}
			deviceID := data[offset]
			offset++

			// device_id = 0 means excluded recipient (no devices).
			if deviceID == 0 {
				if len(deviceIDs) > 0 {
					return nil, &V2ParseError{Detail: "device_id 0 after non-empty device list"}
				}
				break
			}

			// Read registration_id with has_more bit.
			if offset+2 > len(data) {
				return nil, &V2ParseError{Detail: "truncated registration ID"}
			}
			regIDRaw := binary.BigEndian.Uint16(data[offset : offset+2])
			offset += 2

			deviceIDs = append(deviceIDs, uint32(deviceID))
			regIDs = append(regIDs, regIDRaw&v2ValidRegistrationIDMask)

			// Check has_more bit to determine if more devices follow.
			hasMore := (regIDRaw & v2HasMoreDevicesBit) != 0
			if !hasMore {
				break
			}
		}

		sidKey := sid.String()

		if len(deviceIDs) > 0 {
			// Active recipient: read C_i and AT_i, then insert or merge.
			perRecipientSize := v2EncryptedMKeySize + v2AuthTagSize
			if offset+perRecipientSize > len(data) {
				return nil, &V2ParseError{Detail: "truncated per-recipient data"}
			}

			keyMaterialOffset := offset
			encryptedM := make([]byte, v2EncryptedMKeySize)
			copy(encryptedM, data[offset:offset+v2EncryptedMKeySize])
			offset += v2EncryptedMKeySize

			authTag := make([]byte, v2AuthTagSize)
			copy(authTag, data[offset:offset+v2AuthTagSize])
			offset += v2AuthTagSize

			existing, ok := recipients[sidKey]
			if ok {
				// Multiple entries for the same ServiceId: merge device lists.
				// Rust mirrors this; an existing empty entry (excluded recipient)
				// paired with a non-empty one is a protocol error.
				if len(existing.DeviceIDs) == 0 || len(deviceIDs) == 0 {
					return nil, &V2ParseError{Detail: "recipient redundantly encoded as empty"}
				}
				existing.DeviceIDs = append(existing.DeviceIDs, deviceIDs...)
				existing.RegistrationIDs = append(existing.RegistrationIDs, regIDs...)
			} else {
				recipients[sidKey] = &SealedSenderV2SentMessageRecipient{
					DeviceIDs:         deviceIDs,
					RegistrationIDs:   regIDs,
					EncryptedMKey:     encryptedM,
					AuthTag:           authTag,
					KeyMaterialOffset: keyMaterialOffset,
					KeyMaterialLength: perRecipientSize,
				}
				recipientOrder = append(recipientOrder, sidKey)
			}
		} else {
			// Excluded recipient (device_id == 0): insert into the map with empty
			// device/key-material so callers can distinguish "explicitly excluded"
			// from "not in message". Mirrors Rust's IndexMap insert with
			// devices:[] and c_and_at:[] for excluded entries.
			// Inserting a second excluded entry for the same ServiceId is an error
			// (matches Rust's "recipient redundantly encoded as empty" check).
			if existing, ok := recipients[sidKey]; ok {
				if len(existing.DeviceIDs) == 0 {
					return nil, &V2ParseError{Detail: "recipient redundantly encoded as empty"}
				}
				// Active recipient preceded by excluded — also an error per Rust.
				return nil, &V2ParseError{Detail: "recipient redundantly encoded as empty"}
			}
			recipients[sidKey] = &SealedSenderV2SentMessageRecipient{}
			recipientOrder = append(recipientOrder, sidKey)
		}
	}

	// Ephemeral public key (32 bytes).
	if offset+32 > len(data) {
		return nil, &V2ParseError{Detail: "truncated ephemeral public key"}
	}
	sharedBytesOffset := offset
	ephPub := make([]byte, 32)
	copy(ephPub, data[offset:offset+32])
	offset += 32

	// Remaining bytes are the encrypted payload.
	if offset >= len(data) {
		return nil, &V2ParseError{Detail: "missing encrypted payload"}
	}
	encryptedPayload := make([]byte, len(data)-offset)
	copy(encryptedPayload, data[offset:])

	return &SealedSenderV2SentMessage{
		Recipients:        recipients,
		EphemeralPublic:   ephPub,
		EncryptedPayload:  encryptedPayload,
		RecipientOrder:    recipientOrder,
		sharedBytesOffset: sharedBytesOffset,
	}, nil
}
