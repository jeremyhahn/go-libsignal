package sealed

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/logger"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/sealedpb"
	"google.golang.org/protobuf/proto"
)

// ServerCertificate represents a server's signing certificate.
// It contains the server's public key and a signature produced
// by the trust root private key.
//
// Mirrors the Rust libsignal type ServerCertificate at
// rust/protocol/src/sealed_sender.rs. Wire format (protobuf-encoded
// outer envelope with inner Certificate plus XEdDSA signature) is
// byte-identical with the Rust reference; do not introduce JSON or
// other ad-hoc encodings — server-side certificate signing in
// go-signal must construct this type and serialize via Serialize().
type ServerCertificate struct {
	serialized  []byte
	keyID       uint32
	key         ecc.ECPublicKeyable
	certificate []byte // inner Certificate protobuf bytes
	signature   []byte // Ed25519 signature by trust root
}

// NewServerCertificate creates a new ServerCertificate, signing the inner
// certificate with the provided trust root private key.
//
// This is the canonical, Rust-byte-compatible constructor; go-signal must
// call this rather than reimplementing certificate signing with raw
// ed25519 or HMAC.
func NewServerCertificate(keyID uint32, key ecc.ECPublicKeyable, trustRoot ecc.ECPrivateKeyable) (*ServerCertificate, error) {
	// Build the inner Certificate protobuf.
	innerCert := &sealedpb.ServerCertificate_Certificate{
		Id:  proto.Uint32(keyID),
		Key: key.Serialize(),
	}
	certBytes, err := proto.Marshal(innerCert)
	if err != nil {
		return nil, err
	}

	// Sign the certificate bytes with the trust root.
	sig, err := ecc.CalculateSignature(trustRoot, certBytes)
	if err != nil {
		return nil, err
	}

	// Build the outer ServerCertificate protobuf.
	outerPB := &sealedpb.ServerCertificate{
		Certificate: certBytes,
		Signature:   sig[:],
	}
	serialized, err := proto.Marshal(outerPB)
	if err != nil {
		return nil, err
	}

	return &ServerCertificate{
		serialized:  serialized,
		keyID:       keyID,
		key:         key,
		certificate: certBytes,
		signature:   sig[:],
	}, nil
}

// DeserializeServerCertificate reconstructs a ServerCertificate from
// protobuf-encoded bytes.
func DeserializeServerCertificate(data []byte) (*ServerCertificate, error) {
	outerPB := &sealedpb.ServerCertificate{}
	if err := proto.Unmarshal(data, outerPB); err != nil {
		return nil, err
	}

	certBytes := outerPB.GetCertificate()
	sigBytes := outerPB.GetSignature()
	if certBytes == nil || sigBytes == nil {
		return nil, &CertificateError{Detail: "server certificate missing certificate or signature"}
	}

	innerCert := &sealedpb.ServerCertificate_Certificate{}
	if err := proto.Unmarshal(certBytes, innerCert); err != nil {
		return nil, err
	}

	keyBytes := innerCert.GetKey()
	if len(keyBytes) < 1 {
		return nil, &CertificateError{Detail: "server certificate missing key"}
	}

	pubKey, err := ecc.DecodePoint(keyBytes, 0)
	if err != nil {
		return nil, err
	}

	return &ServerCertificate{
		serialized:  data,
		keyID:       innerCert.GetId(),
		key:         pubKey,
		certificate: certBytes,
		signature:   sigBytes,
	}, nil
}

// revokedServerCertificateKeyIDs contains server certificate key IDs that have
// been revoked and must be rejected during validation. Per the Rust reference,
// 0xDEADC357 is a test ID used to verify revocation logic. If a production
// certificate is ever revoked, its key ID should be added here.
var revokedServerCertificateKeyIDs = []uint32{0xDEADC357}

// Validate checks that the server certificate is not revoked and that its
// signature is valid against the given trust root public key.
func (sc *ServerCertificate) Validate(trustRoot ecc.ECPublicKeyable) (bool, error) {
	// Check for revoked server certificate key IDs before verifying the signature.
	// Rust returns Ok(false) and logs the revocation; revocation is a normal
	// validation failure, not an error condition.
	for _, revokedID := range revokedServerCertificateKeyIDs {
		if sc.keyID == revokedID {
			logger.Error(fmt.Sprintf("sealed: received server certificate with revoked ID 0x%X", sc.keyID))
			return false, nil
		}
	}

	// Rust's verify_signature converts the slice to a [u8; 64] via try_into()
	// and returns false (not an error) on a length mismatch. Match that:
	// a wrong-length signature is treated as a failed verification, not a
	// structural error.
	if len(sc.signature) != 64 {
		return false, nil
	}
	var sig [64]byte
	copy(sig[:], sc.signature)
	return ecc.VerifySignature(trustRoot, sc.certificate, sig), nil
}

// KeyID returns the server certificate's key identifier.
func (sc *ServerCertificate) KeyID() uint32 {
	return sc.keyID
}

// Key returns the server certificate's public key.
func (sc *ServerCertificate) Key() ecc.ECPublicKeyable {
	return sc.key
}

// Serialize returns the full protobuf-encoded ServerCertificate bytes.
func (sc *ServerCertificate) Serialize() []byte {
	return sc.serialized
}

// Certificate returns the raw inner Certificate protobuf bytes (the
// blob that was signed by the trust root).
//
// Mirrors Rust libsignal's ServerCertificate::certificate at
// rust/protocol/src/sealed_sender.rs.
func (sc *ServerCertificate) Certificate() []byte {
	return sc.certificate
}

// Signature returns the raw Ed25519 signature bytes produced by the
// trust root over the inner Certificate blob.
//
// Mirrors Rust libsignal's ServerCertificate::signature at
// rust/protocol/src/sealed_sender.rs.
func (sc *ServerCertificate) Signature() []byte {
	return sc.signature
}

// senderCertificateSigner represents the signer of a SenderCertificate,
// which is either an embedded ServerCertificate or a reference to a
// well-known server certificate by its key ID.
type senderCertificateSigner struct {
	embedded *ServerCertificate // non-nil when the full cert is embedded
	refID    uint32             // used when embedded is nil (reference by ID)
}

// SenderCertificate represents a sender's certificate, signed by a
// server certificate's key. It contains the sender's identity key,
// UUID, optional phone number, device ID, and expiration.
//
// Mirrors the Rust libsignal type SenderCertificate at
// rust/protocol/src/sealed_sender.rs. Wire format is byte-identical with
// the Rust reference. go-signal's CertificatesManager must build sender
// certificates via NewSenderCertificate and emit Serialize() bytes; raw
// ed25519/HMAC signing of ad-hoc JSON payloads is forbidden because it
// produces a non-Signal-compatible byte format.
type SenderCertificate struct {
	serialized   []byte
	signer       senderCertificateSigner
	key          ecc.ECPublicKeyable
	senderUUID   string
	senderE164   *string
	senderDevice uint32
	expiration   uint64
	certificate  []byte // inner Certificate protobuf bytes
	signature    []byte // signature by server cert's key
}

// NewSenderCertificate creates a new SenderCertificate, signing the inner
// certificate with the provided server signing key.
//
// This is the canonical, Rust-byte-compatible constructor; go-signal must
// call this rather than reimplementing certificate signing with raw
// ed25519 or HMAC. The signerKey is the *server* certificate's signing
// private key (not the trust root); the resulting SenderCertificate
// chains up to the ServerCertificate that holds the corresponding
// public key.
func NewSenderCertificate(
	senderUUID string,
	senderE164 *string,
	key ecc.ECPublicKeyable,
	senderDevice uint32,
	expiration uint64,
	signer *ServerCertificate,
	signerKey ecc.ECPrivateKeyable,
) (*SenderCertificate, error) {
	// Build the inner SenderCertificate.Certificate protobuf.
	innerCert := &sealedpb.SenderCertificate_Certificate{
		SenderUuid: &sealedpb.SenderCertificate_Certificate_UuidString{
			UuidString: senderUUID,
		},
		SenderDevice: proto.Uint32(senderDevice),
		Expires:      proto.Uint64(expiration),
		IdentityKey:  key.Serialize(),
		Signer: &sealedpb.SenderCertificate_Certificate_Certificate{
			Certificate: signer.Serialize(),
		},
	}
	if senderE164 != nil {
		innerCert.SenderE164 = senderE164
	}

	certBytes, err := proto.Marshal(innerCert)
	if err != nil {
		return nil, err
	}

	// Sign the certificate bytes with the server's signing key.
	sig, err := ecc.CalculateSignature(signerKey, certBytes)
	if err != nil {
		return nil, err
	}

	// Build the outer SenderCertificate protobuf.
	outerPB := &sealedpb.SenderCertificate{
		Certificate: certBytes,
		Signature:   sig[:],
	}
	serialized, err := proto.Marshal(outerPB)
	if err != nil {
		return nil, err
	}

	return &SenderCertificate{
		serialized:   serialized,
		signer:       senderCertificateSigner{embedded: signer},
		key:          key,
		senderUUID:   senderUUID,
		senderE164:   senderE164,
		senderDevice: senderDevice,
		expiration:   expiration,
		certificate:  certBytes,
		signature:    sig[:],
	}, nil
}

// DeserializeSenderCertificate reconstructs a SenderCertificate from
// protobuf-encoded bytes.
func DeserializeSenderCertificate(data []byte) (*SenderCertificate, error) {
	outerPB := &sealedpb.SenderCertificate{}
	if err := proto.Unmarshal(data, outerPB); err != nil {
		return nil, err
	}

	certBytes := outerPB.GetCertificate()
	sigBytes := outerPB.GetSignature()
	if certBytes == nil || sigBytes == nil {
		return nil, &CertificateError{Detail: "sender certificate missing certificate or signature"}
	}

	innerCert := &sealedpb.SenderCertificate_Certificate{}
	if err := proto.Unmarshal(certBytes, innerCert); err != nil {
		return nil, err
	}

	identityKeyBytes := innerCert.GetIdentityKey()
	if len(identityKeyBytes) < 1 {
		return nil, &CertificateError{Detail: "sender certificate missing identity key"}
	}

	identityKey, err := ecc.DecodePoint(identityKeyBytes, 0)
	if err != nil {
		return nil, err
	}

	// Resolve the signer: either an embedded ServerCertificate or a reference ID.
	var signer senderCertificateSigner
	switch s := innerCert.GetSigner().(type) {
	case *sealedpb.SenderCertificate_Certificate_Certificate:
		cert, err := DeserializeServerCertificate(s.Certificate)
		if err != nil {
			return nil, err
		}
		signer = senderCertificateSigner{embedded: cert}
	case *sealedpb.SenderCertificate_Certificate_Id:
		signer = senderCertificateSigner{refID: s.Id}
	default:
		return nil, &CertificateError{Detail: "sender certificate missing signer certificate"}
	}

	// Reject device_id=0, matching the Rust reference which uses NonZeroU8
	// for DeviceId. The TryFrom<u32> for DeviceId fails on 0, causing
	// deserialization to return InvalidProtobufEncoding.
	if innerCert.GetSenderDevice() == 0 {
		return nil, ErrInvalidDeviceID
	}

	var senderE164 *string
	if innerCert.SenderE164 != nil {
		e164 := innerCert.GetSenderE164()
		senderE164 = &e164
	}

	// Resolve the sender UUID from the oneof field.
	// Use a type switch on the oneof interface rather than comparing the string
	// value to "": GetUuidString() returns "" both when the UuidString variant
	// is unset AND when it is explicitly set to "", making == "" ambiguous.
	var senderUUID string
	switch uuidOneof := innerCert.GetSenderUuid().(type) {
	case *sealedpb.SenderCertificate_Certificate_UuidString:
		// Accept the UuidString value verbatim, including the empty string "".
		// Rust libsignal (rust/protocol/src/sealed_sender.rs:246-248) takes the
		// string as-is from the oneof without rejecting empty values.
		senderUUID = uuidOneof.UuidString
	case *sealedpb.SenderCertificate_Certificate_UuidBytes:
		uuidBytes := uuidOneof.UuidBytes
		if len(uuidBytes) == 16 {
			senderUUID = fmt.Sprintf("%s-%s-%s-%s-%s",
				hex.EncodeToString(uuidBytes[0:4]),
				hex.EncodeToString(uuidBytes[4:6]),
				hex.EncodeToString(uuidBytes[6:8]),
				hex.EncodeToString(uuidBytes[8:10]),
				hex.EncodeToString(uuidBytes[10:16]),
			)
		} else {
			return nil, &CertificateError{Detail: fmt.Sprintf("sender certificate UuidBytes has invalid length: %d", len(uuidBytes))}
		}
	default:
		return nil, &CertificateError{Detail: "sender certificate missing sender UUID"}
	}

	return &SenderCertificate{
		serialized:   data,
		signer:       signer,
		key:          identityKey,
		senderUUID:   senderUUID,
		senderE164:   senderE164,
		senderDevice: innerCert.GetSenderDevice(),
		expiration:   innerCert.GetExpires(),
		certificate:  certBytes,
		signature:    sigBytes,
	}, nil
}

// Validate checks:
//  1. The server certificate validates against the trust root.
//  2. The sender certificate signature is valid (signed by the server cert's key).
//  3. The certificate has not expired relative to validationTime.
//
// Validate is a thin wrapper around ValidateWithTrustRoots with a single root.
func (sc *SenderCertificate) Validate(trustRoot ecc.ECPublicKeyable, validationTime uint64) (bool, error) {
	return sc.ValidateWithTrustRoots([]ecc.ECPublicKeyable{trustRoot}, validationTime)
}

// ValidateWithTrustRoots validates the sender certificate against a slice of
// trust roots. It returns true when any root in roots produces a valid chain.
//
// Mirrors Rust libsignal's SenderCertificate::validate_with_trust_roots at
// rust/protocol/src/sealed_sender.rs. The Rust implementation uses a
// constant-time fold over all roots (libsignal_core::ct_equal / subtle::Choice)
// so that timing does not reveal which root matched. This implementation
// accumulates success with subtle.ConstantTimeSelect to preserve that invariant:
// every root is always verified regardless of prior results, and the final
// boolean is assembled with constant-time integer operations even when the
// server-cert signature length check returns early — that check is structural,
// not secret-dependent.
//
// Validation steps:
//  1. Per-root: server certificate signature verified against each trust root
//     (constant-time accumulation; all roots always evaluated).
//  2. Sender certificate signature verified against the server cert's key.
//  3. Expiration check against validationTime.
func (sc *SenderCertificate) ValidateWithTrustRoots(roots []ecc.ECPublicKeyable, validationTime uint64) (bool, error) {
	if len(roots) == 0 {
		return false, nil
	}

	// Resolve the server certificate once — it is the same for all root checks.
	serverCert, err := sc.Signer()
	if err != nil {
		return false, err
	}

	// Rust's verify_signature returns false (not error) on wrong-length signatures
	// (try_into fails → returns false). Match that: a wrong-length sender-cert
	// signature is a failed verification, not a structural error.
	if len(sc.signature) != 64 {
		return false, nil
	}
	var senderSig [64]byte
	copy(senderSig[:], sc.signature)

	// Constant-time accumulator: 1 when any root validates the server cert.
	// Every root is evaluated unconditionally to prevent timing side-channels
	// from revealing which root (if any) matched.
	serverValid := 0
	for _, root := range roots {
		ok, verErr := serverCert.Validate(root)
		if verErr != nil {
			// A structural error (e.g. revocation) is a hard failure.
			return false, verErr
		}
		bit := 0
		if ok {
			bit = 1
		}
		serverValid = subtle.ConstantTimeSelect(bit, 1, serverValid)
	}

	if serverValid != 1 {
		logger.Error("sender certificate contained server certificate not signed by any trust root")
		return false, nil
	}

	// Verify sender signature against the server cert's key.
	if !ecc.VerifySignature(serverCert.Key(), sc.certificate, senderSig) {
		logger.Error("sender certificate not signed by server")
		return false, nil
	}

	// Expiration check.
	if validationTime > sc.expiration {
		logger.Error(fmt.Sprintf("sender certificate is expired (expiration: %d, validation_time: %d)",
			sc.expiration, validationTime))
		return false, nil
	}

	return true, nil
}

// SenderUUID returns the sender's UUID.
func (sc *SenderCertificate) SenderUUID() string {
	return sc.senderUUID
}

// SenderE164 returns the sender's optional phone number.
func (sc *SenderCertificate) SenderE164() *string {
	return sc.senderE164
}

// Key returns the sender's identity public key.
func (sc *SenderCertificate) Key() ecc.ECPublicKeyable {
	return sc.key
}

// SenderDevice returns the sender's device ID.
func (sc *SenderCertificate) SenderDevice() uint32 {
	return sc.senderDevice
}

// Expiration returns the certificate expiration in milliseconds since epoch.
func (sc *SenderCertificate) Expiration() uint64 {
	return sc.expiration
}

// Serialize returns the full protobuf-encoded SenderCertificate bytes.
func (sc *SenderCertificate) Serialize() []byte {
	return sc.serialized
}

// Certificate returns the raw inner Certificate protobuf bytes (the
// blob that was signed by the server certificate's key).
//
// Mirrors Rust libsignal's SenderCertificate::certificate at
// rust/protocol/src/sealed_sender.rs.
func (sc *SenderCertificate) Certificate() []byte {
	return sc.certificate
}

// Signature returns the raw signature bytes produced by the server
// certificate's key over the inner Certificate blob.
//
// Mirrors Rust libsignal's SenderCertificate::signature at
// rust/protocol/src/sealed_sender.rs.
func (sc *SenderCertificate) Signature() []byte {
	return sc.signature
}

// Signer resolves and returns the server certificate that signed this sender
// certificate. For embedded signers, this returns the certificate directly.
// For referenced signers, this performs a lookup in the known server
// certificates table and returns an error if the ID is not recognized.
func (sc *SenderCertificate) Signer() (*ServerCertificate, error) {
	if sc.signer.embedded != nil {
		return sc.signer.embedded, nil
	}
	return lookupKnownServerCertificate(sc.signer.refID)
}
