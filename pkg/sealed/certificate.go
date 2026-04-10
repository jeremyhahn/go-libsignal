package sealed

import (
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
type ServerCertificate struct {
	serialized  []byte
	keyID       uint32
	key         ecc.ECPublicKeyable
	certificate []byte // inner Certificate protobuf bytes
	signature   []byte // Ed25519 signature by trust root
}

// NewServerCertificate creates a new ServerCertificate, signing the inner
// certificate with the provided trust root private key.
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

	if len(sc.signature) != 64 {
		return false, &CertificateError{Detail: "invalid signature length"}
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

	// Resolve the sender UUID from the oneof: prefer UuidString, fall back to UuidBytes.
	senderUUID := innerCert.GetUuidString()
	if senderUUID == "" {
		uuidBytes := innerCert.GetUuidBytes()
		if len(uuidBytes) == 16 {
			senderUUID = fmt.Sprintf("%s-%s-%s-%s-%s",
				hex.EncodeToString(uuidBytes[0:4]),
				hex.EncodeToString(uuidBytes[4:6]),
				hex.EncodeToString(uuidBytes[6:8]),
				hex.EncodeToString(uuidBytes[8:10]),
				hex.EncodeToString(uuidBytes[10:16]),
			)
		} else if uuidBytes != nil {
			return nil, &CertificateError{Detail: fmt.Sprintf("sender certificate has invalid UUID bytes length: %d", len(uuidBytes))}
		} else {
			return nil, &CertificateError{Detail: "sender certificate missing sender UUID"}
		}
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
func (sc *SenderCertificate) Validate(trustRoot ecc.ECPublicKeyable, validationTime uint64) (bool, error) {
	// 1. Resolve and validate the server certificate against the trust root.
	serverCert, err := sc.Signer()
	if err != nil {
		return false, err
	}
	serverValid, err := serverCert.Validate(trustRoot)
	if err != nil {
		return false, err
	}
	if !serverValid {
		// Rust returns Ok(false) when the server certificate is not signed by the
		// trust root. This is a normal validation failure, not an internal error.
		logger.Error("sender certificate contained server certificate not signed by trust root")
		return false, nil
	}

	// 2. Verify the sender certificate signature using the server cert's key.
	if len(sc.signature) != 64 {
		// Malformed signature length is a structural/internal error.
		return false, &CertificateError{Detail: "invalid sender certificate signature length"}
	}
	var sig [64]byte
	copy(sig[:], sc.signature)
	if !ecc.VerifySignature(serverCert.Key(), sc.certificate, sig) {
		// Rust returns Ok(false) when the sender certificate signature is invalid.
		logger.Error("sender certificate not signed by server")
		return false, nil
	}

	// 3. Check expiration.
	if validationTime > sc.expiration {
		// Rust returns Ok(false) for expired certificates.
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
