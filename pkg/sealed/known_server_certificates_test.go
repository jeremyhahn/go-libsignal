package sealed

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/sealedpb"
	"google.golang.org/protobuf/proto"
)

func TestKnownServerCertificatesUniqueIDs(t *testing.T) {
	// Verify all known certificate IDs are unique. This mirrors the Rust
	// verify_known_certificates test.
	seen := make(map[uint32]bool, len(knownServerCertificateData))
	for id := range knownServerCertificateData {
		if seen[id] {
			t.Errorf("duplicate known server certificate ID: 0x%X", id)
		}
		seen[id] = true
	}
}

func TestKnownServerCertificatesValidData(t *testing.T) {
	// Verify each known certificate deserializes correctly, has the expected
	// key ID, and validates against its stored trust root.
	certs := resolvedKnownCertificates()
	if len(certs) != len(knownServerCertificateData) {
		t.Fatalf("resolved %d known certs, want %d", len(certs), len(knownServerCertificateData))
	}

	for id, entry := range certs {
		t.Run(certIDName(id), func(t *testing.T) {
			if entry.cert.KeyID() != id {
				t.Errorf("KeyID() = 0x%X, want 0x%X", entry.cert.KeyID(), id)
			}
			if entry.cert.Key() == nil {
				t.Error("Key() should not be nil")
			}
			if entry.trustRoot == nil {
				t.Error("trustRoot should not be nil")
			}

			// Validate the cert against its trust root.
			valid, err := entry.cert.Validate(entry.trustRoot)
			if err != nil {
				t.Fatalf("Validate() error: %v", err)
			}
			if !valid {
				t.Error("known cert should validate against its own trust root")
			}
		})
	}
}

func TestKnownServerCertificatesExpectedIDs(t *testing.T) {
	// Verify the exact set of expected certificate IDs is present.
	expectedIDs := []uint32{2, 3, 0x7357C357}
	certs := resolvedKnownCertificates()

	for _, id := range expectedIDs {
		if _, ok := certs[id]; !ok {
			t.Errorf("missing expected known certificate ID: 0x%X", id)
		}
	}
	if len(certs) != len(expectedIDs) {
		t.Errorf("found %d known certs, expected %d", len(certs), len(expectedIDs))
	}
}

func TestLookupKnownServerCertificateValid(t *testing.T) {
	for id := range knownServerCertificateData {
		t.Run(certIDName(id), func(t *testing.T) {
			cert, err := lookupKnownServerCertificate(id)
			if err != nil {
				t.Fatalf("lookupKnownServerCertificate(0x%X) error: %v", id, err)
			}
			if cert == nil {
				t.Fatal("returned certificate should not be nil")
			}
			if cert.KeyID() != id {
				t.Errorf("KeyID() = 0x%X, want 0x%X", cert.KeyID(), id)
			}
		})
	}
}

func TestLookupKnownServerCertificateUnknownID(t *testing.T) {
	unknownIDs := []uint32{0, 1, 99, 0xFFFFFFFF, 0xDEADBEEF}
	for _, id := range unknownIDs {
		cert, err := lookupKnownServerCertificate(id)
		if err == nil {
			t.Errorf("lookupKnownServerCertificate(0x%X) should return error", id)
		}
		if cert != nil {
			t.Errorf("lookupKnownServerCertificate(0x%X) should return nil cert", id)
		}
		if !errors.Is(err, ErrUnknownServerCertificateID) {
			t.Errorf("error should match ErrUnknownServerCertificateID, got: %v", err)
		}
	}
}

func TestDeserializeSenderCertificateWithReferencedSigner(t *testing.T) {
	// Build a SenderCertificate protobuf that uses an ID reference
	// instead of an embedded server certificate.
	senderKey, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}

	// Use the test cert ID (0x7357C357) which is a known certificate.
	testCertID := uint32(0x7357C357)

	innerCert := &sealedpb.SenderCertificate_Certificate{
		SenderUuid: &sealedpb.SenderCertificate_Certificate_UuidString{
			UuidString: "9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a",
		},
		SenderDevice: proto.Uint32(1),
		Expires:      proto.Uint64(9999999999),
		IdentityKey:  senderKey.PublicKey().Serialize(),
		Signer: &sealedpb.SenderCertificate_Certificate_Id{
			Id: testCertID,
		},
	}
	certBytes, err := proto.Marshal(innerCert)
	if err != nil {
		t.Fatalf("proto.Marshal inner cert error: %v", err)
	}

	outerPB := &sealedpb.SenderCertificate{
		Certificate: certBytes,
		Signature:   make([]byte, 64), // dummy signature for deserialization
	}
	data, err := proto.Marshal(outerPB)
	if err != nil {
		t.Fatalf("proto.Marshal outer cert error: %v", err)
	}

	sc, err := DeserializeSenderCertificate(data)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate error: %v", err)
	}

	// Signer() should resolve the reference to the known cert.
	signer, err := sc.Signer()
	if err != nil {
		t.Fatalf("Signer() error: %v", err)
	}
	if signer == nil {
		t.Fatal("Signer() should not return nil")
	}
	if signer.KeyID() != testCertID {
		t.Errorf("Signer().KeyID() = 0x%X, want 0x%X", signer.KeyID(), testCertID)
	}

	// Verify the sender cert fields are correct.
	if sc.SenderUUID() != "9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a" {
		t.Errorf("SenderUUID() = %q, want %q", sc.SenderUUID(), "9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a")
	}
	if sc.SenderDevice() != 1 {
		t.Errorf("SenderDevice() = %d, want 1", sc.SenderDevice())
	}
	if sc.Expiration() != 9999999999 {
		t.Errorf("Expiration() = %d, want 9999999999", sc.Expiration())
	}
}

func TestDeserializeSenderCertificateWithUnknownReferencedSigner(t *testing.T) {
	// Build a SenderCertificate protobuf that references an unknown cert ID.
	senderKey, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}

	innerCert := &sealedpb.SenderCertificate_Certificate{
		SenderUuid: &sealedpb.SenderCertificate_Certificate_UuidString{
			UuidString: "9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a",
		},
		SenderDevice: proto.Uint32(1),
		Expires:      proto.Uint64(9999999999),
		IdentityKey:  senderKey.PublicKey().Serialize(),
		Signer: &sealedpb.SenderCertificate_Certificate_Id{
			Id: 0xDEADBEEF, // unknown ID
		},
	}
	certBytes, err := proto.Marshal(innerCert)
	if err != nil {
		t.Fatalf("proto.Marshal inner cert error: %v", err)
	}

	outerPB := &sealedpb.SenderCertificate{
		Certificate: certBytes,
		Signature:   make([]byte, 64),
	}
	data, err := proto.Marshal(outerPB)
	if err != nil {
		t.Fatalf("proto.Marshal outer cert error: %v", err)
	}

	// Deserialization should succeed (the ID is stored, not resolved yet).
	sc, err := DeserializeSenderCertificate(data)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate error: %v", err)
	}

	// Signer() should fail because the ID is unknown.
	_, err = sc.Signer()
	if err == nil {
		t.Fatal("Signer() should return error for unknown cert ID")
	}
	if !errors.Is(err, ErrUnknownServerCertificateID) {
		t.Errorf("error should match ErrUnknownServerCertificateID, got: %v", err)
	}
}

func TestDeserializeSenderCertificateWithEmbeddedSigner(t *testing.T) {
	// Verify that the existing embedded signer path still works correctly
	// through the new oneof-aware deserialization logic.
	trustRoot := newTestTrustRoot(t)
	original, _ := newTestSenderCertificate(t, trustRoot)

	serialized := original.Serialize()
	restored, err := DeserializeSenderCertificate(serialized)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate error: %v", err)
	}

	// Signer() should return the embedded cert.
	signer, err := restored.Signer()
	if err != nil {
		t.Fatalf("Signer() error: %v", err)
	}
	if signer == nil {
		t.Fatal("Signer() should not return nil")
	}
	if signer.KeyID() != 1 {
		t.Errorf("Signer().KeyID() = %d, want 1", signer.KeyID())
	}

	// Validate should still work.
	valid, err := restored.Validate(trustRoot.PublicKey(), 1000)
	if err != nil {
		t.Fatalf("Validate error: %v", err)
	}
	if !valid {
		t.Error("restored cert should validate successfully")
	}
}

func TestSenderCertificateValidateWithReferencedSignerUnknownID(t *testing.T) {
	// Validate should return an error when the referenced cert ID is unknown.
	senderKey, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair error: %v", err)
	}

	innerCert := &sealedpb.SenderCertificate_Certificate{
		SenderUuid: &sealedpb.SenderCertificate_Certificate_UuidString{
			UuidString: "9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a",
		},
		SenderDevice: proto.Uint32(1),
		Expires:      proto.Uint64(9999999999),
		IdentityKey:  senderKey.PublicKey().Serialize(),
		Signer: &sealedpb.SenderCertificate_Certificate_Id{
			Id: 0xBADCAFE,
		},
	}
	certBytes, err := proto.Marshal(innerCert)
	if err != nil {
		t.Fatalf("proto.Marshal error: %v", err)
	}

	outerPB := &sealedpb.SenderCertificate{
		Certificate: certBytes,
		Signature:   make([]byte, 64),
	}
	data, err := proto.Marshal(outerPB)
	if err != nil {
		t.Fatalf("proto.Marshal error: %v", err)
	}

	sc, err := DeserializeSenderCertificate(data)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate error: %v", err)
	}

	trustRoot := newTestTrustRoot(t)
	_, err = sc.Validate(trustRoot.PublicKey(), 1000)
	if err == nil {
		t.Fatal("Validate should fail for unknown referenced cert ID")
	}
	if !errors.Is(err, ErrUnknownServerCertificateID) {
		t.Errorf("error should match ErrUnknownServerCertificateID, got: %v", err)
	}
}

func TestErrUnknownServerCertificateIDMessage(t *testing.T) {
	err := newUnknownServerCertificateIDError(0xDEADBEEF)
	expected := "sealed: unknown server certificate ID 0xDEADBEEF"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

func TestErrUnknownServerCertificateIDIs(t *testing.T) {
	err := newUnknownServerCertificateIDError(0x1234)
	if !errors.Is(err, ErrUnknownServerCertificateID) {
		t.Error("newUnknownServerCertificateIDError should match ErrUnknownServerCertificateID")
	}
	if errors.Is(err, ErrServerCertificateRevoked) {
		t.Error("newUnknownServerCertificateIDError should not match ErrServerCertificateRevoked")
	}
}

// certIDName returns a human-readable name for a certificate key ID.
func certIDName(id uint32) string {
	switch id {
	case 2:
		return "staging_id_2"
	case 3:
		return "production_id_3"
	case 0x7357C357:
		return "test_id_0x7357C357"
	default:
		return "unknown"
	}
}
