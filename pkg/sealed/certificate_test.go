package sealed

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/sealedpb"
	"google.golang.org/protobuf/proto"
)

func newTestTrustRoot(t *testing.T) *ecc.ECKeyPair {
	t.Helper()
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate trust root key pair: %v", err)
	}
	return kp
}

func newTestServerCertificate(t *testing.T, trustRoot *ecc.ECKeyPair) (*ServerCertificate, *ecc.ECKeyPair) {
	t.Helper()
	serverKey, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate server key pair: %v", err)
	}
	cert, err := NewServerCertificate(1, serverKey.PublicKey(), trustRoot.PrivateKey())
	if err != nil {
		t.Fatalf("NewServerCertificate() error: %v", err)
	}
	return cert, serverKey
}

func TestNewServerCertificate(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestServerCertificate(t, trustRoot)

	if cert.KeyID() != 1 {
		t.Errorf("KeyID() = %d, want 1", cert.KeyID())
	}
	if cert.Key() == nil {
		t.Fatal("Key() should not be nil")
	}
	if len(cert.Serialize()) == 0 {
		t.Fatal("Serialize() should not be empty")
	}
}

func TestServerCertificateValidate(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestServerCertificate(t, trustRoot)

	t.Run("valid trust root", func(t *testing.T) {
		valid, err := cert.Validate(trustRoot.PublicKey())
		if err != nil {
			t.Fatalf("Validate() error: %v", err)
		}
		if !valid {
			t.Error("Validate() should return true for correct trust root")
		}
	})

	t.Run("wrong trust root", func(t *testing.T) {
		wrongRoot := newTestTrustRoot(t)
		valid, err := cert.Validate(wrongRoot.PublicKey())
		if err != nil {
			t.Fatalf("Validate() error: %v", err)
		}
		if valid {
			t.Error("Validate() should return false for wrong trust root")
		}
	})
}

func TestServerCertificateValidateInvalidSignature(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestServerCertificate(t, trustRoot)

	// Tamper with signature length. Rust's verify_signature returns false
	// (not error) for wrong-length signatures (try_into fails → returns false).
	// Go matches: wrong-length sig is a failed verification, not a struct error.
	cert.signature = make([]byte, 10) // wrong length
	valid, err := cert.Validate(trustRoot.PublicKey())
	if err != nil {
		t.Errorf("Validate with wrong-length signature should not error: %v", err)
	}
	if valid {
		t.Error("Validate with wrong-length signature should return false")
	}
}

func TestDeserializeServerCertificate(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestServerCertificate(t, trustRoot)

	serialized := cert.Serialize()
	restored, err := DeserializeServerCertificate(serialized)
	if err != nil {
		t.Fatalf("DeserializeServerCertificate() error: %v", err)
	}

	if restored.KeyID() != cert.KeyID() {
		t.Errorf("Restored KeyID() = %d, want %d", restored.KeyID(), cert.KeyID())
	}
	if restored.Key() == nil {
		t.Fatal("Restored Key() should not be nil")
	}
}

func TestDeserializeServerCertificateInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty bytes", []byte{}},
		{"invalid protobuf", []byte{0xFF, 0xFF, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeServerCertificate(tt.input)
			if err == nil {
				t.Error("DeserializeServerCertificate with invalid input should return error")
			}
		})
	}
}

func newTestSenderCertificate(t *testing.T, trustRoot *ecc.ECKeyPair) (*SenderCertificate, *ecc.ECKeyPair) {
	t.Helper()
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderKey, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate sender key pair: %v", err)
	}

	e164 := "+15555555555"
	senderCert, err := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a",
		&e164,
		senderKey.PublicKey(),
		1,
		9999999999,
		serverCert,
		serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate() error: %v", err)
	}
	return senderCert, senderKey
}

func TestNewSenderCertificate(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	if cert.SenderUUID() != "9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a" {
		t.Errorf("SenderUUID() = %q, want %q", cert.SenderUUID(), "9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a")
	}
	if cert.SenderE164() == nil {
		t.Fatal("SenderE164() should not be nil")
	}
	if *cert.SenderE164() != "+15555555555" {
		t.Errorf("SenderE164() = %q, want %q", *cert.SenderE164(), "+15555555555")
	}
	if cert.SenderDevice() != 1 {
		t.Errorf("SenderDevice() = %d, want 1", cert.SenderDevice())
	}
	if cert.Expiration() != 9999999999 {
		t.Errorf("Expiration() = %d, want 9999999999", cert.Expiration())
	}
	if cert.Key() == nil {
		t.Fatal("Key() should not be nil")
	}
	signer, err := cert.Signer()
	if err != nil {
		t.Fatalf("Signer() error: %v", err)
	}
	if signer == nil {
		t.Fatal("Signer() should not be nil")
	}
	if len(cert.Serialize()) == 0 {
		t.Fatal("Serialize() should not be empty")
	}
}

func TestNewSenderCertificateWithoutE164(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderKey, _ := ecc.GenerateKeyPair()
	cert, err := NewSenderCertificate(
		"9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a",
		nil,
		senderKey.PublicKey(),
		1,
		9999999999,
		serverCert,
		serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate() error: %v", err)
	}
	if cert.SenderE164() != nil {
		t.Error("SenderE164() should be nil when not provided")
	}
}

func TestSenderCertificateValidate(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	t.Run("valid", func(t *testing.T) {
		valid, err := cert.Validate(trustRoot.PublicKey(), 1000)
		if err != nil {
			t.Fatalf("Validate() error: %v", err)
		}
		if !valid {
			t.Error("Validate() should return true for valid cert")
		}
	})

	t.Run("wrong trust root", func(t *testing.T) {
		wrongRoot := newTestTrustRoot(t)
		valid, err := cert.Validate(wrongRoot.PublicKey(), 1000)
		if err != nil {
			t.Fatalf("Validate() unexpected error: %v", err)
		}
		if valid {
			t.Error("Validate() should return false for wrong trust root")
		}
	})

	t.Run("expired", func(t *testing.T) {
		valid, err := cert.Validate(trustRoot.PublicKey(), 99999999999)
		if err != nil {
			t.Fatalf("Validate() unexpected error: %v", err)
		}
		if valid {
			t.Error("Validate() should return false for expired cert")
		}
	})
}

func TestSenderCertificateValidateInvalidSignature(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	// Tamper with signature to have wrong length. Rust's verify_signature
	// returns false (not error) for wrong-length sigs. Go matches.
	cert.signature = make([]byte, 10)
	valid, err := cert.Validate(trustRoot.PublicKey(), 1000)
	if err != nil {
		t.Errorf("Validate with wrong-length sender sig should not error: %v", err)
	}
	if valid {
		t.Error("Validate with wrong-length sender sig should return false")
	}
}

func TestSenderCertificateValidateBadSignature(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	// Tamper with signature content but keep length 64
	cert.signature = make([]byte, 64) // all zeros = invalid
	valid, err := cert.Validate(trustRoot.PublicKey(), 1000)
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if valid {
		t.Error("Validate() should return false for tampered signature")
	}
}

func TestDeserializeSenderCertificate(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	serialized := cert.Serialize()
	restored, err := DeserializeSenderCertificate(serialized)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate() error: %v", err)
	}

	if restored.SenderUUID() != cert.SenderUUID() {
		t.Errorf("Restored SenderUUID() = %q, want %q", restored.SenderUUID(), cert.SenderUUID())
	}
	if restored.SenderDevice() != cert.SenderDevice() {
		t.Errorf("Restored SenderDevice() = %d, want %d", restored.SenderDevice(), cert.SenderDevice())
	}
	if restored.Expiration() != cert.Expiration() {
		t.Errorf("Restored Expiration() = %d, want %d", restored.Expiration(), cert.Expiration())
	}
	restoredSigner, err := restored.Signer()
	if err != nil {
		t.Fatalf("Signer() error: %v", err)
	}
	if restoredSigner == nil {
		t.Fatal("Restored Signer() should not be nil")
	}
}

func TestDeserializeSenderCertificateInvalid(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty bytes", []byte{}},
		{"invalid protobuf", []byte{0xFF, 0xFF, 0xFF}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DeserializeSenderCertificate(tt.input)
			if err == nil {
				t.Error("DeserializeSenderCertificate with invalid input should return error")
			}
		})
	}
}

func TestDeserializeServerCertificateMissingFields(t *testing.T) {
	t.Run("missing certificate and signature", func(t *testing.T) {
		// Outer protobuf with nil certificate and signature.
		outer := &sealedpb.ServerCertificate{}
		data, err := proto.Marshal(outer)
		if err != nil {
			t.Fatalf("proto.Marshal error: %v", err)
		}
		_, err = DeserializeServerCertificate(data)
		if err == nil {
			t.Error("Should error when certificate and signature are missing")
		}
	})

	t.Run("missing key in inner cert", func(t *testing.T) {
		// Build an outer cert with a valid inner cert that has no key.
		inner := &sealedpb.ServerCertificate_Certificate{
			Id: proto.Uint32(1),
			// Key is nil
		}
		innerBytes, _ := proto.Marshal(inner)
		outer := &sealedpb.ServerCertificate{
			Certificate: innerBytes,
			Signature:   make([]byte, 64),
		}
		data, _ := proto.Marshal(outer)
		_, err := DeserializeServerCertificate(data)
		if err == nil {
			t.Error("Should error when key is missing from inner certificate")
		}
	})
}

func TestDeserializeServerCertificateCorruptInnerCert(t *testing.T) {
	// Cover the inner cert unmarshal error path (line 75).
	outer := &sealedpb.ServerCertificate{
		Certificate: []byte{0xFF, 0xFF, 0xFF, 0xFF}, // invalid protobuf
		Signature:   make([]byte, 64),
	}
	data, _ := proto.Marshal(outer)
	_, err := DeserializeServerCertificate(data)
	if err == nil {
		t.Error("Should error when inner certificate bytes are corrupt")
	}
}

func TestDeserializeSenderCertificateCorruptInnerCert(t *testing.T) {
	// Cover the inner cert unmarshal error path (line 215).
	outer := &sealedpb.SenderCertificate{
		Certificate: []byte{0xFF, 0xFF, 0xFF, 0xFF}, // invalid protobuf
		Signature:   make([]byte, 64),
	}
	data, _ := proto.Marshal(outer)
	_, err := DeserializeSenderCertificate(data)
	if err == nil {
		t.Error("Should error when inner certificate bytes are corrupt")
	}
}

func TestDeserializeSenderCertificateInvalidIdentityKey(t *testing.T) {
	// Cover the ecc.DecodePoint error path (line 225).
	inner := &sealedpb.SenderCertificate_Certificate{
		SenderDevice: proto.Uint32(1),
		IdentityKey:  []byte{0x99, 0x01, 0x02}, // invalid key (bad type prefix)
	}
	innerBytes, _ := proto.Marshal(inner)
	outer := &sealedpb.SenderCertificate{
		Certificate: innerBytes,
		Signature:   make([]byte, 64),
	}
	data, _ := proto.Marshal(outer)
	_, err := DeserializeSenderCertificate(data)
	if err == nil {
		t.Error("Should error when identity key is invalid")
	}
}

func TestDeserializeServerCertificateInvalidKey(t *testing.T) {
	// Cover the ecc.DecodePoint error path (line 85).
	inner := &sealedpb.ServerCertificate_Certificate{
		Id:  proto.Uint32(1),
		Key: []byte{0x99, 0x01, 0x02}, // invalid key (bad type prefix)
	}
	innerBytes, _ := proto.Marshal(inner)
	outer := &sealedpb.ServerCertificate{
		Certificate: innerBytes,
		Signature:   make([]byte, 64),
	}
	data, _ := proto.Marshal(outer)
	_, err := DeserializeServerCertificate(data)
	if err == nil {
		t.Error("Should error when key has invalid format")
	}
}

func TestDeserializeSenderCertificateMissingFields(t *testing.T) {
	t.Run("missing certificate and signature", func(t *testing.T) {
		outer := &sealedpb.SenderCertificate{}
		data, _ := proto.Marshal(outer)
		_, err := DeserializeSenderCertificate(data)
		if err == nil {
			t.Error("Should error when certificate and signature are missing")
		}
	})

	t.Run("missing identity key", func(t *testing.T) {
		inner := &sealedpb.SenderCertificate_Certificate{
			SenderDevice: proto.Uint32(1),
			// IdentityKey is nil
		}
		innerBytes, _ := proto.Marshal(inner)
		outer := &sealedpb.SenderCertificate{
			Certificate: innerBytes,
			Signature:   make([]byte, 64),
		}
		data, _ := proto.Marshal(outer)
		_, err := DeserializeSenderCertificate(data)
		if err == nil {
			t.Error("Should error when identity key is missing")
		}
	})

	t.Run("missing signer certificate", func(t *testing.T) {
		// Build a sender cert inner that has an identity key but no signer.
		kp, _ := ecc.GenerateKeyPair()
		inner := &sealedpb.SenderCertificate_Certificate{
			SenderDevice: proto.Uint32(1),
			IdentityKey:  kp.PublicKey().Serialize(),
			// Signer (Certificate oneof) is nil
		}
		innerBytes, _ := proto.Marshal(inner)
		outer := &sealedpb.SenderCertificate{
			Certificate: innerBytes,
			Signature:   make([]byte, 64),
		}
		data, _ := proto.Marshal(outer)
		_, err := DeserializeSenderCertificate(data)
		if err == nil {
			t.Error("Should error when signer certificate is missing")
		}
	})
}

func TestSenderCertificateValidateServerInvalid(t *testing.T) {
	// Create a sender cert where the server cert has an invalid signature
	// for the trust root. Rust returns Ok(false) for this case.
	trustRoot := newTestTrustRoot(t)
	wrongRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	// Validate against wrong root should return (false, nil).
	valid, err := cert.Validate(wrongRoot.PublicKey(), 1000)
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if valid {
		t.Error("Validate() should return false when server cert does not match trust root")
	}
}

func TestServerCertificateValidateReturnsFalse(t *testing.T) {
	// Ensure ServerCertificate.Validate returns (false, nil) for wrong trust root.
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestServerCertificate(t, trustRoot)

	wrongRoot := newTestTrustRoot(t)
	valid, err := cert.Validate(wrongRoot.PublicKey())
	if err != nil {
		t.Fatalf("Validate() unexpected error: %v", err)
	}
	if valid {
		t.Error("Validate() should return false for wrong trust root")
	}
}

func TestSenderCertificateValidateServerSignatureInvalid(t *testing.T) {
	// When the embedded server cert's signature has wrong length, Rust
	// verify_signature returns false (not error). ValidateWithTrustRoots
	// sees serverValid=0 and returns (false, nil) with a log line.
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	cert.signer.embedded.signature = make([]byte, 10) // wrong length
	valid, err := cert.Validate(trustRoot.PublicKey(), 1000)
	if err != nil {
		t.Errorf("Validate should not error when server cert has wrong-length sig: %v", err)
	}
	if valid {
		t.Error("Validate should return false when server cert has wrong-length sig")
	}
}

func TestDeserializeSenderCertificateCorruptSigner(t *testing.T) {
	// Cover the DeserializeServerCertificate error path at line 235.
	kp, _ := ecc.GenerateKeyPair()
	inner := &sealedpb.SenderCertificate_Certificate{
		SenderDevice: proto.Uint32(1),
		IdentityKey:  kp.PublicKey().Serialize(),
		Signer: &sealedpb.SenderCertificate_Certificate_Certificate{
			Certificate: []byte{0xFF, 0xFF, 0xFF}, // corrupt server cert bytes
		},
	}
	innerBytes, _ := proto.Marshal(inner)
	outer := &sealedpb.SenderCertificate{
		Certificate: innerBytes,
		Signature:   make([]byte, 64),
	}
	data, _ := proto.Marshal(outer)
	_, err := DeserializeSenderCertificate(data)
	if err == nil {
		t.Error("Should error when signer certificate bytes are corrupt")
	}
}

func TestDeserializeSenderCertificateDeviceIDZero(t *testing.T) {
	// Device ID 0 should be rejected during deserialization, matching the
	// Rust reference which uses NonZeroU8 for DeviceId.
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderKey, _ := ecc.GenerateKeyPair()
	inner := &sealedpb.SenderCertificate_Certificate{
		SenderUuid:   &sealedpb.SenderCertificate_Certificate_UuidString{UuidString: "test-uuid"},
		SenderDevice: proto.Uint32(0), // invalid device ID
		Expires:      proto.Uint64(9999999999),
		IdentityKey:  senderKey.PublicKey().Serialize(),
		Signer: &sealedpb.SenderCertificate_Certificate_Certificate{
			Certificate: serverCert.Serialize(),
		},
	}
	innerBytes, _ := proto.Marshal(inner)

	sig, _ := ecc.CalculateSignature(serverKey.PrivateKey(), innerBytes)
	outer := &sealedpb.SenderCertificate{
		Certificate: innerBytes,
		Signature:   sig[:],
	}
	data, _ := proto.Marshal(outer)

	_, err := DeserializeSenderCertificate(data)
	if err == nil {
		t.Fatal("DeserializeSenderCertificate should reject device_id=0")
	}
	if !errors.Is(err, ErrInvalidDeviceID) {
		t.Errorf("error = %v, want ErrInvalidDeviceID", err)
	}
}

func TestDeserializeSenderCertificateDeviceIDValid(t *testing.T) {
	// Device ID 1 should be accepted during deserialization.
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	serialized := cert.Serialize()
	restored, err := DeserializeSenderCertificate(serialized)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate() error: %v", err)
	}
	if restored.SenderDevice() != 1 {
		t.Errorf("SenderDevice() = %d, want 1", restored.SenderDevice())
	}
}

func TestDeserializeSenderCertificateRoundTrip(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	original, _ := newTestSenderCertificate(t, trustRoot)

	serialized := original.Serialize()
	restored, err := DeserializeSenderCertificate(serialized)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate() error: %v", err)
	}

	// Validate restored cert
	valid, err := restored.Validate(trustRoot.PublicKey(), 1000)
	if err != nil {
		t.Fatalf("Validate restored cert error: %v", err)
	}
	if !valid {
		t.Error("Restored cert should validate successfully")
	}
}

// --- ValidateWithTrustRoots tests (#23) ---

// TestValidateWithTrustRoots_FirstRootMatches verifies that a sender certificate
// validates successfully when the first root in the list matches the server cert.
func TestValidateWithTrustRoots_FirstRootMatches(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	other1, _ := ecc.GenerateKeyPair()
	other2, _ := ecc.GenerateKeyPair()

	roots := []ecc.ECPublicKeyable{trustRoot.PublicKey(), other1.PublicKey(), other2.PublicKey()}
	valid, err := cert.ValidateWithTrustRoots(roots, 1000)
	if err != nil {
		t.Fatalf("ValidateWithTrustRoots() error: %v", err)
	}
	if !valid {
		t.Error("ValidateWithTrustRoots() should return true when first root matches")
	}
}

// TestValidateWithTrustRoots_LastRootMatches verifies that a sender certificate
// validates when only the last root in the list matches. This exercises the
// constant-time accumulation across multiple non-matching roots.
func TestValidateWithTrustRoots_LastRootMatches(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	other1, _ := ecc.GenerateKeyPair()
	other2, _ := ecc.GenerateKeyPair()

	roots := []ecc.ECPublicKeyable{other1.PublicKey(), other2.PublicKey(), trustRoot.PublicKey()}
	valid, err := cert.ValidateWithTrustRoots(roots, 1000)
	if err != nil {
		t.Fatalf("ValidateWithTrustRoots() error: %v", err)
	}
	if !valid {
		t.Error("ValidateWithTrustRoots() should return true when last root matches")
	}
}

// TestValidateWithTrustRoots_NoRootMatches verifies that the cert is rejected
// when no root in the list matches the server certificate.
func TestValidateWithTrustRoots_NoRootMatches(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	wrong1, _ := ecc.GenerateKeyPair()
	wrong2, _ := ecc.GenerateKeyPair()

	roots := []ecc.ECPublicKeyable{wrong1.PublicKey(), wrong2.PublicKey()}
	valid, err := cert.ValidateWithTrustRoots(roots, 1000)
	if err != nil {
		t.Fatalf("ValidateWithTrustRoots() unexpected error: %v", err)
	}
	if valid {
		t.Error("ValidateWithTrustRoots() should return false when no root matches")
	}
}

// TestValidateWithTrustRoots_EmptyRoots verifies that an empty root list
// returns (false, nil) without panicking.
func TestValidateWithTrustRoots_EmptyRoots(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	valid, err := cert.ValidateWithTrustRoots([]ecc.ECPublicKeyable{}, 1000)
	if err != nil {
		t.Fatalf("ValidateWithTrustRoots() unexpected error: %v", err)
	}
	if valid {
		t.Error("ValidateWithTrustRoots() should return false for empty root list")
	}
}

// TestValidateWithTrustRoots_AllRootsEvaluated verifies that all roots are
// evaluated (constant-time) even when the first root already matches.
// Indirectly verified by confirming the result is correct for a 1-of-3 case.
func TestValidateWithTrustRoots_AllRootsEvaluated(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	wrong, _ := ecc.GenerateKeyPair()

	// Two wrong roots flanking the real root.
	roots := []ecc.ECPublicKeyable{wrong.PublicKey(), trustRoot.PublicKey(), wrong.PublicKey()}
	valid, err := cert.ValidateWithTrustRoots(roots, 1000)
	if err != nil {
		t.Fatalf("ValidateWithTrustRoots() error: %v", err)
	}
	if !valid {
		t.Error("ValidateWithTrustRoots() should return true when middle root matches")
	}
}

// TestValidateWithTrustRoots_Expired verifies that an expired certificate is
// rejected even when the root matches.
func TestValidateWithTrustRoots_Expired(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	// validationTime > cert.Expiration() (9999999999).
	valid, err := cert.ValidateWithTrustRoots([]ecc.ECPublicKeyable{trustRoot.PublicKey()}, 99999999999)
	if err != nil {
		t.Fatalf("ValidateWithTrustRoots() unexpected error: %v", err)
	}
	if valid {
		t.Error("ValidateWithTrustRoots() should return false for expired certificate")
	}
}

// TestValidateWithTrustRoots_InvalidSignatureLength verifies that a wrong-length
// sender cert signature returns (false, nil), matching Rust's verify_signature
// which returns false (not error) when try_into for the [u8;64] array fails.
func TestValidateWithTrustRoots_InvalidSignatureLength(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	cert.signature = make([]byte, 10) // wrong length
	valid, err := cert.ValidateWithTrustRoots([]ecc.ECPublicKeyable{trustRoot.PublicKey()}, 1000)
	if err != nil {
		t.Errorf("ValidateWithTrustRoots() must not error for wrong-length sig: %v", err)
	}
	if valid {
		t.Error("ValidateWithTrustRoots() must return false for wrong-length sig")
	}
}

// --- PNI sender certificate decrypt tests (#22) ---

// newTestPNISenderCertificate creates a sender certificate whose UUID field
// is a PNI-prefixed ServiceId string (e.g. "PNI:9d0652a3-...").
// This tests that the Step 7.5 validation in v2 decrypt accepts PNI senders.
func newTestPNISenderCertificate(t *testing.T, trustRoot *ecc.ECKeyPair) *SenderCertificate {
	t.Helper()
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderKey, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// A PNI-prefixed UUID string, matching Rust's PNI ServiceId format.
	pniUUID := "PNI:9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a"

	cert, err := NewSenderCertificate(
		pniUUID,
		nil,
		senderKey.PublicKey(),
		1,
		9999999999,
		serverCert,
		serverKey.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate (PNI): %v", err)
	}
	return cert
}

// TestPNISenderCertificateValidate verifies that a sender certificate carrying
// a PNI-prefixed UUID validates correctly against the trust root.
// This is the precondition for the v2 Step 7.5 PNI acceptance fix.
func TestPNISenderCertificateValidate(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert := newTestPNISenderCertificate(t, trustRoot)

	valid, err := cert.Validate(trustRoot.PublicKey(), 1000)
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if !valid {
		t.Error("Validate() should return true for a PNI-keyed sender certificate")
	}
}

// TestPNISenderCertificateRoundTrip verifies that a PNI sender certificate
// serializes and deserializes correctly, preserving the PNI UUID string.
func TestPNISenderCertificateRoundTrip(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert := newTestPNISenderCertificate(t, trustRoot)

	serialized := cert.Serialize()
	restored, err := DeserializeSenderCertificate(serialized)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate: %v", err)
	}

	if got := restored.SenderUUID(); got != "PNI:9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a" {
		t.Errorf("SenderUUID: got %q, want %q", got, "PNI:9d0652a3-5b24-4e0d-b88e-8e1b2a4f8b1a")
	}
	valid, err := restored.Validate(trustRoot.PublicKey(), 1000)
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if !valid {
		t.Error("Restored PNI sender certificate should validate successfully")
	}
}

// TestServerCertificateCertificateAndSignatureAccessors verifies that the raw
// certificate and signature bytes are accessible, mirroring Rust's
// ServerCertificate::certificate and ServerCertificate::signature at
// rust/protocol/src/sealed_sender.rs.
func TestServerCertificateCertificateAndSignatureAccessors(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestServerCertificate(t, trustRoot)

	if len(cert.Certificate()) == 0 {
		t.Error("Certificate() must return non-empty inner certificate bytes")
	}
	if len(cert.Signature()) != 64 {
		t.Errorf("Signature() must return 64 bytes, got %d", len(cert.Signature()))
	}

	// Round-trip: deserialise and confirm accessors are preserved.
	restored, err := DeserializeServerCertificate(cert.Serialize())
	if err != nil {
		t.Fatalf("DeserializeServerCertificate: %v", err)
	}
	if string(restored.Certificate()) != string(cert.Certificate()) {
		t.Error("Restored Certificate() bytes differ from original")
	}
	if string(restored.Signature()) != string(cert.Signature()) {
		t.Error("Restored Signature() bytes differ from original")
	}
}

// TestSenderCertificateCertificateAndSignatureAccessors verifies that the raw
// inner certificate and signature bytes are accessible, mirroring Rust's
// SenderCertificate::certificate and SenderCertificate::signature at
// rust/protocol/src/sealed_sender.rs.
func TestSenderCertificateCertificateAndSignatureAccessors(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	if len(cert.Certificate()) == 0 {
		t.Error("Certificate() must return non-empty inner certificate bytes")
	}
	if len(cert.Signature()) != 64 {
		t.Errorf("Signature() must return 64 bytes, got %d", len(cert.Signature()))
	}

	// Round-trip: deserialise and confirm accessors are preserved.
	restored, err := DeserializeSenderCertificate(cert.Serialize())
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate: %v", err)
	}
	if string(restored.Certificate()) != string(cert.Certificate()) {
		t.Error("Restored Certificate() bytes differ from original")
	}
	if string(restored.Signature()) != string(cert.Signature()) {
		t.Error("Restored Signature() bytes differ from original")
	}
}

// TestDeserializeSenderCertificate_EmptyUuidString verifies that a sender
// certificate whose oneof SenderUuid is set to the UuidString variant with an
// empty string value "" is accepted verbatim.
//
// Rust libsignal (rust/protocol/src/sealed_sender.rs:246-248) takes the
// UuidString value as-is without rejecting empty strings, so Go must match.
// The type-switch on GetSenderUuid() still distinguishes the UuidString variant
// from an absent oneof (which returns *CertificateError via the default case).
func TestDeserializeSenderCertificate_EmptyUuidString(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderKey, _ := ecc.GenerateKeyPair()
	inner := &sealedpb.SenderCertificate_Certificate{
		// Explicitly set the UuidString variant to empty string "".
		SenderUuid:   &sealedpb.SenderCertificate_Certificate_UuidString{UuidString: ""},
		SenderDevice: proto.Uint32(1),
		Expires:      proto.Uint64(9999999999),
		IdentityKey:  senderKey.PublicKey().Serialize(),
		Signer: &sealedpb.SenderCertificate_Certificate_Certificate{
			Certificate: serverCert.Serialize(),
		},
	}
	innerBytes, _ := proto.Marshal(inner)

	sig, _ := ecc.CalculateSignature(serverKey.PrivateKey(), innerBytes)
	outer := &sealedpb.SenderCertificate{
		Certificate: innerBytes,
		Signature:   sig[:],
	}
	data, _ := proto.Marshal(outer)

	cert, err := DeserializeSenderCertificate(data)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate should accept UuidString = \"\", got error: %v", err)
	}
	if cert.SenderUUID() != "" {
		t.Errorf("SenderUUID: got %q, want empty string", cert.SenderUUID())
	}
}

// TestDeserializeSenderCertificate_UuidBytesVariant verifies that the
// UuidBytes oneof variant is decoded correctly when present.
func TestDeserializeSenderCertificate_UuidBytesVariant(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderKey, _ := ecc.GenerateKeyPair()
	uuidBytes := []byte{
		0x11, 0x11, 0x11, 0x11,
		0x11, 0x11,
		0x11, 0x11,
		0x11, 0x11,
		0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
	}
	inner := &sealedpb.SenderCertificate_Certificate{
		// Use UuidBytes variant (not UuidString).
		SenderUuid:   &sealedpb.SenderCertificate_Certificate_UuidBytes{UuidBytes: uuidBytes},
		SenderDevice: proto.Uint32(1),
		Expires:      proto.Uint64(9999999999),
		IdentityKey:  senderKey.PublicKey().Serialize(),
		Signer: &sealedpb.SenderCertificate_Certificate_Certificate{
			Certificate: serverCert.Serialize(),
		},
	}
	innerBytes, _ := proto.Marshal(inner)

	sig, _ := ecc.CalculateSignature(serverKey.PrivateKey(), innerBytes)
	outer := &sealedpb.SenderCertificate{
		Certificate: innerBytes,
		Signature:   sig[:],
	}
	data, _ := proto.Marshal(outer)

	cert, err := DeserializeSenderCertificate(data)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate with UuidBytes failed: %v", err)
	}

	// The UUID should have been formatted as "11111111-1111-1111-1111-111111111111"
	expectedUUID := "11111111-1111-1111-1111-111111111111"
	if cert.SenderUUID() != expectedUUID {
		t.Errorf("SenderUUID() = %q, want %q", cert.SenderUUID(), expectedUUID)
	}
}

// TestDeserializeSenderCertificate_UuidBytesInvalidLength verifies that
// UuidBytes with an invalid length is rejected with a CertificateError.
func TestDeserializeSenderCertificate_UuidBytesInvalidLength(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderKey, _ := ecc.GenerateKeyPair()
	inner := &sealedpb.SenderCertificate_Certificate{
		SenderUuid:   &sealedpb.SenderCertificate_Certificate_UuidBytes{UuidBytes: []byte{0x01, 0x02}},
		SenderDevice: proto.Uint32(1),
		Expires:      proto.Uint64(9999999999),
		IdentityKey:  senderKey.PublicKey().Serialize(),
		Signer: &sealedpb.SenderCertificate_Certificate_Certificate{
			Certificate: serverCert.Serialize(),
		},
	}
	innerBytes, _ := proto.Marshal(inner)

	sig, _ := ecc.CalculateSignature(serverKey.PrivateKey(), innerBytes)
	outer := &sealedpb.SenderCertificate{
		Certificate: innerBytes,
		Signature:   sig[:],
	}
	data, _ := proto.Marshal(outer)

	_, err := DeserializeSenderCertificate(data)
	if err == nil {
		t.Fatal("expected error for UuidBytes with wrong length")
	}
	var certErr *CertificateError
	if !errors.As(err, &certErr) {
		t.Errorf("expected *CertificateError, got %T: %v", err, err)
	}
}

// TestDeserializeSenderCertificate_MissingSenderUuid verifies that a sender
// certificate with no SenderUuid oneof set is rejected.
func TestDeserializeSenderCertificate_MissingSenderUuid(t *testing.T) {
	trustRoot := newTestTrustRoot(t)
	serverCert, serverKey := newTestServerCertificate(t, trustRoot)

	senderKey, _ := ecc.GenerateKeyPair()
	inner := &sealedpb.SenderCertificate_Certificate{
		// SenderUuid is nil / not set
		SenderDevice: proto.Uint32(1),
		Expires:      proto.Uint64(9999999999),
		IdentityKey:  senderKey.PublicKey().Serialize(),
		Signer: &sealedpb.SenderCertificate_Certificate_Certificate{
			Certificate: serverCert.Serialize(),
		},
	}
	innerBytes, _ := proto.Marshal(inner)

	sig, _ := ecc.CalculateSignature(serverKey.PrivateKey(), innerBytes)
	outer := &sealedpb.SenderCertificate{
		Certificate: innerBytes,
		Signature:   sig[:],
	}
	data, _ := proto.Marshal(outer)

	_, err := DeserializeSenderCertificate(data)
	if err == nil {
		t.Fatal("expected error when SenderUuid is not set")
	}
	var certErr *CertificateError
	if !errors.As(err, &certErr) {
		t.Errorf("expected *CertificateError, got %T: %v", err, err)
	}
}
