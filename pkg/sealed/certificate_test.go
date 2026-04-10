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

	// Tamper with signature
	cert.signature = make([]byte, 10) // wrong length
	_, err := cert.Validate(trustRoot.PublicKey())
	if err == nil {
		t.Error("Validate with invalid signature length should return error")
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

	// Tamper with signature to have wrong length
	cert.signature = make([]byte, 10)
	_, err := cert.Validate(trustRoot.PublicKey(), 1000)
	if err == nil {
		t.Error("Validate with invalid signature length should return error")
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
	// Cover the branch where server cert Validate returns err (invalid sig length).
	trustRoot := newTestTrustRoot(t)
	cert, _ := newTestSenderCertificate(t, trustRoot)

	// Tamper with the signer's signature length to trigger an error from
	// ServerCertificate.Validate.
	cert.signer.embedded.signature = make([]byte, 10) // invalid length
	_, err := cert.Validate(trustRoot.PublicKey(), 1000)
	if err == nil {
		t.Error("Validate should fail when server cert has invalid signature length")
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
