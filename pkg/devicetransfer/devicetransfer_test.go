package devicetransfer

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestCreateRSAPrivateKey_PKCS8(t *testing.T) {
	der, err := CreateRSAPrivateKey(2048, KeyFormatPKCS8)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey(PKCS8): %v", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed key is nil")
	}
}

func TestCreateRSAPrivateKey_PKCS1(t *testing.T) {
	der, err := CreateRSAPrivateKey(2048, KeyFormatPKCS1)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey(PKCS1): %v", err)
	}
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePKCS1PrivateKey: %v", err)
	}
	if key == nil {
		t.Fatal("parsed key is nil")
	}
}

func TestCreateRSAPrivateKey_DefaultBits(t *testing.T) {
	der, err := CreateRSAPrivateKey(0, KeyFormatPKCS8)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey(default bits): %v", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed key is nil")
	}
}

func TestCreateSelfSignedCert_PKCS8(t *testing.T) {
	keyDER, err := CreateRSAPrivateKey(2048, KeyFormatPKCS8)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey: %v", err)
	}

	certDER, err := CreateSelfSignedCert(keyDER, "Test Device", 30)
	if err != nil {
		t.Fatalf("CreateSelfSignedCert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != "Test Device" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Test Device")
	}
	// Rust reference does not set BasicConstraintsValid, KeyUsage, or ExtKeyUsage
	// on device transfer certificates, so we verify they are absent.
	if cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid should be false to match Rust reference")
	}
}

func TestCreateSelfSignedCert_PKCS1(t *testing.T) {
	keyDER, err := CreateRSAPrivateKey(2048, KeyFormatPKCS1)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey: %v", err)
	}

	certDER, err := CreateSelfSignedCert(keyDER, "PKCS1 Device", 365)
	if err != nil {
		t.Fatalf("CreateSelfSignedCert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != "PKCS1 Device" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "PKCS1 Device")
	}
}

func TestCreateRSAPrivateKeyPEM(t *testing.T) {
	for _, tc := range []struct {
		name      string
		format    KeyFormat
		blockType string
	}{
		{"PKCS8", KeyFormatPKCS8, "PRIVATE KEY"},
		{"PKCS1", KeyFormatPKCS1, "RSA PRIVATE KEY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pemBytes, err := CreateRSAPrivateKeyPEM(2048, tc.format)
			if err != nil {
				t.Fatalf("CreateRSAPrivateKeyPEM: %v", err)
			}
			block, _ := pem.Decode(pemBytes)
			if block == nil {
				t.Fatal("failed to decode PEM")
			}
			if block.Type != tc.blockType {
				t.Errorf("PEM type = %q, want %q", block.Type, tc.blockType)
			}
		})
	}
}

func TestCreateSelfSignedCertPEM(t *testing.T) {
	keyPEM, err := CreateRSAPrivateKeyPEM(2048, KeyFormatPKCS8)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKeyPEM: %v", err)
	}

	certPEM, err := CreateSelfSignedCertPEM(keyPEM, "PEM Test", 90)
	if err != nil {
		t.Fatalf("CreateSelfSignedCertPEM: %v", err)
	}

	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatal("failed to decode certificate PEM")
	}
	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM type = %q, want %q", block.Type, "CERTIFICATE")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != "PEM Test" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "PEM Test")
	}
}

func TestCreateSelfSignedCertPEM_InvalidPEM(t *testing.T) {
	_, err := CreateSelfSignedCertPEM([]byte("not pem"), "Bad", 1)
	if err == nil {
		t.Fatal("expected error for invalid PEM input")
	}
}

func TestCreateRSAPrivateKey_InvalidFormat(t *testing.T) {
	_, err := CreateRSAPrivateKey(2048, KeyFormat(99))
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}
