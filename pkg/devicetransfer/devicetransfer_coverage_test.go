package devicetransfer

import (
	"testing"
)

func TestCreateRSAPrivateKey_TinyBitsError(t *testing.T) {
	// RSA key generation with bits=1 should fail because Go's rsa.GenerateKey
	// requires at least 2 bits.
	_, err := CreateRSAPrivateKey(1, KeyFormatPKCS8)
	if err == nil {
		t.Fatal("expected error for 1-bit RSA key generation")
	}
}

func TestCreateRSAPrivateKey_TinyBitsErrorPKCS1(t *testing.T) {
	// Also test with PKCS1 format to ensure the error path before
	// the format switch is exercised.
	_, err := CreateRSAPrivateKey(1, KeyFormatPKCS1)
	if err == nil {
		t.Fatal("expected error for 1-bit RSA key generation with PKCS1")
	}
}

func TestCreateSelfSignedCert_PKCS1Key(t *testing.T) {
	// Exercise the PKCS#1 fallback path in CreateSelfSignedCert by passing
	// a PKCS#1 encoded key directly (not via PEM).
	der, err := CreateRSAPrivateKey(2048, KeyFormatPKCS1)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey: %v", err)
	}
	certDER, err := CreateSelfSignedCert(der, "PKCS1 Direct", 30)
	if err != nil {
		t.Fatalf("CreateSelfSignedCert with PKCS1 key: %v", err)
	}
	if len(certDER) == 0 {
		t.Fatal("expected non-empty certificate DER")
	}
}

func TestCreateRSAPrivateKey_ZeroBitsDefaultsTo4096(t *testing.T) {
	// bits=0 should default to DefaultKeyBits (4096). We just verify no error;
	// key generation at 4096 bits is slow but tests the default path.
	der, err := CreateRSAPrivateKey(0, KeyFormatPKCS1)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey(0): %v", err)
	}
	if len(der) == 0 {
		t.Fatal("expected non-empty DER output")
	}
}
