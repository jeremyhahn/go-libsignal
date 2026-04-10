package devicetransfer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCreateSelfSignedCert_InvalidKey(t *testing.T) {
	_, err := CreateSelfSignedCert([]byte("not a valid key"), "Test", 30)
	if err == nil {
		t.Fatal("expected error for invalid key DER")
	}
}

func TestCreateRSAPrivateKeyPEM_InvalidFormat(t *testing.T) {
	_, err := CreateRSAPrivateKeyPEM(2048, KeyFormat(99))
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestCreateSelfSignedCertPEM_PKCS1(t *testing.T) {
	keyPEM, err := CreateRSAPrivateKeyPEM(2048, KeyFormatPKCS1)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKeyPEM: %v", err)
	}

	certPEM, err := CreateSelfSignedCertPEM(keyPEM, "PKCS1 PEM Test", 90)
	if err != nil {
		t.Fatalf("CreateSelfSignedCertPEM: %v", err)
	}
	if len(certPEM) == 0 {
		t.Fatal("expected non-empty PEM output")
	}
}

func TestParseRSAPrivateKey_PKCS8(t *testing.T) {
	der, err := CreateRSAPrivateKey(2048, KeyFormatPKCS8)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey: %v", err)
	}
	key, err := parseRSAPrivateKey(der)
	if err != nil {
		t.Fatalf("parseRSAPrivateKey(PKCS8): %v", err)
	}
	if key == nil {
		t.Fatal("parsed key is nil")
	}
}

func TestParseRSAPrivateKey_PKCS1(t *testing.T) {
	der, err := CreateRSAPrivateKey(2048, KeyFormatPKCS1)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey: %v", err)
	}
	key, err := parseRSAPrivateKey(der)
	if err != nil {
		t.Fatalf("parseRSAPrivateKey(PKCS1): %v", err)
	}
	if key == nil {
		t.Fatal("parsed key is nil")
	}
}

func TestParseRSAPrivateKey_Invalid(t *testing.T) {
	_, err := parseRSAPrivateKey([]byte("garbage"))
	if err == nil {
		t.Fatal("expected error for invalid DER data")
	}
}

func TestParseRSAPrivateKey_NonRSAPKCS8(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	_, err = parseRSAPrivateKey(der)
	if err == nil {
		t.Fatal("expected error for non-RSA PKCS#8 key")
	}
	if !strings.Contains(err.Error(), "not RSA") {
		t.Errorf("error = %v, want to contain 'not RSA'", err)
	}
}

func TestCreateSelfSignedCertPEM_InvalidKeyInPEM(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	_, err = CreateSelfSignedCertPEM(pemBytes, "Invalid", 30)
	if err == nil {
		t.Fatal("expected error for non-RSA key in PEM")
	}
}

func TestCreateSelfSignedCert_NonRSAKey(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	_, err = CreateSelfSignedCert(der, "ECKey", 30)
	if err == nil {
		t.Fatal("expected error for non-RSA key")
	}
}

func TestCreateSelfSignedCert_ValidityPeriod(t *testing.T) {
	keyDER, err := CreateRSAPrivateKey(2048, KeyFormatPKCS8)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey: %v", err)
	}

	certDER, err := CreateSelfSignedCert(keyDER, "Validity Test", 365)
	if err != nil {
		t.Fatalf("CreateSelfSignedCert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	duration := cert.NotAfter.Sub(cert.NotBefore)
	// NotBefore is set to now - 24h for clock skew, so the total span is ~366 days.
	if duration.Hours() < 365*24 || duration.Hours() > 367*24 {
		t.Errorf("validity period = %v hours, want ~366 days (365 days + 24h clock skew buffer)", duration.Hours())
	}
}

func TestCreateRSAPrivateKey_NegativeBits(t *testing.T) {
	der, err := CreateRSAPrivateKey(-1, KeyFormatPKCS8)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey(-1): %v", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	if parsed == nil {
		t.Fatal("parsed key is nil")
	}
}

// --- GenerateRSASigner tests ---

func TestGenerateRSASigner_HappyPath(t *testing.T) {
	signer, err := GenerateRSASigner(2048)
	if err != nil {
		t.Fatalf("GenerateRSASigner: %v", err)
	}
	defer signer.Destroy()

	pub := signer.Public()
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected *rsa.PublicKey from signer.Public()")
	}
	if rsaPub.N.BitLen() < 2048 {
		t.Errorf("key size = %d bits, want >= 2048", rsaPub.N.BitLen())
	}
}

func TestGenerateRSASigner_BelowMinKeyBitsUsesDefault(t *testing.T) {
	// bits < MinKeyBits (2048) should default to DefaultKeyBits (4096)
	signer, err := GenerateRSASigner(1024)
	if err != nil {
		t.Fatalf("GenerateRSASigner: %v", err)
	}
	defer signer.Destroy()

	rsaPub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected *rsa.PublicKey")
	}
	if rsaPub.N.BitLen() != DefaultKeyBits {
		t.Errorf("key size = %d bits, want %d (DefaultKeyBits)", rsaPub.N.BitLen(), DefaultKeyBits)
	}
}

func TestGenerateRSASigner_ZeroBitsUsesDefault(t *testing.T) {
	signer, err := GenerateRSASigner(0)
	if err != nil {
		t.Fatalf("GenerateRSASigner(0): %v", err)
	}
	defer signer.Destroy()

	rsaPub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected *rsa.PublicKey")
	}
	if rsaPub.N.BitLen() != DefaultKeyBits {
		t.Errorf("key size = %d bits, want %d", rsaPub.N.BitLen(), DefaultKeyBits)
	}
}

// --- CreateSelfSignedCertWithSigner tests ---

func TestCreateSelfSignedCertWithSigner_HappyPath(t *testing.T) {
	signer, err := GenerateRSASigner(2048)
	if err != nil {
		t.Fatalf("GenerateRSASigner: %v", err)
	}
	defer signer.Destroy()

	certDER, err := CreateSelfSignedCertWithSigner(signer, "Signer Test", 30)
	if err != nil {
		t.Fatalf("CreateSelfSignedCertWithSigner: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if cert.Subject.CommonName != "Signer Test" {
		t.Errorf("CommonName = %q, want %q", cert.Subject.CommonName, "Signer Test")
	}
	// Rust reference does not set BasicConstraintsValid, KeyUsage, or ExtKeyUsage
	// on device transfer certificates, so we verify they are absent.
	if cert.BasicConstraintsValid {
		t.Error("BasicConstraintsValid should be false to match Rust reference")
	}
}

func TestCreateSelfSignedCertWithSigner_NilSigner(t *testing.T) {
	_, err := CreateSelfSignedCertWithSigner(nil, "Should Fail", 30)
	if err == nil {
		t.Fatal("expected error for nil signer")
	}
	if !errors.Is(err, ErrNilSigner) {
		t.Errorf("error = %v, want ErrNilSigner", err)
	}
}

func TestCreateSelfSignedCertWithSigner_ValidityPeriod(t *testing.T) {
	signer, err := GenerateRSASigner(2048)
	if err != nil {
		t.Fatalf("GenerateRSASigner: %v", err)
	}
	defer signer.Destroy()

	certDER, err := CreateSelfSignedCertWithSigner(signer, "Period Test", 365)
	if err != nil {
		t.Fatalf("CreateSelfSignedCertWithSigner: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	duration := cert.NotAfter.Sub(cert.NotBefore)
	// NotBefore is set to now - 24h for clock skew, so the total span is ~366 days.
	if duration.Hours() < 365*24 || duration.Hours() > 367*24 {
		t.Errorf("validity period = %v hours, want ~366 days (365 days + 24h clock skew buffer)", duration.Hours())
	}
}

// --- Error type tests ---

func TestError_Is_MatchingKind(t *testing.T) {
	err := newKeyGenerationError(fmt.Errorf("some cause"))
	if !errors.Is(err, ErrKeyGeneration) {
		t.Error("expected errors.Is to match ErrKeyGeneration")
	}
}

func TestError_Is_DifferentKind(t *testing.T) {
	err := newKeyGenerationError(fmt.Errorf("some cause"))
	if errors.Is(err, ErrCertCreation) {
		t.Error("expected errors.Is to NOT match ErrCertCreation")
	}
}

func TestError_Is_NonErrorTarget(t *testing.T) {
	err := newKeyGenerationError(fmt.Errorf("some cause"))
	if errors.Is(err, fmt.Errorf("random error")) {
		t.Error("expected errors.Is to NOT match a non-*Error target")
	}
}

func TestError_Unwrap_WithWrappedError(t *testing.T) {
	cause := fmt.Errorf("root cause")
	err := newKeyGenerationError(cause)
	unwrapped := errors.Unwrap(err)
	if unwrapped != cause {
		t.Errorf("Unwrap = %v, want %v", unwrapped, cause)
	}
}

func TestError_Unwrap_NilInner(t *testing.T) {
	err := newKeyParsingError("just a cause string")
	unwrapped := errors.Unwrap(err)
	if unwrapped != nil {
		t.Errorf("Unwrap = %v, want nil", unwrapped)
	}
}

func TestError_Error_AllKinds(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		contains string
	}{
		{
			name:     "KeyGeneration with wrapped error",
			err:      newKeyGenerationError(fmt.Errorf("gen fail")),
			contains: "failed to generate RSA key: gen fail",
		},
		{
			name:     "KeyParsing with cause string",
			err:      newKeyParsingError("bad format"),
			contains: "failed to parse private key: bad format",
		},
		{
			name:     "KeyParsing with wrapped error",
			err:      newKeyParsingErrorWrap(fmt.Errorf("parse fail")),
			contains: "failed to parse private key: parse fail",
		},
		{
			name:     "CertCreation with wrapped error",
			err:      newCertCreationError(fmt.Errorf("cert fail")),
			contains: "failed to create certificate: cert fail",
		},
		{
			name:     "PEMDecode bare",
			err:      &Error{kind: errPEMDecode},
			contains: "failed to decode PEM block",
		},
		{
			name:     "UnsupportedFormat with cause",
			err:      newUnsupportedFormatError("42"),
			contains: "unsupported key format: 42",
		},
		{
			name:     "Unknown kind",
			err:      &Error{kind: errorKind(999)},
			contains: "unknown error",
		},
		{
			name:     "KeyGeneration bare sentinel",
			err:      ErrKeyGeneration,
			contains: "failed to generate RSA key",
		},
		{
			name:     "CertCreation bare sentinel",
			err:      ErrCertCreation,
			contains: "failed to create certificate",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if !strings.HasPrefix(msg, "devicetransfer: ") {
				t.Errorf("error message missing prefix: %q", msg)
			}
			if !strings.Contains(msg, tc.contains) {
				t.Errorf("error message %q does not contain %q", msg, tc.contains)
			}
		})
	}
}

func TestError_Is_AllSentinels(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sentinel error
		want     bool
	}{
		{"KeyGeneration matches", newKeyGenerationError(nil), ErrKeyGeneration, true},
		{"KeyParsing matches", newKeyParsingError("x"), ErrKeyParsing, true},
		{"CertCreation matches", newCertCreationError(nil), ErrCertCreation, true},
		{"PEMDecode matches", &Error{kind: errPEMDecode}, ErrPEMDecode, true},
		{"UnsupportedFormat matches", newUnsupportedFormatError("x"), ErrUnsupportedFormat, true},
		{"KeyGen does not match KeyParsing", newKeyGenerationError(nil), ErrKeyParsing, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := errors.Is(tc.err, tc.sentinel)
			if got != tc.want {
				t.Errorf("errors.Is(%v, %v) = %v, want %v", tc.err, tc.sentinel, got, tc.want)
			}
		})
	}
}

func TestNewCertCreationError(t *testing.T) {
	cause := fmt.Errorf("underlying cause")
	err := newCertCreationError(cause)
	if err.kind != errCertCreation {
		t.Errorf("kind = %v, want errCertCreation", err.kind)
	}
	if err.err != cause {
		t.Error("expected wrapped error to be the cause")
	}
}

// --- GenerateRSASigner used with CreateSelfSignedCertWithSigner round-trip ---

func TestGenerateRSASigner_RoundTripWithCert(t *testing.T) {
	signer, err := GenerateRSASigner(2048)
	if err != nil {
		t.Fatalf("GenerateRSASigner: %v", err)
	}
	defer signer.Destroy()

	certDER, err := CreateSelfSignedCertWithSigner(signer, "RoundTrip", 7)
	if err != nil {
		t.Fatalf("CreateSelfSignedCertWithSigner: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Verify the certificate's public key matches the signer's public key
	certPub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected *rsa.PublicKey in certificate")
	}
	signerPub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected *rsa.PublicKey from signer")
	}
	if certPub.N.Cmp(signerPub.N) != 0 {
		t.Error("certificate public key does not match signer public key")
	}
}

// --- CreateSelfSignedCertWithSigner with destroyed signer ---

func TestCreateSelfSignedCertWithSigner_DestroyedSigner(t *testing.T) {
	signer, err := GenerateRSASigner(2048)
	if err != nil {
		t.Fatalf("GenerateRSASigner: %v", err)
	}
	signer.Destroy()

	// A destroyed signer should return nil from Public(), causing
	// x509.CreateCertificate to fail.
	_, err = CreateSelfSignedCertWithSigner(signer, "Destroyed", 30)
	if err == nil {
		t.Fatal("expected error when using destroyed signer")
	}
}

// --- Verify errors.Is works through errors.As chain ---

func TestError_ErrorsAs(t *testing.T) {
	err := newCertCreationError(fmt.Errorf("inner"))
	var dtErr *Error
	if !errors.As(err, &dtErr) {
		t.Fatal("expected errors.As to succeed for *Error")
	}
	if dtErr.kind != errCertCreation {
		t.Errorf("kind = %v, want errCertCreation", dtErr.kind)
	}
}

// --- Verify GenerateRSASigner at MinKeyBits boundary ---

func TestGenerateRSASigner_ExactMinKeyBits(t *testing.T) {
	signer, err := GenerateRSASigner(MinKeyBits)
	if err != nil {
		t.Fatalf("GenerateRSASigner(%d): %v", MinKeyBits, err)
	}
	defer signer.Destroy()

	rsaPub, ok := signer.Public().(*rsa.PublicKey)
	if !ok {
		t.Fatal("expected *rsa.PublicKey")
	}
	if rsaPub.N.BitLen() != MinKeyBits {
		t.Errorf("key size = %d bits, want %d", rsaPub.N.BitLen(), MinKeyBits)
	}
}

// TestCreateRSAPrivateKey_BelowMinKeyBits verifies that requesting a key
// size below MinKeyBits is rejected with ErrInvalidKeySize.
func TestCreateRSAPrivateKey_BelowMinKeyBits(t *testing.T) {
	tests := []struct {
		name string
		bits int
	}{
		{"1024 bits", 1024},
		{"512 bits", 512},
		{"1 bit", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := CreateRSAPrivateKey(tt.bits, KeyFormatPKCS8)
			if err == nil {
				t.Fatalf("expected error for %d-bit key, got nil", tt.bits)
			}
			if !errors.Is(err, ErrInvalidKeySize) {
				t.Errorf("expected ErrInvalidKeySize, got %v", err)
			}
		})
	}
}

// TestCreateRSAPrivateKey_ExactMinKeyBits verifies that requesting exactly
// MinKeyBits succeeds.
func TestCreateRSAPrivateKey_ExactMinKeyBits(t *testing.T) {
	der, err := CreateRSAPrivateKey(MinKeyBits, KeyFormatPKCS8)
	if err != nil {
		t.Fatalf("CreateRSAPrivateKey(%d): %v", MinKeyBits, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatal("expected *rsa.PrivateKey")
	}
	if key.N.BitLen() != MinKeyBits {
		t.Errorf("key size = %d bits, want %d", key.N.BitLen(), MinKeyBits)
	}
}

// TestErrInvalidKeySize_ErrorMessage verifies the error message content.
func TestErrInvalidKeySize_ErrorMessage(t *testing.T) {
	err := newInvalidKeySizeError("1024 bits requested, minimum is 2048")
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Error("expected errors.Is to match ErrInvalidKeySize")
	}
	msg := err.Error()
	if !strings.Contains(msg, "key size below minimum") {
		t.Errorf("error message %q does not contain expected text", msg)
	}
	if !strings.Contains(msg, "1024") {
		t.Errorf("error message %q does not contain cause detail", msg)
	}
}

// Verify the signer from GenerateRSASigner implements the interface
func TestGenerateRSASigner_ImplementsInterface(t *testing.T) {
	signer, err := GenerateRSASigner(2048)
	if err != nil {
		t.Fatalf("GenerateRSASigner: %v", err)
	}
	defer signer.Destroy()
}
