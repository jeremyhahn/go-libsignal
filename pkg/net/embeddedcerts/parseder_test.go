package embeddedcerts

import (
	"errors"
	"strings"
	"testing"
)

// TestParseDER_CorruptBytes exercises the error branch of parseDER when the
// DER bytes cannot be parsed as a valid X.509 certificate.
func TestParseDER_CorruptBytes(t *testing.T) {
	corrupt := []byte{0x00, 0x01, 0x02, 0x03}
	_, err := parseDER("fake.cer", corrupt)
	if err == nil {
		t.Fatal("parseDER with corrupt bytes should return an error")
	}
	var certErr *EmbeddedCertError
	if !errors.As(err, &certErr) {
		t.Fatalf("error should be *EmbeddedCertError, got %T", err)
	}
	if certErr.Name != "fake.cer" {
		t.Errorf("Name = %q, want %q", certErr.Name, "fake.cer")
	}
	if !strings.Contains(err.Error(), "fake.cer") {
		t.Errorf("Error() = %q should contain the cert name", err.Error())
	}
	if certErr.Unwrap() == nil {
		t.Error("Unwrap should return the underlying parse error")
	}
}

// TestParseDER_ValidDER exercises the success branch using a real embedded cert.
func TestParseDER_ValidDER(t *testing.T) {
	cert, err := parseDER("signal.cer", signalCERBytes)
	if err != nil {
		t.Fatalf("parseDER with valid DER returned error: %v", err)
	}
	if cert == nil {
		t.Fatal("parseDER returned nil cert for valid DER")
	}
}

// TestSignalCAs_Success confirms SignalCAs succeeds with the real embedded cert.
func TestSignalCAs_Success(t *testing.T) {
	certs, err := SignalCAs()
	if err != nil {
		t.Fatalf("SignalCAs() error: %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("SignalCAs() returned empty slice")
	}
}

// TestSignalCAs_ErrorPath exercises the error-return branch of SignalCAs by
// temporarily replacing the embedded DER bytes with corrupt data.
func TestSignalCAs_ErrorPath(t *testing.T) {
	original := signalCERBytes
	signalCERBytes = []byte{0x00, 0x01} // corrupt DER
	defer func() { signalCERBytes = original }()

	_, err := SignalCAs()
	if err == nil {
		t.Fatal("SignalCAs with corrupt DER should return error")
	}
	var certErr *EmbeddedCertError
	if !errors.As(err, &certErr) {
		t.Fatalf("expected *EmbeddedCertError, got %T", err)
	}
}

// TestGoogleProxyCAs_ErrorPath exercises the error-return branch of GoogleProxyCAs
// by temporarily replacing one of the embedded DER byte slices with corrupt data.
func TestGoogleProxyCAs_ErrorPath(t *testing.T) {
	original := giag2CERBytes
	giag2CERBytes = []byte{0x00, 0x01} // corrupt DER
	defer func() { giag2CERBytes = original }()

	_, err := GoogleProxyCAs()
	if err == nil {
		t.Fatal("GoogleProxyCAs with corrupt DER should return error")
	}
	var certErr *EmbeddedCertError
	if !errors.As(err, &certErr) {
		t.Fatalf("expected *EmbeddedCertError, got %T", err)
	}
}

// TestEmbeddedCertError_Unwrap verifies the Unwrap method via errors.Is.
func TestEmbeddedCertError_Unwrap(t *testing.T) {
	corrupt := []byte{0xFF, 0xFE}
	_, err := parseDER("test.cer", corrupt)
	if err == nil {
		t.Fatal("expected error")
	}
	var certErr *EmbeddedCertError
	if !errors.As(err, &certErr) {
		t.Fatalf("expected *EmbeddedCertError, got %T", err)
	}
	inner := certErr.Unwrap()
	if inner == nil {
		t.Fatal("Unwrap() returned nil")
	}
	// errors.Is traversal should find the inner error.
	if !errors.Is(err, inner) {
		t.Error("errors.Is should find the unwrapped inner error")
	}
}
