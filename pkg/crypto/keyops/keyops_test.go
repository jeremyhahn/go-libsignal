package keyops

import (
	"crypto"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

// mockSigner is a minimal Signer for testing interface satisfaction.
type mockSigner struct {
	destroyed bool
	pubKey    [32]byte
	signErr   error
}

func (m *mockSigner) Sign(_ io.Reader, _ []byte) ([64]byte, error) {
	if m.destroyed {
		return [64]byte{}, ErrKeyDestroyed
	}
	if m.signErr != nil {
		return [64]byte{}, m.signErr
	}
	var sig [64]byte
	sig[0] = 0xAA
	return sig, nil
}

func (m *mockSigner) PublicKey() [32]byte { return m.pubKey }
func (m *mockSigner) Destroy()            { m.destroyed = true }

// mockVRFSigner is a minimal VRFSigner for testing interface satisfaction.
type mockVRFSigner struct {
	mockSigner
	vrfSignErr error
}

func (m *mockVRFSigner) VRFSign(_ io.Reader, _ []byte) ([]byte, []byte, error) {
	if m.destroyed {
		return nil, nil, ErrKeyDestroyed
	}
	if m.vrfSignErr != nil {
		return nil, nil, m.vrfSignErr
	}
	return []byte{0x01, 0x02}, []byte{0x03, 0x04}, nil
}

// mockKeyAgreement is a minimal KeyAgreement for testing interface satisfaction.
type mockKeyAgreement struct {
	destroyed    bool
	pubKey       [32]byte
	agreementErr error
}

func (m *mockKeyAgreement) Agreement(_ [32]byte) (*secret.Secret32, error) {
	if m.destroyed {
		return nil, ErrKeyDestroyed
	}
	if m.agreementErr != nil {
		return nil, m.agreementErr
	}
	var data [32]byte
	data[0] = 0xBB
	s, err := secret.NewSecret32(data)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (m *mockKeyAgreement) PublicKey() [32]byte { return m.pubKey }
func (m *mockKeyAgreement) Destroy()            { m.destroyed = true }

// mockPrivateKey combines signing and key agreement.
type mockPrivateKey struct {
	mockSigner
	agreementErr error
}

func (m *mockPrivateKey) Agreement(_ [32]byte) (*secret.Secret32, error) {
	if m.destroyed {
		return nil, ErrKeyDestroyed
	}
	if m.agreementErr != nil {
		return nil, m.agreementErr
	}
	var data [32]byte
	data[0] = 0xCC
	s, err := secret.NewSecret32(data)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// mockDecapsulator is a minimal Decapsulator for testing interface satisfaction.
type mockDecapsulator struct {
	destroyed bool
	decapErr  error
}

func (m *mockDecapsulator) Decapsulate(_ []byte) (*secret.Secret32, error) {
	if m.destroyed {
		return nil, ErrKeyDestroyed
	}
	if m.decapErr != nil {
		return nil, m.decapErr
	}
	var data [32]byte
	data[0] = 0xDD
	s, err := secret.NewSecret32(data)
	if err != nil {
		return nil, err
	}
	return s, nil
}

func (m *mockDecapsulator) Destroy() { m.destroyed = true }

// mockEncapsulator is a minimal Encapsulator for testing interface satisfaction.
type mockEncapsulator struct {
	encapErr error
}

func (m *mockEncapsulator) Encapsulate() (*secret.Secret32, []byte, error) {
	if m.encapErr != nil {
		return nil, nil, m.encapErr
	}
	var data [32]byte
	data[0] = 0xEE
	s, err := secret.NewSecret32(data)
	if err != nil {
		return nil, nil, err
	}
	return s, []byte{0x01, 0x02, 0x03}, nil
}

// mockRSASigner is a minimal RSASigner for testing interface satisfaction.
type mockRSASigner struct {
	destroyed bool
	pubKey    crypto.PublicKey
	signErr   error
}

func (m *mockRSASigner) Public() crypto.PublicKey { return m.pubKey }
func (m *mockRSASigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	if m.destroyed {
		return nil, ErrKeyDestroyed
	}
	if m.signErr != nil {
		return nil, m.signErr
	}
	return []byte{0xFF}, nil
}
func (m *mockRSASigner) Destroy() { m.destroyed = true }

// ---------------------------------------------------------------------------
// Compile-time interface satisfaction checks
// ---------------------------------------------------------------------------

var (
	_ Signer       = (*mockSigner)(nil)
	_ VRFSigner    = (*mockVRFSigner)(nil)
	_ KeyAgreement = (*mockKeyAgreement)(nil)
	_ PrivateKey   = (*mockPrivateKey)(nil)
	_ Decapsulator = (*mockDecapsulator)(nil)
	_ Encapsulator = (*mockEncapsulator)(nil)
	_ RSASigner    = (*mockRSASigner)(nil)
)

// ---------------------------------------------------------------------------
// Interface tests
// ---------------------------------------------------------------------------

func TestSigner_Sign_Success(t *testing.T) {
	m := &mockSigner{pubKey: [32]byte{0x01}}
	sig, err := m.Sign(nil, []byte("hello"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if sig[0] != 0xAA {
		t.Fatalf("expected sig[0]=0xAA, got 0x%02x", sig[0])
	}
}

func TestSigner_Sign_AfterDestroy(t *testing.T) {
	m := &mockSigner{}
	m.Destroy()
	_, err := m.Sign(nil, []byte("hello"))
	if err == nil {
		t.Fatal("expected error after destroy, got nil")
	}
	if !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("expected ErrKeyDestroyed, got %v", err)
	}
}

func TestSigner_PublicKey(t *testing.T) {
	expected := [32]byte{0x42}
	m := &mockSigner{pubKey: expected}
	if m.PublicKey() != expected {
		t.Fatal("PublicKey did not return expected value")
	}
}

func TestVRFSigner_VRFSign_Success(t *testing.T) {
	m := &mockVRFSigner{}
	sig, vrf, err := m.VRFSign(nil, []byte("test"))
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(sig) == 0 || len(vrf) == 0 {
		t.Fatal("expected non-empty sig and vrf output")
	}
}

func TestVRFSigner_VRFSign_AfterDestroy(t *testing.T) {
	m := &mockVRFSigner{}
	m.Destroy()
	_, _, err := m.VRFSign(nil, []byte("test"))
	if err == nil {
		t.Fatal("expected error after destroy, got nil")
	}
	if !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("expected ErrKeyDestroyed, got %v", err)
	}
}

func TestVRFSigner_VRFSign_Error(t *testing.T) {
	m := &mockVRFSigner{vrfSignErr: NewSignatureError("vrf failed")}
	_, _, err := m.VRFSign(nil, []byte("test"))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrSignatureFailed) {
		t.Fatalf("expected ErrSignatureFailed, got %v", err)
	}
}

func TestKeyAgreement_Agreement_Success(t *testing.T) {
	m := &mockKeyAgreement{pubKey: [32]byte{0x11}}
	ss, err := m.Agreement([32]byte{0x22})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer ss.Destroy()
	secrettest.With(t, ss, func(b []byte) {
		if len(b) == 0 || b[0] != 0xBB {
			t.Errorf("expected shared secret[0]=0xBB")
		}
	})
}

func TestKeyAgreement_Agreement_AfterDestroy(t *testing.T) {
	m := &mockKeyAgreement{}
	m.Destroy()
	_, err := m.Agreement([32]byte{})
	if err == nil {
		t.Fatal("expected error after destroy, got nil")
	}
	if !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("expected ErrKeyDestroyed, got %v", err)
	}
}

func TestKeyAgreement_Agreement_Error(t *testing.T) {
	m := &mockKeyAgreement{agreementErr: NewDHError("mock dh fail")}
	_, err := m.Agreement([32]byte{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrDHFailed) {
		t.Fatalf("expected ErrDHFailed, got %v", err)
	}
}

func TestPrivateKey_CombinedInterface(t *testing.T) {
	m := &mockPrivateKey{
		mockSigner: mockSigner{pubKey: [32]byte{0x55}},
	}

	// Test signing
	sig, err := m.Sign(nil, []byte("msg"))
	if err != nil {
		t.Fatalf("Sign: expected no error, got %v", err)
	}
	if sig[0] != 0xAA {
		t.Fatalf("Sign: expected sig[0]=0xAA, got 0x%02x", sig[0])
	}

	// Test agreement
	ss, err := m.Agreement([32]byte{0x33})
	if err != nil {
		t.Fatalf("Agreement: expected no error, got %v", err)
	}
	defer ss.Destroy()
	secrettest.With(t, ss, func(b []byte) {
		if len(b) == 0 || b[0] != 0xCC {
			t.Errorf("Agreement: expected ss[0]=0xCC")
		}
	})

	// Test PublicKey
	if m.PublicKey() != [32]byte{0x55} {
		t.Fatal("PublicKey mismatch")
	}
}

func TestPrivateKey_AfterDestroy(t *testing.T) {
	m := &mockPrivateKey{}
	m.Destroy()

	_, err := m.Sign(nil, []byte("msg"))
	if !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("Sign after destroy: expected ErrKeyDestroyed, got %v", err)
	}

	_, err = m.Agreement([32]byte{})
	if !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("Agreement after destroy: expected ErrKeyDestroyed, got %v", err)
	}
}

func TestDecapsulator_Decapsulate_Success(t *testing.T) {
	m := &mockDecapsulator{}
	ss, err := m.Decapsulate([]byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer ss.Destroy()
	secrettest.With(t, ss, func(b []byte) {
		if len(b) == 0 || b[0] != 0xDD {
			t.Errorf("expected ss[0]=0xDD")
		}
	})
}

func TestDecapsulator_Decapsulate_AfterDestroy(t *testing.T) {
	m := &mockDecapsulator{}
	m.Destroy()
	_, err := m.Decapsulate([]byte{0x01})
	if err == nil {
		t.Fatal("expected error after destroy, got nil")
	}
	if !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("expected ErrKeyDestroyed, got %v", err)
	}
}

func TestDecapsulator_Decapsulate_Error(t *testing.T) {
	m := &mockDecapsulator{decapErr: NewDecapsulationError("bad ciphertext")}
	_, err := m.Decapsulate([]byte{0x01})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrDecapsulationFailed) {
		t.Fatalf("expected ErrDecapsulationFailed, got %v", err)
	}
}

func TestEncapsulator_Encapsulate_Success(t *testing.T) {
	m := &mockEncapsulator{}
	ss, ct, err := m.Encapsulate()
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	defer ss.Destroy()
	secrettest.With(t, ss, func(b []byte) {
		if len(b) == 0 || b[0] != 0xEE {
			t.Errorf("expected ss[0]=0xEE")
		}
	})
	if len(ct) != 3 {
		t.Fatalf("expected ciphertext length 3, got %d", len(ct))
	}
}

func TestEncapsulator_Encapsulate_Error(t *testing.T) {
	m := &mockEncapsulator{encapErr: NewDecapsulationError("encap fail")}
	_, _, err := m.Encapsulate()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestRSASigner_Sign_Success(t *testing.T) {
	m := &mockRSASigner{pubKey: "test-public-key"}
	sig, err := m.Sign(nil, []byte("digest"), nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("expected non-empty signature")
	}
	if m.Public() != crypto.PublicKey("test-public-key") {
		t.Fatal("Public() mismatch")
	}
}

func TestRSASigner_Sign_AfterDestroy(t *testing.T) {
	m := &mockRSASigner{}
	m.Destroy()
	_, err := m.Sign(nil, []byte("digest"), nil)
	if err == nil {
		t.Fatal("expected error after destroy, got nil")
	}
	if !errors.Is(err, ErrKeyDestroyed) {
		t.Fatalf("expected ErrKeyDestroyed, got %v", err)
	}
}

func TestRSASigner_Sign_Error(t *testing.T) {
	m := &mockRSASigner{signErr: NewSignatureError("rsa failed")}
	_, err := m.Sign(nil, []byte("digest"), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrSignatureFailed) {
		t.Fatalf("expected ErrSignatureFailed, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// Error tests
// ---------------------------------------------------------------------------

func TestError_Messages(t *testing.T) {
	tests := []struct {
		name     string
		err      *Error
		contains string
	}{
		{"KeyDestroyed", ErrKeyDestroyed, "attempt to use a destroyed key"},
		{"UnsupportedOperation", ErrUnsupportedOperation, "unsupported operation"},
		{"HardwareKeyExport", ErrHardwareKeyExport, "cannot export raw material from hardware-backed key"},
		{"SignatureFailed", ErrSignatureFailed, "signing operation failed"},
		{"DHFailed", ErrDHFailed, "ECDH key agreement failed"},
		{"DecapsulationFailed", ErrDecapsulationFailed, "KEM decapsulation failed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if msg == "" {
				t.Fatal("error message is empty")
			}
			if !containsSubstring(msg, "keyops: ") {
				t.Fatalf("error message missing 'keyops: ' prefix: %s", msg)
			}
			if !containsSubstring(msg, tc.contains) {
				t.Fatalf("error message %q does not contain %q", msg, tc.contains)
			}
		})
	}
}

func TestError_Messages_WithCause(t *testing.T) {
	tests := []struct {
		name         string
		err          *Error
		containsMsg  string
		containsCaus string
	}{
		{
			"SignatureError with cause",
			NewSignatureError("bad nonce"),
			"signing operation failed",
			"bad nonce",
		},
		{
			"DHError with cause",
			NewDHError("low order point"),
			"ECDH key agreement failed",
			"low order point",
		},
		{
			"DecapsulationError with cause",
			NewDecapsulationError("invalid ciphertext"),
			"KEM decapsulation failed",
			"invalid ciphertext",
		},
		{
			"UnsupportedOperationError with cause",
			NewUnsupportedOperationError("hardware key"),
			"unsupported operation",
			"hardware key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			if !containsSubstring(msg, tc.containsMsg) {
				t.Fatalf("error %q missing expected message %q", msg, tc.containsMsg)
			}
			if !containsSubstring(msg, tc.containsCaus) {
				t.Fatalf("error %q missing expected cause %q", msg, tc.containsCaus)
			}
		})
	}
}

func TestError_Is_MatchesByKind(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		target   error
		expected bool
	}{
		{"KeyDestroyed matches sentinel", ErrKeyDestroyed, ErrKeyDestroyed, true},
		{"SignatureFailed with cause matches sentinel", NewSignatureError("x"), ErrSignatureFailed, true},
		{"DHFailed with cause matches sentinel", NewDHError("y"), ErrDHFailed, true},
		{"DecapsulationFailed with cause matches sentinel", NewDecapsulationError("z"), ErrDecapsulationFailed, true},
		{"UnsupportedOperation with cause matches sentinel", NewUnsupportedOperationError("w"), ErrUnsupportedOperation, true},
		{"Different kinds do not match", ErrKeyDestroyed, ErrSignatureFailed, false},
		{"DHFailed does not match DecapsulationFailed", ErrDHFailed, ErrDecapsulationFailed, false},
		{"Non-Error target returns false", ErrKeyDestroyed, errors.New("other"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := errors.Is(tc.err, tc.target)
			if result != tc.expected {
				t.Fatalf("errors.Is(%v, %v) = %v, want %v", tc.err, tc.target, result, tc.expected)
			}
		})
	}
}

func TestError_Is_NonErrorTarget(t *testing.T) {
	e := &Error{kind: errKeyDestroyed}
	if e.Is(errors.New("not a keyops error")) {
		t.Fatal("Is() should return false for non-Error target")
	}
}

func TestError_UnknownKind(t *testing.T) {
	e := &Error{kind: 0}
	msg := e.Error()
	if !containsSubstring(msg, "unknown error") {
		t.Fatalf("expected 'unknown error' for kind 0, got %q", msg)
	}
}

func TestError_NoCause_NoCauseInMessage(t *testing.T) {
	msg := ErrKeyDestroyed.Error()
	if containsSubstring(msg, ": :") || msg[len(msg)-1] == ':' {
		t.Fatalf("sentinel error should not have trailing cause separator: %q", msg)
	}
}

func TestNewSignatureError(t *testing.T) {
	e := NewSignatureError("nonce reuse")
	if e.kind != errSignatureFailed {
		t.Fatalf("expected errSignatureFailed kind, got %d", e.kind)
	}
	if e.cause != "nonce reuse" {
		t.Fatalf("expected cause 'nonce reuse', got %q", e.cause)
	}
}

func TestNewDHError(t *testing.T) {
	e := NewDHError("all zeros")
	if e.kind != errDHFailed {
		t.Fatalf("expected errDHFailed kind, got %d", e.kind)
	}
	if e.cause != "all zeros" {
		t.Fatalf("expected cause 'all zeros', got %q", e.cause)
	}
}

func TestNewDecapsulationError(t *testing.T) {
	e := NewDecapsulationError("truncated")
	if e.kind != errDecapsulationFailed {
		t.Fatalf("expected errDecapsulationFailed kind, got %d", e.kind)
	}
	if e.cause != "truncated" {
		t.Fatalf("expected cause 'truncated', got %q", e.cause)
	}
}

func TestNewUnsupportedOperationError(t *testing.T) {
	e := NewUnsupportedOperationError("not available")
	if e.kind != errUnsupportedOperation {
		t.Fatalf("expected errUnsupportedOperation kind, got %d", e.kind)
	}
	if e.cause != "not available" {
		t.Fatalf("expected cause 'not available', got %q", e.cause)
	}
}

func TestNewSignatureError_EmptyCause(t *testing.T) {
	e := NewSignatureError("")
	msg := e.Error()
	// With empty cause, should not have trailing ": "
	if containsSubstring(msg, ": :") {
		t.Fatalf("empty cause should not produce double colon: %q", msg)
	}
	if msg != "keyops: signing operation failed" {
		t.Fatalf("expected clean message, got %q", msg)
	}
}

func TestNewDHError_EmptyCause(t *testing.T) {
	e := NewDHError("")
	msg := e.Error()
	if msg != "keyops: ECDH key agreement failed" {
		t.Fatalf("expected clean message, got %q", msg)
	}
}

func TestNewDecapsulationError_EmptyCause(t *testing.T) {
	e := NewDecapsulationError("")
	msg := e.Error()
	if msg != "keyops: KEM decapsulation failed" {
		t.Fatalf("expected clean message, got %q", msg)
	}
}

func TestNewUnsupportedOperationError_EmptyCause(t *testing.T) {
	e := NewUnsupportedOperationError("")
	msg := e.Error()
	if msg != "keyops: unsupported operation" {
		t.Fatalf("expected clean message, got %q", msg)
	}
}

// ---------------------------------------------------------------------------
// Error sentinel identity tests
// ---------------------------------------------------------------------------

func TestSentinelErrors_AreDistinct(t *testing.T) {
	sentinels := []*Error{
		ErrKeyDestroyed,
		ErrUnsupportedOperation,
		ErrHardwareKeyExport,
		ErrSignatureFailed,
		ErrDHFailed,
		ErrDecapsulationFailed,
	}

	for i := 0; i < len(sentinels); i++ {
		for j := i + 1; j < len(sentinels); j++ {
			if errors.Is(sentinels[i], sentinels[j]) {
				t.Fatalf("sentinel %d and %d should not match: %v == %v",
					i, j, sentinels[i], sentinels[j])
			}
		}
	}
}

func TestError_ImplementsErrorInterface(t *testing.T) {
	var e error = ErrKeyDestroyed
	if e.Error() == "" {
		t.Fatal("Error() returned empty string")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && searchSubstring(s, substr)
}

func searchSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
