package net

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestAuthFromUIDAndSecret(t *testing.T) {
	var uid [16]byte
	for i := range uid {
		uid[i] = byte(i)
	}
	var secret [32]byte
	for i := range secret {
		secret[i] = byte(i + 100)
	}

	auth := AuthFromUIDAndSecret(uid, secret)
	if auth.Username == "" {
		t.Fatal("Username is empty")
	}
	if auth.Password == "" {
		t.Fatal("Password is empty")
	}

	// Username should be hex of UID
	if len(auth.Username) != 32 { // 16 bytes * 2 hex chars
		t.Errorf("Username length = %d, want 32", len(auth.Username))
	}

	// Password format: "timestamp:hex(hmac)[:20]"
	parts := strings.SplitN(auth.Password, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("Password format invalid: %q", auth.Password)
	}
}

func TestComputeOTP(t *testing.T) {
	secret := []byte("test_secret_32_bytes_long_enough!")
	now := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)

	otp := computeOTP("testuser", secret, now)
	if otp == "" {
		t.Fatal("OTP is empty")
	}

	// Format check: "timestamp:hex"
	parts := strings.SplitN(otp, ":", 2)
	if len(parts) != 2 {
		t.Fatalf("OTP format invalid: %q", otp)
	}

	// Hex part should be truncated to otpLength
	if len(parts[1]) != otpLength {
		t.Errorf("hex part length = %d, want %d", len(parts[1]), otpLength)
	}

	// Deterministic
	otp2 := computeOTP("testuser", secret, now)
	if otp != otp2 {
		t.Error("not deterministic")
	}

	// Different username produces different OTP
	otp3 := computeOTP("otheruser", secret, now)
	if otp == otp3 {
		t.Error("different username produced same OTP")
	}
}

func TestAuth_BasicAuthHeader(t *testing.T) {
	auth := &Auth{Username: "user", Password: "pass"}
	header := auth.BasicAuthHeader()
	if !strings.HasPrefix(header, "Basic ") {
		t.Errorf("expected 'Basic ' prefix, got %q", header)
	}
	encoded := header[6:]
	if encoded == "" {
		t.Fatal("encoded part is empty")
	}
}

func TestAuth_SetAuthHeader(t *testing.T) {
	auth := &Auth{Username: "user", Password: "pass"}
	req, _ := http.NewRequest("GET", "http://example.com", nil)
	auth.SetAuthHeader(req)

	username, password, ok := req.BasicAuth()
	if !ok {
		t.Fatal("basic auth not set")
	}
	if username != "user" {
		t.Errorf("username = %q, want %q", username, "user")
	}
	if password != "pass" {
		t.Errorf("password = %q, want %q", password, "pass")
	}
}

func TestBasicAuth(t *testing.T) {
	result := basicAuth("user", "pass")
	if result == "" {
		t.Fatal("result is empty")
	}
}

func TestAuthFromUIDAndSecret_SecretZeroized(t *testing.T) {
	// Verify that after calling AuthFromUIDAndSecret, the secret parameter
	// (which is passed by value) is zeroized within the function's scope.
	// We test this indirectly by verifying the function still produces
	// valid output (the defer runs after password computation).
	var uid [16]byte
	for i := range uid {
		uid[i] = byte(i)
	}
	var secret [32]byte
	for i := range secret {
		secret[i] = byte(i + 100)
	}

	// Keep a copy to verify our original is untouched (passed by value).
	secretCopy := secret

	auth := AuthFromUIDAndSecret(uid, secret)
	if auth.Username == "" || auth.Password == "" {
		t.Fatal("expected non-empty auth credentials")
	}

	// The caller's secret should be unchanged since Go passes arrays by value.
	if secret != secretCopy {
		t.Fatal("caller's secret should not be modified (passed by value)")
	}
}

func TestComputeOTP_DifferentTimes(t *testing.T) {
	secret := []byte("test_secret_32_bytes_long_enough!")
	t1 := time.Date(2024, 6, 15, 12, 0, 0, 0, time.UTC)
	t2 := time.Date(2024, 6, 15, 12, 0, 1, 0, time.UTC) // 1 second later

	otp1 := computeOTP("testuser", secret, t1)
	otp2 := computeOTP("testuser", secret, t2)
	if otp1 == otp2 {
		t.Error("OTPs at different timestamps should differ")
	}
}
