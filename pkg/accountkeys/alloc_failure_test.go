package accountkeys

// alloc_failure_test.go contains tests that exercise memguard allocation
// failure paths by temporarily replacing the package-level secretAlloc,
// secretRandAlloc, and secretEmptyAlloc variables with injected failures.
// These tests run within the package (internal tests) to access unexported variables.

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// errAllocFail is a sentinel error used to simulate memguard allocation failures.
var errAllocFail = errors.New("simulated allocation failure")

// failingAlloc returns an error immediately to simulate a memguard failure.
func failingAlloc(data []byte) (*secret.Secret, error) {
	return nil, errAllocFail
}

// failingRandAlloc returns an error immediately to simulate a random alloc failure.
func failingRandAlloc(size int) (*secret.Secret, error) {
	return nil, errAllocFail
}

// failingEmptyAlloc returns an error immediately to simulate an empty alloc failure.
func failingEmptyAlloc(size int) (*secret.Secret, error) {
	return nil, errAllocFail
}

// failAfterNCalls returns an allocator that succeeds for the first n calls,
// then injects a failure.
func failAfterNCalls(n int) func([]byte) (*secret.Secret, error) {
	count := 0
	return func(data []byte) (*secret.Secret, error) {
		count++
		if count > n {
			return nil, errAllocFail
		}
		return secret.New(data)
	}
}

func TestGenerateAccountEntropyPool_RandAllocFailure(t *testing.T) {
	orig := secretRandAlloc
	secretRandAlloc = failingRandAlloc
	defer func() { secretRandAlloc = orig }()

	_, err := GenerateAccountEntropyPool()
	if err == nil {
		t.Fatal("expected error when random alloc fails")
	}
	var target *ErrGeneratingRandomEntropy
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrGeneratingRandomEntropy, got %T: %v", err, err)
	}
}

// allRejectedBytes returns a secret filled with bytes that are all >= 252,
// which will all be rejected by the rejection-sampling loop in GenerateAccountEntropyPool.
// This forces the loop to exhaust the buffer and call secretRandAlloc again.
func allRejectedBytes(size int) (*secret.Secret, error) {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = 255 // All >= 252, all rejected by rejection sampling
	}
	return secret.New(buf)
}

// TestGenerateAccountEntropyPool_BufferExhaustion_ErrorOnRefill tests the buffer
// exhaustion path where all bytes are rejected and the refill call fails.
func TestGenerateAccountEntropyPool_BufferExhaustion_ErrorOnRefill(t *testing.T) {
	orig := secretRandAlloc
	callCount := 0
	secretRandAlloc = func(size int) (*secret.Secret, error) {
		callCount++
		if callCount == 1 {
			// First call: return a buffer of all-rejected bytes to force exhaustion.
			return allRejectedBytes(size)
		}
		// Second call (refill): inject failure.
		secretRandAlloc = orig
		return nil, errAllocFail
	}
	defer func() { secretRandAlloc = orig }()

	_, err := GenerateAccountEntropyPool()
	if err == nil {
		t.Fatal("expected error when refill alloc fails after buffer exhaustion")
	}
	var target *ErrGeneratingRandomEntropy
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrGeneratingRandomEntropy, got %T: %v", err, err)
	}
}

// TestGenerateAccountEntropyPool_BufferExhaustion_SuccessOnRefill tests the buffer
// exhaustion path where all bytes are rejected and the refill succeeds with valid bytes.
func TestGenerateAccountEntropyPool_BufferExhaustion_SuccessOnRefill(t *testing.T) {
	orig := secretRandAlloc
	callCount := 0
	secretRandAlloc = func(size int) (*secret.Secret, error) {
		callCount++
		if callCount == 1 {
			// First call: return all-rejected bytes to force buffer exhaustion.
			return allRejectedBytes(size)
		}
		// Subsequent calls: use the real allocator (which provides valid bytes).
		secretRandAlloc = orig
		return orig(size)
	}
	defer func() { secretRandAlloc = orig }()

	pool, err := GenerateAccountEntropyPool()
	if err != nil {
		t.Fatalf("unexpected error after buffer exhaustion with successful refill: %v", err)
	}
	if callCount < 2 {
		t.Fatal("expected at least 2 secretRandAlloc calls (initial + refill)")
	}
	if err := pool.Validate(); err != nil {
		t.Fatalf("generated pool after buffer exhaustion failed validation: %v", err)
	}
}

func TestDeriveSVRKey_AllocFailure(t *testing.T) {
	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	pool := AccountEntropyPool("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	_, err := pool.DeriveSVRKey()
	if err == nil {
		t.Fatal("expected error when alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "SVR key" {
		t.Fatalf("expected operation 'SVR key', got %q", target.Operation)
	}
}

func TestDeriveBackupKey_AllocFailure(t *testing.T) {
	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	pool := AccountEntropyPool("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	_, err := pool.DeriveBackupKey()
	if err == nil {
		t.Fatal("expected error when alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "backup key" {
		t.Fatalf("expected operation 'backup key', got %q", target.Operation)
	}
}

func TestHashPin_ArgonOutputAllocFailure(t *testing.T) {
	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	salt := make([]byte, 32)
	_, err := HashPin("1234", salt)
	if err == nil {
		t.Fatal("expected error when first alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "argon2 output" {
		t.Fatalf("expected operation 'argon2 output', got %q", target.Operation)
	}
}

func TestHashPin_EncKeyAllocFailure(t *testing.T) {
	orig := secretAlloc
	// First call (argon2 output) succeeds; second call (encryption key) fails.
	secretAlloc = failAfterNCalls(1)
	defer func() { secretAlloc = orig }()

	salt := make([]byte, 32)
	_, err := HashPin("1234", salt)
	if err == nil {
		t.Fatal("expected error when encryption key alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "encryption key" {
		t.Fatalf("expected operation 'encryption key', got %q", target.Operation)
	}
}

func TestHashPin_AccKeyAllocFailure(t *testing.T) {
	orig := secretAlloc
	// First two calls succeed (argon2 output + encryption key); third fails (access key).
	secretAlloc = failAfterNCalls(2)
	defer func() { secretAlloc = orig }()

	salt := make([]byte, 32)
	_, err := HashPin("1234", salt)
	if err == nil {
		t.Fatal("expected error when access key alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "access key" {
		t.Fatalf("expected operation 'access key', got %q", target.Operation)
	}
}

func TestLocalPinHash_SaltAllocFailure(t *testing.T) {
	orig := secretRandAlloc
	secretRandAlloc = failingRandAlloc
	defer func() { secretRandAlloc = orig }()

	_, err := LocalPinHash("1234")
	if err == nil {
		t.Fatal("expected error when salt alloc fails")
	}
	var target *ErrGeneratingSalt
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrGeneratingSalt, got %T: %v", err, err)
	}
}

func TestLocalPinHashWithSalt_AllocFailure(t *testing.T) {
	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	_, err := localPinHashWithSalt([]byte("1234"), make([]byte, 16))
	if err == nil {
		t.Fatal("expected error when alloc fails in localPinHashWithSalt")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "argon2i output" {
		t.Fatalf("expected operation 'argon2i output', got %q", target.Operation)
	}
}

func TestVerifyLocalPinHash_AllocFailure(t *testing.T) {
	phc := "$argon2i$v=19$m=512,t=64,p=1$ICEiIyQlJicoKSorLC0uLw$NeZzhiNv4cRmRMct9scf7d838bzmHJvrZtU/0BH0v/U"

	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	_, err := VerifyLocalPinHash("apassword", phc)
	if err == nil {
		t.Fatal("expected error when alloc fails in VerifyLocalPinHash")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "argon2i output" {
		t.Fatalf("expected operation 'argon2i output', got %q", target.Operation)
	}
}

func TestNewBackupKey_AllocFailurePanics(t *testing.T) {
	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic when BackupKey alloc fails")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("expected string panic, got %T: %v", r, r)
		}
		if msg == "" {
			t.Fatal("expected non-empty panic message")
		}
	}()

	var data [BackupKeyLength]byte
	NewBackupKey(data)
}

func TestDeriveBackupKeyFromEntropyPool_AllocFailure(t *testing.T) {
	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	pool := AccountEntropyPool("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	_, err := DeriveBackupKeyFromEntropyPool(pool)
	if err == nil {
		t.Fatal("expected error when alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "backup key" {
		t.Fatalf("expected operation 'backup key', got %q", target.Operation)
	}
}

func TestDeriveECKey_AllocFailure(t *testing.T) {
	pool := AccountEntropyPool("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	key, err := DeriveBackupKeyFromEntropyPool(pool)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer key.Zeroize()

	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	aci := make([]byte, 16)
	_, err = key.DeriveECKey(aci)
	if err == nil {
		t.Fatal("expected error when alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "EC key" {
		t.Fatalf("expected operation 'EC key', got %q", target.Operation)
	}
}

func TestDeriveLocalBackupMetadataKey_AllocFailure(t *testing.T) {
	pool := AccountEntropyPool("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	key, err := DeriveBackupKeyFromEntropyPool(pool)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer key.Zeroize()

	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	_, err = key.DeriveLocalBackupMetadataKey()
	if err == nil {
		t.Fatal("expected error when alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "metadata key" {
		t.Fatalf("expected operation 'metadata key', got %q", target.Operation)
	}
}

func TestDeriveMediaEncryptionKeyData_AllocFailure(t *testing.T) {
	pool := AccountEntropyPool("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	key, err := DeriveBackupKeyFromEntropyPool(pool)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer key.Zeroize()

	var mediaId [MediaIDLength]byte

	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	_, err = key.DeriveMediaEncryptionKeyData(mediaId)
	if err == nil {
		t.Fatal("expected error when alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "media encryption key" {
		t.Fatalf("expected operation 'media encryption key', got %q", target.Operation)
	}
}

func TestDeriveThumbnailTransitEncryptionKeyData_AllocFailure(t *testing.T) {
	pool := AccountEntropyPool("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	key, err := DeriveBackupKeyFromEntropyPool(pool)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer key.Zeroize()

	var mediaId [MediaIDLength]byte

	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	_, err = key.DeriveThumbnailTransitEncryptionKeyData(mediaId)
	if err == nil {
		t.Fatal("expected error when alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "thumbnail encryption key" {
		t.Fatalf("expected operation 'thumbnail encryption key', got %q", target.Operation)
	}
}

func TestDeriveForwardSecrecyEncryptionKey_HKDFOutputAllocFailure(t *testing.T) {
	pool := AccountEntropyPool("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	key, err := DeriveBackupKeyFromEntropyPool(pool)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer key.Zeroize()

	origEmpty := secretEmptyAlloc
	secretEmptyAlloc = failingEmptyAlloc
	defer func() { secretEmptyAlloc = origEmpty }()

	_, err = key.DeriveForwardSecrecyEncryptionKey([]byte("salt"))
	if err == nil {
		t.Fatal("expected error when HKDF output alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "HKDF output" {
		t.Fatalf("expected operation 'HKDF output', got %q", target.Operation)
	}
}

func TestDeriveForwardSecrecyEncryptionKey_CipherKeyAllocFailure(t *testing.T) {
	pool := AccountEntropyPool("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	key, err := DeriveBackupKeyFromEntropyPool(pool)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer key.Zeroize()

	// The cipher key is the first secretAlloc call in DeriveForwardSecrecyEncryptionKey.
	orig := secretAlloc
	secretAlloc = failingAlloc
	defer func() { secretAlloc = orig }()

	_, err = key.DeriveForwardSecrecyEncryptionKey([]byte("salt"))
	if err == nil {
		t.Fatal("expected error when cipher key alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "cipher key" {
		t.Fatalf("expected operation 'cipher key', got %q", target.Operation)
	}
}

func TestDeriveForwardSecrecyEncryptionKey_HMACKeyAllocFailure(t *testing.T) {
	pool := AccountEntropyPool("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	key, err := DeriveBackupKeyFromEntropyPool(pool)
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	defer key.Zeroize()

	// First secretAlloc call (cipher key) succeeds; second (HMAC key) fails.
	orig := secretAlloc
	count := 0
	secretAlloc = func(data []byte) (*secret.Secret, error) {
		count++
		if count > 1 {
			secretAlloc = orig
			return nil, errAllocFail
		}
		return secret.New(data)
	}
	defer func() { secretAlloc = orig }()

	_, err = key.DeriveForwardSecrecyEncryptionKey([]byte("salt"))
	if err == nil {
		t.Fatal("expected error when HMAC key alloc fails")
	}
	var target *ErrSecuringSecret
	if !errors.As(err, &target) {
		t.Fatalf("expected ErrSecuringSecret, got %T: %v", err, err)
	}
	if target.Operation != "HMAC key" {
		t.Fatalf("expected operation 'HMAC key', got %q", target.Operation)
	}
}
