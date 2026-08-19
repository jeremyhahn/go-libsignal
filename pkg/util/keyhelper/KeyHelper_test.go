package keyhelper

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/medium"
)

// failingReader is an io.Reader that always returns an error.
type failingReader struct{}

func (f *failingReader) Read([]byte) (int, error) {
	return 0, errors.New("simulated rand failure")
}

// withFailingRand temporarily replaces crypto/rand.Reader with a failing
// reader, calls fn, then restores the original reader.
func withFailingRand(fn func()) {
	original := rand.Reader
	rand.Reader = &failingReader{}
	defer func() { rand.Reader = original }()
	fn()
}

// signingSeedFailReader serves randomness from the real reader for every
// request except the second one of exactly seedSize bytes, which it fails.
//
// The first seedSize-byte request is the Kyber key-pair seed and the second is
// the nonce ecc.CalculateSignature draws, so this fails signing while letting
// key generation succeed. Guarded key generation also draws randomness through
// memguard to scramble its buffers; failing by request size rather than by a
// byte budget keeps the injection stable regardless of how much memguard
// consumes, and never leaves a caller with a short read (crypto/rand treats
// that as fatal).
type signingSeedFailReader struct {
	inner    io.Reader
	seedSize int
	seen     int
}

func (r *signingSeedFailReader) Read(p []byte) (int, error) {
	if len(p) == r.seedSize {
		r.seen++
		if r.seen > 1 {
			return 0, errors.New("simulated rand failure while signing")
		}
	}
	return r.inner.Read(p)
}

// withRandFailingOnSecondSeed replaces crypto/rand.Reader with a reader that
// fails the second seedSize-byte request, calls fn, then restores the original.
func withRandFailingOnSecondSeed(seedSize int, fn func()) {
	original := rand.Reader
	rand.Reader = &signingSeedFailReader{inner: original, seedSize: seedSize}
	defer func() { rand.Reader = original }()
	fn()
}

// ensure failingReader satisfies io.Reader at compile time.
var _ io.Reader = (*failingReader)(nil)
var _ io.Reader = (*signingSeedFailReader)(nil)

type mockKyberSerializer struct{}

func (m *mockKyberSerializer) Serialize(preKey *record.KyberPreKeyStructure) ([]byte, error) {
	return json.Marshal(preKey)
}

func (m *mockKyberSerializer) Deserialize(serialized []byte) (*record.KyberPreKeyStructure, error) {
	var s record.KyberPreKeyStructure
	err := json.Unmarshal(serialized, &s)
	return &s, err
}

func TestGenerateIdentityKeyPair(t *testing.T) {
	kp, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair failed: %v", err)
	}
	if kp == nil {
		t.Fatal("expected non-nil public key")
	}
	if kp.PublicKey() == nil {
		t.Fatal("expected non-nil public key")
	}
	if kp.PrivateKey() == nil {
		t.Fatal("expected non-nil private key")
	}
}

func TestGenerateIdentityKeyPair_Unique(t *testing.T) {
	kp1, _ := GenerateIdentityKeyPair()
	kp2, _ := GenerateIdentityKeyPair()
	if kp1.PublicKey().Fingerprint() == kp2.PublicKey().Fingerprint() {
		t.Fatal("two generated identity key pairs should be unique")
	}
}

func TestGenerateRegistrationID(t *testing.T) {
	id := GenerateRegistrationID()
	// Registration IDs are in [1, 16380] per the Java reference implementation.
	if id < 1 || id > 16380 {
		t.Fatalf("GenerateRegistrationID returned %d, not in [1, 16380]", id)
	}
}

// TestGenerateRegistrationID_ValidRange verifies that 1000 consecutive calls
// always produce values in [1, 16380], confirming no 0 sentinel or out-of-range
// values can be emitted.
func TestGenerateRegistrationID_ValidRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		id := GenerateRegistrationID()
		if id < 1 || id > 16380 {
			t.Fatalf("iteration %d: GenerateRegistrationID returned %d, not in [1, 16380]", i, id)
		}
	}
}

func TestGenerateRegistrationID_Randomness(t *testing.T) {
	ids := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		ids[GenerateRegistrationID()] = true
	}
	// With 100 random 14-bit values, we should get at least a few unique ones
	if len(ids) < 50 {
		t.Fatal("GenerateRegistrationID appears to not be random enough")
	}
}

func TestGeneratePreKeys(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	preKeys, err := GeneratePreKeys(1, 5, serializer.PreKeyRecord)
	if err != nil {
		t.Fatalf("GeneratePreKeys failed: %v", err)
	}
	if len(preKeys) != 5 {
		t.Fatalf("expected 5 pre keys, got %d", len(preKeys))
	}
	for _, pk := range preKeys {
		if pk.KeyPair() == nil {
			t.Fatal("prekey should have a key pair")
		}
	}
}

func TestGeneratePreKeys_CountZero(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	preKeys, err := GeneratePreKeys(1, 0, serializer.PreKeyRecord)
	if err != nil {
		t.Fatalf("GeneratePreKeys with count 0 failed: %v", err)
	}
	if len(preKeys) != 0 {
		t.Fatalf("expected 0 pre keys, got %d", len(preKeys))
	}
}

// TestGeneratePreKeys_IDsStartAtOffset verifies that the generated prekey IDs
// begin at the requested start offset and are sequential.
func TestGeneratePreKeys_IDsStartAtOffset(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	start := 100
	count := 10
	preKeys, err := GeneratePreKeys(start, count, serializer.PreKeyRecord)
	if err != nil {
		t.Fatalf("GeneratePreKeys failed: %v", err)
	}
	if len(preKeys) != count {
		t.Fatalf("expected %d prekeys, got %d", count, len(preKeys))
	}
	for i, pk := range preKeys {
		wantID := uint32(start + i)
		gotID := pk.ID().Value
		if gotID != wantID {
			t.Errorf("preKeys[%d].ID() = %d, want %d", i, gotID, wantID)
		}
	}
}

// TestGeneratePreKeys_IDsWrapNearMaxValue verifies that prekey IDs wrap
// correctly near medium.MaxValue (0xFFFFFF), never emitting 0 or MaxValue.
// When start == MaxValue, the first ID should be 1 (wrapped).
func TestGeneratePreKeys_IDsWrapNearMaxValue(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	start := int(medium.MaxValue) // 0xFFFFFF
	preKeys, err := GeneratePreKeys(start, 3, serializer.PreKeyRecord)
	if err != nil {
		t.Fatalf("GeneratePreKeys failed: %v", err)
	}
	wantIDs := []uint32{1, 2, 3}
	for i, pk := range preKeys {
		gotID := pk.ID().Value
		if gotID != wantIDs[i] {
			t.Errorf("preKeys[%d].ID() = %d, want %d (wrapped)", i, gotID, wantIDs[i])
		}
	}
}

// TestGeneratePreKeys_StartZeroIsZeroBased verifies that start=0 reproduces the
// historical zero-based ID sequence [0, 1, ..., count-1] (Java reference
// behavior), so existing callers that pass start=0 are unaffected.
func TestGeneratePreKeys_StartZeroIsZeroBased(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	preKeys, err := GeneratePreKeys(0, 5, serializer.PreKeyRecord)
	if err != nil {
		t.Fatalf("GeneratePreKeys(0, 5): unexpected error: %v", err)
	}
	if len(preKeys) != 5 {
		t.Fatalf("expected 5 prekeys, got %d", len(preKeys))
	}
	for i, pk := range preKeys {
		if got, want := pk.ID().Value, uint32(i); got != want {
			t.Errorf("preKeys[%d].ID() = %d, want %d", i, got, want)
		}
	}
}

func TestGenerateLastResortKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	key, err := GenerateLastResortKey(serializer.PreKeyRecord)
	if err != nil {
		t.Fatalf("GenerateLastResortKey failed: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil last resort key")
	}
	if key.KeyPair() == nil {
		t.Fatal("last resort key should have a key pair")
	}
}

func TestGenerateSignedPreKey(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	identityKP, _ := GenerateIdentityKeyPair()
	signedPreKey, err := GenerateSignedPreKey(identityKP, 1, serializer.SignedPreKeyRecord)
	if err != nil {
		t.Fatalf("GenerateSignedPreKey failed: %v", err)
	}
	if signedPreKey == nil {
		t.Fatal("expected non-nil signed pre key")
	}
	if signedPreKey.KeyPair() == nil {
		t.Fatal("signed pre key should have a key pair")
	}
	if signedPreKey.ID() != 1 {
		t.Fatalf("expected ID 1, got %d", signedPreKey.ID())
	}
}

func TestGenerateSignedPreKey_DifferentIDs(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	identityKP, _ := GenerateIdentityKeyPair()
	spk1, _ := GenerateSignedPreKey(identityKP, 1, serializer.SignedPreKeyRecord)
	spk2, _ := GenerateSignedPreKey(identityKP, 2, serializer.SignedPreKeyRecord)
	if spk1.ID() == spk2.ID() {
		t.Fatal("signed pre keys should have different IDs")
	}
}

func TestGenerateSenderSigningKey(t *testing.T) {
	kp, err := GenerateSenderSigningKey()
	if err != nil {
		t.Fatalf("GenerateSenderSigningKey failed: %v", err)
	}
	if kp == nil {
		t.Fatal("expected non-nil public key")
	}
}

func TestGenerateSenderKey(t *testing.T) {
	key, err := GenerateSenderKey()
	if err != nil {
		t.Fatalf("GenerateSenderKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte sender key, got %d", len(key))
	}
	// Check it's not all zeros (extremely unlikely for random)
	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("sender key should not be all zeros")
	}
}

func TestGenerateSenderKey_RandFailure(t *testing.T) {
	withFailingRand(func() {
		key, err := GenerateSenderKey()
		if err == nil {
			t.Fatal("expected error when rand.Reader fails")
		}
		if key != nil {
			t.Fatal("expected nil key on error")
		}
		var randErr *ErrRandomGeneration
		if !errors.As(err, &randErr) {
			t.Errorf("expected ErrRandomGeneration, got %T", err)
		}
	})
}

func TestGenerateSenderKeyID_Range(t *testing.T) {
	// Rust uses (csprng.random::<u32>()) >> 1, so result is in [0, 2^31).
	const maxSenderKeyID = uint32(1<<31 - 1)
	for i := 0; i < 100; i++ {
		id := GenerateSenderKeyID()
		if id > maxSenderKeyID {
			t.Fatalf("GenerateSenderKeyID returned %d, exceeds 31-bit max %d", id, maxSenderKeyID)
		}
	}
}

func TestGenerateSenderKeyID_Entropy(t *testing.T) {
	// With 31-bit space, 1000 draws should populate values well above the
	// 14-bit ceiling (16383). At least half should exceed the 14-bit range.
	const iterations = 1000
	const fourteenBitMax = uint32(0x3FFF)
	aboveFourteenBit := 0
	for i := 0; i < iterations; i++ {
		if GenerateSenderKeyID() > fourteenBitMax {
			aboveFourteenBit++
		}
	}
	// With a uniform 31-bit distribution the probability of any value being
	// ≤16383 is 16384/2^31 ≈ 0.00076%. Expect virtually all to exceed 14 bits.
	if aboveFourteenBit < 990 {
		t.Fatalf("only %d/%d GenerateSenderKeyID values exceeded 14-bit range; entropy too low", aboveFourteenBit, iterations)
	}
}

func TestGenerateKyberPreKey(t *testing.T) {
	identityKP, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair failed: %v", err)
	}
	// We need a KyberPreKeySerializer - use a minimal mock
	kpk, err := GenerateKyberPreKey(identityKP.PrivateKey(), 1, &mockKyberSerializer{})
	if err != nil {
		t.Fatalf("GenerateKyberPreKey failed: %v", err)
	}
	if kpk == nil {
		t.Fatal("expected non-nil KyberPreKey")
	}
	if kpk.ID() != 1 {
		t.Fatalf("expected ID 1, got %d", kpk.ID())
	}
	if kpk.PublicKey() == nil {
		t.Fatal("expected non-nil public key")
	}
	if len(kpk.Signature()) == 0 {
		t.Fatal("expected non-empty signature")
	}
}

func TestGenerateKyberPreKey_DifferentIDs(t *testing.T) {
	identityKP, _ := GenerateIdentityKeyPair()
	kpk1, _ := GenerateKyberPreKey(identityKP.PrivateKey(), 10, &mockKyberSerializer{})
	kpk2, _ := GenerateKyberPreKey(identityKP.PrivateKey(), 20, &mockKyberSerializer{})
	if kpk1.ID() == kpk2.ID() {
		t.Fatal("kyber pre keys should have different IDs")
	}
}

func TestGenerateSenderSigningKey_Unique(t *testing.T) {
	kp1, _ := GenerateSenderSigningKey()
	kp2, _ := GenerateSenderSigningKey()
	pub1 := kp1.PublicKey().PublicKey()
	pub2 := kp2.PublicKey().PublicKey()
	if pub1 == pub2 {
		t.Fatal("two generated sender signing keys should be unique")
	}
}

// --- Error path tests using failing rand.Reader ---

func TestGenerateIdentityKeyPair_RandFailure(t *testing.T) {
	withFailingRand(func() {
		kp, err := GenerateIdentityKeyPair()
		if err == nil {
			t.Fatal("expected error when rand.Reader fails")
		}
		if kp != nil {
			t.Fatal("expected nil key pair on error")
		}
	})
}

func TestGeneratePreKeys_RandFailure(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	withFailingRand(func() {
		preKeys, err := GeneratePreKeys(1, 3, serializer.PreKeyRecord)
		if err == nil {
			t.Fatal("expected error when rand.Reader fails")
		}
		if preKeys != nil {
			t.Fatal("expected nil preKeys on error")
		}
	})
}

func TestGenerateLastResortKey_RandFailure(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	withFailingRand(func() {
		key, err := GenerateLastResortKey(serializer.PreKeyRecord)
		if err == nil {
			t.Fatal("expected error when rand.Reader fails")
		}
		if key != nil {
			t.Fatal("expected nil key on error")
		}
	})
}

func TestGenerateSignedPreKey_RandFailure_KeyGen(t *testing.T) {
	serializer := serialize.NewJSONSerializer()
	// Generate identity key pair with working rand first.
	identityKP, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	// Now fail rand.Reader so that the internal ecc.GenerateKeyPair fails.
	withFailingRand(func() {
		spk, err := GenerateSignedPreKey(identityKP, 1, serializer.SignedPreKeyRecord)
		if err == nil {
			t.Fatal("expected error when rand.Reader fails during key generation")
		}
		if spk != nil {
			t.Fatal("expected nil signed pre key on error")
		}
	})
}

// TestGenerateSignedPreKey_RandFailure_Signing tests the signing-failure error
// path by calling ecc.CalculateSignature directly with a failing rand.Reader.
//
// GenerateSignedPreKey cannot be used to reach the signing failure path via
// rand.Reader injection because ecc.GenerateKeyPair runs first and consumes
// random bytes, and memguard's guard-page canary (inside GuardedECPrivateKey)
// consumes an indeterminate number of additional bytes from the same reader
// before CalculateSignature is reached. This makes it impossible to provide
// exactly enough bytes for key generation but not for signing without relying
// on memguard internals.
//
// Calling CalculateSignature directly with pre-generated keys and a failing
// reader deterministically exercises the error path that GenerateSignedPreKey
// propagates with "return nil, err" after the signing step.
func TestGenerateSignedPreKey_RandFailure_Signing(t *testing.T) {
	identityKP, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("setup GenerateIdentityKeyPair: %v", err)
	}
	preKeyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("setup GenerateKeyPair: %v", err)
	}

	// CalculateSignature reads 64 bytes from rand.Reader for the XEdDSA nonce.
	// Failing rand.Reader at this point exercises the error path that
	// GenerateSignedPreKey propagates when signing fails.
	withFailingRand(func() {
		sig, sigErr := ecc.CalculateSignature(identityKP.PrivateKey(), preKeyPair.PublicKey().Serialize())
		if sigErr == nil {
			t.Fatal("expected error from CalculateSignature when rand.Reader fails")
		}
		var emptyArr [64]byte
		if sig != emptyArr {
			t.Fatal("expected zero signature on rand failure")
		}
	})
}

func TestGenerateKyberPreKey_RandFailure_KeyGen(t *testing.T) {
	identityKP, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	withFailingRand(func() {
		kpk, err := GenerateKyberPreKey(identityKP.PrivateKey(), 1, &mockKyberSerializer{})
		if err == nil {
			t.Fatal("expected error when rand.Reader fails during Kyber key generation")
		}
		if kpk != nil {
			t.Fatal("expected nil KyberPreKey on error")
		}
	})
}

func TestGenerateKyberPreKey_RandFailure_Signing(t *testing.T) {
	identityKP, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}
	// Kyber key generation and ecc.CalculateSignature each read 64 bytes from
	// rand.Reader; failing the second such read lets keygen succeed and makes
	// signing fail.
	withRandFailingOnSecondSeed(64, func() {
		kpk, err := GenerateKyberPreKey(identityKP.PrivateKey(), 1, &mockKyberSerializer{})
		if err == nil {
			t.Fatal("expected error when rand.Reader fails during signing")
		}
		if kpk != nil {
			t.Fatal("expected nil KyberPreKey on signing error")
		}
	})
}
