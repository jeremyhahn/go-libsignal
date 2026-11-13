package session

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

func TestNewDerivedSecrets(t *testing.T) {
	keyMaterial := make([]byte, 64)
	for i := range keyMaterial {
		keyMaterial[i] = byte(i)
	}
	secrets := NewDerivedSecrets(keyMaterial)
	if secrets == nil {
		t.Fatal("expected non-nil DerivedSecrets")
	}
	rootKey := secrets.RootKey()
	chainKey := secrets.ChainKey()
	if len(rootKey) != 32 {
		t.Fatalf("expected 32-byte root key, got %d", len(rootKey))
	}
	if len(chainKey) != 32 {
		t.Fatalf("expected 32-byte chain key, got %d", len(chainKey))
	}
	for i := 0; i < 32; i++ {
		if rootKey[i] != byte(i) {
			t.Fatalf("root key byte %d mismatch", i)
		}
	}
	for i := 0; i < 32; i++ {
		if chainKey[i] != byte(i+32) {
			t.Fatalf("chain key byte %d mismatch", i)
		}
	}
}

func TestNewDerivedSecrets_DifferentHalves(t *testing.T) {
	keyMaterial := make([]byte, 64)
	for i := 0; i < 32; i++ {
		keyMaterial[i] = 0xAA
	}
	for i := 32; i < 64; i++ {
		keyMaterial[i] = 0xBB
	}
	secrets := NewDerivedSecrets(keyMaterial)
	if bytes.Equal(secrets.RootKey(), secrets.ChainKey()) {
		t.Fatal("root and chain keys should differ when input halves differ")
	}
}

func TestNewKeyPair(t *testing.T) {
	mockRoot := &mockRootKey{data: []byte("root")}
	mockChain := &mockChainKey{data: []byte("chain")}

	kp := NewKeyPair(mockRoot, mockChain)
	if kp == nil {
		t.Fatal("expected non-nil KeyPair")
	}
	if !bytes.Equal(kp.RootKey.Bytes(), []byte("root")) {
		t.Fatal("RootKey mismatch")
	}
	if !bytes.Equal(kp.ChainKey.Key(), []byte("chain")) {
		t.Fatal("ChainKey mismatch")
	}
}

func TestNewKeyPair_AccessFields(t *testing.T) {
	mockRoot := &mockRootKey{data: []byte("root-key-data")}
	mockChain := &mockChainKey{data: []byte("chain-key-data"), idx: 7}

	kp := NewKeyPair(mockRoot, mockChain)
	if !bytes.Equal(kp.RootKey.Bytes(), []byte("root-key-data")) {
		t.Fatal("RootKey bytes mismatch")
	}
	if kp.ChainKey.Index() != 7 {
		t.Fatalf("expected chain key index 7, got %d", kp.ChainKey.Index())
	}
}

// Mock implementations

type mockRootKey struct {
	data []byte
}

func (m *mockRootKey) Bytes() []byte {
	return m.data
}

func (m *mockRootKey) CreateChain(theirRatchetKey ecc.ECPublicKeyable, ourRatchetKey *ecc.ECKeyPair) (*KeyPair, error) {
	return nil, nil
}

type mockChainKey struct {
	data []byte
	idx  uint32
}

func (m *mockChainKey) Key() []byte {
	return m.data
}

func (m *mockChainKey) Index() uint32 {
	return m.idx
}

func (m *mockChainKey) NextKey() *chain.Key {
	return nil
}

func (m *mockChainKey) MessageKeys() (*message.Keys, error) {
	return nil, nil
}

func (m *mockChainKey) MessageKeysWithSalt(pqrSalt []byte) (*message.Keys, error) {
	return nil, nil
}

func (m *mockChainKey) MessageKeysWithSeed() (*message.Keys, error) {
	return nil, nil
}

func (m *mockChainKey) Current() *chain.Key {
	return nil
}

func TestDerivedSecrets_Zeroize(t *testing.T) {
	keyMaterial := make([]byte, 64)
	for i := range keyMaterial {
		keyMaterial[i] = byte(i + 1)
	}
	secrets := NewDerivedSecrets(keyMaterial)

	// Verify keys are non-zero initially.
	if len(secrets.RootKey()) != 32 {
		t.Fatal("root key should be 32 bytes before Zeroize")
	}

	secrets.Zeroize()

	if !secrets.rootKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy root key guarded memory")
	}
	if !secrets.chainKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy chain key guarded memory")
	}
}

func TestDerivedSecrets_Zeroize_Idempotent(t *testing.T) {
	keyMaterial := make([]byte, 64)
	secrets := NewDerivedSecrets(keyMaterial)
	secrets.Zeroize()
	// Calling Zeroize again should not panic.
	secrets.Zeroize()
}

func TestNewDerivedSecrets_ZeroizesSource(t *testing.T) {
	keyMaterial := make([]byte, 64)
	for i := range keyMaterial {
		keyMaterial[i] = byte(i + 1)
	}
	_ = NewDerivedSecrets(keyMaterial)

	// Source material should be zeroized.
	allZero := true
	for _, b := range keyMaterial {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Fatal("NewDerivedSecrets should zeroize the source key material")
	}
}

// TestNewDerivedSecrets_96Bytes verifies that 96-byte key material produces
// three 32-byte keys: RootKey, ChainKey, and InitialPQRKey.
func TestNewDerivedSecrets_96Bytes(t *testing.T) {
	keyMaterial := make([]byte, 96)
	for i := range keyMaterial {
		keyMaterial[i] = byte(i)
	}
	secrets := NewDerivedSecrets(keyMaterial)
	if secrets == nil {
		t.Fatal("expected non-nil DerivedSecrets")
	}

	rootKey := secrets.RootKey()
	chainKey := secrets.ChainKey()
	pqrKey := secrets.InitialPQRKey()

	if len(rootKey) != 32 {
		t.Fatalf("expected 32-byte root key, got %d", len(rootKey))
	}
	if len(chainKey) != 32 {
		t.Fatalf("expected 32-byte chain key, got %d", len(chainKey))
	}
	if pqrKey == nil {
		t.Fatal("expected non-nil InitialPQRKey for 96-byte input")
	}
	if len(pqrKey) != 32 {
		t.Fatalf("expected 32-byte PQR key, got %d", len(pqrKey))
	}

	// Verify byte content.
	for i := 0; i < 32; i++ {
		if rootKey[i] != byte(i) {
			t.Fatalf("root key byte %d mismatch", i)
		}
		if chainKey[i] != byte(i+32) {
			t.Fatalf("chain key byte %d mismatch", i)
		}
		if pqrKey[i] != byte(i+64) {
			t.Fatalf("PQR key byte %d mismatch", i)
		}
	}
}

// TestNewDerivedSecrets_64Bytes_NilPQRKey verifies that 64-byte key material
// produces a nil InitialPQRKey (backward compatibility with legacy derivations).
func TestNewDerivedSecrets_64Bytes_NilPQRKey(t *testing.T) {
	keyMaterial := make([]byte, 64)
	for i := range keyMaterial {
		keyMaterial[i] = byte(i)
	}
	secrets := NewDerivedSecrets(keyMaterial)
	if secrets.InitialPQRKey() != nil {
		t.Fatal("64-byte key material should produce nil InitialPQRKey")
	}
}

// TestNewDerivedSecrets_96Bytes_Zeroize verifies that Zeroize destroys all
// three guarded secrets including the PQR key.
func TestNewDerivedSecrets_96Bytes_Zeroize(t *testing.T) {
	keyMaterial := make([]byte, 96)
	for i := range keyMaterial {
		keyMaterial[i] = byte(i + 1)
	}
	secrets := NewDerivedSecrets(keyMaterial)

	if secrets.InitialPQRKey() == nil {
		t.Fatal("expected non-nil PQR key before Zeroize")
	}

	secrets.Zeroize()

	if !secrets.rootKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy root key guarded memory")
	}
	if !secrets.chainKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy chain key guarded memory")
	}
	if !secrets.pqrKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy PQR key guarded memory")
	}
}

// TestNewKeyPairWithPQR verifies the new constructor wraps InitialPQRKey in
// locked memory and zeroizes the source bytes.
func TestNewKeyPairWithPQR(t *testing.T) {
	mockRoot := &mockRootKey{data: []byte("root")}
	mockChain := &mockChainKey{data: []byte("chain")}
	// Use a copy so we can verify the original bytes after the call.
	original := []byte("pqr-key-32-bytes-exactly-right!")
	pqrKey := make([]byte, len(original))
	copy(pqrKey, original)

	kp, err := NewKeyPairWithPQR(mockRoot, mockChain, pqrKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kp == nil {
		t.Fatal("expected non-nil KeyPair")
	}
	if !bytes.Equal(kp.RootKey.Bytes(), []byte("root")) {
		t.Fatal("RootKey mismatch")
	}
	if !bytes.Equal(kp.ChainKey.Key(), []byte("chain")) {
		t.Fatal("ChainKey mismatch")
	}
	if kp.InitialPQRKey == nil {
		t.Fatal("expected non-nil InitialPQRKey secret")
	}
	if !bytes.Equal(secrettest.Bytes(kp.InitialPQRKey), original) {
		t.Fatal("InitialPQRKey content mismatch")
	}
	kp.Zeroize()
}

// TestNewKeyPairWithPQR_NilPQR verifies nil PQR key is handled.
func TestNewKeyPairWithPQR_NilPQR(t *testing.T) {
	mockRoot := &mockRootKey{data: []byte("root")}
	mockChain := &mockChainKey{data: []byte("chain")}

	kp, err := NewKeyPairWithPQR(mockRoot, mockChain, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kp.InitialPQRKey != nil {
		t.Fatal("expected nil InitialPQRKey")
	}
}

// TestKeyPair_Zeroize verifies that Zeroize destroys the guarded PQR key.
func TestKeyPair_Zeroize(t *testing.T) {
	mockRoot := &mockRootKey{data: []byte("root")}
	mockChain := &mockChainKey{data: []byte("chain")}
	pqrKey := []byte("pqr-key-32-bytes-exactly-right!")

	kp, err := NewKeyPairWithPQR(mockRoot, mockChain, pqrKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kp.InitialPQRKey == nil {
		t.Fatal("expected non-nil InitialPQRKey before Zeroize")
	}

	kp.Zeroize()

	if !kp.InitialPQRKey.IsDestroyed() {
		t.Fatal("InitialPQRKey should be destroyed after Zeroize")
	}
}

// TestKeyPair_Zeroize_NilKey verifies that Zeroize is safe when InitialPQRKey is nil.
func TestKeyPair_Zeroize_NilKey(t *testing.T) {
	kp := NewKeyPair(&mockRootKey{data: []byte("root")}, &mockChainKey{})
	// Must not panic.
	kp.Zeroize()
}
