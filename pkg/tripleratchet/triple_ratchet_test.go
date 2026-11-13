package tripleratchet_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/tripleratchet"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// --- Test ECCipher implementation ---

// testECState holds a simple symmetric "EC ratchet" backed by a counter and
// shared seed. This is sufficient to exercise the Triple Ratchet logic without
// pulling in the full session machinery.
type testECState struct {
	seed    []byte
	counter uint32
}

func newTestECState(seed []byte) *testECState {
	s := make([]byte, len(seed))
	copy(s, seed)
	return &testECState{seed: s}
}

// testECCipher is a test ECCipher that derives keys from a shared seed.
// Both sides are initialized from the same seed so that SendKey on Alice
// produces keys compatible with ReceiveKey on Bob and vice versa.
type testECCipher struct {
	sendState *testECState
	recvState *testECState
}

// deriveTestKey produces a deterministic 32-byte "EC message key" from a seed
// and a counter by simple XOR with the counter — sufficient for unit tests.
func deriveTestKey(seed []byte, counter uint32) []byte {
	key := make([]byte, 32)
	copy(key, seed)
	key[0] ^= byte(counter)
	key[1] ^= byte(counter >> 8)
	key[2] ^= byte(counter >> 16)
	key[3] ^= byte(counter >> 24)
	return key
}

// SendKey returns a 4-byte header encoding the counter and a 32-byte key.
func (c *testECCipher) SendKey() (ecHeader []byte, messageKey []byte, err error) {
	c.sendState.counter++
	ctr := c.sendState.counter
	header := []byte{byte(ctr), byte(ctr >> 8), byte(ctr >> 16), byte(ctr >> 24)}
	key := deriveTestKey(c.sendState.seed, ctr)
	return header, key, nil
}

// ReceiveKey reads the counter from the 4-byte header and derives the same key.
func (c *testECCipher) ReceiveKey(ecHeader []byte) (messageKey []byte, err error) {
	if len(ecHeader) < 4 {
		return nil, &tripleratchet.ErrInvalidInput{Field: "ecHeader", Reason: "too short"}
	}
	ctr := uint32(ecHeader[0]) | uint32(ecHeader[1])<<8 | uint32(ecHeader[2])<<16 | uint32(ecHeader[3])<<24
	key := deriveTestKey(c.recvState.seed, ctr)
	return key, nil
}

// TakeECSnapshot serializes the send counter as 4-byte big-endian for atomic rollback.
func (c *testECCipher) TakeECSnapshot() ([]byte, error) {
	ctr := c.sendState.counter
	return []byte{byte(ctr >> 24), byte(ctr >> 16), byte(ctr >> 8), byte(ctr)}, nil
}

// RestoreECSnapshot restores the send counter from a snapshot taken by TakeECSnapshot.
func (c *testECCipher) RestoreECSnapshot(data []byte) error {
	if len(data) != 4 {
		return &tripleratchet.ErrInvalidInput{Field: "data", Reason: "EC snapshot must be 4 bytes"}
	}
	c.sendState.counter = uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	return nil
}

// newTestPair creates a matched Alice/Bob cipher pair from a shared seed.
func newTestPair(t *testing.T, sharedSecret []byte) (*tripleratchet.TripleRatchet, *tripleratchet.TripleRatchet) {
	t.Helper()

	seed := make([]byte, 32)
	copy(seed, sharedSecret)

	kemAlice := mlkembraid.NewIncrementalMLKEM768KEM()
	kemBob := mlkembraid.NewIncrementalMLKEM768KEM()

	aliceEC := &testECCipher{
		sendState: newTestECState(seed),
		recvState: newTestECState(seed),
	}
	bobEC := &testECCipher{
		sendState: newTestECState(seed),
		recvState: newTestECState(seed),
	}

	alice, err := tripleratchet.NewAlice(aliceEC, sharedSecret, kemAlice, 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}
	bob, err := tripleratchet.NewBob(bobEC, sharedSecret, kemBob, 10)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}
	return alice, bob
}

func randomSharedSecret(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return buf
}

// --- Tests ---

// TestNewAlice_Success verifies Alice initializes without error.
func TestNewAlice_Success(t *testing.T) {
	ss := randomSharedSecret(t)
	kem := mlkembraid.NewIncrementalMLKEM768KEM()
	ec := &testECCipher{
		sendState: newTestECState(ss),
		recvState: newTestECState(ss),
	}
	_, err := tripleratchet.NewAlice(ec, ss, kem, 10)
	if err != nil {
		t.Fatalf("NewAlice unexpected error: %v", err)
	}
}

// TestNewAlice_NilECCipher verifies that NewAlice rejects a nil ECCipher.
func TestNewAlice_NilECCipher(t *testing.T) {
	ss := randomSharedSecret(t)
	kem := mlkembraid.NewIncrementalMLKEM768KEM()
	_, err := tripleratchet.NewAlice(nil, ss, kem, 10)
	if err == nil {
		t.Fatal("expected error for nil ECCipher")
	}
}

// nonSnapshotCipher implements ECCipher but NOT ECCipherSnapshotable.
// Used as a regression test for Finding 5: newTripleRatchet must reject
// ciphers that cannot atomically roll back EC state.
type nonSnapshotCipher struct{}

func (c *nonSnapshotCipher) SendKey() ([]byte, []byte, error) {
	return make([]byte, 4), make([]byte, 32), nil
}
func (c *nonSnapshotCipher) ReceiveKey([]byte) ([]byte, error) {
	return make([]byte, 32), nil
}

// TestNewAlice_RejectsNonSnapshotableCipher is the Finding 5 regression test.
// Before the fix, NewAlice accepted any ECCipher, silently omitting rollback.
// After the fix, construction fails if the cipher does not implement ECCipherSnapshotable.
func TestNewAlice_RejectsNonSnapshotableCipher(t *testing.T) {
	ss := randomSharedSecret(t)
	kem := mlkembraid.NewIncrementalMLKEM768KEM()
	ec := &nonSnapshotCipher{}

	_, err := tripleratchet.NewAlice(ec, ss, kem, 10)
	if err == nil {
		t.Fatal("NewAlice must reject a cipher that does not implement ECCipherSnapshotable")
	}
	var e *tripleratchet.ErrInvalidInput
	if !errors.As(err, &e) || e.Field != "ecCipher" {
		t.Errorf("expected ErrInvalidInput{ecCipher}, got %T: %v", err, err)
	}
}

// TestNewBob_RejectsNonSnapshotableCipher mirrors the Finding 5 test for Bob.
func TestNewBob_RejectsNonSnapshotableCipher(t *testing.T) {
	ss := randomSharedSecret(t)
	kem := mlkembraid.NewIncrementalMLKEM768KEM()
	ec := &nonSnapshotCipher{}

	_, err := tripleratchet.NewBob(ec, ss, kem, 10)
	if err == nil {
		t.Fatal("NewBob must reject a cipher that does not implement ECCipherSnapshotable")
	}
	var e *tripleratchet.ErrInvalidInput
	if !errors.As(err, &e) || e.Field != "ecCipher" {
		t.Errorf("expected ErrInvalidInput{ecCipher}, got %T: %v", err, err)
	}
}

// TestNewAlice_EmptySharedSecret verifies that NewAlice rejects an empty secret.
func TestNewAlice_EmptySharedSecret(t *testing.T) {
	kem := mlkembraid.NewIncrementalMLKEM768KEM()
	ec := &testECCipher{
		sendState: newTestECState(make([]byte, 32)),
		recvState: newTestECState(make([]byte, 32)),
	}
	_, err := tripleratchet.NewAlice(ec, nil, kem, 10)
	if err == nil {
		t.Fatal("expected error for empty shared secret")
	}
}

// TestNewBob_Success verifies Bob initializes without error.
func TestNewBob_Success(t *testing.T) {
	ss := randomSharedSecret(t)
	kem := mlkembraid.NewIncrementalMLKEM768KEM()
	ec := &testECCipher{
		sendState: newTestECState(ss),
		recvState: newTestECState(ss),
	}
	_, err := tripleratchet.NewBob(ec, ss, kem, 10)
	if err != nil {
		t.Fatalf("NewBob unexpected error: %v", err)
	}
}

// TestNewBob_NilECCipher verifies that NewBob rejects a nil ECCipher.
func TestNewBob_NilECCipher(t *testing.T) {
	ss := randomSharedSecret(t)
	kem := mlkembraid.NewIncrementalMLKEM768KEM()
	_, err := tripleratchet.NewBob(nil, ss, kem, 10)
	if err == nil {
		t.Fatal("expected error for nil ECCipher")
	}
}

// TestEncryptDecrypt_Roundtrip verifies Alice can encrypt and Bob can decrypt.
func TestEncryptDecrypt_Roundtrip(t *testing.T) {
	ss := randomSharedSecret(t)
	alice, bob := newTestPair(t, ss)

	plaintext := []byte("hello triple ratchet")
	ciphertext, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := bob.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q want %q", got, plaintext)
	}
}

// TestEncryptDecrypt_MultipleMessages verifies a sequence of messages round-trips.
func TestEncryptDecrypt_MultipleMessages(t *testing.T) {
	ss := randomSharedSecret(t)
	alice, bob := newTestPair(t, ss)

	messages := []string{
		"message one",
		"message two",
		"a longer message to ensure buffering works correctly",
		"",
	}

	for i, msg := range messages {
		ct, encErr := alice.Encrypt([]byte(msg))
		if encErr != nil {
			t.Fatalf("Encrypt[%d]: %v", i, encErr)
		}

		got, decErr := bob.Decrypt(ct)
		if decErr != nil {
			t.Fatalf("Decrypt[%d]: %v", i, decErr)
		}

		if !bytes.Equal(got, []byte(msg)) {
			t.Fatalf("message[%d] mismatch: got %q want %q", i, got, msg)
		}
	}
}

// TestDecrypt_TamperedMAC verifies that a tampered MAC causes decryption failure
// and does NOT corrupt the TripleRatchet state (snapshot restore).
func TestDecrypt_TamperedMAC(t *testing.T) {
	ss := randomSharedSecret(t)
	alice, bob := newTestPair(t, ss)

	ct, err := alice.Encrypt([]byte("tamper test"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Corrupt the last byte (part of the HMAC tag at the end of the ciphertext
	// embedded in the composite message).
	tampered := make([]byte, len(ct))
	copy(tampered, ct)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = bob.Decrypt(tampered)
	if err == nil {
		t.Fatal("expected MAC verification error, got nil")
	}

	// Verify that Bob's state is still usable (snapshot was restored).
	_, decErr := bob.Decrypt(ct)
	if decErr != nil {
		t.Fatalf("Decrypt after tampered MAC failed unexpectedly: %v", decErr)
	}
}

// TestDecrypt_InvalidCompositeMessage verifies structural errors are surfaced.
func TestDecrypt_InvalidCompositeMessage(t *testing.T) {
	ss := randomSharedSecret(t)
	_, bob := newTestPair(t, ss)

	_, err := bob.Decrypt([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for truncated composite message")
	}
}

// TestKDFHybrid_Success verifies the hybrid KDF produces 80 bytes of output keys.
func TestKDFHybrid_Success(t *testing.T) {
	ecMKBytes := make([]byte, 32)
	pqMKBytes := make([]byte, 32)
	ecMK, err := secret.New(ecMKBytes)
	if err != nil {
		t.Fatalf("secret.New ecMK: %v", err)
	}
	pqMK, err := secret.New(pqMKBytes)
	if err != nil {
		t.Fatalf("secret.New pqMK: %v", err)
	}
	defer ecMK.Destroy()
	defer pqMK.Destroy()

	hkeys, err := tripleratchet.KDFHybrid(ecMK, pqMK)
	if err != nil {
		t.Fatalf("KDFHybrid: %v", err)
	}
	defer hkeys.Zeroize()

	if hkeys.CipherKey == nil || hkeys.CipherKey.IsDestroyed() {
		t.Error("CipherKey nil or destroyed")
	}
	if hkeys.MacKey == nil || hkeys.MacKey.IsDestroyed() {
		t.Error("MacKey nil or destroyed")
	}
	if hkeys.IV == nil || hkeys.IV.IsDestroyed() {
		t.Error("IV nil or destroyed")
	}
}

// TestKDFHybrid_NilECKey verifies that a nil EC key is rejected.
func TestKDFHybrid_NilECKey(t *testing.T) {
	pqMKBytes := make([]byte, 32)
	pqMK, err := secret.New(pqMKBytes)
	if err != nil {
		t.Fatalf("secret.New pqMK: %v", err)
	}
	defer pqMK.Destroy()

	_, err = tripleratchet.KDFHybrid(nil, pqMK)
	if err == nil {
		t.Fatal("expected error for nil ecMK")
	}
}

// TestKDFHybridECOnly_Success verifies the EC-only KDF path.
func TestKDFHybridECOnly_Success(t *testing.T) {
	ecMKBytes := make([]byte, 32)
	ecMK, err := secret.New(ecMKBytes)
	if err != nil {
		t.Fatalf("secret.New ecMK: %v", err)
	}
	defer ecMK.Destroy()

	hkeys, err := tripleratchet.KDFHybridECOnly(ecMK)
	if err != nil {
		t.Fatalf("KDFHybridECOnly: %v", err)
	}
	defer hkeys.Zeroize()

	if hkeys.CipherKey == nil || hkeys.CipherKey.IsDestroyed() {
		t.Error("CipherKey nil or destroyed")
	}
}

// TestKDFHybridECOnly_NilKey verifies that a nil EC key is rejected.
func TestKDFHybridECOnly_NilKey(t *testing.T) {
	_, err := tripleratchet.KDFHybridECOnly(nil)
	if err == nil {
		t.Fatal("expected error for nil ecMK")
	}
}

// TestEncrypt_EmptyPlaintext verifies that an empty plaintext round-trips correctly.
func TestEncrypt_EmptyPlaintext(t *testing.T) {
	ss := randomSharedSecret(t)
	alice, bob := newTestPair(t, ss)

	ct, err := alice.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	got, err := bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %q", got)
	}
}

// TestNewAlice_NilKEM verifies that a nil KEM is rejected.
func TestNewAlice_NilKEM(t *testing.T) {
	ss := randomSharedSecret(t)
	ec := &testECCipher{
		sendState: newTestECState(ss),
		recvState: newTestECState(ss),
	}
	_, err := tripleratchet.NewAlice(ec, ss, nil, 10)
	if err == nil {
		t.Fatal("expected error for nil KEM")
	}
}

// TestNewAlice_InvalidChunkSize verifies that a zero chunk size is rejected.
func TestNewAlice_InvalidChunkSize(t *testing.T) {
	ss := randomSharedSecret(t)
	kem := mlkembraid.NewIncrementalMLKEM768KEM()
	ec := &testECCipher{
		sendState: newTestECState(ss),
		recvState: newTestECState(ss),
	}
	_, err := tripleratchet.NewAlice(ec, ss, kem, 0)
	if err == nil {
		t.Fatal("expected error for zero chunk size")
	}
}
