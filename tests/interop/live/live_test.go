//go:build interop_live

// Package live provides cross-implementation interop tests that wire Go and
// Rust libsignal together in real time via the interop_runner subprocess.
//
// Test naming convention:
//
//	TestLiveInterop_<Flow>_<Direction>
//	  Direction: GoEncryptRustDecrypt | RustEncryptGoDecrypt
//
// All tests use fixed, deterministic seeds so that failures are reproducible.
// Build tag: interop_live — excluded from default `make test`.
package live

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	groupPkg "github.com/jeremyhahn/go-libsignal/pkg/groups"
	groupRecord "github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	groupStore "github.com/jeremyhahn/go-libsignal/pkg/groups/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	identity "github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/prekey"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/sealed"
	"github.com/jeremyhahn/go-libsignal/pkg/serialize"
	"github.com/jeremyhahn/go-libsignal/pkg/session"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/state/store"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// ---------------------------------------------------------------------------
// In-memory store implementations (shared across tests in this file)
// ---------------------------------------------------------------------------

type memIdentityStore struct {
	trustedKeys         map[string]*identity.Key
	identityKeyPair     *identity.KeyPair
	localRegistrationID uint32
}

func newMemIdentityStore(kp *identity.KeyPair, regID uint32) *memIdentityStore {
	return &memIdentityStore{
		trustedKeys:         make(map[string]*identity.Key),
		identityKeyPair:     kp,
		localRegistrationID: regID,
	}
}

func (s *memIdentityStore) GetIdentityKeyPair() *identity.KeyPair { return s.identityKeyPair }
func (s *memIdentityStore) GetLocalRegistrationId() uint32        { return s.localRegistrationID }
func (s *memIdentityStore) SaveIdentity(addr *protocol.SignalAddress, key *identity.Key) (store.IdentityChange, error) {
	s.trustedKeys[addr.String()] = key
	return store.IdentityChangeNewOrUnchanged, nil
}
func (s *memIdentityStore) IsTrustedIdentity(addr *protocol.SignalAddress, key *identity.Key, _ store.Direction) (bool, error) {
	trusted := s.trustedKeys[addr.String()]
	return trusted == nil || trusted.Fingerprint() == key.Fingerprint(), nil
}
func (s *memIdentityStore) GetIdentity(addr *protocol.SignalAddress) (*identity.Key, error) {
	return s.trustedKeys[addr.String()], nil
}

type memPreKeyStore struct{ store map[uint32]*record.PreKey }

func newMemPreKeyStore() *memPreKeyStore {
	return &memPreKeyStore{store: make(map[uint32]*record.PreKey)}
}
func (s *memPreKeyStore) LoadPreKey(id uint32) (*record.PreKey, error) { return s.store[id], nil }
func (s *memPreKeyStore) StorePreKey(id uint32, r *record.PreKey) error {
	s.store[id] = r
	return nil
}
func (s *memPreKeyStore) ContainsPreKey(id uint32) (bool, error) {
	_, ok := s.store[id]
	return ok, nil
}
func (s *memPreKeyStore) RemovePreKey(id uint32) error { delete(s.store, id); return nil }

type memSignedPreKeyStore struct {
	store map[uint32]*record.SignedPreKey
}

func newMemSignedPreKeyStore() *memSignedPreKeyStore {
	return &memSignedPreKeyStore{store: make(map[uint32]*record.SignedPreKey)}
}
func (s *memSignedPreKeyStore) LoadSignedPreKey(id uint32) (*record.SignedPreKey, error) {
	return s.store[id], nil
}
func (s *memSignedPreKeyStore) LoadSignedPreKeys() ([]*record.SignedPreKey, error) {
	out := make([]*record.SignedPreKey, 0, len(s.store))
	for _, r := range s.store {
		out = append(out, r)
	}
	return out, nil
}
func (s *memSignedPreKeyStore) StoreSignedPreKey(id uint32, r *record.SignedPreKey) error {
	s.store[id] = r
	return nil
}
func (s *memSignedPreKeyStore) ContainsSignedPreKey(id uint32) (bool, error) {
	_, ok := s.store[id]
	return ok, nil
}
func (s *memSignedPreKeyStore) RemoveSignedPreKey(id uint32) error { delete(s.store, id); return nil }

type memSessionStore struct {
	sessions   map[string]*record.Session
	serializer *serialize.Serializer
}

func newMemSessionStore(s *serialize.Serializer) *memSessionStore {
	return &memSessionStore{sessions: make(map[string]*record.Session), serializer: s}
}
func (s *memSessionStore) LoadSession(addr *protocol.SignalAddress) (*record.Session, error) {
	if r, ok := s.sessions[addr.String()]; ok {
		return r, nil
	}
	r := record.NewSession(s.serializer.Session, s.serializer.State)
	s.sessions[addr.String()] = r
	return r, nil
}
func (s *memSessionStore) GetSubDeviceSessions(_ string) ([]uint32, error) { return nil, nil }
func (s *memSessionStore) StoreSession(addr *protocol.SignalAddress, r *record.Session) error {
	s.sessions[addr.String()] = r
	return nil
}
func (s *memSessionStore) ContainsSession(addr *protocol.SignalAddress) (bool, error) {
	_, ok := s.sessions[addr.String()]
	return ok, nil
}
func (s *memSessionStore) DeleteSession(addr *protocol.SignalAddress) error {
	delete(s.sessions, addr.String())
	return nil
}
func (s *memSessionStore) DeleteAllSessions() error {
	s.sessions = make(map[string]*record.Session)
	return nil
}

type memKyberPreKeyStore struct {
	store  map[uint32]*record.KyberPreKey
	marked map[uint32]bool
}

func newMemKyberPreKeyStore() *memKyberPreKeyStore {
	return &memKyberPreKeyStore{
		store:  make(map[uint32]*record.KyberPreKey),
		marked: make(map[uint32]bool),
	}
}
func (s *memKyberPreKeyStore) LoadKyberPreKey(id uint32) (*record.KyberPreKey, error) {
	return s.store[id], nil
}
func (s *memKyberPreKeyStore) StoreKyberPreKey(id uint32, r *record.KyberPreKey) error {
	s.store[id] = r
	return nil
}
func (s *memKyberPreKeyStore) MarkKyberPreKeyUsed(id uint32, _ uint32, _ ecc.ECPublicKeyable) error {
	s.marked[id] = true
	return nil
}
func (s *memKyberPreKeyStore) ContainsKyberPreKey(id uint32) (bool, error) {
	_, ok := s.store[id]
	return ok, nil
}

type memSenderKeyStore struct {
	store map[string]*groupRecord.SenderKey
}

func newMemSenderKeyStore() *memSenderKeyStore {
	return &memSenderKeyStore{store: make(map[string]*groupRecord.SenderKey)}
}
func (s *memSenderKeyStore) StoreSenderKey(name *protocol.SenderKeyName, r *groupRecord.SenderKey) error {
	s.store[name.GroupID()+"/"+name.Sender().String()] = r
	return nil
}
func (s *memSenderKeyStore) LoadSenderKey(name *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	return s.store[name.GroupID()+"/"+name.Sender().String()], nil
}

var _ store.IdentityKey = (*memIdentityStore)(nil)
var _ store.PreKey = (*memPreKeyStore)(nil)
var _ store.SignedPreKey = (*memSignedPreKeyStore)(nil)
var _ store.Session = (*memSessionStore)(nil)
var _ store.KyberPreKey = (*memKyberPreKeyStore)(nil)
var _ groupStore.SenderKey = (*memSenderKeyStore)(nil)

// nopKyberSerializer is a minimal KyberPreKeySerializer for in-memory use only.
// It is never called in tests because the store holds the Go struct directly.
type nopKyberSerializer struct{}

func (*nopKyberSerializer) Serialize(_ *record.KyberPreKeyStructure) ([]byte, error) {
	return nil, nil
}
func (*nopKyberSerializer) Deserialize(_ []byte) (*record.KyberPreKeyStructure, error) {
	return nil, nil
}

var _ record.KyberPreKeySerializer = (*nopKyberSerializer)(nil)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// requireRunner skips the test if the runner binary is not present.
func requireRunner(t *testing.T) *Runner {
	t.Helper()
	r, err := GlobalRunner()
	if err != nil {
		if _, ok := err.(*ErrRunnerNotFound); ok {
			t.Skipf("interop_runner not found: %v — run 'make interop-live-build'", err)
		}
		t.Fatalf("GlobalRunner: %v", err)
	}
	return r
}

// mustDecodeHex decodes a hex string or fatals.
func mustDecodeHex(t *testing.T, h string) []byte {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatalf("hex decode %q: %v", h, err)
	}
	return b
}

// mustGetString extracts a required string field from a runner response.
func mustGetString(t *testing.T, resp map[string]json.RawMessage, key string) string {
	t.Helper()
	v, err := GetString(resp, key)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return v
}

// mustGetUint64 extracts a required uint64 field.
func mustGetUint64(t *testing.T, resp map[string]json.RawMessage, key string) uint64 {
	t.Helper()
	raw, ok := resp[key]
	if !ok {
		t.Fatalf("runner response missing field %q", key)
	}
	var v uint64
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("field %q: %v", key, err)
	}
	return v
}

// pubKeyFrom33Bytes decodes a 33-byte DJB-prefix public key (0x05 || 32 bytes).
func pubKeyFrom33Bytes(t *testing.T, b []byte) ecc.ECPublicKeyable {
	t.Helper()
	if len(b) != 33 {
		t.Fatalf("expected 33-byte public key, got %d bytes", len(b))
	}
	pub, err := ecc.DecodePoint(b, 0)
	if err != nil {
		t.Fatalf("DecodePoint: %v", err)
	}
	return pub
}

// privKeyFrom32Bytes decodes a 32-byte raw Curve25519 private key.
func privKeyFrom32Bytes(t *testing.T, b []byte) ecc.ECPrivateKeyable {
	t.Helper()
	if len(b) != 32 {
		t.Fatalf("expected 32-byte private key, got %d bytes", len(b))
	}
	var arr [32]byte
	copy(arr[:], b)
	return ecc.NewDjbECPrivateKey(arr)
}

// identityKeyPairFromHex reconstructs an identity key pair from hex-encoded
// 33-byte public key and 32-byte private key.
func identityKeyPairFromHex(t *testing.T, pubHex, privHex string) *identity.KeyPair {
	t.Helper()
	pub := pubKeyFrom33Bytes(t, mustDecodeHex(t, pubHex))
	priv := privKeyFrom32Bytes(t, mustDecodeHex(t, privHex))
	return identity.NewKeyPair(identity.NewKey(pub), priv)
}

// goSerializer returns the protobuf serializer (matches Rust wire format).
func goSerializer() *serialize.Serializer {
	return serialize.NewProtobufSerializer()
}

// aesCBCDecrypt performs raw AES-256-CBC + PKCS7 decryption.
func aesCBCDecrypt(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, &aesDecryptError{detail: "ciphertext length not a multiple of AES block size"}
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	return pkcs7Unpad(plaintext, aes.BlockSize)
}

// aesCBCEncrypt performs raw AES-256-CBC + PKCS7 encryption.
func aesCBCEncrypt(key, iv, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(plaintext, aes.BlockSize)
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	return ciphertext, nil
}

// hmacSHA256 computes HMAC-SHA256(key, iv || ciphertext).
func hmacSHA256(key, iv, ciphertext []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(iv)
	mac.Write(ciphertext)
	return mac.Sum(nil)
}

// verifyHMACSHA256 verifies HMAC-SHA256(key, iv || ciphertext) == expected.
func verifyHMACSHA256(key, iv, ciphertext, expected []byte) error {
	got := hmacSHA256(key, iv, ciphertext)
	if !hmac.Equal(got, expected) {
		return &hmacMismatchError{}
	}
	return nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padded := make([]byte, len(data)+padding)
	copy(padded, data)
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	return padded
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, &aesDecryptError{detail: "pkcs7Unpad: invalid data length"}
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize {
		return nil, &aesDecryptError{detail: "pkcs7Unpad: invalid padding byte"}
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, &aesDecryptError{detail: "pkcs7Unpad: inconsistent padding"}
		}
	}
	return data[:len(data)-pad], nil
}

type aesDecryptError struct{ detail string }

func (e *aesDecryptError) Error() string { return "aesCBCDecrypt: " + e.detail }

type hmacMismatchError struct{}

func (e *hmacMismatchError) Error() string { return "HMAC verification failed" }

// ---------------------------------------------------------------------------
// Session helper: build Go stores from Rust-provided key material
// ---------------------------------------------------------------------------

// bobStoresFromRust reconstructs Bob's session stores from the key material
// returned by the Rust session_encrypt op.
func bobStoresFromRust(
	t *testing.T,
	resp map[string]json.RawMessage,
	ser *serialize.Serializer,
) (
	idStore *memIdentityStore,
	pkStore *memPreKeyStore,
	spkStore *memSignedPreKeyStore,
	kyberStore *memKyberPreKeyStore,
	sessStore *memSessionStore,
	bobAddr *protocol.SignalAddress,
	aliceAddr *protocol.SignalAddress,
) {
	t.Helper()

	bobIDPair := identityKeyPairFromHex(t,
		mustGetString(t, resp, "bob_identity_public_hex"),
		mustGetString(t, resp, "bob_identity_private_hex"),
	)
	regID := uint32(mustGetUint64(t, resp, "bob_registration_id"))
	idStore = newMemIdentityStore(bobIDPair, regID)
	pkStore = newMemPreKeyStore()
	spkStore = newMemSignedPreKeyStore()
	kyberStore = newMemKyberPreKeyStore()
	sessStore = newMemSessionStore(ser)

	// One-time pre-key.
	pkID := uint32(mustGetUint64(t, resp, "bob_pre_key_id"))
	pkPub := pubKeyFrom33Bytes(t, mustDecodeHex(t, mustGetString(t, resp, "bob_pre_key_public_hex")))
	pkPriv := privKeyFrom32Bytes(t, mustDecodeHex(t, mustGetString(t, resp, "bob_pre_key_private_hex")))
	pkKP := ecc.NewECKeyPair(pkPub, pkPriv)
	pkRecord := record.NewPreKey(pkID, pkKP, ser.PreKeyRecord)
	if err := pkStore.StorePreKey(pkID, pkRecord); err != nil {
		t.Fatalf("StorePreKey: %v", err)
	}

	// Signed pre-key.
	spkID := uint32(mustGetUint64(t, resp, "bob_signed_pre_key_id"))
	spkPrivBytes := mustDecodeHex(t, mustGetString(t, resp, "bob_signed_pre_key_private_hex"))
	spkPubBytes := mustDecodeHex(t, mustGetString(t, resp, "bob_signed_pre_key_public_hex"))
	spkSigBytes := mustDecodeHex(t, mustGetString(t, resp, "bob_signed_pre_key_sig_hex"))
	if len(spkSigBytes) != 64 {
		t.Fatalf("signed pre-key sig must be 64 bytes, got %d", len(spkSigBytes))
	}
	var spkSig [64]byte
	copy(spkSig[:], spkSigBytes)
	spkPrivKey := privKeyFrom32Bytes(t, spkPrivBytes)
	spkPubKey := pubKeyFrom33Bytes(t, spkPubBytes)
	spkKP := ecc.NewECKeyPair(spkPubKey, spkPrivKey)
	spkRecord := record.NewSignedPreKey(spkID, 1_000_000, spkKP, spkSig, ser.SignedPreKeyRecord)
	if err := spkStore.StoreSignedPreKey(spkID, spkRecord); err != nil {
		t.Fatalf("StoreSignedPreKey: %v", err)
	}

	// Kyber pre-key.
	kpkID := uint32(mustGetUint64(t, resp, "bob_kyber_pre_key_id"))
	kpkPubBytes := mustDecodeHex(t, mustGetString(t, resp, "bob_kyber_pre_key_public_hex"))
	kpkPrivBytes := mustDecodeHex(t, mustGetString(t, resp, "bob_kyber_pre_key_private_hex"))
	kpkSigBytes := mustDecodeHex(t, mustGetString(t, resp, "bob_kyber_pre_key_sig_hex"))
	// Rust serializes KEM private keys with a leading type byte; Go's
	// FromPublicAndPrivate expects raw private key data (no type prefix).
	kpkPrivRaw := kpkPrivBytes
	if len(kpkPrivBytes) > 0 && kpkPrivBytes[0] == kpkPubBytes[0] {
		kpkPrivRaw = kpkPrivBytes[1:]
	}
	kpkPair, err := kem.FromPublicAndPrivate(kpkPubBytes, kpkPrivRaw)
	if err != nil {
		t.Fatalf("kem.FromPublicAndPrivate: %v", err)
	}
	kyberRecord := record.NewKyberPreKey(kpkID, 1_000_000, kpkPair, kpkSigBytes, &nopKyberSerializer{})
	if err := kyberStore.StoreKyberPreKey(kpkID, kyberRecord); err != nil {
		t.Fatalf("StoreKyberPreKey: %v", err)
	}

	aliceUUID := mustGetString(t, resp, "alice_uuid")
	bobUUID := mustGetString(t, resp, "bob_uuid")
	aliceAddr = protocol.NewSignalAddress(aliceUUID, 1)
	bobAddr = protocol.NewSignalAddress(bobUUID, 1)

	// Trust Alice's identity.
	aliceIDPair := identityKeyPairFromHex(t,
		mustGetString(t, resp, "alice_identity_public_hex"),
		mustGetString(t, resp, "alice_identity_private_hex"),
	)
	if _, err := idStore.SaveIdentity(aliceAddr, aliceIDPair.PublicKey()); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	return
}

// ---------------------------------------------------------------------------
// Session round-trip tests
// ---------------------------------------------------------------------------

// TestLiveInterop_SessionRoundTrip_RustEncryptGoDecrypt encrypts with Rust's
// full PQXDH + Double Ratchet session machinery and decrypts with Go.
func TestLiveInterop_SessionRoundTrip_RustEncryptGoDecrypt(t *testing.T) {
	r := requireRunner(t)
	ser := goSerializer()

	const plaintext = "Hello from Rust"
	resp, err := r.RunCommand(map[string]any{
		"op":            "session_encrypt",
		"plaintext_hex": hex.EncodeToString([]byte(plaintext)),
		"seed_hex":      "01020304",
	})
	if err != nil {
		t.Fatalf("session_encrypt: %v", err)
	}

	pkmHex := mustGetString(t, resp, "prekey_msg_hex")
	pkmBytes := mustDecodeHex(t, pkmHex)

	// Reconstruct Bob's stores from Rust-provided key material.
	idStore, pkStore, spkStore, kyberStore, sessStore, _, aliceAddr := bobStoresFromRust(t, resp, ser)

	// Parse the PreKeySignalMessage.
	pkMsg, err := protocol.NewPreKeySignalMessageFromBytes(pkmBytes, ser.PreKeySignalMessage, ser.SignalMessage)
	if err != nil {
		t.Fatalf("NewPreKeySignalMessageFromBytes: %v", err)
	}

	// Build Go session cipher for Bob (remote=Alice).
	builder := session.NewBuilderWithKyber(
		sessStore, pkStore, spkStore, idStore, kyberStore,
		aliceAddr, ser,
	)
	cipher := session.NewCipher(builder, aliceAddr)

	// Decrypt.
	got, _, err := cipher.DecryptPreKeyMessage(builder, pkMsg)
	if err != nil {
		t.Fatalf("DecryptPreKeyMessage: %v", err)
	}

	if string(got) != plaintext {
		t.Errorf("plaintext mismatch:\n  got:  %q\n  want: %q", got, plaintext)
	}
	t.Logf("PASS: Rust-encrypted PreKeySignalMessage decrypted by Go to %q", got)
}

// TestLiveInterop_SessionRoundTrip_GoEncryptRustDecrypt encrypts with Go's
// PQXDH session and has Rust decrypt it.
func TestLiveInterop_SessionRoundTrip_GoEncryptRustDecrypt(t *testing.T) {
	r := requireRunner(t)
	ser := goSerializer()

	// Call Rust to get Bob's stable key material via session_encrypt probe.
	const plaintext = "Hello from Go"
	rustResp, err := r.RunCommand(map[string]any{
		"op":            "session_encrypt",
		"plaintext_hex": hex.EncodeToString([]byte("probe")),
		"seed_hex":      "05060708",
	})
	if err != nil {
		t.Fatalf("session_encrypt (probe): %v", err)
	}

	// Build Bob's stores from the Rust-generated key material.
	_, _, _, _, _, _, aliceAddr := bobStoresFromRust(t, rustResp, ser)
	_ = aliceAddr

	// Build Alice's identity.
	aliceIDPair := identityKeyPairFromHex(t,
		mustGetString(t, rustResp, "alice_identity_public_hex"),
		mustGetString(t, rustResp, "alice_identity_private_hex"),
	)
	aliceIDStore := newMemIdentityStore(aliceIDPair, 1001)

	// Build Bob's address and PreKeyBundle from Rust-provided key material.
	bobUUID := mustGetString(t, rustResp, "bob_uuid")
	bobAddr := protocol.NewSignalAddress(bobUUID, 1)

	regID := uint32(mustGetUint64(t, rustResp, "bob_registration_id"))
	pkID := &optional.Uint32{Value: uint32(mustGetUint64(t, rustResp, "bob_pre_key_id"))}
	pkPub := pubKeyFrom33Bytes(t, mustDecodeHex(t, mustGetString(t, rustResp, "bob_pre_key_public_hex")))
	spkID := uint32(mustGetUint64(t, rustResp, "bob_signed_pre_key_id"))
	spkPub := pubKeyFrom33Bytes(t, mustDecodeHex(t, mustGetString(t, rustResp, "bob_signed_pre_key_public_hex")))
	spkSigBytes := mustDecodeHex(t, mustGetString(t, rustResp, "bob_signed_pre_key_sig_hex"))
	if len(spkSigBytes) != 64 {
		t.Fatalf("spk sig must be 64 bytes, got %d", len(spkSigBytes))
	}
	var spkSig [64]byte
	copy(spkSig[:], spkSigBytes)
	bobIDPub := identity.NewKey(pubKeyFrom33Bytes(t, mustDecodeHex(t, mustGetString(t, rustResp, "bob_identity_public_hex"))))
	kpkID := &optional.Uint32{Value: uint32(mustGetUint64(t, rustResp, "bob_kyber_pre_key_id"))}
	kpkPubBytes := mustDecodeHex(t, mustGetString(t, rustResp, "bob_kyber_pre_key_public_hex"))
	kpkPub, err := kem.DeserializePublicKey(kpkPubBytes)
	if err != nil {
		t.Fatalf("kem.DeserializePublicKey: %v", err)
	}
	kpkSigBytes := mustDecodeHex(t, mustGetString(t, rustResp, "bob_kyber_pre_key_sig_hex"))

	bundle := prekey.NewBundleWithKyber(
		regID, 1, pkID, spkID,
		pkPub, spkPub, spkSig, bobIDPub,
		kpkID, kpkPub, kpkSigBytes,
	)

	// Trust Bob in Alice's identity store.
	if _, err := aliceIDStore.SaveIdentity(bobAddr, bobIDPub); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	// Build session from bundle.
	aliceSessStore := newMemSessionStore(ser)
	alicePKStore := newMemPreKeyStore()
	aliceSPKStore := newMemSignedPreKeyStore()
	aliceKyberStore := newMemKyberPreKeyStore()

	aliceBuilder := session.NewBuilderWithKyber(
		aliceSessStore, alicePKStore, aliceSPKStore, aliceIDStore, aliceKyberStore,
		bobAddr, ser,
	)
	if err := aliceBuilder.ProcessBundle(bundle); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}

	// Encrypt with Go.
	aliceCipher := session.NewCipher(aliceBuilder, bobAddr)
	ciphertextMsg, err := aliceCipher.Encrypt([]byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ciphertextBytes, err := ciphertextMsg.Serialize()
	if err != nil {
		t.Fatalf("Serialize ciphertext: %v", err)
	}

	// Have Rust decrypt using Bob's key material.
	decResp, err := r.RunCommand(map[string]any{
		"op":                             "session_decrypt",
		"prekey_msg_hex":                 hex.EncodeToString(ciphertextBytes),
		"bob_identity_private_hex":       mustGetString(t, rustResp, "bob_identity_private_hex"),
		"bob_identity_public_hex":        mustGetString(t, rustResp, "bob_identity_public_hex"),
		"bob_registration_id":            regID,
		"bob_pre_key_id":                 pkID.Value,
		"bob_pre_key_private_hex":        mustGetString(t, rustResp, "bob_pre_key_private_hex"),
		"bob_signed_pre_key_id":          spkID,
		"bob_signed_pre_key_private_hex": mustGetString(t, rustResp, "bob_signed_pre_key_private_hex"),
		"bob_signed_pre_key_sig_hex":     mustGetString(t, rustResp, "bob_signed_pre_key_sig_hex"),
		"bob_kyber_pre_key_id":           kpkID.Value,
		"bob_kyber_pre_key_public_hex":   mustGetString(t, rustResp, "bob_kyber_pre_key_public_hex"),
		"bob_kyber_pre_key_private_hex":  mustGetString(t, rustResp, "bob_kyber_pre_key_private_hex"),
		"bob_kyber_pre_key_sig_hex":      mustGetString(t, rustResp, "bob_kyber_pre_key_sig_hex"),
		"alice_identity_public_hex":      mustGetString(t, rustResp, "alice_identity_public_hex"),
		"alice_uuid":                     mustGetString(t, rustResp, "alice_uuid"),
		"bob_uuid":                       bobUUID,
	})
	if err != nil {
		t.Fatalf("session_decrypt: %v", err)
	}

	gotHex := mustGetString(t, decResp, "plaintext_hex")
	got, _ := hex.DecodeString(gotHex)
	if string(got) != plaintext {
		t.Errorf("plaintext mismatch:\n  got:  %q\n  want: %q", got, plaintext)
	}
	t.Logf("PASS: Go-encrypted PreKeySignalMessage decrypted by Rust to %q", got)
}

// ---------------------------------------------------------------------------
// Sealed Sender v1 round-trip tests
// ---------------------------------------------------------------------------

// TestLiveInterop_SealedSenderV1_RustEncryptGoDecrypt encrypts with Rust and
// decrypts with Go.
func TestLiveInterop_SealedSenderV1_RustEncryptGoDecrypt(t *testing.T) {
	r := requireRunner(t)

	const plaintext = "Sealed v1 from Rust"
	resp, err := r.RunCommand(map[string]any{
		"op":            "sealed_v1_encrypt",
		"plaintext_hex": hex.EncodeToString([]byte(plaintext)),
		"seed_hex":      "aabbccdd",
	})
	if err != nil {
		t.Fatalf("sealed_v1_encrypt: %v", err)
	}

	ctBytes := mustDecodeHex(t, mustGetString(t, resp, "ciphertext_hex"))
	bobPrivHex := mustGetString(t, resp, "bob_identity_private_hex")
	bobPubHex := mustGetString(t, resp, "bob_identity_public_hex")
	trustRootPubHex := mustGetString(t, resp, "trust_root_public_hex")
	certExpiryMS := mustGetUint64(t, resp, "cert_expiry_ms")

	bobIDPair := identityKeyPairFromHex(t, bobPubHex, bobPrivHex)
	bobIDStore := newMemIdentityStore(bobIDPair, 1002)

	// Trust the sender (Alice).
	alicePubKey := identity.NewKey(pubKeyFrom33Bytes(t, mustDecodeHex(t, mustGetString(t, resp, "alice_identity_public_hex"))))
	aliceAddr := protocol.NewSignalAddress(mustGetString(t, resp, "alice_uuid"), 1)
	if _, err := bobIDStore.SaveIdentity(aliceAddr, alicePubKey); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	trustRootPub := pubKeyFrom33Bytes(t, mustDecodeHex(t, trustRootPubHex))

	// Rust v1 sealed sender uses CiphertextMessageType::Plaintext (not a real Signal session),
	// so we just decrypt the outer sealed-sender layer and read the USMC contents directly.
	usmc, err := sealed.SealedSenderDecryptToUSMC(ctBytes, bobIDStore)
	if err != nil {
		t.Fatalf("SealedSenderDecryptToUSMC: %v", err)
	}

	// Validate the sender certificate.
	senderCert := usmc.Sender()
	valid, err := senderCert.Validate(trustRootPub, certExpiryMS-1000)
	if err != nil {
		t.Fatalf("SenderCertificate.Validate: %v", err)
	}
	if !valid {
		t.Fatalf("sender certificate is not valid")
	}

	got := usmc.Contents()
	if string(got) != plaintext {
		t.Errorf("plaintext mismatch:\n  got:  %q\n  want: %q", got, plaintext)
	}
	t.Logf("PASS: Rust sealed_v1_encrypt → Go decrypt: %q", got)
}

// TestLiveInterop_SealedSenderV1_GoEncryptRustDecrypt encrypts with Go and
// has Rust decrypt it.
func TestLiveInterop_SealedSenderV1_GoEncryptRustDecrypt(t *testing.T) {
	r := requireRunner(t)

	// Get stable key material from Rust.
	keyResp, err := r.RunCommand(map[string]any{
		"op":            "sealed_v1_encrypt",
		"plaintext_hex": hex.EncodeToString([]byte("probe")),
		"seed_hex":      "11223344",
	})
	if err != nil {
		t.Fatalf("sealed_v1_encrypt probe: %v", err)
	}

	aliceUUID := mustGetString(t, keyResp, "alice_uuid")
	bobUUID := mustGetString(t, keyResp, "bob_uuid")
	aliceAddr := protocol.NewSignalAddress(aliceUUID, 1)
	bobAddr := protocol.NewSignalAddress(bobUUID, 1)
	_ = aliceAddr

	aliceIDPair := identityKeyPairFromHex(t,
		mustGetString(t, keyResp, "alice_identity_public_hex"),
		mustGetString(t, keyResp, "alice_identity_private_hex"),
	)
	bobIDPair := identityKeyPairFromHex(t,
		mustGetString(t, keyResp, "bob_identity_public_hex"),
		mustGetString(t, keyResp, "bob_identity_private_hex"),
	)

	// Build sender cert from Rust-serialized bytes.
	senderCertBytes := mustDecodeHex(t, mustGetString(t, keyResp, "sender_cert_serialized_hex"))
	senderCert, err := sealed.DeserializeSenderCertificate(senderCertBytes)
	if err != nil {
		t.Fatalf("DeserializeSenderCertificate: %v", err)
	}

	// Go: set up Alice's identity store.
	aliceIDStore := newMemIdentityStore(aliceIDPair, 1001)

	// Alice must know Bob's identity key.
	if _, err := aliceIDStore.SaveIdentity(bobAddr, bobIDPair.PublicKey()); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	const plaintext = "Sealed v1 from Go"

	// Use SealedSenderEncryptFromUSMC with a Plaintext content type (type=8),
	// matching the Rust op which uses CiphertextMessageType::Plaintext.
	// This avoids the need for a pre-established Signal session.
	const plaintextContentType = uint32(8)
	usmc, err := sealed.NewUnidentifiedSenderMessageContent(
		plaintextContentType,
		senderCert,
		[]byte(plaintext),
		sealed.ContentHintDefault,
		nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent: %v", err)
	}
	ctBytes, err := sealed.SealedSenderEncryptFromUSMC(bobAddr, usmc, aliceIDStore)
	if err != nil {
		t.Fatalf("SealedSenderEncryptFromUSMC: %v", err)
	}

	// Rust decrypt.
	decResp, err := r.RunCommand(map[string]any{
		"op":                        "sealed_v1_decrypt",
		"ciphertext_hex":            hex.EncodeToString(ctBytes),
		"bob_identity_private_hex":  mustGetString(t, keyResp, "bob_identity_private_hex"),
		"alice_identity_public_hex": mustGetString(t, keyResp, "alice_identity_public_hex"),
		"alice_uuid":                aliceUUID,
		"bob_uuid":                  bobUUID,
	})
	if err != nil {
		t.Fatalf("sealed_v1_decrypt: %v", err)
	}

	gotHex := mustGetString(t, decResp, "plaintext_hex")
	got, _ := hex.DecodeString(gotHex)
	if string(got) != plaintext {
		t.Errorf("plaintext mismatch:\n  got:  %q\n  want: %q", got, plaintext)
	}
	t.Logf("PASS: Go sealed_v1_encrypt → Rust decrypt: %q", got)
}

// ---------------------------------------------------------------------------
// Sealed Sender v2 round-trip tests
// ---------------------------------------------------------------------------

// TestLiveInterop_SealedSenderV2_RustEncryptGoDecrypt encrypts a multi-recipient
// v2 message with Rust and decrypts with Go (Bob's view) using the received-format bytes.
func TestLiveInterop_SealedSenderV2_RustEncryptGoDecrypt(t *testing.T) {
	r := requireRunner(t)

	const plaintext = "Sealed v2 from Rust"
	resp, err := r.RunCommand(map[string]any{
		"op":            "sealed_v2_encrypt",
		"plaintext_hex": hex.EncodeToString([]byte(plaintext)),
		"seed_hex":      "cafebabe",
	})
	if err != nil {
		t.Fatalf("sealed_v2_encrypt: %v", err)
	}

	bobReceivedBytes := mustDecodeHex(t, mustGetString(t, resp, "bob_received_hex"))
	trustRootPubHex := mustGetString(t, resp, "trust_root_public_hex")
	certExpiryMS := mustGetUint64(t, resp, "cert_expiry_ms")

	// Bob decrypts the received-format message.
	bobIDPair := identityKeyPairFromHex(t,
		mustGetString(t, resp, "bob_identity_public_hex"),
		mustGetString(t, resp, "bob_identity_private_hex"),
	)
	bobIDStore := newMemIdentityStore(bobIDPair, 1002)

	alicePubKey := identity.NewKey(pubKeyFrom33Bytes(t, mustDecodeHex(t, mustGetString(t, resp, "alice_identity_public_hex"))))
	aliceAddr := protocol.NewSignalAddress(mustGetString(t, resp, "alice_uuid"), 1)
	if _, err := bobIDStore.SaveIdentity(aliceAddr, alicePubKey); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}

	trustRootPub := pubKeyFrom33Bytes(t, mustDecodeHex(t, trustRootPubHex))

	// Decrypt the v2 received-format bytes.
	usmc, err := sealed.SealedSenderV2DecryptReceivedToUSMC(bobReceivedBytes, bobIDStore)
	if err != nil {
		t.Fatalf("SealedSenderV2DecryptReceivedToUSMC: %v", err)
	}

	// Validate the sender certificate.
	senderCert := usmc.Sender()
	valid, err := senderCert.Validate(trustRootPub, certExpiryMS-1000)
	if err != nil {
		t.Fatalf("SenderCertificate.Validate: %v", err)
	}
	if !valid {
		t.Fatalf("sender certificate is not valid")
	}

	got := usmc.Contents()
	if string(got) != plaintext {
		t.Errorf("plaintext mismatch:\n  got:  %q\n  want: %q", got, plaintext)
	}
	t.Logf("PASS: Rust sealed_v2_encrypt → Go decrypt: %q", got)
}

// TestLiveInterop_SealedSenderV2_GoEncryptRustDecrypt encrypts with Go's v2
// multi-recipient machinery using Go-generated key material and has Rust decrypt
// Bob's received-format bytes.
func TestLiveInterop_SealedSenderV2_GoEncryptRustDecrypt(t *testing.T) {
	r := requireRunner(t)
	ser := goSerializer()

	const aliceUUID = "11111111-1111-1111-1111-111111111111"
	const bobUUID = "22222222-2222-2222-2222-222222222222"
	const aliceE164 = "+14151111111"
	const certExpiryMS = uint64(4_102_444_800_000)

	// Generate all key material in Go.
	trustRootKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair trustRoot: %v", err)
	}
	serverKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair server: %v", err)
	}
	aliceIDPair, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity.GenerateKeyPair alice: %v", err)
	}
	bobIDPair, err := identity.GenerateKeyPair()
	if err != nil {
		t.Fatalf("identity.GenerateKeyPair bob: %v", err)
	}

	// Generate Bob's one-time prekey, signed prekey, and Kyber prekey.
	bobPKKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair bobPK: %v", err)
	}
	bobSPKKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair bobSPK: %v", err)
	}
	bobSPKSig, err := ecc.CalculateSignature(bobIDPair.PrivateKey(), bobSPKKP.PublicKey().Serialize())
	if err != nil {
		t.Fatalf("CalculateSignature bobSPK: %v", err)
	}
	bobKyberKEM := kem.NewKyber1024KEM()
	bobKyberPair, err := bobKyberKEM.Generate()
	if err != nil {
		t.Fatalf("kyber Generate: %v", err)
	}
	bobKyberSig, err := ecc.CalculateSignature(bobIDPair.PrivateKey(), bobKyberPair.Public.Serialize())
	if err != nil {
		t.Fatalf("CalculateSignature bobKyber: %v", err)
	}

	// Populate Bob's stores.
	bobIDStore := newMemIdentityStore(bobIDPair, 1002)
	bobPKStore := newMemPreKeyStore()
	bobSPKStore := newMemSignedPreKeyStore()
	bobKyberStore := newMemKyberPreKeyStore()
	bobSessStore := newMemSessionStore(ser)

	const bobPKID = uint32(101)
	const bobSPKID = uint32(201)
	const bobKyberID = uint32(301)

	if err := bobPKStore.StorePreKey(bobPKID, record.NewPreKey(bobPKID, bobPKKP, ser.PreKeyRecord)); err != nil {
		t.Fatalf("StorePreKey: %v", err)
	}
	if err := bobSPKStore.StoreSignedPreKey(bobSPKID, record.NewSignedPreKey(bobSPKID, 1_000_000, bobSPKKP, bobSPKSig, ser.SignedPreKeyRecord)); err != nil {
		t.Fatalf("StoreSignedPreKey: %v", err)
	}
	if err := bobKyberStore.StoreKyberPreKey(bobKyberID, record.NewKyberPreKey(bobKyberID, 1_000_000, bobKyberPair, bobKyberSig[:], &nopKyberSerializer{})); err != nil {
		t.Fatalf("StoreKyberPreKey: %v", err)
	}
	_ = bobSessStore
	_ = bobIDStore

	// Build trust chain for the sender certificate.
	serverCert, err := sealed.NewServerCertificate(1, serverKP.PublicKey(), trustRootKP.PrivateKey())
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}
	e164 := aliceE164
	senderCert, err := sealed.NewSenderCertificate(
		aliceUUID, &e164,
		aliceIDPair.PublicKey().PublicKey(),
		1, certExpiryMS, serverCert,
		serverKP.PrivateKey(),
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate: %v", err)
	}

	// Alice establishes a session with Bob by processing his bundle.
	bobKyberPKID := &optional.Uint32{Value: bobKyberID}
	bobPKOptID := &optional.Uint32{Value: bobPKID}
	bundle := prekey.NewBundleWithKyber(
		1002, 1, bobPKOptID, bobSPKID,
		bobPKKP.PublicKey(), bobSPKKP.PublicKey(), bobSPKSig,
		bobIDPair.PublicKey(),
		bobKyberPKID, bobKyberPair.Public, bobKyberSig[:],
	)

	aliceIDStore := newMemIdentityStore(aliceIDPair, 1001)
	aliceSessStore := newMemSessionStore(ser)
	alicePKStore := newMemPreKeyStore()
	aliceSPKStore := newMemSignedPreKeyStore()
	aliceKyberStore := newMemKyberPreKeyStore()

	bobAddr := protocol.NewSignalAddress(bobUUID, 1)
	if _, err := aliceIDStore.SaveIdentity(bobAddr, bobIDPair.PublicKey()); err != nil {
		t.Fatalf("SaveIdentity bob: %v", err)
	}

	aliceBuilder := session.NewBuilderWithKyber(
		aliceSessStore, alicePKStore, aliceSPKStore, aliceIDStore, aliceKyberStore,
		bobAddr, ser,
	)
	if err := aliceBuilder.ProcessBundle(bundle); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}

	// Load the established session record for Bob.
	bobSession, err := aliceSessStore.LoadSession(bobAddr)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}

	const ptxt = "Sealed v2 from Go"

	// PlaintextContent = type 8 (mirrors Rust's CiphertextMessageType::Plaintext).
	const plaintextContentType = uint32(8)
	usmc, err := sealed.NewUnidentifiedSenderMessageContent(
		plaintextContentType,
		senderCert,
		[]byte(ptxt),
		sealed.ContentHintDefault,
		nil,
	)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent: %v", err)
	}

	// Multi-recipient encrypt.
	sentBytes, err := sealed.SealedSenderMultiRecipientEncrypt(
		[]*protocol.SignalAddress{bobAddr},
		[]*record.Session{bobSession},
		nil,
		usmc,
		aliceIDStore,
	)
	if err != nil {
		t.Fatalf("SealedSenderMultiRecipientEncrypt: %v", err)
	}

	// Parse the sent message and extract Bob's received bytes.
	parsed, err := sealed.ParseSealedSenderV2SentMessage(sentBytes)
	if err != nil {
		t.Fatalf("ParseSealedSenderV2SentMessage: %v", err)
	}

	bobServiceID, err := protocol.ServiceIdFromString(protocol.ServiceIdKindACI, bobUUID)
	if err != nil {
		t.Fatalf("ServiceIdFromString: %v", err)
	}
	bobReceivedBytes, err := parsed.MessageForRecipient(bobServiceID)
	if err != nil {
		t.Fatalf("MessageForRecipient: %v", err)
	}

	// Rust decrypts Bob's received bytes using Bob's identity private key.
	decResp, err := r.RunCommand(map[string]any{
		"op":                             "sealed_v2_decrypt",
		"received_hex":                   hex.EncodeToString(bobReceivedBytes),
		"recipient_identity_private_hex": func() string { s := bobIDPair.PrivateKey().Serialize(); return hex.EncodeToString(s[:]) }(),
		"alice_identity_public_hex":      hex.EncodeToString(aliceIDPair.PublicKey().PublicKey().Serialize()),
		"alice_uuid":                     aliceUUID,
		"recipient_uuid":                 bobUUID,
	})
	if err != nil {
		t.Fatalf("sealed_v2_decrypt: %v", err)
	}

	gotHex := mustGetString(t, decResp, "plaintext_hex")
	got, _ := hex.DecodeString(gotHex)
	if string(got) != ptxt {
		t.Errorf("plaintext mismatch:\n  got:  %q\n  want: %q", got, ptxt)
	}
	t.Logf("PASS: Go sealed_v2_encrypt → Rust decrypt: %q", got)
}

// ---------------------------------------------------------------------------
// SenderKey (group) round-trip tests
// ---------------------------------------------------------------------------

// TestLiveInterop_SenderKey_RustEncryptGoDecrypt creates a SenderKey session
// in Rust and has Go decrypt the message.
func TestLiveInterop_SenderKey_RustEncryptGoDecrypt(t *testing.T) {
	r := requireRunner(t)
	ser := goSerializer()

	const plaintext = "Group message from Rust"
	resp, err := r.RunCommand(map[string]any{
		"op":              "sender_key_encrypt",
		"plaintext_hex":   hex.EncodeToString([]byte(plaintext)),
		"alice_uuid":      "11111111-1111-1111-1111-111111111111",
		"distribution_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
		"seed_hex":        "facefeed",
	})
	if err != nil {
		t.Fatalf("sender_key_encrypt: %v", err)
	}

	skdmHex := mustGetString(t, resp, "skdm_hex")
	skdmBytes := mustDecodeHex(t, skdmHex)
	ctHex := mustGetString(t, resp, "ciphertext_hex")
	ctBytes := mustDecodeHex(t, ctHex)
	distIDStr := mustGetString(t, resp, "distribution_id")
	aliceUUID := mustGetString(t, resp, "alice_uuid")

	// Parse distribution ID (UUID string → [16]byte).
	distIDBytes := mustDecodeHex(t, distIDStr[0:8]+distIDStr[9:13]+distIDStr[14:18]+distIDStr[19:23]+distIDStr[24:])
	if len(distIDBytes) != 16 {
		t.Fatalf("distribution_id must be 16 bytes, got %d", len(distIDBytes))
	}
	var distID [16]byte
	copy(distID[:], distIDBytes)

	// Go: process SKDM and decrypt.
	aliceAddr := protocol.NewSignalAddress(aliceUUID, 1)
	groupID := groupPkg.DistributionIDToGroupID(distID)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddr)

	bobSenderKeyStore := newMemSenderKeyStore()
	bobGroupBuilder := groupPkg.NewGroupSessionBuilder(bobSenderKeyStore, ser)

	// Parse the SKDM.
	skdm, err := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, ser.SenderKeyDistributionMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyDistributionMessageFromBytes: %v", err)
	}
	if err := bobGroupBuilder.Process(senderKeyName, skdm); err != nil {
		t.Fatalf("Process SKDM: %v", err)
	}

	// Decrypt the SenderKeyMessage.
	skm, err := protocol.NewSenderKeyMessageFromBytes(ctBytes, ser.SenderKeyMessage)
	if err != nil {
		t.Fatalf("NewSenderKeyMessageFromBytes: %v", err)
	}
	bobCipher := groupPkg.NewGroupCipher(bobGroupBuilder, senderKeyName, bobSenderKeyStore)
	got, err := bobCipher.Decrypt(skm)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(got) != plaintext {
		t.Errorf("plaintext mismatch:\n  got:  %q\n  want: %q", got, plaintext)
	}
	t.Logf("PASS: Rust sender_key_encrypt → Go decrypt: %q", got)
}

// TestLiveInterop_SenderKey_GoEncryptRustDecrypt creates a SenderKey session
// in Go and has Rust decrypt the SenderKeyMessage.
func TestLiveInterop_SenderKey_GoEncryptRustDecrypt(t *testing.T) {
	r := requireRunner(t)
	ser := goSerializer()

	const plaintext = "Group message from Go"
	const aliceUUID = "11111111-1111-1111-1111-111111111111"
	const distIDStr = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	// Parse distribution ID.
	distIDBytes := mustDecodeHex(t, "aaaaaaaabbbbccccddddeeeeeeeeeeee")
	var distID [16]byte
	copy(distID[:], distIDBytes)

	aliceAddr := protocol.NewSignalAddress(aliceUUID, 1)
	groupID := groupPkg.DistributionIDToGroupID(distID)
	senderKeyName := protocol.NewSenderKeyName(groupID, aliceAddr)

	aliceSenderKeyStore := newMemSenderKeyStore()
	aliceGroupBuilder := groupPkg.NewGroupSessionBuilder(aliceSenderKeyStore, ser)

	// Create the sender key distribution message.
	skdm, err := aliceGroupBuilder.Create(distID, senderKeyName)
	if err != nil {
		t.Fatalf("Create SKDM: %v", err)
	}
	skdmBytes, err := skdm.Serialize()
	if err != nil {
		t.Fatalf("SKDM Serialize: %v", err)
	}

	// Encrypt with Go.
	aliceCipher := groupPkg.NewGroupCipher(aliceGroupBuilder, senderKeyName, aliceSenderKeyStore)
	ciphertextMsg, err := aliceCipher.Encrypt(distID, []byte(plaintext))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	// SignedSerialize includes the signature; Rust expects this format on the wire.
	skm, ok := ciphertextMsg.(*protocol.SenderKeyMessage)
	if !ok {
		t.Fatalf("expected *protocol.SenderKeyMessage, got %T", ciphertextMsg)
	}
	ctBytes, err := skm.SignedSerialize()
	if err != nil {
		t.Fatalf("SignedSerialize: %v", err)
	}

	// Rust decrypts.
	decResp, err := r.RunCommand(map[string]any{
		"op":              "sender_key_decrypt",
		"alice_uuid":      aliceUUID,
		"distribution_id": distIDStr,
		"skdm_hex":        hex.EncodeToString(skdmBytes),
		"ciphertext_hex":  hex.EncodeToString(ctBytes),
	})
	if err != nil {
		t.Fatalf("sender_key_decrypt: %v", err)
	}

	gotHex := mustGetString(t, decResp, "plaintext_hex")
	got, _ := hex.DecodeString(gotHex)
	if string(got) != plaintext {
		t.Errorf("plaintext mismatch:\n  got:  %q\n  want: %q", got, plaintext)
	}
	t.Logf("PASS: Go sender_key_encrypt → Rust decrypt: %q", got)
}

// ---------------------------------------------------------------------------
// Backup frame round-trip tests
// ---------------------------------------------------------------------------

// TestLiveInterop_Backup_RustEncryptGoDecrypt encrypts a backup frame in Rust
// (raw AES-256-CBC + PKCS7 + HMAC-SHA256) and decrypts it in Go.
func TestLiveInterop_Backup_RustEncryptGoDecrypt(t *testing.T) {
	r := requireRunner(t)

	const plaintext = "Backup frame from Rust"
	hmacKey := bytes.Repeat([]byte{0xAB}, 32)
	aesKey := bytes.Repeat([]byte{0xCD}, 32)
	iv := bytes.Repeat([]byte{0xEF}, 16)

	resp, err := r.RunCommand(map[string]any{
		"op":            "backup_encrypt",
		"hmac_key_hex":  hex.EncodeToString(hmacKey),
		"aes_key_hex":   hex.EncodeToString(aesKey),
		"plaintext_hex": hex.EncodeToString([]byte(plaintext)),
		"iv_hex":        hex.EncodeToString(iv),
		"seed_hex":      "01234567",
	})
	if err != nil {
		t.Fatalf("backup_encrypt: %v", err)
	}

	ivBytes := mustDecodeHex(t, mustGetString(t, resp, "iv_hex"))
	ctBytes := mustDecodeHex(t, mustGetString(t, resp, "ciphertext_hex"))
	hmacBytes := mustDecodeHex(t, mustGetString(t, resp, "hmac_hex"))

	// Verify HMAC.
	if err := verifyHMACSHA256(hmacKey, ivBytes, ctBytes, hmacBytes); err != nil {
		t.Fatalf("HMAC verification failed: %v", err)
	}

	// Decrypt.
	got, err := aesCBCDecrypt(aesKey, ivBytes, ctBytes)
	if err != nil {
		t.Fatalf("aesCBCDecrypt: %v", err)
	}

	if string(got) != plaintext {
		t.Errorf("plaintext mismatch:\n  got:  %q\n  want: %q", got, plaintext)
	}
	t.Logf("PASS: Rust backup_encrypt → Go decrypt: %q", got)
}

// TestLiveInterop_Backup_GoEncryptRustDecrypt encrypts a backup frame in Go
// (raw AES-256-CBC + PKCS7 + HMAC-SHA256) and has Rust decrypt it.
func TestLiveInterop_Backup_GoEncryptRustDecrypt(t *testing.T) {
	r := requireRunner(t)

	const plaintext = "Backup frame from Go"
	hmacKey := bytes.Repeat([]byte{0x11}, 32)
	aesKey := bytes.Repeat([]byte{0x22}, 32)
	iv := bytes.Repeat([]byte{0x33}, 16)

	// Encrypt: AES-256-CBC + PKCS7.
	ctBytes, err := aesCBCEncrypt(aesKey, iv, []byte(plaintext))
	if err != nil {
		t.Fatalf("aesCBCEncrypt: %v", err)
	}
	hmacBytes := hmacSHA256(hmacKey, iv, ctBytes)

	// Rust decrypt.
	decResp, err := r.RunCommand(map[string]any{
		"op":             "backup_decrypt",
		"hmac_key_hex":   hex.EncodeToString(hmacKey),
		"aes_key_hex":    hex.EncodeToString(aesKey),
		"iv_hex":         hex.EncodeToString(iv),
		"ciphertext_hex": hex.EncodeToString(ctBytes),
		"hmac_hex":       hex.EncodeToString(hmacBytes),
	})
	if err != nil {
		t.Fatalf("backup_decrypt: %v", err)
	}

	gotHex := mustGetString(t, decResp, "plaintext_hex")
	got, _ := hex.DecodeString(gotHex)
	if string(got) != plaintext {
		t.Errorf("plaintext mismatch:\n  got:  %q\n  want: %q", got, plaintext)
	}
	t.Logf("PASS: Go backup_encrypt → Rust decrypt: %q", got)
}
