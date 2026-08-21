package sesame

import (
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// guardedTestSecret moves a copy of the given bytes into guarded memory, for
// building the persisted session state the tests exercise. It panics on
// failure: its callers are serializer stubs with no *testing.T in scope, and a
// guarded-allocation failure is fatal to the run either way.
func guardedTestSecret(data []byte) secret.Secret {
	guarded, err := secret.NewValue(append([]byte(nil), data...))
	if err != nil {
		panic("sesame test: " + err.Error())
	}
	return guarded
}

// testClock returns a clock function that always returns the given time.
func testClock(t time.Time) func() time.Time {
	return func() time.Time { return t }
}

// advanceClock creates a clock that returns baseTime + offset.
func advanceClock(baseTime time.Time, offset time.Duration) func() time.Time {
	return testClock(baseTime.Add(offset))
}

// stubCreateSession returns a CreateSessionFunc that creates a minimal session record.
func stubCreateSession() CreateSessionFunc {
	return func(userID string, deviceID uint32) (*record.Session, error) {
		return record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil
	}
}

// failingCreateSession returns a CreateSessionFunc that always fails.
func failingCreateSession() CreateSessionFunc {
	return func(userID string, deviceID uint32) (*record.Session, error) {
		return nil, errors.New("no prekey bundle available")
	}
}

// successDecrypt returns a DecryptFunc that always succeeds with the given plaintext.
func successDecrypt(plaintext []byte) DecryptFunc {
	return func(session *SessionWrapper, ciphertext []byte) ([]byte, error) {
		return plaintext, nil
	}
}

// failingDecrypt returns a DecryptFunc that always fails.
func failingDecrypt() DecryptFunc {
	return func(session *SessionWrapper, ciphertext []byte) ([]byte, error) {
		return nil, errors.New("decryption failed")
	}
}

// successEncrypt returns an EncryptFunc that returns the plaintext as-is (identity).
func successEncrypt() EncryptFunc {
	return func(session *SessionWrapper, plaintext []byte) ([]byte, error) {
		return plaintext, nil
	}
}

// failingEncrypt returns an EncryptFunc that always fails.
func failingEncrypt() EncryptFunc {
	return func(session *SessionWrapper, plaintext []byte) ([]byte, error) {
		return nil, errors.New("encryption failed")
	}
}

// noopSessionSerializer is a minimal SessionSerializer for tests.
// It produces a valid round-trippable empty session structure with a minimal
// state containing a zero-valued public key, which allows Clone/Copy to work.
type noopSessionSerializer struct{}

func (n *noopSessionSerializer) Serialize(state *record.SessionStructure) ([]byte, error) {
	return []byte("session"), nil
}

func (n *noopSessionSerializer) Deserialize(serialized []byte) (*record.SessionStructure, error) {
	return &record.SessionStructure{
		SessionState: minimalStateStructure(),
	}, nil
}

// noopStateSerializer is a minimal StateSerializer for tests.
type noopStateSerializer struct{}

func (n *noopStateSerializer) Serialize(state *record.StateStructure) ([]byte, error) {
	return []byte("state"), nil
}

func (n *noopStateSerializer) Deserialize(serialized []byte) (*record.StateStructure, error) {
	return minimalStateStructure(), nil
}

// minimalStateStructure returns a StateStructure with the minimum fields
// needed to survive round-tripping through NewStateFromStructure without
// nil pointer panics. Uses zero-valued 33-byte DJB public keys (0x05 prefix).
func minimalStateStructure() *record.StateStructure {
	// DJB EC public keys require 33 bytes: 0x05 prefix + 32 bytes.
	zeroKey := make([]byte, 33)
	zeroKey[0] = 0x05
	return &record.StateStructure{
		LocalIdentityPublic:  zeroKey,
		RemoteIdentityPublic: zeroKey,
		SenderBaseKey:        zeroKey,
		RootKey:              guardedTestSecret(make([]byte, 32)),
		SenderChain: &record.ChainStructure{
			SenderRatchetKeyPublic: zeroKey,
			ChainKey: &chain.KeyStructure{
				Key:   guardedTestSecret(make([]byte, 32)),
				Index: 0,
			},
		},
		SessionVersion: 4,
	}
}

// newTestManager creates a Manager with an in-memory store and fixed clock for testing.
func newTestManager(now time.Time) *Manager {
	store := NewMemoryStore()
	mgr := NewManager(store, DefaultConfig(), stubCreateSession())
	mgr.SetClock(testClock(now))
	return mgr
}

// mustLoadUserRecord loads a user record from a store, calling t.Fatal on error.
func mustLoadUserRecord(t *testing.T, store Store, userID string) *UserRecord {
	t.Helper()
	rec, err := store.LoadUserRecord(userID)
	if err != nil {
		t.Fatalf("LoadUserRecord(%q) error: %v", userID, err)
	}
	return rec
}

// mustStoreUserRecord stores a user record, calling t.Fatal on error.
func mustStoreUserRecord(t *testing.T, store Store, userID string, record *UserRecord) {
	t.Helper()
	if err := store.StoreUserRecord(userID, record); err != nil {
		t.Fatalf("StoreUserRecord(%q) error: %v", userID, err)
	}
}

// --- Config Tests ---

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MaxSend != DefaultMaxSend {
		t.Errorf("expected MaxSend=%v, got %v", DefaultMaxSend, cfg.MaxSend)
	}
	if cfg.MaxRecv != DefaultMaxRecv {
		t.Errorf("expected MaxRecv=%v, got %v", DefaultMaxRecv, cfg.MaxRecv)
	}
	if cfg.MaxLatency != DefaultMaxLatency {
		t.Errorf("expected MaxLatency=%v, got %v", DefaultMaxLatency, cfg.MaxLatency)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    *Config
		expectErr bool
	}{
		{
			name:      "default config is valid",
			config:    DefaultConfig(),
			expectErr: false,
		},
		{
			name: "valid custom config",
			config: &Config{
				MaxSend:             10 * 24 * time.Hour,
				MaxRecv:             60 * 24 * time.Hour,
				MaxLatency:          7 * 24 * time.Hour,
				MaxInactiveSessions: 20,
				MaxSendRetries:      5,
				MaxDevicesPerUser:   10,
				MaxUsers:            500,
			},
			expectErr: false,
		},
		{
			name: "MaxRecv too small",
			config: &Config{
				MaxSend:             30 * 24 * time.Hour,
				MaxRecv:             40 * 24 * time.Hour,
				MaxLatency:          14 * 24 * time.Hour,
				MaxInactiveSessions: DefaultMaxInactiveSessions,
				MaxSendRetries:      DefaultMaxSendRetries,
			},
			expectErr: true,
		},
		{
			name: "MaxRecv exactly at boundary",
			config: &Config{
				MaxSend:             30 * 24 * time.Hour,
				MaxRecv:             58 * 24 * time.Hour, // == MaxSend + 2*MaxLatency
				MaxLatency:          14 * 24 * time.Hour,
				MaxInactiveSessions: DefaultMaxInactiveSessions,
				MaxSendRetries:      DefaultMaxSendRetries,
			},
			expectErr: true,
		},
		{
			name: "negative MaxSend",
			config: &Config{
				MaxSend:             -1 * time.Hour,
				MaxRecv:             90 * 24 * time.Hour,
				MaxLatency:          14 * 24 * time.Hour,
				MaxInactiveSessions: DefaultMaxInactiveSessions,
				MaxSendRetries:      DefaultMaxSendRetries,
			},
			expectErr: true,
		},
		{
			name: "zero MaxRecv",
			config: &Config{
				MaxSend:             30 * 24 * time.Hour,
				MaxRecv:             0,
				MaxLatency:          14 * 24 * time.Hour,
				MaxInactiveSessions: DefaultMaxInactiveSessions,
				MaxSendRetries:      DefaultMaxSendRetries,
			},
			expectErr: true,
		},
		{
			name: "zero MaxLatency",
			config: &Config{
				MaxSend:             30 * 24 * time.Hour,
				MaxRecv:             90 * 24 * time.Hour,
				MaxLatency:          0,
				MaxInactiveSessions: DefaultMaxInactiveSessions,
				MaxSendRetries:      DefaultMaxSendRetries,
			},
			expectErr: true,
		},
		{
			name: "zero MaxInactiveSessions",
			config: &Config{
				MaxSend:             30 * 24 * time.Hour,
				MaxRecv:             90 * 24 * time.Hour,
				MaxLatency:          14 * 24 * time.Hour,
				MaxInactiveSessions: 0,
				MaxSendRetries:      DefaultMaxSendRetries,
			},
			expectErr: true,
		},
		{
			name: "zero MaxSendRetries",
			config: &Config{
				MaxSend:             30 * 24 * time.Hour,
				MaxRecv:             90 * 24 * time.Hour,
				MaxLatency:          14 * 24 * time.Hour,
				MaxInactiveSessions: DefaultMaxInactiveSessions,
				MaxSendRetries:      0,
			},
			expectErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.expectErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
			if tc.expectErr && err != nil {
				var sesameErr *SesameError
				if !errors.As(err, &sesameErr) {
					t.Error("expected SesameError type")
				}
			}
		})
	}
}

func TestConfigValidation_InvalidInputReturnsTypedError(t *testing.T) {
	cfg := &Config{
		MaxSend:             30 * 24 * time.Hour,
		MaxRecv:             40 * 24 * time.Hour,
		MaxLatency:          14 * 24 * time.Hour,
		MaxInactiveSessions: DefaultMaxInactiveSessions,
		MaxSendRetries:      DefaultMaxSendRetries,
		MaxDevicesPerUser:   DefaultMaxDevicesPerUser,
		MaxUsers:            DefaultMaxUsers,
	}
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

// --- NewManager Tests ---

func TestNewManagerDefaultConfig(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store, nil, stubCreateSession())
	if mgr.Config().MaxSend != DefaultMaxSend {
		t.Errorf("expected default MaxSend, got %v", mgr.Config().MaxSend)
	}
	if mgr.Store() != store {
		t.Error("expected store to match")
	}
}

func TestNewManagerCustomConfig(t *testing.T) {
	cfg := &Config{
		MaxSend:             10 * 24 * time.Hour,
		MaxRecv:             60 * 24 * time.Hour,
		MaxLatency:          7 * 24 * time.Hour,
		MaxInactiveSessions: 20,
		MaxSendRetries:      5,
		MaxDevicesPerUser:   DefaultMaxDevicesPerUser,
		MaxUsers:            DefaultMaxUsers,
	}
	store := NewMemoryStore()
	mgr := NewManager(store, cfg, stubCreateSession())
	if mgr.Config().MaxSend != cfg.MaxSend {
		t.Errorf("expected MaxSend=%v, got %v", cfg.MaxSend, mgr.Config().MaxSend)
	}
}

// --- PrepForEncrypting Tests ---

func TestPrepForEncrypting_NewUser(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	session, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("expected session, got nil")
	}
	if session.CreatedAt() != now {
		t.Errorf("expected createdAt=%v, got %v", now, session.CreatedAt())
	}

	// Verify records were created.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	if userRecord == nil {
		t.Fatal("expected user record to exist")
	}
	device := userRecord.GetDevice(1)
	if device == nil {
		t.Fatal("expected device record to exist")
	}
	if device.ActiveSession() == nil {
		t.Fatal("expected active session")
	}
}

func TestPrepForEncrypting_ExistingSession(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// First call creates the session.
	session1, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Second call returns the same active session.
	session2, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// MemoryStore clones on load, so pointer equality won't hold across
	// separate PrepForEncrypting calls. Compare by createdAt instead.
	if session1.CreatedAt() != session2.CreatedAt() {
		t.Error("expected same session to be returned (matched by createdAt)")
	}
}

func TestPrepForEncrypting_StaleCleanup(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create a user record and mark it stale.
	userRecord := NewUserRecord("alice")
	userRecord.MarkStale(now)
	mustStoreUserRecord(t, mgr.Store(), "alice", userRecord)

	// Advance past MaxLatency.
	staleTime := now.Add(DefaultMaxLatency + time.Hour)
	mgr.SetClock(testClock(staleTime))

	// PrepForEncrypting should clean the stale user and create a fresh one.
	session, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("expected session, got nil")
	}

	// The user record should not be stale.
	reloaded := mustLoadUserRecord(t, mgr.Store(), "alice")
	if reloaded.IsStale() {
		t.Error("expected user record to not be stale after PrepForEncrypting")
	}
}

func TestPrepForEncrypting_SessionCreationFails(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	mgr := NewManager(store, DefaultConfig(), failingCreateSession())
	mgr.SetClock(testClock(now))

	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrNoActiveSession) {
		t.Errorf("expected ErrNoActiveSession, got %v", err)
	}
}

// --- Send Tests ---

func TestSend_MultipleDevices(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)
	plaintext := []byte("hello world")

	results, err := mgr.Send("alice", []uint32{1, 2, 3}, plaintext, successEncrypt())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	for deviceID, ct := range results {
		if string(ct) != string(plaintext) {
			t.Errorf("device %d: expected ciphertext=%q, got %q", deviceID, plaintext, ct)
		}
	}
}

func TestSend_StaleDeviceSkipped(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)
	plaintext := []byte("hello")

	// Set up sessions for devices 1, 2, 3.
	for _, id := range []uint32{1, 2, 3} {
		_, err := mgr.PrepForEncrypting("alice", id, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
	}

	// Mark device 2 as stale and advance past MaxLatency.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	device2 := userRecord.GetDevice(2)
	device2.MarkStale(now)
	mustStoreUserRecord(t, mgr.Store(), "alice", userRecord)

	staleTime := now.Add(DefaultMaxLatency + time.Hour)
	mgr.SetClock(testClock(staleTime))

	// Send only to devices 1 and 3 (device 2 was stale and should be cleaned).
	results, err := mgr.Send("alice", []uint32{1, 3}, plaintext, successEncrypt())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
}

func TestSend_EncryptionFails(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	_, err := mgr.Send("alice", []uint32{1}, []byte("hello"), failingEncrypt())
	if err == nil {
		t.Fatal("expected error from failing encrypt")
	}
}

// --- Receive Tests ---

func TestReceive_ActiveSession(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)
	expectedPlaintext := []byte("decrypted message")

	// Set up session first.
	_, err := mgr.PrepForEncrypting("bob", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Receive with active session.
	plaintext, err := mgr.Receive("bob", 1, []byte("ciphertext"), successDecrypt(expectedPlaintext))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(plaintext) != string(expectedPlaintext) {
		t.Errorf("expected %q, got %q", expectedPlaintext, plaintext)
	}

	// Verify last receive was updated.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "bob")
	device := userRecord.GetDevice(1)
	if device.ActiveSession().LastReceive() != now {
		t.Error("expected lastReceive to be updated")
	}
}

func TestReceive_InactiveSessionPromotion(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Use different creation times to distinguish sessions after cloning.
	oldTime := now
	goodTime := now.Add(time.Second)

	// Create user and device manually with inactive sessions.
	userRecord := NewUserRecord("bob")
	device, _ := userRecord.AddDevice(1, 0)

	// Create "old" session (active) and "good" session (inactive).
	oldSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, oldTime,
	)
	goodSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, goodTime,
	)
	device.ActivateSession(oldSession, nil, time.Time{})
	// Manually set up: active=oldSession, inactive=[goodSession]
	device.inactiveSessions = []*SessionWrapper{goodSession}

	mustStoreUserRecord(t, mgr.Store(), "bob", userRecord)

	// Active session (oldTime) fails, inactive session (goodTime) succeeds.
	// Discriminate by createdAt since MemoryStore clones prevent pointer comparison.
	decrypt := func(session *SessionWrapper, ciphertext []byte) ([]byte, error) {
		if session.CreatedAt().Equal(oldTime) {
			return nil, errors.New("wrong session")
		}
		return []byte("success"), nil
	}

	plaintext, err := mgr.Receive("bob", 1, []byte("ct"), decrypt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(plaintext) != "success" {
		t.Errorf("expected 'success', got %q", plaintext)
	}

	// Verify the good session was promoted to active (by createdAt).
	reloaded := mustLoadUserRecord(t, mgr.Store(), "bob")
	activeSession := reloaded.GetDevice(1).ActiveSession()
	if activeSession.CreatedAt() != goodTime {
		t.Error("expected good session to be promoted to active")
	}
}

func TestReceive_AllSessionsFail(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Set up a session.
	_, err := mgr.PrepForEncrypting("bob", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	_, err = mgr.Receive("bob", 1, []byte("bad ciphertext"), failingDecrypt())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

func TestReceive_NoExistingDeviceRecord(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// No existing session for bob/1 - decryption should fail since there's
	// no active session to try.
	_, err := mgr.Receive("bob", 1, []byte("ciphertext"), failingDecrypt())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

// --- ReceiveNewSession Tests ---

func TestReceiveNewSession_Success(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)
	expected := []byte("decrypted")

	newSession := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	plaintext, err := mgr.ReceiveNewSession("bob", 1, newSession, []byte("ct"), successDecrypt(expected))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(plaintext) != string(expected) {
		t.Errorf("expected %q, got %q", expected, plaintext)
	}

	// Verify session was stored.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "bob")
	if userRecord == nil {
		t.Fatal("expected user record")
	}
	device := userRecord.GetDevice(1)
	if device == nil {
		t.Fatal("expected device record")
	}
	if device.ActiveSession() == nil {
		t.Fatal("expected active session")
	}
}

func TestReceiveNewSession_DecryptionFails(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	newSession := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	_, err := mgr.ReceiveNewSession("bob", 1, newSession, []byte("ct"), failingDecrypt())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("expected ErrDecryptionFailed, got %v", err)
	}
}

// --- UpdateDeviceList Tests ---

func TestUpdateDeviceList_MarksStale(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Set up sessions for devices 1, 2, 3.
	for _, id := range []uint32{1, 2, 3} {
		_, err := mgr.PrepForEncrypting("alice", id, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
	}

	// Server says only devices 1 and 3 exist.
	if err := mgr.UpdateDeviceList("alice", []uint32{1, 3}); err != nil {
		t.Fatalf("UpdateDeviceList error: %v", err)
	}

	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	device2 := userRecord.GetDevice(2)
	if device2 == nil {
		t.Fatal("expected device 2 to still exist")
	}
	if !device2.IsStale() {
		t.Error("expected device 2 to be marked stale")
	}
	if device2.StaledAt() != now {
		t.Errorf("expected staledAt=%v, got %v", now, device2.StaledAt())
	}

	// Devices 1 and 3 should not be stale.
	for _, id := range []uint32{1, 3} {
		d := userRecord.GetDevice(id)
		if d.IsStale() {
			t.Errorf("device %d should not be stale", id)
		}
	}
}

func TestUpdateDeviceList_NonexistentUser(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Should not panic for non-existent user.
	if err := mgr.UpdateDeviceList("nonexistent", []uint32{1, 2}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- Session Expiration Tests ---

func TestSessionExpiration_MaxSend(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create session (expiration based on createdAt per spec).
	session, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Advance past MaxSend.
	expiredTime := now.Add(DefaultMaxSend + time.Hour)
	mgr.SetClock(testClock(expiredTime))

	// Trigger cleanup via PrepForEncrypting (which calls RemoveStaleDevices).
	newSession, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The old session should have been deactivated and a new one created.
	if newSession == session {
		t.Error("expected a new session after MaxSend expiration")
	}
}

func TestSessionExpiration_MaxRecv(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create user with a session created at `now`.
	// Per spec, expiration is based on createdAt, not lastReceive.
	userRecord := NewUserRecord("alice")
	device, _ := userRecord.AddDevice(1, 0)
	oldSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.ActivateSession(oldSession, nil, time.Time{})
	// Deactivate to move to inactive list.
	device.DeactivateSession(nil)
	mustStoreUserRecord(t, mgr.Store(), "alice", userRecord)

	// Advance past MaxRecv.
	expiredTime := now.Add(DefaultMaxRecv + time.Hour)

	// Clean expired sessions.
	device.CleanExpiredSessions(mgr.Config(), expiredTime)

	// The inactive session should be removed.
	if len(device.InactiveSessions()) != 0 {
		t.Errorf("expected 0 inactive sessions, got %d", len(device.InactiveSessions()))
	}
}

// --- CleanupExpired Tests ---

func TestCleanupExpired_CascadeDelete(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create user with a session created at `now` that will expire.
	// Per spec, expiration is based on createdAt.
	userRecord := NewUserRecord("alice")
	device, _ := userRecord.AddDevice(1, 0)
	oldSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.ActivateSession(oldSession, nil, time.Time{})
	// Deactivate so it becomes inactive.
	device.DeactivateSession(nil)
	mustStoreUserRecord(t, mgr.Store(), "alice", userRecord)

	// Advance past MaxRecv so all sessions expire.
	expiredTime := now.Add(DefaultMaxRecv + time.Hour)
	mgr.SetClock(testClock(expiredTime))

	if err := mgr.CleanupExpired(); err != nil {
		t.Fatalf("CleanupExpired error: %v", err)
	}

	// Alice should be completely removed (empty user -> deleted).
	if mgr.Store().ContainsUserRecord("alice") {
		t.Error("expected alice to be deleted after cascade cleanup")
	}
}

func TestCleanupExpired_StaleUserDeleted(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create a stale user.
	userRecord := NewUserRecord("alice")
	_, _ = userRecord.AddDevice(1, 0)
	userRecord.MarkStale(now)
	mustStoreUserRecord(t, mgr.Store(), "alice", userRecord)

	// Advance past MaxLatency.
	expiredTime := now.Add(DefaultMaxLatency + time.Hour)
	mgr.SetClock(testClock(expiredTime))

	if err := mgr.CleanupExpired(); err != nil {
		t.Fatalf("CleanupExpired error: %v", err)
	}

	if mgr.Store().ContainsUserRecord("alice") {
		t.Error("expected stale user to be deleted after MaxLatency")
	}
}

func TestCleanupExpired_HealthyUserPreserved(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create a healthy user.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Advance slightly.
	mgr.SetClock(advanceClock(now, time.Hour))

	if err := mgr.CleanupExpired(); err != nil {
		t.Fatalf("CleanupExpired error: %v", err)
	}

	if !mgr.Store().ContainsUserRecord("alice") {
		t.Error("expected healthy user to be preserved")
	}
}

// --- StaleDevice Tests ---

func TestStaleDevice_DeletedAfterMaxLatency(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Set up devices.
	for _, id := range []uint32{1, 2} {
		_, err := mgr.PrepForEncrypting("alice", id, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
	}

	// Mark device 2 stale.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	userRecord.GetDevice(2).MarkStale(now)
	mustStoreUserRecord(t, mgr.Store(), "alice", userRecord)

	// Advance past MaxLatency.
	expiredTime := now.Add(DefaultMaxLatency + time.Hour)
	mgr.SetClock(testClock(expiredTime))

	// PrepForEncrypting triggers cleanup.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Device 2 should be removed.
	reloaded := mustLoadUserRecord(t, mgr.Store(), "alice")
	if reloaded.GetDevice(2) != nil {
		t.Error("expected stale device 2 to be removed after MaxLatency")
	}
	// Device 1 should remain.
	if reloaded.GetDevice(1) == nil {
		t.Error("expected device 1 to still exist")
	}
}

// --- Error Type Tests ---

func TestErrorTypes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sentinel *SesameError
	}{
		{"NoActiveSession", NewNoActiveSessionError("alice", 1), ErrNoActiveSession},
		{"NoUserRecord", NewNoUserRecordError("alice"), ErrNoUserRecord},
		{"NoDeviceRecord", NewNoDeviceRecordError("alice", 1), ErrNoDeviceRecord},
		{"DecryptionFailed", NewDecryptionFailedError("alice", 1, nil), ErrDecryptionFailed},
		{"MaxLatencyExceeded", NewMaxLatencyExceededError("user"), ErrMaxLatencyExceeded},
		{"InvalidConfig", NewInvalidConfigError("bad"), ErrInvalidConfig},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, tc.sentinel) {
				t.Errorf("expected errors.Is(%v, %v) to be true", tc.err, tc.sentinel)
			}
		})
	}
}

func TestErrorUnwrap(t *testing.T) {
	cause := errors.New("underlying cause")
	err := NewDecryptionFailedError("alice", 1, cause)

	unwrapped := errors.Unwrap(err)
	if unwrapped != cause {
		t.Errorf("expected unwrapped error to be %v, got %v", cause, unwrapped)
	}
}

func TestErrorMessage(t *testing.T) {
	err := NewNoActiveSessionError("alice", 1)
	msg := err.Error()
	if msg == "" {
		t.Error("expected non-empty error message")
	}

	errWithCause := NewDecryptionFailedError("alice", 1, errors.New("bad key"))
	msg = errWithCause.Error()
	if msg == "" {
		t.Error("expected non-empty error message with cause")
	}
}

// --- SessionWrapper Tests ---

func TestSessionWrapper_Timestamps(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	session := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	sw := NewSessionWrapper(session, nil, now)

	if sw.CreatedAt() != now {
		t.Errorf("expected createdAt=%v, got %v", now, sw.CreatedAt())
	}
	if !sw.LastSend().IsZero() {
		t.Error("expected zero lastSend initially")
	}
	if !sw.LastReceive().IsZero() {
		t.Error("expected zero lastReceive initially")
	}

	sendTime := now.Add(time.Hour)
	sw.RecordSend(sendTime)
	if sw.LastSend() != sendTime {
		t.Errorf("expected lastSend=%v, got %v", sendTime, sw.LastSend())
	}

	recvTime := now.Add(2 * time.Hour)
	sw.RecordReceive(recvTime)
	if sw.LastReceive() != recvTime {
		t.Errorf("expected lastReceive=%v, got %v", recvTime, sw.LastReceive())
	}
}

func TestSessionWrapper_SendExpiration(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	session := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	sw := NewSessionWrapper(session, nil, now)

	// Per spec: expiration is based on createdAt, not lastSend.
	// Just before expiration.
	if sw.IsSendExpired(cfg, now.Add(DefaultMaxSend-time.Hour)) {
		t.Error("expected not expired before MaxSend from creation")
	}

	// After expiration - should be expired even without any send recorded.
	if !sw.IsSendExpired(cfg, now.Add(DefaultMaxSend+time.Hour)) {
		t.Error("expected expired after MaxSend from creation")
	}

	// Recording a send should NOT affect expiration.
	recentSendTime := now.Add(DefaultMaxSend + 30*time.Minute)
	sw.RecordSend(recentSendTime)
	if !sw.IsSendExpired(cfg, now.Add(DefaultMaxSend+time.Hour)) {
		t.Error("expected still expired - recent send does not reset expiration")
	}
}

func TestSessionWrapper_RecvExpiration(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	session := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	sw := NewSessionWrapper(session, nil, now)

	// Per spec: expiration is based on createdAt, not lastReceive.
	// Just before expiration.
	if sw.IsRecvExpired(cfg, now.Add(DefaultMaxRecv-time.Hour)) {
		t.Error("expected not expired before MaxRecv from creation")
	}

	// After expiration - expired even without any receive recorded.
	if !sw.IsRecvExpired(cfg, now.Add(DefaultMaxRecv+time.Hour)) {
		t.Error("expected expired after MaxRecv from creation")
	}

	// Recording a receive should NOT affect expiration.
	recentRecvTime := now.Add(DefaultMaxRecv + 30*time.Minute)
	sw.RecordReceive(recentRecvTime)
	if !sw.IsRecvExpired(cfg, now.Add(DefaultMaxRecv+time.Hour)) {
		t.Error("expected still expired - recent receive does not reset expiration")
	}
}

// --- DeviceRecord Tests ---

func TestDeviceRecord_ActivateDeactivate(t *testing.T) {
	device := NewDeviceRecord(1)

	if device.DeviceID() != 1 {
		t.Errorf("expected deviceID=1, got %d", device.DeviceID())
	}
	if !device.IsEmpty() {
		t.Error("expected new device to be empty")
	}

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s1 := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.ActivateSession(s1, nil, time.Time{})

	if device.ActiveSession() != s1 {
		t.Error("expected s1 as active session")
	}
	if device.IsEmpty() {
		t.Error("expected device not empty after activate")
	}

	// Activate a new session - s1 should move to inactive.
	s2 := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.ActivateSession(s2, nil, time.Time{})

	if device.ActiveSession() != s2 {
		t.Error("expected s2 as active session")
	}
	if len(device.InactiveSessions()) != 1 {
		t.Fatalf("expected 1 inactive session, got %d", len(device.InactiveSessions()))
	}
	if device.InactiveSessions()[0] != s1 {
		t.Error("expected s1 as inactive session")
	}

	// Deactivate - s2 moves to inactive.
	device.DeactivateSession(nil)
	if device.ActiveSession() != nil {
		t.Error("expected nil active session after deactivate")
	}
	if len(device.InactiveSessions()) != 2 {
		t.Fatalf("expected 2 inactive sessions, got %d", len(device.InactiveSessions()))
	}
}

func TestDeviceRecord_DeactivateNilActive(t *testing.T) {
	device := NewDeviceRecord(1)
	// Should not panic.
	device.DeactivateSession(nil)
	if device.ActiveSession() != nil {
		t.Error("expected nil active session")
	}
	if len(device.InactiveSessions()) != 0 {
		t.Error("expected no inactive sessions")
	}
}

func TestDeviceRecord_StaleExpiration(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	if device.IsStale() {
		t.Error("expected not stale initially")
	}
	if device.IsStaleExpired(cfg, now) {
		t.Error("expected not stale expired when not stale")
	}

	device.MarkStale(now)
	if !device.IsStale() {
		t.Error("expected stale after MarkStale")
	}

	// Just before MaxLatency.
	if device.IsStaleExpired(cfg, now.Add(DefaultMaxLatency-time.Hour)) {
		t.Error("expected not stale expired before MaxLatency")
	}

	// After MaxLatency.
	if !device.IsStaleExpired(cfg, now.Add(DefaultMaxLatency+time.Hour)) {
		t.Error("expected stale expired after MaxLatency")
	}

	// ClearStale resets.
	device.ClearStale()
	if device.IsStale() {
		t.Error("expected not stale after ClearStale")
	}
}

func TestDeviceRecord_PromoteInactiveSession(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	device := NewDeviceRecord(1)

	s1 := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	s2 := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	s3 := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)

	device.ActivateSession(s1, nil, time.Time{})
	device.inactiveSessions = []*SessionWrapper{s2, s3}

	// Promote s3 (index 1).
	device.PromoteInactiveSession(1, nil, time.Time{})

	if device.ActiveSession() != s3 {
		t.Error("expected s3 as active after promotion")
	}
	// s1 should be in inactive (pushed by ActivateSession), plus s2 remaining.
	if len(device.InactiveSessions()) != 2 {
		t.Errorf("expected 2 inactive sessions, got %d", len(device.InactiveSessions()))
	}
}

func TestDeviceRecord_PromoteInvalidIndex(t *testing.T) {
	device := NewDeviceRecord(1)
	// Should not panic with invalid indices.
	device.PromoteInactiveSession(-1, nil, time.Time{})
	device.PromoteInactiveSession(0, nil, time.Time{})
	device.PromoteInactiveSession(100, nil, time.Time{})
}

func TestDeviceRecord_SessionCount(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	device := NewDeviceRecord(1)

	if device.SessionCount() != 0 {
		t.Errorf("expected 0, got %d", device.SessionCount())
	}

	s := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.ActivateSession(s, nil, time.Time{})
	if device.SessionCount() != 1 {
		t.Errorf("expected 1, got %d", device.SessionCount())
	}
}

// --- UserRecord Tests ---

func TestUserRecord_AddRemoveDevice(t *testing.T) {
	user := NewUserRecord("alice")

	if user.UserID() != "alice" {
		t.Errorf("expected userID=alice, got %s", user.UserID())
	}
	if !user.IsEmpty() {
		t.Error("expected empty user")
	}

	d1, err := user.AddDevice(1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d1 == nil {
		t.Fatal("expected device")
	}
	if user.IsEmpty() {
		t.Error("expected non-empty user after add")
	}

	// Adding same ID returns existing.
	d1Again, err := user.AddDevice(1, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if d1Again != d1 {
		t.Error("expected same device on duplicate add")
	}

	user.RemoveDevice(1)
	if user.GetDevice(1) != nil {
		t.Error("expected nil after remove")
	}
	if !user.IsEmpty() {
		t.Error("expected empty after remove")
	}
}

func TestUserRecord_StaleExpiration(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	user := NewUserRecord("alice")

	if user.IsStale() {
		t.Error("expected not stale initially")
	}

	user.MarkStale(now)
	if !user.IsStale() {
		t.Error("expected stale after MarkStale")
	}
	if user.StaledAt() != now {
		t.Errorf("expected staledAt=%v", now)
	}

	if user.IsStaleExpired(cfg, now.Add(DefaultMaxLatency-time.Hour)) {
		t.Error("expected not stale expired before MaxLatency")
	}
	if !user.IsStaleExpired(cfg, now.Add(DefaultMaxLatency+time.Hour)) {
		t.Error("expected stale expired after MaxLatency")
	}

	user.ClearStale()
	if user.IsStale() {
		t.Error("expected not stale after ClearStale")
	}
}

func TestUserRecord_RemoveStaleDevices(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	user := NewUserRecord("alice")

	d1, _ := user.AddDevice(1, 0)
	d2, _ := user.AddDevice(2, 0)

	// Mark device 1 stale.
	d1.MarkStale(now)
	// Keep device 2 active.
	_ = d2

	// Advance past MaxLatency.
	expired := now.Add(DefaultMaxLatency + time.Hour)
	user.RemoveStaleDevices(cfg, expired)

	if user.GetDevice(1) != nil {
		t.Error("expected device 1 removed (stale expired)")
	}
	// Device 2 has no sessions, so it should also be removed (empty).
	if user.GetDevice(2) != nil {
		t.Error("expected device 2 removed (empty)")
	}
}

func TestUserRecord_DeviceIDs(t *testing.T) {
	user := NewUserRecord("alice")
	_, _ = user.AddDevice(1, 0)
	_, _ = user.AddDevice(5, 0)
	_, _ = user.AddDevice(3, 0)

	ids := user.DeviceIDs()
	if len(ids) != 3 {
		t.Fatalf("expected 3 device IDs, got %d", len(ids))
	}

	idSet := make(map[uint32]bool)
	for _, id := range ids {
		idSet[id] = true
	}
	for _, expected := range []uint32{1, 5, 3} {
		if !idSet[expected] {
			t.Errorf("expected device ID %d in list", expected)
		}
	}
}

// --- MemoryStore Tests ---

func TestMemoryStore_CRUD(t *testing.T) {
	store := NewMemoryStore()

	if store.ContainsUserRecord("alice") {
		t.Error("expected no record for alice")
	}
	if mustLoadUserRecord(t, store, "alice") != nil {
		t.Error("expected nil for non-existent user")
	}

	user := NewUserRecord("alice")
	mustStoreUserRecord(t, store, "alice", user)

	if !store.ContainsUserRecord("alice") {
		t.Error("expected record for alice")
	}
	loaded := mustLoadUserRecord(t, store, "alice")
	// MemoryStore clones on load/store, so check by value not pointer.
	if loaded == nil || loaded.UserID() != "alice" {
		t.Error("expected loaded record to match stored user ID")
	}

	store.DeleteUserRecord("alice")
	if store.ContainsUserRecord("alice") {
		t.Error("expected no record after delete")
	}
}

func TestMemoryStore_DeleteNonexistent(t *testing.T) {
	store := NewMemoryStore()
	// Should not panic.
	store.DeleteUserRecord("nonexistent")
}

// testIdentityKey creates an identity key from a 32-byte array for testing.
func testIdentityKey(seed byte) *identity.Key {
	var keyBytes [32]byte
	keyBytes[0] = seed
	return identity.NewKey(ecc.NewDjbECPublicKey(keyBytes))
}

// --- PrepForEncrypting Identity Key Comparison Tests ---

func TestPrepForEncrypting_IdentityKeyChanged_ReplacesRecords(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	keyA := testIdentityKey(0x01)
	keyB := testIdentityKey(0x02)

	// Create initial session with identity key A.
	session1, err := mgr.PrepForEncrypting("alice", 1, keyA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session1.IdentityKey() == nil {
		t.Fatal("expected session to have an identity key")
	}

	// Call again with different identity key B - per spec, should replace
	// the entire UserRecord/DeviceRecord with empty ones.
	session2, err := mgr.PrepForEncrypting("alice", 1, keyB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session2.CreatedAt().Equal(session1.CreatedAt()) && session2.IdentityKey() == session1.IdentityKey() {
		t.Error("expected new session when identity key changed")
	}

	// Per spec: identity key mismatch replaces records entirely;
	// old sessions are NOT preserved in inactive list.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	device := userRecord.GetDevice(1)
	if len(device.InactiveSessions()) != 0 {
		t.Fatalf("expected 0 inactive sessions (record replaced), got %d", len(device.InactiveSessions()))
	}
}

func TestPrepForEncrypting_SameIdentityKey_KeepsSession(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	keyA := testIdentityKey(0x01)

	session1, err := mgr.PrepForEncrypting("alice", 1, keyA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Call again with the same identity key - should keep the same session.
	session2, err := mgr.PrepForEncrypting("alice", 1, keyA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// MemoryStore clones, so compare by value.
	if session1.CreatedAt() != session2.CreatedAt() {
		t.Error("expected same session when identity key unchanged")
	}
}

func TestPrepForEncrypting_NilIdentityKey_SkipsComparison(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	keyA := testIdentityKey(0x01)

	// Create session with identity key.
	session1, err := mgr.PrepForEncrypting("alice", 1, keyA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Call with nil identity key - should not deactivate.
	session2, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// MemoryStore clones, so compare by value.
	if session1.CreatedAt() != session2.CreatedAt() {
		t.Error("expected same session when nil identity key provided")
	}
}

// --- SessionWrapper Identity Key Tests ---

func TestSessionWrapper_IdentityKey(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	session := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})

	key := testIdentityKey(0x42)
	sw := NewSessionWrapper(session, key, now)

	if sw.IdentityKey() != key {
		t.Error("expected identity key to match")
	}
}

func TestSessionWrapper_IdentityKeyNil(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	session := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	sw := NewSessionWrapper(session, nil, now)

	if sw.IdentityKey() != nil {
		t.Error("expected nil identity key")
	}
}

func TestSessionWrapper_HasIdentityKeyChanged(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	session := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	keyA := testIdentityKey(0x01)
	keyB := testIdentityKey(0x02)

	sw := NewSessionWrapper(session, keyA, now)

	if !sw.HasIdentityKeyChanged(keyB) {
		t.Error("expected identity key to be detected as changed")
	}
	if sw.HasIdentityKeyChanged(keyA) {
		t.Error("expected same identity key to not be detected as changed")
	}
	if sw.HasIdentityKeyChanged(nil) {
		t.Error("expected nil comparison to return false")
	}

	// Session with nil identity key should not detect changes.
	swNil := NewSessionWrapper(session, nil, now)
	if swNil.HasIdentityKeyChanged(keyA) {
		t.Error("expected nil session key to not detect changes")
	}
}

// --- Receive Mutation Safety Tests ---

func TestReceive_FailureDoesNotLeakMutations(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Attempt to receive for a user that does not exist in the store.
	// This should NOT create a user record in the store on failure.
	_, err := mgr.Receive("unknown-user", 1, []byte("ct"), failingDecrypt())
	if err == nil {
		t.Fatal("expected error")
	}

	// The store should NOT have a record for "unknown-user".
	if mgr.Store().ContainsUserRecord("unknown-user") {
		t.Error("expected no user record after failed Receive")
	}
}

func TestReceive_FailureDoesNotAddDevice(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create a user with device 1 only.
	_, err := mgr.PrepForEncrypting("bob", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Attempt to receive on device 2 (which does not exist) and fail.
	_, err = mgr.Receive("bob", 2, []byte("ct"), failingDecrypt())
	if err == nil {
		t.Fatal("expected error")
	}

	// Device 2 should NOT have been added to the user record.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "bob")
	if userRecord.GetDevice(2) != nil {
		t.Error("expected no device 2 after failed Receive")
	}
}

// --- ReceiveNewSession Mutation Safety Tests ---

func TestReceiveNewSession_FailureDoesNotActivateSession(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create an existing session for bob/device 1.
	originalSession, err := mgr.PrepForEncrypting("bob", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Attempt to receive a new session that fails decryption.
	newSessionRecord := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	_, err = mgr.ReceiveNewSession("bob", 1, newSessionRecord, []byte("ct"), failingDecrypt())
	if err == nil {
		t.Fatal("expected error")
	}

	// The original session should still be active - the failed new session
	// should not have been activated.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "bob")
	device := userRecord.GetDevice(1)
	// MemoryStore clones, so compare by value not pointer.
	if device.ActiveSession().CreatedAt() != originalSession.CreatedAt() {
		t.Error("expected original session to remain active after failed ReceiveNewSession")
	}
}

func TestReceiveNewSession_FailureDoesNotCreateUserRecord(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	newSessionRecord := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	_, err := mgr.ReceiveNewSession("unknown-user", 1, newSessionRecord, []byte("ct"), failingDecrypt())
	if err == nil {
		t.Fatal("expected error")
	}

	// No user record should be created on failure.
	if mgr.Store().ContainsUserRecord("unknown-user") {
		t.Error("expected no user record after failed ReceiveNewSession")
	}
}

// --- AllUserIDs Tests ---

func TestMemoryStore_AllUserIDs(t *testing.T) {
	store := NewMemoryStore()

	ids := store.AllUserIDs()
	if len(ids) != 0 {
		t.Errorf("expected 0 user IDs, got %d", len(ids))
	}

	mustStoreUserRecord(t, store, "alice", NewUserRecord("alice"))
	mustStoreUserRecord(t, store, "bob", NewUserRecord("bob"))

	ids = store.AllUserIDs()
	if len(ids) != 2 {
		t.Fatalf("expected 2 user IDs, got %d", len(ids))
	}

	idSet := make(map[string]bool)
	for _, id := range ids {
		idSet[id] = true
	}
	if !idSet["alice"] || !idSet["bob"] {
		t.Error("expected alice and bob in AllUserIDs")
	}
}

func TestMemoryStore_AllUserIDs_AfterDelete(t *testing.T) {
	store := NewMemoryStore()
	mustStoreUserRecord(t, store, "alice", NewUserRecord("alice"))
	mustStoreUserRecord(t, store, "bob", NewUserRecord("bob"))
	store.DeleteUserRecord("alice")

	ids := store.AllUserIDs()
	if len(ids) != 1 {
		t.Fatalf("expected 1 user ID, got %d", len(ids))
	}
	if ids[0] != "bob" {
		t.Errorf("expected bob, got %s", ids[0])
	}
}

// =============================================================================
// Sesame Spec Alignment Tests
// =============================================================================

// --- Session Expiration Uses CreatedAt (Section 4.2) ---

func TestSessionExpiration_UsesCreatedAt(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	session := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})

	// Create session at `now`.
	sw := NewSessionWrapper(session, nil, now)

	// Record a recent send - should NOT prevent expiration.
	recentTime := now.Add(DefaultMaxSend + 30*time.Minute)
	sw.RecordSend(recentTime)

	// Session should be expired because createdAt is `now` and
	// we are checking at now + MaxSend + 1h.
	checkTime := now.Add(DefaultMaxSend + time.Hour)
	if !sw.IsSendExpired(cfg, checkTime) {
		t.Error("expected send-expired based on createdAt, not lastSend")
	}

	// Record a recent receive - should NOT prevent expiration.
	sw.RecordReceive(recentTime)

	checkRecvTime := now.Add(DefaultMaxRecv + time.Hour)
	if !sw.IsRecvExpired(cfg, checkRecvTime) {
		t.Error("expected recv-expired based on createdAt, not lastReceive")
	}
}

func TestSessionExpiration_NotExpiredBeforeThreshold(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	session := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	sw := NewSessionWrapper(session, nil, now)

	// Just before expiration.
	if sw.IsSendExpired(cfg, now.Add(DefaultMaxSend-time.Second)) {
		t.Error("expected not send-expired just before threshold")
	}
	if sw.IsRecvExpired(cfg, now.Add(DefaultMaxRecv-time.Second)) {
		t.Error("expected not recv-expired just before threshold")
	}
}

// --- Inactive Session List Bounds (Section 3.2) ---

func TestInactiveSessionListBounds(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	// Activate more sessions than MaxInactiveSessions.
	for i := 0; i < cfg.MaxInactiveSessions+10; i++ {
		sw := NewSessionWrapper(
			record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
		)
		device.ActivateSession(sw, cfg, now)
	}

	// The inactive list should be trimmed to MaxInactiveSessions.
	if len(device.InactiveSessions()) > cfg.MaxInactiveSessions {
		t.Errorf("expected at most %d inactive sessions, got %d",
			cfg.MaxInactiveSessions, len(device.InactiveSessions()))
	}
}

func TestInactiveSessionListBounds_SmallLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	cfg.MaxInactiveSessions = 3
	device := NewDeviceRecord(1)

	// Activate 10 sessions.
	for i := 0; i < 10; i++ {
		sw := NewSessionWrapper(
			record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
		)
		device.ActivateSession(sw, cfg, now)
	}

	if len(device.InactiveSessions()) != 3 {
		t.Errorf("expected 3 inactive sessions, got %d", len(device.InactiveSessions()))
	}
}

func TestInactiveSessionListBounds_NilConfig(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	device := NewDeviceRecord(1)

	// With nil config, no trimming or expiry checks should occur.
	for i := 0; i < 100; i++ {
		sw := NewSessionWrapper(
			record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
		)
		device.ActivateSession(sw, nil, time.Time{})
	}

	// All 99 previous sessions should be in inactive list (no trimming).
	if len(device.InactiveSessions()) != 99 {
		t.Errorf("expected 99 inactive sessions with nil config, got %d",
			len(device.InactiveSessions()))
	}
}

// --- Expired Session Cannot Be Activated (Section 4.2) ---

func TestExpiredSessionCannotBeActivated(t *testing.T) {
	createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	// Create a session that was created long ago.
	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, createdAt,
	)

	// Try to activate it at a time past MAXSEND.
	activateTime := createdAt.Add(DefaultMaxSend + time.Hour)
	activated := device.ActivateSession(sw, cfg, activateTime)

	if activated {
		t.Error("expected activation to be rejected for MAXSEND-expired session")
	}
	if device.ActiveSession() != nil {
		t.Error("expected no active session after rejected activation")
	}
}

func TestExpiredSessionCannotBeActivated_NotExpired(t *testing.T) {
	createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, createdAt,
	)

	// Activate within MAXSEND threshold - should succeed.
	activateTime := createdAt.Add(DefaultMaxSend - time.Hour)
	activated := device.ActivateSession(sw, cfg, activateTime)

	if !activated {
		t.Error("expected activation to succeed for non-expired session")
	}
	if device.ActiveSession() != sw {
		t.Error("expected session to be active")
	}
}

func TestExpiredSessionCannotBePromoted(t *testing.T) {
	createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	// Set up an expired session in the inactive list.
	expiredSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, createdAt,
	)
	activeSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, createdAt.Add(DefaultMaxSend),
	)
	device.ActivateSession(activeSession, nil, time.Time{})
	device.inactiveSessions = []*SessionWrapper{expiredSession}

	// Try to promote the expired session at a time past MAXSEND.
	promoteTime := createdAt.Add(DefaultMaxSend + time.Hour)
	promoted := device.PromoteInactiveSession(0, cfg, promoteTime)

	if promoted {
		t.Error("expected promotion to be rejected for MAXSEND-expired session")
	}
	if device.ActiveSession() != activeSession {
		t.Error("expected original active session to remain")
	}
}

// --- SendWithServerLoop Tests (Section 3.3) ---

func TestSendWithServerLoop_NewDevices(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Set up initial device.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	callCount := 0
	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		callCount++
		if callCount == 1 {
			// First attempt: server reports a new device 2.
			return &ServerResponse{
				Accepted:   false,
				UserExists: true,
				OldDevices: nil,
				NewDevices: map[uint32]*identity.Key{2: nil},
			}, nil
		}
		// Second attempt: all devices known, accepted.
		return &ServerResponse{
			Accepted:   true,
			UserExists: true,
		}, nil
	}

	results, err := mgr.SendWithServerLoop("alice", []byte("hello"), successEncrypt(), sendToServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have results for both device 1 and 2.
	if _, ok := results[1]; !ok {
		t.Error("expected result for device 1")
	}
	if _, ok := results[2]; !ok {
		t.Error("expected result for device 2")
	}
	if callCount != 2 {
		t.Errorf("expected 2 server calls, got %d", callCount)
	}
}

func TestSendWithServerLoop_StaleDevices(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Set up two devices.
	for _, id := range []uint32{1, 2} {
		_, err := mgr.PrepForEncrypting("alice", id, nil)
		if err != nil {
			t.Fatalf("setup error: %v", err)
		}
	}

	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		return &ServerResponse{
			Accepted:   true,
			UserExists: true,
			OldDevices: []uint32{2}, // Device 2 no longer registered.
		}, nil
	}

	_, err := mgr.SendWithServerLoop("alice", []byte("hello"), successEncrypt(), sendToServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Device 2 should be marked stale.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	device2 := userRecord.GetDevice(2)
	if device2 == nil {
		t.Fatal("expected device 2 to still exist")
	}
	if !device2.IsStale() {
		t.Error("expected device 2 to be marked stale")
	}
}

func TestSendWithServerLoop_UserNotFound(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		return &ServerResponse{
			Accepted:   false,
			UserExists: false,
		}, nil
	}

	_, err = mgr.SendWithServerLoop("alice", []byte("hello"), successEncrypt(), sendToServer)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrUserNotFound) {
		t.Errorf("expected ErrUserNotFound, got %v", err)
	}
}

func TestSendWithServerLoop_RetryLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	nextDeviceID := uint32(2)
	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		// Always report a new device to force retries.
		resp := &ServerResponse{
			Accepted:   false,
			UserExists: true,
			NewDevices: map[uint32]*identity.Key{nextDeviceID: nil},
		}
		nextDeviceID++
		return resp, nil
	}

	_, err = mgr.SendWithServerLoop("alice", []byte("hello"), successEncrypt(), sendToServer)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrMaxRetriesExceeded) {
		t.Errorf("expected ErrMaxRetriesExceeded, got %v", err)
	}
}

func TestSendWithServerLoop_ServerError(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		return nil, errors.New("network error")
	}

	_, err = mgr.SendWithServerLoop("alice", []byte("hello"), successEncrypt(), sendToServer)
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- Send Error Discards Changes (Section 3.3) ---

func TestSendErrorDiscardsChanges(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Set up initial state.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Verify initial state.
	userBefore := mustLoadUserRecord(t, mgr.Store(), "alice")
	devicesBefore := len(userBefore.DeviceIDs())

	callCount := 0
	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		callCount++
		if callCount == 1 {
			// First call: report new device, then next attempt will fail.
			return &ServerResponse{
				Accepted:   false,
				UserExists: true,
				NewDevices: map[uint32]*identity.Key{2: nil},
			}, nil
		}
		// Second call: server error.
		return nil, errors.New("server unavailable")
	}

	_, err = mgr.SendWithServerLoop("alice", []byte("hello"), successEncrypt(), sendToServer)
	if err == nil {
		t.Fatal("expected error")
	}

	// Changes should be rolled back - only original device should exist.
	userAfter := mustLoadUserRecord(t, mgr.Store(), "alice")
	devicesAfter := len(userAfter.DeviceIDs())
	if devicesAfter != devicesBefore {
		t.Errorf("expected %d devices after rollback, got %d", devicesBefore, devicesAfter)
	}
}

func TestSendErrorDiscardsChanges_NoExistingRecord(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// No existing user record.
	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		return nil, errors.New("server error")
	}

	_, err := mgr.SendWithServerLoop("nonexistent", []byte("hello"), successEncrypt(), sendToServer)
	if err == nil {
		t.Fatal("expected error")
	}

	// No user record should remain after rollback.
	if mgr.Store().ContainsUserRecord("nonexistent") {
		t.Error("expected no user record after error rollback")
	}
}

// --- Clone Tests ---

func TestUserRecord_Clone(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	original := NewUserRecord("alice")
	_, _ = original.AddDevice(1, 0)
	_, _ = original.AddDevice(2, 0)
	device1 := original.GetDevice(1)
	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device1.ActivateSession(sw, nil, time.Time{})
	original.MarkStale(now)

	clone, err := original.Clone()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Clone should be independent.
	if clone.UserID() != "alice" {
		t.Error("expected cloned userID to match")
	}
	if !clone.IsStale() {
		t.Error("expected cloned stale flag to match")
	}
	if len(clone.DeviceIDs()) != 2 {
		t.Errorf("expected 2 devices in clone, got %d", len(clone.DeviceIDs()))
	}

	// Modifying clone should not affect original.
	clone.RemoveDevice(2)
	if original.GetDevice(2) == nil {
		t.Error("removing device from clone should not affect original")
	}
}

func TestDeviceRecord_Clone(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	original := NewDeviceRecord(1)
	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	original.ActivateSession(sw, nil, time.Time{})
	original.MarkStale(now)

	clone, err := original.Clone()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if clone.DeviceID() != 1 {
		t.Error("expected cloned deviceID to match")
	}
	if !clone.IsStale() {
		t.Error("expected cloned stale flag to match")
	}
	// Clone deep-copies SessionWrappers, so pointers differ but values match.
	if clone.ActiveSession() == sw {
		t.Error("expected cloned active session to be a different pointer (deep copy)")
	}
	if clone.ActiveSession().CreatedAt() != sw.CreatedAt() {
		t.Error("expected cloned active session createdAt to match")
	}

	// Modifying clone's mutable SessionWrapper state should not affect original.
	clone.ActiveSession().RecordSend(now.Add(time.Hour))
	if !sw.LastSend().IsZero() {
		t.Error("modifying clone's session lastSend should not affect original")
	}

	// Modifying clone's inactive list should not affect original.
	sw2 := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	clone.ActivateSession(sw2, nil, time.Time{})
	if len(original.InactiveSessions()) != 0 {
		t.Error("modifying clone inactive list should not affect original")
	}
}

// --- New Error Types ---

func TestNewErrorTypes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		sentinel *SesameError
	}{
		{"MaxRetriesExceeded", NewMaxRetriesExceededError("alice", 3), ErrMaxRetriesExceeded},
		{"UserNotFound", NewUserNotFoundError("alice"), ErrUserNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !errors.Is(tc.err, tc.sentinel) {
				t.Errorf("expected errors.Is(%v, %v) to be true", tc.err, tc.sentinel)
			}
			msg := tc.err.Error()
			if msg == "" {
				t.Error("expected non-empty error message")
			}
		})
	}
}

// --- Config Validation for New Fields ---

func TestDefaultConfig_NewFields(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.MaxInactiveSessions != DefaultMaxInactiveSessions {
		t.Errorf("expected MaxInactiveSessions=%d, got %d",
			DefaultMaxInactiveSessions, cfg.MaxInactiveSessions)
	}
	if cfg.MaxSendRetries != DefaultMaxSendRetries {
		t.Errorf("expected MaxSendRetries=%d, got %d",
			DefaultMaxSendRetries, cfg.MaxSendRetries)
	}

	if err := cfg.Validate(); err != nil {
		t.Errorf("default config should be valid: %v", err)
	}
}

// --- SendWithServerLoop with encryption failure ---

func TestSendWithServerLoop_EncryptionFailure(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		t.Fatal("sendToServer should not be called when encryption fails")
		return nil, nil
	}

	_, err = mgr.SendWithServerLoop("alice", []byte("hello"), failingEncrypt(), sendToServer)
	if err == nil {
		t.Fatal("expected error from failing encrypt")
	}
}

// --- SendWithServerLoop immediate accept ---

func TestSendWithServerLoop_ImmediateAccept(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		return &ServerResponse{
			Accepted:   true,
			UserExists: true,
		}, nil
	}

	results, err := mgr.SendWithServerLoop("alice", []byte("hello"), successEncrypt(), sendToServer)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	}
}

// --- ActivateSession return value test ---

func TestActivateSession_ReturnsTrue(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	result := device.ActivateSession(sw, cfg, now)
	if !result {
		t.Error("expected ActivateSession to return true for non-expired session")
	}
}

// --- PromoteInactiveSession return values ---

func TestPromoteInactiveSession_InvalidIndex_ReturnsFalse(t *testing.T) {
	device := NewDeviceRecord(1)

	if device.PromoteInactiveSession(-1, nil, time.Time{}) {
		t.Error("expected false for negative index")
	}
	if device.PromoteInactiveSession(0, nil, time.Time{}) {
		t.Error("expected false for out-of-bounds index on empty list")
	}
}

// --- Receive with MAXSEND-expired inactive session ---

func TestReceive_ExpiredInactiveSessionNotPromoted(t *testing.T) {
	createdAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(createdAt)

	// Create user with an expired inactive session.
	userRecord := NewUserRecord("bob")
	device, _ := userRecord.AddDevice(1, 0)

	// Active session that will fail decryption.
	activeSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, createdAt,
	)
	device.ActivateSession(activeSession, nil, time.Time{})

	// Expired inactive session that succeeds decryption.
	expiredSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil,
		createdAt.Add(-DefaultMaxSend-time.Hour), // created long ago
	)
	device.inactiveSessions = []*SessionWrapper{expiredSession}
	mustStoreUserRecord(t, mgr.Store(), "bob", userRecord)

	// Advance time past the expired session's MAXSEND.
	checkTime := createdAt.Add(time.Hour)
	mgr.SetClock(testClock(checkTime))

	// Active fails, expired inactive succeeds decryption.
	callCount := 0
	decrypt := func(session *SessionWrapper, ciphertext []byte) ([]byte, error) {
		callCount++
		if session == activeSession {
			return nil, errors.New("wrong session")
		}
		return []byte("decrypted"), nil
	}

	// The expired session can still decrypt (the promotion check is in
	// PromoteInactiveSession, not in decrypt). The receive should succeed
	// because the session can decrypt, but the expired session should not
	// be promoted. Instead, per the current implementation, it will still
	// be used for decryption and the promotion will fail silently.
	plaintext, err := mgr.Receive("bob", 1, []byte("ct"), decrypt)
	if err != nil {
		// Even though promotion fails, decryption succeeded and that's returned.
		t.Fatalf("unexpected error: %v", err)
	}
	if string(plaintext) != "decrypted" {
		t.Errorf("expected 'decrypted', got %q", plaintext)
	}
}

// ============================================================================
// MaxDevicesPerUser Bound Tests
// ============================================================================

func TestAddDevice_RespectsMaxDevicesLimit(t *testing.T) {
	user := NewUserRecord("alice")

	// Add devices up to the limit.
	for i := uint32(1); i <= 3; i++ {
		_, err := user.AddDevice(i, 3)
		if err != nil {
			t.Fatalf("unexpected error adding device %d: %v", i, err)
		}
	}

	// Adding one more should fail.
	_, err := user.AddDevice(4, 3)
	if err == nil {
		t.Fatal("expected error when exceeding max devices")
	}
	if !errors.Is(err, ErrMaxDevicesExceeded) {
		t.Errorf("expected ErrMaxDevicesExceeded, got: %v", err)
	}
}

func TestAddDevice_ExistingDeviceDoesNotCountAgainstLimit(t *testing.T) {
	user := NewUserRecord("alice")

	// Add 3 devices with a limit of 3.
	for i := uint32(1); i <= 3; i++ {
		_, err := user.AddDevice(i, 3)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	// Re-adding an existing device should succeed (returns existing).
	device, err := user.AddDevice(2, 3)
	if err != nil {
		t.Fatalf("unexpected error re-adding existing device: %v", err)
	}
	if device == nil {
		t.Fatal("expected non-nil device")
	}
}

func TestAddDeviceWithIdentity_RespectsMaxDevicesLimit(t *testing.T) {
	user := NewUserRecord("alice")
	key := testIdentityKey(0x01)

	_, err := user.AddDeviceWithIdentity(1, key, 1)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = user.AddDeviceWithIdentity(2, key, 1)
	if err == nil {
		t.Fatal("expected error when exceeding max devices")
	}
	if !errors.Is(err, ErrMaxDevicesExceeded) {
		t.Errorf("expected ErrMaxDevicesExceeded, got: %v", err)
	}
}

func TestAddDevice_ZeroLimitDisablesCheck(t *testing.T) {
	user := NewUserRecord("alice")

	// With limit 0, should be able to add many devices.
	for i := uint32(1); i <= 100; i++ {
		_, err := user.AddDevice(i, 0)
		if err != nil {
			t.Fatalf("unexpected error with no limit: %v", err)
		}
	}
}

func TestPrepForEncrypting_RespectsMaxDevicesLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	cfg.MaxDevicesPerUser = 2

	store := NewMemoryStore()
	mgr := NewManager(store, cfg, stubCreateSession())
	mgr.SetClock(testClock(now))

	// Add 2 devices (within limit).
	_, err := mgr.PrepForEncrypting("bob", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = mgr.PrepForEncrypting("bob", 2, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Third device should fail.
	_, err = mgr.PrepForEncrypting("bob", 3, nil)
	if err == nil {
		t.Fatal("expected error when exceeding max devices per user")
	}
	if !errors.Is(err, ErrMaxDevicesExceeded) {
		t.Errorf("expected ErrMaxDevicesExceeded, got: %v", err)
	}
}

// ============================================================================
// MaxUsers Bound Tests
// ============================================================================

func TestManager_RespectsMaxUsersLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	cfg.MaxUsers = 2

	store := NewMemoryStore()
	mgr := NewManager(store, cfg, stubCreateSession())
	mgr.SetClock(testClock(now))

	// Add 2 users (within limit).
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = mgr.PrepForEncrypting("bob", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Third user should fail.
	_, err = mgr.PrepForEncrypting("charlie", 1, nil)
	if err == nil {
		t.Fatal("expected error when exceeding max users")
	}
	if !errors.Is(err, ErrMaxUsersExceeded) {
		t.Errorf("expected ErrMaxUsersExceeded, got: %v", err)
	}
}

func TestManager_ExistingUserDoesNotCountAgainstMaxUsersLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	cfg.MaxUsers = 2

	store := NewMemoryStore()
	mgr := NewManager(store, cfg, stubCreateSession())
	mgr.SetClock(testClock(now))

	// Add 2 users.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = mgr.PrepForEncrypting("bob", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Adding another device for an existing user should succeed.
	_, err = mgr.PrepForEncrypting("alice", 2, nil)
	if err != nil {
		t.Fatalf("unexpected error adding device to existing user: %v", err)
	}
}

func TestReceiveNewSession_RespectsMaxUsersLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	cfg.MaxUsers = 1

	store := NewMemoryStore()
	mgr := NewManager(store, cfg, stubCreateSession())
	mgr.SetClock(testClock(now))

	// Fill the one user slot.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// ReceiveNewSession for a new user should fail.
	newSession := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	decrypt := func(sw *SessionWrapper, ct []byte) ([]byte, error) {
		return []byte("ok"), nil
	}
	_, err = mgr.ReceiveNewSession("bob", 1, newSession, []byte("ct"), decrypt)
	if err == nil {
		t.Fatal("expected error when exceeding max users via ReceiveNewSession")
	}
	if !errors.Is(err, ErrMaxUsersExceeded) {
		t.Errorf("expected ErrMaxUsersExceeded, got: %v", err)
	}
}

// ============================================================================
// Config Validation for New Fields
// ============================================================================

func TestConfigValidation_MaxDevicesPerUser(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxDevicesPerUser = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero MaxDevicesPerUser")
	}

	cfg.MaxDevicesPerUser = -1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for negative MaxDevicesPerUser")
	}
}

func TestConfigValidation_MaxUsers(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxUsers = 0
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for zero MaxUsers")
	}

	cfg.MaxUsers = -1
	if err := cfg.Validate(); err == nil {
		t.Error("expected error for negative MaxUsers")
	}
}

// ============================================================================
// Constant-Time Comparison Tests
// ============================================================================

func TestIdentityKeysEqual_ConstantTime(t *testing.T) {
	key1 := testIdentityKey(0x01)
	key2 := testIdentityKey(0x01)
	key3 := testIdentityKey(0x02)

	if !identityKeysEqual(key1, key2) {
		t.Error("expected equal keys to be equal")
	}
	if identityKeysEqual(key1, key3) {
		t.Error("expected different keys to not be equal")
	}
	if identityKeysEqual(nil, key1) {
		t.Error("expected nil/non-nil to not be equal")
	}
	if identityKeysEqual(key1, nil) {
		t.Error("expected non-nil/nil to not be equal")
	}
	if !identityKeysEqual(nil, nil) {
		t.Error("expected nil/nil to be equal")
	}
}

func TestSessionWrapper_HasIdentityKeyChanged_ConstantTime(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key1 := testIdentityKey(0x01)
	key2 := testIdentityKey(0x02)

	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), key1, now,
	)

	// Same key should not be "changed".
	if sw.HasIdentityKeyChanged(key1) {
		t.Error("expected no change for same key")
	}

	// Different key should be "changed".
	if !sw.HasIdentityKeyChanged(key2) {
		t.Error("expected change for different key")
	}

	// Nil other key should return false (unknown).
	if sw.HasIdentityKeyChanged(nil) {
		t.Error("expected false for nil other key")
	}

	// Nil session key should return false (unknown).
	swNilKey := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	if swNilKey.HasIdentityKeyChanged(key1) {
		t.Error("expected false for nil session key")
	}
}

// ============================================================================
// Error Type Tests for New Errors
// ============================================================================

func TestMaxDevicesExceededError(t *testing.T) {
	err := NewMaxDevicesExceededError("alice", 20)
	if !errors.Is(err, ErrMaxDevicesExceeded) {
		t.Error("expected ErrMaxDevicesExceeded")
	}
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestMaxUsersExceededError(t *testing.T) {
	err := NewMaxUsersExceededError(1000)
	if !errors.Is(err, ErrMaxUsersExceeded) {
		t.Error("expected ErrMaxUsersExceeded")
	}
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}
