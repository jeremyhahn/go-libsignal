package sesame

import (
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// --- DeviceRecord.IsExpired ---

func TestDeviceRecord_IsExpired_ActiveSessionExpired(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	sw.RecordSend(now)
	device.ActivateSession(sw, nil, time.Time{})

	// Before MaxSend: not expired.
	if device.IsExpired(cfg, now.Add(DefaultMaxSend-time.Hour)) {
		t.Error("expected not expired before MaxSend")
	}

	// After MaxSend: expired.
	if !device.IsExpired(cfg, now.Add(DefaultMaxSend+time.Hour)) {
		t.Error("expected expired after MaxSend")
	}
}

func TestDeviceRecord_IsExpired_NoActiveSession(t *testing.T) {
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)
	now := time.Now()

	// No active session means not expired.
	if device.IsExpired(cfg, now) {
		t.Error("expected not expired when no active session exists")
	}
}

func TestDeviceRecord_IsExpired_ActiveSessionNoSend(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.ActivateSession(sw, nil, time.Time{})

	// Per spec: expiration is based on createdAt. Even without a send recorded,
	// the session expires after MaxSend from creation.
	if device.IsExpired(cfg, now.Add(DefaultMaxSend+time.Hour)) != true {
		t.Error("expected expired after MaxSend from creation regardless of send activity")
	}

	// Before MaxSend: not yet expired.
	if device.IsExpired(cfg, now.Add(DefaultMaxSend-time.Hour)) {
		t.Error("expected not expired before MaxSend from creation")
	}
}

// --- SessionWrapper.Session ---

func TestSessionWrapper_Session(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sessionRecord := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	sw := NewSessionWrapper(sessionRecord, nil, now)

	if sw.Session() != sessionRecord {
		t.Error("Session() should return the underlying session record")
	}
}

// --- UserRecord.Devices ---

func TestUserRecord_Devices(t *testing.T) {
	user := NewUserRecord("alice")
	_, _ = user.AddDevice(1, 0)
	_, _ = user.AddDevice(2, 0)

	devices := user.Devices()
	if len(devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(devices))
	}
	if _, ok := devices[1]; !ok {
		t.Error("expected device 1 in map")
	}
	if _, ok := devices[2]; !ok {
		t.Error("expected device 2 in map")
	}
}

func TestUserRecord_DevicesEmpty(t *testing.T) {
	user := NewUserRecord("bob")
	devices := user.Devices()
	if len(devices) != 0 {
		t.Fatalf("expected 0 devices, got %d", len(devices))
	}
}

// --- SesameError.Is with non-SesameError target ---

func TestSesameError_Is_NonSesameError(t *testing.T) {
	err := NewNoActiveSessionError("alice", 1)
	stdErr := errors.New("standard error")

	if errors.Is(err, stdErr) {
		t.Error("SesameError should not match a non-SesameError")
	}
}

func TestSesameError_Is_DifferentKind(t *testing.T) {
	err := NewNoActiveSessionError("alice", 1)
	if errors.Is(err, ErrDecryptionFailed) {
		t.Error("NoActiveSession error should not match DecryptionFailed")
	}
}

// --- Send with stale user ---

func TestSend_StaleUserExpired(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create a user and mark as stale.
	userRecord := NewUserRecord("alice")
	userRecord.MarkStale(now)
	mustStoreUserRecord(t, mgr.Store(), "alice", userRecord)

	// Advance past MaxLatency.
	expiredTime := now.Add(DefaultMaxLatency + time.Hour)
	mgr.SetClock(testClock(expiredTime))

	// Send should still work because PrepForEncrypting cleans stale users
	// and creates new sessions.
	results, err := mgr.Send("alice", []uint32{1}, []byte("hello"), successEncrypt())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
}

// --- CleanupExpired with nil user record ---

func TestCleanupExpired_NilUserRecordSkipped(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Store a user and then delete it behind the manager's back
	// so LoadUserRecord returns nil.
	mustStoreUserRecord(t, mgr.Store(), "alice", NewUserRecord("alice"))
	mgr.Store().DeleteUserRecord("alice")

	// Should not panic.
	if err := mgr.CleanupExpired(); err != nil {
		t.Fatalf("CleanupExpired error: %v", err)
	}
}

// --- PrepForEncrypting stale device past MaxLatency ---

func TestPrepForEncrypting_StaleDevicePastMaxLatency(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create a session.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Mark the device stale.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	device := userRecord.GetDevice(1)
	device.MarkStale(now)
	mustStoreUserRecord(t, mgr.Store(), "alice", userRecord)

	// Advance past MaxLatency.
	expiredTime := now.Add(DefaultMaxLatency + time.Hour)
	mgr.SetClock(testClock(expiredTime))

	// PrepForEncrypting should remove the stale device and create a new one.
	session, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("expected a new session")
	}

	// Verify it is a fresh device (not stale).
	reloaded := mustLoadUserRecord(t, mgr.Store(), "alice")
	freshDevice := reloaded.GetDevice(1)
	if freshDevice.IsStale() {
		t.Error("expected fresh device to not be stale")
	}
}

// --- ReceiveNewSession with existing user ---

func TestReceiveNewSession_ExistingUser(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create an existing user with device 1.
	_, err := mgr.PrepForEncrypting("bob", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Receive a new session for device 2.
	newSession := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	plaintext, err := mgr.ReceiveNewSession("bob", 2, newSession, []byte("ct"), successDecrypt([]byte("decrypted")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(plaintext) != "decrypted" {
		t.Errorf("expected 'decrypted', got %q", plaintext)
	}

	// Both devices should exist.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "bob")
	if userRecord.GetDevice(1) == nil {
		t.Error("expected device 1 to still exist")
	}
	if userRecord.GetDevice(2) == nil {
		t.Error("expected device 2 to be created")
	}
}

// --- ReceiveNewSession with existing device ---

func TestReceiveNewSession_ExistingDevice(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create an existing session for bob/device 1.
	_, err := mgr.PrepForEncrypting("bob", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Receive a new session for the same device.
	newSession := record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{})
	plaintext, err := mgr.ReceiveNewSession("bob", 1, newSession, []byte("ct"), successDecrypt([]byte("new-decrypted")))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(plaintext) != "new-decrypted" {
		t.Errorf("expected 'new-decrypted', got %q", plaintext)
	}

	// The new session should be the active one, and the old one should be inactive.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "bob")
	device := userRecord.GetDevice(1)
	if len(device.InactiveSessions()) < 1 {
		t.Error("expected old session to be in inactive list")
	}
}

// --- DeviceRecord.CleanExpiredSessions ---

func TestDeviceRecord_CleanExpiredSessions_DeactivatesExpired(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	// Create and activate a session with a send timestamp.
	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	sw.RecordSend(now)
	device.ActivateSession(sw, nil, time.Time{})

	// Advance past MaxSend: active session should be deactivated.
	device.CleanExpiredSessions(cfg, now.Add(DefaultMaxSend+time.Hour))
	if device.ActiveSession() != nil {
		t.Error("expected active session to be deactivated after MaxSend")
	}
	if len(device.InactiveSessions()) != 1 {
		t.Errorf("expected 1 inactive session, got %d", len(device.InactiveSessions()))
	}
}

// --- DeviceRecord.StaledAt ---

func TestDeviceRecord_StaledAt(t *testing.T) {
	now := time.Date(2026, 3, 15, 10, 30, 0, 0, time.UTC)
	device := NewDeviceRecord(1)
	device.MarkStale(now)

	if device.StaledAt() != now {
		t.Errorf("expected staledAt=%v, got %v", now, device.StaledAt())
	}
}
