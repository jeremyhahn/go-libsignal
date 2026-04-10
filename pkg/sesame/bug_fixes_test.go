package sesame

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// ============================================================================
// Bug 1: MemoryStore clone-on-load/store
// ============================================================================

func TestMemoryStore_LoadReturnsClone(t *testing.T) {
	store := NewMemoryStore()
	user := NewUserRecord("alice")
	_, _ = user.AddDevice(1, 0)
	mustStoreUserRecord(t, store, "alice", user)

	loaded1 := mustLoadUserRecord(t, store, "alice")
	loaded2 := mustLoadUserRecord(t, store, "alice")

	// Mutating loaded1 should not affect loaded2.
	_, _ = loaded1.AddDevice(99, 0)
	if loaded2.GetDevice(99) != nil {
		t.Error("mutating one loaded record should not affect another loaded record")
	}
}

func TestMemoryStore_StoreClones(t *testing.T) {
	store := NewMemoryStore()
	user := NewUserRecord("alice")
	mustStoreUserRecord(t, store, "alice", user)

	// Mutating the original after storing should not affect the stored record.
	_, _ = user.AddDevice(42, 0)
	loaded := mustLoadUserRecord(t, store, "alice")
	if loaded.GetDevice(42) != nil {
		t.Error("mutating original after store should not affect stored record")
	}
}

func TestMemoryStore_LoadNonexistent(t *testing.T) {
	store := NewMemoryStore()
	if mustLoadUserRecord(t, store, "nobody") != nil {
		t.Error("expected nil for nonexistent user")
	}
}

func TestMemoryStore_RollbackSemantics(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()

	// Set up a user with a session.
	user := NewUserRecord("alice")
	device, _ := user.AddDevice(1, 0)
	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.InsertSession(sw, nil, now)
	mustStoreUserRecord(t, store, "alice", user)

	// Load and mutate (simulating a failed decryption path).
	loaded := mustLoadUserRecord(t, store, "alice")
	loaded.GetDevice(1).ActiveSession().RecordSend(now.Add(time.Hour))

	// Original stored record should be unaffected.
	reloaded := mustLoadUserRecord(t, store, "alice")
	if !reloaded.GetDevice(1).ActiveSession().LastSend().IsZero() {
		t.Error("rollback semantics broken: mutation leaked to stored record")
	}
}

// ============================================================================
// Bug 2: InsertSession vs ActivateSession
// ============================================================================

func TestInsertSession_AlwaysBecomesActive(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	// Create a send-expired session.
	expiredSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	expiredTime := now.Add(cfg.MaxSend + time.Hour)

	// InsertSession should unconditionally set as active, even if expired.
	device.InsertSession(expiredSession, cfg, expiredTime)
	if device.ActiveSession() == nil {
		t.Error("InsertSession should unconditionally set session as active")
	}
}

func TestInsertSession_MovesOldActiveToInactive(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	device := NewDeviceRecord(1)

	s1 := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	s2 := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now.Add(time.Second),
	)

	device.InsertSession(s1, nil, now)
	device.InsertSession(s2, nil, now)

	if device.ActiveSession().CreatedAt() != s2.CreatedAt() {
		t.Error("expected s2 as active session")
	}
	if len(device.InactiveSessions()) != 1 {
		t.Fatalf("expected 1 inactive session, got %d", len(device.InactiveSessions()))
	}
	if device.InactiveSessions()[0].CreatedAt() != s1.CreatedAt() {
		t.Error("expected s1 as first inactive session")
	}
}

func TestInsertSession_TrimsInactiveList(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := &Config{
		MaxSend:             DefaultMaxSend,
		MaxRecv:             DefaultMaxRecv,
		MaxLatency:          DefaultMaxLatency,
		MaxInactiveSessions: 2,
		MaxSendRetries:      DefaultMaxSendRetries,
	}
	device := NewDeviceRecord(1)

	// Insert 4 sessions, inactive list should be capped at 2.
	for i := 0; i < 4; i++ {
		sw := NewSessionWrapper(
			record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil,
			now.Add(time.Duration(i)*time.Second),
		)
		device.InsertSession(sw, cfg, now)
	}

	if len(device.InactiveSessions()) > 2 {
		t.Errorf("expected at most 2 inactive sessions, got %d", len(device.InactiveSessions()))
	}
}

func TestActivateSession_RejectsExpired(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	expiredSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	expiredTime := now.Add(cfg.MaxSend + time.Hour)

	activated := device.ActivateSession(expiredSession, cfg, expiredTime)
	if activated {
		t.Error("ActivateSession should reject send-expired session")
	}
	if device.ActiveSession() != nil {
		t.Error("expected no active session after rejected activation")
	}
}

func TestActivateSession_AcceptsNonExpired(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	freshSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)

	activated := device.ActivateSession(freshSession, cfg, now.Add(time.Hour))
	if !activated {
		t.Error("ActivateSession should accept non-expired session")
	}
	if device.ActiveSession() == nil {
		t.Error("expected active session after successful activation")
	}
}

// ============================================================================
// Bug 3: PromoteInactiveSession checks expiry before removing
// ============================================================================

func TestPromoteInactiveSession_ExpiredSessionNotLost(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	// Create an expired session in inactive list.
	expiredSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.inactiveSessions = []*SessionWrapper{expiredSession}

	expiredTime := now.Add(cfg.MaxSend + time.Hour)
	promoted := device.PromoteInactiveSession(0, cfg, expiredTime)

	if promoted {
		t.Error("should not promote an expired session")
	}
	// The session should still be in the inactive list (not lost).
	if len(device.InactiveSessions()) != 1 {
		t.Fatalf("expired session should remain in inactive list, got %d sessions", len(device.InactiveSessions()))
	}
}

func TestPromoteInactiveSession_ValidSessionPromoted(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)

	validSession := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.inactiveSessions = []*SessionWrapper{validSession}

	promoted := device.PromoteInactiveSession(0, cfg, now.Add(time.Hour))
	if !promoted {
		t.Error("should promote a valid non-expired session")
	}
	if device.ActiveSession() == nil {
		t.Error("expected session to be active after promotion")
	}
}

// ============================================================================
// Bug 4: Identity key mismatch replaces records
// ============================================================================

func TestPrepForEncrypting_IdentityKeyMismatch_ReplacesEntireRecord(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	keyA := testIdentityKey(0x01)
	keyB := testIdentityKey(0x02)

	// Create sessions for multiple devices with key A.
	_, err := mgr.PrepForEncrypting("alice", 1, keyA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = mgr.PrepForEncrypting("alice", 2, keyA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Now call with key B -- per spec, entire UserRecord should be replaced.
	_, err = mgr.PrepForEncrypting("alice", 1, keyB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Device 2 should no longer exist (record was replaced).
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	if userRecord.GetDevice(2) != nil {
		t.Error("expected device 2 to be gone after identity key mismatch replacement")
	}
	// Device 1 should exist with new session.
	if userRecord.GetDevice(1) == nil {
		t.Error("expected device 1 to exist with new session")
	}
}

func TestPrepForEncrypting_IdentityKeyMismatch_ErrorOnBadInput(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	keyA := testIdentityKey(0x01)
	keyB := testIdentityKey(0x02)

	// Create initial session with keyA.
	_, err := mgr.PrepForEncrypting("alice", 1, keyA)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify user-level identity key is stored.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	if userRecord.IdentityKey() == nil {
		t.Fatal("expected identity key on user record")
	}

	// Call with keyB - should replace.
	_, err = mgr.PrepForEncrypting("alice", 1, keyB)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// New user record should have keyB.
	userRecord = mustLoadUserRecord(t, mgr.Store(), "alice")
	if !bytes.Equal(userRecord.IdentityKey().Serialize(), keyB.Serialize()) {
		t.Error("expected user record to have new identity key")
	}
}

// ============================================================================
// Bug 5: PrepForEncrypting deletes stale records unconditionally for send path
// ============================================================================

func TestPrepForEncrypting_DeletesStaleDeviceUnconditionally(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create a session for device 1.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Also add device 2.
	_, err = mgr.PrepForEncrypting("alice", 2, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Mark device 2 as stale (just now, NOT past MaxLatency).
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	device2 := userRecord.GetDevice(2)
	device2.MarkStale(now)
	mustStoreUserRecord(t, mgr.Store(), "alice", userRecord)

	// PrepForEncrypting for device 1 should delete stale device 2
	// unconditionally (send path doesn't wait for MaxLatency).
	_, err = mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	userRecord = mustLoadUserRecord(t, mgr.Store(), "alice")
	if userRecord.GetDevice(2) != nil {
		t.Error("stale device should be deleted unconditionally in send path")
	}
}

func TestPrepForEncrypting_DeletesStaleDeviceEvenJustMarked(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create device 1.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Mark device 1 stale at `now`.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	userRecord.GetDevice(1).MarkStale(now)
	mustStoreUserRecord(t, mgr.Store(), "alice", userRecord)

	// Prep for device 1 again -- the stale device 1 should be deleted
	// and a fresh one created.
	session, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if session == nil {
		t.Fatal("expected a new session")
	}

	userRecord = mustLoadUserRecord(t, mgr.Store(), "alice")
	device := userRecord.GetDevice(1)
	if device.IsStale() {
		t.Error("freshly created device should not be stale")
	}
}

// ============================================================================
// Bug 6: Expiry checks use >= instead of >
// ============================================================================

func TestIsSendExpired_Inclusive(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()

	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)

	// At exactly MaxSend, should be expired (inclusive).
	atMaxSend := now.Add(cfg.MaxSend)
	if !sw.IsSendExpired(cfg, atMaxSend) {
		t.Error("expected session to be send-expired at exactly MaxSend (inclusive)")
	}

	// Just before MaxSend, should not be expired.
	beforeMaxSend := now.Add(cfg.MaxSend - time.Nanosecond)
	if sw.IsSendExpired(cfg, beforeMaxSend) {
		t.Error("expected session to NOT be send-expired just before MaxSend")
	}
}

func TestIsRecvExpired_Inclusive(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()

	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)

	// At exactly MaxRecv, should be expired (inclusive).
	atMaxRecv := now.Add(cfg.MaxRecv)
	if !sw.IsRecvExpired(cfg, atMaxRecv) {
		t.Error("expected session to be recv-expired at exactly MaxRecv (inclusive)")
	}

	// Just before MaxRecv, should not be expired.
	beforeMaxRecv := now.Add(cfg.MaxRecv - time.Nanosecond)
	if sw.IsRecvExpired(cfg, beforeMaxRecv) {
		t.Error("expected session to NOT be recv-expired just before MaxRecv")
	}
}

func TestDeviceRecord_IsStaleExpired_Inclusive(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	device := NewDeviceRecord(1)
	device.MarkStale(now)

	// At exactly MaxLatency, should be expired (inclusive).
	atMaxLatency := now.Add(cfg.MaxLatency)
	if !device.IsStaleExpired(cfg, atMaxLatency) {
		t.Error("expected device to be stale-expired at exactly MaxLatency (inclusive)")
	}

	// Just before MaxLatency, should not be expired.
	beforeMaxLatency := now.Add(cfg.MaxLatency - time.Nanosecond)
	if device.IsStaleExpired(cfg, beforeMaxLatency) {
		t.Error("expected device to NOT be stale-expired just before MaxLatency")
	}
}

func TestUserRecord_IsStaleExpired_Inclusive(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	user := NewUserRecord("alice")
	user.MarkStale(now)

	// At exactly MaxLatency, should be expired (inclusive).
	atMaxLatency := now.Add(cfg.MaxLatency)
	if !user.IsStaleExpired(cfg, atMaxLatency) {
		t.Error("expected user to be stale-expired at exactly MaxLatency (inclusive)")
	}

	// Just before MaxLatency, should not be expired.
	beforeMaxLatency := now.Add(cfg.MaxLatency - time.Nanosecond)
	if user.IsStaleExpired(cfg, beforeMaxLatency) {
		t.Error("expected user to NOT be stale-expired just before MaxLatency")
	}
}

// ============================================================================
// Bug 7: DeactivateSession enforces MaxInactiveSessions
// ============================================================================

func TestDeactivateSession_TrimsInactiveList(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := &Config{
		MaxSend:             DefaultMaxSend,
		MaxRecv:             DefaultMaxRecv,
		MaxLatency:          DefaultMaxLatency,
		MaxInactiveSessions: 2,
		MaxSendRetries:      DefaultMaxSendRetries,
	}
	device := NewDeviceRecord(1)

	// Add 3 inactive sessions manually.
	for i := 0; i < 3; i++ {
		device.inactiveSessions = append(device.inactiveSessions, NewSessionWrapper(
			record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil,
			now.Add(time.Duration(i)*time.Second),
		))
	}

	// Activate a session, then deactivate it with config.
	active := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.activeSession = active
	device.DeactivateSession(cfg)

	// Should be trimmed to MaxInactiveSessions (2).
	if len(device.InactiveSessions()) > cfg.MaxInactiveSessions {
		t.Errorf("expected at most %d inactive sessions, got %d",
			cfg.MaxInactiveSessions, len(device.InactiveSessions()))
	}
}

func TestDeactivateSession_NilConfig_NoTrim(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	device := NewDeviceRecord(1)

	// Add 5 inactive sessions.
	for i := 0; i < 5; i++ {
		device.inactiveSessions = append(device.inactiveSessions, NewSessionWrapper(
			record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil,
			now.Add(time.Duration(i)*time.Second),
		))
	}

	active := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.activeSession = active
	device.DeactivateSession(nil)

	// With nil config, no trimming occurs; all 6 sessions (5 + 1 deactivated) remain.
	if len(device.InactiveSessions()) != 6 {
		t.Errorf("expected 6 inactive sessions (no trim), got %d", len(device.InactiveSessions()))
	}
}

// ============================================================================
// Bug 8: SessionWrapper.Clone deep-copies mutable fields
// ============================================================================

func TestSessionWrapper_Clone(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	key := testIdentityKey(0x42)
	original := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), key, now,
	)
	original.RecordSend(now)
	original.RecordReceive(now.Add(time.Hour))

	clone, err := original.Clone()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify values are equal.
	if clone.CreatedAt() != original.CreatedAt() {
		t.Error("createdAt mismatch")
	}
	if clone.LastSend() != original.LastSend() {
		t.Error("lastSend mismatch")
	}
	if clone.LastReceive() != original.LastReceive() {
		t.Error("lastReceive mismatch")
	}
	if clone.IdentityKey() != original.IdentityKey() {
		t.Error("identityKey mismatch")
	}

	// Mutating clone should not affect original.
	clone.RecordSend(now.Add(24 * time.Hour))
	if original.LastSend().Equal(clone.LastSend()) {
		t.Error("mutating clone lastSend should not affect original")
	}

	clone.RecordReceive(now.Add(48 * time.Hour))
	if original.LastReceive().Equal(clone.LastReceive()) {
		t.Error("mutating clone lastReceive should not affect original")
	}
}

func TestSessionWrapper_Clone_NilIdentityKey(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	original := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)

	clone, err := original.Clone()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if clone.IdentityKey() != nil {
		t.Error("expected nil identity key in clone")
	}
}

func TestDeviceRecord_Clone_DeepCopiesSessionWrappers(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	device := NewDeviceRecord(1)

	active := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	inactive := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now.Add(time.Second),
	)
	device.InsertSession(active, nil, now)
	device.inactiveSessions = append(device.inactiveSessions, inactive)

	clone, err := device.Clone()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mutating clone's active session should not affect original.
	clone.ActiveSession().RecordSend(now.Add(time.Hour))
	if !device.ActiveSession().LastSend().IsZero() {
		t.Error("mutating clone's active session should not affect original")
	}

	// Mutating clone's inactive session should not affect original.
	clone.InactiveSessions()[0].RecordReceive(now.Add(2 * time.Hour))
	if !device.InactiveSessions()[0].LastReceive().IsZero() {
		t.Error("mutating clone's inactive session should not affect original")
	}
}

// ============================================================================
// Bug 9: Self-device exclusion
// ============================================================================

func TestPrepForEncrypting_RejectsSelfDevice(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	mgr := NewManager(store, DefaultConfig(), stubCreateSession(),
		WithLocalIdentity("alice", 1))
	mgr.SetClock(testClock(now))

	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err == nil {
		t.Fatal("expected error for self-device")
	}
	if !errors.Is(err, ErrSelfDevice) {
		t.Errorf("expected ErrSelfDevice, got %v", err)
	}
}

func TestPrepForEncrypting_AllowsDifferentDevice(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	mgr := NewManager(store, DefaultConfig(), stubCreateSession(),
		WithLocalIdentity("alice", 1))
	mgr.SetClock(testClock(now))

	// Different device ID should be allowed.
	_, err := mgr.PrepForEncrypting("alice", 2, nil)
	if err != nil {
		t.Fatalf("unexpected error for different device: %v", err)
	}

	// Different user should be allowed.
	_, err = mgr.PrepForEncrypting("bob", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error for different user: %v", err)
	}
}

func TestSend_SkipsSelfDevice(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	mgr := NewManager(store, DefaultConfig(), stubCreateSession(),
		WithLocalIdentity("alice", 1))
	mgr.SetClock(testClock(now))

	results, err := mgr.Send("alice", []uint32{1, 2, 3}, []byte("hello"), successEncrypt())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Self-device (1) should be skipped.
	if _, ok := results[1]; ok {
		t.Error("expected self-device to be skipped in Send")
	}
	if _, ok := results[2]; !ok {
		t.Error("expected device 2 in results")
	}
	if _, ok := results[3]; !ok {
		t.Error("expected device 3 in results")
	}
}

func TestManager_LocalIdentity(t *testing.T) {
	store := NewMemoryStore()
	mgr := NewManager(store, nil, stubCreateSession(),
		WithLocalIdentity("alice", 42))

	if mgr.LocalUserID() != "alice" {
		t.Errorf("expected localUserID=alice, got %s", mgr.LocalUserID())
	}
	if mgr.LocalDeviceID() != 42 {
		t.Errorf("expected localDeviceID=42, got %d", mgr.LocalDeviceID())
	}
}

func TestManager_NoLocalIdentity_SelfDeviceNotExcluded(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	// No WithLocalIdentity option.
	mgr := NewManager(store, DefaultConfig(), stubCreateSession())
	mgr.SetClock(testClock(now))

	// Without local identity set, no self-device exclusion.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ============================================================================
// Bug 10: Cascade deletion
// ============================================================================

func TestCleanupExpired_CascadeDeleteEmptyDevice(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	mgr := NewManager(NewMemoryStore(), cfg, stubCreateSession())
	mgr.SetClock(testClock(now))

	// Create a session.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// Advance past MaxRecv so all sessions expire and get cleaned.
	expiredTime := now.Add(cfg.MaxRecv + time.Hour)
	mgr.SetClock(testClock(expiredTime))

	if err := mgr.CleanupExpired(); err != nil {
		t.Fatal(err)
	}

	// Device should be cascade-deleted (empty after session cleanup).
	// User should also be cascade-deleted (empty after device cleanup).
	if mgr.Store().ContainsUserRecord("alice") {
		t.Error("expected user record to be cascade-deleted when all devices/sessions removed")
	}
}

func TestRemoveStaleDevices_CascadeDeleteEmptyDevice(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()

	user := NewUserRecord("alice")
	device, _ := user.AddDevice(1, 0)

	// Add a session that's recv-expired.
	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}), nil, now,
	)
	device.InsertSession(sw, nil, now)

	expiredTime := now.Add(cfg.MaxRecv + time.Hour)
	user.RemoveStaleDevices(cfg, expiredTime)

	// Device should be removed because it became empty after session cleanup.
	if user.GetDevice(1) != nil {
		t.Error("expected empty device to be cascade-deleted")
	}
}

// ============================================================================
// New type constructors
// ============================================================================

func TestNewDeviceRecordWithIdentity(t *testing.T) {
	key := testIdentityKey(0x01)
	device := NewDeviceRecordWithIdentity(42, key)

	if device.DeviceID() != 42 {
		t.Errorf("expected deviceID=42, got %d", device.DeviceID())
	}
	if device.IdentityKey() != key {
		t.Error("expected identity key to be set")
	}
}

func TestNewDeviceRecordWithIdentity_Nil(t *testing.T) {
	device := NewDeviceRecordWithIdentity(42, nil)
	if device.IdentityKey() != nil {
		t.Error("expected nil identity key")
	}
}

func TestNewUserRecordWithIdentity(t *testing.T) {
	key := testIdentityKey(0x01)
	user := NewUserRecordWithIdentity("alice", key)

	if user.UserID() != "alice" {
		t.Errorf("expected userID=alice, got %s", user.UserID())
	}
	if user.IdentityKey() != key {
		t.Error("expected identity key to be set")
	}
}

func TestNewUserRecordWithIdentity_Nil(t *testing.T) {
	user := NewUserRecordWithIdentity("alice", nil)
	if user.IdentityKey() != nil {
		t.Error("expected nil identity key")
	}
}

func TestDeviceRecord_SetIdentityKey(t *testing.T) {
	device := NewDeviceRecord(1)
	key := testIdentityKey(0x42)
	device.SetIdentityKey(key)
	if device.IdentityKey() != key {
		t.Error("SetIdentityKey did not set key")
	}
}

func TestUserRecord_SetIdentityKey(t *testing.T) {
	user := NewUserRecord("alice")
	key := testIdentityKey(0x42)
	user.SetIdentityKey(key)
	if user.IdentityKey() != key {
		t.Error("SetIdentityKey did not set key")
	}
}

func TestUserRecord_AddDeviceWithIdentity(t *testing.T) {
	key := testIdentityKey(0x01)
	user := NewUserRecord("alice")
	device, err := user.AddDeviceWithIdentity(1, key, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if device.IdentityKey() != key {
		t.Error("expected identity key on device")
	}

	// Adding again should return existing.
	device2, err := user.AddDeviceWithIdentity(1, testIdentityKey(0x02), 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if device2 != device {
		t.Error("expected same device when already exists")
	}
}

// ============================================================================
// Error type tests
// ============================================================================

func TestSelfDeviceError(t *testing.T) {
	err := NewSelfDeviceError("alice", 1)
	if !errors.Is(err, ErrSelfDevice) {
		t.Error("expected ErrSelfDevice")
	}
	if err.Error() == "" {
		t.Error("expected non-empty error message")
	}
}

func TestSelfDeviceError_Kind(t *testing.T) {
	err := NewSelfDeviceError("alice", 1)
	if err.Kind != ErrorKindSelfDevice {
		t.Errorf("expected ErrorKindSelfDevice, got %d", err.Kind)
	}
}

// ============================================================================
// identityKeysEqual helper
// ============================================================================

func TestIdentityKeysEqual_BothNil(t *testing.T) {
	if !identityKeysEqual(nil, nil) {
		t.Error("expected nil == nil to be true")
	}
}

func TestIdentityKeysEqual_OneNil(t *testing.T) {
	key := testIdentityKey(0x01)
	if identityKeysEqual(key, nil) {
		t.Error("expected key != nil to be false")
	}
	if identityKeysEqual(nil, key) {
		t.Error("expected nil != key to be false")
	}
}

func TestIdentityKeysEqual_SameKey(t *testing.T) {
	key := testIdentityKey(0x01)
	if !identityKeysEqual(key, key) {
		t.Error("expected same key to be equal")
	}
}

func TestIdentityKeysEqual_DifferentKeys(t *testing.T) {
	keyA := testIdentityKey(0x01)
	keyB := testIdentityKey(0x02)
	if identityKeysEqual(keyA, keyB) {
		t.Error("expected different keys to not be equal")
	}
}

func TestIdentityKeysEqual_EqualKeys(t *testing.T) {
	keyA := testIdentityKey(0x01)
	keyB := testIdentityKey(0x01)
	if !identityKeysEqual(keyA, keyB) {
		t.Error("expected equal keys to be equal")
	}
}
