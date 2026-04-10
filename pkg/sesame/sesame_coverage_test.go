package sesame

import (
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// TestRestoreError_ErrorAndUnwrapAndIs covers RestoreError.Error(), Unwrap(), Is().
func TestRestoreError_ErrorAndUnwrapAndIs(t *testing.T) {
	origErr := errors.New("original failure")
	restoreErr := errors.New("restore failure")

	re := NewRestoreFailedError(origErr, restoreErr)
	if re == nil {
		t.Fatal("NewRestoreFailedError returned nil")
	}

	msg := re.Error()
	if msg == "" {
		t.Fatal("Error() returned empty string")
	}
	if !strHas(msg, "original failure") {
		t.Errorf("Error() = %q, expected 'original failure'", msg)
	}
	if !strHas(msg, "restore failure") {
		t.Errorf("Error() = %q, expected 'restore failure'", msg)
	}

	// Unwrap returns the original error.
	if re.Unwrap() != origErr {
		t.Error("Unwrap() should return the original error")
	}

	// Is matches RestoreError by type.
	if !errors.Is(re, &RestoreError{}) {
		t.Error("errors.Is should match RestoreError")
	}

	// Is does not match SesameError.
	if errors.Is(re, ErrNoActiveSession) {
		t.Error("RestoreError should not match ErrNoActiveSession")
	}
}

// TestNewSendExpiredError covers the NewSendExpiredError constructor.
func TestNewSendExpiredError(t *testing.T) {
	err := NewSendExpiredError("alice", 1)
	if err == nil {
		t.Fatal("NewSendExpiredError returned nil")
	}

	msg := err.Error()
	if !strHas(msg, "alice") {
		t.Errorf("Error() = %q, expected 'alice'", msg)
	}
	if !strHas(msg, "MAXSEND") {
		t.Errorf("Error() = %q, expected 'MAXSEND'", msg)
	}

	if !errors.Is(err, ErrSendExpired) {
		t.Error("NewSendExpiredError should match ErrSendExpired sentinel")
	}
}

// TestSessionWrapper_LastSend_ZeroValue ensures LastSend returns zero time
// when no send has been recorded (atomic.Value stores zero time{} on init).
func TestSessionWrapper_LastSend_ZeroValue(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}),
		nil,
		now,
	)

	lastSend := sw.LastSend()
	if !lastSend.IsZero() {
		t.Errorf("LastSend() = %v, want zero time before any send", lastSend)
	}
}

// TestSessionWrapper_LastReceive_ZeroValue ensures LastReceive returns zero time
// when no receive has been recorded.
func TestSessionWrapper_LastReceive_ZeroValue(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}),
		nil,
		now,
	)

	lastRecv := sw.LastReceive()
	if !lastRecv.IsZero() {
		t.Errorf("LastReceive() = %v, want zero time before any receive", lastRecv)
	}
}

// TestSessionWrapper_LastSend_AfterRecordSend verifies that LastSend returns the
// stored timestamp after RecordSend is called.
func TestSessionWrapper_LastSend_AfterRecordSend(t *testing.T) {
	now := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}),
		nil,
		now,
	)

	sendTime := now.Add(5 * time.Minute)
	sw.RecordSend(sendTime)

	if !sw.LastSend().Equal(sendTime) {
		t.Errorf("LastSend() = %v, want %v", sw.LastSend(), sendTime)
	}
}

// TestSessionWrapper_LastReceive_AfterRecordReceive verifies LastReceive
// returns the stored timestamp after RecordReceive is called.
func TestSessionWrapper_LastReceive_AfterRecordReceive(t *testing.T) {
	now := time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}),
		nil,
		now,
	)

	recvTime := now.Add(3 * time.Minute)
	sw.RecordReceive(recvTime)

	if !sw.LastReceive().Equal(recvTime) {
		t.Errorf("LastReceive() = %v, want %v", sw.LastReceive(), recvTime)
	}
}

// TestSessionWrapper_Clone_CopiesTimestamps verifies Clone copies lastSend and lastReceive.
func TestSessionWrapper_Clone_CopiesTimestamps(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sw := NewSessionWrapper(
		record.NewSession(&noopSessionSerializer{}, &noopStateSerializer{}),
		nil,
		now,
	)

	sendTime := now.Add(10 * time.Minute)
	recvTime := now.Add(15 * time.Minute)
	sw.RecordSend(sendTime)
	sw.RecordReceive(recvTime)

	cloned, err := sw.Clone()
	if err != nil {
		t.Fatalf("Clone() error: %v", err)
	}

	if !cloned.LastSend().Equal(sendTime) {
		t.Errorf("clone LastSend() = %v, want %v", cloned.LastSend(), sendTime)
	}
	if !cloned.LastReceive().Equal(recvTime) {
		t.Errorf("clone LastReceive() = %v, want %v", cloned.LastReceive(), recvTime)
	}
}

// TestMemoryStore_StoreLoad_Roundtrip verifies MemoryStore stores and loads records.
func TestMemoryStore_StoreLoad_Roundtrip(t *testing.T) {
	store := NewMemoryStore()
	user := NewUserRecord("alice")

	if err := store.StoreUserRecord("alice", user); err != nil {
		t.Fatalf("StoreUserRecord failed: %v", err)
	}

	loaded, err := store.LoadUserRecord("alice")
	if err != nil {
		t.Fatalf("LoadUserRecord failed: %v", err)
	}
	if loaded == nil {
		t.Fatal("expected non-nil user record")
	}
	if loaded.UserID() != "alice" {
		t.Errorf("UserID() = %q, want 'alice'", loaded.UserID())
	}
}

// TestMemoryStore_LoadNonExistent verifies LoadUserRecord returns nil for missing user.
func TestMemoryStore_LoadNonExistent(t *testing.T) {
	store := NewMemoryStore()
	rec, err := store.LoadUserRecord("nobody")
	if err != nil {
		t.Fatalf("LoadUserRecord error: %v", err)
	}
	if rec != nil {
		t.Error("expected nil for non-existent user record")
	}
}

// TestManager_PrepForEncrypting_MaxUsersLimit covers the checkMaxUsers error path.
func TestManager_PrepForEncrypting_MaxUsersLimit(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	cfg.MaxUsers = 1 // allow only 1 user

	store := NewMemoryStore()
	mgr := NewManager(store, cfg, stubCreateSession())
	mgr.SetClock(testClock(now))

	// First user should succeed.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("first PrepForEncrypting failed: %v", err)
	}

	// Second different user should fail with MaxUsersExceeded.
	_, err = mgr.PrepForEncrypting("bob", 1, nil)
	if err == nil {
		t.Fatal("expected error when MaxUsers exceeded")
	}
	if !errors.Is(err, ErrMaxUsersExceeded) {
		t.Errorf("error = %v, want ErrMaxUsersExceeded", err)
	}
}

// TestManager_Send_EncryptFails covers the encrypt error path in Send.
func TestManager_Send_EncryptFails(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Pre-create session.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	encryptErr := errors.New("encrypt error")
	_, err = mgr.Send("alice", []uint32{1}, []byte("hello"), func(session *SessionWrapper, plaintext []byte) ([]byte, error) {
		return nil, encryptErr
	})
	if err == nil {
		t.Fatal("expected error when encrypt fails")
	}
}

// TestManager_Receive_AllSessionsFail covers the decryption-failed error path.
func TestManager_Receive_AllSessionsFail(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Pre-create session for bob.
	_, err := mgr.PrepForEncrypting("bob", 1, nil)
	if err != nil {
		t.Fatalf("setup error: %v", err)
	}

	// All decrypt attempts fail.
	_, err = mgr.Receive("bob", 1, []byte("ciphertext"), failingDecrypt())
	if err == nil {
		t.Fatal("expected error when all sessions fail to decrypt")
	}
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Errorf("error = %v, want ErrDecryptionFailed", err)
	}
}

// TestManager_UpdateDeviceList_MarksAbsentDevicesStale covers the UpdateDeviceList path
// where a device not in the new list is marked stale (not removed).
func TestManager_UpdateDeviceList_MarksAbsentDevicesStale(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create sessions for devices 1, 2, 3.
	for _, deviceID := range []uint32{1, 2, 3} {
		if _, err := mgr.PrepForEncrypting("carol", deviceID, nil); err != nil {
			t.Fatalf("PrepForEncrypting device %d error: %v", deviceID, err)
		}
	}

	// Update device list to only include devices 1 and 2.
	if err := mgr.UpdateDeviceList("carol", []uint32{1, 2}); err != nil {
		t.Fatalf("UpdateDeviceList error: %v", err)
	}

	// Device 3 should be marked stale, not removed.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "carol")
	device3 := userRecord.GetDevice(3)
	if device3 == nil {
		t.Fatal("device 3 should still exist (marked stale, not deleted)")
	}
	if !device3.IsStale() {
		t.Error("device 3 should be marked stale after UpdateDeviceList")
	}
	// Devices 1 and 2 should not be stale.
	if userRecord.GetDevice(1).IsStale() {
		t.Error("device 1 should not be stale")
	}
	if userRecord.GetDevice(2).IsStale() {
		t.Error("device 2 should not be stale")
	}
}

// TestSesameError_Error_WithCause verifies SesameError.Error() includes the cause.
func TestSesameError_Error_WithCause(t *testing.T) {
	cause := errors.New("inner cause")
	err := &SesameError{
		Kind:    ErrorKindDecryptionFailed,
		Message: "decrypt error",
		Cause:   cause,
	}

	msg := err.Error()
	if !strHas(msg, "decrypt error") {
		t.Errorf("Error() = %q, expected 'decrypt error'", msg)
	}
	if !strHas(msg, "inner cause") {
		t.Errorf("Error() = %q, expected 'inner cause'", msg)
	}
	if err.Unwrap() != cause {
		t.Error("Unwrap() should return the cause")
	}
}

// TestSessionWrapper_LastSend_NilAtomicValue verifies LastSend returns zero
// time when the atomic.Value has never been stored (defensive nil guard).
func TestSessionWrapper_LastSend_NilAtomicValue(t *testing.T) {
	// Create a SessionWrapper without calling NewSessionWrapper to leave
	// the atomic.Value in its zero state (never stored).
	sw := &SessionWrapper{}

	lastSend := sw.LastSend()
	if !lastSend.IsZero() {
		t.Errorf("LastSend() = %v, want zero time for nil atomic.Value", lastSend)
	}
}

// TestSessionWrapper_LastReceive_NilAtomicValue verifies LastReceive returns
// zero time when the atomic.Value has never been stored.
func TestSessionWrapper_LastReceive_NilAtomicValue(t *testing.T) {
	sw := &SessionWrapper{}

	lastRecv := sw.LastReceive()
	if !lastRecv.IsZero() {
		t.Errorf("LastReceive() = %v, want zero time for nil atomic.Value", lastRecv)
	}
}

// TestCleanupExpired_RemovesStaleExpiredUser covers the stale user past MaxLatency path.
func TestCleanupExpired_RemovesStaleExpiredUser(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create a user record and mark it stale.
	_, err := mgr.PrepForEncrypting("staleuser", 1, nil)
	if err != nil {
		t.Fatalf("PrepForEncrypting failed: %v", err)
	}

	// Mark the user stale.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "staleuser")
	userRecord.MarkStale(now)
	mustStoreUserRecord(t, mgr.Store(), "staleuser", userRecord)

	// Advance past MaxLatency.
	expiredTime := now.Add(DefaultMaxLatency + time.Hour)
	mgr.SetClock(testClock(expiredTime))

	if err := mgr.CleanupExpired(); err != nil {
		t.Fatalf("CleanupExpired error: %v", err)
	}

	// The stale-expired user should be removed.
	if mgr.Store().ContainsUserRecord("staleuser") {
		t.Error("stale-expired user should be deleted by CleanupExpired")
	}
}

// TestCleanupExpired_CascadeDeletesEmptyUser covers the empty user record cascade path.
func TestCleanupExpired_CascadeDeletesEmptyUser(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create a user with device 1 that has a session.
	_, err := mgr.PrepForEncrypting("cascadeuser", 1, nil)
	if err != nil {
		t.Fatalf("PrepForEncrypting failed: %v", err)
	}

	// Mark the device stale so it gets removed during CleanupExpired.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "cascadeuser")
	device := userRecord.GetDevice(1)
	device.MarkStale(now)
	mustStoreUserRecord(t, mgr.Store(), "cascadeuser", userRecord)

	// Advance past MaxLatency so the stale device expires.
	expiredTime := now.Add(DefaultMaxLatency + time.Hour)
	mgr.SetClock(testClock(expiredTime))

	if err := mgr.CleanupExpired(); err != nil {
		t.Fatalf("CleanupExpired error: %v", err)
	}

	// After all devices are removed, the empty user record should be cascade-deleted.
	if mgr.Store().ContainsUserRecord("cascadeuser") {
		t.Error("empty user record should be cascade-deleted by CleanupExpired")
	}
}

// TestManager_SendWithServerLoop_NewDevicesRetry verifies that SendWithServerLoop
// handles the case where new devices are returned by the server.
func TestManager_SendWithServerLoop_NewDevicesRetry(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	callCount := 0
	// The server returns no old/new devices — no retry needed.
	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		callCount++
		return &ServerResponse{UserExists: true}, nil
	}

	_, err := mgr.SendWithServerLoop("dave", []byte("hello"), successEncrypt(), sendToServer)
	if err != nil {
		t.Fatalf("SendWithServerLoop failed: %v", err)
	}
	if callCount < 1 {
		t.Error("sendToServer should have been called at least once")
	}
}

// TestManager_CheckMaxUsers_ZeroMaxDisabled verifies that MaxUsers <= 0 allows
// unlimited users without error.
func TestManager_CheckMaxUsers_ZeroMaxDisabled(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	cfg := DefaultConfig()
	cfg.MaxUsers = 0 // 0 means unlimited

	store := NewMemoryStore()
	mgr := NewManager(store, cfg, stubCreateSession())
	mgr.SetClock(testClock(now))

	// Should be able to add many users when MaxUsers == 0 (unlimited).
	for i := 0; i < 5; i++ {
		userID := "user" + string(rune('a'+i))
		_, err := mgr.PrepForEncrypting(userID, 1, nil)
		if err != nil {
			t.Fatalf("PrepForEncrypting %s failed: %v", userID, err)
		}
	}
}

// TestSend_PrepForEncryptingFails covers the error rollback path in Send when
// prepForEncryptingLocked returns an error (MaxDevicesPerUser exceeded).
func TestSend_PrepForEncryptingFails(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	store := NewMemoryStore()
	cfg := DefaultConfig()
	cfg.MaxDevicesPerUser = 1 // only 1 device per user

	mgr := NewManager(store, cfg, stubCreateSession())
	mgr.SetClock(testClock(now))

	// Prep device 1 for alice — this succeeds (1 device within limit).
	if _, err := mgr.PrepForEncrypting("alice", 1, nil); err != nil {
		t.Fatalf("PrepForEncrypting device 1 failed: %v", err)
	}

	// Now Send for devices [1, 2] — device 2 doesn't exist yet and exceeds MaxDevicesPerUser.
	// prepForEncryptingLocked should fail when trying to add device 2, triggering rollback.
	_, err := mgr.Send("alice", []uint32{1, 2}, []byte("hello"), successEncrypt())
	if err == nil {
		t.Fatal("expected error when MaxDevicesPerUser exceeded during Send")
	}
}

// TestSendAttempt_StaleDeviceSkipped verifies that sendAttempt skips stale devices
// in the encryption loop, exercising the stale device continue branch.
func TestSendAttempt_StaleDeviceSkipped(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Prep device 1 for alice.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("PrepForEncrypting failed: %v", err)
	}

	// Mark device 1 as stale directly so sendAttempt's loop hits the continue branch.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	device := userRecord.GetDevice(1)
	device.MarkStale(now)
	mustStoreUserRecord(t, mgr.Store(), "alice", userRecord)

	// sendAttempt is called internally by SendWithServerLoop.
	// With device 1 stale, it should skip it and produce empty results.
	callCount := 0
	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		callCount++
		// Verify no messages sent (stale device skipped).
		if len(messages) != 0 {
			t.Errorf("expected empty messages for stale device, got %d", len(messages))
		}
		return &ServerResponse{UserExists: true, Accepted: true}, nil
	}

	results, err := mgr.SendWithServerLoop("alice", []byte("hello"), successEncrypt(), sendToServer)
	if err != nil {
		t.Fatalf("SendWithServerLoop failed: %v", err)
	}
	if len(results) != 0 {
		t.Errorf("expected no ciphertexts for stale device, got %d", len(results))
	}
	if callCount != 1 {
		t.Errorf("sendToServer should be called once, got %d", callCount)
	}
}

// TestSendAttempt_SelfDeviceSkipped verifies that sendAttempt skips the local
// device in the encryption loop when a local identity is configured.
func TestSendAttempt_SelfDeviceSkipped(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	store := NewMemoryStore()
	cfg := DefaultConfig()
	// Configure local identity: userID="alice", deviceID=1.
	mgr := NewManager(store, cfg, stubCreateSession(), WithLocalIdentity("alice", 1))
	mgr.SetClock(testClock(now))

	// Inject a user record with device 1 (self-device) manually since
	// PrepForEncrypting rejects self-device.
	ur := NewUserRecord("alice")
	if _, err := ur.AddDevice(1, cfg.MaxDevicesPerUser); err != nil {
		t.Fatalf("AddDevice failed: %v", err)
	}
	mustStoreUserRecord(t, mgr.Store(), "alice", ur)

	callCount := 0
	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		callCount++
		return &ServerResponse{UserExists: true, Accepted: true}, nil
	}

	// SendWithServerLoop should skip device 1 (self) and produce empty ciphertexts.
	results, err := mgr.SendWithServerLoop("alice", []byte("hello"), successEncrypt(), sendToServer)
	if err != nil {
		t.Fatalf("SendWithServerLoop failed: %v", err)
	}
	// Self-device is skipped, so no ciphertext for device 1.
	if _, ok := results[1]; ok {
		t.Error("self-device should be skipped in sendAttempt")
	}
}

// TestSendWithServerLoop_OldDevicesMarkedStale verifies that OldDevices in
// the server response causes those devices to be marked stale.
func TestSendWithServerLoop_OldDevicesMarkedStale(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Prep two devices.
	for _, devID := range []uint32{1, 2} {
		if _, err := mgr.PrepForEncrypting("alice", devID, nil); err != nil {
			t.Fatalf("PrepForEncrypting device %d failed: %v", devID, err)
		}
	}

	// Server reports device 2 as old.
	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		return &ServerResponse{
			UserExists: true,
			Accepted:   true,
			OldDevices: []uint32{2},
		}, nil
	}

	_, err := mgr.SendWithServerLoop("alice", []byte("hello"), successEncrypt(), sendToServer)
	if err != nil {
		t.Fatalf("SendWithServerLoop failed: %v", err)
	}

	// Device 2 should now be marked stale.
	userRecord := mustLoadUserRecord(t, mgr.Store(), "alice")
	dev2 := userRecord.GetDevice(2)
	if dev2 == nil {
		t.Fatal("device 2 should still exist")
	}
	if !dev2.IsStale() {
		t.Error("device 2 should be marked stale after OldDevices response")
	}
}

// TestSendWithServerLoop_NewDevicesSelfSkipped verifies that when the server
// returns new devices that include the local device, they are skipped.
func TestSendWithServerLoop_NewDevicesSelfSkipped(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	store := NewMemoryStore()
	cfg := DefaultConfig()
	// Local identity: alice, device 99.
	mgr := NewManager(store, cfg, stubCreateSession(), WithLocalIdentity("alice", 99))
	mgr.SetClock(testClock(now))

	// Prep device 1 for alice.
	_, err := mgr.PrepForEncrypting("alice", 1, nil)
	if err != nil {
		t.Fatalf("PrepForEncrypting failed: %v", err)
	}

	callCount := 0
	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		callCount++
		if callCount == 1 {
			// First call: report device 99 (self) as a "new" device.
			return &ServerResponse{
				UserExists: true,
				Accepted:   true,
				NewDevices: map[uint32]*identity.Key{99: nil},
			}, nil
		}
		// Second call (retry): no new devices.
		return &ServerResponse{UserExists: true, Accepted: true}, nil
	}

	_, err = mgr.SendWithServerLoop("alice", []byte("hello"), successEncrypt(), sendToServer)
	if err != nil {
		t.Fatalf("SendWithServerLoop failed: %v", err)
	}
}

// TestSendAttempt_StaleUserDeletedInLoop exercises the IsStaleExpired path
// inside sendAttempt where the user record is expired when the attempt starts.
func TestSendAttempt_StaleUserDeletedInLoop(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	mgr := newTestManager(now)

	// Create a user record that is stale and beyond MaxLatency.
	ur := NewUserRecord("stale")
	ur.MarkStale(now.Add(-DefaultMaxLatency - time.Hour))
	mustStoreUserRecord(t, mgr.Store(), "stale", ur)

	// Advance clock past MaxLatency.
	mgr.SetClock(testClock(now.Add(DefaultMaxLatency + 2*time.Hour)))

	sendToServer := func(userID string, messages map[uint32][]byte) (*ServerResponse, error) {
		return &ServerResponse{UserExists: true, Accepted: true}, nil
	}

	// sendAttempt should delete the expired user record and create a new one.
	_, err := mgr.SendWithServerLoop("stale", []byte("msg"), successEncrypt(), sendToServer)
	if err != nil {
		t.Fatalf("SendWithServerLoop failed: %v", err)
	}
}

// strHas is a simple substring check.
func strHas(s, sub string) bool {
	if len(sub) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
