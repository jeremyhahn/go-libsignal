package sesame

import (
	"crypto/subtle"
	"sync"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// EncryptFunc is a callback that encrypts plaintext using the given session.
type EncryptFunc func(session *SessionWrapper, plaintext []byte) ([]byte, error)

// DecryptFunc is a callback that decrypts ciphertext using the given session.
type DecryptFunc func(session *SessionWrapper, ciphertext []byte) ([]byte, error)

// CreateSessionFunc is a callback that creates a new initiating session from
// a prekey bundle for the given user and device. It returns the new session
// record, or an error if the session cannot be established.
type CreateSessionFunc func(userID string, deviceID uint32) (*record.Session, error)

// ServerResponse represents the server's response after a send attempt.
// Per Sesame spec section 3.3, the server returns the current device list
// so the sender can reconcile.
type ServerResponse struct {
	// Accepted indicates whether the server accepted the messages.
	Accepted bool
	// UserExists indicates whether the user exists on the server.
	UserExists bool
	// OldDevices lists DeviceIDs that are no longer registered.
	OldDevices []uint32
	// NewDevices maps new DeviceIDs to their identity keys.
	NewDevices map[uint32]*identity.Key
}

// SendToServerFunc is called to send encrypted messages to the server.
// Returns the server's response about device list changes.
type SendToServerFunc func(userID string, messages map[uint32][]byte) (*ServerResponse, error)

// Manager implements the Sesame session management algorithm as described in
// the Sesame specification. It coordinates session lifecycle across multiple
// users and devices, handling creation, expiration, and routing of encrypt
// and decrypt operations.
type Manager struct {
	mu            sync.RWMutex
	store         Store
	config        *Config
	clock         func() time.Time
	createSession CreateSessionFunc
	localUserID   string
	localDeviceID uint32
}

// NewManager creates a new Sesame Manager with the given store, configuration,
// session creation callback, and local identity. If config is nil, DefaultConfig
// is used. The localUserID and localDeviceID identify this device; per the Sesame
// spec, a device must not store a DeviceRecord for its own DeviceID.
func NewManager(store Store, config *Config, createSession CreateSessionFunc, opts ...ManagerOption) *Manager {
	if config == nil {
		config = DefaultConfig()
	}
	m := &Manager{
		store:         store,
		config:        config,
		clock:         time.Now,
		createSession: createSession,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// ManagerOption configures optional Manager parameters.
type ManagerOption func(*Manager)

// WithLocalIdentity sets the local user ID and device ID for self-device
// exclusion per the Sesame specification.
func WithLocalIdentity(userID string, deviceID uint32) ManagerOption {
	return func(m *Manager) {
		m.localUserID = userID
		m.localDeviceID = deviceID
	}
}

// SetClock overrides the clock function used for timestamp generation.
// This is primarily intended for testing.
func (m *Manager) SetClock(clock func() time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clock = clock
}

// Config returns the manager's configuration.
func (m *Manager) Config() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// Store returns the manager's store.
func (m *Manager) Store() Store {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.store
}

// LocalUserID returns the local user ID.
func (m *Manager) LocalUserID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.localUserID
}

// LocalDeviceID returns the local device ID.
func (m *Manager) LocalDeviceID() uint32 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.localDeviceID
}

// isSelfDevice returns true if the given user and device match the local identity.
// Must be called with m.mu held (read or write).
func (m *Manager) isSelfDevice(userID string, deviceID uint32) bool {
	return m.localUserID != "" && m.localUserID == userID && m.localDeviceID == deviceID
}

// PrepForEncrypting implements section 3.2 of the Sesame specification.
// It ensures a valid active session exists for the given user and device,
// creating one from a prekey bundle if necessary.
//
// Steps:
//  1. Delete any stale DeviceRecords unconditionally (for send path)
//  2. Conditionally update records (create if needed, replace on identity key change)
//  3. If no active session, create initiating session from prekey bundle
//  4. Check MAXSEND on active session; deactivate and create new if expired
//  5. Return active session
func (m *Manager) PrepForEncrypting(userID string, deviceID uint32, identityKey *identity.Key) (*SessionWrapper, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.prepForEncryptingLocked(userID, deviceID, identityKey)
}

// prepForEncryptingLocked is the internal implementation of PrepForEncrypting.
// Must be called with m.mu held for writing.
func (m *Manager) prepForEncryptingLocked(userID string, deviceID uint32, identityKey *identity.Key) (*SessionWrapper, error) {
	// Per spec: device must not store a DeviceRecord for its own DeviceID.
	if m.isSelfDevice(userID, deviceID) {
		return nil, NewSelfDeviceError(userID, deviceID)
	}

	now := m.clock()

	// Step 1: Load or create user record, delete stale entries.
	// Per spec: "prep for encrypting" step 1 deletes stale records
	// unconditionally for sending. The MaxLatency grace period is for
	// the receive path only.
	userRecord, err := m.store.LoadUserRecord(userID)
	if err != nil {
		return nil, err
	}
	if userRecord != nil {
		// Delete stale user record past MaxLatency.
		if userRecord.IsStaleExpired(m.config, now) {
			m.store.DeleteUserRecord(userID)
			userRecord = nil
		} else {
			// Delete stale devices unconditionally for send path.
			m.deleteStaleDevicesForSend(userRecord)
		}
	}

	// Step 2: Create user record if needed.
	if userRecord == nil {
		if err := m.checkMaxUsers(userID); err != nil {
			return nil, err
		}
		if identityKey != nil {
			userRecord = NewUserRecordWithIdentity(userID, identityKey)
		} else {
			userRecord = NewUserRecord(userID)
		}
	}

	// Step 2: Conditional update - get or create device record.
	// Per spec: when identity key doesn't match, replace the entire
	// UserRecord/DeviceRecord with empty ones.
	deviceRecord := userRecord.GetDevice(deviceID)
	if deviceRecord != nil && identityKey != nil {
		if deviceRecord.ActiveSession() != nil && deviceRecord.ActiveSession().HasIdentityKeyChanged(identityKey) {
			// Identity key mismatch: replace with empty records per spec.
			userRecord = NewUserRecordWithIdentity(userID, identityKey)
			deviceRecord = nil
		} else if userRecord.IdentityKey() != nil && !identityKeysEqual(userRecord.IdentityKey(), identityKey) {
			// User-level identity key mismatch.
			userRecord = NewUserRecordWithIdentity(userID, identityKey)
			deviceRecord = nil
		}
	}

	if deviceRecord == nil {
		if identityKey != nil {
			deviceRecord, err = userRecord.AddDeviceWithIdentity(deviceID, identityKey, m.config.MaxDevicesPerUser)
		} else {
			deviceRecord, err = userRecord.AddDevice(deviceID, m.config.MaxDevicesPerUser)
		}
		if err != nil {
			return nil, err
		}
	} else {
		// Clear stale flag if device is being actively addressed.
		deviceRecord.ClearStale()
	}

	// Update identity keys on the records if provided.
	if identityKey != nil {
		userRecord.SetIdentityKey(identityKey)
		deviceRecord.SetIdentityKey(identityKey)
	}

	// Step 3: If no active session, create one from prekey bundle.
	if deviceRecord.ActiveSession() == nil {
		sessionRecord, createErr := m.createSession(userID, deviceID)
		if createErr != nil {
			// Persist any cleanup we did.
			if storeErr := m.store.StoreUserRecord(userID, userRecord); storeErr != nil {
				return nil, storeErr
			}
			return nil, &SesameError{
				Kind:    ErrorKindNoActiveSession,
				Message: "failed to create session",
				Cause:   createErr,
			}
		}
		wrapper := NewSessionWrapper(sessionRecord, identityKey, now)
		// Use InsertSession: new session always becomes active per spec.
		deviceRecord.InsertSession(wrapper, m.config, now)
	}

	// Fix 2: Per spec section 4.2, sessions that exceed MAXSEND "must no
	// longer be used for encryption." Check the active session and deactivate
	// it if expired, then create a new session.
	if deviceRecord.ActiveSession() != nil && deviceRecord.ActiveSession().IsSendExpired(m.config, now) {
		deviceRecord.DeactivateSession(m.config)

		// Create a fresh session from prekey bundle.
		sessionRecord, createErr := m.createSession(userID, deviceID)
		if createErr != nil {
			// Persist current state and return error indicating no valid session.
			if storeErr := m.store.StoreUserRecord(userID, userRecord); storeErr != nil {
				return nil, storeErr
			}
			return nil, NewSendExpiredError(userID, deviceID)
		}
		wrapper := NewSessionWrapper(sessionRecord, identityKey, now)
		deviceRecord.InsertSession(wrapper, m.config, now)
	}

	// Clear user stale flag since we are actively using it.
	userRecord.ClearStale()

	// Persist the updated state.
	if storeErr := m.store.StoreUserRecord(userID, userRecord); storeErr != nil {
		return nil, storeErr
	}

	// Step 5: Return active session.
	return deviceRecord.ActiveSession(), nil
}

// deleteStaleDevicesForSend removes all stale devices unconditionally.
// Per spec, the send path deletes stale records without waiting for MaxLatency.
func (m *Manager) deleteStaleDevicesForSend(userRecord *UserRecord) {
	for _, id := range userRecord.DeviceIDs() {
		device := userRecord.GetDevice(id)
		if device != nil && device.IsStale() {
			userRecord.RemoveDevice(id)
		}
	}
}

// Send implements section 3.3 of the Sesame specification (8-step sending).
// It encrypts plaintext for all specified devices of a user and returns
// a map of deviceID to ciphertext.
//
// Per spec section 3.3: "If any error occurs in encrypting to a particular user...
// then the sending device shall discard any changes to the relevant UserRecord."
//
// Steps:
//  1. Snapshot UserRecord for rollback
//  2. Look up UserRecord for recipient
//  3. PrepForEncrypting for each device
//  4. Encrypt plaintext with active session
//  5. Restore snapshot on any error
func (m *Manager) Send(userID string, deviceIDs []uint32, plaintext []byte, encrypt EncryptFunc) (map[uint32][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()

	// Fix 3: Snapshot user record before we start so we can restore on error.
	snapshot, snapshotErr := m.snapshotUserRecord(userID)
	if snapshotErr != nil {
		return nil, snapshotErr
	}

	results := make(map[uint32][]byte, len(deviceIDs))

	// Step 2: Look up or create user record.
	userRecord, loadErr := m.store.LoadUserRecord(userID)
	if loadErr != nil {
		return nil, loadErr
	}
	if userRecord != nil && userRecord.IsStaleExpired(m.config, now) {
		m.store.DeleteUserRecord(userID)
		userRecord = nil
	}

	// Steps 3-4: PrepForEncrypting and encrypt for each device.
	for _, deviceID := range deviceIDs {
		// Skip self-device.
		if m.isSelfDevice(userID, deviceID) {
			continue
		}

		session, err := m.prepForEncryptingLocked(userID, deviceID, nil)
		if err != nil {
			// Per spec: discard changes on error.
			if restoreErr := m.restoreUserRecord(userID, snapshot); restoreErr != nil {
				return nil, NewRestoreFailedError(err, restoreErr)
			}
			return nil, err
		}

		ciphertext, err := encrypt(session, plaintext)
		if err != nil {
			encryptErr := &SesameError{
				Kind:    ErrorKindNoActiveSession,
				Message: "encryption failed",
				Cause:   err,
			}
			// Per spec: discard changes on error.
			if restoreErr := m.restoreUserRecord(userID, snapshot); restoreErr != nil {
				return nil, NewRestoreFailedError(encryptErr, restoreErr)
			}
			return nil, encryptErr
		}

		// Record send timestamp.
		session.RecordSend(now)
		results[deviceID] = ciphertext
	}

	// Persist updated state after all encryptions succeed.
	updatedRecord, loadErr := m.store.LoadUserRecord(userID)
	if loadErr != nil {
		if restoreErr := m.restoreUserRecord(userID, snapshot); restoreErr != nil {
			return nil, NewRestoreFailedError(loadErr, restoreErr)
		}
		return nil, loadErr
	}
	if updatedRecord != nil {
		if storeErr := m.store.StoreUserRecord(userID, updatedRecord); storeErr != nil {
			if restoreErr := m.restoreUserRecord(userID, snapshot); restoreErr != nil {
				return nil, NewRestoreFailedError(storeErr, restoreErr)
			}
			return nil, storeErr
		}
	}

	return results, nil
}

// Receive implements section 3.4 of the Sesame specification (4-step receiving).
// It attempts to decrypt the ciphertext from the given user and device using
// only existing sessions -- it does NOT handle initiation messages that
// establish new sessions.
//
// For messages that create a new session (initiation messages / PreKeySignalMessage),
// callers must use ReceiveNewSession instead, which accepts the new session record
// produced by processing the prekey message. The caller is responsible for
// determining whether an incoming message is an initiation message before
// choosing between Receive and ReceiveNewSession. This is a deliberate API
// design choice that splits the Sesame spec's single receive entry point into
// two methods for clarity, making the session-creation side effect explicit.
//
// Steps:
//  1. Load existing user record; return error if no sessions exist to try
//  2. Try active session
//  3. Try inactive sessions (promote to active on success)
//  4. If nothing works, return DecryptionFailedError
func (m *Manager) Receive(userID string, deviceID uint32, ciphertext []byte, decrypt DecryptFunc) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()

	// Load the existing user record. MemoryStore returns clones,
	// so mutations here do not affect stored state until we explicitly store.
	existingRecord, loadErr := m.store.LoadUserRecord(userID)
	if loadErr != nil {
		return nil, loadErr
	}

	// If there is an existing record with a device, try existing sessions.
	if existingRecord != nil {
		deviceRecord := existingRecord.GetDevice(deviceID)
		if deviceRecord != nil {
			// Step 2: Try active session.
			if deviceRecord.ActiveSession() != nil {
				plaintext, err := decrypt(deviceRecord.ActiveSession(), ciphertext)
				if err == nil {
					deviceRecord.ActiveSession().RecordReceive(now)
					existingRecord.ClearStale()
					if storeErr := m.store.StoreUserRecord(userID, existingRecord); storeErr != nil {
						return nil, storeErr
					}
					return plaintext, nil
				}
			}

			// Step 3: Try inactive sessions.
			for i, session := range deviceRecord.InactiveSessions() {
				plaintext, err := decrypt(session, ciphertext)
				if err == nil {
					session.RecordReceive(now)
					// Promote to active.
					deviceRecord.PromoteInactiveSession(i, m.config, now)
					existingRecord.ClearStale()
					if storeErr := m.store.StoreUserRecord(userID, existingRecord); storeErr != nil {
						return nil, storeErr
					}
					return plaintext, nil
				}
			}
		}
	}

	// Step 4: All sessions failed (or no sessions existed to try).
	return nil, NewDecryptionFailedError(userID, deviceID, nil)
}

// ReceiveNewSession handles receiving an initiation message that establishes
// a new session. The caller provides the new session record from processing
// the prekey message. The new session is activated and used for decryption.
func (m *Manager) ReceiveNewSession(userID string, deviceID uint32, newSession *record.Session, ciphertext []byte, decrypt DecryptFunc) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()

	// Wrap the new session but do NOT activate it yet. We must verify
	// decryption succeeds before mutating any stored state.
	wrapper := NewSessionWrapper(newSession, nil, now)

	// Try to decrypt with the new session first.
	plaintext, err := decrypt(wrapper, ciphertext)
	if err != nil {
		return nil, NewDecryptionFailedError(userID, deviceID, err)
	}

	// Decryption succeeded - now persist the state.
	userRecord, loadErr := m.store.LoadUserRecord(userID)
	if loadErr != nil {
		return nil, loadErr
	}
	if userRecord == nil {
		if maxErr := m.checkMaxUsers(userID); maxErr != nil {
			return nil, maxErr
		}
		userRecord = NewUserRecord(userID)
	}

	deviceRecord := userRecord.GetDevice(deviceID)
	if deviceRecord == nil {
		var addErr error
		deviceRecord, addErr = userRecord.AddDevice(deviceID, m.config.MaxDevicesPerUser)
		if addErr != nil {
			return nil, addErr
		}
	}

	wrapper.RecordReceive(now)
	// Use InsertSession: new session from initiation always becomes active.
	deviceRecord.InsertSession(wrapper, m.config, now)
	userRecord.ClearStale()
	if storeErr := m.store.StoreUserRecord(userID, userRecord); storeErr != nil {
		return nil, storeErr
	}
	return plaintext, nil
}

// UpdateDeviceList compares the server-provided device list against the
// local records and marks devices not in the list as stale. This implements
// step 6 of the sending algorithm (section 3.3).
func (m *Manager) UpdateDeviceList(userID string, currentDevices []uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()

	userRecord, loadErr := m.store.LoadUserRecord(userID)
	if loadErr != nil {
		return loadErr
	}
	if userRecord == nil {
		return nil
	}

	// Build a set for O(1) lookup.
	currentSet := make(map[uint32]struct{}, len(currentDevices))
	for _, id := range currentDevices {
		currentSet[id] = struct{}{}
	}

	// Mark devices not in the current list as stale.
	for _, id := range userRecord.DeviceIDs() {
		if _, ok := currentSet[id]; !ok {
			device := userRecord.GetDevice(id)
			if device != nil && !device.IsStale() {
				device.MarkStale(now)
			}
		}
	}

	return m.store.StoreUserRecord(userID, userRecord)
}

// CleanupExpired removes expired sessions and stale records across all
// stored users. This should be called periodically as part of maintenance.
// Implements cascade deletion: when last session is deleted, the DeviceRecord
// is removed; when last DeviceRecord is deleted, the UserRecord is removed.
func (m *Manager) CleanupExpired() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.clock()

	userIDs := m.store.AllUserIDs()

	for _, userID := range userIDs {
		userRecord, loadErr := m.store.LoadUserRecord(userID)
		if loadErr != nil {
			return loadErr
		}
		if userRecord == nil {
			continue
		}

		// Remove stale user past MaxLatency.
		if userRecord.IsStaleExpired(m.config, now) {
			m.store.DeleteUserRecord(userID)
			continue
		}

		// Clean up devices and sessions (includes cascade deletion of empty devices).
		userRecord.RemoveStaleDevices(m.config, now)

		// Cascade: remove empty user records (last DeviceRecord deleted -> delete UserRecord).
		if userRecord.IsEmpty() {
			m.store.DeleteUserRecord(userID)
			continue
		}

		if storeErr := m.store.StoreUserRecord(userID, userRecord); storeErr != nil {
			return storeErr
		}
	}
	return nil
}

// SendWithServerLoop implements the 8-step iterative send process from
// Sesame spec section 3.3. It encrypts plaintext for a user's devices,
// sends to the server, and handles device list reconciliation with retries.
//
// Steps:
//  1. Look up UserRecord for recipient
//  2. For each non-stale DeviceRecord with active session, encrypt
//  3. Send to server via sendToServer callback
//  4. Server returns current device list (old + new devices)
//  5. Mark old devices stale
//  6. For each new device, PrepForEncrypting
//  7. Encrypt for new devices
//  8. Restart from step 1 if new devices were discovered (with retry limit)
//
// Per spec: "If any error occurs in encrypting to a particular user...
// then the sending device shall discard any changes to the relevant UserRecord."
func (m *Manager) SendWithServerLoop(
	userID string,
	plaintext []byte,
	encrypt EncryptFunc,
	sendToServer SendToServerFunc,
) (map[uint32][]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Snapshot the user record before we start so we can restore on error.
	snapshot, err := m.snapshotUserRecord(userID)
	if err != nil {
		return nil, err
	}

	// Note: On retry, re-encryption advances the EC ratchet for each attempt,
	// creating skipped message keys on the receiver side. This is inherent to
	// the Sesame spec's retry design and is bounded by MaxSendAttempts.
	for attempt := 0; attempt < m.config.MaxSendRetries; attempt++ {
		results, needsRetry, err := m.sendAttempt(userID, plaintext, encrypt, sendToServer)
		if err != nil {
			// Per spec: discard changes on error.
			if restoreErr := m.restoreUserRecord(userID, snapshot); restoreErr != nil {
				return nil, NewRestoreFailedError(err, restoreErr)
			}
			return nil, err
		}
		if !needsRetry {
			return results, nil
		}
		// New devices were discovered; loop back to step 1.
	}

	// Per spec: retry limit exceeded.
	maxRetriesErr := NewMaxRetriesExceededError(userID, m.config.MaxSendRetries)
	if restoreErr := m.restoreUserRecord(userID, snapshot); restoreErr != nil {
		return nil, NewRestoreFailedError(maxRetriesErr, restoreErr)
	}
	return nil, maxRetriesErr
}

// sendAttempt performs one iteration of the send loop. It returns the results,
// a flag indicating whether a retry is needed (new devices discovered), and
// any error.
func (m *Manager) sendAttempt(
	userID string,
	plaintext []byte,
	encrypt EncryptFunc,
	sendToServer SendToServerFunc,
) (map[uint32][]byte, bool, error) {
	now := m.clock()

	// Step 1: Look up UserRecord.
	userRecord, loadErr := m.store.LoadUserRecord(userID)
	if loadErr != nil {
		return nil, false, loadErr
	}
	if userRecord != nil && userRecord.IsStaleExpired(m.config, now) {
		m.store.DeleteUserRecord(userID)
		userRecord = nil
	}

	if userRecord == nil {
		if err := m.checkMaxUsers(userID); err != nil {
			return nil, false, err
		}
		userRecord = NewUserRecord(userID)
		if storeErr := m.store.StoreUserRecord(userID, userRecord); storeErr != nil {
			return nil, false, storeErr
		}
	}

	// Step 2: Encrypt for each non-stale device with an active, non-expired session.
	results := make(map[uint32][]byte)
	for _, deviceID := range userRecord.DeviceIDs() {
		device := userRecord.GetDevice(deviceID)
		if device == nil || device.IsStale() {
			continue
		}

		// Skip self-device.
		if m.isSelfDevice(userID, deviceID) {
			continue
		}

		session, err := m.prepForEncryptingLocked(userID, deviceID, nil)
		if err != nil {
			return nil, false, err
		}

		ciphertext, err := encrypt(session, plaintext)
		if err != nil {
			return nil, false, &SesameError{
				Kind:    ErrorKindNoActiveSession,
				Message: "encryption failed",
				Cause:   err,
			}
		}
		session.RecordSend(now)
		results[deviceID] = ciphertext
	}

	// Step 3: Send to server.
	resp, err := sendToServer(userID, results)
	if err != nil {
		return nil, false, &SesameError{
			Kind:    ErrorKindNoActiveSession,
			Message: "server communication failed",
			Cause:   err,
		}
	}

	// Step 4-5: Process server response.
	if !resp.UserExists {
		// User doesn't exist on server; mark stale.
		ur, loadErr := m.store.LoadUserRecord(userID)
		if loadErr != nil {
			return nil, false, loadErr
		}
		if ur != nil {
			ur.MarkStale(now)
			if storeErr := m.store.StoreUserRecord(userID, ur); storeErr != nil {
				return nil, false, storeErr
			}
		}
		return nil, false, NewUserNotFoundError(userID)
	}

	// Mark old devices as stale.
	for _, oldDeviceID := range resp.OldDevices {
		ur, loadErr := m.store.LoadUserRecord(userID)
		if loadErr != nil {
			return nil, false, loadErr
		}
		if ur != nil {
			device := ur.GetDevice(oldDeviceID)
			if device != nil && !device.IsStale() {
				device.MarkStale(now)
			}
			if storeErr := m.store.StoreUserRecord(userID, ur); storeErr != nil {
				return nil, false, storeErr
			}
		}
	}

	// Step 6-7: PrepForEncrypting and encrypt for new devices.
	if len(resp.NewDevices) == 0 {
		// No new devices; done.
		if resp.Accepted {
			return results, false, nil
		}
		// Server did not accept but reported no new devices.
		return results, false, nil
	}

	for newDeviceID, identKey := range resp.NewDevices {
		// Skip self-device.
		if m.isSelfDevice(userID, newDeviceID) {
			continue
		}

		session, err := m.prepForEncryptingLocked(userID, newDeviceID, identKey)
		if err != nil {
			return nil, false, err
		}

		ciphertext, err := encrypt(session, plaintext)
		if err != nil {
			return nil, false, &SesameError{
				Kind:    ErrorKindNoActiveSession,
				Message: "encryption failed for new device",
				Cause:   err,
			}
		}
		session.RecordSend(now)
		results[newDeviceID] = ciphertext
	}

	// Step 8: Need to restart since new devices were discovered.
	return results, true, nil
}

// snapshotUserRecord creates a deep copy of the user record for rollback.
// Returns nil if no record exists.
func (m *Manager) snapshotUserRecord(userID string) (*UserRecord, error) {
	existing, loadErr := m.store.LoadUserRecord(userID)
	if loadErr != nil {
		return nil, loadErr
	}
	if existing == nil {
		return nil, nil
	}
	return existing.Clone()
}

// restoreUserRecord restores the user record from a snapshot, or deletes
// it if the snapshot is nil (meaning no record existed before).
// Returns an error if StoreUserRecord fails during the restore.
func (m *Manager) restoreUserRecord(userID string, snapshot *UserRecord) error {
	if snapshot == nil {
		m.store.DeleteUserRecord(userID)
		return nil
	}
	return m.store.StoreUserRecord(userID, snapshot)
}

// identityKeysEqual compares two identity keys for equality using
// constant-time comparison to prevent timing side-channel attacks.
func identityKeysEqual(a, b *identity.Key) bool {
	if a == nil || b == nil {
		return a == b
	}
	aBytes := a.Serialize()
	bBytes := b.Serialize()
	return subtle.ConstantTimeCompare(aBytes, bBytes) == 1
}

// checkMaxUsers returns an error if storing a new user would exceed the
// MaxUsers limit. It only counts against the limit when the user does not
// already exist in the store.
func (m *Manager) checkMaxUsers(userID string) error {
	if m.config.MaxUsers <= 0 {
		return nil
	}
	if m.store.ContainsUserRecord(userID) {
		return nil
	}
	userIDs := m.store.AllUserIDs()
	if len(userIDs) >= m.config.MaxUsers {
		return NewMaxUsersExceededError(m.config.MaxUsers)
	}
	return nil
}
