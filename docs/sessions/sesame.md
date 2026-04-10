# Sesame Multi-Device Session Management

The `sesame` package implements the Sesame session management algorithm for the Signal Protocol. It coordinates session lifecycle across multiple users and devices, handling session creation, expiration, device list reconciliation, and routing of encrypt/decrypt operations.

## Data Model

Sesame organizes state into a three-level hierarchy:

```
UserRecord (keyed by userID)
  |- IdentityKey
  |- Stale flag + timestamp
  |- DeviceRecord (keyed by deviceID)
       |- IdentityKey
       |- Stale flag + timestamp
       |- ActiveSession (at most one)
       |- InactiveSessions (ordered list, max 40 by default)
            |- SessionWrapper
                 |- Signal Protocol session record
                 |- IdentityKey
                 |- CreatedAt, LastSend, LastReceive timestamps
```

A `UserRecord` holds all device records for a single remote user. Each `DeviceRecord` contains at most one active session and a list of inactive (previous) sessions. `SessionWrapper` decorates a Signal Protocol `record.Session` with lifecycle timestamps.

Per the Sesame specification, a device must not store a `DeviceRecord` for its own `DeviceID`. The `Manager` enforces this through the `WithLocalIdentity` option.

## Lifecycle Limits: MAXSEND and MAXRECV

Session expiration is driven by two duration-based limits, both measured from the session's creation time (not from last use):

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `MaxSend` | 30 days | Sessions older than this cannot encrypt |
| `MaxRecv` | 90 days | Sessions older than this may be deleted |
| `MaxLatency` | 14 days | Grace period before stale records are purged |

The specification requires `MaxRecv > MaxSend + 2*MaxLatency`. The `Config.Validate()` method checks this constraint.

When a session exceeds MAXSEND, it is deactivated (moved to the inactive list) and can no longer encrypt. It can still decrypt incoming messages until MAXRECV, at which point it is eligible for deletion. This asymmetry accounts for in-flight messages that were encrypted before the sender knew the session expired.

## Manager

`Manager` is the main entry point. It holds a `Store`, a `Config`, a `CreateSessionFunc` callback for establishing new sessions from prekey bundles, and an optional local identity for self-device exclusion.

```go
store := sesame.NewMemoryStore()
config := sesame.DefaultConfig()

manager := sesame.NewManager(store, config, createSessionFromBundle,
    sesame.WithLocalIdentity("alice", 1),
)
```

The `Manager` uses a `sync.RWMutex` internally. All public methods acquire the lock, so callers do not need external synchronization.

### PrepForEncrypting

`PrepForEncrypting` ensures a valid active session exists for a given user and device. It follows section 3.2 of the Sesame specification:

1. Delete any stale `DeviceRecord` entries unconditionally (the send path does not wait for `MaxLatency`)
2. Create or replace records as needed, including on identity key change
3. If no active session exists, call the `CreateSessionFunc` to establish one from a prekey bundle
4. Check MAXSEND on the active session. If expired, deactivate it and create a new session
5. Return the active `SessionWrapper`

If the active session's age exceeds `MaxSend`, `PrepForEncrypting` deactivates it and attempts to create a fresh session. If the new session cannot be created, it returns a `SendExpired` error.

### Send (Snapshot/Restore Rollback)

`Send` encrypts plaintext for a list of device IDs belonging to a single user. It follows section 3.3 of the specification, with snapshot/restore rollback on partial failure:

1. Snapshot the `UserRecord` via `Clone()` before any modifications
2. For each device: call `prepForEncryptingLocked`, then call the `EncryptFunc` callback
3. If any step fails, restore the snapshot (discard all changes) and return the error
4. On full success, persist the updated `UserRecord`

The snapshot uses `UserRecord.Clone()`, which deep-copies all device records and session wrappers. If `Clone()` fails, `Send` returns the clone error directly rather than proceeding without rollback guarantees.

### SendWithServerLoop

`SendWithServerLoop` implements the full 8-step iterative send process. It encrypts for all known devices, sends to the server via a `SendToServerFunc` callback, processes the server's device list response (marking old devices stale, establishing sessions for new devices), and retries if new devices were discovered. The loop is bounded by `MaxSendRetries` (default: 3).

The `ServerResponse` from the server includes:
- `Accepted`: whether the server accepted the messages
- `UserExists`: whether the user exists
- `OldDevices`: device IDs that are no longer registered
- `NewDevices`: map of new device IDs to identity keys

### Receive

`Receive` attempts to decrypt a ciphertext from a known user/device. It tries the active session first, then each inactive session in order. If an inactive session succeeds, it is promoted to active via `PromoteInactiveSession`. Promotion checks MAXSEND before completing, so an expired inactive session stays inactive even if it can decrypt.

### ReceiveNewSession

`ReceiveNewSession` handles initiation messages that establish a new session. The caller provides the `record.Session` created from processing the prekey message. The method attempts decryption first and only persists the new session if decryption succeeds.

### CleanupExpired

`CleanupExpired` iterates over all stored users and performs cascade cleanup:
- Removes stale users past `MaxLatency`
- Removes stale devices past `MaxLatency`
- Deactivates sessions past `MaxSend`, deletes sessions past `MaxRecv`
- Removes empty device records, then removes empty user records

Call this periodically as part of maintenance.

## Store Interface

```go
type Store interface {
    LoadUserRecord(userID string) (*UserRecord, error)
    StoreUserRecord(userID string, record *UserRecord) error
    DeleteUserRecord(userID string)
    ContainsUserRecord(userID string) bool
    AllUserIDs() []string
}
```

`LoadUserRecord` returns `(*UserRecord, error)`. A nil `UserRecord` with nil error means the user does not exist. A non-nil error means the record exists but could not be loaded (for example, a clone failure in `MemoryStore`).

`StoreUserRecord` returns an error to allow store implementations to report persistence or cloning failures.

### MemoryStore

`MemoryStore` is the provided in-memory implementation. It clones records on both load and store to prevent external mutation from corrupting stored state. This is what makes snapshot/restore rollback possible: mutations to a loaded record do not affect the stored copy until `StoreUserRecord` is called.

If cloning fails, `MemoryStore` returns a `StoreCloneFailed` error rather than falling back to a raw pointer, which would break rollback guarantees.

## Error Types

All errors are typed as `*SesameError` with a `Kind` field for programmatic matching via `errors.Is`:

| ErrorKind | Sentinel | When |
|-----------|----------|------|
| `ErrorKindStoreCloneFailed` | `ErrStoreCloneFailed` | Clone failed during store load/save |
| `ErrorKindSendExpired` | `ErrSendExpired` | Active session exceeded MAXSEND and new session creation failed |
| `ErrorKindNoActiveSession` | `ErrNoActiveSession` | No active session available, or encryption callback failed |
| `ErrorKindDecryptionFailed` | `ErrDecryptionFailed` | All sessions failed to decrypt |
| `ErrorKindSelfDevice` | `ErrSelfDevice` | Attempted to create session for the local device |
| `ErrorKindMaxDevicesExceeded` | `ErrMaxDevicesExceeded` | Per-user device limit reached (default: 20) |
| `ErrorKindMaxUsersExceeded` | `ErrMaxUsersExceeded` | Total user record limit reached (default: 1000) |
| `ErrorKindMaxRetriesExceeded` | `ErrMaxRetriesExceeded` | Send loop exceeded retry limit |
| `ErrorKindUserNotFound` | `ErrUserNotFound` | Server reported user does not exist |
| `ErrorKindInvalidConfig` | `ErrInvalidConfig` | Configuration fails validation |

Errors wrap a `Cause` field accessible via `errors.Unwrap()`.

## Identity Key Handling

Identity key comparison uses `crypto/subtle.ConstantTimeCompare` to prevent timing side-channel attacks. When `PrepForEncrypting` detects an identity key mismatch (either at the device or user level), it replaces the entire `UserRecord` and `DeviceRecord` with empty ones, discarding all existing sessions for that user.

## Configuration

```go
config := &sesame.Config{
    MaxSend:             30 * 24 * time.Hour,  // 30 days
    MaxRecv:             90 * 24 * time.Hour,  // 90 days
    MaxLatency:          14 * 24 * time.Hour,  // 14 days
    MaxInactiveSessions: 40,
    MaxSendRetries:      3,
    MaxDevicesPerUser:   20,
    MaxUsers:            1000,
}

if err := config.Validate(); err != nil {
    // handle invalid config
}
```

All duration values must be positive. `MaxRecv` must be greater than `MaxSend + 2*MaxLatency`.

## Files

| File | Contents |
|------|----------|
| `sesame/manager.go` | `Manager` type, `Send`, `Receive`, `PrepForEncrypting`, `SendWithServerLoop` |
| `sesame/store.go` | `Store` interface |
| `sesame/memory_store.go` | `MemoryStore` in-memory implementation |
| `sesame/config.go` | `Config` struct, defaults, validation |
| `sesame/session_wrapper.go` | `SessionWrapper` with lifecycle timestamps |
| `sesame/device_record.go` | `DeviceRecord` with active/inactive session management |
| `sesame/user_record.go` | `UserRecord` with device map and stale tracking |
| `sesame/errors.go` | Typed errors and sentinel values |
