package store

import (
	"encoding/hex"
	"fmt"
)

// ErrStoreIO indicates a storage backend I/O failure when reading or writing
// session, identity, or pre-key records. It wraps the underlying error so
// callers can use errors.Is / errors.As for diagnosis.
//
// Mirrors the storage-layer error semantics from
// rust/protocol/src/storage/traits.rs where every store method returns
// Result<T, SignalProtocolError>.
type ErrStoreIO struct {
	Op  string
	Err error
}

func (e *ErrStoreIO) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("store: %s: %v", e.Op, e.Err)
	}
	return fmt.Sprintf("store: %s: I/O error", e.Op)
}

func (e *ErrStoreIO) Unwrap() error { return e.Err }

// ErrStoreNotFound indicates that a record was not found in the store.
// Callers that need to distinguish "not found" from "I/O failure" should
// use errors.As to check for this type; a (nil, nil) return from Load
// methods also signals not-found for backward-compatible callers.
type ErrStoreNotFound struct {
	Op string
	ID interface{}
}

func (e *ErrStoreNotFound) Error() string {
	return fmt.Sprintf("store: %s: record not found: %v", e.Op, e.ID)
}

// ErrLastResortReplay is returned by KyberPreKey.MarkKyberPreKeyUsed when a
// last-resort Kyber pre-key is presented with the same
// (kyberPreKeyID, signedPreKeyID, baseKey) triple as a previous call,
// indicating a replay attack.
//
// Implementations of KyberPreKeyStore.MarkKyberPreKeyUsed MUST return this
// error (or a type that wraps it) when last-resort replay is detected.
// Mirrors the intent of rust/protocol/src/storage/traits.rs:131-134.
type ErrLastResortReplay struct {
	KyberPreKeyID  uint32
	SignedPreKeyID uint32
	// BaseKeyHex is the hex-encoded public base key for diagnostic messages.
	BaseKeyHex string
}

// NewErrLastResortReplay creates an ErrLastResortReplay. baseKey may be nil.
func NewErrLastResortReplay(kyberPreKeyID, signedPreKeyID uint32, baseKey []byte) *ErrLastResortReplay {
	return &ErrLastResortReplay{
		KyberPreKeyID:  kyberPreKeyID,
		SignedPreKeyID: signedPreKeyID,
		BaseKeyHex:     hex.EncodeToString(baseKey),
	}
}

func (e *ErrLastResortReplay) Error() string {
	return fmt.Sprintf(
		"store: last-resort Kyber pre-key replay detected: kyberPreKeyID=%d signedPreKeyID=%d baseKey=%s",
		e.KyberPreKeyID, e.SignedPreKeyID, e.BaseKeyHex,
	)
}
