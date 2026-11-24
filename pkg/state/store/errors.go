package store

import (
	"encoding/hex"
	"fmt"
)

// ErrStoreIO wraps a storage backend failure reading or writing records.
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

// ErrStoreNotFound indicates a missing record; Load may also return (nil, nil).
type ErrStoreNotFound struct {
	Op string
	ID interface{}
}

func (e *ErrStoreNotFound) Error() string {
	return fmt.Sprintf("store: %s: record not found: %v", e.Op, e.ID)
}

// ErrLastResortReplay is returned by MarkKyberPreKeyUsed when a last-resort pre-key triple is presented again; implementations must return it or wrap it.
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
