package store

import (
	"github.com/jeremyhahn/go-libsignal/pkg/groups/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

// SenderKey is the interface for storing and retrieving sender key records.
// Both methods return errors to match the Rust reference SenderKeyStore trait,
// which returns Result<()> and Result<Option<SenderKeyRecord>> respectively.
type SenderKey interface {
	StoreSenderKey(senderKeyName *protocol.SenderKeyName, keyRecord *record.SenderKey) error
	LoadSenderKey(senderKeyName *protocol.SenderKeyName) (*record.SenderKey, error)
}
