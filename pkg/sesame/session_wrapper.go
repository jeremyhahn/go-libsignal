package sesame

import (
	"crypto/subtle"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// SessionWrapper adds Sesame lifecycle timestamps, read and written atomically, to a session record.
type SessionWrapper struct {
	session     *record.Session
	identityKey *identity.Key
	lastSend    atomic.Value // stores time.Time
	lastReceive atomic.Value // stores time.Time
	createdAt   time.Time
}

// NewSessionWrapper creates a new SessionWrapper around the given session record.
// The creation time is set to the provided now timestamp. The identityKey may be
// nil if the remote identity key is not yet known.
func NewSessionWrapper(session *record.Session, identityKey *identity.Key, now time.Time) *SessionWrapper {
	sw := &SessionWrapper{
		session:     session,
		identityKey: identityKey,
		createdAt:   now,
	}
	sw.lastSend.Store(time.Time{})
	sw.lastReceive.Store(time.Time{})
	return sw
}

// Session returns the underlying Signal Protocol session record.
func (sw *SessionWrapper) Session() *record.Session {
	return sw.session
}

// IdentityKey returns the remote identity key associated with this session,
// or nil if no identity key was provided at creation time.
func (sw *SessionWrapper) IdentityKey() *identity.Key {
	return sw.identityKey
}

// HasIdentityKeyChanged returns true if the provided identity key differs
// from the session's stored identity key. Returns false if either key is nil,
// since a nil key indicates the identity is unknown and comparison is not possible.
func (sw *SessionWrapper) HasIdentityKeyChanged(other *identity.Key) bool {
	if sw.identityKey == nil || other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(sw.identityKey.Serialize(), other.Serialize()) != 1
}

// LastSend returns the timestamp of the last message sent using this session.
func (sw *SessionWrapper) LastSend() time.Time {
	val := sw.lastSend.Load()
	if val == nil {
		return time.Time{}
	}
	return val.(time.Time)
}

// LastReceive returns the timestamp of the last message received using this session.
func (sw *SessionWrapper) LastReceive() time.Time {
	val := sw.lastReceive.Load()
	if val == nil {
		return time.Time{}
	}
	return val.(time.Time)
}

// CreatedAt returns the timestamp when this session wrapper was created.
func (sw *SessionWrapper) CreatedAt() time.Time {
	return sw.createdAt
}

// RecordSend updates the last send timestamp to the given time.
func (sw *SessionWrapper) RecordSend(now time.Time) {
	sw.lastSend.Store(now)
}

// RecordReceive updates the last receive timestamp to the given time.
func (sw *SessionWrapper) RecordReceive(now time.Time) {
	sw.lastReceive.Store(now)
}

// IsSendExpired reports whether MAXSEND has passed since creation, inclusive (Sesame §4.2).
func (sw *SessionWrapper) IsSendExpired(config *Config, now time.Time) bool {
	return now.Sub(sw.createdAt) >= config.MaxSend
}

// IsRecvExpired reports whether MAXRECV has passed since creation, inclusive (Sesame §4.2).
func (sw *SessionWrapper) IsRecvExpired(config *Config, now time.Time) bool {
	return now.Sub(sw.createdAt) >= config.MaxRecv
}

// Clone creates a deep copy of the SessionWrapper. The underlying session
// record is deep-copied so mutations to the clone do not affect the original.
// Returns an error if the session state cannot be cloned.
func (sw *SessionWrapper) Clone() (*SessionWrapper, error) {
	sessionCopy, err := sw.session.Copy()
	if err != nil {
		return nil, err
	}
	cloned := &SessionWrapper{
		session:     sessionCopy,
		identityKey: sw.identityKey,
		createdAt:   sw.createdAt,
	}
	cloned.lastSend.Store(sw.LastSend())
	cloned.lastReceive.Store(sw.LastReceive())
	return cloned, nil
}
