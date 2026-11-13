package record

import (
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

// maxUnacknowledgedSessionAge is the maximum age of an unacknowledged session
// before it is considered stale. Matches Rust's consts::MAX_UNACKNOWLEDGED_SESSION_AGE
// (60 * 60 * 24 * 30 seconds = 30 days).
const maxUnacknowledgedSessionAge = 30 * 24 * time.Hour

// SessionUsabilityRequirements is a bitflag type that specifies which properties
// a session must satisfy to be considered usable. It mirrors Rust's
// bitflags! SessionUsabilityRequirements struct in libsignal-protocol.
//
// Use bitwise OR to combine multiple requirements. Zero value means no
// requirements beyond the presence of a sender chain.
type SessionUsabilityRequirements uint32

const (
	// SessionRequireNotStale requires that the session is not stale.
	//
	// A non-stale session is one of the following:
	//   - "incoming", i.e. started by the peer (no pending pre-key)
	//   - "acknowledged", i.e. started locally but received a response
	//   - no more than 30 days old (matching Rust's MAX_UNACKNOWLEDGED_SESSION_AGE)
	SessionRequireNotStale SessionUsabilityRequirements = 1 << iota

	// SessionRequireEstablishedWithPqxdh requires that the session was established
	// using PQXDH (version > PreKyberVersion) rather than X3DH/X4DH.
	//
	// This includes unacknowledged sessions that are using PQXDH, since if they
	// get a response, the peer is confirmed to be using PQXDH as well.
	SessionRequireEstablishedWithPqxdh

	// SessionRequireSpqr requires that the session is using SPQR (post-quantum ratchet).
	//
	// Warning: This allows unacknowledged sessions that include SPQR in their PreKey
	// messages. If the peer downgrades the session and the local client allows it,
	// a session previously considered "usable" can become "not usable" upon receiving
	// a response. Only use this flag when future downgrades will also be rejected.
	SessionRequireSpqr
)

// SessionRequirementsAll combines all defined requirement flags. It corresponds
// to Rust's SessionUsabilityRequirements::all().
const SessionRequirementsAll = SessionRequireNotStale | SessionRequireEstablishedWithPqxdh | SessionRequireSpqr

// Contains reports whether all bits in flag are set in r.
// It mirrors Rust's bitflags::Flags::contains method.
func (r SessionUsabilityRequirements) Contains(flag SessionUsabilityRequirements) bool {
	return r&flag == flag
}

// HasUsableSenderChain reports whether the session state has a usable sender
// chain that satisfies all requirements in req.
//
// It mirrors Rust's SessionState::has_usable_sender_chain exactly:
//   - If there is no sender chain, returns false.
//   - If SessionRequireNotStale is set: an unacknowledged session older than
//     maxUnacknowledgedSessionAge is considered stale and returns false.
//   - If SessionRequireEstablishedWithPqxdh is set: sessions at or below
//     protocol.PreKyberVersion (3) return false.
//   - If SessionRequireSpqr is set: sessions without PQ ratchet state return false.
func (s *State) HasUsableSenderChain(now time.Time, req SessionUsabilityRequirements) (bool, error) {
	if s.senderChain == nil {
		return false, nil
	}
	if req.Contains(SessionRequireNotStale) {
		if s.pendingPreKey != nil {
			creationTime := time.Unix(int64(s.pendingPreKey.timestamp), 0)
			if creationTime.Add(maxUnacknowledgedSessionAge).Before(now) {
				return false, nil
			}
		}
	}
	if req.Contains(SessionRequireEstablishedWithPqxdh) {
		if s.Version() <= protocol.PreKyberVersion {
			return false, nil
		}
	}
	if req.Contains(SessionRequireSpqr) {
		if secretLen(s.pqRatchetState) == 0 {
			return false, nil
		}
	}
	return true, nil
}

// HasUsableSenderChain reports whether the current session has a usable sender
// chain that satisfies all requirements in req. Returns false when there is no
// current session. It mirrors Rust's SessionRecord::has_usable_sender_chain.
func (r *Session) HasUsableSenderChain(now time.Time, req SessionUsabilityRequirements) (bool, error) {
	if r.sessionState == nil {
		return false, nil
	}
	return r.sessionState.HasUsableSenderChain(now, req)
}
