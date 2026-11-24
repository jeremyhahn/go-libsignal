package record

import (
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

// maxUnacknowledgedSessionAge is the maximum age of an unacknowledged session
// before it is considered stale. Matches Rust's consts::MAX_UNACKNOWLEDGED_SESSION_AGE
// (60 * 60 * 24 * 30 seconds = 30 days).
const maxUnacknowledgedSessionAge = 30 * 24 * time.Hour

// SessionUsabilityRequirements are bitflags a usable session must meet beyond having a sender chain.
type SessionUsabilityRequirements uint32

const (
	// SessionRequireNotStale requires an incoming or acknowledged session, or one at most 30 days old.
	SessionRequireNotStale SessionUsabilityRequirements = 1 << iota

	// SessionRequireEstablishedWithPqxdh requires a PQXDH session, acknowledged or not.
	SessionRequireEstablishedWithPqxdh

	// SessionRequireSpqr requires SPQR; an unacknowledged session may lose it if the peer downgrades, so use it only when downgrades are rejected.
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

// HasUsableSenderChain reports whether the state has a sender chain meeting every requirement in req, as Rust has_usable_sender_chain does.
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
