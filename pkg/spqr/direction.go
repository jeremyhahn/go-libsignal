package spqr

import "fmt"

// Direction indicates which party initiated the session,
// determining how send and receive chain keys are assigned.
type Direction uint8

const (
	// DirectionA2B indicates party A initiated the session with party B.
	DirectionA2B Direction = iota
	// DirectionB2A indicates party B initiated the session with party A.
	DirectionB2A
)

// String returns a human-readable representation of the direction.
func (d Direction) String() string {
	switch d {
	case DirectionA2B:
		return "A2B"
	case DirectionB2A:
		return "B2A"
	default:
		return "unknown"
	}
}

// Version is the SPQR protocol version negotiated at session setup.
type Version uint8

const (
	// VersionV0 indicates PQR is disabled (fallback for older clients).
	VersionV0 Version = 0
	// VersionV1 indicates PQR is enabled.
	VersionV1 Version = 1
)

// String returns a human-readable representation of the version.
func (v Version) String() string {
	switch v {
	case VersionV0:
		return "V0"
	case VersionV1:
		return "V1"
	default:
		return fmt.Sprintf("unknown(%d)", v)
	}
}

// CurrentVersion is the negotiation state of a serialized SPQR state (Rust spqr::CurrentVersion).
type CurrentVersion struct {
	// Complete is true when negotiation has finished.
	// When false, Version and MinVersion describe the pending negotiation.
	Complete bool
	// Version is the resolved or pending protocol version.
	Version Version
	// MinVersion is the minimum acceptable version during pending negotiation.
	// Undefined (zero) when Complete is true.
	MinVersion Version
}

// CurrentVersionOf returns the negotiation state of serialized SPQR state without full deserialization; an empty state is NegotiationComplete(V0).
func CurrentVersionOf(serializedState []byte) (CurrentVersion, error) {
	s, err := Deserialize(serializedState)
	if err != nil {
		return CurrentVersion{}, err
	}
	defer s.Zeroize()

	if s.negotiation == negotiationPending {
		return CurrentVersion{
			Complete:   false,
			Version:    s.version,
			MinVersion: s.minVersion,
		}, nil
	}
	return CurrentVersion{
		Complete: true,
		Version:  s.version,
	}, nil
}

// Params holds the parameters for an initial SPQR state with version negotiation.
type Params struct {
	// AuthKey is the 32-byte initial PQR key from X3DH key agreement.
	AuthKey []byte
	// Version is the requested protocol version (typically VersionV1).
	Version Version
	// Direction determines the assignment of send/receive chain keys.
	Direction Direction
	// MinVersion is the minimum acceptable version. Set to VersionV0 to allow
	// fallback to PQR-disabled mode when the remote peer does not support PQR.
	MinVersion Version
	// MaxJump is the maximum forward jump allowed in the receive counter.
	// Use maxJump (25000) for normal sessions, math.MaxUint32 for self-sessions.
	MaxJump uint32
	// MaxOOOKeys is the maximum number of out-of-order message keys to retain.
	// Use maxSkippedKeys (2000) as the default.
	MaxOOOKeys uint32
}
