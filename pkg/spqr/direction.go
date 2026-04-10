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

// Version represents the SPQR protocol version for version negotiation.
// During session setup, the parties negotiate whether PQR is enabled.
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

// Params holds the parameters for creating an initial SPQR state with
// version negotiation support.
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
