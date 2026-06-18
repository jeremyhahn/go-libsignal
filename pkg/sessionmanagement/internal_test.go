package sessionmanagement

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
)

// canonicalUUID is a well-formed bare-UUID ACI name accepted by
// ServiceIdFromServiceIdString.
const canonicalUUID = "550e8400-e29b-41d4-a716-446655440000"

// canonicalPNI is a well-formed PNI name accepted by ServiceIdFromServiceIdString.
const canonicalPNI = "PNI:550e8400-e29b-41d4-a716-446655440001"

// canonicalACIPrefix is the legacy "ACI:<uuid>" form accepted by the lenient parser.
const canonicalACIPrefix = "ACI:550e8400-e29b-41d4-a716-446655440002"

// TestEffectiveLocalAddress_BothCanonical verifies that two canonical-UUID
// addresses yield the local address (bound path enabled).
func TestEffectiveLocalAddress_BothCanonical(t *testing.T) {
	local := protocol.NewSignalAddress(canonicalUUID, 1)
	remote := protocol.NewSignalAddress(canonicalUUID, 2)
	got := effectiveLocalAddress(local, remote)
	if got != local {
		t.Errorf("expected local address returned for both-canonical pair, got %v", got)
	}
}

// TestEffectiveLocalAddress_LocalNil verifies that a nil local address yields
// nil (unbound path).
func TestEffectiveLocalAddress_LocalNil(t *testing.T) {
	remote := protocol.NewSignalAddress(canonicalUUID, 1)
	if got := effectiveLocalAddress(nil, remote); got != nil {
		t.Errorf("expected nil for nil local, got %v", got)
	}
}

// TestEffectiveLocalAddress_RemoteNil verifies that a nil remote address
// yields nil (unbound path).
func TestEffectiveLocalAddress_RemoteNil(t *testing.T) {
	local := protocol.NewSignalAddress(canonicalUUID, 1)
	if got := effectiveLocalAddress(local, nil); got != nil {
		t.Errorf("expected nil for nil remote, got %v", got)
	}
}

// TestEffectiveLocalAddress_NonCanonicalLocal verifies that a phone-number
// local address yields nil even when remote is canonical.
func TestEffectiveLocalAddress_NonCanonicalLocal(t *testing.T) {
	local := protocol.NewSignalAddress("+15555550100", 1)
	remote := protocol.NewSignalAddress(canonicalUUID, 2)
	if got := effectiveLocalAddress(local, remote); got != nil {
		t.Errorf("expected nil for non-canonical local, got %v", got)
	}
}

// TestEffectiveLocalAddress_NonCanonicalRemote verifies that a phone-number
// remote address yields nil even when local is canonical.
func TestEffectiveLocalAddress_NonCanonicalRemote(t *testing.T) {
	local := protocol.NewSignalAddress(canonicalUUID, 1)
	remote := protocol.NewSignalAddress("+15555550100", 2)
	if got := effectiveLocalAddress(local, remote); got != nil {
		t.Errorf("expected nil for non-canonical remote, got %v", got)
	}
}

// TestEffectiveLocalAddress_BothPhoneNumbers verifies that two phone-number
// addresses yield nil (unbound path).
func TestEffectiveLocalAddress_BothPhoneNumbers(t *testing.T) {
	local := protocol.NewSignalAddress("+15555550100", 1)
	remote := protocol.NewSignalAddress("+15555550101", 2)
	if got := effectiveLocalAddress(local, remote); got != nil {
		t.Errorf("expected nil for both phone-number addresses, got %v", got)
	}
}

// TestEffectiveLocalAddress_PNI verifies that PNI-prefixed names are canonical.
func TestEffectiveLocalAddress_PNI(t *testing.T) {
	local := protocol.NewSignalAddress(canonicalPNI, 1)
	remote := protocol.NewSignalAddress(canonicalPNI, 2)
	got := effectiveLocalAddress(local, remote)
	if got != local {
		t.Errorf("expected local returned for both-PNI pair, got %v", got)
	}
}

// TestEffectiveLocalAddress_ACIPrefix verifies that the legacy "ACI:<uuid>"
// form is accepted as canonical (lenient parser).
func TestEffectiveLocalAddress_ACIPrefix(t *testing.T) {
	local := protocol.NewSignalAddress(canonicalACIPrefix, 1)
	remote := protocol.NewSignalAddress(canonicalACIPrefix, 2)
	got := effectiveLocalAddress(local, remote)
	if got != local {
		t.Errorf("expected local returned for both-ACI-prefix pair, got %v", got)
	}
}

// unknownCiphertextMessage is a minimal CiphertextMessage implementation that
// is not one of the three concrete types recognized by messageKind.
type unknownCiphertextMessage struct{}

func (u *unknownCiphertextMessage) Serialize() ([]byte, error) { return nil, errors.New("mock") }
func (u *unknownCiphertextMessage) Type() uint32               { return 0xFF }

// TestMessageKind_Nil verifies the nil guard in messageKind.
func TestMessageKind_Nil(t *testing.T) {
	kind := messageKind(nil)
	if kind != "" {
		t.Errorf("messageKind(nil) = %q, want %q", kind, "")
	}
}

// TestMessageKind_Unknown verifies the default/unknown branch for an
// unrecognized CiphertextMessage implementation.
func TestMessageKind_Unknown(t *testing.T) {
	kind := messageKind(&unknownCiphertextMessage{})
	if kind != "unknown" {
		t.Errorf("messageKind(unknown) = %q, want %q", kind, "unknown")
	}
}

// TestMessageKind_AllKnownTypes verifies that each known type returns the
// expected label (regression guard).
func TestMessageKind_AllKnownTypes(t *testing.T) {
	tests := []struct {
		msg  protocol.CiphertextMessage
		want string
	}{
		{&protocol.PlaintextContent{}, "PlaintextContent"},
	}
	for _, tc := range tests {
		if got := messageKind(tc.msg); got != tc.want {
			t.Errorf("messageKind(%T) = %q, want %q", tc.msg, got, tc.want)
		}
	}
}
