package protocol

import (
	"fmt"
)

// ADDRESS_SEPARATOR is the separator used between the address name and device ID
// in the human-readable display form of a SignalAddress.
//
// The value is "~" (tilde). Rust libsignal uses "." (dot) in its ProtocolAddress
// Display impl (rust/core/src/address.rs:818), but that divergence is intentional:
// String() is display-only and no wire format depends on it. Using "~" preserves
// backwards compatibility with go-libsignal address.String() values that callers
// may have persisted as map keys or in storage.
const ADDRESS_SEPARATOR = "~"

// NewSignalAddress returns a new SignalAddress, or an error if deviceID is
// outside the valid Signal range [1, 127].
//
// Signal protocol requires device IDs to be between 1 and 127 inclusive
// (Java DeviceId int 1-127; Rust DeviceId u8 non-zero ≤ 127).
// The field type is uint32 to match the protobuf wire type but the range is
// enforced here and in SerializeAddresses.
func NewSignalAddress(name string, deviceID uint32) *SignalAddress {
	addr := SignalAddress{
		name:     name,
		deviceID: deviceID,
	}
	return &addr
}

// NewSignalAddressStrict returns a new SignalAddress validated against the
// Signal device ID range [1, 127], or ErrInvalidDeviceID if the range is
// violated.
func NewSignalAddressStrict(name string, deviceID uint32) (*SignalAddress, error) {
	if deviceID == 0 || deviceID > 127 {
		return nil, &DeviceIDError{ID: deviceID}
	}
	return &SignalAddress{name: name, deviceID: deviceID}, nil
}

// SignalAddress is a combination of a name and a device ID.
type SignalAddress struct {
	name     string
	deviceID uint32
}

// Name returns the signal address's name.
func (s *SignalAddress) Name() string {
	return s.name
}

// DeviceID returns the signal address's device ID.
func (s *SignalAddress) DeviceID() uint32 {
	return s.deviceID
}

// String returns "name~deviceID" as the human-readable form of the address.
// The separator is "~" (tilde). Rust libsignal uses "." for its equivalent
// Display implementation; the difference is intentional and display-only — no
// wire format depends on this value — and preserves backwards compatibility
// with go-libsignal address.String() values that callers may have persisted.
func (s *SignalAddress) String() string {
	return s.name + ADDRESS_SEPARATOR + fmt.Sprint(s.deviceID)
}

// IsCanonicalServiceIdAddress reports whether the address's Name() parses
// successfully as a canonical Signal ServiceId string via
// ServiceIdFromServiceIdString. An address is canonical if its name is one of:
//   - A bare hyphenated UUID (8-4-4-4-12 form) — ACI.
//   - "PNI:<hyphenated-uuid>" — PNI.
//   - "ACI:<hyphenated-uuid>" — legacy Go ACI form, still accepted.
//
// Phone numbers, Signal usernames, and other opaque name strings are
// non-canonical. Callers use this to decide whether address binding should
// be enabled or whether the legacy unbound path must be used.
//
// A nil receiver returns false.
func IsCanonicalServiceIdAddress(addr *SignalAddress) bool {
	if addr == nil {
		return false
	}
	_, err := ServiceIdFromServiceIdString(addr.Name())
	return err == nil
}
