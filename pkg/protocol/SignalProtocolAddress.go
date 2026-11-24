package protocol

import (
	"fmt"
)

// ADDRESS_SEPARATOR separates name and device ID in String(); "~" differs from Rust's "." but is display-only.
const ADDRESS_SEPARATOR = "~"

// NewSignalAddress returns a SignalAddress, or an error if deviceID is outside 1..127.
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

// String returns "name~deviceID" for display.
func (s *SignalAddress) String() string {
	return s.name + ADDRESS_SEPARATOR + fmt.Sprint(s.deviceID)
}

// IsCanonicalServiceIdAddress reports whether Name() parses as a ServiceId string, which enables address binding; nil returns false.
func IsCanonicalServiceIdAddress(addr *SignalAddress) bool {
	if addr == nil {
		return false
	}
	_, err := ServiceIdFromServiceIdString(addr.Name())
	return err == nil
}
