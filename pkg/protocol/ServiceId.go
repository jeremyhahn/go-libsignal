package protocol

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// ServiceIdKind identifies the type of service ID.
type ServiceIdKind byte

const (
	// ServiceIdKindACI represents an Account Identity.
	ServiceIdKindACI ServiceIdKind = 0x00
	// ServiceIdKindPNI represents a Phone Number Identity.
	ServiceIdKindPNI ServiceIdKind = 0x01
)

// ServiceId is a unique identifier for a Signal user, either an ACI or PNI.
type ServiceId struct {
	kind ServiceIdKind
	uuid [16]byte
}

// NewServiceId creates a new ServiceId with the given kind and UUID bytes.
func NewServiceId(kind ServiceIdKind, uuid [16]byte) ServiceId {
	return ServiceId{kind: kind, uuid: uuid}
}

// ServiceIdFromString parses a UUID string into a ServiceId with the given kind.
// The UUID string may be in the standard 8-4-4-4-12 format or a plain 32-char hex string.
func ServiceIdFromString(kind ServiceIdKind, uuidStr string) (ServiceId, error) {
	cleaned := strings.ReplaceAll(uuidStr, "-", "")
	if len(cleaned) != 32 {
		return ServiceId{}, &ServiceIdParseError{Detail: fmt.Sprintf("invalid UUID string length: %d", len(cleaned))}
	}

	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return ServiceId{}, &ServiceIdParseError{Detail: "invalid UUID hex", Err: err}
	}

	var uuid [16]byte
	copy(uuid[:], b)
	return NewServiceId(kind, uuid), nil
}

// Kind returns the ServiceIdKind (ACI or PNI).
func (s ServiceId) Kind() ServiceIdKind {
	return s.kind
}

// UUID returns the raw 16-byte UUID.
func (s ServiceId) UUID() [16]byte {
	return s.uuid
}

// UUIDString formats the UUID as a standard string with dashes (8-4-4-4-12).
func (s ServiceId) UUIDString() string {
	h := hex.EncodeToString(s.uuid[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// String returns a human-readable representation: "ACI:<uuid>" or "PNI:<uuid>".
func (s ServiceId) String() string {
	prefix := "ACI"
	if s.kind == ServiceIdKindPNI {
		prefix = "PNI"
	}
	return prefix + ":" + s.UUIDString()
}

// FixedWidthBinary returns the 17-byte encoding: [kind_byte][16_uuid_bytes].
func (s ServiceId) FixedWidthBinary() [17]byte {
	var out [17]byte
	out[0] = byte(s.kind)
	copy(out[1:], s.uuid[:])
	return out
}

// ServiceIdFromFixedWidthBinary parses a 17-byte fixed-width binary representation.
func ServiceIdFromFixedWidthBinary(data [17]byte) (ServiceId, error) {
	kind := ServiceIdKind(data[0])
	if kind != ServiceIdKindACI && kind != ServiceIdKindPNI {
		return ServiceId{}, &ServiceIdParseError{Detail: fmt.Sprintf("unknown ServiceIdKind: 0x%02x", data[0])}
	}
	var uuid [16]byte
	copy(uuid[:], data[1:])
	return NewServiceId(kind, uuid), nil
}

// NewACI creates a new ACI ServiceId.
func NewACI(uuid [16]byte) ServiceId {
	return NewServiceId(ServiceIdKindACI, uuid)
}

// NewPNI creates a new PNI ServiceId.
func NewPNI(uuid [16]byte) ServiceId {
	return NewServiceId(ServiceIdKindPNI, uuid)
}
