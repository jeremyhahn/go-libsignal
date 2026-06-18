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

// String returns the canonical service ID string representation.
// ACI prints as a bare hyphenated UUID (e.g. "abcd1234-…"). The "ACI:" prefix
// is never emitted. PNI prints as "PNI:<hyphenated-uuid>".
//
// Note: the ACI format changed from the legacy "ACI:<uuid>" prefixed form.
// Callers that persisted ServiceId strings under the old form must parse them
// through ServiceIdFromServiceIdString, which accepts both the legacy
// "ACI:<uuid>" prefix and the current bare-UUID form, before calling String().
//
// Mirrors Rust libsignal_core ServiceId::service_id_string at
// rust/core/src/address.rs:220-226.
func (s ServiceId) String() string {
	if s.kind == ServiceIdKindACI {
		return s.UUIDString()
	}
	return "PNI:" + s.UUIDString()
}

// FixedWidthBinary returns the 17-byte encoding: [kind_byte][16_uuid_bytes].
//
// Mirrors Rust libsignal_core's ServiceId::service_id_fixed_width_binary
// at rust/core/src/address.rs.
func (s ServiceId) FixedWidthBinary() [17]byte {
	var out [17]byte
	out[0] = byte(s.kind)
	copy(out[1:], s.uuid[:])
	return out
}

// ServiceIdBinary returns the variable-width binary encoding used by
// Rust libsignal_core's ServiceId::service_id_binary: 16 raw UUID bytes
// for an ACI, or 17 bytes ([0x01][16 UUID bytes]) for a PNI. This is the
// form HKDF info strings (e.g. backup_id derivation) concatenate.
//
// Mirrors rust/core/src/address.rs.
func (s ServiceId) ServiceIdBinary() []byte {
	if s.kind == ServiceIdKindACI {
		out := make([]byte, 16)
		copy(out, s.uuid[:])
		return out
	}
	out := make([]byte, 17)
	out[0] = byte(s.kind)
	copy(out[1:], s.uuid[:])
	return out
}

// ServiceIdFromBinary parses the variable-width binary encoding produced by
// ServiceIdBinary: 16 bytes → ACI (no prefix); 17 bytes → PNI (0x01 tag ||
// 16-byte UUID). A 17-byte buffer with kind byte 0x00 (ACI) is rejected
// because ACI is always encoded without a tag in this format.
//
// Returns ErrInvalidServiceIdLength if the buffer length is not 16 or 17.
// Returns a ServiceIdParseError if the kind byte is unknown or if a 17-byte
// buffer carries the ACI kind (non-canonical).
//
// Mirrors Rust libsignal_core ServiceId::parse_from_service_id_binary at
// rust/core/src/address.rs:230-245.
func ServiceIdFromBinary(data []byte) (ServiceId, error) {
	switch len(data) {
	case 16:
		var uuid [16]byte
		copy(uuid[:], data)
		return NewServiceId(ServiceIdKindACI, uuid), nil
	case 17:
		kind := ServiceIdKind(data[0])
		if kind == ServiceIdKindACI {
			// ACI is unmarked in the variable-width format; a 17-byte ACI is
			// non-canonical and rejected to match Rust behaviour.
			return ServiceId{}, ErrInvalidServiceIdLength
		}
		if kind != ServiceIdKindPNI {
			return ServiceId{}, &ServiceIdParseError{Detail: fmt.Sprintf("unknown ServiceIdKind: 0x%02x", data[0])}
		}
		var uuid [16]byte
		copy(uuid[:], data[1:])
		return NewServiceId(ServiceIdKindPNI, uuid), nil
	default:
		return ServiceId{}, ErrInvalidServiceIdLength
	}
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

// ServiceIdFromServiceIdString parses a Signal service ID string into a
// ServiceId. Accepted formats:
//   - Bare hyphenated UUID (8-4-4-4-12 form) → ACI (Rust canonical).
//   - "PNI:<hyphenated-uuid>" → PNI (Rust canonical).
//   - "ACI:<hyphenated-uuid>" → ACI (legacy Go form, accepted for backwards
//     compatibility with persisted output from older releases).
//
// Postel's law: lenient on input, strict on output. String() always emits the
// Rust-canonical bare UUID for ACI; the "ACI:" prefix is only accepted here,
// never produced. The prefix match is case-sensitive: "aci:<uuid>" is rejected.
//
// Rejected forms: un-hyphenated (32-char hex) UUID, lowercase "aci:" prefix,
// and any other unrecognised format. Returns ErrInvalidServiceIdString for all
// unrecognised inputs.
//
// Mirrors Rust libsignal_core ServiceId::parse_from_service_id_string at
// rust/core/src/address.rs:263-279.
func ServiceIdFromServiceIdString(s string) (ServiceId, error) {
	// Legacy Go form: "ACI:<uuid>" was emitted by older releases of this
	// package. Accept it leniently and parse the remainder as a bare UUID for
	// ACI. The prefix match is case-sensitive; "aci:" is not accepted.
	if rest, ok := strings.CutPrefix(s, "ACI:"); ok {
		return parseHyphenatedUUID(ServiceIdKindACI, rest)
	}
	if rest, ok := strings.CutPrefix(s, "PNI:"); ok {
		sid, err := parseHyphenatedUUID(ServiceIdKindPNI, rest)
		if err != nil {
			return ServiceId{}, err
		}
		return sid, nil
	}
	// Must be a bare hyphenated UUID (ACI).
	sid, err := parseHyphenatedUUID(ServiceIdKindACI, s)
	if err != nil {
		return ServiceId{}, err
	}
	return sid, nil
}

// parseHyphenatedUUID parses exactly a hyphenated UUID (8-4-4-4-12 form, 36
// characters) and returns a ServiceId with the given kind. It rejects
// un-hyphenated or otherwise malformed inputs.
func parseHyphenatedUUID(kind ServiceIdKind, s string) (ServiceId, error) {
	// Rust's try_parse_hyphenated only accepts the hyphenated form (length 36).
	const hyphenatedLen = 36
	if len(s) != hyphenatedLen {
		return ServiceId{}, ErrInvalidServiceIdString
	}
	// Verify hyphens at positions 8, 13, 18, 23.
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return ServiceId{}, ErrInvalidServiceIdString
	}
	cleaned := strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return ServiceId{}, ErrInvalidServiceIdString
	}
	var uuid [16]byte
	copy(uuid[:], b)
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
