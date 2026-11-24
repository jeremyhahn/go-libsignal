package spqr

import "fmt"

// ErrSerialize is returned when serialization fails.
type ErrSerialize struct {
	Reason string
}

func (e *ErrSerialize) Error() string {
	return fmt.Sprintf("spqr: serialization failed: %s", e.Reason)
}

// ErrDeserialize is returned when deserialization fails.
type ErrDeserialize struct {
	Reason string
}

func (e *ErrDeserialize) Error() string {
	return fmt.Sprintf("spqr: deserialization failed: %s", e.Reason)
}

// Serialize encodes the SPQR state in Rust-compatible PqRatchetState proto format.
// Bytes produced by this method are byte-for-byte compatible with Rust libsignal's
// spqr::initial_state / spqr::send / spqr::recv output.
func (s *SPQR) Serialize() ([]byte, error) {
	b, err := MarshalStateProto(s)
	if err != nil {
		return nil, &ErrSerialize{Reason: err.Error()}
	}
	return b, nil
}

// Deserialize decodes Rust-compatible PqRatchetState proto bytes into a Go SPQR.
func Deserialize(data []byte) (*SPQR, error) {
	s, err := UnmarshalStateProto(data)
	if err != nil {
		return nil, &ErrDeserialize{Reason: err.Error()}
	}
	return s, nil
}
