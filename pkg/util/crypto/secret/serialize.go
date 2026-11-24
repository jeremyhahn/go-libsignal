package secret

import "encoding/json"

// NewValue creates a Secret held by value, for use as a struct field that
// encoding/json decodes into. A pointer field cannot be used there: when JSON
// supersedes an earlier value with null, encoding/json sets the pointer to nil
// without calling UnmarshalJSON, abandoning the guarded allocation it already
// made. A value field always routes the decode through UnmarshalJSON, so the
// superseded material is destroyed.
//
// The zero Secret means "no material present", which is what an empty input
// yields — guarded memory cannot be allocated with zero length. As with New,
// the source slice is zeroized as part of the move into guarded memory.
func NewValue(data []byte) (Secret, error) {
	if len(data) == 0 {
		return Secret{}, nil
	}
	guarded, err := New(data)
	if err != nil {
		return Secret{}, err
	}
	return *guarded, nil
}

// NewOptional creates a Secret from key material that may legitimately be
// absent. It returns (nil, nil) when data is empty, because guarded memory
// cannot be allocated with zero length; callers treat a nil *Secret as
// "no material present".
//
// Use NewValue instead for a field that encoding/json decodes into.
//
// As with New, the source slice is zeroized as part of the move into guarded
// memory.
func NewOptional(data []byte) (*Secret, error) {
	if len(data) == 0 {
		return nil, nil
	}
	return New(data)
}

// FromSecret converts a Secret held by pointer into one held by value, taking
// ownership of the guarded material: the caller must not use the pointer
// afterwards. A nil pointer yields the zero Secret, which holds no material.
//
// This is the bridge from the guarded types used by the live key material
// (which hand out *Secret) to the structure fields that cross the storage
// boundary, so key material can move between the two without transiting the
// Go heap.
func FromSecret(s *Secret) Secret {
	if s == nil {
		return Secret{}
	}
	return *s
}

// IsZero reports whether the secret holds no material, which is what the
// `json:",omitzero"` tag option consults to decide whether to write the field
// at all.
//
// It exists so that a field carrying `omitempty` as a []byte keeps being
// omitted after it becomes a Secret. `omitempty` looks only at a small set of
// built-in kinds and silently does nothing to a struct, so a straight
// conversion would start writing `"Field":null` where the []byte wrote
// nothing — a change to the persisted layout. `omitzero` plus this method
// reproduces the old behaviour exactly: absent when there are no bytes,
// present otherwise.
//
// The receiver is a value for the same reason MarshalJSON's is: the field is
// held by value and is not addressable when its struct is marshaled.
func (s Secret) IsZero() bool {
	return s.Size() == 0
}

// MarshalJSON encodes the secret exactly as encoding/json encodes a []byte:
// a base64 string, or null when there is no material. This keeps persisted
// state byte-identical to the plain []byte representation it replaced.
//
// The receiver is a value so that a Secret held by value in a struct still
// encodes its material when that struct is marshaled without being
// addressable; a pointer receiver would silently emit an empty object.
//
// Marshaling necessarily copies the plaintext into the unguarded JSON output
// buffer. It exists for the persisted-state structures in pkg/state/record,
// whose whole purpose is to cross the storage boundary; the plaintext window
// is bounded by the caller destroying the structure after serialization.
func (s Secret) MarshalJSON() ([]byte, error) {
	if s.IsDestroyed() {
		return []byte("null"), nil
	}
	var out []byte
	err := s.WithBytes(func(b []byte) error {
		var marshalErr error
		out, marshalErr = json.Marshal(b)
		return marshalErr
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// UnmarshalJSON decodes a base64 string (or null) into freshly allocated
// guarded memory. A null or empty value yields a secret holding no material,
// whose WithBytes view is nil.
//
// Decoding over a secret that already holds material destroys that material:
// encoding/json reuses an existing pointer field, so abandoning the old buffer
// would strand a locked allocation on every decode. The existing material is
// left untouched if the decode fails.
func (s *Secret) UnmarshalJSON(data []byte) error {
	var raw []byte
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		s.Destroy()
		s.enc = nil
		return nil
	}
	loaded, err := New(raw)
	if err != nil {
		return err
	}
	s.Destroy()
	s.enc = loaded.enc
	return nil
}
