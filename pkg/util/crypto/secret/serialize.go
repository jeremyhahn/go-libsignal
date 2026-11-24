package secret

import "encoding/json"

// NewValue creates a Secret held by value for a JSON-decoded field, so a superseding null still goes through UnmarshalJSON; empty data gives the zero Secret, and data is zeroized.
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

// NewOptional creates a Secret from data, or returns (nil, nil) when data is empty; data is zeroized. Use NewValue for JSON-decoded fields.
func NewOptional(data []byte) (*Secret, error) {
	if len(data) == 0 {
		return nil, nil
	}
	return New(data)
}

// FromSecret moves a *Secret into a value Secret, which takes ownership; nil gives the zero Secret.
func FromSecret(s *Secret) Secret {
	if s == nil {
		return Secret{}
	}
	return *s
}

// IsZero reports whether the secret holds no material, for the omitzero tag, which keeps the old omitempty []byte layout.
func (s Secret) IsZero() bool {
	return s.Size() == 0
}

// MarshalJSON encodes the secret as encoding/json encodes a []byte (base64, or null when empty); the output is plaintext, so destroy the structure after serializing.
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

// UnmarshalJSON decodes base64 or null into new guarded memory, destroying any existing material on success.
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
