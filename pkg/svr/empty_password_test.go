package svr

import (
	"errors"
	"testing"
)

// TestConstructors_RefuseEmptyPassword checks that a nil or empty password
// is refused with ErrEmptyPIN before any derivation, so HKDF never runs on
// empty input key material.
func TestConstructors_RefuseEmptyPassword(t *testing.T) {
	ids := []uint64{1, 2}
	for name, pw := range map[string][]byte{"nil": nil, "empty": {}} {
		b, err := NewOPRFBackup4(ids, pw, 10)
		if !errors.Is(err, ErrEmptyPIN) || b != nil {
			t.Errorf("backup, %s password: want ErrEmptyPIN, got %v, %v", name, b, err)
		}
		r, err := NewRestore1(ids, pw)
		if !errors.Is(err, ErrEmptyPIN) || r != nil {
			t.Errorf("restore, %s password: want ErrEmptyPIN, got %v, %v", name, r, err)
		}
	}
}
