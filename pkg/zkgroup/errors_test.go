package zkgroup

import (
	"errors"
	"testing"
)

func TestZkGroupVerificationFailure(t *testing.T) {
	t.Run("with context", func(t *testing.T) {
		err := &ZkGroupVerificationFailure{Context: "bad proof"}
		if err.Error() != "zkgroup: verification failure: bad proof" {
			t.Errorf("Error() = %q", err.Error())
		}
	})

	t.Run("without context", func(t *testing.T) {
		err := &ZkGroupVerificationFailure{}
		if err.Error() != ErrVerificationFailure.Error() {
			t.Errorf("Error() = %q, want %q", err.Error(), ErrVerificationFailure.Error())
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		err := &ZkGroupVerificationFailure{Context: "test"}
		if !errors.Is(err, ErrVerificationFailure) {
			t.Error("should unwrap to ErrVerificationFailure")
		}
	})
}

func TestZkGroupDeserializationFailure(t *testing.T) {
	t.Run("with type name", func(t *testing.T) {
		err := &ZkGroupDeserializationFailure{TypeName: "AuthCredential"}
		if err.Error() != "zkgroup: failed to deserialize AuthCredential" {
			t.Errorf("Error() = %q", err.Error())
		}
	})

	t.Run("without type name", func(t *testing.T) {
		err := &ZkGroupDeserializationFailure{}
		if err.Error() != ErrDeserializationFailure.Error() {
			t.Errorf("Error() = %q, want %q", err.Error(), ErrDeserializationFailure.Error())
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		err := &ZkGroupDeserializationFailure{TypeName: "test"}
		if !errors.Is(err, ErrDeserializationFailure) {
			t.Error("should unwrap to ErrDeserializationFailure")
		}
	})
}
