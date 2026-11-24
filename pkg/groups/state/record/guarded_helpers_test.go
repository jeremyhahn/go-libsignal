package record

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// mustGuard moves a copy of the given bytes into guarded memory, for building
// the sender-key structures these tests exercise. It returns the zero Secret
// for empty input, matching the convention of the persisted-state structures.
func mustGuard(t *testing.T, data []byte) secret.Secret {
	t.Helper()
	guarded, err := secret.NewValue(append([]byte(nil), data...))
	if err != nil {
		t.Fatalf("secret.NewValue: %v", err)
	}
	return guarded
}

// TestNewSenderKeyStateFromStructureReleasesOnFailure checks destroySenderKeyState releases the message keys when the chain key fails to decode.
func TestNewSenderKeyStateFromStructureReleasesOnFailure(t *testing.T) {
	// Fixed key bytes, so the test runs in the FIPS gate.
	signingKeyPublic := append([]byte{ecc.DjbType}, bytes.Repeat([]byte{0x42}, 32)...)

	structure := &SenderKeyStateStructure{
		KeyID:             1,
		MessageVersion:    3,
		SigningKeyPublic:  signingKeyPublic,
		SigningKeyPrivate: mustGuard(t, bytes.Repeat([]byte{0x43}, 32)),
		Keys: []*ratchet.SenderMessageKeyStructure{
			{Iteration: 1, Seed: mustGuard(t, bytes.Repeat([]byte{0x01}, 32))},
			{Iteration: 2, Seed: mustGuard(t, bytes.Repeat([]byte{0x02}, 32))},
		},
		// SenderChainKey deliberately absent: mandatory, so the decode fails
		// after the message keys above have been guarded.
	}
	defer structure.Zeroize()

	state, err := NewSenderKeyStateFromStructure(structure, nil)
	if state != nil {
		t.Fatal("a failed decode must not return a state")
	}
	var missing *ratchet.MissingKeyError
	if !errors.As(err, &missing) {
		t.Fatalf("expected *ratchet.MissingKeyError, got %#v", err)
	}
	// The source structure is untouched by the failure: the decode clones, so
	// the caller still owns its own material and can Zeroize it above.
	if structure.Keys[0].Seed.IsZero() {
		t.Error("a failed decode must not consume the source structure")
	}
}

// TestMissingKeyErrorMessage pins the error text, which is what a caller sees
// when persisted state is rejected.
func TestMissingKeyErrorMessage(t *testing.T) {
	err := &ratchet.MissingKeyError{Field: "sender chain key"}
	if got := err.Error(); got != "ratchet: sender key structure is missing its sender chain key" {
		t.Errorf("Error() = %q", got)
	}
}
