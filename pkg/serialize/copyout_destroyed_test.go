//go:build !fips140only

package serialize

import (
	"bytes"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// destroyBeforeCopyOut makes target destroyed just before copyOut borrows
// it, as a concurrent wipe would. It returns a counter of the borrows it hit
// and restores the no-op hook when the test ends.
func destroyBeforeCopyOut(t *testing.T, target *secret.Secret) *int {
	t.Helper()
	hits := new(int)
	prev := beforeCopyOut
	beforeCopyOut = func(s *secret.Secret) {
		if s == target {
			*hits++
			s.Destroy()
		}
	}
	t.Cleanup(func() { beforeCopyOut = prev })
	return hits
}

func mustSecretValue(t *testing.T, b []byte) secret.Secret {
	t.Helper()
	s, err := secret.NewValue(b)
	if err != nil {
		t.Fatalf("secret.NewValue: %v", err)
	}
	return s
}

// TestStateSerialize_DestroyedPqRatchetStateFails covers the borrow failure
// copyOut used to swallow: a destroyed PQ ratchet state was serialized as
// absent, so the reloaded session ran without its PQ ratchet. It must be an
// error instead.
func TestStateSerialize_DestroyedPqRatchetStateFails(t *testing.T) {
	state := &record.StateStructure{
		SessionVersion: 4,
		RootKey:        mustSecretValue(t, bytes.Repeat([]byte{0x11}, 32)),
		PqRatchetState: mustSecretValue(t, []byte{0x01, 0x02, 0x03}),
	}
	t.Cleanup(state.Zeroize)

	hits := destroyBeforeCopyOut(t, &state.PqRatchetState)

	serializer := &ProtobufStateSerializer{}
	out, err := serializer.Serialize(state)
	if !errors.Is(err, secret.ErrSecretDestroyed) {
		t.Fatalf("Serialize err = %v, want ErrSecretDestroyed", err)
	}
	if out != nil {
		t.Fatal("Serialize returned a record without the destroyed PQ ratchet state")
	}
	if *hits == 0 {
		t.Fatal("copyOut was not reached for the PQ ratchet state")
	}

	sessionOut, err := (&ProtobufSessionSerializer{}).Serialize(&record.SessionStructure{SessionState: state})
	if !errors.Is(err, secret.ErrSecretDestroyed) || sessionOut != nil {
		t.Fatalf("session Serialize = %d bytes, %v; want nil, ErrSecretDestroyed", len(sessionOut), err)
	}
}

// TestCopyOut_AbsentIsNil keeps the absent case distinct: a secret that
// never held material is omitted without error.
func TestCopyOut_AbsentIsNil(t *testing.T) {
	var absent secret.Secret
	got, err := (&ownedCopies{}).copyOut(&absent)
	if err != nil || got != nil {
		t.Fatalf("copyOut(absent) = %v, %v; want nil, nil", got, err)
	}
}
