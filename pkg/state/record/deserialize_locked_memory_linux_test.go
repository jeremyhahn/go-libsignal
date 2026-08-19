//go:build linux

package record_test

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/message"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
)

// The deserialization constructors move key material into guarded memory as
// they decode, so a record that is malformed only after a well formed,
// secret-bearing component used to strand every buffer allocated before the
// failure. Nothing in memguard reports how many locked buffers a process
// holds, so these tests read the kernel's own accounting — VmLck in
// /proc/self/status — which is exactly the resource an abandoned buffer
// consumes. That measurement is Linux-only; the cleanup itself is covered
// portably in destroy_test.go.

// failedAttempts is how many malformed records each test feeds through a
// constructor. Enough that a leak of a handful of pages per attempt is orders
// of magnitude above the tolerance, few enough that the leak stays inside a
// default RLIMIT_MEMLOCK while it is being measured.
const failedAttempts = 32

// growthToleranceKB absorbs page-granularity noise from allocations the Go
// runtime and memguard make around the measurement. A leak of the size these
// tests provoke is measured in megabytes.
const growthToleranceKB = 128

func lockedMemoryKB(t *testing.T) int {
	t.Helper()
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("read /proc/self/status: %v", err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "VmLck:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			t.Fatalf("unexpected VmLck line: %q", line)
		}
		locked, err := strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("parse VmLck from %q: %v", line, err)
		}
		return locked
	}
	t.Fatal("/proc/self/status has no VmLck line")
	return 0
}

// assertNoLockedMemoryGrowth repeats an operation that is expected to release
// everything it allocates and fails the test if the process is holding
// materially more locked memory afterwards. The what argument names the
// operation for the failure message.
func assertNoLockedMemoryGrowth(t *testing.T, what string, attempt func()) {
	t.Helper()

	// One attempt outside the measurement, so any one-off allocation made on
	// the way in is not counted as growth.
	attempt()

	before := lockedMemoryKB(t)
	for i := 0; i < failedAttempts; i++ {
		attempt()
	}
	if growth := lockedMemoryKB(t) - before; growth > growthToleranceKB {
		t.Errorf("locked memory grew by %d kB over %d %s (tolerance %d kB): guarded buffers are being abandoned",
			growth, failedAttempts, what, growthToleranceKB)
	}
}

func publicKeyBytes(fill byte) []byte {
	key := bytes.Repeat([]byte{fill}, 33)
	key[0] = 0x05 // ecc.DjbType
	return key
}

// chainStructure builds a well formed chain carrying guarded material in every
// place a persisted chain can carry it.
func chainStructure(t *testing.T, fill byte) *record.ChainStructure {
	t.Helper()
	return &record.ChainStructure{
		SenderRatchetKeyPublic:  publicKeyBytes(fill),
		SenderRatchetKeyPrivate: mustGuard(t, bytes.Repeat([]byte{fill}, 32)),
		ChainKey:                &chain.KeyStructure{Key: bytes.Repeat([]byte{fill}, 32)},
		MessageKeys: []*message.KeysStructure{{
			CipherKey: bytes.Repeat([]byte{fill}, 32),
			MacKey:    bytes.Repeat([]byte{fill}, 32),
			IV:        bytes.Repeat([]byte{fill}, 16),
		}},
	}
}

// malformedChainStructure carries a sender ratchet public key with an unknown
// type byte, which ecc.DecodePoint rejects.
func malformedChainStructure(t *testing.T, fill byte) *record.ChainStructure {
	t.Helper()
	structure := chainStructure(t, fill)
	structure.SenderRatchetKeyPublic = bytes.Repeat([]byte{0xFF}, 33)
	return structure
}

func stateStructure(t *testing.T, receiverChains []*record.ChainStructure) *record.StateStructure {
	t.Helper()
	return &record.StateStructure{
		// A non-zero version, so the state is a real one: Clone short-circuits
		// to an empty state for the version-0 placeholder.
		SessionVersion:       3,
		LocalIdentityPublic:  publicKeyBytes(0x01),
		RemoteIdentityPublic: publicKeyBytes(0x02),
		SenderBaseKey:        publicKeyBytes(0x03),
		RootKey:              mustGuard(t, bytes.Repeat([]byte{0x04}, 32)),
		PqRatchetState:       mustGuard(t, bytes.Repeat([]byte{0x05}, 64)),
		SenderChain:          chainStructure(t, 0x06),
		ReceiverChains:       receiverChains,
	}
}

func TestNewStateFromStructureReleasesGuardedMemoryOnMalformedChain(t *testing.T) {
	assertNoLockedMemoryGrowth(t, "failed state deserializations", func() {
		// A valid sender chain and receiver chain, then a malformed one: the
		// guarded buffers behind the first two are what used to be stranded.
		structure := stateStructure(t, []*record.ChainStructure{
			chainStructure(t, 0x07),
			malformedChainStructure(t, 0x08),
		})
		defer structure.Zeroize()

		if _, err := record.NewStateFromStructure(structure, nil); err == nil {
			t.Fatal("expected an error for the malformed receiver chain")
		}
	})
}

func TestNewStateFromStructureReleasesGuardedMemoryOnMalformedIdentity(t *testing.T) {
	assertNoLockedMemoryGrowth(t, "failed state deserializations", func() {
		// Errors are accumulated, not returned at the first failure, so a bad
		// identity key still lets every chain below it allocate.
		structure := stateStructure(t, []*record.ChainStructure{chainStructure(t, 0x09)})
		structure.RemoteIdentityPublic = bytes.Repeat([]byte{0xFF}, 33)
		defer structure.Zeroize()

		if _, err := record.NewStateFromStructure(structure, nil); err == nil {
			t.Fatal("expected an error for the malformed remote identity key")
		}
	})
}

func TestNewSessionFromStructureReleasesGuardedMemoryOfEarlierStates(t *testing.T) {
	assertNoLockedMemoryGrowth(t, "failed session deserializations", func() {
		// A well formed previous state followed by a malformed current one.
		previous := stateStructure(t, []*record.ChainStructure{chainStructure(t, 0x0A)})
		current := stateStructure(t, []*record.ChainStructure{malformedChainStructure(t, 0x0B)})
		structure := &record.SessionStructure{
			PreviousStates: []*record.StateStructure{previous},
			SessionState:   current,
		}
		defer structure.Zeroize()

		if _, err := record.NewSessionFromStructure(structure, nil, nil); err == nil {
			t.Fatal("expected an error for the malformed session state")
		}
	})
}

func TestNewSessionFromStructureKeepsGuardedMemoryOnSuccess(t *testing.T) {
	// The cleanup must not fire on the success path: the returned session owns
	// its guarded material and has to stay usable.
	structure := &record.SessionStructure{
		PreviousStates: []*record.StateStructure{stateStructure(t, nil)},
		SessionState:   stateStructure(t, []*record.ChainStructure{chainStructure(t, 0x0C)}),
	}
	defer structure.Zeroize()

	session, err := record.NewSessionFromStructure(structure, nil, nil)
	if err != nil {
		t.Fatalf("NewSessionFromStructure: %v", err)
	}
	if got := session.SessionState().RootKey().Bytes(); !bytes.Equal(got, bytes.Repeat([]byte{0x04}, 32)) {
		t.Errorf("root key of the live session is %x, want the deserialized material", got)
	}
	if got := session.PreviousSessionStates()[0].RootKey().Bytes(); !bytes.Equal(got, bytes.Repeat([]byte{0x04}, 32)) {
		t.Errorf("root key of the previous state is %x, want the deserialized material", got)
	}
}

// TestDiscardCloneReleasesTheCloneOnly covers the other object a caller owns
// outright: a working clone that is thrown away instead of committed.
func TestDiscardCloneReleasesTheCloneOnly(t *testing.T) {
	serializer := newSerializer()
	structure := stateStructure(t, []*record.ChainStructure{chainStructure(t, 0x0D)})
	defer structure.Zeroize()

	state, err := record.NewStateFromStructure(structure, serializer.State)
	if err != nil {
		t.Fatalf("NewStateFromStructure: %v", err)
	}

	assertNoLockedMemoryGrowth(t, "discarded clones", func() {
		clone, cloneErr := state.Clone()
		if cloneErr != nil {
			t.Fatalf("Clone: %v", cloneErr)
		}
		clone.DiscardClone()
	})

	// The source keeps its own guarded material: a discard must never reach
	// through to the state that was cloned.
	if got := state.RootKey().Bytes(); !bytes.Equal(got, bytes.Repeat([]byte{0x04}, 32)) {
		t.Errorf("root key of the cloned state is %x, want the material it was built with", got)
	}
	if _, err := state.Serialize(); err != nil {
		t.Errorf("the cloned state is no longer serializable: %v", err)
	}
}
