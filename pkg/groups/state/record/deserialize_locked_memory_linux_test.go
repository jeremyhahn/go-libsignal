//go:build linux

package record

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/groups/ratchet"
)

// Deserialize now returns structures carrying guarded material, so the byte
// entry points own locked memory they did not own before. Nothing in memguard
// reports how many locked buffers a process holds, so these tests read the
// kernel's own accounting — VmLck in /proc/self/status — which is exactly the
// resource an abandoned buffer consumes. That measurement is Linux-only.
//
// This mirrors the same harness in pkg/state/record for the 1:1 path.

// loadAttempts is how many loads each test performs. Enough that a leak of a
// few pages per load is orders of magnitude above the tolerance, few enough to
// stay inside a default RLIMIT_MEMLOCK while being measured.
const loadAttempts = 32

// growthToleranceKB absorbs page-granularity noise from allocations the Go
// runtime and memguard make around the measurement. The leaks these tests
// provoke are measured in megabytes.
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

// assertNoLockedMemoryGrowth repeats an operation expected to release
// everything it allocates and fails if the process holds materially more
// locked memory afterwards.
func assertNoLockedMemoryGrowth(t *testing.T, what string, attempt func()) {
	t.Helper()

	// One attempt outside the measurement, so a one-off allocation made on the
	// way in is not counted as growth.
	attempt()

	before := lockedMemoryKB(t)
	for i := 0; i < loadAttempts; i++ {
		attempt()
	}
	if growth := lockedMemoryKB(t) - before; growth > growthToleranceKB {
		t.Errorf("locked memory grew by %d kB over %d %s (tolerance %d kB): guarded buffers are being abandoned",
			growth, loadAttempts, what, growthToleranceKB)
	}
}

// senderKeyPublicBytes returns a decodable Curve25519 public point. Fixed bytes
// rather than a generated key: nothing here needs a curve operation, and
// generating one would put these tests outside the FIPS gate.
func senderKeyPublicBytes(fill byte) []byte {
	key := bytes.Repeat([]byte{fill}, 33)
	key[0] = ecc.DjbType
	return key
}

// wellFormedStateStructure builds a state carrying guarded material in every
// place a persisted sender key state can carry it.
func wellFormedStateStructure(t *testing.T, fill byte) *SenderKeyStateStructure {
	t.Helper()
	return &SenderKeyStateStructure{
		KeyID:             uint32(fill),
		MessageVersion:    3,
		SigningKeyPublic:  senderKeyPublicBytes(fill),
		SigningKeyPrivate: mustGuard(t, bytes.Repeat([]byte{fill}, 32)),
		SenderChainKey: &ratchet.SenderChainKeyStructure{
			Iteration: 1,
			ChainKey:  mustGuard(t, bytes.Repeat([]byte{fill}, 32)),
		},
		Keys: []*ratchet.SenderMessageKeyStructure{
			{Iteration: 1, Seed: mustGuard(t, bytes.Repeat([]byte{fill}, 32))},
			{Iteration: 2, Seed: mustGuard(t, bytes.Repeat([]byte{fill + 1}, 32))},
		},
	}
}

// malformedStateStructure carries a signing public key with an unknown type
// byte, which ecc.DecodePoint rejects — after the guarded fields around it have
// already been decoded.
func malformedStateStructure(t *testing.T, fill byte) *SenderKeyStateStructure {
	t.Helper()
	structure := wellFormedStateStructure(t, fill)
	structure.SigningKeyPublic = bytes.Repeat([]byte{0xFF}, 33)
	return structure
}

// TestNewSenderKeyStateFromBytesReleasesTheDecodedStructure is the regression
// test for the leak this conversion introduced: Deserialize hands back guarded
// material, NewSenderKeyStateFromStructure clones out of it and deliberately
// leaves the source alone, so the byte entry point owns the source and must
// release it. Without that, every SUCCESSFUL load strands a duplicate set of
// secrets — which is the dangerous shape, since it needs no malformed input at
// all.
func TestNewSenderKeyStateFromBytesReleasesTheDecodedStructure(t *testing.T) {
	stateSerializer := newTestStateSerializer()

	structure := wellFormedStateStructure(t, 0x21)
	defer structure.Zeroize()
	serialized, err := stateSerializer.Serialize(structure)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	assertNoLockedMemoryGrowth(t, "successful state loads", func() {
		state, lErr := NewSenderKeyStateFromBytes(serialized, stateSerializer)
		if lErr != nil {
			t.Fatalf("NewSenderKeyStateFromBytes: %v", lErr)
		}
		destroySenderKeyState(state)
	})
}

// TestNewSenderKeyStateFromBytesReleasesOnConstructionFailure covers the same
// ownership on the path where the live state is never built.
func TestNewSenderKeyStateFromBytesReleasesOnConstructionFailure(t *testing.T) {
	stateSerializer := newTestStateSerializer()

	structure := malformedStateStructure(t, 0x22)
	defer structure.Zeroize()
	serialized, err := stateSerializer.Serialize(structure)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	assertNoLockedMemoryGrowth(t, "failed state loads", func() {
		if _, lErr := NewSenderKeyStateFromBytes(serialized, stateSerializer); lErr == nil {
			t.Fatal("expected an error for the malformed signing public key")
		}
	})
}

// TestNewSenderKeyFromBytesReleasesTheDecodedRecord is the record-level
// counterpart: the decoded SenderKeyStructure carries guarded material for
// every state it holds.
func TestNewSenderKeyFromBytesReleasesTheDecodedRecord(t *testing.T) {
	recordSerializer, stateSerializer := newTestRecordSerializer(), newTestStateSerializer()

	record := &SenderKeyStructure{SenderKeyStates: []*SenderKeyStateStructure{
		wellFormedStateStructure(t, 0x31),
		wellFormedStateStructure(t, 0x32),
	}}
	defer record.Zeroize()
	serialized, err := recordSerializer.Serialize(record)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	assertNoLockedMemoryGrowth(t, "successful record loads", func() {
		key, lErr := NewSenderKeyFromBytes(serialized, recordSerializer, stateSerializer)
		if lErr != nil {
			t.Fatalf("NewSenderKeyFromBytes: %v", lErr)
		}
		for _, state := range key.senderKeyStates {
			destroySenderKeyState(state)
		}
	})
}

// TestNewSenderKeyFromStructReleasesEarlierStates is the multi-state case: the
// first state decodes into guarded clones, then a later one fails. Without the
// cleanup, a peer supplying records whose LAST state is malformed strands every
// preceding state's signing key, chain key and message keys — one record at a
// time, with no successful load required.
func TestNewSenderKeyFromStructReleasesEarlierStates(t *testing.T) {
	recordSerializer, stateSerializer := newTestRecordSerializer(), newTestStateSerializer()

	assertNoLockedMemoryGrowth(t, "records whose later state is malformed", func() {
		record := &SenderKeyStructure{SenderKeyStates: []*SenderKeyStateStructure{
			wellFormedStateStructure(t, 0x41),
			wellFormedStateStructure(t, 0x42),
			malformedStateStructure(t, 0x43),
		}}
		defer record.Zeroize()

		if _, err := NewSenderKeyFromStruct(record, recordSerializer, stateSerializer); err == nil {
			t.Fatal("expected an error for the malformed third state")
		}
	})
}
