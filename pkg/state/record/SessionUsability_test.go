package record_test

import (
	"testing"
	"time"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/chain"
	"github.com/jeremyhahn/go-libsignal/pkg/protocol"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/optional"
)

// refNow is a fixed reference point used across all usability tests.
var refNow = time.Now()

// ================== SessionUsabilityRequirements flags ==================

func TestSessionUsabilityRequirementsContainsSingleFlag(t *testing.T) {
	tests := []struct {
		name string
		req  record.SessionUsabilityRequirements
		flag record.SessionUsabilityRequirements
		want bool
	}{
		{"NotStale contains NotStale", record.SessionRequireNotStale, record.SessionRequireNotStale, true},
		{"NotStale does not contain Pqxdh", record.SessionRequireNotStale, record.SessionRequireEstablishedWithPqxdh, false},
		{"NotStale does not contain Spqr", record.SessionRequireNotStale, record.SessionRequireSpqr, false},
		{"Pqxdh contains Pqxdh", record.SessionRequireEstablishedWithPqxdh, record.SessionRequireEstablishedWithPqxdh, true},
		{"Spqr contains Spqr", record.SessionRequireSpqr, record.SessionRequireSpqr, true},
		{"zero contains nothing", 0, record.SessionRequireNotStale, false},
		{"All contains NotStale", record.SessionRequirementsAll, record.SessionRequireNotStale, true},
		{"All contains Pqxdh", record.SessionRequirementsAll, record.SessionRequireEstablishedWithPqxdh, true},
		{"All contains Spqr", record.SessionRequirementsAll, record.SessionRequireSpqr, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.req.Contains(tc.flag); got != tc.want {
				t.Fatalf("Contains() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSessionUsabilityRequirementsContainsCombination(t *testing.T) {
	combined := record.SessionRequireNotStale | record.SessionRequireEstablishedWithPqxdh

	if !combined.Contains(record.SessionRequireNotStale) {
		t.Fatal("combined should contain NotStale")
	}
	if !combined.Contains(record.SessionRequireEstablishedWithPqxdh) {
		t.Fatal("combined should contain EstablishedWithPqxdh")
	}
	if combined.Contains(record.SessionRequireSpqr) {
		t.Fatal("combined should not contain Spqr")
	}
	if !combined.Contains(combined) {
		t.Fatal("combined should contain itself")
	}
}

func TestSessionUsabilityRequirementsAllBitsDistinct(t *testing.T) {
	// Each flag must occupy a unique bit so they compose independently.
	flags := []record.SessionUsabilityRequirements{
		record.SessionRequireNotStale,
		record.SessionRequireEstablishedWithPqxdh,
		record.SessionRequireSpqr,
	}
	for i := 0; i < len(flags); i++ {
		for j := i + 1; j < len(flags); j++ {
			if flags[i]&flags[j] != 0 {
				t.Fatalf("flags[%d] and flags[%d] share bits", i, j)
			}
		}
	}
}

func TestSessionUsabilityRequirementsAllEqualsUnion(t *testing.T) {
	union := record.SessionRequireNotStale | record.SessionRequireEstablishedWithPqxdh | record.SessionRequireSpqr
	if record.SessionRequirementsAll != union {
		t.Fatalf("SessionRequirementsAll (%b) != explicit union (%b)", record.SessionRequirementsAll, union)
	}
}

// ================== State.HasUsableSenderChain ==================

// newUsabilityState builds a State with a sender chain set for testing usability.
func newUsabilityState(t *testing.T, version int, pqRatchetState []byte) *record.State {
	t.Helper()
	s := newSerializer()
	state := record.NewState(s.State)
	state.SetVersion(version)
	kp := genKP(t)
	ck := chain.NewKey(kdf.DeriveSecrets, make([]byte, 32), 0)
	state.SetSenderChain(kp, ck)
	state.SetPqRatchetState(pqRatchetState)
	return state
}

func TestStateHasUsableSenderChain_NoSenderChain(t *testing.T) {
	s := newSerializer()
	state := record.NewState(s.State)
	// No sender chain set.

	got, err := state.HasUsableSenderChain(refNow, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false when no sender chain")
	}
}

func TestStateHasUsableSenderChain_ZeroRequirements_WithChain(t *testing.T) {
	state := newUsabilityState(t, protocol.CurrentVersion, nil)

	got, err := state.HasUsableSenderChain(refNow, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true with sender chain and zero requirements")
	}
}

// NotStale: session with no pending pre-key is never stale (incoming/acknowledged).
func TestStateHasUsableSenderChain_NotStale_NoPendingPreKey(t *testing.T) {
	state := newUsabilityState(t, protocol.CurrentVersion, nil)
	// No pending pre-key means the session is not unacknowledged — not stale.

	got, err := state.HasUsableSenderChain(refNow, record.SessionRequireNotStale)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true: no pending pre-key means session is not stale")
	}
}

// NotStale: unacknowledged session within the 30-day window.
func TestStateHasUsableSenderChain_NotStale_FreshUnacknowledged(t *testing.T) {
	state := newUsabilityState(t, protocol.CurrentVersion, nil)
	// SetUnacknowledgedPreKeyMessage sets timestamp to time.Now() internally,
	// which is within the 30-day window evaluated against refNow.
	kp := genKP(t)
	preKeyID := optional.NewOptionalUint32(1)
	state.SetUnacknowledgedPreKeyMessage(preKeyID, 10, kp.PublicKey())

	got, err := state.HasUsableSenderChain(refNow, record.SessionRequireNotStale)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true: freshly unacknowledged session is not stale")
	}
}

// NotStale: unacknowledged session older than 30 days is stale.
func TestStateHasUsableSenderChain_NotStale_StaleUnacknowledged(t *testing.T) {
	s := newSerializer()
	kp := genKP(t)
	privKeyArr := kp.PrivateKey().Serialize()
	baseKeyBytes := kp.PublicKey().Serialize()
	// 31 days before refNow — beyond the 30-day window.
	staleTimestamp := uint64(refNow.Add(-(31 * 24 * time.Hour)).Unix())

	structure := &record.StateStructure{
		SessionVersion:       protocol.CurrentVersion,
		LocalIdentityPublic:  baseKeyBytes,
		RemoteIdentityPublic: baseKeyBytes,
		SenderBaseKey:        baseKeyBytes,
		RootKey:              make([]byte, 32),
		PendingPreKey: &record.PendingPreKeyStructure{
			PreKeyID:       optional.NewOptionalUint32(1),
			SignedPreKeyID: 1,
			BaseKey:        baseKeyBytes,
			Timestamp:      staleTimestamp,
		},
		SenderChain: &record.ChainStructure{
			SenderRatchetKeyPublic:  baseKeyBytes,
			SenderRatchetKeyPrivate: privKeyArr[:],
			ChainKey:                &chain.KeyStructure{Key: make([]byte, 32), Index: 0},
		},
	}

	state, err := record.NewStateFromStructure(structure, s.State)
	if err != nil {
		t.Fatalf("NewStateFromStructure: %v", err)
	}

	got, err := state.HasUsableSenderChain(refNow, record.SessionRequireNotStale)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false: unacknowledged session older than 30 days is stale")
	}
}

// EstablishedWithPqxdh: version 4 (CurrentVersion) passes.
func TestStateHasUsableSenderChain_Pqxdh_CurrentVersion(t *testing.T) {
	state := newUsabilityState(t, protocol.CurrentVersion, nil)

	got, err := state.HasUsableSenderChain(refNow, record.SessionRequireEstablishedWithPqxdh)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatalf("expected true: CurrentVersion (%d) > PreKyberVersion (%d)",
			protocol.CurrentVersion, protocol.PreKyberVersion)
	}
}

// EstablishedWithPqxdh: version 3 (PreKyberVersion) fails.
func TestStateHasUsableSenderChain_Pqxdh_PreKyberVersion(t *testing.T) {
	state := newUsabilityState(t, protocol.PreKyberVersion, nil)

	got, err := state.HasUsableSenderChain(refNow, record.SessionRequireEstablishedWithPqxdh)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false: PreKyberVersion session did not use PQXDH")
	}
}

// EstablishedWithPqxdh: version 2 (below PreKyberVersion) also fails.
func TestStateHasUsableSenderChain_Pqxdh_BelowPreKyberVersion(t *testing.T) {
	state := newUsabilityState(t, 2, nil)

	got, err := state.HasUsableSenderChain(refNow, record.SessionRequireEstablishedWithPqxdh)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false: version 2 session did not use PQXDH")
	}
}

// Spqr: non-empty PQ ratchet state passes.
func TestStateHasUsableSenderChain_Spqr_WithPqState(t *testing.T) {
	pqState := []byte("some-pq-ratchet-state")
	state := newUsabilityState(t, protocol.CurrentVersion, pqState)

	got, err := state.HasUsableSenderChain(refNow, record.SessionRequireSpqr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true: session has PQ ratchet state")
	}
}

// Spqr: empty/nil PQ ratchet state fails.
func TestStateHasUsableSenderChain_Spqr_NoPqState(t *testing.T) {
	state := newUsabilityState(t, protocol.CurrentVersion, nil)

	got, err := state.HasUsableSenderChain(refNow, record.SessionRequireSpqr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false: session has no PQ ratchet state")
	}
}

// All requirements satisfied simultaneously.
func TestStateHasUsableSenderChain_AllRequirements_Satisfied(t *testing.T) {
	pqState := []byte("pq-ratchet")
	state := newUsabilityState(t, protocol.CurrentVersion, pqState)
	// No pending pre-key: session is not unacknowledged → not stale.

	got, err := state.HasUsableSenderChain(refNow, record.SessionRequirementsAll)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true: all requirements satisfied")
	}
}

// All requirements but Spqr is not satisfied.
func TestStateHasUsableSenderChain_AllRequirements_SpqrMissing(t *testing.T) {
	state := newUsabilityState(t, protocol.CurrentVersion, nil) // no PQ state

	got, err := state.HasUsableSenderChain(refNow, record.SessionRequirementsAll)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false: Spqr requirement not met (empty PQ ratchet state)")
	}
}

// All requirements but Pqxdh is not satisfied.
func TestStateHasUsableSenderChain_AllRequirements_PqxdhMissing(t *testing.T) {
	pqState := []byte("pq-ratchet")
	state := newUsabilityState(t, protocol.PreKyberVersion, pqState)

	got, err := state.HasUsableSenderChain(refNow, record.SessionRequirementsAll)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false: PQXDH requirement not met (PreKyberVersion)")
	}
}

// Combination: NotStale | Pqxdh both satisfied.
func TestStateHasUsableSenderChain_NotStaleAndPqxdh_Satisfied(t *testing.T) {
	state := newUsabilityState(t, protocol.CurrentVersion, nil)

	req := record.SessionRequireNotStale | record.SessionRequireEstablishedWithPqxdh
	got, err := state.HasUsableSenderChain(refNow, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true: NotStale and Pqxdh both satisfied")
	}
}

// ================== Session.HasUsableSenderChain ==================

func TestSessionHasUsableSenderChain_NoSenderChain(t *testing.T) {
	s := newSerializer()
	sess := record.NewSession(s.Session, s.State)
	// The default fresh session state has no sender chain.

	got, err := sess.HasUsableSenderChain(refNow, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false: session state has no sender chain")
	}
}

func TestSessionHasUsableSenderChain_WithChain_ZeroRequirements(t *testing.T) {
	s := newSerializer()
	state := newUsabilityState(t, protocol.CurrentVersion, nil)
	sess := record.NewSessionFromState(state, s.Session)

	got, err := sess.HasUsableSenderChain(refNow, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true: session has sender chain and zero requirements")
	}
}

func TestSessionHasUsableSenderChain_Pqxdh_Fails(t *testing.T) {
	s := newSerializer()
	state := newUsabilityState(t, protocol.PreKyberVersion, nil)
	sess := record.NewSessionFromState(state, s.Session)

	got, err := sess.HasUsableSenderChain(refNow, record.SessionRequireEstablishedWithPqxdh)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false: Session delegates to State which rejects PreKyberVersion")
	}
}

func TestSessionHasUsableSenderChain_AllSatisfied(t *testing.T) {
	s := newSerializer()
	pqState := []byte("pq")
	state := newUsabilityState(t, protocol.CurrentVersion, pqState)
	sess := record.NewSessionFromState(state, s.Session)

	got, err := sess.HasUsableSenderChain(refNow, record.SessionRequirementsAll)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !got {
		t.Fatal("expected true: session satisfies all requirements")
	}
}

func TestSessionHasUsableSenderChain_SpqrRequired_Missing(t *testing.T) {
	s := newSerializer()
	state := newUsabilityState(t, protocol.CurrentVersion, nil) // no PQ state
	sess := record.NewSessionFromState(state, s.Session)

	got, err := sess.HasUsableSenderChain(refNow, record.SessionRequireSpqr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got {
		t.Fatal("expected false: Spqr required but no PQ ratchet state present")
	}
}
