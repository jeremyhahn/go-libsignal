package tripleratchet

// White-box tests for destroySnapshot memory-zeroization.
// These tests live in package tripleratchet (not tripleratchet_test) so they
// can access unexported types decryptSnapshot and destroySnapshot.

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// snapshotableECCipher is a minimal ECCipher + ECCipherSnapshotable for
// testing the ecSnapshot zeroization path.
type snapshotableECCipher struct {
	seed []byte
}

func (c *snapshotableECCipher) SendKey() ([]byte, []byte, error) {
	return []byte{0}, make([]byte, 32), nil
}

func (c *snapshotableECCipher) ReceiveKey([]byte) ([]byte, error) {
	return make([]byte, 32), nil
}

func (c *snapshotableECCipher) TakeECSnapshot() ([]byte, error) {
	out := make([]byte, len(c.seed))
	copy(out, c.seed)
	return out, nil
}

func (c *snapshotableECCipher) RestoreECSnapshot(data []byte) error {
	return nil
}

// makeMinimalSnapshot builds a decryptSnapshot with real secret.Secret
// and non-trivial byte slices so we can assert zeroization.
func makeMinimalSnapshot(t *testing.T, braidPayload []byte, ecPayload []byte) (*decryptSnapshot, []byte, []byte) {
	t.Helper()

	// Clone backing arrays so the caller can inspect them after destroy.
	braidCopy := make([]byte, len(braidPayload))
	copy(braidCopy, braidPayload)

	ecCopy := make([]byte, len(ecPayload))
	copy(ecCopy, ecPayload)

	rk, err := secret.New([]byte{1, 2, 3, 4})
	if err != nil {
		t.Fatalf("secret.New rootKey: %v", err)
	}
	sc, err := secret.New([]byte{5, 6, 7, 8})
	if err != nil {
		t.Fatalf("secret.New sendChain: %v", err)
	}
	rc, err := secret.New([]byte{9, 10, 11, 12})
	if err != nil {
		t.Fatalf("secret.New recvChain: %v", err)
	}

	skippedKey, err := secret.New([]byte{0xAB, 0xCD})
	if err != nil {
		t.Fatalf("secret.New skippedKey: %v", err)
	}

	snap := &decryptSnapshot{
		braidData:     braidCopy,
		rootKey:       rk,
		sendChainKey:  sc,
		recvChainKey:  rc,
		sendCounter:   1,
		recvCounter:   2,
		pqEpoch:       3,
		handshakeDone: true,
		skippedPQKeys: map[pqSkippedKeyID]*secret.Secret{
			{epoch: 0, counter: 0}: skippedKey,
		},
		ecSnapshot: ecCopy,
	}

	// Return the original backing slices so the caller can read them after
	// destroySnapshot nils the snap fields. We keep references here because
	// Go's GC will not collect the underlying arrays while these live.
	return snap, braidCopy, ecCopy
}

// TestDestroySnapshot_ZeroizesBraidData confirms the braidData backing array is
// overwritten with zeros before the reference is cleared.
func TestDestroySnapshot_ZeroizesBraidData(t *testing.T) {
	braidPayload := []byte{0x11, 0x22, 0x33, 0x44, 0x55}
	ecPayload := []byte{0xAA, 0xBB}

	snap, braidBacking, _ := makeMinimalSnapshot(t, braidPayload, ecPayload)

	// Sanity: backing array has non-zero content before destroy.
	allZero := true
	for _, b := range braidBacking {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("pre-condition: braidBacking should not be all-zero before destroySnapshot")
	}

	tr := &TripleRatchet{}
	tr.destroySnapshot(snap)

	// The snap field must be nil.
	if snap.braidData != nil {
		t.Error("snap.braidData must be nil after destroySnapshot")
	}

	// The backing array (still referenced by braidBacking) must be all zeros.
	for i, b := range braidBacking {
		if b != 0 {
			t.Errorf("braidData backing[%d] = 0x%02x, want 0x00 after destroySnapshot", i, b)
		}
	}
}

// TestDestroySnapshot_ZeroziesECSnapshot confirms the ecSnapshot backing array
// is overwritten with zeros before the reference is cleared.
func TestDestroySnapshot_ZeroziesECSnapshot(t *testing.T) {
	braidPayload := []byte{0x01}
	ecPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF}

	snap, _, ecBacking := makeMinimalSnapshot(t, braidPayload, ecPayload)

	tr := &TripleRatchet{}
	tr.destroySnapshot(snap)

	if snap.ecSnapshot != nil {
		t.Error("snap.ecSnapshot must be nil after destroySnapshot")
	}

	for i, b := range ecBacking {
		if b != 0 {
			t.Errorf("ecSnapshot backing[%d] = 0x%02x, want 0x00 after destroySnapshot", i, b)
		}
	}
}

// TestDestroySnapshot_DestroysSecrets confirms that all secret.Secret fields
// (rootKey, sendChainKey, recvChainKey, skippedPQKeys) are destroyed.
func TestDestroySnapshot_DestroysSecrets(t *testing.T) {
	snap, _, _ := makeMinimalSnapshot(t, []byte{0x01, 0x02}, []byte{0x03})

	rk := snap.rootKey
	sc := snap.sendChainKey
	rc := snap.recvChainKey
	var skipped []*secret.Secret
	for _, v := range snap.skippedPQKeys {
		skipped = append(skipped, v)
	}

	tr := &TripleRatchet{}
	tr.destroySnapshot(snap)

	if !rk.IsDestroyed() {
		t.Error("rootKey must be destroyed after destroySnapshot")
	}
	if !sc.IsDestroyed() {
		t.Error("sendChainKey must be destroyed after destroySnapshot")
	}
	if !rc.IsDestroyed() {
		t.Error("recvChainKey must be destroyed after destroySnapshot")
	}
	for i, sk := range skipped {
		if !sk.IsDestroyed() {
			t.Errorf("skippedPQKeys[%d] must be destroyed after destroySnapshot", i)
		}
	}

	if snap.rootKey != nil {
		t.Error("snap.rootKey must be nil after destroySnapshot")
	}
	if snap.sendChainKey != nil {
		t.Error("snap.sendChainKey must be nil after destroySnapshot")
	}
	if snap.recvChainKey != nil {
		t.Error("snap.recvChainKey must be nil after destroySnapshot")
	}
	if snap.skippedPQKeys != nil {
		t.Error("snap.skippedPQKeys must be nil after destroySnapshot")
	}
}

// TestDestroySnapshot_NilSnapshot guards against panics when optional fields
// are absent (no EC snapshot, no skipped keys).
func TestDestroySnapshot_NilOptionalFields(t *testing.T) {
	rk, _ := secret.New([]byte{1, 2, 3, 4})
	sc, _ := secret.New([]byte{5, 6, 7, 8})
	rc, _ := secret.New([]byte{9, 10, 11, 12})

	snap := &decryptSnapshot{
		braidData:     nil,
		rootKey:       rk,
		sendChainKey:  sc,
		recvChainKey:  rc,
		skippedPQKeys: nil,
		ecSnapshot:    nil,
	}

	tr := &TripleRatchet{}
	// Must not panic when byte slices and maps are nil.
	tr.destroySnapshot(snap)

	if !rk.IsDestroyed() {
		t.Error("rootKey must be destroyed")
	}
}

// TestTakeSnapshot_DestroySnapshot_RoundTrip verifies that a snapshot taken
// from a live TripleRatchet and then destroyed leaves all byte buffers zeroed.
func TestTakeSnapshot_DestroySnapshot_RoundTrip(t *testing.T) {
	sharedSecret := make([]byte, 32)
	for i := range sharedSecret {
		sharedSecret[i] = byte(i + 1)
	}

	ec := &snapshotableECCipher{seed: []byte{0xCA, 0xFE, 0xBA, 0xBE}}
	kem := mlkembraid.NewIncrementalMLKEM768KEM()

	tr, err := NewAlice(ec, sharedSecret, kem, 10)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	snap, takeErr := tr.takeSnapshot()
	if takeErr != nil {
		t.Fatalf("takeSnapshot: %v", takeErr)
	}

	// Capture backing-array references before destroySnapshot nils them.
	braidBacking := snap.braidData
	ecBacking := snap.ecSnapshot

	if len(braidBacking) == 0 {
		t.Fatal("expected non-empty braidData from takeSnapshot")
	}

	tr.destroySnapshot(snap)

	// braidData backing must be all zeros.
	for i, b := range braidBacking {
		if b != 0 {
			t.Errorf("braidData backing[%d] = 0x%02x after destroySnapshot, want 0x00", i, b)
			break
		}
	}

	// ecSnapshot backing must be all zeros.
	for i, b := range ecBacking {
		if b != 0 {
			t.Errorf("ecSnapshot backing[%d] = 0x%02x after destroySnapshot, want 0x00", i, b)
			break
		}
	}

	if snap.braidData != nil {
		t.Error("snap.braidData must be nil after destroySnapshot")
	}
	if snap.ecSnapshot != nil {
		t.Error("snap.ecSnapshot must be nil after destroySnapshot")
	}
}
