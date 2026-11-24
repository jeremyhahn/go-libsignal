package spqr

import (
	"math"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// maxSkippedKeys is the maximum number of out-of-order message keys to
	// retain. Matches Rust DEFAULT_CHAIN_PARAMS.max_ooo_keys.
	maxSkippedKeys = 2000

	// maxJump is the maximum forward jump allowed in the receive counter.
	// Matches Rust DEFAULT_CHAIN_PARAMS.max_jump.
	maxJump = 25000

	// trimSize is the threshold above which GC runs on skipped keys.
	// Matches Rust: max_ooo_keys * 11/10 + 1 = 2201.
	trimSize = maxSkippedKeys*11/10 + 1
)

// SkippedKeyID uniquely identifies a skipped message key by its epoch and
// message counter within that epoch.
type SkippedKeyID struct {
	Epoch   uint64
	Counter uint32
}

// negotiationState tracks version negotiation, pending until the first received message resolves it to V0 or V1.
type negotiationState uint8

const (
	// negotiationPending sends empty PQR messages until the first received message sets the version.
	negotiationPending negotiationState = iota
	// negotiationResolved means the version field holds the negotiated version.
	negotiationResolved
)

// SPQR is the Sparse Post-Quantum Ratchet state machine. It manages epoch-based
// chain keys derived from SCKA outputs, providing forward secrecy and
// post-compromise security through periodic post-quantum key agreement.
//
// When a Braid (ML-KEM SCKA) is attached, SPQR piggybacks braid chunks on
// each message and advances the chain epoch when the braid completes a key
// agreement round.
//
// SPQR is NOT safe for concurrent use by multiple goroutines.
// The session-level serialization (load -> mutate -> store) provides
// implicit synchronization when used through the session cipher.
type SPQR struct {
	rootKey     *secret.Secret
	epoch       uint64
	sendEpoch   uint64
	chains      map[uint64]*EpochChain
	skippedKeys map[SkippedKeyID]*secret.Secret
	direction   Direction
	maxJump     uint32

	// Version negotiation fields.
	negotiation negotiationState
	version     Version
	minVersion  Version
	// authKey holds the initial PQR key during pending negotiation.
	// Once negotiation resolves, this is consumed (used to init the chain
	// for V1, or discarded for V0).
	authKey []byte

	// braid, when set, piggybacks chunks on Send and Recv and advances the epoch on each output key; only the V4 format persists it.
	braid *mlkembraid.Braid

	// skippedKeysFIFO lists skipped key IDs in insertion order for amortized O(1) eviction; stale entries are skipped, and skippedKeysFIFOHead marks the first candidate.
	skippedKeysFIFO     []SkippedKeyID
	skippedKeysFIFOHead int
}

// Init creates a new SPQR instance from a shared secret, direction, and max
// forward jump limit. The shared secret is used to derive the initial root key
// and chain keys for epoch 0. Direction determines the assignment of
// send/receive chains. The maxJumpLimit controls the maximum forward jump
// allowed in the receive counter; use the package-level maxJump constant
// (25000) for normal sessions and math.MaxUint32 for self-sessions.
//
// MinVersion is set to VersionV1, matching the Rust libsignal policy of
// "Require that all clients speak SPQR" (ratchet.rs:88, 152). V0 (opt-in
// downgrade) requires explicit use of InitialStateWithParams and warrants an
// audit note before deployment.
func Init(sharedSecret []byte, direction Direction, maxJumpLimit uint32) (*SPQR, error) {
	rk, cks, ckr, err := KdfSckaInit(sharedSecret)
	if err != nil {
		return nil, err
	}

	if direction == DirectionB2A {
		cks, ckr = ckr, cks
	}

	chain := &EpochChain{
		sendKey: cks,
		recvKey: ckr,
	}

	return &SPQR{
		rootKey:     rk,
		epoch:       0,
		chains:      map[uint64]*EpochChain{0: chain},
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   direction,
		maxJump:     maxJumpLimit,
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV1,
	}, nil
}

// InitWithBraid creates a new SPQR instance with an attached ML-KEM Braid for
// SCKA-integrated epoch advancement. The braid is used by SendBraid/RecvBraid
// to piggyback key agreement chunks on each message.
//
// Parameters:
//   - sharedSecret: initial shared secret for chain key derivation
//   - direction: A2B or B2A, determines send/recv key assignment
//   - maxJumpLimit: max forward jump for the receive counter
//   - braid: initialized ML-KEM Braid instance (Alice or Bob)
func InitWithBraid(sharedSecret []byte, direction Direction, maxJumpLimit uint32, braid *mlkembraid.Braid) (*SPQR, error) {
	s, err := Init(sharedSecret, direction, maxJumpLimit)
	if err != nil {
		return nil, err
	}
	s.braid = braid
	return s, nil
}

// ReceiveKey processes an SCKA output for a new epoch, deriving fresh chain
// keys and updating the root key. The new epoch must be strictly greater
// than the current epoch.
func (s *SPQR) ReceiveKey(sckaOutput []byte, newEpoch uint64) error {
	if newEpoch <= s.epoch {
		return &ErrOldEpoch{Current: s.epoch, Received: newEpoch}
	}

	newRK, newCKs, newCKr, err := KdfSckaRK(s.rootKey, sckaOutput)
	if err != nil {
		return err
	}

	if s.direction == DirectionB2A {
		newCKs, newCKr = newCKr, newCKs
	}

	// Destroy old root key before replacing.
	s.rootKey.Destroy()
	s.rootKey = newRK

	s.chains[newEpoch] = &EpochChain{
		sendKey: newCKs,
		recvKey: newCKr,
	}
	s.epoch = newEpoch
	s.clearOldEpochs()

	return nil
}

// Encrypt derives the next message key from the send chain of the given epoch,
// returning the message key and the counter for this message.
// The counter is incremented before use, so the first message key is at index 1,
// matching the Rust reference implementation.
func (s *SPQR) Encrypt(epoch uint64) (messageKey *secret.Secret, counter uint32, err error) {
	if epoch < s.sendEpoch {
		return nil, 0, &ErrSendEpochDecreased{Current: s.sendEpoch, Requested: epoch}
	}

	chain, ok := s.chains[epoch]
	if !ok {
		return nil, 0, &ErrUnknownEpoch{Epoch: epoch}
	}
	if chain.sendKey == nil {
		return nil, 0, &ErrSendKeyDestroyed{Epoch: epoch}
	}

	// Update send epoch tracking. When the epoch advances, clear send keys
	// on retained chains and enforce EPOCHS_TO_KEEP trimming.
	if epoch != s.sendEpoch {
		s.sendEpoch = epoch
		s.clearOldEpochs()
	}

	// Check for counter overflow before incrementing.
	if chain.sendCounter == math.MaxUint32 {
		return nil, 0, &ErrCounterExhausted{Epoch: epoch}
	}

	// Increment counter before use: first key is at index 1.
	chain.sendCounter++
	counter = chain.sendCounter

	mk, nextCK, kdfErr := KdfSckaCK(chain.sendKey, counter)
	if kdfErr != nil {
		return nil, 0, kdfErr
	}
	chain.sendKey.Destroy()
	chain.sendKey = nextCK

	return mk, counter, nil
}

// Decrypt derives the message key for the given epoch and counter. If the
// message arrived out of order, intermediate keys are stored as skipped keys.
// Previously skipped keys are returned directly.
// Counters are 1-based (first message key is at index 1), matching the Rust
// reference implementation where the counter is incremented before use.
//
// Note: The maxSkippedKeys limit is enforced globally across all epochs,
// matching Rust's per-epoch KeyHistory::gc behavior. Skipped keys from
// older epochs are only garbage-collected when the total count exceeds
// trimSize, which means keys from multiple epochs may coexist in the map.
func (s *SPQR) Decrypt(epoch uint64, counter uint32) (messageKey *secret.Secret, err error) {
	// Check skipped keys first (out-of-order message retrieval).
	skID := SkippedKeyID{Epoch: epoch, Counter: counter}
	if mk, ok := s.skippedKeys[skID]; ok {
		// Transfer ownership of the secret out of the map.
		delete(s.skippedKeys, skID)
		// Compact the FIFO so consumed keys do not accumulate.
		s.trimFIFOIfNeeded()
		return mk, nil
	}

	chain, ok := s.chains[epoch]
	if !ok {
		return nil, &ErrUnknownEpoch{Epoch: epoch}
	}

	// Handle counters at or behind the current receive position.
	// These have already been derived; if not in skipped keys above,
	// they were either already consumed or trimmed.
	if counter == chain.recvCounter {
		return nil, &ErrKeyAlreadyRequested{Counter: counter}
	}
	if counter < chain.recvCounter {
		// Match Rust KeyHistory::get(): if the counter is old enough that
		// it would have been garbage-collected, report it as trimmed.
		// Otherwise it was in the skipped map and already consumed.
		if uint64(counter)+uint64(maxSkippedKeys) < uint64(chain.recvCounter) {
			return nil, &ErrKeyTrimmed{Counter: counter}
		}
		return nil, &ErrKeyAlreadyRequested{Counter: counter}
	}

	// Enforce maximum forward jump to prevent DoS via memory exhaustion.
	if counter-chain.recvCounter > s.maxJump {
		return nil, &ErrMaxJump{From: chain.recvCounter, To: counter}
	}

	// Walk forward to counter, recording skipped keys in the map and the FIFO and evicting the oldest at capacity, as Rust KeyHistory::gc does.
	for chain.recvCounter+1 < counter {
		if chain.recvCounter == math.MaxUint32 {
			return nil, &ErrCounterExhausted{Epoch: epoch}
		}
		chain.recvCounter++
		mk, nextCK, kdfErr := KdfSckaCK(chain.recvKey, chain.recvCounter)
		if kdfErr != nil {
			return nil, kdfErr
		}
		chain.recvKey.Destroy()
		chain.recvKey = nextCK

		if len(s.skippedKeys) >= maxSkippedKeys {
			s.evictOldestSkippedKey()
		}
		id := SkippedKeyID{Epoch: epoch, Counter: chain.recvCounter}
		s.skippedKeys[id] = mk
		s.skippedKeysFIFO = append(s.skippedKeysFIFO, id)
	}

	// Derive the requested key.
	if chain.recvCounter == math.MaxUint32 {
		return nil, &ErrCounterExhausted{Epoch: epoch}
	}
	chain.recvCounter++
	mk, nextCK, kdfErr := KdfSckaCK(chain.recvKey, chain.recvCounter)
	if kdfErr != nil {
		return nil, kdfErr
	}
	chain.recvKey.Destroy()
	chain.recvKey = nextCK

	// Garbage-collect old skipped keys for this epoch, matching Rust's
	// amortized GC which only runs when skippedKeys exceeds trimSize.
	if len(s.skippedKeys) > trimSize {
		s.gcSkippedKeys(epoch, chain.recvCounter)
	}

	return mk, nil
}

// Epoch returns the current epoch number.
func (s *SPQR) Epoch() uint64 {
	return s.epoch
}

// SkippedKeyCount returns the number of stored skipped message keys.
func (s *SPQR) SkippedKeyCount() int {
	return len(s.skippedKeys)
}

// Zeroize clears all sensitive key material from the SPQR state.
func (s *SPQR) Zeroize() {
	if s.rootKey != nil {
		s.rootKey.Destroy()
	}
	for _, chain := range s.chains {
		chain.Zeroize()
	}
	for id, mk := range s.skippedKeys {
		mk.Destroy()
		delete(s.skippedKeys, id)
	}
	// Zeroize auth key if still pending.
	if len(s.authKey) > 0 {
		crypto.Zeroize(s.authKey)
		s.authKey = nil
	}
	// Zeroize braid state.
	if s.braid != nil {
		s.braid.Zeroize()
		s.braid = nil
	}
	// The FIFO holds only IDs; nil it.
	s.skippedKeysFIFO = nil
	s.skippedKeysFIFOHead = 0
}

// IsNegotiated returns true if version negotiation has been resolved.
func (s *SPQR) IsNegotiated() bool {
	return s.negotiation == negotiationResolved
}

// NegotiatedVersion returns the resolved version. Only valid after negotiation
// is resolved (IsNegotiated returns true).
func (s *SPQR) NegotiatedVersion() Version {
	return s.version
}

// IsDisabled returns true if PQR has been negotiated to V0 (disabled).
func (s *SPQR) IsDisabled() bool {
	return s.negotiation == negotiationResolved && s.version == VersionV0
}

// Braid returns the attached braid, or nil if none is attached.
func (s *SPQR) Braid() *mlkembraid.Braid {
	return s.braid
}

// SetBraid attaches an ML-KEM Braid SCKA instance to the SPQR state.
// This enables braid-integrated Send/Recv with epoch advancement.
func (s *SPQR) SetBraid(braid *mlkembraid.Braid) {
	s.braid = braid
}

// advanceEpoch installs a new epoch chain from KdfSckaRK over the braid output key.
func (s *SPQR) advanceEpoch(outputKey *secret.Secret) error {
	if outputKey == nil || outputKey.IsDestroyed() {
		return &ErrInvalidInput{
			Field:  "outputKey",
			Reason: "must not be nil or destroyed",
		}
	}

	// Check for epoch overflow before deriving or changing anything.
	if s.epoch == math.MaxUint64 {
		return &ErrEpochOverflow{}
	}

	var newRK, newCKs, newCKr *secret.Secret
	err := outputKey.WithBytes(func(ok []byte) error {
		var kErr error
		newRK, newCKs, newCKr, kErr = KdfSckaRK(s.rootKey, ok)
		return kErr
	})
	if err != nil {
		return err
	}

	if s.direction == DirectionB2A {
		newCKs, newCKr = newCKr, newCKs
	}

	// Destroy old root key.
	s.rootKey.Destroy()
	s.rootKey = newRK

	newEpoch := s.epoch + 1
	s.chains[newEpoch] = &EpochChain{
		sendKey: newCKs,
		recvKey: newCKr,
	}
	s.epoch = newEpoch
	s.clearOldEpochs()

	return nil
}

// clearOldEpochs drops chains and skipped keys before min(sendEpoch, epoch) - 1; unlike Rust it removes whole chains, which is safe because skipped keys live in skippedKeys.
func (s *SPQR) clearOldEpochs() {
	keepFrom := s.sendEpoch
	if s.epoch < keepFrom {
		keepFrom = s.epoch
	}
	if keepFrom > 0 {
		keepFrom--
	}

	for epoch, chain := range s.chains {
		if epoch < keepFrom {
			chain.Zeroize()
			delete(s.chains, epoch)
		}
	}
	// Clear send keys on retained chains below sendEpoch (matches Rust's
	// Chain::send_key which calls clear_next() on prior epochs).
	for epoch, chain := range s.chains {
		if epoch < s.sendEpoch && chain.sendKey != nil {
			chain.sendKey.Destroy()
			chain.sendKey = nil
		}
	}
	for id, mk := range s.skippedKeys {
		if id.Epoch < keepFrom {
			mk.Destroy()
			delete(s.skippedKeys, id)
		}
	}
	s.trimFIFOIfNeeded()
}

// gcSkippedKeys removes skipped message keys for the given epoch that are
// older than (currentCounter - maxSkippedKeys), matching Rust's KeyHistory::gc.
func (s *SPQR) gcSkippedKeys(epoch uint64, currentCounter uint32) {
	if currentCounter <= maxSkippedKeys {
		return
	}
	trimBelow := currentCounter - maxSkippedKeys
	for id, mk := range s.skippedKeys {
		if id.Epoch == epoch && id.Counter < trimBelow {
			mk.Destroy()
			delete(s.skippedKeys, id)
		}
	}
	s.trimFIFOIfNeeded()
}

// evictOldestSkippedKey evicts the oldest live skipped key in FIFO order, rebuilding the FIFO from the map when it is exhausted.
func (s *SPQR) evictOldestSkippedKey() {
	for s.skippedKeysFIFOHead < len(s.skippedKeysFIFO) {
		id := s.skippedKeysFIFO[s.skippedKeysFIFOHead]
		s.skippedKeysFIFOHead++
		if mk, ok := s.skippedKeys[id]; ok {
			mk.Destroy()
			delete(s.skippedKeys, id)
			s.compactFIFOIfNeeded()
			return
		}
		// Entry was already removed (by gcSkippedKeys, clearOldEpochs, or
		// consumption). Advance past it without evicting — still O(1) amortized.
	}
	// No live entry: rebuild from the map, as after deserialization, and retry once.
	s.rebuildSkippedKeysFIFO()
	if s.skippedKeysFIFOHead < len(s.skippedKeysFIFO) {
		id := s.skippedKeysFIFO[s.skippedKeysFIFOHead]
		s.skippedKeysFIFOHead++
		if mk, ok := s.skippedKeys[id]; ok {
			mk.Destroy()
			delete(s.skippedKeys, id)
		}
		s.compactFIFOIfNeeded()
	}
}

// compactFIFOIfNeeded copies the live tail of skippedKeysFIFO to the front when
// the consumed head exceeds half the slice capacity, reclaiming memory without
// frequent allocations.
func (s *SPQR) compactFIFOIfNeeded() {
	if s.skippedKeysFIFOHead > len(s.skippedKeysFIFO)/2 {
		tail := s.skippedKeysFIFO[s.skippedKeysFIFOHead:]
		copy(s.skippedKeysFIFO, tail)
		s.skippedKeysFIFO = s.skippedKeysFIFO[:len(tail)]
		s.skippedKeysFIFOHead = 0
	}
}

// trimFIFOIfNeeded trims the consumed head and rebuilds the FIFO when stale entries far outnumber live keys.
func (s *SPQR) trimFIFOIfNeeded() {
	s.compactFIFOIfNeeded()
	// Rebuild when stale entries in the tail significantly outnumber live
	// entries. The factor of 2 keeps rebuild cost amortized: each entry
	// triggers at most one rebuild per "doubling" of live map size.
	live := len(s.skippedKeysFIFO) - s.skippedKeysFIFOHead
	if live > 2*len(s.skippedKeys)+64 {
		s.rebuildSkippedKeysFIFO()
	}
}

// rebuildSkippedKeysFIFO rebuilds the FIFO from skippedKeys sorted by (Epoch, Counter).
func (s *SPQR) rebuildSkippedKeysFIFO() {
	s.skippedKeysFIFO = make([]SkippedKeyID, 0, len(s.skippedKeys))
	for id := range s.skippedKeys {
		s.skippedKeysFIFO = append(s.skippedKeysFIFO, id)
	}
	// Insertion sort by (Epoch, Counter) — skipped-key maps are always small.
	for i := 1; i < len(s.skippedKeysFIFO); i++ {
		key := s.skippedKeysFIFO[i]
		j := i - 1
		for j >= 0 && (s.skippedKeysFIFO[j].Epoch > key.Epoch ||
			(s.skippedKeysFIFO[j].Epoch == key.Epoch && s.skippedKeysFIFO[j].Counter > key.Counter)) {
			s.skippedKeysFIFO[j+1] = s.skippedKeysFIFO[j]
			j--
		}
		s.skippedKeysFIFO[j+1] = key
	}
	s.skippedKeysFIFOHead = 0
}
