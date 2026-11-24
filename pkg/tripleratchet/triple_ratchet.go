// Package tripleratchet implements a Triple Ratchet: each message key combines the EC Double Ratchet and the SPQR chain, whose epoch advances on each ML-KEM Braid output key.
//
// NewAlice and NewBob create the two ends; Encrypt and Decrypt exchange composite messages. Unlike the internal Rust TripleRatchet (rust/protocol/src/triple_ratchet.rs), this is a standalone API.
package tripleratchet

import (
	"crypto/hmac"
	"crypto/sha256"
	"math"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// maxSkippedPQKeys is the maximum number of out-of-order PQ keys retained.
	maxSkippedPQKeys = 2000

	// maxPQJump is the maximum forward jump in PQ counters.
	maxPQJump = 25000

	// epochsToKeepPriorToSendEpoch is the epoch retention window for skipped keys.
	epochsToKeepPriorToSendEpoch = 1
)

// pqSkippedKeyID identifies a skipped PQ key by epoch and counter; the header carries no epoch, so skipped keys work only within the current epoch.
type pqSkippedKeyID struct {
	epoch   uint64
	counter uint32
}

// ECCipher is the EC Double Ratchet used by the Triple Ratchet: SendKey returns a message key and serialized header, and receiving derives the key from a header.
type ECCipher interface {
	// SendKey returns the EC message key and serialized EC header for the next
	// outgoing message without performing the actual encryption.
	SendKey() (ecHeader []byte, messageKey []byte, err error)

	// ReceiveKey derives the EC message key for an incoming message using the
	// given serialized EC header.
	ReceiveKey(ecHeader []byte) (messageKey []byte, err error)
}

// ECCipherSnapshotable lets the Triple Ratchet snapshot EC state before ReceiveKey and restore it on failure.
type ECCipherSnapshotable interface {
	// TakeECSnapshot serializes the current EC state for atomic rollback.
	TakeECSnapshot() ([]byte, error)

	// RestoreECSnapshot replaces the current EC state from a snapshot taken
	// by TakeECSnapshot.
	RestoreECSnapshot(data []byte) error
}

// decryptSnapshot captures all mutable Triple Ratchet state before a Decrypt
// call. All secrets are independent clones so destroying the snapshot does not
// affect the live state.
type decryptSnapshot struct {
	braidData     []byte
	rootKey       *secret.Secret
	sendChainKey  *secret.Secret
	recvChainKey  *secret.Secret
	sendCounter   uint32
	recvCounter   uint32
	pqEpoch       uint64
	handshakeDone bool
	// skippedPQKeys is a deep copy of the skipped keys map at snapshot time.
	skippedPQKeys map[pqSkippedKeyID]*secret.Secret
	// ecSnapshot is only set when the ECCipher implements ECCipherSnapshotable.
	ecSnapshot []byte
}

// TripleRatchet is a hybrid EC and PQ session; it is not safe for concurrent use.
type TripleRatchet struct {
	ecCipher  ECCipher
	braid     *mlkembraid.Braid
	rootKey   *secret.Secret
	sendChain *secret.Secret
	recvChain *secret.Secret

	sendCounter uint32
	recvCounter uint32
	pqEpoch     uint64

	// isResponder is true for Bob. Controls send/recv chain key assignment.
	isResponder bool

	// braidHandshakeComplete is set after the first epoch advancement.
	// Before this is set, suppressed braid errors are tolerated; after it,
	// all braid errors propagate.
	braidHandshakeComplete bool

	// skippedPQKeys holds out-of-order PQ message keys keyed by (epoch, counter).
	skippedPQKeys map[pqSkippedKeyID]*secret.Secret

	// skippedPQKeysFIFO lists skipped key IDs in insertion order for amortized O(1) eviction; stale entries are skipped, and skippedPQKeysFIFOHead marks the first candidate.
	skippedPQKeysFIFO     []pqSkippedKeyID
	skippedPQKeysFIFOHead int
}

// NewAlice creates the initiator: SPQR chain keys from spqr.KdfSckaInit and a braid from mlkembraid.InitAlice.
func NewAlice(ecCipher ECCipher, sharedSecret []byte, kemImpl mlkembraid.IncrementalKEM, chunkSize int) (*TripleRatchet, error) {
	return newTripleRatchet(ecCipher, sharedSecret, kemImpl, chunkSize, false)
}

// NewBob creates the responder with mlkembraid.InitBob and Alice's send and receive chain keys swapped.
func NewBob(ecCipher ECCipher, sharedSecret []byte, kemImpl mlkembraid.IncrementalKEM, chunkSize int) (*TripleRatchet, error) {
	return newTripleRatchet(ecCipher, sharedSecret, kemImpl, chunkSize, true)
}

// newTripleRatchet is the shared constructor for Alice and Bob.
func newTripleRatchet(ecCipher ECCipher, sharedSecret []byte, kemImpl mlkembraid.IncrementalKEM, chunkSize int, isResponder bool) (*TripleRatchet, error) {
	if ecCipher == nil {
		return nil, &ErrInvalidInput{Field: "ecCipher", Reason: "must not be nil"}
	}
	// ECCipherSnapshotable is required so that Decrypt can atomically roll back
	// EC state when MAC verification fails. Without it the EC ratchet permanently
	// advances on any failure, silently voiding all rollback guarantees.
	if _, ok := ecCipher.(ECCipherSnapshotable); !ok {
		return nil, &ErrInvalidInput{Field: "ecCipher", Reason: "must implement ECCipherSnapshotable for atomic rollback"}
	}
	if len(sharedSecret) == 0 {
		return nil, &ErrInvalidInput{Field: "sharedSecret", Reason: "must not be empty"}
	}
	if kemImpl == nil {
		return nil, &ErrInvalidInput{Field: "kemImpl", Reason: "must not be nil"}
	}
	if chunkSize <= 0 {
		return nil, &ErrInvalidInput{Field: "chunkSize", Reason: "must be positive"}
	}

	rk, cks, ckr, err := spqr.KdfSckaInit(sharedSecret)
	if err != nil { // coverage-exempt: KdfSckaInit only fails on empty sharedSecret (checked above) or locked-memory allocation failure
		return nil, &ErrSPQRFailed{Op: "KdfSckaInit", Cause: err}
	}

	var braid *mlkembraid.Braid
	if isResponder {
		braid, err = mlkembraid.InitBob(sharedSecret, kemImpl, chunkSize)
	} else {
		braid, err = mlkembraid.InitAlice(sharedSecret, kemImpl, chunkSize)
	}
	if err != nil { // coverage-exempt: braid init only fails on empty sharedSecret (checked above), nil KEM (checked above), or locked-memory allocation failure
		rk.Destroy()
		cks.Destroy()
		ckr.Destroy()
		return nil, &ErrBraidFailed{Op: "Init", Cause: err}
	}

	// For Bob, swap send and receive chain keys (matches Rust Chain direction handling).
	sendChain := cks
	recvChain := ckr
	if isResponder {
		sendChain, recvChain = ckr, cks
	}

	return &TripleRatchet{
		ecCipher:      ecCipher,
		braid:         braid,
		rootKey:       rk,
		sendChain:     sendChain,
		recvChain:     recvChain,
		sendCounter:   0,
		recvCounter:   0,
		pqEpoch:       0,
		isResponder:   isResponder,
		skippedPQKeys: make(map[pqSkippedKeyID]*secret.Secret),
	}, nil
}

// Encrypt combines the EC message key with the next SPQR key through KDFHybrid, encrypts with AES-256-CBC and HMAC-SHA256, and returns the composite message with the braid's SCKA message.
func (tr *TripleRatchet) Encrypt(plaintext []byte) ([]byte, error) {
	// Step 1: EC ratchet send key.
	ecHeader, ecMKBytes, err := tr.ecCipher.SendKey()
	if err != nil {
		return nil, &ErrECRatchetFailed{Op: "SendKey", Cause: err}
	}
	ecMK, err := secret.New(ecMKBytes)
	if err != nil { // coverage-exempt: only reachable on locked-memory allocation failure
		return nil, &ErrECRatchetFailed{Op: "SendKey", Cause: err}
	}
	defer ecMK.Destroy()

	// Step 2: Braid SCKA send.
	sckaMsg, _, outputKey, braidErr := tr.braid.Send()
	if braidErr != nil { // coverage-exempt: braid.Send only fails when the state machine is in an invalid state, which cannot occur with a correctly initialized TripleRatchet
		return nil, &ErrBraidFailed{Op: "Send", Cause: braidErr}
	}

	// Braid send handlers return no OutputKey today; handle one anyway, copying it out of locked memory since secret.New zeroes its input.
	if outputKey != nil { // coverage-exempt: braid.Send never produces OutputKey in current protocol
		epochSecretBytes := []byte{}
		_ = outputKey.Key.WithBytes(func(b []byte) error {
			epochSecretBytes = append(epochSecretBytes, b...)
			return nil
		})
		outputKey.Key.Destroy()
		if epochErr := tr.advancePQEpoch(epochSecretBytes); epochErr != nil { // coverage-exempt: only reachable on locked-memory allocation failure
			return nil, epochErr
		}
	}

	// Reject MaxUint32 before incrementing so the counter never wraps.
	if tr.sendCounter == math.MaxUint32 {
		return nil, &ErrInvalidInput{Field: "sendCounter", Reason: "counter overflow"}
	}
	tr.sendCounter++

	pqMK, nextSendChain, spqrErr := spqr.KdfSckaCK(tr.sendChain, tr.sendCounter)
	if spqrErr != nil {
		return nil, &ErrSPQRFailed{Op: "KdfSckaCK", Cause: spqrErr}
	}
	tr.sendChain.Destroy()
	tr.sendChain = nextSendChain
	defer pqMK.Destroy()

	// Step 5: derive hybrid keys.
	hkeys, hkdfErr := KDFHybrid(ecMK, pqMK)
	if hkdfErr != nil { // coverage-exempt: KDFHybrid only fails on nil/destroyed key or locked-memory allocation failure; both keys are freshly created above
		return nil, hkdfErr
	}
	defer hkeys.Zeroize()

	// Step 6: AES-256-CBC encrypt.
	var ciphertext []byte
	encErr := hkeys.CipherKey.WithBytes(func(key []byte) error {
		return hkeys.IV.WithBytes(func(iv []byte) error {
			var aesErr error
			ciphertext, aesErr = cipher.AESCBCEncrypt(key, iv, plaintext)
			return aesErr
		})
	})
	if encErr != nil { // coverage-exempt: AESCBCEncrypt only fails on invalid key/IV length; KDFHybrid always produces 32-byte key and 16-byte IV
		return nil, &ErrDecryptFailed{Cause: encErr}
	}

	// Step 7: HMAC-SHA256 over ciphertext.
	var mac []byte
	if macErr := hkeys.MacKey.WithBytes(func(key []byte) error {
		mac = computeHMAC(key, ciphertext)
		return nil
	}); macErr != nil {
		return nil, &ErrDecryptFailed{Cause: macErr}
	}

	// authenticated ciphertext: encrypted_payload || mac(32 bytes)
	authenticated := make([]byte, len(ciphertext)+HMACSize)
	copy(authenticated, ciphertext)
	copy(authenticated[len(ciphertext):], mac)

	// Step 8: build composite header and message.
	header := &CompositeHeader{
		ECHeader:  ecHeader,
		PQCounter: tr.sendCounter,
		SCKAMsg:   sckaMsg,
	}
	headerBytes, marshalErr := marshalCompositeHeader(header)
	if marshalErr != nil { // coverage-exempt: marshalCompositeHeader only fails on nil header; header is always non-nil here
		return nil, marshalErr
	}

	return marshalCompositeMessage(headerBytes, authenticated), nil
}

// Decrypt returns the plaintext of an Encrypt message, restoring the snapshot on any failure.
func (tr *TripleRatchet) Decrypt(compositeMessage []byte) ([]byte, error) {
	// Parse outer framing.
	headerBytes, authenticatedCiphertext, parseErr := unmarshalCompositeMessage(compositeMessage)
	if parseErr != nil {
		return nil, parseErr
	}

	// Parse the composite header.
	header, headerErr := unmarshalCompositeHeader(headerBytes)
	if headerErr != nil {
		return nil, headerErr
	}

	// Validate ciphertext has at least an HMAC tag.
	if len(authenticatedCiphertext) < HMACSize {
		return nil, &ErrInvalidCompositeMessage{Reason: "ciphertext too short to contain MAC"}
	}

	// Snapshot all mutable state before any mutations.
	snap, snapErr := tr.takeSnapshot()
	if snapErr != nil {
		return nil, snapErr
	}

	plaintext, err := tr.decryptWithSnapshot(header, authenticatedCiphertext, snap)
	if err != nil {
		if restoreErr := tr.restoreSnapshot(snap); restoreErr != nil {
			// Both decrypt and rollback failed: session state is unrecoverable.
			// Destroy remaining snapshot secrets and signal to the caller that
			// this session must be discarded.
			tr.destroySnapshot(snap)
			return nil, &ErrStateCorrupted{DecryptErr: err, RestoreErr: restoreErr}
		}
		tr.destroySnapshot(snap)
		return nil, err
	}

	tr.destroySnapshot(snap)
	return plaintext, nil
}

// decryptWithSnapshot performs the actual decryption on live state.
// On any error, the caller is responsible for restoring the snapshot.
func (tr *TripleRatchet) decryptWithSnapshot(
	header *CompositeHeader,
	authenticatedCiphertext []byte,
	snap *decryptSnapshot,
) ([]byte, error) {
	// Step 1: EC ratchet receive key.
	ecMKBytes, ecErr := tr.ecCipher.ReceiveKey(header.ECHeader)
	if ecErr != nil {
		return nil, &ErrECRatchetFailed{Op: "ReceiveKey", Cause: ecErr}
	}
	ecMK, err := secret.New(ecMKBytes)
	if err != nil { // coverage-exempt: only reachable on locked-memory allocation failure
		return nil, &ErrECRatchetFailed{Op: "ReceiveKey", Cause: err}
	}
	defer ecMK.Destroy()

	// Step 2: Braid SCKA receive.
	var outputKey *mlkembraid.OutputKey
	if header.SCKAMsg != nil {
		var braidErr error
		_, outputKey, braidErr = tr.braid.Receive(header.SCKAMsg)
		if braidErr != nil {
			// During the initial handshake phase, suppress InvalidState and InvalidEpoch
			// errors to tolerate out-of-order initial braid messages. After handshake
			// completes, all braid errors propagate.
			if tr.braidHandshakeComplete {
				return nil, &ErrBraidFailed{Op: "Receive", Cause: braidErr}
			}
		}
	}

	// Copy the output key out of locked memory, since secret.New zeroes its input.
	if outputKey != nil { // coverage-exempt: reachable only in a synchronized bidirectional TripleRatchet session after the full ML-KEM Braid SCKA handshake completes; requires both parties to exchange braid messages in both directions, which is not achievable in unit tests using a simple symmetric EC cipher without a full session-layer implementation
		epochSecretBytes := []byte{}
		_ = outputKey.Key.WithBytes(func(b []byte) error {
			epochSecretBytes = append(epochSecretBytes, b...)
			return nil
		})
		outputKey.Key.Destroy()
		if epochErr := tr.advancePQEpoch(epochSecretBytes); epochErr != nil { // coverage-exempt: only reachable on locked-memory allocation failure
			return nil, epochErr
		}
	}

	// Step 4: derive PQ message key for this counter, handling out-of-order.
	pqMK, pqErr := tr.receivePQKey(header.PQCounter)
	if pqErr != nil {
		return nil, pqErr
	}
	if pqMK != nil {
		defer pqMK.Destroy()
	}

	// pqMK is nil only at epoch 0, counter 0; counters start at 1, so the EC-only branch is defensive.
	var hkeys *HybridKeys
	if pqMK != nil {
		hkeys, err = KDFHybrid(ecMK, pqMK)
	} else { // coverage-exempt: PQCounter==0 at pqEpoch==0 never occurs in normal flow
		hkeys, err = KDFHybridECOnly(ecMK)
	}
	if err != nil { // coverage-exempt: KDFHybrid only fails on nil/destroyed key or locked-memory allocation failure; KDFHybridECOnly branch is dead code (PQCounter==0 never occurs)
		return nil, err
	}
	defer hkeys.Zeroize()

	// Split the authenticated ciphertext.
	ciphertextLen := len(authenticatedCiphertext) - HMACSize
	ciphertext := authenticatedCiphertext[:ciphertextLen]
	receivedMAC := authenticatedCiphertext[ciphertextLen:]

	// Step 6: verify HMAC-SHA256 (constant-time).
	var expectedMAC []byte
	if macErr := hkeys.MacKey.WithBytes(func(key []byte) error {
		expectedMAC = computeHMAC(key, ciphertext)
		return nil
	}); macErr != nil {
		return nil, &ErrDecryptFailed{Cause: macErr}
	}
	if !hmac.Equal(expectedMAC, receivedMAC) {
		return nil, &ErrMACVerificationFailed{}
	}

	// Step 7: AES-256-CBC decrypt.
	var plaintext []byte
	decErr := hkeys.CipherKey.WithBytes(func(key []byte) error {
		return hkeys.IV.WithBytes(func(iv []byte) error {
			var aesErr error
			plaintext, aesErr = cipher.AESCBCDecrypt(key, iv, ciphertext)
			return aesErr
		})
	})
	if decErr != nil { // coverage-exempt: only reachable when ciphertext is not block-aligned after valid MAC; MAC verification above ensures the ciphertext was produced by Encrypt which always PKCS7-pads
		return nil, &ErrDecryptFailed{Cause: decErr}
	}

	return plaintext, nil
}

// advancePQEpoch derives new root and chain keys with spqr.KdfSckaRK (swapped for Bob), resets counters, completes the handshake and purges old skipped keys.
func (tr *TripleRatchet) advancePQEpoch(epochSecret []byte) error {
	epochSec, err := secret.New(epochSecret)
	if err != nil { // coverage-exempt: only reachable on locked-memory allocation failure
		return &ErrSPQRFailed{Op: "advancePQEpoch", Cause: err}
	}
	defer epochSec.Destroy()

	var newRK, newCKs, newCKr *secret.Secret
	kdfErr := epochSec.WithBytes(func(b []byte) error {
		var err error
		newRK, newCKs, newCKr, err = spqr.KdfSckaRK(tr.rootKey, b)
		return err
	})
	if kdfErr != nil {
		return &ErrSPQRFailed{Op: "KdfSckaRK", Cause: kdfErr}
	}

	tr.rootKey.Destroy()
	tr.rootKey = newRK

	tr.sendChain.Destroy()
	tr.recvChain.Destroy()

	if tr.isResponder {
		tr.sendChain = newCKr
		tr.recvChain = newCKs
	} else {
		tr.sendChain = newCKs
		tr.recvChain = newCKr
	}

	tr.pqEpoch++
	tr.sendCounter = 0
	tr.recvCounter = 0
	tr.braidHandshakeComplete = true

	// Purge skipped keys from epochs before the retention window.
	tr.purgeOldSkippedKeys()

	return nil
}

// receivePQKey returns the PQ key for counter: nil at epoch 0 counter 0, a stored skipped key, an error for a consumed counter, or the key ahead within maxPQJump, storing those skipped. Skipped keys are looked up in the current epoch only.
func (tr *TripleRatchet) receivePQKey(counter uint32) (*secret.Secret, error) {
	// Pre-negotiation: no PQ key yet.
	if tr.pqEpoch == 0 && counter == 0 {
		return nil, nil
	}

	// Check for a previously stored skipped key.
	skippedID := pqSkippedKeyID{epoch: tr.pqEpoch, counter: counter}
	if mk, ok := tr.skippedPQKeys[skippedID]; ok {
		delete(tr.skippedPQKeys, skippedID)
		// Trim the FIFO now this entry is stale.
		tr.trimPQFIFOIfNeeded()
		return mk, nil
	}

	// Counter behind or at current position but not in skipped map: already consumed.
	if counter <= tr.recvCounter {
		return nil, &ErrPQKeyConsumed{Counter: counter}
	}

	// Counter too far ahead.
	jump := counter - tr.recvCounter
	if jump > maxPQJump {
		return nil, &ErrPQKeyOutOfRange{Current: tr.recvCounter, Got: counter, Max: maxPQJump}
	}

	// Advance the chain, storing intermediate keys as skipped, until we reach
	// counter-1. Then derive and return the key for counter.
	for tr.recvCounter < counter-1 {
		tr.recvCounter++
		if tr.recvCounter == math.MaxUint32 { // coverage-exempt: dead code — with uint32 counter, the loop terminates when recvCounter reaches counter-1 (at most MaxUint32-1); MaxUint32 is unreachable inside this loop
			return nil, &ErrInvalidInput{Field: "recvCounter", Reason: "counter overflow"}
		}

		mk, nextCK, kdfErr := spqr.KdfSckaCK(tr.recvChain, tr.recvCounter)
		if kdfErr != nil {
			return nil, &ErrSPQRFailed{Op: "KdfSckaCK", Cause: kdfErr}
		}
		tr.recvChain.Destroy()
		tr.recvChain = nextCK

		// At capacity evict the oldest skipped key, as spqr does.
		if len(tr.skippedPQKeys) >= maxSkippedPQKeys {
			tr.evictOldestSkippedPQKey()
		}
		id := pqSkippedKeyID{epoch: tr.pqEpoch, counter: tr.recvCounter}
		tr.skippedPQKeys[id] = mk
		tr.skippedPQKeysFIFO = append(tr.skippedPQKeysFIFO, id)
	}

	// Derive the key for the target counter.
	tr.recvCounter = counter
	mk, nextCK, kdfErr := spqr.KdfSckaCK(tr.recvChain, tr.recvCounter)
	if kdfErr != nil {
		return nil, &ErrSPQRFailed{Op: "KdfSckaCK", Cause: kdfErr}
	}
	tr.recvChain.Destroy()
	tr.recvChain = nextCK

	return mk, nil
}

// purgeOldSkippedKeys drops skipped keys from epochs before the retention window and compacts the FIFO.
func (tr *TripleRatchet) purgeOldSkippedKeys() {
	if tr.pqEpoch <= epochsToKeepPriorToSendEpoch {
		return
	}
	cutoff := tr.pqEpoch - epochsToKeepPriorToSendEpoch
	for k, v := range tr.skippedPQKeys {
		if k.epoch < cutoff {
			v.Destroy()
			delete(tr.skippedPQKeys, k)
		}
	}
	tr.trimPQFIFOIfNeeded()
}

// evictOldestSkippedPQKey evicts the oldest live skipped key in FIFO order, rebuilding the FIFO when it is exhausted, as after a restore.
func (tr *TripleRatchet) evictOldestSkippedPQKey() {
	for tr.skippedPQKeysFIFOHead < len(tr.skippedPQKeysFIFO) {
		id := tr.skippedPQKeysFIFO[tr.skippedPQKeysFIFOHead]
		tr.skippedPQKeysFIFOHead++
		if mk, ok := tr.skippedPQKeys[id]; ok {
			mk.Destroy()
			delete(tr.skippedPQKeys, id)
			tr.compactPQFIFOIfNeeded()
			return
		}
		// Entry already removed — advance past it without evicting.
	}
	// No live entry: rebuild from the map, as after a restore, and retry once.
	tr.rebuildSkippedPQKeysFIFO()
	if tr.skippedPQKeysFIFOHead < len(tr.skippedPQKeysFIFO) {
		id := tr.skippedPQKeysFIFO[tr.skippedPQKeysFIFOHead]
		tr.skippedPQKeysFIFOHead++
		if mk, ok := tr.skippedPQKeys[id]; ok {
			mk.Destroy()
			delete(tr.skippedPQKeys, id)
		}
		tr.compactPQFIFOIfNeeded()
	}
}

// compactPQFIFOIfNeeded advances the head past stale entries and compacts the slice once over half is consumed.
func (tr *TripleRatchet) compactPQFIFOIfNeeded() {
	// Advance head past any stale entries at the front of the FIFO.
	for tr.skippedPQKeysFIFOHead < len(tr.skippedPQKeysFIFO) {
		id := tr.skippedPQKeysFIFO[tr.skippedPQKeysFIFOHead]
		if _, ok := tr.skippedPQKeys[id]; ok {
			break // first live entry found
		}
		tr.skippedPQKeysFIFOHead++
	}
	// Compact the slice when the consumed head exceeds half the slice length.
	if tr.skippedPQKeysFIFOHead > len(tr.skippedPQKeysFIFO)/2 {
		tail := tr.skippedPQKeysFIFO[tr.skippedPQKeysFIFOHead:]
		copy(tr.skippedPQKeysFIFO, tail)
		tr.skippedPQKeysFIFO = tr.skippedPQKeysFIFO[:len(tail)]
		tr.skippedPQKeysFIFOHead = 0
	}
}

// trimPQFIFOIfNeeded compacts the head and rebuilds the FIFO when stale entries exceed twice the live ones, as SPQR.trimFIFOIfNeeded does.
func (tr *TripleRatchet) trimPQFIFOIfNeeded() {
	tr.compactPQFIFOIfNeeded()
	live := len(tr.skippedPQKeysFIFO) - tr.skippedPQKeysFIFOHead
	if live > 2*len(tr.skippedPQKeys)+64 {
		tr.rebuildSkippedPQKeysFIFO()
	}
}

// rebuildSkippedPQKeysFIFO rebuilds the FIFO from skippedPQKeys sorted by (epoch, counter).
func (tr *TripleRatchet) rebuildSkippedPQKeysFIFO() {
	tr.skippedPQKeysFIFO = make([]pqSkippedKeyID, 0, len(tr.skippedPQKeys))
	for id := range tr.skippedPQKeys {
		tr.skippedPQKeysFIFO = append(tr.skippedPQKeysFIFO, id)
	}
	// Insertion sort by (epoch, counter) — skipped-key maps are always small.
	for i := 1; i < len(tr.skippedPQKeysFIFO); i++ {
		key := tr.skippedPQKeysFIFO[i]
		j := i - 1
		for j >= 0 && (tr.skippedPQKeysFIFO[j].epoch > key.epoch ||
			(tr.skippedPQKeysFIFO[j].epoch == key.epoch && tr.skippedPQKeysFIFO[j].counter > key.counter)) {
			tr.skippedPQKeysFIFO[j+1] = tr.skippedPQKeysFIFO[j]
			j--
		}
		tr.skippedPQKeysFIFO[j+1] = key
	}
	tr.skippedPQKeysFIFOHead = 0
}

// takeSnapshot captures a deep copy of all mutable TripleRatchet state.
func (tr *TripleRatchet) takeSnapshot() (*decryptSnapshot, error) {
	braidData, err := snapshotBraid(tr.braid)
	if err != nil { // coverage-exempt: Braid.Serialize only fails when braid.state is nil, which cannot occur after a valid NewAlice/NewBob initialization
		return nil, &ErrBraidFailed{Op: "Serialize", Cause: err}
	}

	rkClone, err := tr.rootKey.Clone()
	if err != nil { // coverage-exempt: only reachable on locked-memory allocation failure
		return nil, &ErrSPQRFailed{Op: "takeSnapshot(rootKey)", Cause: err}
	}

	scClone, err := tr.sendChain.Clone()
	if err != nil { // coverage-exempt: only reachable on locked-memory allocation failure
		rkClone.Destroy()
		return nil, &ErrSPQRFailed{Op: "takeSnapshot(sendChain)", Cause: err}
	}

	rcClone, err := tr.recvChain.Clone()
	if err != nil { // coverage-exempt: only reachable on locked-memory allocation failure
		rkClone.Destroy()
		scClone.Destroy()
		return nil, &ErrSPQRFailed{Op: "takeSnapshot(recvChain)", Cause: err}
	}

	// Deep-copy the skipped keys map.
	skippedCopy := make(map[pqSkippedKeyID]*secret.Secret, len(tr.skippedPQKeys))
	for k, v := range tr.skippedPQKeys {
		clone, cloneErr := v.Clone()
		if cloneErr != nil { // coverage-exempt: only reachable on locked-memory allocation failure; cleanup loop and return are unreachable in normal operation
			rkClone.Destroy()
			scClone.Destroy()
			rcClone.Destroy()
			for _, s := range skippedCopy {
				s.Destroy()
			}
			return nil, &ErrSPQRFailed{Op: "takeSnapshot(skippedPQKeys)", Cause: cloneErr}
		}
		skippedCopy[k] = clone
	}

	snap := &decryptSnapshot{
		braidData:     braidData,
		rootKey:       rkClone,
		sendChainKey:  scClone,
		recvChainKey:  rcClone,
		sendCounter:   tr.sendCounter,
		recvCounter:   tr.recvCounter,
		pqEpoch:       tr.pqEpoch,
		handshakeDone: tr.braidHandshakeComplete,
		skippedPQKeys: skippedCopy,
	}

	// Snapshot EC state if the cipher supports it.
	if snapshotable, ok := tr.ecCipher.(ECCipherSnapshotable); ok {
		ecSnap, ecErr := snapshotable.TakeECSnapshot()
		if ecErr != nil {
			tr.destroySnapshot(snap)
			return nil, &ErrECRatchetFailed{Op: "TakeECSnapshot", Cause: ecErr}
		}
		snap.ecSnapshot = ecSnap
	}

	return snap, nil
}

// restoreSnapshot restores all mutable state from snap, returning an error only when the braid or EC restore fails; key material is always restored.
func (tr *TripleRatchet) restoreSnapshot(snap *decryptSnapshot) error {
	// Attempt braid restore. On failure, continue restoring key material so
	// the session is in the most consistent state possible; report the error
	// at the end.
	var restoreErr error
	braid, braidErr := restoreBraid(snap.braidData)
	if braidErr != nil {
		restoreErr = &ErrBraidFailed{Op: "restoreBraid", Cause: braidErr}
	} else {
		tr.braid = braid
	}

	// Restore key material, destroying current values first.
	tr.rootKey.Destroy()
	tr.rootKey = snap.rootKey
	snap.rootKey = nil

	tr.sendChain.Destroy()
	tr.sendChain = snap.sendChainKey
	snap.sendChainKey = nil

	tr.recvChain.Destroy()
	tr.recvChain = snap.recvChainKey
	snap.recvChainKey = nil

	tr.sendCounter = snap.sendCounter
	tr.recvCounter = snap.recvCounter
	tr.pqEpoch = snap.pqEpoch
	tr.braidHandshakeComplete = snap.handshakeDone

	// Restore skipped keys, destroying current values first.
	for _, v := range tr.skippedPQKeys {
		v.Destroy()
	}
	tr.skippedPQKeys = snap.skippedPQKeys
	snap.skippedPQKeys = nil
	// Reset the FIFO; the next eviction rebuilds it.
	tr.skippedPQKeysFIFO = nil
	tr.skippedPQKeysFIFOHead = 0

	// Restore EC state if available.
	if snap.ecSnapshot != nil {
		if snapshotable, ok := tr.ecCipher.(ECCipherSnapshotable); ok {
			if ecErr := snapshotable.RestoreECSnapshot(snap.ecSnapshot); ecErr != nil && restoreErr == nil {
				restoreErr = &ErrECRatchetFailed{Op: "RestoreECSnapshot", Cause: ecErr}
			}
		}
	}

	return restoreErr
}

// destroySnapshot zeroizes every secret in a snapshot after a successful decrypt.
func (tr *TripleRatchet) destroySnapshot(snap *decryptSnapshot) {
	if snap.rootKey != nil {
		snap.rootKey.Destroy()
		snap.rootKey = nil
	}
	if snap.sendChainKey != nil {
		snap.sendChainKey.Destroy()
		snap.sendChainKey = nil
	}
	if snap.recvChainKey != nil {
		snap.recvChainKey.Destroy()
		snap.recvChainKey = nil
	}
	for _, v := range snap.skippedPQKeys {
		v.Destroy()
	}
	snap.skippedPQKeys = nil

	// Zero the serialized Braid state before releasing the reference so the
	// backing array does not contain plaintext session material on the heap.
	clear(snap.braidData)
	snap.braidData = nil

	// Zero the serialized EC ratchet snapshot for the same reason.
	clear(snap.ecSnapshot)
	snap.ecSnapshot = nil
}

// computeHMAC computes an HMAC-SHA256 tag over data using key.
func computeHMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
