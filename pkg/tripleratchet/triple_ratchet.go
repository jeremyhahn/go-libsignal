package tripleratchet

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// compositeMessageMinSize is the minimum size of a serialized composite message:
	// 4 bytes header length + compositeHeaderMinSize + 4 bytes ciphertext length.
	compositeMessageMinSize = 8

	// headerLenPrefixSize is the byte size of the header length prefix.
	headerLenPrefixSize = 4

	// ciphertextLenPrefixSize is the byte size of the ciphertext length prefix.
	ciphertextLenPrefixSize = 4

	// HMACSize is the size of the HMAC-SHA256 authentication tag in bytes.
	HMACSize = sha256.Size

	// maxCompositeComponentLen is the maximum allowed length for header or
	// ciphertext components in a composite message (64 MiB).
	maxCompositeComponentLen = 64 * 1024 * 1024
)

// ECCipher abstracts the EC Double Ratchet encrypt/decrypt operations.
// This allows testing with mock implementations and decouples the Triple
// Ratchet from the concrete session.Cipher type.
type ECCipher interface {
	// SendKey advances the EC Double Ratchet send chain and returns the
	// serialized EC header and message key bytes without performing
	// encryption. This avoids wasting CPU on a ciphertext that the Triple
	// Ratchet discards in favor of its own hybrid-key encryption.
	SendKey() (ecHeader []byte, messageKey []byte, err error)

	// ReceiveKey advances the EC Double Ratchet receive chain using only the
	// EC header (no ciphertext) and returns the derived message key.
	// This mirrors SendKey on the receive side: the Triple Ratchet does not
	// produce EC ciphertext, so there is nothing for the EC cipher to
	// decrypt. Passing composite ciphertext to DecryptGetKey would be
	// incorrect because the EC cipher cannot parse hybrid-encrypted data.
	ReceiveKey(ecHeader []byte) (messageKey []byte, err error)

	// EncryptGetKey encrypts plaintext and returns the ciphertext body,
	// the serialized EC header, and the message key bytes used.
	EncryptGetKey(plaintext []byte) (ciphertext []byte, ecHeader []byte, messageKey []byte, err error)

	// DecryptGetKey decrypts using the provided EC header bytes and
	// ciphertext body, returning plaintext and the message key used.
	DecryptGetKey(ecHeader []byte, ciphertext []byte) (plaintext []byte, messageKey []byte, err error)
}

// ECCipherSnapshotable is an optional interface that ECCipher implementations
// can provide to support atomic rollback of EC ratchet state on Decrypt
// failure. When the ECCipher implements this interface, the Triple Ratchet
// snapshots EC state before ReceiveKey and restores it if MAC verification
// or any subsequent step fails. Without this interface, a forged message with
// a valid-looking EC header can permanently advance the EC receive chain.
type ECCipherSnapshotable interface {
	// TakeECSnapshot serializes the current EC ratchet state for later
	// restoration. The returned bytes are opaque to the caller.
	TakeECSnapshot() ([]byte, error)

	// RestoreECSnapshot restores the EC ratchet state from a previous
	// snapshot, discarding any mutations made since the snapshot was taken.
	RestoreECSnapshot(data []byte) error
}

// maxSkippedPQKeys is the maximum number of out-of-order PQ message keys
// to retain. Matches the SPQR maxSkippedKeys constant.
const maxSkippedPQKeys = 2000

// maxPQJump is the maximum allowed forward jump in PQ counters.
// Prevents DoS via memory exhaustion from a malicious counter value.
// Matches the SPQR maxJump constant (Rust default: 25000).
const maxPQJump = 25000

// epochsToKeepPriorToSendEpoch controls how many prior epochs' skipped keys
// are retained during epoch advancement. Matches Rust's
// EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH = 1.
const epochsToKeepPriorToSendEpoch = 1

// pqSkippedKeyID uniquely identifies a skipped PQ message key by both its
// epoch and counter. This prevents cross-epoch collisions where different
// epochs could produce keys at the same counter value.
type pqSkippedKeyID struct {
	Epoch   uint64
	Counter uint32
}

// TripleRatchet combines the EC Double Ratchet with the Sparse PQ Ratchet
// (via the ML-KEM Braid SCKA protocol) to provide hybrid EC+PQ forward secrecy.
//
// Each message is encrypted using keys derived from both the EC ratchet and the
// PQ ratchet via KDF_HYBRID. The PQ chain epoch advances when the Braid SCKA
// produces an output key, which is fed into KdfSckaRK to derive new root and
// chain keys (matching Rust's Chain.add_epoch behavior).
//
// All sensitive key material is stored in memguard-backed Secrets that are
// protected from swap and zeroized on destruction.
type TripleRatchet struct {
	ecCipher ECCipher
	braid    *mlkembraid.Braid

	// rootKey holds the current SPQR root key, used as the salt when deriving
	// new epoch chain keys via KdfSckaRK. Matches Rust Chain.next_root.
	rootKey *secret.Secret

	// sendChainKey and recvChainKey hold the current epoch's per-message chain keys
	// for the SPQR layer, backed by memguard protected memory.
	sendChainKey *secret.Secret
	recvChainKey *secret.Secret

	// sendCounter and recvCounter track the number of messages sent/received
	// within the current SPQR chain epoch, used as input to KdfSckaCK.
	sendCounter uint32
	recvCounter uint32

	// pqEpoch tracks the current PQ chain epoch, incremented when the Braid
	// produces an output key and KdfSckaRK advances the chain.
	pqEpoch uint64

	// isResponder indicates whether this party is Bob (the responder).
	// When true, send/recv chain keys are swapped relative to KdfSckaRK output,
	// matching Rust's Chain direction (A2B vs B2A).
	isResponder bool

	// braidHandshakeComplete is set to true once the first successful Braid
	// epoch advancement occurs. After that, Braid errors are no longer
	// suppressed as handshake errors -- they indicate real protocol failures
	// and must not silently downgrade to EC-only security.
	braidHandshakeComplete bool

	// skippedPQKeys stores PQ message keys derived when the receiver skips
	// ahead to handle an out-of-order message. Keyed by epoch + counter
	// to prevent cross-epoch collisions.
	skippedPQKeys map[pqSkippedKeyID]*secret.Secret
}

// NewAlice creates a Triple Ratchet for the session initiator (Alice).
// The ecCipher handles EC Double Ratchet operations. The sharedSecret and
// KEM implementation initialize the ML-KEM Braid for PQ key agreement.
func NewAlice(ecCipher ECCipher, sharedSecret []byte, kemImpl mlkembraid.IncrementalKEM, chunkSize int) (*TripleRatchet, error) {
	if ecCipher == nil {
		return nil, &ErrInvalidInput{Field: "ecCipher", Reason: "must not be nil"}
	}
	if len(sharedSecret) == 0 {
		return nil, &ErrInvalidInput{Field: "sharedSecret", Reason: "must not be empty"}
	}
	if kemImpl == nil {
		return nil, &ErrInvalidInput{Field: "kemImpl", Reason: "must not be nil"}
	}

	braid, err := mlkembraid.InitAlice(sharedSecret, kemImpl, chunkSize)
	if err != nil {
		return nil, &ErrSPQRFailed{Op: "InitAlice", Err: err}
	}

	// Initialize SPQR chain keys from the shared secret.
	// KdfSckaInit returns *secret.Secret values directly.
	rk, cks, ckr, err := spqr.KdfSckaInit(sharedSecret)
	if err != nil {
		return nil, &ErrSPQRFailed{Op: "KdfSckaInit", Err: err}
	}

	return &TripleRatchet{
		ecCipher:      ecCipher,
		braid:         braid,
		rootKey:       rk,
		sendChainKey:  cks,
		recvChainKey:  ckr,
		skippedPQKeys: make(map[pqSkippedKeyID]*secret.Secret),
	}, nil
}

// NewBob creates a Triple Ratchet for the session responder (Bob).
// The ecCipher handles EC Double Ratchet operations. The sharedSecret and
// KEM implementation initialize the ML-KEM Braid for PQ key agreement.
func NewBob(ecCipher ECCipher, sharedSecret []byte, kemImpl mlkembraid.IncrementalKEM, chunkSize int) (*TripleRatchet, error) {
	if ecCipher == nil {
		return nil, &ErrInvalidInput{Field: "ecCipher", Reason: "must not be nil"}
	}
	if len(sharedSecret) == 0 {
		return nil, &ErrInvalidInput{Field: "sharedSecret", Reason: "must not be empty"}
	}
	if kemImpl == nil {
		return nil, &ErrInvalidInput{Field: "kemImpl", Reason: "must not be nil"}
	}

	braid, err := mlkembraid.InitBob(sharedSecret, kemImpl, chunkSize)
	if err != nil {
		return nil, &ErrSPQRFailed{Op: "InitBob", Err: err}
	}

	// Initialize SPQR chain keys from the shared secret.
	// Bob's send/recv are swapped relative to Alice.
	// KdfSckaInit returns *secret.Secret values directly.
	rk, cks, ckr, err := spqr.KdfSckaInit(sharedSecret)
	if err != nil {
		return nil, &ErrSPQRFailed{Op: "KdfSckaInit", Err: err}
	}

	// Bob's send = Alice's recv (ckr), Bob's recv = Alice's send (cks).
	return &TripleRatchet{
		ecCipher:      ecCipher,
		braid:         braid,
		rootKey:       rk,
		sendChainKey:  ckr,
		recvChainKey:  cks,
		isResponder:   true,
		skippedPQKeys: make(map[pqSkippedKeyID]*secret.Secret),
	}, nil
}

// Encrypt produces a composite message with both EC and PQ components.
//
// The encryption flow:
//  1. Advance the EC Double Ratchet to get an EC message key and header.
//  2. Advance the SPQR (Braid) to get a PQ message and optional output key.
//  3. Derive a per-message PQ key from the send chain.
//  4. Combine EC and PQ keys via KDF_HYBRID.
//  5. Encrypt plaintext with the combined keys.
//  6. Serialize composite header + ciphertext into the output message.
func (tr *TripleRatchet) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, &ErrInvalidInput{Field: "plaintext", Reason: "must not be empty"}
	}

	// Step 1: Get EC message key and header from the Double Ratchet.
	// We use SendKey instead of EncryptGetKey to avoid wasting CPU on a
	// ciphertext that is immediately discarded -- the Triple Ratchet
	// re-encrypts with hybrid keys below.
	ecHeader, ecMK, err := tr.ecCipher.SendKey()
	if err != nil {
		return nil, &ErrECRatchetFailed{Op: "Encrypt", Err: err}
	}

	// Step 2: Advance the Braid SCKA protocol.
	sckaMsg, _, outputKey, err := tr.braid.Send()
	if err != nil {
		return nil, &ErrSPQRFailed{Op: "Send", Err: err}
	}

	// If the Braid produced an output key, advance the PQ chain epoch.
	// This matches Rust's chain.add_epoch(epoch_secret) which calls
	// KdfSckaRK(next_root, epoch_secret) to derive new root + chain keys.
	if outputKey != nil && outputKey.Key != nil {
		epochSecret := copyBytes(outputKey.Key.Bytes())
		outputKey.Key.Destroy()

		advanceErr := tr.advancePQEpoch(epochSecret)
		for i := range epochSecret {
			epochSecret[i] = 0
		}
		if advanceErr != nil {
			return nil, advanceErr
		}
	}

	// Step 3: Derive a per-message PQ key from the send chain.
	// Increment counter before use so the first key is at index 1,
	// matching the SPQR convention.
	if tr.sendCounter == math.MaxUint32 {
		return nil, &ErrSPQRFailed{Op: "Encrypt", Err: &ErrInvalidInput{Field: "sendCounter", Reason: "counter overflow"}}
	}
	tr.sendCounter++
	pqCounter := tr.sendCounter

	// KdfSckaCK takes *secret.Secret and returns *secret.Secret values.
	pqMK, nextChainKey, kdfErr := spqr.KdfSckaCK(tr.sendChainKey, pqCounter)
	if kdfErr != nil {
		return nil, kdfErr
	}
	tr.sendChainKey.Destroy()
	tr.sendChainKey = nextChainKey

	// Step 4: Combine EC and PQ keys.
	// When pqMK is nil (epoch-0, counter-0 pre-negotiation state), fall back
	// to EC-only key derivation matching Rust's behavior where the PQ
	// contribution is None.
	var hybridKeys *HybridKeys
	if pqMK == nil {
		hybridKeys, err = KDFHybridECOnly(ecMK)
	} else {
		hybridKeys, err = KDFHybrid(ecMK, pqMK.Bytes())
		pqMK.Destroy()
	}
	// Zeroize raw EC message key.
	crypto.Zeroize(ecMK)
	if err != nil {
		return nil, err
	}
	defer hybridKeys.Zeroize()

	// Step 5: Encrypt plaintext with hybrid keys using AES-CBC.
	encryptedPayload, err := cipher.Encrypt(hybridKeys.IV.Bytes(), hybridKeys.CipherKey.Bytes(), plaintext)
	if err != nil {
		return nil, &ErrECRatchetFailed{Op: "Encrypt/AES", Err: err}
	}

	// Step 5b: Compute HMAC-SHA256 over the encrypted payload for Encrypt-then-MAC.
	mac := computeHMAC(hybridKeys.MacKey.Bytes(), encryptedPayload)

	// Compose authenticated ciphertext: encrypted_payload || mac(32 bytes).
	ciphertext := make([]byte, len(encryptedPayload)+HMACSize)
	copy(ciphertext, encryptedPayload)
	copy(ciphertext[len(encryptedPayload):], mac)

	// Step 6: Build composite message with PQ counter for out-of-order support.
	header := &CompositeHeader{
		ECHeader:  ecHeader,
		PQCounter: pqCounter,
		SCKAMsg:   sckaMsg,
	}

	return serializeCompositeMessage(header, ciphertext)
}

// decryptSnapshot captures all mutable state before Decrypt begins, enabling
// rollback on MAC failure to prevent state corruption from forged messages.
// Both PQ and EC ratchet state are captured when the ECCipher supports
// snapshotting (implements ECCipherSnapshotable).
type decryptSnapshot struct {
	braidData              []byte
	rootKey                *secret.Secret
	sendChainKey           *secret.Secret
	recvChainKey           *secret.Secret
	sendCounter            uint32
	recvCounter            uint32
	pqEpoch                uint64
	braidHandshakeComplete bool
	skippedPQKeys          map[pqSkippedKeyID]*secret.Secret

	// ecData holds the serialized EC ratchet state captured before ReceiveKey.
	// Non-nil only when the ECCipher implements ECCipherSnapshotable.
	ecData []byte
}

// takeSnapshot captures the current mutable PQ and EC state for potential rollback.
func (tr *TripleRatchet) takeSnapshot() (*decryptSnapshot, error) {
	braidData, err := tr.braid.Serialize()
	if err != nil {
		return nil, &ErrSPQRFailed{Op: "takeSnapshot/braid", Err: err}
	}

	// Snapshot EC state if the cipher supports it.
	var ecData []byte
	if snapshotable, ok := tr.ecCipher.(ECCipherSnapshotable); ok {
		ecData, err = snapshotable.TakeECSnapshot()
		if err != nil {
			return nil, &ErrECRatchetFailed{Op: "takeSnapshot", Err: err}
		}
	}

	rk, err := tr.rootKey.Clone()
	if err != nil {
		return nil, &ErrSPQRFailed{Op: "takeSnapshot/rootKey", Err: err}
	}
	sck, err := tr.sendChainKey.Clone()
	if err != nil {
		rk.Destroy()
		return nil, &ErrSPQRFailed{Op: "takeSnapshot/sendChainKey", Err: err}
	}
	rck, err := tr.recvChainKey.Clone()
	if err != nil {
		rk.Destroy()
		sck.Destroy()
		return nil, &ErrSPQRFailed{Op: "takeSnapshot/recvChainKey", Err: err}
	}

	// Deep copy the skipped keys map.
	skippedCopy := make(map[pqSkippedKeyID]*secret.Secret, len(tr.skippedPQKeys))
	for id, mk := range tr.skippedPQKeys {
		cloned, cloneErr := mk.Clone()
		if cloneErr != nil {
			// Clean up already-cloned keys and snapshot secrets.
			for _, c := range skippedCopy {
				c.Destroy()
			}
			rk.Destroy()
			sck.Destroy()
			rck.Destroy()
			return nil, &ErrSPQRFailed{Op: "takeSnapshot/skippedKeys", Err: cloneErr}
		}
		skippedCopy[id] = cloned
	}

	return &decryptSnapshot{
		braidData:              braidData,
		rootKey:                rk,
		sendChainKey:           sck,
		recvChainKey:           rck,
		sendCounter:            tr.sendCounter,
		recvCounter:            tr.recvCounter,
		pqEpoch:                tr.pqEpoch,
		braidHandshakeComplete: tr.braidHandshakeComplete,
		skippedPQKeys:          skippedCopy,
		ecData:                 ecData,
	}, nil
}

// restoreSnapshot restores the mutable PQ and EC state from a snapshot,
// destroying the current state. The snapshot is consumed and must not be
// used afterward.
func (tr *TripleRatchet) restoreSnapshot(snap *decryptSnapshot) error {
	// Restore braid from serialized data.
	restoredBraid, err := mlkembraid.DeserializeBraid(snap.braidData)
	if err != nil {
		return &ErrSPQRFailed{Op: "restoreSnapshot/braid", Err: err}
	}

	// Restore EC state if a snapshot was captured.
	if snap.ecData != nil {
		if snapshotable, ok := tr.ecCipher.(ECCipherSnapshotable); ok {
			if restoreErr := snapshotable.RestoreECSnapshot(snap.ecData); restoreErr != nil {
				restoredBraid.Zeroize()
				return &ErrECRatchetFailed{Op: "restoreSnapshot", Err: restoreErr}
			}
		}
	}

	// Destroy current state.
	tr.braid.Zeroize()
	tr.rootKey.Destroy()
	tr.sendChainKey.Destroy()
	tr.recvChainKey.Destroy()
	for id, mk := range tr.skippedPQKeys {
		mk.Destroy()
		delete(tr.skippedPQKeys, id)
	}

	// Install snapshot state.
	tr.braid = restoredBraid
	tr.rootKey = snap.rootKey
	tr.sendChainKey = snap.sendChainKey
	tr.recvChainKey = snap.recvChainKey
	tr.sendCounter = snap.sendCounter
	tr.recvCounter = snap.recvCounter
	tr.pqEpoch = snap.pqEpoch
	tr.braidHandshakeComplete = snap.braidHandshakeComplete
	tr.skippedPQKeys = snap.skippedPQKeys

	return nil
}

// destroySnapshot cleans up a snapshot that is no longer needed (successful path).
func destroySnapshot(snap *decryptSnapshot) {
	if snap == nil {
		return
	}
	snap.rootKey.Destroy()
	snap.sendChainKey.Destroy()
	snap.recvChainKey.Destroy()
	for id, mk := range snap.skippedPQKeys {
		mk.Destroy()
		delete(snap.skippedPQKeys, id)
	}
	// Zeroize serialized braid data.
	for i := range snap.braidData {
		snap.braidData[i] = 0
	}
	// Zeroize serialized EC state data.
	for i := range snap.ecData {
		snap.ecData[i] = 0
	}
}

// Decrypt processes a composite message using both the EC and PQ ratchets.
//
// The decryption flow:
//  1. Parse the composite header and ciphertext from the message.
//  2. Snapshot mutable PQ and EC state for rollback on failure.
//  3. Use the EC header to get the EC message key from the Double Ratchet.
//  4. Process the SCKA message through the Braid.
//  5. Derive a per-message PQ key from the receive chain.
//  6. Combine EC and PQ keys via KDF_HYBRID.
//  7. Decrypt the ciphertext with the combined keys.
//
// On MAC verification failure, both PQ and EC state are rolled back to the
// snapshot to prevent state corruption from forged messages. EC rollback
// requires the ECCipher to implement ECCipherSnapshotable.
func (tr *TripleRatchet) Decrypt(compositeMessage []byte) ([]byte, error) {
	if len(compositeMessage) == 0 {
		return nil, &ErrInvalidInput{Field: "compositeMessage", Reason: "must not be empty"}
	}

	// Step 1: Parse composite message.
	header, ciphertext, err := deserializeCompositeMessage(compositeMessage)
	if err != nil {
		return nil, err
	}

	// Step 2: Snapshot PQ and EC state before any mutations for rollback on failure.
	snap, err := tr.takeSnapshot()
	if err != nil {
		return nil, err
	}

	// Step 3: Get EC message key from the Double Ratchet.
	// Use ReceiveKey (not DecryptGetKey) because the Triple Ratchet
	// encrypts with hybrid keys -- there is no EC ciphertext body.
	// Passing the composite ciphertext to DecryptGetKey would be incorrect
	// since the EC cipher cannot parse hybrid-encrypted data.
	ecMK, err := tr.ecCipher.ReceiveKey(header.ECHeader)
	if err != nil {
		destroySnapshot(snap)
		return nil, &ErrECRatchetFailed{Op: "Decrypt", Err: err}
	}

	// Step 4: Process SCKA message through the Braid.
	// Propagate errors from Braid.Receive, except for expected state
	// machine errors during early handshake (ErrInvalidState, ErrInvalidEpoch)
	// which indicate the Braid is not yet ready to process messages.
	_, outputKey, braidErr := tr.braid.Receive(header.SCKAMsg)
	if braidErr != nil {
		// Once the Braid handshake has completed (first epoch key produced),
		// all Braid errors are real failures. Only suppress handshake errors
		// during the initial negotiation phase; after that, propagate them
		// to prevent silent downgrade to EC-only security.
		if tr.braidHandshakeComplete || !isBraidHandshakeError(braidErr) {
			destroySnapshot(snap)
			return nil, &ErrSPQRFailed{Op: "Receive", Err: braidErr}
		}
		// Expected handshake state: Braid not ready yet, continue with
		// current chain keys (no epoch advancement).
	}

	// If the Braid produced an output key, advance the PQ chain epoch.
	if braidErr == nil && outputKey != nil && outputKey.Key != nil {
		epochSecret := copyBytes(outputKey.Key.Bytes())
		outputKey.Key.Destroy()

		advanceErr := tr.advancePQEpoch(epochSecret)
		for i := range epochSecret {
			epochSecret[i] = 0
		}
		if advanceErr != nil {
			destroySnapshot(snap)
			return nil, advanceErr
		}
	}

	// Step 5: Derive a per-message PQ key from the receive chain.
	// Use the PQ counter from the header to support out-of-order messages.
	// If the counter is ahead of our current position, skip forward and
	// store intermediate keys (matching SPQR's out-of-order behavior).
	pqCounter := header.PQCounter
	pqMK, skipErr := tr.receivePQKey(pqCounter)
	if skipErr != nil {
		destroySnapshot(snap)
		return nil, skipErr
	}

	// Step 6: Combine EC and PQ keys.
	// When pqMK is nil (epoch-0, counter-0 pre-negotiation state), fall back
	// to EC-only key derivation matching Rust's behavior.
	var hybridKeys *HybridKeys
	if pqMK == nil {
		hybridKeys, err = KDFHybridECOnly(ecMK)
	} else {
		hybridKeys, err = KDFHybrid(ecMK, pqMK.Bytes())
		pqMK.Destroy()
	}
	// Zeroize raw EC message key.
	crypto.Zeroize(ecMK)
	if err != nil {
		destroySnapshot(snap)
		return nil, err
	}
	defer hybridKeys.Zeroize()

	// Step 7: Verify HMAC and decrypt with hybrid keys.
	// The ciphertext format is: encrypted_payload || mac(32 bytes).
	if len(ciphertext) < HMACSize {
		destroySnapshot(snap)
		return nil, &ErrInvalidCompositeMessage{Reason: "ciphertext too short for MAC"}
	}

	splitPoint := len(ciphertext) - HMACSize
	encryptedPayload := ciphertext[:splitPoint]
	receivedMAC := ciphertext[splitPoint:]

	// Verify HMAC-SHA256 using constant-time comparison.
	expectedMAC := computeHMAC(hybridKeys.MacKey.Bytes(), encryptedPayload)
	if !hmac.Equal(receivedMAC, expectedMAC) {
		// MAC failure: rollback PQ state to prevent state corruption
		// from forged messages.
		if restoreErr := tr.restoreSnapshot(snap); restoreErr != nil {
			// Restore failed -- state is inconsistent. Return the original
			// MAC error wrapped with the restore failure context.
			return nil, &ErrSPQRFailed{Op: "Decrypt/rollback", Err: restoreErr}
		}
		return nil, &ErrMACVerificationFailed{}
	}

	// MAC verified. Attempt AES decryption before committing state -- if
	// decryption fails (e.g., PKCS7 unpad error) we must roll back.
	pt, err := cipher.Decrypt(hybridKeys.IV.Bytes(), hybridKeys.CipherKey.Bytes(), encryptedPayload)
	if err != nil {
		// AES decryption failed: rollback state to prevent corruption.
		if restoreErr := tr.restoreSnapshot(snap); restoreErr != nil {
			return nil, &ErrSPQRFailed{Op: "Decrypt/AES-rollback", Err: restoreErr}
		}
		return nil, &ErrECRatchetFailed{Op: "Decrypt/AES", Err: err}
	}

	// All operations succeeded -- commit the state mutations and discard the snapshot.
	destroySnapshot(snap)

	return pt, nil
}

// receivePQKey derives the PQ message key for the given counter, supporting
// out-of-order delivery. If the counter is ahead of the current receive
// position, intermediate keys are stored in skippedPQKeys. If a previously
// skipped key is requested, it is returned and removed from the map.
func (tr *TripleRatchet) receivePQKey(counter uint32) (*secret.Secret, error) {
	// Epoch-0, counter-0 represents the pre-negotiation state where no PQ key
	// is available yet. Return nil to signal EC-only encryption, matching Rust
	// behavior where msg_key_epoch=0 && index=0 returns an empty key.
	if tr.pqEpoch == 0 && counter == 0 {
		return nil, nil
	}

	// Check skipped keys first (out-of-order message).
	keyID := pqSkippedKeyID{Epoch: tr.pqEpoch, Counter: counter}
	if mk, ok := tr.skippedPQKeys[keyID]; ok {
		delete(tr.skippedPQKeys, keyID)
		return mk, nil
	}

	// Counter must be ahead of our current position.
	if counter != 0 && counter <= tr.recvCounter {
		return nil, &ErrSPQRFailed{
			Op:  "receivePQKey",
			Err: &ErrInvalidInput{Field: "PQCounter", Reason: "counter already consumed"},
		}
	}

	// Enforce maximum forward jump to prevent DoS via memory exhaustion.
	if counter > tr.recvCounter && counter-tr.recvCounter > maxPQJump {
		return nil, &ErrSPQRFailed{
			Op:  "receivePQKey",
			Err: &ErrInvalidInput{Field: "PQCounter", Reason: "forward jump exceeds maximum"},
		}
	}

	// Skip forward, storing intermediate keys.
	for tr.recvCounter+1 < counter {
		if uint32(len(tr.skippedPQKeys)) >= maxSkippedPQKeys {
			return nil, &ErrSPQRFailed{
				Op:  "receivePQKey",
				Err: &ErrInvalidInput{Field: "PQCounter", Reason: "too many skipped PQ keys"},
			}
		}
		if tr.recvCounter == math.MaxUint32 {
			return nil, &ErrSPQRFailed{Op: "Decrypt", Err: &ErrInvalidInput{Field: "recvCounter", Reason: "counter overflow"}}
		}
		tr.recvCounter++
		mk, nextCK, kdfErr := spqr.KdfSckaCK(tr.recvChainKey, tr.recvCounter)
		if kdfErr != nil {
			return nil, kdfErr
		}
		tr.recvChainKey.Destroy()
		tr.recvChainKey = nextCK
		skippedID := pqSkippedKeyID{Epoch: tr.pqEpoch, Counter: tr.recvCounter}
		tr.skippedPQKeys[skippedID] = mk
	}

	// Derive the requested key.
	if tr.recvCounter == math.MaxUint32 {
		return nil, &ErrSPQRFailed{Op: "Decrypt", Err: &ErrInvalidInput{Field: "recvCounter", Reason: "counter overflow"}}
	}
	tr.recvCounter++
	mk, nextCK, kdfErr := spqr.KdfSckaCK(tr.recvChainKey, tr.recvCounter)
	if kdfErr != nil {
		return nil, kdfErr
	}
	tr.recvChainKey.Destroy()
	tr.recvChainKey = nextCK
	return mk, nil
}

// Epoch returns the current SPQR/Braid epoch.
func (tr *TripleRatchet) Epoch() uint64 {
	return tr.braid.Epoch()
}

// Zeroize clears all sensitive key material from the Triple Ratchet state.
// All memguard-backed Secrets are destroyed, releasing their guarded memory.
func (tr *TripleRatchet) Zeroize() {
	if tr.rootKey != nil {
		tr.rootKey.Destroy()
	}
	if tr.sendChainKey != nil {
		tr.sendChainKey.Destroy()
	}
	if tr.recvChainKey != nil {
		tr.recvChainKey.Destroy()
	}
	for keyID, mk := range tr.skippedPQKeys {
		mk.Destroy()
		delete(tr.skippedPQKeys, keyID)
	}
	tr.braid.Zeroize()
}

// advancePQEpoch advances the PQ chain to a new epoch using the given
// epoch secret from the Braid. This matches Rust's Chain.add_epoch() which
// calls KdfSckaRK(next_root, epoch_secret) to derive:
//   - A new root key (retained for the next epoch advancement)
//   - New send and recv chain keys (replacing the current ones)
//
// Counters and skipped keys are reset for the new epoch.
func (tr *TripleRatchet) advancePQEpoch(epochSecret []byte) error {
	newRK, newCKs, newCKr, err := spqr.KdfSckaRK(tr.rootKey, epochSecret)
	if err != nil {
		return &ErrSPQRFailed{Op: "advancePQEpoch", Err: err}
	}

	// Destroy old keys.
	tr.rootKey.Destroy()
	tr.sendChainKey.Destroy()
	tr.recvChainKey.Destroy()

	// Install new epoch keys. The responder (Bob) swaps send/recv chain
	// keys, matching Rust's Chain direction handling where A2B gets
	// send=CKs,recv=CKr and B2A gets send=CKr,recv=CKs.
	tr.rootKey = newRK
	if tr.isResponder {
		tr.sendChainKey = newCKr
		tr.recvChainKey = newCKs
	} else {
		tr.sendChainKey = newCKs
		tr.recvChainKey = newCKr
	}

	// Mark the Braid handshake as complete once the first epoch key is produced.
	// After this point, Braid errors will no longer be suppressed.
	tr.braidHandshakeComplete = true

	// Reset counters for the new epoch.
	tr.sendCounter = 0
	tr.recvCounter = 0
	tr.pqEpoch++

	// Purge skipped keys from epochs older than the retention window.
	// Rust keeps EPOCHS_TO_KEEP_PRIOR_TO_SEND_EPOCH = 1 epoch of skipped
	// keys, so we only destroy keys from epochs strictly before
	// (newEpoch - epochsToKeepPriorToSendEpoch).
	minRetainEpoch := uint64(0)
	if tr.pqEpoch > epochsToKeepPriorToSendEpoch {
		minRetainEpoch = tr.pqEpoch - epochsToKeepPriorToSendEpoch
	}
	for keyID, mk := range tr.skippedPQKeys {
		if keyID.Epoch < minRetainEpoch {
			mk.Destroy()
			delete(tr.skippedPQKeys, keyID)
		}
	}

	return nil
}

// isBraidHandshakeError returns true for Braid errors that are expected
// during the early handshake phase when the state machine is not yet
// ready to process incoming messages. These are non-fatal and indicate
// the caller should continue with the current PQ chain state.
func isBraidHandshakeError(err error) bool {
	var stateErr *mlkembraid.ErrInvalidState
	var epochErr *mlkembraid.ErrInvalidEpoch
	return errors.As(err, &stateErr) || errors.As(err, &epochErr)
}

// serializeCompositeMessage serializes a composite header and ciphertext into
// a single byte slice:
//
//	[4 bytes: header length][header bytes][4 bytes: ciphertext length][ciphertext bytes]
func serializeCompositeMessage(header *CompositeHeader, ciphertext []byte) ([]byte, error) {
	headerBytes, err := header.Serialize()
	if err != nil {
		return nil, &ErrInvalidCompositeMessage{Reason: "failed to serialize header"}
	}

	totalSize := headerLenPrefixSize + len(headerBytes) + ciphertextLenPrefixSize + len(ciphertext)
	buf := make([]byte, totalSize)

	offset := 0
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(headerBytes)))
	offset += headerLenPrefixSize

	copy(buf[offset:], headerBytes)
	offset += len(headerBytes)

	binary.BigEndian.PutUint32(buf[offset:], uint32(len(ciphertext)))
	offset += ciphertextLenPrefixSize

	copy(buf[offset:], ciphertext)

	return buf, nil
}

// deserializeCompositeMessage parses a composite message into its header and
// ciphertext components.
func deserializeCompositeMessage(data []byte) (*CompositeHeader, []byte, error) {
	if len(data) < compositeMessageMinSize {
		return nil, nil, &ErrInvalidCompositeMessage{
			Reason: "message too short",
		}
	}

	offset := 0

	// Header length.
	headerLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += headerLenPrefixSize

	if headerLen > maxCompositeComponentLen {
		return nil, nil, &ErrMessageTooLarge{
			Component: "header",
			Size:      headerLen,
			Max:       maxCompositeComponentLen,
		}
	}

	if headerLen < 0 || offset+headerLen > len(data) {
		return nil, nil, &ErrInvalidCompositeMessage{
			Reason: "header length exceeds available data",
		}
	}

	// Header bytes.
	headerBytes := data[offset : offset+headerLen]
	offset += headerLen

	// Ciphertext length.
	if offset+ciphertextLenPrefixSize > len(data) {
		return nil, nil, &ErrInvalidCompositeMessage{
			Reason: "missing ciphertext length",
		}
	}

	ctLen := int(binary.BigEndian.Uint32(data[offset:]))
	offset += ciphertextLenPrefixSize

	if ctLen > maxCompositeComponentLen {
		return nil, nil, &ErrMessageTooLarge{
			Component: "ciphertext",
			Size:      ctLen,
			Max:       maxCompositeComponentLen,
		}
	}

	if ctLen < 0 || offset+ctLen > len(data) {
		return nil, nil, &ErrInvalidCompositeMessage{
			Reason: "ciphertext length exceeds available data",
		}
	}

	// Ciphertext.
	ciphertext := make([]byte, ctLen)
	copy(ciphertext, data[offset:offset+ctLen])

	// Deserialize header.
	header, err := DeserializeCompositeHeader(headerBytes)
	if err != nil {
		return nil, nil, err
	}

	return header, ciphertext, nil
}

// computeHMAC computes HMAC-SHA256 over the given data using the provided key.
// The returned tag is always 32 bytes (sha256.Size).
func computeHMAC(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// copyBytes returns an independent copy of the source slice.
// Returns nil if src is nil.
func copyBytes(src []byte) []byte {
	if src == nil {
		return nil
	}
	dst := make([]byte, len(src))
	copy(dst, src)
	return dst
}

// xorKeys XORs two byte slices together and returns the result as a
// memguard-backed Secret. If they differ in length, the result is the
// length of the shorter slice. Both inputs are left intact.
func xorKeys(a, b []byte) (*secret.Secret, error) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	result := make([]byte, n)
	for i := 0; i < n; i++ {
		result[i] = a[i] ^ b[i]
	}
	s, err := secret.New(result)
	if err != nil {
		return nil, &ErrSPQRFailed{Op: "xorKeys", Err: err}
	}
	return s, nil
}
