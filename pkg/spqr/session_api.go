// Package spqr implements the Sparse Post-Quantum Ratchet (SPQR) protocol.
//
// # session_api.go: Chain + SCKA API
//
// This file provides two layers of API:
//
// ## Stateless Chain-Only API (legacy)
//
// The package-level functions Send() and Recv() operate on serialized SPQR state
// bytes. They derive per-message PQ keys from the current epoch's chain key and
// counter but do NOT perform epoch advancement.
//
// ## Braid-Integrated API
//
// The methods SendBraid() and RecvBraid() on the SPQR struct bundle chain key
// derivation with ML-KEM Braid SCKA. On each call they:
//  1. Derive the per-message key from the chain
//  2. Call the braid to get an outbound chunk (or process an inbound chunk)
//  3. If the braid produces an OutputKey, advance the epoch via KdfSckaRK
//  4. Build a variable-length wire message with chain info + SCKA chunk
//
// This matches the Rust reference where a single spqr crate bundles both
// chain key management and SCKA state machine.
package spqr

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// MessageKey is the PQR key used as HKDF salt for message key derivation.
// nil means no PQR key (V0 / pre-negotiation fallback).
type MessageKey = []byte

const (
	// pqrMsgSize is the wire size of a PQR message: epoch(8) + counter(4).
	pqrMsgSize = 12
)

// ErrPQRMessage is returned when a PQR message is malformed.
type ErrPQRMessage struct {
	Reason string
}

func (e *ErrPQRMessage) Error() string {
	return fmt.Sprintf("spqr: invalid PQR message: %s", e.Reason)
}

// InitialState creates and serializes a new SPQR state from initial parameters.
// When selfSession is true, the max forward jump limit is set to math.MaxUint32
// to match the Rust reference behavior for sessions where local and remote
// identity keys are identical. Otherwise the default maxJump (25000) is used.
//
// This function creates a state with version negotiation pending. The chain is
// NOT initialized immediately; instead, it defers chain creation until the first
// Recv() call resolves the version negotiation. During the pending state, Send()
// returns empty PQR messages and nil message keys.
func InitialState(sharedSecret []byte, direction Direction, selfSession bool) (serializedState []byte, err error) {
	maxJumpLimit := uint32(maxJump)
	if selfSession {
		maxJumpLimit = math.MaxUint32
	}

	return InitialStateWithParams(Params{
		AuthKey:    sharedSecret,
		Version:    VersionV1,
		Direction:  direction,
		MinVersion: VersionV0,
		MaxJump:    maxJumpLimit,
		MaxOOOKeys: maxSkippedKeys,
	})
}

// InitialStateWithParams creates and serializes a new SPQR state with explicit
// version negotiation parameters. The chain is not initialized immediately;
// negotiation is deferred until the first Recv() call.
func InitialStateWithParams(params Params) (serializedState []byte, err error) {
	if len(params.AuthKey) == 0 {
		return nil, &ErrInvalidInput{
			Field:  "AuthKey",
			Reason: "must not be empty",
		}
	}
	if params.Version > VersionV1 {
		return nil, &ErrInvalidInput{
			Field:  "Version",
			Reason: fmt.Sprintf("unsupported version %d", params.Version),
		}
	}
	if params.MinVersion > params.Version {
		return nil, &ErrInvalidInput{
			Field:  "MinVersion",
			Reason: "minimum version cannot exceed requested version",
		}
	}

	// Copy the auth key to prevent external mutation.
	authKey := make([]byte, len(params.AuthKey))
	copy(authKey, params.AuthKey)

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   params.Direction,
		maxJump:     params.MaxJump,
		negotiation: negotiationPending,
		version:     params.Version,
		minVersion:  params.MinVersion,
		authKey:     authKey,
	}
	defer s.Zeroize()

	return s.Serialize()
}

// InitialStateWithBraid creates and serializes a new SPQR state with an
// attached ML-KEM Braid for SCKA-integrated epoch advancement. The braid state
// is serialized alongside the chain state in V4 format, so that subsequent
// Send()/Recv() calls transparently handle both chain keys and SCKA.
//
// Parameters:
//   - sharedSecret: initial shared secret for chain key derivation
//   - direction: A2B or B2A, determines send/recv key assignment
//   - selfSession: if true, sets maxJump to math.MaxUint32
//   - braid: initialized ML-KEM Braid instance (Alice or Bob)
func InitialStateWithBraid(sharedSecret []byte, direction Direction, selfSession bool, braid *mlkembraid.Braid) ([]byte, error) {
	if braid == nil {
		return nil, &ErrInvalidInput{
			Field:  "braid",
			Reason: "must not be nil",
		}
	}

	maxJumpLimit := uint32(maxJump)
	if selfSession {
		maxJumpLimit = math.MaxUint32
	}

	if len(sharedSecret) == 0 {
		return nil, &ErrInvalidInput{
			Field:  "sharedSecret",
			Reason: "must not be empty",
		}
	}

	// Copy the auth key to prevent external mutation.
	authKey := make([]byte, len(sharedSecret))
	copy(authKey, sharedSecret)

	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   direction,
		maxJump:     maxJumpLimit,
		negotiation: negotiationPending,
		version:     VersionV1,
		minVersion:  VersionV0,
		authKey:     authKey,
		braid:       braid,
	}
	defer s.Zeroize()

	return s.Serialize()
}

// InitialStateWithBraidResolved creates and serializes a pre-resolved V1 SPQR
// state with an attached ML-KEM Braid. Unlike InitialStateWithBraid, this
// immediately initializes the chain (no version negotiation), suitable for
// cases where PQR support is known a priori.
func InitialStateWithBraidResolved(sharedSecret []byte, direction Direction, selfSession bool, braid *mlkembraid.Braid) ([]byte, error) {
	if braid == nil {
		return nil, &ErrInvalidInput{
			Field:  "braid",
			Reason: "must not be nil",
		}
	}

	maxJumpLimit := uint32(maxJump)
	if selfSession {
		maxJumpLimit = math.MaxUint32
	}

	s, err := InitWithBraid(sharedSecret, direction, maxJumpLimit, braid)
	if err != nil {
		return nil, err
	}
	defer s.Zeroize()

	return s.Serialize()
}

// resolveNegotiation resolves the version negotiation on a deserialized SPQR
// instance. If pqrData is non-empty, resolves to V1 and initializes the chain.
// If pqrData is empty, resolves to V0 (disabled) if minVersion allows it.
func (s *SPQR) resolveNegotiation(pqrData []byte) error {
	if len(pqrData) > 0 {
		// Remote supports PQR: resolve to V1 and initialize the chain.
		rk, cks, ckr, err := KdfSckaInit(s.authKey)
		if err != nil {
			return err
		}

		if s.direction == DirectionB2A {
			cks, ckr = ckr, cks
		}

		s.rootKey = rk
		s.epoch = 0
		s.chains[0] = &EpochChain{
			sendKey: cks,
			recvKey: ckr,
		}

		s.negotiation = negotiationResolved
		s.version = VersionV1
		// Zeroize auth key.
		crypto.Zeroize(s.authKey)
		s.authKey = nil
		return nil
	}

	// Remote does not support PQR: check minimum version.
	if s.minVersion > VersionV0 {
		return &ErrVersionNegotiationFailed{
			MinVersion: s.minVersion,
			GotVersion: VersionV0,
		}
	}

	// Resolve to V0 (disabled).
	s.negotiation = negotiationResolved
	s.version = VersionV0
	// Zeroize auth key since we won't use it.
	crypto.Zeroize(s.authKey)
	s.authKey = nil
	return nil
}

// Send derives the next PQR message key for encryption and returns the
// updated serialized state, the PQR message bytes, and the message key to use
// as HKDF salt.
//
// When braid state is present in the serialized state (V4 format), Send
// transparently uses the braid-integrated path: chain key derivation + SCKA
// chunk piggybacking + epoch advancement + variable-length wire format.
//
// When no braid is present (V3 or earlier), Send uses the legacy chain-only
// path with 12-byte fixed wire format.
//
// During version negotiation (pending state), Send returns an empty PQR message
// ([]byte{}) and nil message key. The caller should include the empty PQR
// message on the wire so the remote peer can detect PQR support.
//
// After negotiation resolves to V0 (disabled), Send returns an empty PQR message
// and nil message key for all subsequent calls.
//
// After negotiation resolves to V1, Send derives keys normally.
func Send(serializedState []byte) (newState []byte, pqrMsg []byte, messageKey MessageKey, err error) {
	s, err := Deserialize(serializedState)
	if err != nil {
		return nil, nil, nil, err
	}
	defer s.Zeroize()

	// Version negotiation pending: if minVersion requires V1, resolve immediately.
	if s.negotiation == negotiationPending {
		if s.minVersion >= VersionV1 {
			if err := s.resolveNegotiation([]byte{0x01}); err != nil {
				return nil, nil, nil, err
			}
		} else {
			newState, err = s.Serialize()
			if err != nil {
				return nil, nil, nil, err
			}
			return newState, []byte{}, nil, nil
		}
	}

	// Resolved to V0 (disabled): return empty message, nil key.
	if s.IsDisabled() {
		newState, err = s.Serialize()
		if err != nil {
			return nil, nil, nil, err
		}
		return newState, []byte{}, nil, nil
	}

	// Braid-integrated path: delegate to SendBraid which handles chain
	// derivation, SCKA chunk piggybacking, epoch advancement, and
	// variable-length wire encoding.
	if s.braid != nil {
		pqrMsg, messageKey, err = s.SendBraid()
		if err != nil {
			return nil, nil, nil, err
		}
		newState, err = s.Serialize()
		if err != nil {
			return nil, nil, nil, err
		}
		return newState, pqrMsg, messageKey, nil
	}

	// Legacy chain-only path: derive message key and build 12-byte wire message.
	mk, counter, encErr := s.Encrypt(s.epoch)
	if encErr != nil {
		return nil, nil, nil, encErr
	}
	defer mk.Destroy()

	pqrMsg = make([]byte, pqrMsgSize)
	binary.BigEndian.PutUint64(pqrMsg[0:8], s.epoch)
	binary.BigEndian.PutUint32(pqrMsg[8:12], counter)

	messageKey = make([]byte, mk.Size())
	copy(messageKey, mk.Bytes())

	newState, err = s.Serialize()
	if err != nil {
		return nil, nil, nil, err
	}

	return newState, pqrMsg, messageKey, nil
}

// ErrNoBraid is returned when a braid-integrated operation is called on
// an SPQR instance that has no attached braid.
type ErrNoBraid struct{}

func (e *ErrNoBraid) Error() string {
	return "spqr: braid not attached"
}

// ErrBraidSend is returned when the braid Send operation fails.
type ErrBraidSend struct {
	Err error
}

func (e *ErrBraidSend) Error() string {
	return fmt.Sprintf("spqr: braid send failed: %v", e.Err)
}

func (e *ErrBraidSend) Unwrap() error {
	return e.Err
}

// ErrBraidRecv is returned when the braid Receive operation fails.
type ErrBraidRecv struct {
	Err error
}

func (e *ErrBraidRecv) Error() string {
	return fmt.Sprintf("spqr: braid receive failed: %v", e.Err)
}

func (e *ErrBraidRecv) Unwrap() error {
	return e.Err
}

// ErrEpochAdvance is returned when epoch advancement via KdfSckaRK fails.
type ErrEpochAdvance struct {
	Err error
}

func (e *ErrEpochAdvance) Error() string {
	return fmt.Sprintf("spqr: epoch advance failed: %v", e.Err)
}

func (e *ErrEpochAdvance) Unwrap() error {
	return e.Err
}

// SendBraid derives the next PQR message key for encryption with braid
// integration. Following the Rust reference ordering, it:
//  1. Calls the braid to produce an outbound SCKA chunk
//  2. If the braid produces an OutputKey, advances to a new epoch FIRST
//  3. Derives the per-message key from the (potentially new) epoch's send chain
//  4. Builds a variable-length wire message using the braid's SerializeSCKA
//     format: version(1) + varint(braidEpoch) + varint(chainCounter) +
//     msg_type(1) + [chunk_data]
//
// Returns the wire message bytes and the message key to use as HKDF salt.
// The caller must hold the SPQR instance in memory across calls.
func (s *SPQR) SendBraid() (pqrMsg []byte, messageKey MessageKey, err error) {
	if s.braid == nil {
		return nil, nil, &ErrNoBraid{}
	}

	// Handle negotiation states: pending or V0 disabled.
	if s.negotiation == negotiationPending {
		if s.minVersion >= VersionV1 {
			if err := s.resolveNegotiation([]byte{0x01}); err != nil {
				return nil, nil, err
			}
		} else {
			return []byte{}, nil, nil
		}
	}
	if s.IsDisabled() {
		return []byte{}, nil, nil
	}

	// Step 1: Call braid to get the outbound SCKA chunk.
	// The braid must be called first to determine if an epoch advancement
	// is needed before deriving the message key.
	braidMsg, _, outputKey, braidErr := s.braid.Send()
	if braidErr != nil {
		return nil, nil, &ErrBraidSend{Err: braidErr}
	}

	// Step 2: If the braid produced an output key, advance the epoch BEFORE
	// deriving the message key so the chain derivation uses the new epoch.
	if outputKey != nil && outputKey.Key != nil {
		advErr := s.advanceEpoch(outputKey.Key)
		outputKey.Key.Destroy()
		if advErr != nil {
			return nil, nil, &ErrEpochAdvance{Err: advErr}
		}
	}

	// Step 3: Derive per-message key from the (potentially new) send chain.
	mk, counter, err := s.Encrypt(s.epoch)
	if err != nil {
		return nil, nil, err
	}
	defer mk.Destroy()

	// Step 4: Build the wire message using the braid's serialization format.
	// The braid message carries the braid's epoch (>= 1), distinct from the
	// SPQR chain epoch (>= 0). The chain counter is encoded as chain_index.
	if braidMsg != nil {
		pqrMsg = braidMsg.SerializeSCKA(counter)
	} else {
		// Fallback: build a None message with the braid's current epoch.
		noneMsg := &mlkembraid.Message{
			Epoch: s.braid.Epoch(),
			Type:  mlkembraid.MessageTypeNone,
		}
		pqrMsg = noneMsg.SerializeSCKA(counter)
	}

	// Copy message key bytes.
	messageKey = make([]byte, mk.Size())
	copy(messageKey, mk.Bytes())

	return pqrMsg, messageKey, nil
}

// RecvBraid processes a received PQR message with braid integration. Following
// the Rust reference ordering, it:
//  1. Parses the variable-length wire message using DeserializeSCKA to extract
//     the braid message and chain counter
//  2. Feeds the braid message to the braid's Receive method FIRST
//  3. If the braid produces an OutputKey, advances to a new epoch
//  4. Derives the per-message key using the braid epoch mapping:
//     chain_epoch = braidMsg.Epoch - 1 (braid epochs are 1-indexed)
//
// Special case: when chain_epoch == 0 and chainCounter == 0, returns nil
// message key (no chain derivation). This represents the initial state before
// any chain key advancement has occurred.
//
// For backward compatibility, 12-byte legacy messages are parsed as
// epoch(8 BE) + counter(4 BE) with no SCKA data.
//
// Returns the message key to use as HKDF salt for decryption.
// The caller must hold the SPQR instance in memory across calls.
func (s *SPQR) RecvBraid(pqrMsg []byte) (messageKey MessageKey, err error) {
	if s.braid == nil {
		return nil, &ErrNoBraid{}
	}

	// Handle negotiation states.
	if s.negotiation == negotiationPending {
		if err := s.resolveNegotiation(pqrMsg); err != nil {
			return nil, err
		}
		if s.IsDisabled() {
			return nil, nil
		}
	}
	if s.IsDisabled() {
		return nil, nil
	}

	// Parse the wire message.
	// Legacy 12-byte format: fall back to chain-only decryption.
	if len(pqrMsg) == legacyPQRMsgSize {
		return s.recvLegacy(pqrMsg)
	}

	// Variable-length format: decode using the braid's SCKA wire format.
	braidMsg, chainCounter, decErr := mlkembraid.DeserializeSCKA(pqrMsg)
	if decErr != nil {
		return nil, &ErrPQRMessage{Reason: decErr.Error()}
	}

	// Step 1: Feed the braid message to the braid's Receive method FIRST,
	// before deriving the message key, so epoch advancement happens in the
	// correct order. All message types including MessageTypeNone are passed
	// through to update epoch tracking in the braid state machine.
	_, outputKey, braidErr := s.braid.Receive(braidMsg)
	if braidErr != nil {
		return nil, &ErrBraidRecv{Err: braidErr}
	}

	// Step 2: If the braid produced an output key, advance the epoch
	// BEFORE deriving the message key.
	if outputKey != nil && outputKey.Key != nil {
		advErr := s.advanceEpoch(outputKey.Key)
		outputKey.Key.Destroy()
		if advErr != nil {
			return nil, &ErrEpochAdvance{Err: advErr}
		}
	}

	// Step 3: Map braid epoch to chain epoch. The braid uses 1-indexed epochs
	// while the SPQR chains use 0-indexed epochs: chain_epoch = braid_epoch - 1.
	if braidMsg.Epoch == 0 {
		return nil, &ErrPQRMessage{Reason: "braid epoch must be >= 1"}
	}
	msgKeyEpoch := braidMsg.Epoch - 1

	// Step 4: Special case — epoch 0 index 0 returns nil message key.
	// This represents the very first message before any chain key derivation
	// has occurred, matching the Rust reference behavior.
	if msgKeyEpoch == 0 && chainCounter == 0 {
		return nil, nil
	}

	// Step 5: Derive per-message key from the receive chain using the
	// mapped chain epoch and the wire message's chain counter.
	mk, mkErr := s.Decrypt(msgKeyEpoch, chainCounter)
	if mkErr != nil {
		return nil, mkErr
	}
	defer mk.Destroy()

	// Copy message key bytes.
	messageKey = make([]byte, mk.Size())
	copy(messageKey, mk.Bytes())

	return messageKey, nil
}

// recvLegacy handles the legacy 12-byte fixed wire format for backward
// compatibility. Legacy messages carry epoch(8 BE) + counter(4 BE) with
// no SCKA data.
func (s *SPQR) recvLegacy(pqrMsg []byte) (MessageKey, error) {
	epoch := binary.BigEndian.Uint64(pqrMsg[0:8])
	counter := binary.BigEndian.Uint32(pqrMsg[8:12])

	mk, err := s.Decrypt(epoch, counter)
	if err != nil {
		return nil, err
	}
	defer mk.Destroy()

	messageKey := make([]byte, mk.Size())
	copy(messageKey, mk.Bytes())
	return messageKey, nil
}

// Recv processes a received PQR message and returns the updated serialized state
// and the message key to use as HKDF salt for decryption.
//
// When braid state is present in the serialized state (V4 format), Recv
// transparently uses the braid-integrated path: variable-length wire format
// parsing + chain key derivation + SCKA chunk processing + epoch advancement.
//
// When no braid is present (V3 or earlier), Recv uses the legacy chain-only
// path with 12-byte fixed wire format.
//
// If version negotiation is pending:
//   - Empty pqrMsg (len 0): resolves to V0 (disabled), returns nil key
//   - Non-empty pqrMsg: resolves to V1, initializes chain, decrypts
//
// After negotiation resolves to V0: returns nil key regardless of pqrMsg.
// After negotiation resolves to V1: decrypts normally.
func Recv(serializedState []byte, pqrMsg []byte) (newState []byte, messageKey MessageKey, err error) {
	s, err := Deserialize(serializedState)
	if err != nil {
		return nil, nil, err
	}
	defer s.Zeroize()

	// Handle version negotiation.
	if s.negotiation == negotiationPending {
		if err := s.resolveNegotiation(pqrMsg); err != nil {
			return nil, nil, err
		}

		if s.IsDisabled() {
			newState, err = s.Serialize()
			if err != nil {
				return nil, nil, err
			}
			return newState, nil, nil
		}

		// V1: negotiation resolved, now decrypt the first message.
		// Braid-integrated path handles its own wire format.
		if s.braid != nil {
			messageKey, err = s.RecvBraid(pqrMsg)
			if err != nil {
				return nil, nil, err
			}
			newState, err = s.Serialize()
			if err != nil {
				return nil, nil, err
			}
			return newState, messageKey, nil
		}

		// Legacy path: first message must be 12 bytes.
		if len(pqrMsg) != pqrMsgSize {
			return nil, nil, &ErrPQRMessage{
				Reason: fmt.Sprintf("expected %d bytes, got %d", pqrMsgSize, len(pqrMsg)),
			}
		}

		epoch := binary.BigEndian.Uint64(pqrMsg[0:8])
		counter := binary.BigEndian.Uint32(pqrMsg[8:12])

		mk, decErr := s.Decrypt(epoch, counter)
		if decErr != nil {
			return nil, nil, decErr
		}
		defer mk.Destroy()

		messageKey = make([]byte, mk.Size())
		copy(messageKey, mk.Bytes())

		newState, err = s.Serialize()
		if err != nil {
			return nil, nil, err
		}
		return newState, messageKey, nil
	}

	// Already negotiated to V0: return nil key.
	if s.IsDisabled() {
		newState, err = s.Serialize()
		if err != nil {
			return nil, nil, err
		}
		return newState, nil, nil
	}

	// Braid-integrated path: delegate to RecvBraid which handles wire format
	// parsing, chain derivation, SCKA chunk processing, and epoch advancement.
	if s.braid != nil {
		messageKey, err = s.RecvBraid(pqrMsg)
		if err != nil {
			return nil, nil, err
		}
		newState, err = s.Serialize()
		if err != nil {
			return nil, nil, err
		}
		return newState, messageKey, nil
	}

	// Legacy chain-only path: 12-byte fixed wire format.
	if len(pqrMsg) != pqrMsgSize {
		return nil, nil, &ErrPQRMessage{
			Reason: fmt.Sprintf("expected %d bytes, got %d", pqrMsgSize, len(pqrMsg)),
		}
	}

	epoch := binary.BigEndian.Uint64(pqrMsg[0:8])
	counter := binary.BigEndian.Uint32(pqrMsg[8:12])

	mk, decErr := s.Decrypt(epoch, counter)
	if decErr != nil {
		return nil, nil, decErr
	}
	defer mk.Destroy()

	messageKey = make([]byte, mk.Size())
	copy(messageKey, mk.Bytes())

	newState, err = s.Serialize()
	if err != nil {
		return nil, nil, err
	}

	return newState, messageKey, nil
}
