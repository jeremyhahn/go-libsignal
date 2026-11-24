// Package spqr implements the Sparse Post-Quantum Ratchet: chain-only Send and Recv on serialized state, and SendBraid and RecvBraid with ML-KEM Braid SCKA.
package spqr

import (
	"fmt"
	"math"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// MessageKey is the PQR key used as HKDF salt for message key derivation.
// nil means no PQR key (V0 / pre-negotiation fallback).
type MessageKey = []byte

// ErrPQRMessage is returned when a PQR message is malformed.
type ErrPQRMessage struct {
	Reason string
}

func (e *ErrPQRMessage) Error() string {
	return fmt.Sprintf("spqr: invalid PQR message: %s", e.Reason)
}

// InitialState returns a serialized SPQR state pending negotiation, with MinVersion V1 (Rust ratchet.rs:88); selfSession sets maxJump to math.MaxUint32.
func InitialState(sharedSecret []byte, direction Direction, selfSession bool) (serializedState []byte, err error) {
	maxJumpLimit := uint32(maxJump)
	if selfSession {
		maxJumpLimit = math.MaxUint32
	}

	return InitialStateWithParams(Params{
		AuthKey:    sharedSecret,
		Version:    VersionV1,
		Direction:  direction,
		MinVersion: VersionV1,
		MaxJump:    maxJumpLimit,
		MaxOOOKeys: maxSkippedKeys,
	})
}

// InitialStateWithParams returns a serialized SPQR state with the given negotiation parameters, resolved on the first Recv.
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

// InitialStateWithBraid returns a serialized SPQR state with braid attached for SCKA epoch advancement.
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
		minVersion:  VersionV1,
		authKey:     authKey,
		braid:       braid,
	}
	defer s.Zeroize()

	return s.Serialize()
}

// InitialStateWithBraidResolved returns a serialized V1 SPQR state with braid and an initialized chain.
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

// resolveNegotiation resolves to V1 on non-empty pqrData, else to V0 if minVersion allows.
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

// Send returns the new state, the SCKA wire message and the message key (HKDF salt); while pending or at V0 the message is empty and the key nil.
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

	// With a braid, SendBraid handles derivation, chunks, epochs and encoding.
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

	// Without a braid, derive the key and build an SCKA message with a 1-indexed epoch.
	mk, counter, encErr := s.Encrypt(s.epoch)
	if encErr != nil {
		return nil, nil, nil, encErr
	}
	defer mk.Destroy()

	// Build a MessageTypeNone SCKA wire message carrying the chain epoch and counter.
	noneMsg := &mlkembraid.Message{
		Epoch: chainToSckaEpoch(s.epoch),
		Type:  mlkembraid.MessageTypeNone,
	}
	pqrMsg = noneMsg.SerializeSCKA(counter)

	messageKey = copySecret(mk)

	newState, err = s.Serialize()
	if err != nil {
		return nil, nil, nil, err
	}

	return newState, pqrMsg, messageKey, nil
}

// ErrNoBraid is returned by braid operations on an SPQR without a braid.
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

// SendBraid gets the braid's chunk, advances the epoch on an output key, derives the message key and returns the SCKA message and key, as Rust orders it.
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

	// Call the braid first to learn whether the epoch advances.
	braidMsg, _, outputKey, braidErr := s.braid.Send()
	if braidErr != nil {
		return nil, nil, &ErrBraidSend{Err: braidErr}
	}

	// Advance the epoch before deriving the message key.
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

	// The message carries the braid epoch (from 1), not the chain epoch (from 0), and the chain counter.
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
	messageKey = copySecret(mk)

	return pqrMsg, messageKey, nil
}

// RecvBraid parses the SCKA message, feeds the braid first, advances on an output key and derives the key for chain epoch braid epoch - 1; epoch 0 counter 0 and 12-byte legacy messages yield no key.
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

	// Parse the SCKA wire message using the braid's SCKA wire format.
	braidMsg, chainCounter, decErr := mlkembraid.DeserializeSCKA(pqrMsg)
	if decErr != nil {
		return nil, &ErrPQRMessage{Reason: decErr.Error()}
	}

	// Feed every message, including MessageTypeNone, to the braid before deriving the key.
	_, outputKey, braidErr := s.braid.Receive(braidMsg)
	if braidErr != nil {
		return nil, &ErrBraidRecv{Err: braidErr}
	}

	// Advance the epoch before deriving the message key.
	if outputKey != nil && outputKey.Key != nil {
		advErr := s.advanceEpoch(outputKey.Key)
		outputKey.Key.Destroy()
		if advErr != nil {
			return nil, &ErrEpochAdvance{Err: advErr}
		}
	}

	// chain epoch = braid epoch - 1.
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
	messageKey = copySecret(mk)

	return messageKey, nil
}

// Recv returns the new state and message key for an SCKA message; while pending an empty message resolves V0 and a non-empty one V1; at V0 the key is nil.
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

		// Parse the SCKA wire message to extract the chain epoch and counter.
		braidMsg, chainCounter, decErr := mlkembraid.DeserializeSCKA(pqrMsg)
		if decErr != nil {
			return nil, nil, &ErrPQRMessage{Reason: decErr.Error()}
		}
		if braidMsg.Epoch == 0 {
			return nil, nil, &ErrPQRMessage{Reason: "braid epoch must be >= 1"}
		}
		// Map SCKA 1-indexed epoch to Go 0-indexed chain epoch.
		chainEpoch := sckaToChainEpoch(braidMsg.Epoch)

		mk, decErr2 := s.Decrypt(chainEpoch, chainCounter)
		if decErr2 != nil {
			return nil, nil, decErr2
		}
		defer mk.Destroy()

		messageKey = copySecret(mk)

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

	// With a braid, RecvBraid handles parsing, derivation, chunks and epochs.
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

	// Chain-only path: parse Rust-compatible SCKA wire message.
	braidMsg, chainCounter, decErr := mlkembraid.DeserializeSCKA(pqrMsg)
	if decErr != nil {
		return nil, nil, &ErrPQRMessage{Reason: decErr.Error()}
	}
	if braidMsg.Epoch == 0 {
		return nil, nil, &ErrPQRMessage{Reason: "braid epoch must be >= 1"}
	}
	// Map SCKA 1-indexed epoch to Go 0-indexed chain epoch.
	chainEpoch := sckaToChainEpoch(braidMsg.Epoch)

	mk, decErr2 := s.Decrypt(chainEpoch, chainCounter)
	if decErr2 != nil {
		return nil, nil, decErr2
	}
	defer mk.Destroy()

	messageKey = copySecret(mk)

	newState, err = s.Serialize()
	if err != nil {
		return nil, nil, err
	}

	return newState, messageKey, nil
}
