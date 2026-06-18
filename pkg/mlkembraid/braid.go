// Package mlkembraid implements the ML-KEM Braid SCKA protocol.
//
// Use IncrementalMLKEM768KEM (via NewIncrementalMLKEM768KEM) as the KEM
// implementation. It uses internal/incremental_mlkem768 which is a pure-Go,
// byte-wire-compatible port of the Rust libcrux-ml-kem incremental API.
// The incremental split (Encaps1/Encaps2) is fully implemented: Encaps1
// persists a 2080-byte EncapsulationState and Encaps2 completes encapsulation,
// producing wire-compatible ct1 (960 bytes) and ct2 (128 bytes).
//
// The legacy MLKEM768IncrementalKEM is retained for backward compatibility.
package mlkembraid

// Braid is the top-level ML-KEM Braid SCKA protocol instance. It manages
// the internal state machine and provides Send/Receive operations for
// exchanging post-quantum key agreement messages.
//
// Braid is NOT safe for concurrent use by multiple goroutines.
// The session-level serialization (load -> mutate -> store) provides
// implicit synchronization when used through the session cipher.
type Braid struct {
	state     *State
	kem       IncrementalKEM
	chunkSize int
}

// InitAlice creates a new Braid instance for the initiator (Alice).
// Per spec Section 2.6: epoch=1, state=KeysUnsampled.
func InitAlice(sharedSecret []byte, kemImpl IncrementalKEM, chunkSize int) (*Braid, error) {
	if len(sharedSecret) == 0 {
		return nil, &ErrInvalidInput{Field: "sharedSecret", Reason: "must not be empty"}
	}
	if kemImpl == nil {
		return nil, &ErrInvalidInput{Field: "kem", Reason: "must not be nil"}
	}
	if chunkSize <= 0 {
		return nil, &ErrChunkSize{Size: chunkSize, Reason: "must be positive"}
	}

	epoch := uint64(1)
	auth, err := NewAuthenticator(epoch, sharedSecret)
	if err != nil {
		return nil, err
	}

	state := &State{
		kind:      StateKeysUnsampled,
		epoch:     epoch, // Per spec Section 2.6: epoch=1
		auth:      auth,
		chunkSize: chunkSize,
	}

	return &Braid{
		state:     state,
		kem:       kemImpl,
		chunkSize: chunkSize,
	}, nil
}

// InitBob creates a new Braid instance for the responder (Bob).
// Per spec Section 2.6: epoch=1, state=NoHeaderReceived with header decoder initialized.
func InitBob(sharedSecret []byte, kemImpl IncrementalKEM, chunkSize int) (*Braid, error) {
	if len(sharedSecret) == 0 {
		return nil, &ErrInvalidInput{Field: "sharedSecret", Reason: "must not be empty"}
	}
	if kemImpl == nil {
		return nil, &ErrInvalidInput{Field: "kem", Reason: "must not be nil"}
	}
	if chunkSize <= 0 {
		return nil, &ErrChunkSize{Size: chunkSize, Reason: "must be positive"}
	}

	epoch := uint64(1)
	auth, err := NewAuthenticator(epoch, sharedSecret)
	if err != nil {
		return nil, err
	}

	// Bob's header decoder: header(64) + MAC(32) = 96 bytes.
	headerDec, err := NewDecoder(HeaderSize+MacSize, chunkSize)
	if err != nil {
		return nil, err
	}

	state := &State{
		kind:          StateNoHeaderReceived,
		epoch:         epoch, // Per spec Section 2.6: epoch=1
		auth:          auth,
		headerDecoder: headerDec,
		chunkSize:     chunkSize,
	}

	return &Braid{
		state:     state,
		kem:       kemImpl,
		chunkSize: chunkSize,
	}, nil
}

// Send produces the next outbound message. Per spec Section 1.1, returns
// the message, sending_epoch (the latest epoch guaranteed to be known by
// the other party on receipt), and an optional output key.
func (b *Braid) Send() (*Message, uint64, *OutputKey, error) {
	return b.state.Send(b.kem)
}

// Receive processes an inbound message. Per spec Section 1.1, returns
// receiving_epoch (the epoch the sender output as sending_epoch when
// generating msg) and an optional output key.
func (b *Braid) Receive(msg *Message) (uint64, *OutputKey, error) {
	return b.state.Receive(msg, b.kem, b.chunkSize)
}

// Epoch returns the current protocol epoch.
func (b *Braid) Epoch() uint64 {
	return b.state.epoch
}

// StateKind returns the current state of the protocol state machine.
func (b *Braid) StateKind() StateKind {
	return b.state.kind
}

// State returns the internal State for proto marshaling. It is used exclusively
// by the proto codec (Phase D) to serialize/deserialize braid state. Callers
// outside the serialization layer must not access the returned State directly.
func (b *Braid) State() *State {
	return b.state
}

// BraidFromState constructs a Braid from a previously deserialized State.
// This is the inverse of Braid.State(), used by UnmarshalStateProto to
// reconstruct a Braid from a proto-decoded State.
func BraidFromState(state *State, kemImpl IncrementalKEM, chunkSize int) *Braid {
	return &Braid{
		state:     state,
		kem:       kemImpl,
		chunkSize: chunkSize,
	}
}

// Zeroize clears all sensitive key material.
func (b *Braid) Zeroize() {
	b.state.Zeroize()
}
