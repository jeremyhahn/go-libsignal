package mlkembraid

import (
	"crypto/subtle"
	"fmt"
	"math"

	imlkem "github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/incremental_mlkem768"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// StateKind identifies which of the protocol states the state machine is in.
type StateKind uint8

const (
	// StateKeysUnsampled is Alice's initial state before key generation.
	StateKeysUnsampled StateKind = iota
	// StateKeysSampled means keys have been generated, sending header chunks.
	StateKeysSampled
	// StateHeaderSent means all header chunks sent, sending Ek chunks.
	StateHeaderSent
	// StateCt1Received means ct1 fully received, sending remaining EkCt1Ack chunks.
	StateCt1Received
	// StateEkSentCt1Received means all ek sent and ct1 received, waiting for ct2.
	StateEkSentCt1Received
	// StateNoHeaderReceived is Bob's initial state, waiting for header chunks.
	StateNoHeaderReceived
	// StateHeaderReceived means complete header received, collecting ek chunks.
	StateHeaderReceived
	// StateCt1Sampled means encapsulation done, sending ct1 chunks.
	StateCt1Sampled
	// StateEkReceivedCt1Sampled means ek fully received, ct1 sampled, waiting for ct1 ack.
	StateEkReceivedCt1Sampled
	// StateCt1Acknowledged means ct1 was acknowledged, receiving remaining ek if needed.
	StateCt1Acknowledged
	// StateCt2Sampled means ct2 computed, sending ct2 chunks.
	StateCt2Sampled
)

// stateKindNames maps state kinds to human-readable names.
var stateKindNames = map[StateKind]string{
	StateKeysUnsampled:        "KeysUnsampled",
	StateKeysSampled:          "KeysSampled",
	StateHeaderSent:           "HeaderSent",
	StateCt1Received:          "Ct1Received",
	StateEkSentCt1Received:    "EkSentCt1Received",
	StateNoHeaderReceived:     "NoHeaderReceived",
	StateHeaderReceived:       "HeaderReceived",
	StateCt1Sampled:           "Ct1Sampled",
	StateEkReceivedCt1Sampled: "EkReceivedCt1Sampled",
	StateCt1Acknowledged:      "Ct1Acknowledged",
	StateCt2Sampled:           "Ct2Sampled",
}

// String returns the human-readable name of the state kind.
func (sk StateKind) String() string {
	if name, ok := stateKindNames[sk]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(%d)", sk)
}

// OutputKey represents a derived output key with its associated epoch.
// The Key field is wrapped in a locked-memory-backed Secret for protection
// against swap and core dumps. Callers must copy bytes out before the
// Secret is destroyed.
type OutputKey struct {
	Epoch uint64
	Key   *secret.Secret
}

// State represents the current state of the ML-KEM Braid state machine.
//
// Protocol flow adapted for standard Kyber-1024 (which doesn't support
// incremental encapsulation):
//
//  1. Alice generates keypair, sends Hdr chunks (ek_seed || hek || mac)
//  2. Alice continues sending Ek chunks (ek_vector)
//  3. Bob receives header, verifies MAC, collects ek_vector
//  4. When Bob has full ek_vector: FullEncaps -> (ct1, ct2, ss), KDF_OK, auth.Update
//  5. Bob sends Ct1 chunks
//  6. Alice receives Ct1, sends EkCt1Ack for remaining ek chunks
//  7. Bob receives ct1 ack + remaining ek, sends Ct2 || MAC
//  8. Alice receives Ct2, Decaps -> ss, verifies MAC, derives output key
type State struct {
	kind  StateKind
	epoch uint64
	auth  *Authenticator

	// Encoders for outbound data.
	headerEncoder *Encoder // header || mac
	ekEncoder     *Encoder // ek_vector chunks
	ct1Encoder    *Encoder // ct1 chunks
	ct2Encoder    *Encoder // ct2 || mac chunks

	// Decoders for inbound data.
	headerDecoder *Decoder // header || mac
	ekDecoder     *Decoder // ek_vector chunks
	ct1Decoder    *Decoder // ct1 chunks
	ct2Decoder    *Decoder // ct2 || mac chunks

	// Alice's KEM state (locked-memory-protected).
	dk       *secret.Secret // decapsulation (secret) key
	ekSeed   *secret.Secret // ek_seed (32 bytes)
	ekVector *secret.Secret // ek_vector (noisy vector part)

	// Bob's KEM state (locked-memory-protected).
	bobEkSeed      *secret.Secret // received Alice's ek_seed (from header)
	bobHek         *secret.Secret // received hek (from header)
	bobEncapSecret *secret.Secret // opaque encapsSecret from Encaps1 (ek_seed || hek)
	bobEkVector    *secret.Secret // received Alice's ek_vector
	bobCt1         *secret.Secret // ct1 Bob generated
	bobCt2         *secret.Secret // ct2 Bob generated
	bobSS          *secret.Secret // shared secret from encapsulation

	// Received ct1 data (stored by Alice, locked-memory-protected).
	receivedCt1 *secret.Secret

	// ct1Ack tracks whether Alice has acknowledged receiving ct1.
	ct1Ack bool

	// MAC epoch tracking.
	headerMACEpoch uint64

	// lastReceivedEpoch tracks the most recent epoch seen from the peer.
	lastReceivedEpoch uint64

	// chunkSize is the chunk size for encoding/decoding.
	chunkSize int
}

// Kind returns the current state kind.
func (s *State) Kind() StateKind {
	return s.kind
}

// Epoch returns the current epoch.
func (s *State) Epoch() uint64 {
	return s.epoch
}

// destroySecret is a helper that safely destroys a secret and sets the pointer to nil.
func destroySecret(sp **secret.Secret) {
	if *sp != nil {
		(*sp).Destroy()
		*sp = nil
	}
}

// Zeroize clears all sensitive key material from the state.
func (s *State) Zeroize() {
	destroySecret(&s.dk)
	destroySecret(&s.ekSeed)
	destroySecret(&s.ekVector)
	destroySecret(&s.bobEkSeed)
	destroySecret(&s.bobHek)
	destroySecret(&s.bobEncapSecret)
	destroySecret(&s.bobEkVector)
	destroySecret(&s.bobCt1)
	destroySecret(&s.bobCt2)
	destroySecret(&s.bobSS)
	destroySecret(&s.receivedCt1)
	if s.auth != nil {
		s.auth.Zeroize()
	}
}

// Send produces the next outbound message. Per spec Section 1.1, Send returns
// (msg, sending_epoch, output_key) where sending_epoch is the identifier of
// the latest epoch guaranteed to be known by the other party on receipt of msg.
// The epoch is only incremented on specific state transitions (5 and 13),
// not on every Send call.
func (s *State) Send(kemImpl IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	handler, ok := sendHandlers[s.kind]
	if !ok {
		return nil, 0, nil, &ErrInvalidState{Current: s.kind, Expected: StateKeysUnsampled, Op: "Send"}
	}
	return handler(s, kemImpl)
}

// Receive processes an inbound message. Per spec Section 1.1, Receive returns
// (receiving_epoch, output_key) where receiving_epoch is the epoch identifier
// that was output by the other party as sending_epoch when they called Send()
// to generate msg.
func (s *State) Receive(msg *Message, kemImpl IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	if msg == nil {
		return 0, nil, &ErrInvalidInput{Field: "msg", Reason: "must not be nil"}
	}

	if msg.Epoch < s.lastReceivedEpoch {
		return 0, nil, &ErrInvalidEpoch{Expected: s.lastReceivedEpoch, Received: msg.Epoch}
	}
	// Per Rust spqr states.rs: only Ct2Sampled accepts epoch+1 (next-epoch trigger).
	// Every other state rejects msg.epoch > state.epoch with EpochOutOfRange.
	// This matches `match msg.epoch.cmp(&state.epoch()) { Ordering::Greater => Err(...) }`
	// in all non-Ct2Sampled arms of States::recv.
	if s.kind == StateCt2Sampled {
		// Ct2Sampled allows exactly epoch+1 (handled in receiveCt2Sampled);
		// anything further ahead is still out of range.
		if msg.Epoch > s.epoch+1 {
			return 0, nil, &ErrEpochOutOfRange{Expected: s.epoch, Got: msg.Epoch}
		}
	} else {
		// All other states reject any future-epoch message.
		if msg.Epoch > s.epoch {
			return 0, nil, &ErrEpochOutOfRange{Expected: s.epoch, Got: msg.Epoch}
		}
	}
	s.lastReceivedEpoch = msg.Epoch

	handler, ok := receiveHandlers[s.kind]
	if !ok {
		return 0, nil, &ErrInvalidState{Current: s.kind, Expected: StateHeaderSent, Op: "Receive"}
	}
	return handler(s, msg, kemImpl, chunkSize)
}

// sendHandlers dispatches Send to the appropriate state handler.
var sendHandlers = map[StateKind]func(*State, IncrementalKEM) (*Message, uint64, *OutputKey, error){
	StateKeysUnsampled:        (*State).sendKeysUnsampled,
	StateKeysSampled:          (*State).sendKeysSampled,
	StateHeaderSent:           (*State).sendHeaderSent,
	StateCt1Received:          (*State).sendCt1Received,
	StateEkSentCt1Received:    (*State).sendEkSentCt1Received,
	StateNoHeaderReceived:     (*State).sendNoHeaderReceived,
	StateHeaderReceived:       (*State).sendHeaderReceived,
	StateCt1Sampled:           (*State).sendCt1Sampled,
	StateEkReceivedCt1Sampled: (*State).sendEkReceivedCt1Sampled,
	StateCt1Acknowledged:      (*State).sendCt1Acknowledged,
	StateCt2Sampled:           (*State).sendCt2Sampled,
}

// receiveHandlers dispatches Receive to the appropriate state handler.
var receiveHandlers = map[StateKind]func(*State, *Message, IncrementalKEM, int) (uint64, *OutputKey, error){
	StateKeysUnsampled:        (*State).receiveKeysUnsampled,
	StateKeysSampled:          (*State).receiveKeysSampled,
	StateHeaderSent:           (*State).receiveHeaderSent,
	StateCt1Received:          (*State).receiveCt1Received,
	StateEkSentCt1Received:    (*State).receiveEkSentCt1Received,
	StateNoHeaderReceived:     (*State).receiveNoHeaderReceived,
	StateHeaderReceived:       (*State).receiveHeaderReceived,
	StateCt1Sampled:           (*State).receiveCt1Sampled,
	StateEkReceivedCt1Sampled: (*State).receiveEkReceivedCt1Sampled,
	StateCt1Acknowledged:      (*State).receiveCt1Acknowledged,
	StateCt2Sampled:           (*State).receiveCt2Sampled,
}

// ============================================================================
// Alice state transitions
// ============================================================================

// sendKeysUnsampled: Alice generates keys, starts sending header chunks.
// Per spec: sending_epoch = state.epoch - 1, Transition (1) to KeysSampled.
func (s *State) sendKeysUnsampled(kemImpl IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	dk, ekSeed, ekVector, err := kemImpl.KeyGen()
	if err != nil {
		return nil, 0, nil, err
	}

	s.dk, err = secret.New(dk)
	if err != nil {
		return nil, 0, nil, &ErrKEMOperation{Op: "sendKeysUnsampled dk", Err: err}
	}
	s.ekSeed, err = secret.New(ekSeed)
	if err != nil {
		return nil, 0, nil, &ErrKEMOperation{Op: "sendKeysUnsampled ekSeed", Err: err}
	}
	s.ekVector, err = secret.New(ekVector)
	if err != nil {
		return nil, 0, nil, &ErrKEMOperation{Op: "sendKeysUnsampled ekVector", Err: err}
	}

	// Build header: legacy KEM uses ek_seed(32) || SHA3-256(ek_seed||ek_vector)(32);
	// IncrementalMLKEM768KEM uses pk1 directly as the header (it IS pk1).
	// Detect via headerAwareKEM so the legacy wire format is unchanged.
	var header []byte
	if ha, ok := kemImpl.(headerAwareKEM); ok {
		header = ha.BuildHeader(s.ekSeed.Bytes(), s.ekVector.Bytes())
	} else {
		header = Header(s.ekSeed.Bytes(), s.ekVector.Bytes())
	}

	// MAC the header at auth's current epoch.
	mac, err := s.auth.MacHdr(s.auth.Epoch(), header)
	if err != nil {
		return nil, 0, nil, err
	}
	s.headerMACEpoch = s.auth.Epoch()

	// Encode header || mac.
	payload := make([]byte, 0, HeaderSize+MacSize)
	payload = append(payload, header...)
	payload = append(payload, mac...)

	enc, err := NewEncoder(payload, s.chunkSize)
	if err != nil {
		return nil, 0, nil, err
	}
	s.headerEncoder = enc

	chunk := s.headerEncoder.NextChunk()
	s.kind = StateKeysSampled

	sendingEpoch := s.epoch - 1
	return &Message{Epoch: s.epoch, Type: MessageTypeHdr, Data: chunk}, sendingEpoch, nil, nil
}

// sendKeysSampled: Continue sending header chunks. When done, start ek chunks.
// Per spec: sending_epoch = state.epoch - 1, Transition (2) to HeaderSent.
func (s *State) sendKeysSampled(_ IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	sendingEpoch := s.epoch - 1

	if s.headerEncoder.HasMore() {
		chunk := s.headerEncoder.NextChunk()
		return &Message{Epoch: s.epoch, Type: MessageTypeHdr, Data: chunk}, sendingEpoch, nil, nil
	}

	// Header complete. Initialize ek encoder and transition to HeaderSent.
	if s.ekEncoder == nil {
		enc, err := NewEncoder(s.ekVector.Bytes(), s.chunkSize)
		if err != nil {
			return nil, 0, nil, err
		}
		s.ekEncoder = enc
	}

	s.kind = StateHeaderSent
	chunk := s.ekEncoder.NextChunk()
	return &Message{Epoch: s.epoch, Type: MessageTypeEk, Data: chunk}, sendingEpoch, nil, nil
}

// sendHeaderSent: Send Ek chunks.
// Per spec: sending_epoch = state.epoch - 1.
func (s *State) sendHeaderSent(_ IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	sendingEpoch := s.epoch - 1

	if s.ekEncoder.HasMore() {
		chunk := s.ekEncoder.NextChunk()
		return &Message{Epoch: s.epoch, Type: MessageTypeEk, Data: chunk}, sendingEpoch, nil, nil
	}
	// All ek sent, send None while waiting for ct1.
	return &Message{Epoch: s.epoch, Type: MessageTypeNone}, sendingEpoch, nil, nil
}

// sendCt1Received: Ct1 received, send EkCt1Ack for remaining ek or Ct1Ack.
// Per spec: sending_epoch = state.epoch - 1.
func (s *State) sendCt1Received(_ IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	sendingEpoch := s.epoch - 1

	if s.ekEncoder != nil && s.ekEncoder.HasMore() {
		chunk := s.ekEncoder.NextChunk()
		return &Message{Epoch: s.epoch, Type: MessageTypeEkCt1Ack, Data: chunk}, sendingEpoch, nil, nil
	}
	// All ek sent, transition to EkSentCt1Received.
	s.kind = StateEkSentCt1Received
	return &Message{Epoch: s.epoch, Type: MessageTypeCt1Ack}, sendingEpoch, nil, nil
}

// sendEkSentCt1Received: Wait for ct2.
// Per spec: sending_epoch = state.epoch - 1.
func (s *State) sendEkSentCt1Received(_ IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	sendingEpoch := s.epoch - 1
	return &Message{Epoch: s.epoch, Type: MessageTypeNone}, sendingEpoch, nil, nil
}

// receiveKeysSampled: Alice receives while still sending header. Accept Ct1 or None.
// Per spec: receiving_epoch = state.epoch - 1.
func (s *State) receiveKeysSampled(msg *Message, _ IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	if msg.Type == MessageTypeNone {
		return receivingEpoch, nil, nil
	}
	if msg.Type != MessageTypeCt1 {
		return 0, nil, &ErrInvalidMessageType{Expected: MessageTypeCt1, Received: msg.Type}
	}

	// Init ct1 decoder on first ct1 chunk.
	if s.ct1Decoder == nil {
		dec, err := NewDecoder(MLKEM768CT1Size, chunkSize)
		if err != nil {
			return 0, nil, err
		}
		s.ct1Decoder = dec
	}
	if err := s.ct1Decoder.AddChunk(msg.Data); err != nil {
		return 0, nil, err
	}
	return receivingEpoch, nil, nil
}

// receiveHeaderSent: Alice receives Ct1 chunks while sending Ek.
// Per spec: receiving_epoch = state.epoch - 1, Transition (3) to Ct1Received.
func (s *State) receiveHeaderSent(msg *Message, _ IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	if msg.Type == MessageTypeNone {
		return receivingEpoch, nil, nil
	}
	if msg.Type != MessageTypeCt1 {
		return 0, nil, &ErrInvalidMessageType{Expected: MessageTypeCt1, Received: msg.Type}
	}

	if s.ct1Decoder == nil {
		dec, err := NewDecoder(MLKEM768CT1Size, chunkSize)
		if err != nil {
			return 0, nil, err
		}
		s.ct1Decoder = dec
	}
	if err := s.ct1Decoder.AddChunk(msg.Data); err != nil {
		return 0, nil, err
	}

	if s.ct1Decoder.HasMessage() {
		ct1Data, err := s.ct1Decoder.Message()
		if err != nil {
			return 0, nil, err
		}
		ct1Copy := make([]byte, len(ct1Data))
		copy(ct1Copy, ct1Data)
		destroySecret(&s.receivedCt1)
		s.receivedCt1, err = secret.New(ct1Copy)
		if err != nil {
			return 0, nil, &ErrKEMOperation{Op: "receiveHeaderSent receivedCt1", Err: err}
		}
		s.kind = StateCt1Received
	}
	return receivingEpoch, nil, nil
}

// receiveCt1Received: Alice receives Ct2 chunks.
// Per spec: receiving_epoch = state.epoch - 1, Transition (4) to EkSentCt1Received.
// Even when ct2 arrives in a single chunk, we must transition through
// EkSentCt1Received before completing, matching the spec's state machine
// sequence: Ct1Received -> EkSentCt1Received -> NoHeaderReceived.
func (s *State) receiveCt1Received(msg *Message, kemImpl IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	if msg.Type == MessageTypeNone {
		return receivingEpoch, nil, nil
	}
	if msg.Type != MessageTypeCt2 {
		return 0, nil, &ErrInvalidMessageType{Expected: MessageTypeCt2, Received: msg.Type}
	}

	if s.ct2Decoder == nil {
		dec, err := NewDecoder(MLKEM768CT2Size+MacSize, chunkSize)
		if err != nil {
			return 0, nil, err
		}
		s.ct2Decoder = dec
	}
	if err := s.ct2Decoder.AddChunk(msg.Data); err != nil {
		return 0, nil, err
	}

	// Always transition to EkSentCt1Received first (spec Transition 4).
	// If ct2 is already complete, aliceCompleteCt2 will handle
	// Transition 5 to NoHeaderReceived from the EkSentCt1Received state.
	s.kind = StateEkSentCt1Received

	if s.ct2Decoder.HasMessage() {
		return s.aliceCompleteCt2(msg, kemImpl)
	}
	return receivingEpoch, nil, nil
}

// receiveEkSentCt1Received: Alice receives Ct2 chunks and completes.
// Per spec: receiving_epoch = state.epoch - 1, Transition (5) to NoHeaderReceived.
func (s *State) receiveEkSentCt1Received(msg *Message, kemImpl IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	if msg.Type == MessageTypeNone {
		return receivingEpoch, nil, nil
	}
	if msg.Type != MessageTypeCt2 {
		return 0, nil, &ErrInvalidMessageType{Expected: MessageTypeCt2, Received: msg.Type}
	}

	if s.ct2Decoder == nil {
		dec, err := NewDecoder(MLKEM768CT2Size+MacSize, chunkSize)
		if err != nil {
			return 0, nil, err
		}
		s.ct2Decoder = dec
	}
	if err := s.ct2Decoder.AddChunk(msg.Data); err != nil {
		return 0, nil, err
	}

	if !s.ct2Decoder.HasMessage() {
		return receivingEpoch, nil, nil
	}

	return s.aliceCompleteCt2(msg, kemImpl)
}

// aliceCompleteCt2 performs Alice's final steps per spec Section 2.5
// (EkSentCt1Received.Receive): Decaps, KDF_OK, auth.Update with KDF_OK output,
// VfyCt, then Transition (5) to NoHeaderReceived with epoch+1.
func (s *State) aliceCompleteCt2(_ *Message, kemImpl IncrementalKEM) (uint64, *OutputKey, error) {
	data, err := s.ct2Decoder.Message()
	if err != nil {
		return 0, nil, err
	}

	ct2 := data[:MLKEM768CT2Size]
	mac := data[MLKEM768CT2Size:]

	// Use the KEM instance provided by the caller for decapsulation.
	ss, err := kemImpl.Decaps(s.dk.Bytes(), s.receivedCt1.Bytes(), ct2)
	if err != nil {
		return 0, nil, err
	}
	defer crypto.Zeroize(ss)

	currentEpoch := s.auth.Epoch()

	// Per spec: ss = KDF_OK(ss, state.epoch) -- overwrite ss with KDF output.
	outputKey, err := KDFOK(ss, currentEpoch)
	if err != nil {
		return 0, nil, err
	}
	defer crypto.Zeroize(outputKey)

	// Clone the authenticator before Update so we can roll back if VfyCt fails.
	// Without this, a forged ct2 that passes Decaps but fails VfyCt permanently
	// advances the auth mac_key, desynchronizing Alice's and Bob's authenticators
	// for all future epochs (Finding 2).
	//
	// Per protocol: auth.Update advances the mac_key to the same state Bob used when
	// computing the MAC, so VfyCt MUST use the post-Update mac_key. The clone is only
	// used for rollback; VfyCt always runs on the updated auth.
	preUpdateAuth, err := s.auth.Clone()
	if err != nil {
		return 0, nil, &ErrKEMOperation{Op: "aliceCompleteCt2/auth.Clone", Err: err}
	}
	if err := s.auth.Update(currentEpoch, outputKey); err != nil {
		preUpdateAuth.Zeroize()
		return 0, nil, err
	}

	// VfyCt(epoch, ct1||ct2, mac) using the post-Update mac_key.
	receivedCt1Bytes := s.receivedCt1.Bytes()
	fullCT := make([]byte, 0, len(receivedCt1Bytes)+len(ct2))
	fullCT = append(fullCT, receivedCt1Bytes...)
	fullCT = append(fullCT, ct2...)

	valid, err := s.auth.VfyCt(currentEpoch, fullCT, mac)
	if err != nil {
		// Roll back auth to pre-Update state on any error.
		s.auth.Zeroize()
		s.auth = preUpdateAuth
		return 0, nil, err
	}
	if !valid {
		// Roll back auth so the session is intact for a legitimate retry.
		s.auth.Zeroize()
		s.auth = preUpdateAuth
		return 0, nil, &ErrMACVerification{Epoch: currentEpoch, Kind: "ct"}
	}
	preUpdateAuth.Zeroize()

	// Destroy intermediate secret state.
	destroySecret(&s.dk)
	destroySecret(&s.receivedCt1)

	// Transition (5): EkSentCt1Received -> NoHeaderReceived with epoch+1.
	if s.epoch == math.MaxUint64 {
		return 0, nil, &ErrEpochOverflow{}
	}
	s.epoch++
	s.kind = StateNoHeaderReceived
	headerDec, headerErr := NewDecoder(HeaderSize+MacSize, s.chunkSize)
	if headerErr != nil {
		return 0, nil, &ErrKEMOperation{Op: "receiveEkSentCt1Received/headerDecoder", Err: headerErr}
	}
	s.headerDecoder = headerDec
	s.ct1Decoder = nil
	s.ct2Decoder = nil
	s.ekEncoder = nil
	s.headerEncoder = nil

	receivingEpoch := s.epoch - 1
	outputSecret, err := secret.New(outputKey)
	if err != nil {
		return 0, nil, &ErrKEMOperation{Op: "receiveEkSentCt1Received/outputKey", Err: err}
	}
	return receivingEpoch, &OutputKey{Epoch: currentEpoch, Key: outputSecret}, nil
}

// ============================================================================
// Bob state transitions
// ============================================================================

// sendNoHeaderReceived: Bob sends None while waiting for header.
// Per spec: sending_epoch = state.epoch - 1.
func (s *State) sendNoHeaderReceived(_ IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	sendingEpoch := s.epoch - 1
	return &Message{Epoch: s.epoch, Type: MessageTypeNone}, sendingEpoch, nil, nil
}

// sendHeaderReceived: Bob has header (ek_seed + hek) but does not yet have ek_vector.
// Per spec Section 2.5 (HeaderReceived.Send): computes Encaps1 to initiate
// the two-phase encapsulation. Since ML-KEM-1024 cannot produce ct1 without the
// full ek, Encaps1 stores ek_seed and hek into an opaque encapsSecret token.
// The actual crypto (ct1, ct2, shared_secret) is deferred to CompleteEncaps2
// when ek_vector arrives. Bob sends None while waiting for ek_vector chunks.
//
// The encapsSecret is stored in bobEncapSecret so that receiveHeaderReceived
// can call CompleteEncaps2 when the ek_vector decoder completes.
func (s *State) sendHeaderReceived(kemImpl IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	sendingEpoch := s.epoch - 1

	// Perform Encaps1 on first Send in this state (idempotent guard).
	if s.bobEncapSecret == nil && s.bobEkSeed != nil && s.bobHek != nil {
		encapsSecret, _, _, err := kemImpl.Encaps1(s.bobEkSeed.Bytes(), s.bobHek.Bytes())
		if err != nil {
			return nil, 0, nil, err
		}
		s.bobEncapSecret, err = secret.New(encapsSecret)
		if err != nil {
			return nil, 0, nil, &ErrKEMOperation{Op: "sendHeaderReceived bobEncapSecret", Err: err}
		}
	}

	return &Message{Epoch: s.epoch, Type: MessageTypeNone}, sendingEpoch, nil, nil
}

// sendCt1Sampled: Bob sends ct1 chunks.
// Per spec: sending_epoch = state.epoch - 1.
func (s *State) sendCt1Sampled(_ IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	sendingEpoch := s.epoch - 1

	if s.ct1Encoder != nil && s.ct1Encoder.HasMore() {
		chunk := s.ct1Encoder.NextChunk()
		return &Message{Epoch: s.epoch, Type: MessageTypeCt1, Data: chunk}, sendingEpoch, nil, nil
	}
	if s.ct1Encoder != nil {
		// Wrap around for retransmission: intentionally re-sends chunks from
		// the beginning when all unique chunks have been sent. This matches
		// Rust's PolyEncoder wrapping behavior and provides redundancy for
		// reliability when messages are lost or reordered.
		return &Message{Epoch: s.epoch, Type: MessageTypeCt1, Data: s.ct1Encoder.NextChunk()}, sendingEpoch, nil, nil
	}
	return &Message{Epoch: s.epoch, Type: MessageTypeNone}, sendingEpoch, nil, nil
}

// sendEkReceivedCt1Sampled: Send remaining ct1 chunks.
// Per spec: sending_epoch = state.epoch - 1.
func (s *State) sendEkReceivedCt1Sampled(_ IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	sendingEpoch := s.epoch - 1

	if s.ct1Encoder != nil && s.ct1Encoder.HasMore() {
		chunk := s.ct1Encoder.NextChunk()
		return &Message{Epoch: s.epoch, Type: MessageTypeCt1, Data: chunk}, sendingEpoch, nil, nil
	}
	if s.ct1Encoder != nil {
		// Wrap around for retransmission redundancy (see sendCt1Sampled).
		return &Message{Epoch: s.epoch, Type: MessageTypeCt1, Data: s.ct1Encoder.NextChunk()}, sendingEpoch, nil, nil
	}
	return &Message{Epoch: s.epoch, Type: MessageTypeNone}, sendingEpoch, nil, nil
}

// sendCt1Acknowledged: Continue sending ct1 chunks while waiting for remaining ek.
// Per spec: sending_epoch = state.epoch - 1.
func (s *State) sendCt1Acknowledged(_ IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	sendingEpoch := s.epoch - 1

	if s.ct1Encoder != nil && s.ct1Encoder.HasMore() {
		chunk := s.ct1Encoder.NextChunk()
		return &Message{Epoch: s.epoch, Type: MessageTypeCt1, Data: chunk}, sendingEpoch, nil, nil
	}
	if s.ct1Encoder != nil {
		// Wrap around for retransmission redundancy (see sendCt1Sampled).
		return &Message{Epoch: s.epoch, Type: MessageTypeCt1, Data: s.ct1Encoder.NextChunk()}, sendingEpoch, nil, nil
	}
	return &Message{Epoch: s.epoch, Type: MessageTypeNone}, sendingEpoch, nil, nil
}

// sendCt2Sampled: Send ct2 chunks.
// Per spec: sending_epoch = state.epoch - 1.
func (s *State) sendCt2Sampled(_ IncrementalKEM) (*Message, uint64, *OutputKey, error) {
	sendingEpoch := s.epoch - 1

	if s.ct2Encoder != nil && s.ct2Encoder.HasMore() {
		chunk := s.ct2Encoder.NextChunk()
		return &Message{Epoch: s.epoch, Type: MessageTypeCt2, Data: chunk}, sendingEpoch, nil, nil
	}
	if s.ct2Encoder != nil {
		// Wrap around for retransmission redundancy (see sendCt1Sampled).
		return &Message{Epoch: s.epoch, Type: MessageTypeCt2, Data: s.ct2Encoder.NextChunk()}, sendingEpoch, nil, nil
	}
	return &Message{Epoch: s.epoch, Type: MessageTypeNone}, sendingEpoch, nil, nil
}

// receiveKeysUnsampled: Alice in KeysUnsampled ignores all messages per spec.
// Per spec: receiving_epoch = state.epoch - 1.
func (s *State) receiveKeysUnsampled(_ *Message, _ IncrementalKEM, _ int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1
	return receivingEpoch, nil, nil
}

// receiveNoHeaderReceived: Bob receives header chunks.
// Per spec: receiving_epoch = state.epoch - 1. Requires msg.epoch == state.epoch.
// Transition (6) to HeaderReceived.
func (s *State) receiveNoHeaderReceived(msg *Message, kemImpl IncrementalKEM, _ int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	if msg.Type == MessageTypeNone {
		return receivingEpoch, nil, nil
	}
	if msg.Type != MessageTypeHdr {
		return 0, nil, &ErrInvalidMessageType{Expected: MessageTypeHdr, Received: msg.Type}
	}

	// Per spec: only process Hdr messages for the current epoch.
	if msg.Epoch != s.epoch {
		return receivingEpoch, nil, nil
	}

	if s.headerDecoder == nil {
		return 0, nil, &ErrInvalidState{
			Current:  s.kind,
			Expected: StateNoHeaderReceived,
			Op:       "Receive (no header decoder)",
		}
	}

	if s.headerDecoder.ReceivedCount() == 0 {
		s.headerMACEpoch = msg.Epoch
	}

	if err := s.headerDecoder.AddChunk(msg.Data); err != nil {
		return 0, nil, err
	}

	if s.headerDecoder.HasMessage() {
		data, err := s.headerDecoder.Message()
		if err != nil {
			return 0, nil, err
		}

		header := data[:HeaderSize]
		mac := data[HeaderSize:]

		// Verify MAC.
		valid, err := s.auth.VfyHdr(s.auth.Epoch(), header, mac)
		if err != nil {
			return 0, nil, err
		}
		if !valid {
			return 0, nil, &ErrMACVerification{Epoch: s.auth.Epoch(), Kind: "header"}
		}

		// Extract ek_seed and hek into guarded memory.
		// IncrementalMLKEM768KEM: ek_seed = full header = pk1 (64 bytes).
		// Legacy MLKEM768IncrementalKEM: ek_seed = header[:32], hek = header[32:64].
		var ekSeedData []byte
		if ha, ok := kemImpl.(headerAwareKEM); ok {
			full := ha.EKSeedFromHeader(header)
			ekSeedData = make([]byte, len(full))
			copy(ekSeedData, full)
		} else {
			ekSeedData = make([]byte, EKSeedSize)
			copy(ekSeedData, header[:EKSeedSize])
		}
		destroySecret(&s.bobEkSeed)
		s.bobEkSeed, err = secret.New(ekSeedData)
		if err != nil {
			return 0, nil, &ErrKEMOperation{Op: "receiveNoHeaderReceived bobEkSeed", Err: err}
		}

		// hekData: for legacy KEM = header[32:64]; for IncrementalMLKEM768KEM = header[32:64] = H(ek).
		// IncrementalMLKEM768KEM.Encaps1 ignores hek, but verifyEkVector uses it for the legacy path.
		hekData := make([]byte, 32)
		copy(hekData, header[EKSeedSize:])
		destroySecret(&s.bobHek)
		s.bobHek, err = secret.New(hekData)
		if err != nil {
			return 0, nil, &ErrKEMOperation{Op: "receiveNoHeaderReceived bobHek", Err: err}
		}

		s.kind = StateHeaderReceived
	}

	return receivingEpoch, nil, nil
}

// receiveHeaderReceived: Bob receives Ek chunks after header is complete.
// Per spec: receiving_epoch = state.epoch - 1.
func (s *State) receiveHeaderReceived(msg *Message, kemImpl IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	if msg.Type == MessageTypeNone {
		return receivingEpoch, nil, nil
	}
	if msg.Type != MessageTypeEk && msg.Type != MessageTypeEkCt1Ack {
		return 0, nil, &ErrInvalidMessageType{Expected: MessageTypeEk, Received: msg.Type}
	}

	if s.ekDecoder == nil {
		dec, err := NewDecoder(MLKEM768EKSize, chunkSize)
		if err != nil {
			return 0, nil, err
		}
		s.ekDecoder = dec
	}
	if err := s.ekDecoder.AddChunk(msg.Data); err != nil {
		return 0, nil, err
	}

	if msg.Type == MessageTypeEkCt1Ack {
		s.ct1Ack = true
	}

	if !s.ekDecoder.HasMessage() {
		return receivingEpoch, nil, nil
	}

	// ek_vector complete. Verify hek and encapsulate.
	outputKey, err := s.bobCompleteEncapsulation(kemImpl, chunkSize)
	if err != nil {
		return 0, nil, err
	}
	return receivingEpoch, outputKey, nil
}

// receiveCt1Sampled: Bob in Ct1Sampled receives Ek, EkCt1Ack, or Ct1Ack.
// Per spec Section 2.5:
//   - Transition 10 (receives Ek): collect ek chunks; when ek complete,
//     verify hek, transition to EkReceivedCt1Sampled (wait for ct1 ack).
//   - Transition 8 (receives EkCt1Ack, ek incomplete): add ek chunk,
//     transition to Ct1Acknowledged.
//   - Transition 9 (receives EkCt1Ack, ek complete + acknowledged):
//     verify hek, FullEncaps, compute MAC, create ct2_encoder,
//     transition to Ct2Sampled.
//   - Ct1Ack with ek already complete: transition directly to Ct2Sampled.
//
// When encapsulation was already completed (via bobCompleteEncapsulation from
// HeaderReceived), the ct2Encoder is non-nil and re-encapsulation is skipped.
// receiving_epoch = state.epoch - 1.
func (s *State) receiveCt1Sampled(msg *Message, kemImpl IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	if msg.Type == MessageTypeNone {
		return receivingEpoch, nil, nil
	}

	switch msg.Type {
	case MessageTypeEk:
		return s.receiveCt1SampledEk(msg, chunkSize)

	case MessageTypeEkCt1Ack:
		return s.receiveCt1SampledEkCt1Ack(msg, kemImpl, chunkSize)

	case MessageTypeCt1Ack:
		return s.receiveCt1SampledCt1Ack(kemImpl, chunkSize)

	default:
		return 0, nil, &ErrInvalidMessageType{Expected: MessageTypeEkCt1Ack, Received: msg.Type}
	}
}

// receiveCt1SampledEk handles Transition 10: Ct1Sampled receives Ek.
// Collects ek chunks. When ek_decoder completes, verifies hek and transitions
// to EkReceivedCt1Sampled (waiting for ct1 ack before completing encapsulation).
func (s *State) receiveCt1SampledEk(msg *Message, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	// If encapsulation is already complete, accept ek chunks silently.
	if s.ct2Encoder != nil {
		return receivingEpoch, nil, nil
	}

	if s.ekDecoder == nil {
		dec, err := NewDecoder(MLKEM768EKSize, chunkSize)
		if err != nil {
			return 0, nil, err
		}
		s.ekDecoder = dec
	}
	if err := s.ekDecoder.AddChunk(msg.Data); err != nil {
		return 0, nil, err
	}

	if s.ekDecoder.HasMessage() {
		ekVector, err := s.ekDecoder.Message()
		if err != nil {
			return 0, nil, err
		}

		if err := s.verifyEkVector(ekVector); err != nil {
			return 0, nil, err
		}

		ekVectorCopy := make([]byte, len(ekVector))
		copy(ekVectorCopy, ekVector)
		destroySecret(&s.bobEkVector)
		s.bobEkVector, err = secret.New(ekVectorCopy)
		if err != nil {
			return 0, nil, &ErrKEMOperation{Op: "receiveCt1SampledEk bobEkVector", Err: err}
		}

		s.kind = StateEkReceivedCt1Sampled
	}

	return receivingEpoch, nil, nil
}

// receiveCt1SampledEkCt1Ack handles Transitions 8 and 9:
// Ct1Sampled receives EkCt1Ack.
//   - Transition 8: ek_decoder NOT complete -> Ct1Acknowledged.
//   - Transition 9: ek_decoder IS complete -> verify hek, FullEncaps,
//     compute MAC, create ct2_encoder -> Ct2Sampled.
func (s *State) receiveCt1SampledEkCt1Ack(msg *Message, kemImpl IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1
	s.ct1Ack = true

	// If encapsulation is already complete, transition directly to Ct2Sampled.
	if s.ct2Encoder != nil {
		s.kind = StateCt2Sampled
		return receivingEpoch, nil, nil
	}

	// Initialize ek_decoder if needed and add the ek chunk from this message.
	if s.ekDecoder == nil {
		dec, err := NewDecoder(MLKEM768EKSize, chunkSize)
		if err != nil {
			return 0, nil, err
		}
		s.ekDecoder = dec
	}
	if len(msg.Data) > 0 {
		if err := s.ekDecoder.AddChunk(msg.Data); err != nil {
			return 0, nil, err
		}
	}

	if !s.ekDecoder.HasMessage() {
		// Transition 8: ek incomplete, but ct1 acknowledged.
		s.kind = StateCt1Acknowledged
		return receivingEpoch, nil, nil
	}

	// Transition 9: ek complete AND ct1 acknowledged -> complete encapsulation.
	return s.bobCompleteEncapsulationDeferred(kemImpl, chunkSize)
}

// receiveCt1SampledCt1Ack handles Ct1Sampled receiving a bare Ct1Ack (no ek data).
// If encapsulation is already complete or ek_vector is available, transitions to
// Ct2Sampled. Otherwise waits in Ct1Acknowledged for remaining ek.
func (s *State) receiveCt1SampledCt1Ack(kemImpl IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1
	s.ct1Ack = true

	// If encapsulation is already complete, transition directly.
	if s.ct2Encoder != nil {
		s.kind = StateCt2Sampled
		return receivingEpoch, nil, nil
	}

	// If ek_vector was already received (from transition 10), complete now.
	if s.bobEkVector != nil {
		return s.bobCompleteEncapsulationDeferred(kemImpl, chunkSize)
	}

	// If ek_decoder is complete, complete now.
	if s.ekDecoder != nil && s.ekDecoder.HasMessage() {
		return s.bobCompleteEncapsulationDeferred(kemImpl, chunkSize)
	}

	// ek not yet complete. Wait for remaining ek in Ct1Acknowledged state.
	s.kind = StateCt1Acknowledged
	return receivingEpoch, nil, nil
}

// receiveEkReceivedCt1Sampled: Bob has full ek_vector but awaits ct1 acknowledgment.
// Per spec: receiving_epoch = state.epoch - 1. On Ct1Ack or EkCt1Ack,
// triggers FullEncaps and transitions to Ct2Sampled.
func (s *State) receiveEkReceivedCt1Sampled(msg *Message, kemImpl IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	if msg.Type == MessageTypeNone {
		return receivingEpoch, nil, nil
	}
	if msg.Type == MessageTypeEkCt1Ack || msg.Type == MessageTypeCt1Ack {
		s.ct1Ack = true

		// If encapsulation is already complete, transition directly.
		if s.ct2Encoder != nil {
			s.kind = StateCt2Sampled
			return receivingEpoch, nil, nil
		}

		// Complete encapsulation now that ct1 is acknowledged.
		return s.bobCompleteEncapsulationDeferred(kemImpl, chunkSize)
	}
	return 0, nil, &ErrInvalidMessageType{Expected: MessageTypeEkCt1Ack, Received: msg.Type}
}

// receiveCt1Acknowledged: Bob has ct1 acknowledgment but awaits remaining ek chunks.
// Per spec: receiving_epoch = state.epoch - 1. Accepts Ek chunks; when ek_decoder
// completes, triggers FullEncaps and transitions to Ct2Sampled.
func (s *State) receiveCt1Acknowledged(msg *Message, kemImpl IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	if msg.Type == MessageTypeNone {
		return receivingEpoch, nil, nil
	}

	switch msg.Type {
	case MessageTypeEk, MessageTypeEkCt1Ack:
		// Continue collecting ek chunks.
		if s.ekDecoder == nil {
			dec, err := NewDecoder(MLKEM768EKSize, chunkSize)
			if err != nil {
				return 0, nil, err
			}
			s.ekDecoder = dec
		}
		if len(msg.Data) > 0 {
			if err := s.ekDecoder.AddChunk(msg.Data); err != nil {
				return 0, nil, err
			}
		}

		if !s.ekDecoder.HasMessage() {
			return receivingEpoch, nil, nil
		}

		// ek complete. Complete encapsulation.
		return s.bobCompleteEncapsulationDeferred(kemImpl, chunkSize)

	default:
		return 0, nil, &ErrInvalidMessageType{Expected: MessageTypeEk, Received: msg.Type}
	}
}

// verifyEkVector verifies that ekVector (pk2) is consistent with the stored
// bobEkSeed (pk1) and bobHek. Accepts both KEM implementations:
//
//   - Legacy (MLKEM768IncrementalKEM): hek = SHA3-256(ek_seed[0:32] || ekVector)
//   - Incremental (IncrementalMLKEM768KEM): uses ValidatePKBytes(pk1, pk2) which
//     checks SHA3-256(pk2 || pk1[:32]) == pk1[32:64].
func (s *State) verifyEkVector(ekVector []byte) error {
	if s.bobEkSeed == nil || s.bobHek == nil {
		return &ErrInvalidState{
			Current:  s.kind,
			Expected: StateCt1Sampled,
			Op:       "verifyEkVector (missing ek_seed or hek)",
		}
	}

	// If bobEkSeed is 64 bytes (pk1 format), use IncrementalVerifyEKVector.
	// If bobEkSeed is 32 bytes (legacy format), use the legacy SHA3-256 check.
	pk1 := s.bobEkSeed.Bytes()
	if len(pk1) == imlkem.PublicKey1Size {
		if err := IncrementalVerifyEKVector(pk1, ekVector); err != nil {
			return &ErrHeaderFormat{Reason: "pk2 does not match pk1 for incremental KEM"}
		}
		return nil
	}

	computedHEK := computeHEK(pk1, ekVector)
	if subtle.ConstantTimeCompare(computedHEK, s.bobHek.Bytes()) != 1 {
		return &ErrHeaderFormat{Reason: "hek does not match received ek_vector"}
	}
	return nil
}

// bobCompleteEncapsulationDeferred performs full encapsulation when Bob has both
// ek_vector and ct1 acknowledgment, entering from Ct1Sampled, EkReceivedCt1Sampled,
// or Ct1Acknowledged. Uses CompleteEncaps2 if bobEncapSecret is available,
// otherwise falls back to FullEncaps with explicit hek verification.
// Computes MAC over ct1||ct2, creates ct2_encoder, transitions to Ct2Sampled.
func (s *State) bobCompleteEncapsulationDeferred(kemImpl IncrementalKEM, chunkSize int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	// Retrieve ek_vector from stored field or from decoder.
	var ekVector []byte
	if s.bobEkVector != nil {
		ekVector = s.bobEkVector.Bytes()
	}
	if len(ekVector) == 0 && s.ekDecoder != nil && s.ekDecoder.HasMessage() {
		var err error
		ekVector, err = s.ekDecoder.Message()
		if err != nil {
			return 0, nil, err
		}
	}
	if len(ekVector) == 0 {
		return 0, nil, &ErrInvalidState{
			Current:  s.kind,
			Expected: StateCt1Sampled,
			Op:       "bobCompleteEncapsulationDeferred (no ek_vector)",
		}
	}

	completer, ok := kemImpl.(kemCompleter)
	if !ok {
		return 0, nil, &ErrKEMOperation{Op: "FullEncaps", Err: &ErrInvalidInput{
			Field: "kemImpl", Reason: "must implement kemCompleter (MLKEM768IncrementalKEM or IncrementalMLKEM768KEM)",
		}}
	}

	// Always verify ekVector authenticity before encapsulating (Finding 3).
	// The two-phase path (bobEncapSecret != nil) previously skipped this check,
	// allowing a tampered ek_vector to silently produce a mismatched shared secret.
	if err := s.verifyEkVector(ekVector); err != nil {
		return 0, nil, err
	}

	var ct1, ct2, ss []byte
	var err error

	if s.bobEncapSecret != nil {
		// Two-phase path: Encaps1 was called in sendHeaderReceived.
		ct1, ct2, ss, err = completer.CompleteEncaps2(s.bobEncapSecret.Bytes(), s.bobEkSeed.Bytes(), ekVector)
		if err != nil {
			return 0, nil, err
		}
		destroySecret(&s.bobEncapSecret)
	} else {
		// Single-phase path: encapsulate directly (ekVector verified above).
		ct1, ct2, ss, err = completer.FullEncaps(s.bobEkSeed.Bytes(), ekVector)
		if err != nil {
			return 0, nil, err
		}
	}
	defer crypto.Zeroize(ss)

	currentEpoch := s.auth.Epoch()

	outputKey, err := KDFOK(ss, currentEpoch)
	if err != nil {
		return 0, nil, err
	}
	defer crypto.Zeroize(outputKey)

	if err := s.auth.Update(currentEpoch, outputKey); err != nil {
		return 0, nil, err
	}

	// MAC over ct1 || ct2.
	fullCT := make([]byte, 0, len(ct1)+len(ct2))
	fullCT = append(fullCT, ct1...)
	fullCT = append(fullCT, ct2...)

	ctMAC, err := s.auth.MacCt(currentEpoch, fullCT)
	if err != nil {
		return 0, nil, err
	}

	// Store ct1 and ct2 in guarded memory.
	destroySecret(&s.bobCt1)
	s.bobCt1, err = secret.New(ct1)
	if err != nil {
		return 0, nil, &ErrKEMOperation{Op: "bobCompleteEncapsulationDeferred bobCt1", Err: err}
	}
	destroySecret(&s.bobCt2)
	s.bobCt2, err = secret.New(ct2)
	if err != nil {
		return 0, nil, &ErrKEMOperation{Op: "bobCompleteEncapsulationDeferred bobCt2", Err: err}
	}

	// Encode ct1 if not already encoded.
	if s.ct1Encoder == nil {
		ct1Enc, err := NewEncoder(s.bobCt1.Bytes(), chunkSize)
		if err != nil {
			return 0, nil, err
		}
		s.ct1Encoder = ct1Enc
	}

	// Encode ct2 || MAC.
	ct2Bytes := s.bobCt2.Bytes()
	ct2WithMAC := make([]byte, 0, len(ct2Bytes)+MacSize)
	ct2WithMAC = append(ct2WithMAC, ct2Bytes...)
	ct2WithMAC = append(ct2WithMAC, ctMAC...)

	ct2Enc, err := NewEncoder(ct2WithMAC, chunkSize)
	if err != nil {
		return 0, nil, err
	}
	s.ct2Encoder = ct2Enc

	// Zeroize intermediate material.
	destroySecret(&s.bobEkSeed)
	destroySecret(&s.bobHek)
	destroySecret(&s.bobEkVector)

	s.kind = StateCt2Sampled

	outputSecret, err := secret.New(outputKey)
	if err != nil {
		return 0, nil, &ErrKEMOperation{Op: "bobCompleteEncapsulationDeferred/outputKey", Err: err}
	}
	return receivingEpoch, &OutputKey{Epoch: currentEpoch, Key: outputSecret}, nil
}

// receiveCt2Sampled: Bob in Ct2Sampled sends ct2 and waits for next epoch.
// Per spec Section 2.5 (Ct2Sampled.Receive): if msg.epoch == state.epoch + 1,
// Transition (13) to KeysUnsampled with epoch+1.
// receiving_epoch = state.epoch - 1.
func (s *State) receiveCt2Sampled(msg *Message, _ IncrementalKEM, _ int) (uint64, *OutputKey, error) {
	receivingEpoch := s.epoch - 1

	// Check for Transition (13): next epoch has begun.
	// Per Rust sparsepostquantumratchet states.rs Ct2Sampled arm: ANY message with
	// epoch == state.epoch+1 triggers recv_next_epoch regardless of message type.
	//
	// Defense-in-depth note: tearing down the epoch on the FIRST message carrying
	// epoch+1 (before Alice confirms key receipt) is intentional — it matches the
	// Rust reference and prevents the receiver from accumulating stale epoch state.
	// An attacker injecting a spoofed epoch+1 message can only cause Bob to advance
	// his own epoch counter early; he cannot forge Alice's epoch advance (which
	// requires a valid VfyCt MAC from Alice). This is an inherent property of the
	// protocol design (see also Rust's ct2_sampled_receive in states.rs).
	if msg.Epoch == s.epoch+1 {
		// Destroy secrets from the completed epoch before transitioning.
		destroySecret(&s.bobCt1)
		destroySecret(&s.bobCt2)
		destroySecret(&s.bobSS)
		destroySecret(&s.bobEncapSecret)

		if s.epoch == math.MaxUint64 {
			return 0, nil, &ErrEpochOverflow{}
		}
		s.epoch++
		s.kind = StateKeysUnsampled

		// Reset state for new epoch.
		s.ct2Encoder = nil
		s.ct1Encoder = nil
		s.ekDecoder = nil
		s.ct1Ack = false

		return receivingEpoch, nil, nil
	}

	// Accept messages from current epoch silently.
	return receivingEpoch, nil, nil
}

// bobCompleteEncapsulation performs the second phase of two-phase incremental
// encapsulation when ek_vector is available. Routes through the kemCompleter
// interface so that both MLKEM768IncrementalKEM and IncrementalMLKEM768KEM
// complete correctly (Finding 1). Always verifies ekVector before encapsulating
// regardless of which path (two-phase vs single-phase) is taken (Finding 3).
func (s *State) bobCompleteEncapsulation(kemImpl IncrementalKEM, chunkSize int) (*OutputKey, error) {
	ekVectorData, err := s.ekDecoder.Message()
	if err != nil {
		return nil, err
	}

	ekVectorCopy := make([]byte, len(ekVectorData))
	copy(ekVectorCopy, ekVectorData)
	destroySecret(&s.bobEkVector)
	s.bobEkVector, err = secret.New(ekVectorCopy)
	if err != nil {
		return nil, &ErrKEMOperation{Op: "bobCompleteEncapsulation bobEkVector", Err: err}
	}

	completer, ok := kemImpl.(kemCompleter)
	if !ok {
		return nil, &ErrKEMOperation{Op: "bobCompleteEncapsulation", Err: &ErrInvalidInput{
			Field: "kemImpl", Reason: "must implement kemCompleter (MLKEM768IncrementalKEM or IncrementalMLKEM768KEM)",
		}}
	}

	// Always verify ekVector authenticity before encapsulating (Finding 3).
	// This applies to both the two-phase path (bobEncapSecret != nil) and the
	// single-phase path, preventing a tampered ek_vector from producing a
	// shared secret that Alice can never replicate.
	if err := s.verifyEkVector(s.bobEkVector.Bytes()); err != nil {
		return nil, err
	}

	var ct1, ct2, ss []byte

	if s.bobEncapSecret != nil {
		// Two-phase path: Encaps1 was called in sendHeaderReceived.
		ct1, ct2, ss, err = completer.CompleteEncaps2(s.bobEncapSecret.Bytes(), s.bobEkSeed.Bytes(), s.bobEkVector.Bytes())
		if err != nil {
			return nil, err
		}
		destroySecret(&s.bobEncapSecret)
	} else {
		// Single-phase path: ekVector was available from the start.
		ct1, ct2, ss, err = completer.FullEncaps(s.bobEkSeed.Bytes(), s.bobEkVector.Bytes())
		if err != nil {
			return nil, err
		}
	}
	defer crypto.Zeroize(ss)

	currentEpoch := s.auth.Epoch()

	// Per spec: ss = KDF_OK(ss, state.epoch) -- overwrite ss with KDF output.
	outputKey, err := KDFOK(ss, currentEpoch)
	if err != nil {
		return nil, err
	}
	defer crypto.Zeroize(outputKey)

	// Per spec: auth.Update(state.epoch, ss) -- uses KDF_OK-derived key.
	if err := s.auth.Update(currentEpoch, outputKey); err != nil {
		return nil, err
	}

	// MAC over ct1 || ct2.
	fullCT := make([]byte, 0, len(ct1)+len(ct2))
	fullCT = append(fullCT, ct1...)
	fullCT = append(fullCT, ct2...)

	ctMAC, err := s.auth.MacCt(currentEpoch, fullCT)
	if err != nil {
		return nil, err
	}

	// Store ct1 and ct2 in guarded memory.
	destroySecret(&s.bobCt1)
	s.bobCt1, err = secret.New(ct1)
	if err != nil {
		return nil, &ErrKEMOperation{Op: "bobCompleteEncapsulation bobCt1", Err: err}
	}
	destroySecret(&s.bobCt2)
	s.bobCt2, err = secret.New(ct2)
	if err != nil {
		return nil, &ErrKEMOperation{Op: "bobCompleteEncapsulation bobCt2", Err: err}
	}

	// Encode ct1 for sending.
	ct1Enc, err := NewEncoder(s.bobCt1.Bytes(), chunkSize)
	if err != nil {
		return nil, err
	}
	s.ct1Encoder = ct1Enc

	// Encode ct2 || MAC for sending.
	ct2Bytes := s.bobCt2.Bytes()
	ct2WithMAC := make([]byte, 0, len(ct2Bytes)+MacSize)
	ct2WithMAC = append(ct2WithMAC, ct2Bytes...)
	ct2WithMAC = append(ct2WithMAC, ctMAC...)

	ct2Enc, err := NewEncoder(ct2WithMAC, chunkSize)
	if err != nil {
		return nil, err
	}
	s.ct2Encoder = ct2Enc

	// Zeroize intermediate material.
	destroySecret(&s.bobEkSeed)
	destroySecret(&s.bobHek)
	destroySecret(&s.bobEkVector)

	s.kind = StateCt1Sampled

	outputSecret, err := secret.New(outputKey)
	if err != nil {
		return nil, &ErrKEMOperation{Op: "bobCompleteEncapsulation/outputKey", Err: err}
	}
	return &OutputKey{Epoch: currentEpoch, Key: outputSecret}, nil
}
