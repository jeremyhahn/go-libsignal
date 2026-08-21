// Package spqr: proto_codec.go — Phase D marshaling bridge.
//
// MarshalStateProto / UnmarshalStateProto convert a Go SPQR into/from the
// Rust PqRatchetState protobuf wire format. The goal is byte-level parity
// with Rust's PqRatchetState::encode_to_vec().
//
// Epoch convention: Rust stores epochs 1-indexed in the protobuf; Go uses
// 0-indexed epochs internally. Add 1 when writing to proto; subtract 1 when
// reading.
//
// NOTE: Three states (Ct1Sampled, EkReceivedCt1Sampled, Ct1Acknowledged)
// expose a semantic gap: Rust's Unchunked.Ct1Sent stores hdr (64 B) and es
// (2080 B — the intermediate EncapsulationState), but Go destroys those
// fields immediately after encapsulation completes in bobCompleteEncapsulation.
// When unmarshaling from Rust-produced bytes for these states, the hdr and es
// bytes are stored back in bobEkSeed/bobHek (for hdr) and bobEncapSecret (for
// es) so that a subsequent marshal round-trips identically. Callers that
// attempt live protocol operation on unmarshaled states in these three variants
// should call Braid.Send/Recv only after the braid has been freshly
// re-initialized, because the Go runtime may not be able to resume crypto
// operations on fields that were already consumed by the Rust peer.
package spqr

import (
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/proto/pqratchetpb"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
	"google.golang.org/protobuf/proto"
)

// ────────────────────────────── typed errors ─────────────────────────────────

// ErrProtoMarshalUnknownState is returned when the mlkembraid state machine is
// in a kind that has no proto representation.
type ErrProtoMarshalUnknownState struct {
	Kind mlkembraid.StateKind
}

// Error implements the error interface.
func (e *ErrProtoMarshalUnknownState) Error() string {
	return fmt.Sprintf("spqr proto_codec: cannot marshal unknown state kind %d", e.Kind)
}

// ErrProtoMissingField is returned when a required field is absent while
// constructing a proto message (marshal path) or is absent in an incoming
// proto message (unmarshal path).
type ErrProtoMissingField struct {
	Name string
}

// Error implements the error interface.
func (e *ErrProtoMissingField) Error() string {
	return fmt.Sprintf("spqr proto_codec: missing required field %q", e.Name)
}

// ErrProtoEpochOutOfRange is returned when the proto epoch value cannot be
// converted to a valid Go epoch (e.g. proto epoch 0, which is invalid).
type ErrProtoEpochOutOfRange struct {
	ProtoEpoch uint64
}

// Error implements the error interface.
func (e *ErrProtoEpochOutOfRange) Error() string {
	return fmt.Sprintf("spqr proto_codec: proto epoch %d out of range (must be >= 1)", e.ProtoEpoch)
}

// ErrProtoInvalidState is returned when the decoded proto inner_state is nil
// or contains an unexpected combination of fields.
type ErrProtoInvalidState struct {
	Reason string
}

// Error implements the error interface.
func (e *ErrProtoInvalidState) Error() string {
	return fmt.Sprintf("spqr proto_codec: invalid proto state: %s", e.Reason)
}

// ErrProtoChainUnderflow is returned when the number of link entries in a
// proto Chain would cause a uint64 underflow when computing the start epoch.
// A well-formed Chain satisfies current_epoch >= len(links) - 1.
type ErrProtoChainUnderflow struct {
	CurrentEpoch uint64
	NumLinks     uint64
}

// Error implements the error interface.
func (e *ErrProtoChainUnderflow) Error() string {
	return fmt.Sprintf("spqr proto_codec: chain startEpoch underflow: current_epoch=%d num_links=%d",
		e.CurrentEpoch, e.NumLinks)
}

// ────────────────────────── public codec functions ───────────────────────────

// MarshalStateProto serializes a Go SPQR into Rust's PqRatchetState wire
// format. Round-trips with Rust's spqr::initial_state / spqr::send /
// spqr::recv byte-for-byte when braid state is present.
//
// When s has no attached braid (s.braid == nil), the returned bytes encode
// only the outer PqRatchetState envelope with version_negotiation and chain
// fields; the inner V1State is omitted.
//
// V0-disabled states (negotiated to V0 / PQR absent) are serialized as empty
// bytes, matching Rust's empty_state() / recv() V0 path which returns vec![].
// This eliminates the Go-only VersionNegotiation{AuthKey:nil} sentinel that
// was not compatible with Rust's proto decoder (lib.rs:470-473).
func MarshalStateProto(s *SPQR) ([]byte, error) {
	// V0-disabled: return empty bytes matching Rust's empty_state() (lib.rs:45-47).
	if s.IsDisabled() {
		return []byte{}, nil
	}
	pb, err := spqrToProto(s)
	if err != nil {
		return nil, err
	}
	return proto.Marshal(pb)
}

// UnmarshalStateProto deserializes Rust-produced state bytes into a Go SPQR.
// It performs the inverse of MarshalStateProto.
//
// Empty input is treated as V0-disabled (Rust's empty_state()), matching
// Rust's decode_state (lib.rs:470-473) which interprets empty bytes as
// PqRatchetState{inner:None, chain:None, version_negotiation:None}.
func UnmarshalStateProto(data []byte) (*SPQR, error) {
	// Empty bytes → V0-disabled, matching Rust's empty_state() convention.
	if len(data) == 0 {
		return &SPQR{
			chains:      make(map[uint64]*EpochChain),
			skippedKeys: make(map[SkippedKeyID]*secret.Secret),
			maxJump:     maxJump,
			negotiation: negotiationResolved,
			version:     VersionV0,
		}, nil
	}
	var pb pqratchetpb.PqRatchetState
	if err := proto.Unmarshal(data, &pb); err != nil {
		return nil, &ErrProtoInvalidState{Reason: err.Error()}
	}
	return protoToSPQR(&pb)
}

// ─────────────────────────── marshal (Go → proto) ────────────────────────────

func spqrToProto(s *SPQR) (*pqratchetpb.PqRatchetState, error) {
	pb := &pqratchetpb.PqRatchetState{}

	// ── version negotiation ──
	if s.negotiation == negotiationPending && len(s.authKey) > 0 {
		pb.VersionNegotiation = &pqratchetpb.PqRatchetState_VersionNegotiation{
			AuthKey:   s.authKey,
			Direction: directionToProto(s.direction),
			MinVersion: func() pqratchetpb.Version {
				if s.minVersion == VersionV0 {
					return pqratchetpb.Version_V_0
				}
				return pqratchetpb.Version_V_1
			}(),
			ChainParams: &pqratchetpb.ChainParams{
				MaxJump:    chainParamMaxJump(s.maxJump),
				MaxOooKeys: chainParamMaxOOO(maxSkippedKeys),
			},
		}
	}

	// ── chain ──
	chain, err := spqrChainToProto(s)
	if err != nil {
		return nil, err
	}
	pb.Chain = chain

	// ── inner V1 state (braid) ──
	if s.braid != nil {
		braidState := s.braid.State()
		if braidState == nil {
			return nil, &ErrProtoMissingField{Name: "braid.state"}
		}
		v1pb, err := mlkembraidStateToProto(braidState)
		if err != nil {
			return nil, err
		}
		pb.Inner = &pqratchetpb.PqRatchetState_V1{V1: v1pb}
	}

	return pb, nil
}

// directionToProto converts a Go Direction to the proto enum.
func directionToProto(d Direction) pqratchetpb.Direction {
	if d == DirectionB2A {
		return pqratchetpb.Direction_B_2_A
	}
	return pqratchetpb.Direction_A_2_B
}

// chainParamMaxJump returns 0 when the value matches the Rust default (25000),
// otherwise returns the value. Matches Rust's ChainParams::into_pb.
func chainParamMaxJump(v uint32) uint32 {
	if v == maxJump {
		return 0
	}
	return v
}

// chainParamMaxOOO returns 0 when the value matches the Rust default (2000),
// otherwise returns the value.
func chainParamMaxOOO(v uint32) uint32 {
	if v == maxSkippedKeys {
		return 0
	}
	return v
}

// skippedRecvRecord is a single entry from the skippedKeys map for one epoch,
// ready to be encoded into the proto prev field.
type skippedRecvRecord struct {
	counter uint32
	key     *secret.Secret
}

// spqrChainToProto converts Go SPQR chain state to proto Chain message.
// Returns nil when no chain data exists.
//
// The recv.prev field is encoded as a concatenation of (be32 idx | 32 B key)
// records, one per skipped recv key for that epoch, matching Rust's
// KeyHistory.data layout (chain.rs:91-96). This allows full round-trip fidelity
// of the skipped-key map across serialize/deserialize cycles.
func spqrChainToProto(s *SPQR) (*pqratchetpb.Chain, error) {
	if s.rootKey == nil || s.rootKey.IsDestroyed() {
		return nil, nil
	}
	if len(s.chains) == 0 {
		return nil, nil
	}

	pb := &pqratchetpb.Chain{
		Direction:    directionToProto(s.direction),
		CurrentEpoch: s.epoch,
		SendEpoch:    s.sendEpoch,
		NextRoot:     s.rootKey.Bytes(),
		Params: &pqratchetpb.ChainParams{
			MaxJump:    chainParamMaxJump(s.maxJump),
			MaxOooKeys: chainParamMaxOOO(maxSkippedKeys),
		},
	}

	epochs := sortedEpochs(s.chains)
	links := make([]*pqratchetpb.Chain_Epoch, 0, len(epochs))
	for _, ep := range epochs {
		chain := s.chains[ep]
		skipped := skippedRecvKeysForEpoch(s.skippedKeys, ep)
		link := &pqratchetpb.Chain_Epoch{
			Send: chainSendDirToProto(chain),
			Recv: chainRecvDirToProto(chain, skipped),
		}
		links = append(links, link)
	}
	pb.Links = links

	return pb, nil
}

// skippedRecvKeysForEpoch collects all live (non-destroyed) skipped recv keys
// for a given epoch from the global skipped-key map, sorted by counter in
// ascending order. Destroyed secrets are silently excluded.
func skippedRecvKeysForEpoch(skipped map[SkippedKeyID]*secret.Secret, epoch uint64) []skippedRecvRecord {
	records := make([]skippedRecvRecord, 0)
	for id, sk := range skipped {
		if id.Epoch == epoch && sk != nil && !sk.IsDestroyed() {
			records = append(records, skippedRecvRecord{counter: id.Counter, key: sk})
		}
	}
	// Insertion sort by counter — skipped maps are small (≤ maxSkippedKeys).
	for i := 1; i < len(records); i++ {
		r := records[i]
		j := i - 1
		for j >= 0 && records[j].counter > r.counter {
			records[j+1] = records[j]
			j--
		}
		records[j+1] = r
	}
	return records
}

// chainSendDirToProto converts an EpochChain send direction to proto.
func chainSendDirToProto(chain *EpochChain) *pqratchetpb.Chain_Epoch_EpochDirection {
	var next []byte
	if chain.sendKey != nil && !chain.sendKey.IsDestroyed() {
		next = chain.sendKey.Bytes()
	}
	return &pqratchetpb.Chain_Epoch_EpochDirection{
		Ctr:  chain.sendCounter,
		Next: next,
		Prev: nil,
	}
}

// chainRecvDirToProto converts an EpochChain recv direction to proto,
// encoding skipped recv keys as (be32 counter | 32 B key) records in the prev
// field. This matches Rust's KeyHistory.data wire format exactly:
//
//	chain.rs ChainEpochDirection::into_pb → prev: self.prev.data
//	chain.rs KeyHistory::add → data.extend(&k.0.to_be_bytes()); data.extend(&k.1)
//
// KEY_SIZE = 36 bytes per record (4-byte BE index + 32-byte key).
func chainRecvDirToProto(chain *EpochChain, skipped []skippedRecvRecord) *pqratchetpb.Chain_Epoch_EpochDirection {
	var next []byte
	if chain.recvKey != nil && !chain.recvKey.IsDestroyed() {
		next = chain.recvKey.Bytes()
	}

	const recSize = 4 + keyLen // 36 bytes per KeyHistory record
	var prev []byte
	if len(skipped) > 0 {
		prev = make([]byte, len(skipped)*recSize)
		for i, rec := range skipped {
			off := i * recSize
			prev[off] = byte(rec.counter >> 24)
			prev[off+1] = byte(rec.counter >> 16)
			prev[off+2] = byte(rec.counter >> 8)
			prev[off+3] = byte(rec.counter)
			copy(prev[off+4:off+recSize], rec.key.Bytes())
		}
	}

	return &pqratchetpb.Chain_Epoch_EpochDirection{
		Ctr:  chain.recvCounter,
		Next: next,
		Prev: prev,
	}
}

// sortedEpochs returns the epoch keys from chains in ascending order.
func sortedEpochs(chains map[uint64]*EpochChain) []uint64 {
	epochs := make([]uint64, 0, len(chains))
	for ep := range chains {
		epochs = append(epochs, ep)
	}
	insertionSortEpochs(epochs)
	return epochs
}

// insertionSortEpochs sorts epochs ascending in place. Insertion sort — chain
// maps are always tiny (≤ 3 epochs).
//
// Split out from sortedEpochs so it can be tested on input the test chooses.
// Driven through the map, the shift loop below runs only when Go's randomised
// iteration order happens to hand it unsorted keys, so its coverage varied
// between runs on identical source and moved the repository total by 0.1pp at
// random (measured 1 run in 12 on go1.26.6).
func insertionSortEpochs(epochs []uint64) {
	for i := 1; i < len(epochs); i++ {
		key := epochs[i]
		j := i - 1
		for j >= 0 && epochs[j] > key {
			epochs[j+1] = epochs[j]
			j--
		}
		epochs[j+1] = key
	}
}

// mlkembraidStateToProto converts a mlkembraid.State to pqratchetpb.V1State.
func mlkembraidStateToProto(s *mlkembraid.State) (*pqratchetpb.V1State, error) {
	pb := &pqratchetpb.V1State{}
	if err := stateKindToInnerState(s, pb); err != nil {
		return nil, err
	}
	return pb, nil
}

// protoEpoch converts the Go 0-indexed epoch to the Rust 1-indexed proto epoch.
func protoEpoch(goEpoch uint64) uint64 {
	return goEpoch + 1
}

// authToProto converts the mlkembraid Authenticator to the proto message.
func authToProto(a *mlkembraid.Authenticator) (*pqratchetpb.Authenticator, error) {
	if a == nil {
		return nil, &ErrProtoMissingField{Name: "auth"}
	}
	rk := a.ProtoAuthRootKey()
	if rk == nil {
		return nil, &ErrProtoMissingField{Name: "auth.root_key"}
	}
	return &pqratchetpb.Authenticator{
		RootKey: rk,
		MacKey:  a.ProtoAuthMacKey(),
	}, nil
}

// encoderToProto converts a mlkembraid Encoder to pqratchetpb.PolynomialEncoder.
func encoderToProto(enc *mlkembraid.Encoder) (*pqratchetpb.PolynomialEncoder, error) {
	if enc == nil {
		return nil, &ErrProtoMissingField{Name: "encoder"}
	}
	fields, err := mlkembraid.ProtoMarshalEncoder(enc)
	if err != nil {
		return nil, &ErrProtoInvalidState{Reason: err.Error()}
	}
	return &pqratchetpb.PolynomialEncoder{
		Idx:   fields.Idx,
		Pts:   fields.Pts,
		Polys: fields.Polys,
	}, nil
}

// decoderToProto converts a mlkembraid Decoder to pqratchetpb.PolynomialDecoder.
func decoderToProto(dec *mlkembraid.Decoder) (*pqratchetpb.PolynomialDecoder, error) {
	if dec == nil {
		return nil, &ErrProtoMissingField{Name: "decoder"}
	}
	fields, err := mlkembraid.ProtoMarshalDecoder(dec)
	if err != nil {
		return nil, &ErrProtoInvalidState{Reason: err.Error()}
	}
	return &pqratchetpb.PolynomialDecoder{
		PtsNeeded:  fields.PtsNeeded,
		Polys:      fields.Polys,
		IsComplete: fields.IsComplete,
		Pts:        fields.Pts,
	}, nil
}

// stateKindToInnerState dispatches on State.Kind() to populate the V1State
// oneof field. Using a setter pattern avoids naming the unexported proto oneof
// interface type, which protoc-gen-go generates as package-private.
func stateKindToInnerState(s *mlkembraid.State, pb *pqratchetpb.V1State) error {
	ep := protoEpoch(s.ProtoEpoch())
	auth, err := authToProto(s.ProtoAuth())
	if err != nil {
		return err
	}

	switch s.Kind() {
	case mlkembraid.StateKeysUnsampled:
		v, e := marshalKeysUnsampled(ep, auth)
		if e != nil {
			return e
		}
		pb.InnerState = v
	case mlkembraid.StateKeysSampled:
		v, e := marshalKeysSampled(s, ep, auth)
		if e != nil {
			return e
		}
		pb.InnerState = v
	case mlkembraid.StateHeaderSent:
		v, e := marshalHeaderSent(s, ep, auth)
		if e != nil {
			return e
		}
		pb.InnerState = v
	case mlkembraid.StateCt1Received:
		v, e := marshalCt1Received(s, ep, auth)
		if e != nil {
			return e
		}
		pb.InnerState = v
	case mlkembraid.StateEkSentCt1Received:
		v, e := marshalEkSentCt1Received(s, ep, auth)
		if e != nil {
			return e
		}
		pb.InnerState = v
	case mlkembraid.StateNoHeaderReceived:
		v, e := marshalNoHeaderReceived(s, ep, auth)
		if e != nil {
			return e
		}
		pb.InnerState = v
	case mlkembraid.StateHeaderReceived:
		v, e := marshalHeaderReceived(s, ep, auth)
		if e != nil {
			return e
		}
		pb.InnerState = v
	case mlkembraid.StateCt1Sampled:
		v, e := marshalCt1Sampled(s, ep, auth)
		if e != nil {
			return e
		}
		pb.InnerState = v
	case mlkembraid.StateEkReceivedCt1Sampled:
		v, e := marshalEkReceivedCt1Sampled(s, ep, auth)
		if e != nil {
			return e
		}
		pb.InnerState = v
	case mlkembraid.StateCt1Acknowledged:
		v, e := marshalCt1Acknowledged(s, ep, auth)
		if e != nil {
			return e
		}
		pb.InnerState = v
	case mlkembraid.StateCt2Sampled:
		v, e := marshalCt2Sampled(s, ep, auth)
		if e != nil {
			return e
		}
		pb.InnerState = v
	default:
		return &ErrProtoMarshalUnknownState{Kind: s.Kind()}
	}
	return nil
}

// marshalKeysUnsampled builds the proto for StateKeysUnsampled.
func marshalKeysUnsampled(ep uint64, auth *pqratchetpb.Authenticator) (*pqratchetpb.V1State_KeysUnsampled, error) {
	return &pqratchetpb.V1State_KeysUnsampled{
		KeysUnsampled: &pqratchetpb.V1State_Chunked_KeysUnsampled{
			Uc: &pqratchetpb.V1State_Unchunked_KeysUnsampled{
				Epoch: ep,
				Auth:  auth,
			},
		},
	}, nil
}

// marshalKeysSampled builds the proto for StateKeysSampled.
// Unchunked: Rust HeaderSent { epoch, auth, ek = ekSeed||ekVector, dk }
// Chunked:   adds sending_hdr (headerEncoder)
func marshalKeysSampled(s *mlkembraid.State, ep uint64, auth *pqratchetpb.Authenticator) (*pqratchetpb.V1State_KeysSampled, error) {
	ekSeed := s.ProtoEKSeed()
	ekVec := s.ProtoEKVector()
	if ekSeed == nil {
		return nil, &ErrProtoMissingField{Name: "KeysSampled.ekSeed"}
	}
	if ekVec == nil {
		return nil, &ErrProtoMissingField{Name: "KeysSampled.ekVector"}
	}
	dk := s.ProtoDK()
	if dk == nil {
		return nil, &ErrProtoMissingField{Name: "KeysSampled.dk"}
	}
	enc := s.ProtoHeaderEncoder()
	if enc == nil {
		return nil, &ErrProtoMissingField{Name: "KeysSampled.headerEncoder"}
	}
	encPB, err := encoderToProto(enc)
	if err != nil {
		return nil, err
	}

	ek := make([]byte, len(ekSeed)+len(ekVec))
	copy(ek, ekSeed)
	copy(ek[len(ekSeed):], ekVec)

	return &pqratchetpb.V1State_KeysSampled{
		KeysSampled: &pqratchetpb.V1State_Chunked_KeysSampled{
			Uc: &pqratchetpb.V1State_Unchunked_HeaderSent{
				Epoch: ep,
				Auth:  auth,
				Ek:    ek,
				Dk:    dk,
			},
			SendingHdr: encPB,
		},
	}, nil
}

// marshalHeaderSent builds the proto for StateHeaderSent.
// Unchunked: Rust EkSent { epoch, auth, dk }
// Chunked:   adds sending_ek + receiving_ct1 (optional — nil when no ct1 chunks received yet)
func marshalHeaderSent(s *mlkembraid.State, ep uint64, auth *pqratchetpb.Authenticator) (*pqratchetpb.V1State_HeaderSent, error) {
	dk := s.ProtoDK()
	if dk == nil {
		return nil, &ErrProtoMissingField{Name: "HeaderSent.dk"}
	}
	ekEnc := s.ProtoEKEncoder()
	if ekEnc == nil {
		return nil, &ErrProtoMissingField{Name: "HeaderSent.ekEncoder"}
	}
	ekEncPB, err := encoderToProto(ekEnc)
	if err != nil {
		return nil, err
	}

	// ct1Decoder is nil when no ct1 chunks have been received yet (lazily initialized).
	var ct1DecPB *pqratchetpb.PolynomialDecoder
	if ct1Dec := s.ProtoCt1Decoder(); ct1Dec != nil {
		ct1DecPB, err = decoderToProto(ct1Dec)
		if err != nil {
			return nil, err
		}
	}

	return &pqratchetpb.V1State_HeaderSent{
		HeaderSent: &pqratchetpb.V1State_Chunked_HeaderSent{
			Uc: &pqratchetpb.V1State_Unchunked_EkSent{
				Epoch: ep,
				Auth:  auth,
				Dk:    dk,
			},
			SendingEk:    ekEncPB,
			ReceivingCt1: ct1DecPB, // nil when no ct1 chunks received yet
		},
	}, nil
}

// marshalCt1Received builds the proto for StateCt1Received.
// Unchunked: Rust EkSentCt1Received { epoch, auth, dk, ct1 }
// Chunked:   adds sending_ek
func marshalCt1Received(s *mlkembraid.State, ep uint64, auth *pqratchetpb.Authenticator) (*pqratchetpb.V1State_Ct1Received, error) {
	dk := s.ProtoDK()
	if dk == nil {
		return nil, &ErrProtoMissingField{Name: "Ct1Received.dk"}
	}
	ct1 := s.ProtoReceivedCt1()
	if ct1 == nil {
		return nil, &ErrProtoMissingField{Name: "Ct1Received.receivedCt1"}
	}
	ekEnc := s.ProtoEKEncoder()
	if ekEnc == nil {
		return nil, &ErrProtoMissingField{Name: "Ct1Received.ekEncoder"}
	}
	ekEncPB, err := encoderToProto(ekEnc)
	if err != nil {
		return nil, err
	}

	return &pqratchetpb.V1State_Ct1Received{
		Ct1Received: &pqratchetpb.V1State_Chunked_Ct1Received{
			Uc: &pqratchetpb.V1State_Unchunked_EkSentCt1Received{
				Epoch: ep,
				Auth:  auth,
				Dk:    dk,
				Ct1:   ct1,
			},
			SendingEk: ekEncPB,
		},
	}, nil
}

// marshalEkSentCt1Received builds the proto for StateEkSentCt1Received.
// Unchunked: Rust EkSentCt1Received { epoch, auth, dk, ct1 }
// Chunked:   adds receiving_ct2
func marshalEkSentCt1Received(s *mlkembraid.State, ep uint64, auth *pqratchetpb.Authenticator) (*pqratchetpb.V1State_EkSentCt1Received, error) {
	dk := s.ProtoDK()
	if dk == nil {
		return nil, &ErrProtoMissingField{Name: "EkSentCt1Received.dk"}
	}
	ct1 := s.ProtoReceivedCt1()
	if ct1 == nil {
		return nil, &ErrProtoMissingField{Name: "EkSentCt1Received.receivedCt1"}
	}
	ct2Dec := s.ProtoCt2Decoder()
	if ct2Dec == nil {
		return nil, &ErrProtoMissingField{Name: "EkSentCt1Received.ct2Decoder"}
	}
	ct2DecPB, err := decoderToProto(ct2Dec)
	if err != nil {
		return nil, err
	}

	return &pqratchetpb.V1State_EkSentCt1Received{
		EkSentCt1Received: &pqratchetpb.V1State_Chunked_EkSentCt1Received{
			Uc: &pqratchetpb.V1State_Unchunked_EkSentCt1Received{
				Epoch: ep,
				Auth:  auth,
				Dk:    dk,
				Ct1:   ct1,
			},
			ReceivingCt2: ct2DecPB,
		},
	}, nil
}

// marshalNoHeaderReceived builds the proto for StateNoHeaderReceived.
// Unchunked: Rust NoHeaderReceived { epoch, auth }
// Chunked:   adds receiving_hdr
func marshalNoHeaderReceived(s *mlkembraid.State, ep uint64, auth *pqratchetpb.Authenticator) (*pqratchetpb.V1State_NoHeaderReceived, error) {
	hdrDec := s.ProtoHeaderDecoder()
	if hdrDec == nil {
		return nil, &ErrProtoMissingField{Name: "NoHeaderReceived.headerDecoder"}
	}
	hdrDecPB, err := decoderToProto(hdrDec)
	if err != nil {
		return nil, err
	}

	return &pqratchetpb.V1State_NoHeaderReceived{
		NoHeaderReceived: &pqratchetpb.V1State_Chunked_NoHeaderReceived{
			Uc: &pqratchetpb.V1State_Unchunked_NoHeaderReceived{
				Epoch: ep,
				Auth:  auth,
			},
			ReceivingHdr: hdrDecPB,
		},
	}, nil
}

// marshalHeaderReceived builds the proto for StateHeaderReceived.
// Unchunked: Rust HeaderReceived { epoch, auth, hdr = bobEkSeed||bobHek }
// Chunked:   adds receiving_ek (optional — nil when no Ek chunks received yet)
func marshalHeaderReceived(s *mlkembraid.State, ep uint64, auth *pqratchetpb.Authenticator) (*pqratchetpb.V1State_HeaderReceived, error) {
	ekSeed := s.ProtoBobEKSeed()
	hek := s.ProtoBobHek()
	if ekSeed == nil {
		return nil, &ErrProtoMissingField{Name: "HeaderReceived.bobEkSeed"}
	}
	if hek == nil {
		return nil, &ErrProtoMissingField{Name: "HeaderReceived.bobHek"}
	}

	// ekDecoder is nil when no Ek chunks have been received yet (lazy init in
	// receiveHeaderReceived). Omit the ReceivingEk field in that case.
	var ekDecPB *pqratchetpb.PolynomialDecoder
	if ekDec := s.ProtoEKDecoder(); ekDec != nil {
		var err error
		ekDecPB, err = decoderToProto(ekDec)
		if err != nil {
			return nil, err
		}
	}

	hdr := make([]byte, len(ekSeed)+len(hek))
	copy(hdr, ekSeed)
	copy(hdr[len(ekSeed):], hek)

	return &pqratchetpb.V1State_HeaderReceived{
		HeaderReceived: &pqratchetpb.V1State_Chunked_HeaderReceived{
			Uc: &pqratchetpb.V1State_Unchunked_HeaderReceived{
				Epoch: ep,
				Auth:  auth,
				Hdr:   hdr,
			},
			ReceivingEk: ekDecPB, // nil when no Ek chunks received yet
		},
	}, nil
}

// marshalCt1Sampled builds the proto for StateCt1Sampled.
// Unchunked: Rust Ct1Sent { epoch, auth, hdr, es, ct1 }
// Chunked:   adds sending_ct1 + receiving_ek
//
// hdr = bobEkSeed||bobHek (64 B), es = bobEncapSecret, ct1 = bobCt1 (960 B).
// After Go bobCompleteEncapsulation, bobEkSeed, bobHek, bobEncapSecret are
// destroyed. When nil, zero bytes are emitted to keep the proto structurally
// valid. See the package comment for the documented semantic gap.
func marshalCt1Sampled(s *mlkembraid.State, ep uint64, auth *pqratchetpb.Authenticator) (*pqratchetpb.V1State_Ct1Sampled, error) {
	ekSeed := s.ProtoBobEKSeed()
	hek := s.ProtoBobHek()
	es := s.ProtoBobEncapSecret()
	ct1 := s.ProtoBobCt1()

	if ct1 == nil {
		return nil, &ErrProtoMissingField{Name: "Ct1Sampled.bobCt1"}
	}

	hdr := make([]byte, mlkembraid.HeaderSize)
	if ekSeed != nil && hek != nil {
		copy(hdr, ekSeed)
		copy(hdr[mlkembraid.EKSeedSize:], hek)
	}

	esBytes := make([]byte, mlkembraid.MLKEM768EncapStateSize)
	if es != nil {
		copy(esBytes, es)
	}

	ct1Enc := s.ProtoCt1Encoder()
	if ct1Enc == nil {
		return nil, &ErrProtoMissingField{Name: "Ct1Sampled.ct1Encoder"}
	}
	ekDec := s.ProtoEKDecoder()
	if ekDec == nil {
		return nil, &ErrProtoMissingField{Name: "Ct1Sampled.ekDecoder"}
	}
	ct1EncPB, err := encoderToProto(ct1Enc)
	if err != nil {
		return nil, err
	}
	ekDecPB, err := decoderToProto(ekDec)
	if err != nil {
		return nil, err
	}

	return &pqratchetpb.V1State_Ct1Sampled{
		Ct1Sampled: &pqratchetpb.V1State_Chunked_Ct1Sampled{
			Uc: &pqratchetpb.V1State_Unchunked_Ct1Sent{
				Epoch: ep,
				Auth:  auth,
				Hdr:   hdr,
				Es:    esBytes,
				Ct1:   ct1,
			},
			SendingCt1:  ct1EncPB,
			ReceivingEk: ekDecPB,
		},
	}, nil
}

// marshalEkReceivedCt1Sampled builds the proto for StateEkReceivedCt1Sampled.
// Unchunked: Rust Ct1SentEkReceived { epoch, auth, es, ek, ct1 }
// Chunked:   adds sending_ct1
func marshalEkReceivedCt1Sampled(s *mlkembraid.State, ep uint64, auth *pqratchetpb.Authenticator) (*pqratchetpb.V1State_EkReceivedCt1Sampled, error) {
	es := s.ProtoBobEncapSecret()
	ek := s.ProtoBobEKVector()
	ct1 := s.ProtoBobCt1()

	if ct1 == nil {
		return nil, &ErrProtoMissingField{Name: "EkReceivedCt1Sampled.bobCt1"}
	}

	esBytes := make([]byte, mlkembraid.MLKEM768EncapStateSize)
	if es != nil {
		copy(esBytes, es)
	}

	ekBytes := make([]byte, mlkembraid.MLKEM768EKSize)
	if ek != nil {
		copy(ekBytes, ek)
	}

	ct1Enc := s.ProtoCt1Encoder()
	if ct1Enc == nil {
		return nil, &ErrProtoMissingField{Name: "EkReceivedCt1Sampled.ct1Encoder"}
	}
	ct1EncPB, err := encoderToProto(ct1Enc)
	if err != nil {
		return nil, err
	}

	return &pqratchetpb.V1State_EkReceivedCt1Sampled{
		EkReceivedCt1Sampled: &pqratchetpb.V1State_Chunked_EkReceivedCt1Sampled{
			Uc: &pqratchetpb.V1State_Unchunked_Ct1SentEkReceived{
				Epoch: ep,
				Auth:  auth,
				Es:    esBytes,
				Ek:    ekBytes,
				Ct1:   ct1,
			},
			SendingCt1: ct1EncPB,
		},
	}, nil
}

// marshalCt1Acknowledged builds the proto for StateCt1Acknowledged.
// Unchunked: Rust Ct1Sent { epoch, auth, hdr, es, ct1 }
// Chunked:   adds receiving_ek
func marshalCt1Acknowledged(s *mlkembraid.State, ep uint64, auth *pqratchetpb.Authenticator) (*pqratchetpb.V1State_Ct1Acknowledged, error) {
	ekSeed := s.ProtoBobEKSeed()
	hek := s.ProtoBobHek()
	es := s.ProtoBobEncapSecret()
	ct1 := s.ProtoBobCt1()

	if ct1 == nil {
		return nil, &ErrProtoMissingField{Name: "Ct1Acknowledged.bobCt1"}
	}

	hdr := make([]byte, mlkembraid.HeaderSize)
	if ekSeed != nil && hek != nil {
		copy(hdr, ekSeed)
		copy(hdr[mlkembraid.EKSeedSize:], hek)
	}

	esBytes := make([]byte, mlkembraid.MLKEM768EncapStateSize)
	if es != nil {
		copy(esBytes, es)
	}

	ekDec := s.ProtoEKDecoder()
	if ekDec == nil {
		return nil, &ErrProtoMissingField{Name: "Ct1Acknowledged.ekDecoder"}
	}
	ekDecPB, err := decoderToProto(ekDec)
	if err != nil {
		return nil, err
	}

	return &pqratchetpb.V1State_Ct1Acknowledged{
		Ct1Acknowledged: &pqratchetpb.V1State_Chunked_Ct1Acknowledged{
			Uc: &pqratchetpb.V1State_Unchunked_Ct1Sent{
				Epoch: ep,
				Auth:  auth,
				Hdr:   hdr,
				Es:    esBytes,
				Ct1:   ct1,
			},
			ReceivingEk: ekDecPB,
		},
	}, nil
}

// marshalCt2Sampled builds the proto for StateCt2Sampled.
// Unchunked: Rust Ct2Sent { epoch, auth }
// Chunked:   adds sending_ct2
func marshalCt2Sampled(s *mlkembraid.State, ep uint64, auth *pqratchetpb.Authenticator) (*pqratchetpb.V1State_Ct2Sampled, error) {
	ct2Enc := s.ProtoCt2Encoder()
	if ct2Enc == nil {
		return nil, &ErrProtoMissingField{Name: "Ct2Sampled.ct2Encoder"}
	}
	ct2EncPB, err := encoderToProto(ct2Enc)
	if err != nil {
		return nil, err
	}

	return &pqratchetpb.V1State_Ct2Sampled{
		Ct2Sampled: &pqratchetpb.V1State_Chunked_Ct2Sampled{
			Uc: &pqratchetpb.V1State_Unchunked_Ct2Sent{
				Epoch: ep,
				Auth:  auth,
			},
			SendingCt2: ct2EncPB,
		},
	}, nil
}

// ─────────────────────────── unmarshal (proto → Go) ──────────────────────────

func protoToSPQR(pb *pqratchetpb.PqRatchetState) (*SPQR, error) {
	s := &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		maxJump:     maxJump,
	}

	// ── version negotiation ──
	// Rust: version_negotiation is present only during pending negotiation;
	// it always carries a non-empty auth_key (lib.rs:220-224).
	// A VersionNegotiation with an empty AuthKey was a Go-only legacy sentinel
	// for V0-disabled states. New code never writes it (V0 → empty bytes);
	// we still handle it here for backward-compatibility with older persisted states.
	if vn := pb.VersionNegotiation; vn != nil {
		if len(vn.AuthKey) == 0 {
			// Legacy Go-only V0-disabled sentinel: treat as resolved-to-V0.
			s.negotiation = negotiationResolved
			s.version = VersionV0
			s.minVersion = VersionV0
			s.direction = protoDirectionToGo(vn.Direction)
			if cp := vn.ChainParams; cp != nil {
				if cp.MaxJump > 0 {
					s.maxJump = cp.MaxJump
				}
			}
		} else {
			s.negotiation = negotiationPending
			s.authKey = vn.AuthKey
			s.direction = protoDirectionToGo(vn.Direction)
			s.version = VersionV1
			s.minVersion = protoVersionToGo(vn.MinVersion)
			if cp := vn.ChainParams; cp != nil {
				if cp.MaxJump > 0 {
					s.maxJump = cp.MaxJump
				}
			}
		}
	} else {
		s.negotiation = negotiationResolved
		s.version = VersionV1
		s.minVersion = VersionV0
	}

	// ── chain ──
	if pb.Chain != nil {
		if err := protoChainToSPQR(pb.Chain, s); err != nil {
			s.Zeroize()
			return nil, err
		}
	}

	// ── inner V1 state (braid) ──
	if pb.Inner != nil {
		v1Inner, ok := pb.Inner.(*pqratchetpb.PqRatchetState_V1)
		if !ok || v1Inner.V1 == nil {
			s.Zeroize()
			return nil, &ErrProtoInvalidState{Reason: "inner is set but not V1"}
		}
		braidState, err := protoV1StateToBraidState(v1Inner.V1)
		if err != nil {
			s.Zeroize()
			return nil, err
		}
		s.braid = mlkembraid.BraidFromState(braidState, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	}

	return s, nil
}

// protoDirectionToGo converts the proto Direction enum to Go Direction.
func protoDirectionToGo(d pqratchetpb.Direction) Direction {
	if d == pqratchetpb.Direction_B_2_A {
		return DirectionB2A
	}
	return DirectionA2B
}

// protoVersionToGo converts the proto Version enum to Go Version.
func protoVersionToGo(v pqratchetpb.Version) Version {
	if v == pqratchetpb.Version_V_1 {
		return VersionV1
	}
	return VersionV0
}

// protoChainToSPQR populates the SPQR chain from a proto Chain message.
func protoChainToSPQR(pb *pqratchetpb.Chain, s *SPQR) error {
	s.direction = protoDirectionToGo(pb.Direction)
	s.epoch = pb.CurrentEpoch
	s.sendEpoch = pb.SendEpoch

	if len(pb.NextRoot) > 0 {
		rk, err := secret.New(append([]byte{}, pb.NextRoot...))
		if err != nil {
			return err
		}
		if s.rootKey != nil {
			s.rootKey.Destroy()
		}
		s.rootKey = rk
	}

	if pb.Params != nil {
		if pb.Params.MaxJump > 0 {
			s.maxJump = pb.Params.MaxJump
		}
	}

	n := uint64(len(pb.Links))
	if n == 0 {
		return nil
	}
	// Guard against uint64 underflow: startEpoch = currentEpoch - (n-1).
	// A malformed proto with more links than current_epoch allows would wrap around.
	if pb.CurrentEpoch < n-1 {
		return &ErrProtoChainUnderflow{CurrentEpoch: pb.CurrentEpoch, NumLinks: n}
	}
	// Bound the number of epoch links processed to prevent CPU-DoS from a
	// malformed proto carrying an unbounded pb.Links slice. The cap matches
	// maxSkippedKeys: storing more epochs than can fit in the skipped-key map
	// has no legitimate use, and each link iteration allocates key material.
	const maxEpochLinks = maxSkippedKeys
	if n > maxEpochLinks {
		return &ErrProtoChainUnderflow{CurrentEpoch: pb.CurrentEpoch, NumLinks: n}
	}
	startEpoch := pb.CurrentEpoch - (n - 1)

	for i, link := range pb.Links {
		ep := startEpoch + uint64(i)
		chain, err := protoEpochLinkToChain(link, ep, s.skippedKeys)
		if err != nil {
			return err
		}
		s.chains[ep] = chain
	}

	// Rebuild the skippedKeysFIFO from the populated skippedKeys map so that
	// subsequent evictions have a valid FIFO order without a live-receive pass.
	s.rebuildSkippedKeysFIFO()

	// Enforce the live-session cap on skipped keys after deserialization.
	// A malformed proto with unbounded recv.prev fields could cause memory
	// exhaustion; evict oldest entries until the map is within maxSkippedKeys.
	for len(s.skippedKeys) > maxSkippedKeys {
		s.evictOldestSkippedKey()
	}

	return nil
}

// protoEpochLinkToChain reconstructs an EpochChain from a proto Epoch link and
// populates the global skipped-key map from the recv.prev field.
//
// The recv.prev field is treated as a sequence of (be32 idx | 32 B key) records,
// matching Rust's KeyHistory.data wire format (chain.rs:91-96, KEY_SIZE=36).
// Any non-zero length that is NOT a multiple of 36 returns ErrInvalidPrevEncoding.
// Each valid record is inserted into skippedKeys under SkippedKeyID{Epoch: ep,
// Counter: idx}.
func protoEpochLinkToChain(link *pqratchetpb.Chain_Epoch, ep uint64, skippedKeys map[SkippedKeyID]*secret.Secret) (*EpochChain, error) {
	if link == nil {
		return nil, &ErrProtoMissingField{Name: "chain link"}
	}
	chain := &EpochChain{}
	if link.Send != nil {
		chain.sendCounter = link.Send.Ctr
		if len(link.Send.Next) > 0 {
			sk, err := secret.New(append([]byte{}, link.Send.Next...))
			if err != nil {
				return nil, err
			}
			chain.sendKey = sk
		}
	}
	if link.Recv != nil {
		chain.recvCounter = link.Recv.Ctr
		if len(link.Recv.Next) > 0 {
			rk, err := secret.New(append([]byte{}, link.Recv.Next...))
			if err != nil {
				chain.Zeroize()
				return nil, err
			}
			chain.recvKey = rk
		}
		// Parse recv.prev as a sequence of (be32 idx | 32 B key) records.
		// This matches Rust's KeyHistory.data layout (chain.rs KeyHistory::KEY_SIZE=36).
		// Each record is inserted into the global skipped-key map under the
		// epoch and counter decoded from the record header.
		if prev := link.Recv.Prev; len(prev) > 0 {
			const recSize = 4 + keyLen // 36 bytes per KeyHistory record
			if len(prev)%recSize != 0 {
				chain.Zeroize()
				return nil, &ErrInvalidPrevEncoding{Len: len(prev)}
			}
			for off := 0; off < len(prev); off += recSize {
				idx := uint32(prev[off])<<24 | uint32(prev[off+1])<<16 |
					uint32(prev[off+2])<<8 | uint32(prev[off+3])
				keyBytes := append([]byte{}, prev[off+4:off+recSize]...)
				sk, err := secret.New(keyBytes)
				if err != nil {
					chain.Zeroize()
					return nil, err
				}
				id := SkippedKeyID{Epoch: ep, Counter: idx}
				// Destroy any prior key at this slot before overwriting.
				if existing, ok := skippedKeys[id]; ok {
					existing.Destroy()
				}
				skippedKeys[id] = sk
			}
		}
	}
	return chain, nil
}

// goEpoch converts the Rust 1-indexed proto epoch to Go 0-indexed epoch.
func goEpoch(protoEp uint64) (uint64, error) {
	if protoEp == 0 {
		return 0, &ErrProtoEpochOutOfRange{ProtoEpoch: protoEp}
	}
	return protoEp - 1, nil
}

// protoV1StateToBraidState converts a V1State proto to a mlkembraid.State.
func protoV1StateToBraidState(pb *pqratchetpb.V1State) (*mlkembraid.State, error) {
	if pb.InnerState == nil {
		return nil, &ErrProtoInvalidState{Reason: "inner_state is nil"}
	}

	switch is := pb.InnerState.(type) {
	case *pqratchetpb.V1State_KeysUnsampled:
		return unmarshalKeysUnsampled(is.KeysUnsampled)
	case *pqratchetpb.V1State_KeysSampled:
		return unmarshalKeysSampled(is.KeysSampled)
	case *pqratchetpb.V1State_HeaderSent:
		return unmarshalHeaderSent(is.HeaderSent)
	case *pqratchetpb.V1State_Ct1Received:
		return unmarshalCt1Received(is.Ct1Received)
	case *pqratchetpb.V1State_EkSentCt1Received:
		return unmarshalEkSentCt1Received(is.EkSentCt1Received)
	case *pqratchetpb.V1State_NoHeaderReceived:
		return unmarshalNoHeaderReceived(is.NoHeaderReceived)
	case *pqratchetpb.V1State_HeaderReceived:
		return unmarshalHeaderReceived(is.HeaderReceived)
	case *pqratchetpb.V1State_Ct1Sampled:
		return unmarshalCt1Sampled(is.Ct1Sampled)
	case *pqratchetpb.V1State_EkReceivedCt1Sampled:
		return unmarshalEkReceivedCt1Sampled(is.EkReceivedCt1Sampled)
	case *pqratchetpb.V1State_Ct1Acknowledged:
		return unmarshalCt1Acknowledged(is.Ct1Acknowledged)
	case *pqratchetpb.V1State_Ct2Sampled:
		return unmarshalCt2Sampled(is.Ct2Sampled)
	default:
		return nil, &ErrProtoInvalidState{Reason: "unrecognized inner_state variant"}
	}
}

// protoAuthToGo converts a proto Authenticator to a Go Authenticator.
func protoAuthToGo(pb *pqratchetpb.Authenticator, epoch uint64) (*mlkembraid.Authenticator, error) {
	if pb == nil {
		return nil, &ErrProtoMissingField{Name: "auth"}
	}
	return mlkembraid.ProtoNewAuthenticator(pb.RootKey, pb.MacKey, epoch)
}

// protoEncoderToGo converts a proto PolynomialEncoder to a mlkembraid.Encoder.
func protoEncoderToGo(pb *pqratchetpb.PolynomialEncoder) (*mlkembraid.Encoder, error) {
	if pb == nil {
		return nil, &ErrProtoMissingField{Name: "encoder"}
	}
	enc, err := mlkembraid.ProtoUnmarshalEncoder(pb.Idx, pb.Pts, pb.Polys)
	if err != nil {
		return nil, &ErrProtoInvalidState{Reason: err.Error()}
	}
	return enc, nil
}

// protoDecoderToGo converts a proto PolynomialDecoder to a mlkembraid.Decoder.
func protoDecoderToGo(pb *pqratchetpb.PolynomialDecoder) (*mlkembraid.Decoder, error) {
	if pb == nil {
		return nil, &ErrProtoMissingField{Name: "decoder"}
	}
	dec, err := mlkembraid.ProtoUnmarshalDecoder(pb.PtsNeeded, pb.Pts, pb.IsComplete)
	if err != nil {
		return nil, &ErrProtoInvalidState{Reason: err.Error()}
	}
	return dec, nil
}

// ────────────── state-specific unmarshalers ───────────────────────────────────

func unmarshalKeysUnsampled(pb *pqratchetpb.V1State_Chunked_KeysUnsampled) (*mlkembraid.State, error) {
	if pb == nil || pb.Uc == nil {
		return nil, &ErrProtoMissingField{Name: "KeysUnsampled.uc"}
	}
	ep, err := goEpoch(pb.Uc.Epoch)
	if err != nil {
		return nil, err
	}
	auth, err := protoAuthToGo(pb.Uc.Auth, ep)
	if err != nil {
		return nil, err
	}
	return mlkembraid.ProtoSetFromFields(
		mlkembraid.StateKeysUnsampled, ep, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, nil,
	)
}

func unmarshalKeysSampled(pb *pqratchetpb.V1State_Chunked_KeysSampled) (*mlkembraid.State, error) {
	if pb == nil || pb.Uc == nil {
		return nil, &ErrProtoMissingField{Name: "KeysSampled.uc"}
	}
	ep, err := goEpoch(pb.Uc.Epoch)
	if err != nil {
		return nil, err
	}
	auth, err := protoAuthToGo(pb.Uc.Auth, ep)
	if err != nil {
		return nil, err
	}
	ek := pb.Uc.Ek
	if len(ek) != mlkembraid.EKSeedSize+mlkembraid.MLKEM768EKSize {
		return nil, &ErrProtoInvalidState{Reason: fmt.Sprintf("KeysSampled.ek: want %d bytes, got %d", mlkembraid.EKSeedSize+mlkembraid.MLKEM768EKSize, len(ek))}
	}
	ekSeed := ek[:mlkembraid.EKSeedSize]
	ekVec := ek[mlkembraid.EKSeedSize:]

	enc, err := protoEncoderToGo(pb.SendingHdr)
	if err != nil {
		return nil, err
	}
	return mlkembraid.ProtoSetFromFields(
		mlkembraid.StateKeysSampled, ep, mlkembraid.DefaultChunkSize,
		auth, pb.Uc.Dk, ekSeed, ekVec, nil, nil, nil, nil, nil, nil, nil,
		enc, nil, nil, nil, nil, nil, nil, nil,
	)
}

func unmarshalHeaderSent(pb *pqratchetpb.V1State_Chunked_HeaderSent) (*mlkembraid.State, error) {
	if pb == nil || pb.Uc == nil {
		return nil, &ErrProtoMissingField{Name: "HeaderSent.uc"}
	}
	ep, err := goEpoch(pb.Uc.Epoch)
	if err != nil {
		return nil, err
	}
	auth, err := protoAuthToGo(pb.Uc.Auth, ep)
	if err != nil {
		return nil, err
	}
	ekEnc, err := protoEncoderToGo(pb.SendingEk)
	if err != nil {
		return nil, err
	}
	// ReceivingCt1 is optional: nil when no ct1 chunks received yet.
	var ct1Dec *mlkembraid.Decoder
	if pb.ReceivingCt1 != nil {
		ct1Dec, err = protoDecoderToGo(pb.ReceivingCt1)
		if err != nil {
			return nil, err
		}
	}
	return mlkembraid.ProtoSetFromFields(
		mlkembraid.StateHeaderSent, ep, mlkembraid.DefaultChunkSize,
		auth, pb.Uc.Dk, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, ekEnc, nil, nil, nil, nil, ct1Dec, nil,
	)
}

func unmarshalCt1Received(pb *pqratchetpb.V1State_Chunked_Ct1Received) (*mlkembraid.State, error) {
	if pb == nil || pb.Uc == nil {
		return nil, &ErrProtoMissingField{Name: "Ct1Received.uc"}
	}
	ep, err := goEpoch(pb.Uc.Epoch)
	if err != nil {
		return nil, err
	}
	auth, err := protoAuthToGo(pb.Uc.Auth, ep)
	if err != nil {
		return nil, err
	}
	ekEnc, err := protoEncoderToGo(pb.SendingEk)
	if err != nil {
		return nil, err
	}
	return mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt1Received, ep, mlkembraid.DefaultChunkSize,
		auth, pb.Uc.Dk, nil, nil, pb.Uc.Ct1, nil, nil, nil, nil, nil, nil,
		nil, ekEnc, nil, nil, nil, nil, nil, nil,
	)
}

func unmarshalEkSentCt1Received(pb *pqratchetpb.V1State_Chunked_EkSentCt1Received) (*mlkembraid.State, error) {
	if pb == nil || pb.Uc == nil {
		return nil, &ErrProtoMissingField{Name: "EkSentCt1Received.uc"}
	}
	ep, err := goEpoch(pb.Uc.Epoch)
	if err != nil {
		return nil, err
	}
	auth, err := protoAuthToGo(pb.Uc.Auth, ep)
	if err != nil {
		return nil, err
	}
	ct2Dec, err := protoDecoderToGo(pb.ReceivingCt2)
	if err != nil {
		return nil, err
	}
	return mlkembraid.ProtoSetFromFields(
		mlkembraid.StateEkSentCt1Received, ep, mlkembraid.DefaultChunkSize,
		auth, pb.Uc.Dk, nil, nil, pb.Uc.Ct1, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, nil, nil, ct2Dec,
	)
}

func unmarshalNoHeaderReceived(pb *pqratchetpb.V1State_Chunked_NoHeaderReceived) (*mlkembraid.State, error) {
	if pb == nil || pb.Uc == nil {
		return nil, &ErrProtoMissingField{Name: "NoHeaderReceived.uc"}
	}
	ep, err := goEpoch(pb.Uc.Epoch)
	if err != nil {
		return nil, err
	}
	auth, err := protoAuthToGo(pb.Uc.Auth, ep)
	if err != nil {
		return nil, err
	}
	hdrDec, err := protoDecoderToGo(pb.ReceivingHdr)
	if err != nil {
		return nil, err
	}
	return mlkembraid.ProtoSetFromFields(
		mlkembraid.StateNoHeaderReceived, ep, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, nil, hdrDec, nil, nil, nil,
	)
}

func unmarshalHeaderReceived(pb *pqratchetpb.V1State_Chunked_HeaderReceived) (*mlkembraid.State, error) {
	if pb == nil || pb.Uc == nil {
		return nil, &ErrProtoMissingField{Name: "HeaderReceived.uc"}
	}
	ep, err := goEpoch(pb.Uc.Epoch)
	if err != nil {
		return nil, err
	}
	auth, err := protoAuthToGo(pb.Uc.Auth, ep)
	if err != nil {
		return nil, err
	}
	hdr := pb.Uc.Hdr
	if len(hdr) != mlkembraid.HeaderSize {
		return nil, &ErrProtoInvalidState{Reason: fmt.Sprintf("HeaderReceived.hdr: want %d bytes, got %d", mlkembraid.HeaderSize, len(hdr))}
	}
	bobEkSeed := hdr[:mlkembraid.EKSeedSize]
	bobHek := hdr[mlkembraid.EKSeedSize:]

	// ReceivingEk is optional: nil when no Ek chunks have been received yet
	// (the ekDecoder is lazily initialized in receiveHeaderReceived).
	var ekDec *mlkembraid.Decoder
	if pb.ReceivingEk != nil {
		var err error
		ekDec, err = protoDecoderToGo(pb.ReceivingEk)
		if err != nil {
			return nil, err
		}
	}
	return mlkembraid.ProtoSetFromFields(
		mlkembraid.StateHeaderReceived, ep, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, bobEkSeed, bobHek, nil, nil, nil, nil,
		nil, nil, nil, nil, nil, ekDec, nil, nil,
	)
}

func unmarshalCt1Sampled(pb *pqratchetpb.V1State_Chunked_Ct1Sampled) (*mlkembraid.State, error) {
	if pb == nil || pb.Uc == nil {
		return nil, &ErrProtoMissingField{Name: "Ct1Sampled.uc"}
	}
	ep, err := goEpoch(pb.Uc.Epoch)
	if err != nil {
		return nil, err
	}
	auth, err := protoAuthToGo(pb.Uc.Auth, ep)
	if err != nil {
		return nil, err
	}
	hdr := pb.Uc.Hdr
	if len(hdr) != mlkembraid.HeaderSize {
		return nil, &ErrProtoInvalidState{Reason: fmt.Sprintf("Ct1Sampled.hdr: want %d bytes, got %d", mlkembraid.HeaderSize, len(hdr))}
	}
	bobEkSeed := hdr[:mlkembraid.EKSeedSize]
	bobHek := hdr[mlkembraid.EKSeedSize:]

	ct1Enc, err := protoEncoderToGo(pb.SendingCt1)
	if err != nil {
		return nil, err
	}
	ekDec, err := protoDecoderToGo(pb.ReceivingEk)
	if err != nil {
		return nil, err
	}
	return mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt1Sampled, ep, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, bobEkSeed, bobHek, pb.Uc.Es, nil, pb.Uc.Ct1, nil,
		nil, nil, ct1Enc, nil, nil, ekDec, nil, nil,
	)
}

func unmarshalEkReceivedCt1Sampled(pb *pqratchetpb.V1State_Chunked_EkReceivedCt1Sampled) (*mlkembraid.State, error) {
	if pb == nil || pb.Uc == nil {
		return nil, &ErrProtoMissingField{Name: "EkReceivedCt1Sampled.uc"}
	}
	ep, err := goEpoch(pb.Uc.Epoch)
	if err != nil {
		return nil, err
	}
	auth, err := protoAuthToGo(pb.Uc.Auth, ep)
	if err != nil {
		return nil, err
	}
	ct1Enc, err := protoEncoderToGo(pb.SendingCt1)
	if err != nil {
		return nil, err
	}
	return mlkembraid.ProtoSetFromFields(
		mlkembraid.StateEkReceivedCt1Sampled, ep, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, pb.Uc.Es, pb.Uc.Ek, pb.Uc.Ct1, nil,
		nil, nil, ct1Enc, nil, nil, nil, nil, nil,
	)
}

func unmarshalCt1Acknowledged(pb *pqratchetpb.V1State_Chunked_Ct1Acknowledged) (*mlkembraid.State, error) {
	if pb == nil || pb.Uc == nil {
		return nil, &ErrProtoMissingField{Name: "Ct1Acknowledged.uc"}
	}
	ep, err := goEpoch(pb.Uc.Epoch)
	if err != nil {
		return nil, err
	}
	auth, err := protoAuthToGo(pb.Uc.Auth, ep)
	if err != nil {
		return nil, err
	}
	hdr := pb.Uc.Hdr
	if len(hdr) != mlkembraid.HeaderSize {
		return nil, &ErrProtoInvalidState{Reason: fmt.Sprintf("Ct1Acknowledged.hdr: want %d bytes, got %d", mlkembraid.HeaderSize, len(hdr))}
	}
	bobEkSeed := hdr[:mlkembraid.EKSeedSize]
	bobHek := hdr[mlkembraid.EKSeedSize:]

	ekDec, err := protoDecoderToGo(pb.ReceivingEk)
	if err != nil {
		return nil, err
	}
	return mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt1Acknowledged, ep, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, bobEkSeed, bobHek, pb.Uc.Es, nil, pb.Uc.Ct1, nil,
		nil, nil, nil, nil, nil, ekDec, nil, nil,
	)
}

func unmarshalCt2Sampled(pb *pqratchetpb.V1State_Chunked_Ct2Sampled) (*mlkembraid.State, error) {
	if pb == nil || pb.Uc == nil {
		return nil, &ErrProtoMissingField{Name: "Ct2Sampled.uc"}
	}
	ep, err := goEpoch(pb.Uc.Epoch)
	if err != nil {
		return nil, err
	}
	auth, err := protoAuthToGo(pb.Uc.Auth, ep)
	if err != nil {
		return nil, err
	}
	ct2Enc, err := protoEncoderToGo(pb.SendingCt2)
	if err != nil {
		return nil, err
	}
	return mlkembraid.ProtoSetFromFields(
		mlkembraid.StateCt2Sampled, ep, mlkembraid.DefaultChunkSize,
		auth, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		nil, nil, nil, ct2Enc, nil, nil, nil, nil,
	)
}
