package mlkembraid

import (
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/polynomial"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// Proto marshaling accessors — used exclusively by pkg/spqr/proto_codec.go
// (Phase D). These expose internal State fields at the minimum visibility needed
// for protobuf round-trips with the Rust reference implementation.  They are NOT
// part of the public API and must not be used outside the serialization layer.

// ProtoEpoch returns the protocol epoch stored in the state. The proto layer
// adds 1 before writing to the protobuf field because Rust uses 1-indexed epochs.
func (s *State) ProtoEpoch() uint64 {
	return s.epoch
}

// ProtoAuth returns the authenticator for proto marshaling.
func (s *State) ProtoAuth() *Authenticator {
	return s.auth
}

// ProtoAuthRootKey returns the authenticator's root_key bytes for proto
// marshaling. Returns nil if the authenticator or root key is nil/destroyed.
func (a *Authenticator) ProtoAuthRootKey() []byte {
	if a == nil || a.rootKey == nil || a.rootKey.IsDestroyed() {
		return nil
	}
	return a.rootKey.Bytes()
}

// ProtoAuthMacKey returns the authenticator's mac_key bytes for proto
// marshaling. Returns nil if the mac key is nil or destroyed.
func (a *Authenticator) ProtoAuthMacKey() []byte {
	if a == nil || a.macKey == nil || a.macKey.IsDestroyed() {
		return nil
	}
	return a.macKey.Bytes()
}

// ProtoAuthEpoch returns the authenticator's epoch for proto marshaling.
func (a *Authenticator) ProtoAuthEpoch() uint64 {
	if a == nil {
		return 0
	}
	return a.epoch
}

// ProtoDK returns the decapsulation key bytes (Alice's dk). Returns nil if
// the secret is nil or destroyed.
func (s *State) ProtoDK() []byte {
	if s.dk == nil || s.dk.IsDestroyed() {
		return nil
	}
	return s.dk.Bytes()
}

// ProtoEKSeed returns the ek_seed bytes. Returns nil if nil or destroyed.
func (s *State) ProtoEKSeed() []byte {
	if s.ekSeed == nil || s.ekSeed.IsDestroyed() {
		return nil
	}
	return s.ekSeed.Bytes()
}

// ProtoEKVector returns the ek_vector bytes. Returns nil if nil or destroyed.
func (s *State) ProtoEKVector() []byte {
	if s.ekVector == nil || s.ekVector.IsDestroyed() {
		return nil
	}
	return s.ekVector.Bytes()
}

// ProtoReceivedCt1 returns the received ct1 bytes. Returns nil if nil or
// destroyed.
func (s *State) ProtoReceivedCt1() []byte {
	if s.receivedCt1 == nil || s.receivedCt1.IsDestroyed() {
		return nil
	}
	return s.receivedCt1.Bytes()
}

// ProtoBobEKSeed returns Bob's received ek_seed bytes (from header). Returns
// nil if nil or destroyed.
func (s *State) ProtoBobEKSeed() []byte {
	if s.bobEkSeed == nil || s.bobEkSeed.IsDestroyed() {
		return nil
	}
	return s.bobEkSeed.Bytes()
}

// ProtoBobHek returns Bob's received hek bytes (from header). Returns nil if
// nil or destroyed.
func (s *State) ProtoBobHek() []byte {
	if s.bobHek == nil || s.bobHek.IsDestroyed() {
		return nil
	}
	return s.bobHek.Bytes()
}

// ProtoBobEncapSecret returns Bob's packed encapsulation secret blob.
// For IncrementalMLKEM768KEM this is 3072 bytes: es(2080) || ct1(960) || ss(32),
// where es is the 2080-byte libcrux EncapsulationState wire format.
// Returns nil if nil or destroyed.
func (s *State) ProtoBobEncapSecret() []byte {
	if s.bobEncapSecret == nil || s.bobEncapSecret.IsDestroyed() {
		return nil
	}
	return s.bobEncapSecret.Bytes()
}

// ProtoBobEKVector returns Bob's received ek_vector bytes. Returns nil if nil
// or destroyed.
func (s *State) ProtoBobEKVector() []byte {
	if s.bobEkVector == nil || s.bobEkVector.IsDestroyed() {
		return nil
	}
	return s.bobEkVector.Bytes()
}

// ProtoBobCt1 returns Bob's ct1 bytes. Returns nil if nil or destroyed.
func (s *State) ProtoBobCt1() []byte {
	if s.bobCt1 == nil || s.bobCt1.IsDestroyed() {
		return nil
	}
	return s.bobCt1.Bytes()
}

// ProtoBobSS returns Bob's shared secret bytes. Returns nil if nil or
// destroyed.
func (s *State) ProtoBobSS() []byte {
	if s.bobSS == nil || s.bobSS.IsDestroyed() {
		return nil
	}
	return s.bobSS.Bytes()
}

// ProtoHeaderEncoder returns the header encoder for proto marshaling.
func (s *State) ProtoHeaderEncoder() *Encoder {
	return s.headerEncoder
}

// ProtoEKEncoder returns the ek encoder for proto marshaling.
func (s *State) ProtoEKEncoder() *Encoder {
	return s.ekEncoder
}

// ProtoCt1Encoder returns the ct1 encoder for proto marshaling.
func (s *State) ProtoCt1Encoder() *Encoder {
	return s.ct1Encoder
}

// ProtoCt2Encoder returns the ct2 encoder for proto marshaling.
func (s *State) ProtoCt2Encoder() *Encoder {
	return s.ct2Encoder
}

// ProtoHeaderDecoder returns the header decoder for proto marshaling.
func (s *State) ProtoHeaderDecoder() *Decoder {
	return s.headerDecoder
}

// ProtoEKDecoder returns the ek decoder for proto marshaling.
func (s *State) ProtoEKDecoder() *Decoder {
	return s.ekDecoder
}

// ProtoCt1Decoder returns the ct1 decoder for proto marshaling.
func (s *State) ProtoCt1Decoder() *Decoder {
	return s.ct1Decoder
}

// ProtoCt2Decoder returns the ct2 decoder for proto marshaling.
func (s *State) ProtoCt2Decoder() *Decoder {
	return s.ct2Decoder
}

// ProtoChunkSize returns the chunk size stored in the state.
func (s *State) ProtoChunkSize() int {
	return s.chunkSize
}

// ProtoSetFromFields constructs a State from proto-decoded fields. This is used
// by UnmarshalStateProto to rebuild the Go State from Rust wire data.
//
// Parameters mirror the fields written by MarshalStateProto; any optional field
// that was absent in the proto is passed as nil.
func ProtoSetFromFields(
	kind StateKind,
	epoch uint64,
	chunkSize int,
	auth *Authenticator,
	dk []byte,
	ekSeed []byte,
	ekVector []byte,
	receivedCt1 []byte,
	bobEkSeed []byte,
	bobHek []byte,
	bobEncapSecret []byte,
	bobEkVector []byte,
	bobCt1 []byte,
	bobSS []byte,
	headerEncoder *Encoder,
	ekEncoder *Encoder,
	ct1Encoder *Encoder,
	ct2Encoder *Encoder,
	headerDecoder *Decoder,
	ekDecoder *Decoder,
	ct1Decoder *Decoder,
	ct2Decoder *Decoder,
) (*State, error) {
	makeSecret := func(data []byte) (*secret.Secret, error) {
		if len(data) == 0 {
			return nil, nil
		}
		cp := make([]byte, len(data))
		copy(cp, data)
		s, err := secret.New(cp)
		if err != nil {
			return nil, err
		}
		return s, nil
	}

	dkSec, err := makeSecret(dk)
	if err != nil {
		return nil, err
	}
	ekSeedSec, err := makeSecret(ekSeed)
	if err != nil {
		if dkSec != nil {
			dkSec.Destroy()
		}
		return nil, err
	}
	ekVecSec, err := makeSecret(ekVector)
	if err != nil {
		if dkSec != nil {
			dkSec.Destroy()
		}
		if ekSeedSec != nil {
			ekSeedSec.Destroy()
		}
		return nil, err
	}
	recvCt1Sec, err := makeSecret(receivedCt1)
	if err != nil {
		if dkSec != nil {
			dkSec.Destroy()
		}
		if ekSeedSec != nil {
			ekSeedSec.Destroy()
		}
		if ekVecSec != nil {
			ekVecSec.Destroy()
		}
		return nil, err
	}
	bobEkSeedSec, err := makeSecret(bobEkSeed)
	if err != nil {
		if dkSec != nil {
			dkSec.Destroy()
		}
		if ekSeedSec != nil {
			ekSeedSec.Destroy()
		}
		if ekVecSec != nil {
			ekVecSec.Destroy()
		}
		if recvCt1Sec != nil {
			recvCt1Sec.Destroy()
		}
		return nil, err
	}
	bobHekSec, err := makeSecret(bobHek)
	if err != nil {
		if dkSec != nil {
			dkSec.Destroy()
		}
		if ekSeedSec != nil {
			ekSeedSec.Destroy()
		}
		if ekVecSec != nil {
			ekVecSec.Destroy()
		}
		if recvCt1Sec != nil {
			recvCt1Sec.Destroy()
		}
		if bobEkSeedSec != nil {
			bobEkSeedSec.Destroy()
		}
		return nil, err
	}
	bobEncapSec, err := makeSecret(bobEncapSecret)
	if err != nil {
		if dkSec != nil {
			dkSec.Destroy()
		}
		if ekSeedSec != nil {
			ekSeedSec.Destroy()
		}
		if ekVecSec != nil {
			ekVecSec.Destroy()
		}
		if recvCt1Sec != nil {
			recvCt1Sec.Destroy()
		}
		if bobEkSeedSec != nil {
			bobEkSeedSec.Destroy()
		}
		if bobHekSec != nil {
			bobHekSec.Destroy()
		}
		return nil, err
	}
	bobEkVecSec, err := makeSecret(bobEkVector)
	if err != nil {
		if dkSec != nil {
			dkSec.Destroy()
		}
		if ekSeedSec != nil {
			ekSeedSec.Destroy()
		}
		if ekVecSec != nil {
			ekVecSec.Destroy()
		}
		if recvCt1Sec != nil {
			recvCt1Sec.Destroy()
		}
		if bobEkSeedSec != nil {
			bobEkSeedSec.Destroy()
		}
		if bobHekSec != nil {
			bobHekSec.Destroy()
		}
		if bobEncapSec != nil {
			bobEncapSec.Destroy()
		}
		return nil, err
	}
	bobCt1Sec, err := makeSecret(bobCt1)
	if err != nil {
		if dkSec != nil {
			dkSec.Destroy()
		}
		if ekSeedSec != nil {
			ekSeedSec.Destroy()
		}
		if ekVecSec != nil {
			ekVecSec.Destroy()
		}
		if recvCt1Sec != nil {
			recvCt1Sec.Destroy()
		}
		if bobEkSeedSec != nil {
			bobEkSeedSec.Destroy()
		}
		if bobHekSec != nil {
			bobHekSec.Destroy()
		}
		if bobEncapSec != nil {
			bobEncapSec.Destroy()
		}
		if bobEkVecSec != nil {
			bobEkVecSec.Destroy()
		}
		return nil, err
	}
	bobSSSec, err := makeSecret(bobSS)
	if err != nil {
		if dkSec != nil {
			dkSec.Destroy()
		}
		if ekSeedSec != nil {
			ekSeedSec.Destroy()
		}
		if ekVecSec != nil {
			ekVecSec.Destroy()
		}
		if recvCt1Sec != nil {
			recvCt1Sec.Destroy()
		}
		if bobEkSeedSec != nil {
			bobEkSeedSec.Destroy()
		}
		if bobHekSec != nil {
			bobHekSec.Destroy()
		}
		if bobEncapSec != nil {
			bobEncapSec.Destroy()
		}
		if bobEkVecSec != nil {
			bobEkVecSec.Destroy()
		}
		if bobCt1Sec != nil {
			bobCt1Sec.Destroy()
		}
		return nil, err
	}

	return &State{
		kind:           kind,
		epoch:          epoch,
		chunkSize:      chunkSize,
		auth:           auth,
		dk:             dkSec,
		ekSeed:         ekSeedSec,
		ekVector:       ekVecSec,
		receivedCt1:    recvCt1Sec,
		bobEkSeed:      bobEkSeedSec,
		bobHek:         bobHekSec,
		bobEncapSecret: bobEncapSec,
		bobEkVector:    bobEkVecSec,
		bobCt1:         bobCt1Sec,
		bobSS:          bobSSSec,
		headerEncoder:  headerEncoder,
		ekEncoder:      ekEncoder,
		ct1Encoder:     ct1Encoder,
		ct2Encoder:     ct2Encoder,
		headerDecoder:  headerDecoder,
		ekDecoder:      ekDecoder,
		ct1Decoder:     ct1Decoder,
		ct2Decoder:     ct2Decoder,
	}, nil
}

// ProtoEncoderFields holds the serialized proto field values for a
// PolynomialEncoder message. Exactly one of Pts or Polys is non-nil.
type ProtoEncoderFields struct {
	// Idx is the current chunk counter (proto: idx field).
	Idx uint32
	// Pts holds 2 bytes per GF(2^16) element per channel (Points state).
	// len(Pts) == NumPolyChannels when in Points state, nil otherwise.
	Pts [][]byte
	// Polys holds serialized polynomial coefficients per channel (Polys state).
	// len(Polys) == NumPolyChannels when in Polys state, nil otherwise.
	Polys [][]byte
}

// NumPolyChannels is the number of parallel polynomial channels (16).
// Exported for the proto codec.
const NumPolyChannels = polynomial.NumPolys

// ProtoMarshalEncoder converts an Encoder to its proto field representation.
// The caller uses the returned ProtoEncoderFields to populate the
// pqratchetpb.PolynomialEncoder message.
func ProtoMarshalEncoder(enc *Encoder) (*ProtoEncoderFields, error) {
	if enc == nil {
		return nil, fmt.Errorf("mlkembraid: ProtoMarshalEncoder: nil encoder")
	}
	inner := enc.InnerEncoder()
	out := &ProtoEncoderFields{Idx: inner.Idx()}

	switch inner.StateKind() {
	case polynomial.EncoderStatePoints:
		pts := inner.Points()
		pbPts := make([][]byte, polynomial.NumPolys)
		for i := 0; i < polynomial.NumPolys; i++ {
			vals := pts[i].Value
			b := make([]byte, len(vals)*2)
			for j, v := range vals {
				b[j*2] = byte(v.Value >> 8)
				b[j*2+1] = byte(v.Value)
			}
			pbPts[i] = b
		}
		out.Pts = pbPts

	case polynomial.EncoderStatePolys:
		polys := inner.Polys()
		pbPolys := make([][]byte, polynomial.NumPolys)
		for i := 0; i < polynomial.NumPolys; i++ {
			pbPolys[i] = polys[i].Serialize()
		}
		out.Polys = pbPolys
	}

	return out, nil
}

// ProtoUnmarshalEncoder reconstructs an Encoder from its proto field representation.
// pts is indexed [channel][2*elemIdx .. 2*elemIdx+2] (big-endian GF values).
// polys is indexed [channel][serialized coefficients] (big-endian).
// idx is the current chunk counter from the proto.
func ProtoUnmarshalEncoder(idx uint32, pts [][]byte, polys [][]byte) (*Encoder, error) {
	inner, err := protoPolyEncoderFromFields(idx, pts, polys)
	if err != nil {
		return nil, err
	}
	msgLen := ProtoEncoderMessageLen(inner)
	if msgLen == 0 {
		return nil, fmt.Errorf("mlkembraid: ProtoUnmarshalEncoder: encoder produced empty message")
	}
	return NewEncoderFromInner(inner, int(idx), msgLen)
}

// protoPolyEncoderFromFields rebuilds a PolyEncoder from raw proto field values.
func protoPolyEncoderFromFields(idx uint32, pts [][]byte, polys [][]byte) (*polynomial.PolyEncoder, error) {
	if len(pts) > 0 {
		// Points state: reconstruct message bytes from channel points.
		if len(pts) != polynomial.NumPolys {
			return nil, fmt.Errorf("mlkembraid: encoder pts: want %d channels, got %d", polynomial.NumPolys, len(pts))
		}
		for i, ch := range pts {
			if len(ch)%2 != 0 {
				return nil, fmt.Errorf("mlkembraid: encoder pts[%d] has odd byte length", i)
			}
		}

		// Compute total element count across all channels.
		totalElems := 0
		for _, ch := range pts {
			totalElems += len(ch) / 2
		}
		if totalElems == 0 {
			return nil, fmt.Errorf("mlkembraid: encoder pts: all channels empty")
		}

		// Reconstruct message in interleaved order.
		// NewPolyEncoder maps message element i → channel i%NumPolys at polyIdx i/NumPolys.
		// Inverse: channel ch, polyIdx j → message element j*NumPolys + ch.
		chanElems := make([]int, polynomial.NumPolys)
		for i, ch := range pts {
			chanElems[i] = len(ch) / 2
		}
		msgLen := totalElems * 2
		msg := make([]byte, msgLen)
		msgPos := 0
		maxPolyIdx := chanElems[0] // channel 0 has the most (or equal) elements
		for polyIdx := 0; polyIdx < maxPolyIdx; polyIdx++ {
			for ch := 0; ch < polynomial.NumPolys; ch++ {
				if polyIdx < chanElems[ch] {
					elemIdx := polyIdx * 2
					msg[msgPos] = pts[ch][elemIdx]
					msg[msgPos+1] = pts[ch][elemIdx+1]
				}
				msgPos += 2
			}
		}

		if len(msg)%2 != 0 {
			msg = append(msg, 0)
		}
		inner, err := polynomial.NewPolyEncoder(msg)
		if err != nil {
			return nil, fmt.Errorf("mlkembraid: rebuild encoder from pts: %w", err)
		}
		// Advance inner chunk counter to match idx.
		for i := uint32(0); i < idx; i++ {
			inner.NextChunk()
		}
		return inner, nil
	}

	if len(polys) == polynomial.NumPolys {
		// Polys state: deserialize coefficients and construct directly.
		polyList := make([]polynomial.Poly, polynomial.NumPolys)
		for i := 0; i < polynomial.NumPolys; i++ {
			p, err := polynomial.DeserializePoly(polys[i])
			if err != nil {
				return nil, fmt.Errorf("mlkembraid: encoder poly[%d]: %w", i, err)
			}
			polyList[i] = p
		}
		inner, err := polynomial.NewPolyEncoderFromPolys(polyList, idx)
		if err != nil {
			return nil, fmt.Errorf("mlkembraid: rebuild encoder from polys: %w", err)
		}
		return inner, nil
	}

	return nil, fmt.Errorf("mlkembraid: encoder has neither pts nor polys")
}

// ProtoDecoderFields holds the serialized proto field values for a
// PolynomialDecoder message.
type ProtoDecoderFields struct {
	// PtsNeeded is the total GF element count (proto: pts_needed field).
	PtsNeeded uint32
	// Polys is always 16 (proto: polys field).
	Polys uint32
	// IsComplete mirrors the decoder's completion flag.
	IsComplete bool
	// Pts holds serialized points per channel: 4 bytes each (x:2 BE || y:2 BE).
	// len(Pts) == NumPolyChannels.
	Pts [][]byte
}

// ProtoMarshalDecoder converts a Decoder to its proto field representation.
func ProtoMarshalDecoder(dec *Decoder) (*ProtoDecoderFields, error) {
	if dec == nil {
		return nil, fmt.Errorf("mlkembraid: ProtoMarshalDecoder: nil decoder")
	}
	inner := dec.InnerDecoder()
	out := &ProtoDecoderFields{
		PtsNeeded:  uint32(inner.PtsNeeded),
		Polys:      16,
		IsComplete: inner.IsComplete,
	}

	pbPts := make([][]byte, polynomial.NumPolys)
	for i := 0; i < polynomial.NumPolys; i++ {
		chanPts := inner.PtsForChannel(i)
		b := make([]byte, len(chanPts)*4)
		for j, p := range chanPts {
			s := polynomial.SerializePt(p)
			b[j*4] = s[0]
			b[j*4+1] = s[1]
			b[j*4+2] = s[2]
			b[j*4+3] = s[3]
		}
		pbPts[i] = b
	}
	out.Pts = pbPts
	return out, nil
}

// ProtoUnmarshalDecoder reconstructs a Decoder from its proto field representation.
// ptsNeeded is in GF(2^16) elements (not bytes). pts contains 4 bytes per point
// per channel (x:2 BE || y:2 BE). isComplete is the decoder completion flag.
func ProtoUnmarshalDecoder(ptsNeeded uint32, pts [][]byte, isComplete bool) (*Decoder, error) {
	if len(pts) != polynomial.NumPolys {
		return nil, fmt.Errorf("mlkembraid: decoder pts: want %d channels, got %d", polynomial.NumPolys, len(pts))
	}

	lenBytes := int(ptsNeeded) * 2
	inner, err := polynomial.NewPolyDecoder(lenBytes)
	if err != nil {
		return nil, fmt.Errorf("mlkembraid: decoder init: %w", err)
	}
	inner.IsComplete = isComplete

	for i := 0; i < polynomial.NumPolys; i++ {
		chPts := pts[i]
		if len(chPts)%4 != 0 {
			return nil, fmt.Errorf("mlkembraid: decoder pts[%d] length %d not multiple of 4", i, len(chPts))
		}
		chanPts := make([]polynomial.Pt, len(chPts)/4)
		for j := range chanPts {
			xVal := uint16(chPts[j*4])<<8 | uint16(chPts[j*4+1])
			yVal := uint16(chPts[j*4+2])<<8 | uint16(chPts[j*4+3])
			chanPts[j] = polynomial.MakePt(xVal, yVal)
		}
		inner.SetPtsForChannel(i, chanPts)
	}

	return NewDecoderFromInner(inner, lenBytes), nil
}

// ProtoEncoderMessageLen returns the length in bytes of the message encoded by
// inner. Used by the proto codec (Phase D) to determine Encoder.total during
// reconstruction.
func ProtoEncoderMessageLen(inner *polynomial.PolyEncoder) int {
	msg := encoderMessage(inner)
	return len(msg)
}

// ProtoNewAuthenticator constructs an Authenticator from raw proto bytes.
// This is used during UnmarshalStateProto.
func ProtoNewAuthenticator(rootKey, macKey []byte, epoch uint64) (*Authenticator, error) {
	rkCopy := make([]byte, len(rootKey))
	copy(rkCopy, rootKey)
	rkSec, err := secret.New(rkCopy)
	if err != nil {
		return nil, err
	}
	var mkSec *secret.Secret
	if len(macKey) > 0 {
		mkCopy := make([]byte, len(macKey))
		copy(mkCopy, macKey)
		mkSec, err = secret.New(mkCopy)
		if err != nil {
			rkSec.Destroy()
			return nil, err
		}
	}
	return &Authenticator{
		rootKey: rkSec,
		macKey:  mkSec,
		epoch:   epoch,
	}, nil
}
