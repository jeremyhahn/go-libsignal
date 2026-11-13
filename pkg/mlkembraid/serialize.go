package mlkembraid

import (
	"encoding/binary"
	"fmt"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/polynomial"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// serializeVersion is the binary format version for Braid serialization.
	serializeVersion uint8 = 0x01
	// kemTypeMLKEM768 identifies ML-KEM-768 in the serialized format.
	kemTypeMLKEM768 uint8 = 0x00
	// stateFixedHeaderSize is the size of the fixed header portion of State serialization.
	stateFixedHeaderSize = 1 + 8 + 4 + 1 + 8 + 8 // stateKind + epoch + chunkSize + ct1Ack + headerMACEpoch + lastReceivedEpoch

	// maxSecretLength is the upper bound on the byte length of a deserialized
	// secret. ML-KEM secrets are at most a few hundred bytes (e.g., ML-KEM-768
	// ciphertext is 1088 bytes, public key is 1184 bytes). A 4096-byte cap
	// prevents unbounded allocation from malformed data.
	maxSecretLength = 4096
)

// ErrSerialize is returned when serialization of a Braid or State fails.
type ErrSerialize struct {
	Reason string
}

func (e *ErrSerialize) Error() string {
	return fmt.Sprintf("mlkembraid: serialize failed: %s", e.Reason)
}

// ErrDeserialize is returned when deserialization of a Braid or State fails.
type ErrDeserialize struct {
	Reason string
}

func (e *ErrDeserialize) Error() string {
	return fmt.Sprintf("mlkembraid: deserialize failed: %s", e.Reason)
}

// Serialize encodes a Braid into a versioned binary format:
//
//	version(1) = 0x01
//	kemType(1) = 0x00 for MLKEM768
//	chunkSize(4, big-endian)
//	stateLen(4, big-endian) + stateBytes(N)
//
// Deprecated: This method emits a Go-only binary format (version byte 0x01)
// that is NOT byte-compatible with the Rust sparsepostquantumratchet crate.
// For Rust-interop serialization, use pkg/spqr proto_codec.go MarshalStateProto /
// UnmarshalStateProto, which encodes state as a prost-compatible PqRatchetState
// protobuf message. This method is retained for existing callers only.
func (b *Braid) Serialize() ([]byte, error) {
	if b.state == nil {
		return nil, &ErrSerialize{Reason: "nil state"}
	}

	stateBytes, err := b.state.serialize()
	if err != nil {
		return nil, err
	}

	// version(1) + kemType(1) + chunkSize(4) + stateLen(4) + stateBytes
	buf := make([]byte, 0, 1+1+4+4+len(stateBytes))
	buf = append(buf, serializeVersion)
	buf = append(buf, kemTypeMLKEM768)
	buf = appendU32BE(buf, uint32(b.chunkSize))
	buf = appendU32BE(buf, uint32(len(stateBytes)))
	buf = append(buf, stateBytes...)

	return buf, nil
}

// DeserializeBraid reconstructs a Braid from binary data produced by Serialize.
//
// Deprecated: This function reads the Go-only binary format (version byte 0x01)
// that is NOT byte-compatible with the Rust sparsepostquantumratchet crate.
// For Rust-interop deserialization, use pkg/spqr proto_codec.go UnmarshalStateProto,
// which decodes a prost-compatible PqRatchetState protobuf message. This function
// is retained for existing callers only.
func DeserializeBraid(data []byte) (*Braid, error) {
	if len(data) < 10 { // version(1) + kemType(1) + chunkSize(4) + stateLen(4)
		return nil, &ErrDeserialize{Reason: "data too short for braid header"}
	}

	offset := 0

	version := data[offset]
	offset++
	if version != serializeVersion {
		return nil, &ErrDeserialize{
			Reason: fmt.Sprintf("unsupported version: %d", version),
		}
	}

	kemType := data[offset]
	offset++

	var kemImpl IncrementalKEM
	switch kemType {
	case kemTypeMLKEM768:
		kemImpl = NewMLKEM768IncrementalKEM()
	default:
		return nil, &ErrDeserialize{
			Reason: fmt.Sprintf("unsupported KEM type: %d", kemType),
		}
	}

	chunkSize := readU32BE(data[offset:])
	offset += 4

	stateLen := readU32BE(data[offset:])
	offset += 4

	if uint32(len(data)-offset) < stateLen {
		return nil, &ErrDeserialize{Reason: "data too short for state payload"}
	}

	stateData := data[offset : offset+int(stateLen)]
	state, err := deserializeState(stateData)
	if err != nil {
		return nil, err
	}

	return &Braid{
		state:     state,
		kem:       kemImpl,
		chunkSize: int(chunkSize),
	}, nil
}

// serialize encodes a State into binary format.
func (s *State) serialize() ([]byte, error) {
	// Estimate capacity: fixed header + authenticator + secrets + encoders + decoders
	buf := make([]byte, 0, 512)

	// Fixed header (30 bytes).
	buf = append(buf, byte(s.kind))
	buf = appendU64BE(buf, s.epoch)
	buf = appendU32BE(buf, uint32(s.chunkSize))
	buf = appendBool(buf, s.ct1Ack)
	buf = appendU64BE(buf, s.headerMACEpoch)
	buf = appendU64BE(buf, s.lastReceivedEpoch)

	// Authenticator (always present).
	authBytes, err := serializeAuthenticator(s.auth)
	if err != nil {
		return nil, err
	}
	buf = append(buf, authBytes...)

	// Secrets: dk, ekSeed, ekVector, bobEkSeed, bobHek, bobEncapSecret,
	// bobEkVector, bobCt1, bobCt2, bobSS, receivedCt1
	secrets := []*secret.Secret{
		s.dk, s.ekSeed, s.ekVector,
		s.bobEkSeed, s.bobHek, s.bobEncapSecret,
		s.bobEkVector, s.bobCt1, s.bobCt2, s.bobSS,
		s.receivedCt1,
	}
	for _, sec := range secrets {
		buf = appendOptionalSecret(buf, sec)
	}

	// Encoders: headerEncoder, ekEncoder, ct1Encoder, ct2Encoder
	encoders := []*Encoder{s.headerEncoder, s.ekEncoder, s.ct1Encoder, s.ct2Encoder}
	for _, enc := range encoders {
		buf = appendOptionalEncoder(buf, enc)
	}

	// Decoders: headerDecoder, ekDecoder, ct1Decoder, ct2Decoder
	decoders := []*Decoder{s.headerDecoder, s.ekDecoder, s.ct1Decoder, s.ct2Decoder}
	for _, dec := range decoders {
		buf = appendOptionalDecoder(buf, dec)
	}

	return buf, nil
}

// deserializeState reconstructs a State from binary data.
func deserializeState(data []byte) (*State, error) {
	if len(data) < stateFixedHeaderSize {
		return nil, &ErrDeserialize{Reason: "data too short for state header"}
	}

	offset := 0
	s := &State{}

	// Fixed header.
	kind := StateKind(data[offset])
	if kind > StateCt2Sampled {
		return nil, &ErrDeserialize{
			Reason: fmt.Sprintf("invalid state kind: %d", kind),
		}
	}
	s.kind = kind
	offset++
	s.epoch = readU64BE(data[offset:])
	offset += 8
	s.chunkSize = int(readU32BE(data[offset:]))
	offset += 4
	s.ct1Ack = data[offset] != 0x00
	offset++
	s.headerMACEpoch = readU64BE(data[offset:])
	offset += 8
	s.lastReceivedEpoch = readU64BE(data[offset:])
	offset += 8

	// Authenticator.
	auth, n, err := deserializeAuthenticator(data[offset:])
	if err != nil {
		return nil, err
	}
	s.auth = auth
	offset += n

	// Secrets.
	secretPtrs := []*(*secret.Secret){
		&s.dk, &s.ekSeed, &s.ekVector,
		&s.bobEkSeed, &s.bobHek, &s.bobEncapSecret,
		&s.bobEkVector, &s.bobCt1, &s.bobCt2, &s.bobSS,
		&s.receivedCt1,
	}
	for _, sp := range secretPtrs {
		sec, n, secErr := readOptionalSecret(data[offset:])
		if secErr != nil {
			s.Zeroize()
			return nil, secErr
		}
		*sp = sec
		offset += n
	}

	// Encoders.
	encoderPtrs := []*(*Encoder){&s.headerEncoder, &s.ekEncoder, &s.ct1Encoder, &s.ct2Encoder}
	for _, ep := range encoderPtrs {
		enc, n, encErr := readOptionalEncoder(data[offset:])
		if encErr != nil {
			s.Zeroize()
			return nil, encErr
		}
		*ep = enc
		offset += n
	}

	// Decoders.
	decoderPtrs := []*(*Decoder){&s.headerDecoder, &s.ekDecoder, &s.ct1Decoder, &s.ct2Decoder}
	for _, dp := range decoderPtrs {
		dec, n, decErr := readOptionalDecoder(data[offset:])
		if decErr != nil {
			s.Zeroize()
			return nil, decErr
		}
		*dp = dec
		offset += n
	}

	return s, nil
}

// serializeAuthenticator encodes an Authenticator into binary:
//
//	rootKey(32) + epoch(8, BE) + hasMAC(1) + [macKey(32)]
func serializeAuthenticator(a *Authenticator) ([]byte, error) {
	if a == nil {
		return nil, &ErrSerialize{Reason: "nil authenticator"}
	}
	if a.rootKey == nil || a.rootKey.IsDestroyed() {
		return nil, &ErrSerialize{Reason: "authenticator rootKey is nil or destroyed"}
	}

	buf := make([]byte, 0, 32+8+1+32)
	if err := a.rootKey.WithBytes(func(rootBytes []byte) error {
		buf = append(buf, rootBytes...)
		return nil
	}); err != nil {
		return nil, &ErrSerialize{Reason: "authenticator rootKey is nil or destroyed"}
	}
	buf = appendU64BE(buf, a.epoch)

	if a.macKey != nil && !a.macKey.IsDestroyed() {
		buf = append(buf, 0x01)
		if err := a.macKey.WithBytes(func(macBytes []byte) error {
			buf = append(buf, macBytes...)
			return nil
		}); err != nil {
			clear(buf)
			return nil, &ErrSerialize{Reason: "authenticator macKey destroyed during serialization"}
		}
	} else {
		buf = append(buf, 0x00)
	}

	return buf, nil
}

// deserializeAuthenticator reads an Authenticator from binary data.
// Returns the authenticator, number of bytes consumed, and any error.
func deserializeAuthenticator(data []byte) (*Authenticator, int, error) {
	minSize := 32 + 8 + 1 // rootKey + epoch + hasMac
	if len(data) < minSize {
		return nil, 0, &ErrDeserialize{Reason: "data too short for authenticator"}
	}

	offset := 0

	// rootKey(32)
	rootCopy := make([]byte, 32)
	copy(rootCopy, data[offset:offset+32])
	offset += 32

	rootKey, err := secret.New(rootCopy) // zeroizes rootCopy
	if err != nil {
		return nil, 0, &ErrDeserialize{Reason: "failed to create rootKey secret: " + err.Error()}
	}

	// epoch(8)
	epoch := readU64BE(data[offset:])
	offset += 8

	// hasMacKey(1)
	hasMac := data[offset]
	offset++

	var macKey *secret.Secret
	if hasMac == 0x01 {
		if len(data) < offset+32 {
			rootKey.Destroy()
			return nil, 0, &ErrDeserialize{Reason: "data too short for authenticator macKey"}
		}
		macCopy := make([]byte, 32)
		copy(macCopy, data[offset:offset+32])
		macKey, err = secret.New(macCopy) // zeroizes macCopy
		if err != nil {
			rootKey.Destroy()
			return nil, 0, &ErrDeserialize{Reason: "failed to create macKey secret: " + err.Error()}
		}
		offset += 32
	}

	return &Authenticator{
		rootKey: rootKey,
		macKey:  macKey,
		epoch:   epoch,
	}, offset, nil
}

// appendOptionalSecret serializes an optional secret as:
//
//	hasField(1) + [dataLen(4, BE) + data(N)]
func appendOptionalSecret(buf []byte, s *secret.Secret) []byte {
	present := false
	if s != nil && !s.IsDestroyed() {
		// The bytes are appended inside the borrow; a secret destroyed
		// concurrently is written as absent.
		_ = s.WithBytes(func(data []byte) error {
			buf = append(buf, 0x01)
			buf = appendU32BE(buf, uint32(len(data)))
			buf = append(buf, data...)
			present = true
			return nil
		})
	}
	if !present {
		buf = append(buf, 0x00)
	}
	return buf
}

// readOptionalSecret reads an optional secret from binary data.
// Returns the secret (or nil), bytes consumed, and any error.
func readOptionalSecret(data []byte) (*secret.Secret, int, error) {
	if len(data) < 1 {
		return nil, 0, &ErrDeserialize{Reason: "data too short for optional secret flag"}
	}

	if data[0] == 0x00 {
		return nil, 1, nil
	}

	if len(data) < 5 { // flag(1) + len(4)
		return nil, 0, &ErrDeserialize{Reason: "data too short for secret length"}
	}

	length := int(readU32BE(data[1:]))
	if length > maxSecretLength {
		return nil, 0, &ErrDeserialize{Reason: fmt.Sprintf("secret length %d exceeds maximum %d", length, maxSecretLength)}
	}
	if len(data) < 5+length {
		return nil, 0, &ErrDeserialize{Reason: "data too short for secret data"}
	}

	copied := make([]byte, length)
	copy(copied, data[5:5+length])
	s, err := secret.New(copied) // zeroizes copied
	if err != nil {
		return nil, 0, &ErrDeserialize{Reason: "failed to create secret: " + err.Error()}
	}

	return s, 5 + length, nil
}

// appendOptionalEncoder serializes an optional Encoder as:
//
//	hasEncoder(1) + [msgLen(4, BE) + msg(N) + sent(4, BE) + total(4, BE) + innerIdx(4, BE)]
//
// msg is the original (padded-if-needed) message that was passed to
// polynomial.NewPolyEncoder. innerIdx is the next chunk index the inner
// PolyEncoder will emit, allowing exact resume after deserialization.
func appendOptionalEncoder(buf []byte, e *Encoder) []byte {
	if e == nil {
		return append(buf, 0x00)
	}
	buf = append(buf, 0x01)

	// Reconstruct the message from the inner encoder's points (first-pass data).
	msg := encoderMessage(e.inner)
	buf = appendU32BE(buf, uint32(len(msg)))
	buf = append(buf, msg...)
	buf = appendU32BE(buf, uint32(e.sent))
	buf = appendU32BE(buf, uint32(e.total))
	buf = appendU32BE(buf, e.inner.Idx())
	return buf
}

// readOptionalEncoder reads an optional Encoder from binary data.
func readOptionalEncoder(data []byte) (*Encoder, int, error) {
	if len(data) < 1 {
		return nil, 0, &ErrDeserialize{Reason: "data too short for optional encoder flag"}
	}

	if data[0] == 0x00 {
		return nil, 1, nil
	}

	// flag(1) + msgLen(4) = 5 minimum to read the length field.
	if len(data) < 5 {
		return nil, 0, &ErrDeserialize{Reason: "data too short for encoder data length"}
	}

	at := 1
	msgLen := int(readU32BE(data[at:]))
	at += 4

	if msgLen > maxSecretLength {
		return nil, 0, &ErrDeserialize{Reason: fmt.Sprintf("encoder message length %d exceeds maximum %d", msgLen, maxSecretLength)}
	}

	// msg(N) + sent(4) + total(4) + innerIdx(4) = N+12
	if len(data) < at+msgLen+12 {
		return nil, 0, &ErrDeserialize{Reason: "data too short for encoder fields"}
	}

	msg := make([]byte, msgLen)
	copy(msg, data[at:at+msgLen])
	at += msgLen

	sent := int(readU32BE(data[at:]))
	at += 4
	total := int(readU32BE(data[at:]))
	at += 4
	innerIdx := readU32BE(data[at:])
	at += 4

	// Bound innerIdx by total to prevent attacker-controlled CPU-DoS.
	// A serialized blob with innerIdx >> total would cause the fast-forward
	// loop below to iterate up to 2^32 times before the legitimate chunks
	// are emitted. Since innerIdx is the number of chunks already emitted
	// from a (sent, total) encoder, any innerIdx > total is malformed.
	if innerIdx > uint32(total) {
		return nil, 0, &ErrDeserialize{Reason: fmt.Sprintf("encoder innerIdx %d exceeds total %d", innerIdx, total)}
	}

	// Re-create the polynomial encoder from the original message.
	inner, err := polynomial.NewPolyEncoder(msg)
	if err != nil {
		return nil, 0, &ErrDeserialize{Reason: "encoder message invalid: " + err.Error()}
	}

	// Fast-forward the inner encoder to the saved chunk index by calling
	// ChunkAt directly (avoids re-emitting chunks via NextChunk).
	// We set idx by pre-advancing: call NextChunk innerIdx times.
	// For large innerIdx this is cheap because ChunkAt is O(1) after the
	// first polynomial interpolation.
	for i := uint32(0); i < innerIdx; i++ {
		inner.NextChunk()
	}

	return &Encoder{
		inner: inner,
		sent:  sent,
		total: total,
	}, at, nil
}

// appendOptionalDecoder serializes an optional Decoder as:
//
//	hasDecoder(1) + [originalLen(4, BE) + received(4, BE) +
//	numLoggedChunks(4, BE) + [chunkWireLen(2, BE) + chunkWireBytes(N)] * numLogged]
//
// The decoder's chunkLog (the exact wire bytes fed to AddChunk, in order)
// is stored verbatim so deserialization can replay them.
func appendOptionalDecoder(buf []byte, d *Decoder) []byte {
	if d == nil {
		return append(buf, 0x00)
	}
	buf = append(buf, 0x01)
	buf = appendU32BE(buf, uint32(d.originalLen))
	buf = appendU32BE(buf, uint32(d.ReceivedCount()))
	buf = appendU32BE(buf, uint32(len(d.chunkLog)))
	for _, wc := range d.chunkLog {
		buf = appendU16BE(buf, uint16(len(wc)))
		buf = append(buf, wc...)
	}
	return buf
}

// readOptionalDecoder reads an optional Decoder from binary data.
func readOptionalDecoder(data []byte) (*Decoder, int, error) {
	if len(data) < 1 {
		return nil, 0, &ErrDeserialize{Reason: "data too short for optional decoder flag"}
	}

	if data[0] == 0x00 {
		return nil, 1, nil
	}

	// flag(1) + originalLen(4) + received(4) + numLogged(4) = 13 minimum.
	if len(data) < 13 {
		return nil, 0, &ErrDeserialize{Reason: "data too short for decoder header"}
	}

	at := 1
	originalLen := int(readU32BE(data[at:]))
	at += 4
	received := int(readU32BE(data[at:]))
	at += 4
	numLogged := int(readU32BE(data[at:]))
	at += 4

	if numLogged > MaxChunkIndex+1 {
		return nil, 0, &ErrDeserialize{Reason: fmt.Sprintf("decoder logged chunk count %d exceeds maximum %d", numLogged, MaxChunkIndex+1)}
	}

	// Reconstruct the Decoder and replay the logged wire chunks.
	d, err := NewDecoder(originalLen, 0)
	if err != nil {
		return nil, 0, &ErrDeserialize{Reason: "decoder init failed: " + err.Error()}
	}

	for i := 0; i < numLogged; i++ {
		if len(data) < at+2 {
			return nil, 0, &ErrDeserialize{Reason: "data too short for decoder chunk length"}
		}
		chunkLen := int(readU16BE(data[at:]))
		at += 2

		if len(data) < at+chunkLen {
			return nil, 0, &ErrDeserialize{Reason: "data too short for decoder chunk data"}
		}
		wireChunk := make([]byte, chunkLen)
		copy(wireChunk, data[at:at+chunkLen])
		at += chunkLen

		if addErr := d.AddChunk(wireChunk); addErr != nil {
			return nil, 0, &ErrDeserialize{Reason: "decoder chunk replay failed: " + addErr.Error()}
		}
	}

	// received is not separately restored: AddChunk replay above naturally
	// rebuilds seenIndices, so ReceivedCount() will match the original.
	// Suppress the unused variable warning.
	_ = received

	return d, at, nil
}

// Binary encoding helpers.

func appendU16BE(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

func appendU32BE(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendU64BE(buf []byte, v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return append(buf, b[:]...)
}

func appendBool(buf []byte, v bool) []byte {
	if v {
		return append(buf, 0x01)
	}
	return append(buf, 0x00)
}

func readU16BE(data []byte) uint16 {
	return uint16(data[0])<<8 | uint16(data[1])
}

func readU32BE(data []byte) uint32 {
	return uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
}

func readU64BE(data []byte) uint64 {
	return binary.BigEndian.Uint64(data)
}
