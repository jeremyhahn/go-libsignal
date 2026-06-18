// Package zkgroup implements the Signal Private Group System's zero-knowledge
// group credentials. It provides types and operations for anonymous credential
// issuance, presentation, and verification using ristretto255 group operations.
//
// This is a port of the Rust libsignal zkgroup implementation. The low-level
// credential operations are delegated to the zkcredential package; this package
// provides the higher-level API types used by Signal clients and servers.
//
// Based on "The Signal Private Group System and Anonymous Credentials Supporting
// Efficient Verifiable Encryption" by Chase, Perrin, and Zaverucha.
package zkgroup

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// Standard byte lengths for zkgroup types.
const (
	RandomnessLen               = 32
	UUIDLen                     = 16
	ProfileKeyLen               = 32
	ProfileKeyVersionLen        = 32
	ProfileKeyVersionEncodedLen = 64
	GroupMasterKeyLen           = 32
	GroupIdentifierLen          = 32
	AESKeyLen                   = 32
	AESGCMNonceLen              = 12
	AESGCMTagLen                = 16
	SignatureLen                = 64
	AccessKeyLen                = 16
	ReceiptSerialLen            = 16
	ReservedLen                 = 1
	SecondsPerDay               = 86400
)

// Standard type aliases for byte arrays used throughout zkgroup.
type (
	RandomnessBytes               [RandomnessLen]byte
	UIDBytes                      [UUIDLen]byte
	ProfileKeyBytes               [ProfileKeyLen]byte
	ProfileKeyVersionBytes        [ProfileKeyVersionLen]byte
	ProfileKeyVersionEncodedBytes [ProfileKeyVersionEncodedLen]byte
	GroupMasterKeyBytes           [GroupMasterKeyLen]byte
	GroupIdentifierBytes          [GroupIdentifierLen]byte
	AESKeyBytes                   [AESKeyLen]byte
	SignatureBytes                [SignatureLen]byte
	NotarySignatureBytes          [SignatureLen]byte
	ReceiptSerialBytes            [ReceiptSerialLen]byte
)

// ReceiptLevel is used to tell the server what to redeem a receipt for.
type ReceiptLevel = uint64

// Timestamp represents a point in time as seconds since the Unix epoch.
// Clients should only accept round multiples of 86400 to avoid fingerprinting.
type Timestamp struct {
	seconds uint64
}

// NewTimestamp creates a Timestamp from epoch seconds.
func NewTimestamp(epochSeconds uint64) Timestamp {
	return Timestamp{seconds: epochSeconds}
}

// TimestampFromTime creates a Timestamp from a time.Time.
func TimestampFromTime(t time.Time) Timestamp {
	return Timestamp{seconds: uint64(t.Unix())}
}

// EpochSeconds returns the epoch seconds value.
func (t Timestamp) EpochSeconds() uint64 {
	return t.seconds
}

// ToTime converts this Timestamp to a time.Time.
func (t Timestamp) ToTime() time.Time {
	return time.Unix(int64(t.seconds), 0)
}

// AddSeconds returns a new Timestamp with additional seconds added.
func (t Timestamp) AddSeconds(s uint64) Timestamp {
	return Timestamp{seconds: t.seconds + s}
}

// SubSeconds returns a new Timestamp with seconds subtracted.
func (t Timestamp) SubSeconds(s uint64) Timestamp {
	return Timestamp{seconds: t.seconds - s}
}

// CheckedAddSeconds returns a new Timestamp with seconds added, or false if overflow.
func (t Timestamp) CheckedAddSeconds(s uint64) (Timestamp, bool) {
	result := t.seconds + s
	if result < t.seconds {
		return Timestamp{}, false
	}
	return Timestamp{seconds: result}, true
}

// CheckedSubSeconds returns a new Timestamp with seconds subtracted, or false if underflow.
func (t Timestamp) CheckedSubSeconds(s uint64) (Timestamp, bool) {
	if t.seconds < s {
		return Timestamp{}, false
	}
	return Timestamp{seconds: t.seconds - s}, true
}

// IsDayAligned returns true if this timestamp falls on a UTC day boundary.
func (t Timestamp) IsDayAligned() bool {
	return t.seconds%SecondsPerDay == 0
}

// ToBeBytes returns the big-endian byte representation.
func (t Timestamp) ToBeBytes() [8]byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], t.seconds)
	return b
}

// ToLeBytes returns the little-endian byte representation, matching the Rust
// bincode wire format (with_little_endian + with_fixint_encoding).
func (t Timestamp) ToLeBytes() [8]byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], t.seconds)
	return b
}

// TimestampFromLeBytes decodes a Timestamp from 8 little-endian bytes.
func TimestampFromLeBytes(b [8]byte) Timestamp {
	return Timestamp{seconds: binary.LittleEndian.Uint64(b[:])}
}

// SaturatingSecondsSince returns the number of seconds between t and before,
// returning 0 if t is earlier than before.
func (t Timestamp) SaturatingSecondsSince(before Timestamp) uint64 {
	if t.seconds <= before.seconds {
		return 0
	}
	return t.seconds - before.seconds
}

// HashInto implements the zkcredential.PublicAttribute interface.
func (t Timestamp) HashInto(sho *zkcredential.ShoExt) {
	b := t.ToBeBytes()
	sho.AbsorbAndRatchet(b[:])
}

// ServiceID represents a Signal service identifier (ACI or PNI).
type ServiceID struct {
	Type    ServiceIDType
	RawUUID [UUIDLen]byte
}

// ServiceIDType distinguishes between ACI and PNI service identifiers.
type ServiceIDType byte

const (
	// ServiceIDTypeACI is an Account Identity.
	ServiceIDTypeACI ServiceIDType = 0
	// ServiceIDTypePNI is a Phone Number Identity.
	ServiceIDTypePNI ServiceIDType = 1
)

// NewACI creates a ServiceID for an ACI.
func NewACI(uuid [UUIDLen]byte) ServiceID {
	return ServiceID{Type: ServiceIDTypeACI, RawUUID: uuid}
}

// NewPNI creates a ServiceID for a PNI.
func NewPNI(uuid [UUIDLen]byte) ServiceID {
	return ServiceID{Type: ServiceIDTypePNI, RawUUID: uuid}
}

// Bytes returns the raw UUID bytes.
func (s ServiceID) Bytes() [UUIDLen]byte {
	return s.RawUUID
}

// ServiceIdBinary returns the standard variable-width binary representation
// of this ServiceID, matching Rust's ServiceId::service_id_binary().
// For ACI, this returns just the raw 16-byte UUID.
// For PNI, this returns 17 bytes: [0x01 type prefix] + [16 UUID bytes].
func (s ServiceID) ServiceIdBinary() []byte {
	if s.Type == ServiceIDTypeACI {
		return s.RawUUID[:]
	}
	out := make([]byte, 1+UUIDLen)
	out[0] = byte(s.Type)
	copy(out[1:], s.RawUUID[:])
	return out
}

// scalarGroupOrder is the ristretto255/edwards25519 scalar group order L.
// L = 2^252 + 27742317777372353535851937790883648493
var scalarGroupOrder = func() *big.Int {
	l, ok := new(big.Int).SetString("7237005577332262213973186563042994240857116359379907606001950938285454250989", 10)
	if !ok {
		panic("zkgroup: failed to parse scalar group order")
	}
	return l
}()

// scalarFromBytesModOrder interprets a 32-byte slice as a little-endian integer
// and reduces it modulo the scalar group order L. This matches Rust's
// Scalar::from_bytes_mod_order which performs 32-byte modular reduction.
func scalarFromBytesModOrder(input [32]byte) *ristretto255.Scalar {
	// Convert little-endian bytes to big.Int.
	// big.Int.SetBytes expects big-endian, so reverse the byte order.
	var reversed [32]byte
	for i := 0; i < 32; i++ {
		reversed[i] = input[31-i]
	}
	n := new(big.Int).SetBytes(reversed[:])

	// Reduce mod L.
	n.Mod(n, scalarGroupOrder)

	// Convert back to 32-byte little-endian representation.
	reduced := n.Bytes() // big-endian
	var result [32]byte
	for i, b := range reduced {
		result[len(reduced)-1-i] = b
	}

	sc := ristretto255.NewScalar()
	if _, err := sc.SetCanonicalBytes(result[:]); err != nil {
		// After mod-L reduction, the value is always < L and canonical.
		panic(fmt.Sprintf("zkgroup: scalar from bytes mod order produced non-canonical result: %v", err))
	}
	return sc
}

// encodeRedemptionTime encodes a u32 redemption time as a ristretto255 scalar.
// Matches Rust's encode_redemption_time: big-endian u32 in first 4 bytes of a
// 32-byte array, then Scalar::from_bytes_mod_order.
func encodeRedemptionTime(redemptionTime uint32) *ristretto255.Scalar {
	var scalarBytes [32]byte
	binary.BigEndian.PutUint32(scalarBytes[0:4], redemptionTime)
	return scalarFromBytesModOrder(scalarBytes)
}

// encodeReceiptSerialBytes encodes receipt serial bytes as a scalar.
// Matches Rust's encode_receipt_serial_bytes: first 16 bytes copied into a
// 32-byte array, then Scalar::from_bytes_mod_order.
func encodeReceiptSerialBytes(serialBytes ReceiptSerialBytes) *ristretto255.Scalar {
	var scalarBytes [32]byte
	copy(scalarBytes[:16], serialBytes[:])
	return scalarFromBytesModOrder(scalarBytes)
}

// hexEncode returns the hex encoding of src.
func hexEncode(src []byte) string {
	return hex.EncodeToString(src)
}

// Serialize encodes a byte slice with a leading reserved byte.
func Serialize(data []byte) []byte {
	out := make([]byte, 0, 1+len(data))
	out = append(out, 0) // reserved byte
	out = append(out, data...)
	return out
}

// Deserialize strips the leading reserved byte and returns the rest.
func Deserialize(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return nil, &ErrDataTooShort{}
	}
	if data[0] != 0 {
		return nil, &ErrUnexpectedReservedByte{Value: data[0]}
	}
	return data[1:], nil
}
