package spqr

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

const (
	// serializeVersionV4 is the current serialization format version.
	// V4 extends V3 by appending optional braid state after chain data.
	serializeVersionV4 = 0x04

	// serializeVersionV3 is a serialization format version.
	// V3 adds version negotiation state after the version byte.
	serializeVersionV3 = 0x03

	// serializeVersion is the V2 serialization format version.
	// V2 adds the maxJump field (4 bytes) to the header.
	serializeVersion = 0x02

	// serializeVersionV1 is the legacy serialization format version that
	// did not include the maxJump field. On deserialization, V1 data is
	// assigned the default maxJump value (25000).
	serializeVersionV1 = 0x01

	// headerSize is the fixed-size header for V2:
	// version(1) + direction(1) + epoch(8) + sendEpoch(8) + rootKey(32) + maxJump(4) + numChains(4).
	headerSize = 1 + 1 + 8 + 8 + 32 + 4 + 4

	// headerSizeV1 is the fixed-size header for V1 (without maxJump):
	// version(1) + direction(1) + epoch(8) + sendEpoch(8) + rootKey(32) + numChains(4).
	headerSizeV1 = 1 + 1 + 8 + 8 + 32 + 4

	// v3NegotiationPendingSize is the size of a V3 pending negotiation state:
	// version(1) + negotiated(1) + authKey(32) + minVersion(1) + direction(1) + maxJump(4).
	v3NegotiationPendingSize = 1 + 1 + keyLen + 1 + 1 + 4

	// v3DisabledSize is the size of a V3 disabled (V0) state:
	// version(1) + negotiated(1) + resolvedVersion(1).
	v3DisabledSize = 1 + 1 + 1

	// chainFixedSize is the fixed portion of each chain entry: epoch(8) + sendCounter(4) + recvCounter(4) + hasSendKey(1) + hasRecvKey(1).
	chainFixedSize = 8 + 4 + 4 + 1 + 1

	// skippedKeyEntrySize is the size of each skipped key entry: epoch(8) + counter(4) + key(32).
	skippedKeyEntrySize = 8 + 4 + 32

	// maxDeserializedChains is the upper bound on the number of epoch chains
	// that can be deserialized, well above normal usage to prevent unbounded
	// allocation from malformed data.
	maxDeserializedChains = 100

	// maxDeserializedSkippedKeys is the upper bound on the number of skipped
	// message keys that can be deserialized, slightly above maxSkippedKeys
	// to allow for serialization of states near the limit.
	maxDeserializedSkippedKeys = 5000

	// maxBraidSerializedLen is the upper bound on the serialized braid state
	// length (64 KiB) to prevent unbounded allocation from malformed data.
	maxBraidSerializedLen = 65536
)

// ErrSerialize is returned when serialization fails.
type ErrSerialize struct {
	Reason string
}

func (e *ErrSerialize) Error() string {
	return fmt.Sprintf("spqr: serialization failed: %s", e.Reason)
}

// ErrDeserialize is returned when deserialization fails.
type ErrDeserialize struct {
	Reason string
}

func (e *ErrDeserialize) Error() string {
	return fmt.Sprintf("spqr: deserialization failed: %s", e.Reason)
}

// Serialize serializes the SPQR state into opaque bytes for storage.
// The key material is copied out of guarded memory for serialization.
//
// Note: The serialized output is an unprotected []byte in GC-managed memory.
// The caller should zeroize the returned buffer when no longer needed
// (e.g., via crypto.Zeroize) to minimize the window where key material
// is exposed outside memguard protection.
//
// V4 format extends V3 by appending optional braid state after chain data:
//   - Pending negotiation: version(1) + negotiated(0x00) + authKey(32) + minVersion(1) + direction(1) + maxJump(4) + hasBraid(1) + [braidLen(4 BE) + braidState(N)]
//   - Resolved V0 (disabled): version(1) + negotiated(0x01) + resolvedVersion(0x00)
//   - Resolved V1: version(1) + negotiated(0x01) + resolvedVersion(0x01) + [V2 chain format without version byte] + hasBraid(1) + [braidLen(4 BE) + braidState(N)]
//
// V3 format (legacy, no braid):
//   - Same as V4 but without the hasBraid trailer.
func (s *SPQR) Serialize() ([]byte, error) {
	// If braid is present, use V4 format.
	if s.braid != nil {
		return s.serializeV4(s.braid)
	}

	// No braid: use V3 format for backward compatibility.
	if s.negotiation == negotiationPending {
		return s.serializeV3Pending()
	}
	if s.IsDisabled() {
		return s.serializeV3Disabled()
	}
	return s.serializeV3Resolved()
}

// serializeV4 serializes the state in V4 format, which includes braid state.
func (s *SPQR) serializeV4(braid *mlkembraid.Braid) ([]byte, error) {
	if s.negotiation == negotiationPending {
		return s.serializeV4Pending(braid)
	}
	if s.IsDisabled() {
		// V0 disabled has no chain data and no braid to store, but we must
		// preserve the V4 version byte so that round-trip deserialization
		// correctly enters the V4 code path (which can handle braid state
		// on future re-enablement).
		return s.serializeV4Disabled()
	}
	return s.serializeV4Resolved(braid)
}

// serializeV4Disabled serializes a V0 (disabled) resolved state with the V4
// version byte. This preserves the version byte on round-trip so that a V4
// instance that was disabled does not silently downgrade to V3 format.
// The body format is identical to V3 disabled: negotiated(0x01) + resolvedVersion(0x00).
func (s *SPQR) serializeV4Disabled() ([]byte, error) {
	buf := make([]byte, v3DisabledSize)
	buf[0] = serializeVersionV4
	buf[1] = 0x01 // negotiated
	buf[2] = byte(VersionV0)
	return buf, nil
}

// serializeV4Pending serializes a pending negotiation state with braid.
func (s *SPQR) serializeV4Pending(braid *mlkembraid.Braid) ([]byte, error) {
	if len(s.authKey) == 0 {
		return nil, &ErrSerialize{Reason: "auth key is nil for pending negotiation"}
	}

	braidData, err := braid.Serialize()
	if err != nil {
		return nil, &ErrSerialize{Reason: fmt.Sprintf("braid serialization failed: %v", err)}
	}

	// V4 pending: version(1) + negotiated(1) + authKey(32) + minVersion(1) + direction(1) + maxJump(4) + hasBraid(1) + braidLen(4) + braidData(N)
	size := 1 + 1 + keyLen + 1 + 1 + 4 + 1 + 4 + len(braidData)
	buf := make([]byte, size)
	offset := 0
	buf[offset] = serializeVersionV4
	offset++
	buf[offset] = 0x00 // not negotiated
	offset++
	copy(buf[offset:], s.authKey)
	offset += keyLen
	buf[offset] = byte(s.minVersion)
	offset++
	buf[offset] = byte(s.direction)
	offset++
	binary.BigEndian.PutUint32(buf[offset:], s.maxJump)
	offset += 4
	buf[offset] = 0x01 // hasBraid
	offset++
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(braidData)))
	offset += 4
	copy(buf[offset:], braidData)

	return buf, nil
}

// serializeV4Resolved serializes a V1 resolved state with braid state appended.
func (s *SPQR) serializeV4Resolved(braid *mlkembraid.Braid) ([]byte, error) {
	if s.rootKey == nil || s.rootKey.IsDestroyed() {
		return nil, &ErrSerialize{Reason: "root key is nil or destroyed"}
	}

	braidData, err := braid.Serialize()
	if err != nil {
		return nil, &ErrSerialize{Reason: fmt.Sprintf("braid serialization failed: %v", err)}
	}

	// Calculate size: V4 header(3) + chain header + chains + skipped keys + hasBraid(1) + braidLen(4) + braidData(N)
	chainHeaderSize := 1 + 8 + 8 + keyLen + 4 + 4 // direction + epoch + sendEpoch + rootKey + maxJump + numChains
	size := 3 + chainHeaderSize
	for _, chain := range s.chains {
		size += chainFixedSize
		if chain.sendKey != nil && !chain.sendKey.IsDestroyed() {
			size += keyLen
		}
		if chain.recvKey != nil && !chain.recvKey.IsDestroyed() {
			size += keyLen
		}
	}
	size += 4 // numSkippedKeys
	size += len(s.skippedKeys) * skippedKeyEntrySize
	size += 1 + 4 + len(braidData) // hasBraid + braidLen + braidData

	buf := make([]byte, size)
	offset := 0

	// V4 header.
	buf[offset] = serializeVersionV4
	offset++
	buf[offset] = 0x01 // negotiated
	offset++
	buf[offset] = byte(VersionV1)
	offset++

	// Chain data (same as V3 resolved).
	buf[offset] = byte(s.direction)
	offset++
	binary.BigEndian.PutUint64(buf[offset:], s.epoch)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], s.sendEpoch)
	offset += 8
	copy(buf[offset:], s.rootKey.Bytes())
	offset += keyLen
	binary.BigEndian.PutUint32(buf[offset:], s.maxJump)
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(s.chains)))
	offset += 4

	// Chains in sorted epoch order.
	epochs := make([]uint64, 0, len(s.chains))
	for epoch := range s.chains {
		epochs = append(epochs, epoch)
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })

	for _, epoch := range epochs {
		chain := s.chains[epoch]
		binary.BigEndian.PutUint64(buf[offset:], epoch)
		offset += 8
		binary.BigEndian.PutUint32(buf[offset:], chain.sendCounter)
		offset += 4
		binary.BigEndian.PutUint32(buf[offset:], chain.recvCounter)
		offset += 4

		hasSend := chain.sendKey != nil && !chain.sendKey.IsDestroyed()
		if hasSend {
			buf[offset] = 1
		}
		offset++
		if hasSend {
			copy(buf[offset:], chain.sendKey.Bytes())
			offset += keyLen
		}

		hasRecv := chain.recvKey != nil && !chain.recvKey.IsDestroyed()
		if hasRecv {
			buf[offset] = 1
		}
		offset++
		if hasRecv {
			copy(buf[offset:], chain.recvKey.Bytes())
			offset += keyLen
		}
	}

	// Skipped keys.
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(s.skippedKeys)))
	offset += 4

	skIDs := make([]SkippedKeyID, 0, len(s.skippedKeys))
	for id := range s.skippedKeys {
		skIDs = append(skIDs, id)
	}
	sort.Slice(skIDs, func(i, j int) bool {
		if skIDs[i].Epoch != skIDs[j].Epoch {
			return skIDs[i].Epoch < skIDs[j].Epoch
		}
		return skIDs[i].Counter < skIDs[j].Counter
	})

	for _, id := range skIDs {
		sk := s.skippedKeys[id]
		if sk == nil || sk.IsDestroyed() {
			return nil, &ErrSerialize{Reason: "skipped key is nil or destroyed"}
		}
		binary.BigEndian.PutUint64(buf[offset:], id.Epoch)
		offset += 8
		binary.BigEndian.PutUint32(buf[offset:], id.Counter)
		offset += 4
		copy(buf[offset:], sk.Bytes())
		offset += keyLen
	}

	// Braid state.
	buf[offset] = 0x01 // hasBraid
	offset++
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(braidData)))
	offset += 4
	copy(buf[offset:], braidData)

	return buf, nil
}

// serializeV3Pending serializes a pending negotiation state.
func (s *SPQR) serializeV3Pending() ([]byte, error) {
	if len(s.authKey) == 0 {
		return nil, &ErrSerialize{Reason: "auth key is nil for pending negotiation"}
	}

	buf := make([]byte, v3NegotiationPendingSize)
	offset := 0
	buf[offset] = serializeVersionV3
	offset++
	buf[offset] = 0x00 // not negotiated
	offset++
	copy(buf[offset:], s.authKey)
	offset += keyLen
	buf[offset] = byte(s.minVersion)
	offset++
	buf[offset] = byte(s.direction)
	offset++
	binary.BigEndian.PutUint32(buf[offset:], s.maxJump)
	return buf, nil
}

// serializeV3Disabled serializes a V0 (disabled) resolved state with V3 format.
// Used only for instances without a braid. V4 instances use serializeV4Disabled
// to preserve the V4 version byte on round-trip.
func (s *SPQR) serializeV3Disabled() ([]byte, error) {
	buf := make([]byte, v3DisabledSize)
	buf[0] = serializeVersionV3
	buf[1] = 0x01 // negotiated
	buf[2] = byte(VersionV0)
	return buf, nil
}

// serializeV3Resolved serializes a V1 resolved state (with chain data).
func (s *SPQR) serializeV3Resolved() ([]byte, error) {
	if s.rootKey == nil || s.rootKey.IsDestroyed() {
		return nil, &ErrSerialize{Reason: "root key is nil or destroyed"}
	}

	// Calculate chain data size (same as V2 but without the version byte).
	// v3 header: version(1) + negotiated(1) + resolvedVersion(1)
	// then V2 chain format: direction(1) + epoch(8) + sendEpoch(8) + rootKey(32) + maxJump(4) + numChains(4)
	chainHeaderSize := 1 + 8 + 8 + keyLen + 4 + 4
	size := 3 + chainHeaderSize // v3 header + chain header
	for _, chain := range s.chains {
		size += chainFixedSize
		if chain.sendKey != nil && !chain.sendKey.IsDestroyed() {
			size += keyLen
		}
		if chain.recvKey != nil && !chain.recvKey.IsDestroyed() {
			size += keyLen
		}
	}
	size += 4 // numSkippedKeys
	size += len(s.skippedKeys) * skippedKeyEntrySize

	buf := make([]byte, size)
	offset := 0

	// V3 header.
	buf[offset] = serializeVersionV3
	offset++
	buf[offset] = 0x01 // negotiated
	offset++
	buf[offset] = byte(VersionV1)
	offset++

	// Chain data (V2 format without version byte).
	buf[offset] = byte(s.direction)
	offset++
	binary.BigEndian.PutUint64(buf[offset:], s.epoch)
	offset += 8
	binary.BigEndian.PutUint64(buf[offset:], s.sendEpoch)
	offset += 8
	copy(buf[offset:], s.rootKey.Bytes())
	offset += keyLen
	binary.BigEndian.PutUint32(buf[offset:], s.maxJump)
	offset += 4
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(s.chains)))
	offset += 4

	// Chains in sorted epoch order for deterministic output.
	epochs := make([]uint64, 0, len(s.chains))
	for epoch := range s.chains {
		epochs = append(epochs, epoch)
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })

	for _, epoch := range epochs {
		chain := s.chains[epoch]
		binary.BigEndian.PutUint64(buf[offset:], epoch)
		offset += 8
		binary.BigEndian.PutUint32(buf[offset:], chain.sendCounter)
		offset += 4
		binary.BigEndian.PutUint32(buf[offset:], chain.recvCounter)
		offset += 4

		hasSend := chain.sendKey != nil && !chain.sendKey.IsDestroyed()
		if hasSend {
			buf[offset] = 1
		}
		offset++
		if hasSend {
			copy(buf[offset:], chain.sendKey.Bytes())
			offset += keyLen
		}

		hasRecv := chain.recvKey != nil && !chain.recvKey.IsDestroyed()
		if hasRecv {
			buf[offset] = 1
		}
		offset++
		if hasRecv {
			copy(buf[offset:], chain.recvKey.Bytes())
			offset += keyLen
		}
	}

	// Skipped keys in sorted order for deterministic output.
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(s.skippedKeys)))
	offset += 4

	skIDs := make([]SkippedKeyID, 0, len(s.skippedKeys))
	for id := range s.skippedKeys {
		skIDs = append(skIDs, id)
	}
	sort.Slice(skIDs, func(i, j int) bool {
		if skIDs[i].Epoch != skIDs[j].Epoch {
			return skIDs[i].Epoch < skIDs[j].Epoch
		}
		return skIDs[i].Counter < skIDs[j].Counter
	})

	for _, id := range skIDs {
		sk := s.skippedKeys[id]
		if sk == nil || sk.IsDestroyed() {
			return nil, &ErrSerialize{Reason: "skipped key is nil or destroyed"}
		}
		binary.BigEndian.PutUint64(buf[offset:], id.Epoch)
		offset += 8
		binary.BigEndian.PutUint32(buf[offset:], id.Counter)
		offset += 4
		copy(buf[offset:], sk.Bytes())
		offset += keyLen
	}

	return buf, nil
}

// Deserialize reconstructs an SPQR instance from serialized bytes.
// The key material is moved into guarded memory (secret.New).
// V1 (without maxJump), V2 (with maxJump), and V3 (with version negotiation)
// formats are all supported.
func Deserialize(data []byte) (*SPQR, error) {
	// Need at least 1 byte to read version.
	if len(data) < 1 {
		return nil, &ErrDeserialize{Reason: "data too short for header"}
	}

	version := data[0]

	// V4: handle braid-aware format.
	if version == serializeVersionV4 {
		return deserializeV4(data)
	}

	// V3: handle version negotiation format.
	if version == serializeVersionV3 {
		return deserializeV3(data)
	}

	var minHeader int
	switch version {
	case serializeVersionV1:
		minHeader = headerSizeV1
	case serializeVersion:
		minHeader = headerSize
	default:
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("unsupported version %d", version)}
	}

	if len(data) < minHeader {
		return nil, &ErrDeserialize{Reason: "data too short for header"}
	}

	offset := 1 // version already read

	dirByte := data[offset]
	offset++
	if dirByte > 1 {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("invalid direction %d", dirByte)}
	}
	direction := Direction(dirByte)

	epoch := binary.BigEndian.Uint64(data[offset:])
	offset += 8
	sendEpoch := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	rkBytes := make([]byte, keyLen)
	copy(rkBytes, data[offset:offset+keyLen])
	offset += keyLen
	rootKey, err := secret.New(rkBytes)
	if err != nil {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create root key secret: %v", err)}
	}

	// V2 includes maxJump; V1 defaults to the package-level constant.
	maxJumpValue := uint32(maxJump)
	if version >= serializeVersion {
		maxJumpValue = binary.BigEndian.Uint32(data[offset:])
		offset += 4
	}

	numChains := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if numChains > maxDeserializedChains {
		rootKey.Destroy()
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("chain count %d exceeds maximum %d", numChains, maxDeserializedChains)}
	}

	chains := make(map[uint64]*EpochChain, numChains)
	for i := uint32(0); i < numChains; i++ {
		if offset+chainFixedSize > len(data) {
			rootKey.Destroy()
			destroyChains(chains)
			return nil, &ErrDeserialize{Reason: "data too short for chain entry"}
		}

		chainEpoch := binary.BigEndian.Uint64(data[offset:])
		offset += 8
		sendCounter := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		recvCounter := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		hasSendKey := data[offset] == 1
		offset++
		var sendKey *secret.Secret
		if hasSendKey {
			if offset+keyLen > len(data) {
				rootKey.Destroy()
				destroyChains(chains)
				return nil, &ErrDeserialize{Reason: "data too short for send key"}
			}
			skBytes := make([]byte, keyLen)
			copy(skBytes, data[offset:offset+keyLen])
			offset += keyLen
			sendKey, err = secret.New(skBytes)
			if err != nil {
				rootKey.Destroy()
				destroyChains(chains)
				return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create send key secret: %v", err)}
			}
		}

		hasRecvKey := data[offset] == 1
		offset++
		var recvKey *secret.Secret
		if hasRecvKey {
			if offset+keyLen > len(data) {
				rootKey.Destroy()
				destroyChains(chains)
				if sendKey != nil {
					sendKey.Destroy()
				}
				return nil, &ErrDeserialize{Reason: "data too short for recv key"}
			}
			rkB := make([]byte, keyLen)
			copy(rkB, data[offset:offset+keyLen])
			offset += keyLen
			recvKey, err = secret.New(rkB)
			if err != nil {
				rootKey.Destroy()
				destroyChains(chains)
				if sendKey != nil {
					sendKey.Destroy()
				}
				return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create recv key secret: %v", err)}
			}
		}

		chains[chainEpoch] = &EpochChain{
			sendKey:     sendKey,
			recvKey:     recvKey,
			sendCounter: sendCounter,
			recvCounter: recvCounter,
		}
	}

	// Skipped keys.
	if offset+4 > len(data) {
		rootKey.Destroy()
		destroyChains(chains)
		return nil, &ErrDeserialize{Reason: "data too short for skipped keys count"}
	}
	numSkipped := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if numSkipped > maxDeserializedSkippedKeys {
		rootKey.Destroy()
		destroyChains(chains)
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("skipped key count %d exceeds maximum %d", numSkipped, maxDeserializedSkippedKeys)}
	}

	skippedKeys := make(map[SkippedKeyID]*secret.Secret, numSkipped)
	for i := uint32(0); i < numSkipped; i++ {
		if offset+skippedKeyEntrySize > len(data) {
			rootKey.Destroy()
			destroyChains(chains)
			destroySkippedKeys(skippedKeys)
			return nil, &ErrDeserialize{Reason: "data too short for skipped key entry"}
		}

		skEpoch := binary.BigEndian.Uint64(data[offset:])
		offset += 8
		skCounter := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		mkBytes := make([]byte, keyLen)
		copy(mkBytes, data[offset:offset+keyLen])
		offset += keyLen
		mk, mkErr := secret.New(mkBytes)
		if mkErr != nil {
			rootKey.Destroy()
			destroyChains(chains)
			destroySkippedKeys(skippedKeys)
			return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create skipped key secret: %v", mkErr)}
		}

		skippedKeys[SkippedKeyID{Epoch: skEpoch, Counter: skCounter}] = mk
	}

	if offset != len(data) {
		rootKey.Destroy()
		destroyChains(chains)
		destroySkippedKeys(skippedKeys)
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("trailing data: %d bytes remaining", len(data)-offset)}
	}

	// V1/V2 formats always had chains initialized, so mark as negotiated V1.
	return &SPQR{
		rootKey:     rootKey,
		epoch:       epoch,
		sendEpoch:   sendEpoch,
		chains:      chains,
		skippedKeys: skippedKeys,
		direction:   direction,
		maxJump:     maxJumpValue,
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV0,
	}, nil
}

// deserializeV3 handles deserialization of V3 format data with version negotiation.
func deserializeV3(data []byte) (*SPQR, error) {
	if len(data) < 2 {
		return nil, &ErrDeserialize{Reason: "V3 data too short"}
	}

	negotiated := data[1]

	switch negotiated {
	case 0x00:
		// Pending negotiation.
		return deserializeV3Pending(data)
	case 0x01:
		// Negotiation resolved.
		if len(data) < 3 {
			return nil, &ErrDeserialize{Reason: "V3 resolved data too short for version"}
		}
		resolvedVersion := Version(data[2])
		switch resolvedVersion {
		case VersionV0:
			return deserializeV3Disabled(data)
		case VersionV1:
			return deserializeV3Resolved(data)
		default:
			return nil, &ErrDeserialize{Reason: fmt.Sprintf("V3 unsupported resolved version %d", resolvedVersion)}
		}
	default:
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V3 invalid negotiation byte %d", negotiated)}
	}
}

// deserializeV3Pending deserializes a V3 pending negotiation state.
func deserializeV3Pending(data []byte) (*SPQR, error) {
	if len(data) < v3NegotiationPendingSize {
		return nil, &ErrDeserialize{Reason: "V3 pending data too short"}
	}
	if len(data) != v3NegotiationPendingSize {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V3 pending trailing data: %d bytes remaining", len(data)-v3NegotiationPendingSize)}
	}

	offset := 2 // version + negotiated already read

	authKey := make([]byte, keyLen)
	copy(authKey, data[offset:offset+keyLen])
	offset += keyLen

	minVersion := Version(data[offset])
	offset++
	if minVersion > VersionV1 {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V3 invalid min version %d", minVersion)}
	}

	dirByte := data[offset]
	offset++
	if dirByte > 1 {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V3 invalid direction %d", dirByte)}
	}

	maxJumpValue := binary.BigEndian.Uint32(data[offset:])

	return &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   Direction(dirByte),
		maxJump:     maxJumpValue,
		negotiation: negotiationPending,
		version:     VersionV1,
		minVersion:  minVersion,
		authKey:     authKey,
	}, nil
}

// deserializeV3Disabled deserializes a V3 disabled (V0) state.
func deserializeV3Disabled(data []byte) (*SPQR, error) {
	if len(data) != v3DisabledSize {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V3 disabled trailing data: %d bytes remaining", len(data)-v3DisabledSize)}
	}

	return &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		negotiation: negotiationResolved,
		version:     VersionV0,
	}, nil
}

// deserializeV3Resolved deserializes a V3 resolved V1 state (with chain data).
func deserializeV3Resolved(data []byte) (*SPQR, error) {
	// After V3 header (3 bytes), the rest is V2 chain format without the version byte.
	offset := 3 // version + negotiated + resolvedVersion

	// Need at least: direction(1) + epoch(8) + sendEpoch(8) + rootKey(32) + maxJump(4) + numChains(4) = 57
	minSize := offset + 1 + 8 + 8 + keyLen + 4 + 4
	if len(data) < minSize {
		return nil, &ErrDeserialize{Reason: "V3 resolved data too short for chain header"}
	}

	dirByte := data[offset]
	offset++
	if dirByte > 1 {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V3 invalid direction %d", dirByte)}
	}
	direction := Direction(dirByte)

	epoch := binary.BigEndian.Uint64(data[offset:])
	offset += 8
	sendEpoch := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	rkBytes := make([]byte, keyLen)
	copy(rkBytes, data[offset:offset+keyLen])
	offset += keyLen
	rootKey, err := secret.New(rkBytes)
	if err != nil {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create root key secret: %v", err)}
	}

	maxJumpValue := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	numChains := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if numChains > maxDeserializedChains {
		rootKey.Destroy()
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("chain count %d exceeds maximum %d", numChains, maxDeserializedChains)}
	}

	chains := make(map[uint64]*EpochChain, numChains)
	for i := uint32(0); i < numChains; i++ {
		if offset+chainFixedSize > len(data) {
			rootKey.Destroy()
			destroyChains(chains)
			return nil, &ErrDeserialize{Reason: "V3 data too short for chain entry"}
		}

		chainEpoch := binary.BigEndian.Uint64(data[offset:])
		offset += 8
		sendCounter := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		recvCounter := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		hasSendKey := data[offset] == 1
		offset++
		var sendKey *secret.Secret
		if hasSendKey {
			if offset+keyLen > len(data) {
				rootKey.Destroy()
				destroyChains(chains)
				return nil, &ErrDeserialize{Reason: "V3 data too short for send key"}
			}
			skBytes := make([]byte, keyLen)
			copy(skBytes, data[offset:offset+keyLen])
			offset += keyLen
			sendKey, err = secret.New(skBytes)
			if err != nil {
				rootKey.Destroy()
				destroyChains(chains)
				return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create send key secret: %v", err)}
			}
		}

		hasRecvKey := data[offset] == 1
		offset++
		var recvKey *secret.Secret
		if hasRecvKey {
			if offset+keyLen > len(data) {
				rootKey.Destroy()
				destroyChains(chains)
				if sendKey != nil {
					sendKey.Destroy()
				}
				return nil, &ErrDeserialize{Reason: "V3 data too short for recv key"}
			}
			rkB := make([]byte, keyLen)
			copy(rkB, data[offset:offset+keyLen])
			offset += keyLen
			recvKey, err = secret.New(rkB)
			if err != nil {
				rootKey.Destroy()
				destroyChains(chains)
				if sendKey != nil {
					sendKey.Destroy()
				}
				return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create recv key secret: %v", err)}
			}
		}

		chains[chainEpoch] = &EpochChain{
			sendKey:     sendKey,
			recvKey:     recvKey,
			sendCounter: sendCounter,
			recvCounter: recvCounter,
		}
	}

	// Skipped keys.
	if offset+4 > len(data) {
		rootKey.Destroy()
		destroyChains(chains)
		return nil, &ErrDeserialize{Reason: "V3 data too short for skipped keys count"}
	}
	numSkipped := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if numSkipped > maxDeserializedSkippedKeys {
		rootKey.Destroy()
		destroyChains(chains)
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("skipped key count %d exceeds maximum %d", numSkipped, maxDeserializedSkippedKeys)}
	}

	skippedKeys := make(map[SkippedKeyID]*secret.Secret, numSkipped)
	for i := uint32(0); i < numSkipped; i++ {
		if offset+skippedKeyEntrySize > len(data) {
			rootKey.Destroy()
			destroyChains(chains)
			destroySkippedKeys(skippedKeys)
			return nil, &ErrDeserialize{Reason: "V3 data too short for skipped key entry"}
		}

		skEpoch := binary.BigEndian.Uint64(data[offset:])
		offset += 8
		skCounter := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		mkBytes := make([]byte, keyLen)
		copy(mkBytes, data[offset:offset+keyLen])
		offset += keyLen
		mk, mkErr := secret.New(mkBytes)
		if mkErr != nil {
			rootKey.Destroy()
			destroyChains(chains)
			destroySkippedKeys(skippedKeys)
			return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create skipped key secret: %v", mkErr)}
		}

		skippedKeys[SkippedKeyID{Epoch: skEpoch, Counter: skCounter}] = mk
	}

	if offset != len(data) {
		rootKey.Destroy()
		destroyChains(chains)
		destroySkippedKeys(skippedKeys)
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V3 trailing data: %d bytes remaining", len(data)-offset)}
	}

	return &SPQR{
		rootKey:     rootKey,
		epoch:       epoch,
		sendEpoch:   sendEpoch,
		chains:      chains,
		skippedKeys: skippedKeys,
		direction:   direction,
		maxJump:     maxJumpValue,
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV0,
	}, nil
}

// deserializeV4 handles deserialization of V4 format data with optional braid state.
func deserializeV4(data []byte) (*SPQR, error) {
	if len(data) < 2 {
		return nil, &ErrDeserialize{Reason: "V4 data too short"}
	}

	negotiated := data[1]

	switch negotiated {
	case 0x00:
		return deserializeV4Pending(data)
	case 0x01:
		if len(data) < 3 {
			return nil, &ErrDeserialize{Reason: "V4 resolved data too short for version"}
		}
		resolvedVersion := Version(data[2])
		switch resolvedVersion {
		case VersionV0:
			return deserializeV3Disabled(data)
		case VersionV1:
			return deserializeV4Resolved(data)
		default:
			return nil, &ErrDeserialize{Reason: fmt.Sprintf("V4 unsupported resolved version %d", resolvedVersion)}
		}
	default:
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V4 invalid negotiation byte %d", negotiated)}
	}
}

// deserializeV4Pending deserializes a V4 pending negotiation state with optional braid.
func deserializeV4Pending(data []byte) (*SPQR, error) {
	// Minimum size: version(1) + negotiated(1) + authKey(32) + minVersion(1) + direction(1) + maxJump(4) + hasBraid(1) = 41
	minSize := 1 + 1 + keyLen + 1 + 1 + 4 + 1
	if len(data) < minSize {
		return nil, &ErrDeserialize{Reason: "V4 pending data too short"}
	}

	offset := 2 // version + negotiated already read

	authKey := make([]byte, keyLen)
	copy(authKey, data[offset:offset+keyLen])
	offset += keyLen

	minVersion := Version(data[offset])
	offset++
	if minVersion > VersionV1 {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V4 invalid min version %d", minVersion)}
	}

	dirByte := data[offset]
	offset++
	if dirByte > 1 {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V4 invalid direction %d", dirByte)}
	}

	maxJumpValue := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	hasBraid := data[offset]
	offset++

	var braid *mlkembraid.Braid
	if hasBraid == 0x01 {
		if offset+4 > len(data) {
			return nil, &ErrDeserialize{Reason: "V4 pending data too short for braid length"}
		}
		braidLen := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		if braidLen > maxBraidSerializedLen {
			return nil, &ErrBraidTooLarge{Size: braidLen, Max: maxBraidSerializedLen}
		}
		if offset+int(braidLen) > len(data) {
			return nil, &ErrDeserialize{Reason: "V4 pending data too short for braid state"}
		}
		braidData := data[offset : offset+int(braidLen)]
		offset += int(braidLen)

		var braidErr error
		braid, braidErr = mlkembraid.DeserializeBraid(braidData)
		if braidErr != nil {
			return nil, &ErrDeserialize{Reason: fmt.Sprintf("V4 braid deserialization failed: %v", braidErr)}
		}
	}

	if offset != len(data) {
		if braid != nil {
			braid.Zeroize()
		}
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V4 pending trailing data: %d bytes remaining", len(data)-offset)}
	}

	return &SPQR{
		chains:      make(map[uint64]*EpochChain),
		skippedKeys: make(map[SkippedKeyID]*secret.Secret),
		direction:   Direction(dirByte),
		maxJump:     maxJumpValue,
		negotiation: negotiationPending,
		version:     VersionV1,
		minVersion:  minVersion,
		authKey:     authKey,
		braid:       braid,
	}, nil
}

// deserializeV4Resolved deserializes a V4 resolved V1 state with chain data and optional braid.
func deserializeV4Resolved(data []byte) (*SPQR, error) {
	offset := 3 // version + negotiated + resolvedVersion

	// Need at least: direction(1) + epoch(8) + sendEpoch(8) + rootKey(32) + maxJump(4) + numChains(4) = 57
	minSize := offset + 1 + 8 + 8 + keyLen + 4 + 4
	if len(data) < minSize {
		return nil, &ErrDeserialize{Reason: "V4 resolved data too short for chain header"}
	}

	dirByte := data[offset]
	offset++
	if dirByte > 1 {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V4 invalid direction %d", dirByte)}
	}
	direction := Direction(dirByte)

	epoch := binary.BigEndian.Uint64(data[offset:])
	offset += 8
	sendEpoch := binary.BigEndian.Uint64(data[offset:])
	offset += 8

	rkBytes := make([]byte, keyLen)
	copy(rkBytes, data[offset:offset+keyLen])
	offset += keyLen
	rootKey, err := secret.New(rkBytes)
	if err != nil {
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create root key secret: %v", err)}
	}

	maxJumpValue := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	numChains := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if numChains > maxDeserializedChains {
		rootKey.Destroy()
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("chain count %d exceeds maximum %d", numChains, maxDeserializedChains)}
	}

	chains := make(map[uint64]*EpochChain, numChains)
	for i := uint32(0); i < numChains; i++ {
		if offset+chainFixedSize > len(data) {
			rootKey.Destroy()
			destroyChains(chains)
			return nil, &ErrDeserialize{Reason: "V4 data too short for chain entry"}
		}

		chainEpoch := binary.BigEndian.Uint64(data[offset:])
		offset += 8
		sendCounter := binary.BigEndian.Uint32(data[offset:])
		offset += 4
		recvCounter := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		hasSendKey := data[offset] == 1
		offset++
		var sendKey *secret.Secret
		if hasSendKey {
			if offset+keyLen > len(data) {
				rootKey.Destroy()
				destroyChains(chains)
				return nil, &ErrDeserialize{Reason: "V4 data too short for send key"}
			}
			skBytes := make([]byte, keyLen)
			copy(skBytes, data[offset:offset+keyLen])
			offset += keyLen
			sendKey, err = secret.New(skBytes)
			if err != nil {
				rootKey.Destroy()
				destroyChains(chains)
				return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create send key secret: %v", err)}
			}
		}

		hasRecvKey := data[offset] == 1
		offset++
		var recvKey *secret.Secret
		if hasRecvKey {
			if offset+keyLen > len(data) {
				rootKey.Destroy()
				destroyChains(chains)
				if sendKey != nil {
					sendKey.Destroy()
				}
				return nil, &ErrDeserialize{Reason: "V4 data too short for recv key"}
			}
			rkB := make([]byte, keyLen)
			copy(rkB, data[offset:offset+keyLen])
			offset += keyLen
			recvKey, err = secret.New(rkB)
			if err != nil {
				rootKey.Destroy()
				destroyChains(chains)
				if sendKey != nil {
					sendKey.Destroy()
				}
				return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create recv key secret: %v", err)}
			}
		}

		chains[chainEpoch] = &EpochChain{
			sendKey:     sendKey,
			recvKey:     recvKey,
			sendCounter: sendCounter,
			recvCounter: recvCounter,
		}
	}

	// Skipped keys.
	if offset+4 > len(data) {
		rootKey.Destroy()
		destroyChains(chains)
		return nil, &ErrDeserialize{Reason: "V4 data too short for skipped keys count"}
	}
	numSkipped := binary.BigEndian.Uint32(data[offset:])
	offset += 4

	if numSkipped > maxDeserializedSkippedKeys {
		rootKey.Destroy()
		destroyChains(chains)
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("skipped key count %d exceeds maximum %d", numSkipped, maxDeserializedSkippedKeys)}
	}

	skippedKeys := make(map[SkippedKeyID]*secret.Secret, numSkipped)
	for i := uint32(0); i < numSkipped; i++ {
		if offset+skippedKeyEntrySize > len(data) {
			rootKey.Destroy()
			destroyChains(chains)
			destroySkippedKeys(skippedKeys)
			return nil, &ErrDeserialize{Reason: "V4 data too short for skipped key entry"}
		}

		skEpoch := binary.BigEndian.Uint64(data[offset:])
		offset += 8
		skCounter := binary.BigEndian.Uint32(data[offset:])
		offset += 4

		mkBytes := make([]byte, keyLen)
		copy(mkBytes, data[offset:offset+keyLen])
		offset += keyLen
		mk, mkErr := secret.New(mkBytes)
		if mkErr != nil {
			rootKey.Destroy()
			destroyChains(chains)
			destroySkippedKeys(skippedKeys)
			return nil, &ErrDeserialize{Reason: fmt.Sprintf("failed to create skipped key secret: %v", mkErr)}
		}

		skippedKeys[SkippedKeyID{Epoch: skEpoch, Counter: skCounter}] = mk
	}

	// Braid state (optional trailer).
	var braid *mlkembraid.Braid
	if offset < len(data) {
		hasBraid := data[offset]
		offset++
		if hasBraid == 0x01 {
			if offset+4 > len(data) {
				rootKey.Destroy()
				destroyChains(chains)
				destroySkippedKeys(skippedKeys)
				return nil, &ErrDeserialize{Reason: "V4 data too short for braid length"}
			}
			braidLen := binary.BigEndian.Uint32(data[offset:])
			offset += 4
			if braidLen > maxBraidSerializedLen {
				rootKey.Destroy()
				destroyChains(chains)
				destroySkippedKeys(skippedKeys)
				return nil, &ErrBraidTooLarge{Size: braidLen, Max: maxBraidSerializedLen}
			}
			if offset+int(braidLen) > len(data) {
				rootKey.Destroy()
				destroyChains(chains)
				destroySkippedKeys(skippedKeys)
				return nil, &ErrDeserialize{Reason: "V4 data too short for braid state"}
			}
			braidData := data[offset : offset+int(braidLen)]
			offset += int(braidLen)

			var braidErr error
			braid, braidErr = mlkembraid.DeserializeBraid(braidData)
			if braidErr != nil {
				rootKey.Destroy()
				destroyChains(chains)
				destroySkippedKeys(skippedKeys)
				return nil, &ErrDeserialize{Reason: fmt.Sprintf("V4 braid deserialization failed: %v", braidErr)}
			}
		}
	}

	if offset != len(data) {
		rootKey.Destroy()
		destroyChains(chains)
		destroySkippedKeys(skippedKeys)
		if braid != nil {
			braid.Zeroize()
		}
		return nil, &ErrDeserialize{Reason: fmt.Sprintf("V4 trailing data: %d bytes remaining", len(data)-offset)}
	}

	return &SPQR{
		rootKey:     rootKey,
		epoch:       epoch,
		sendEpoch:   sendEpoch,
		chains:      chains,
		skippedKeys: skippedKeys,
		direction:   direction,
		maxJump:     maxJumpValue,
		negotiation: negotiationResolved,
		version:     VersionV1,
		minVersion:  VersionV0,
		braid:       braid,
	}, nil
}

// destroyChains zeroizes all chain keys during error cleanup.
func destroyChains(chains map[uint64]*EpochChain) {
	for _, chain := range chains {
		chain.Zeroize()
	}
}

// destroySkippedKeys zeroizes all skipped keys during error cleanup.
func destroySkippedKeys(keys map[SkippedKeyID]*secret.Secret) {
	for id, mk := range keys {
		mk.Destroy()
		delete(keys, id)
	}
}
