package zkgroup

import (
	"encoding/binary"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// SerializeReceiptCredentialPresentation encodes p as 329 bytes of Rust bincode: reserved byte, five points, proof, expiration, level, serial.
func SerializeReceiptCredentialPresentation(p *ReceiptCredentialPresentation) []byte {
	proofLen := len(p.PokshoProof)
	out := make([]byte, 0, 1+5*32+8+proofLen+8+8+16)

	out = append(out, 0x00) // reserved

	out = append(out, p.Cx0.Bytes()...)
	out = append(out, p.Cx1.Bytes()...)
	out = append(out, p.Cy1.Bytes()...)
	out = append(out, p.Cy2.Bytes()...)
	out = append(out, p.CV.Bytes()...)

	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(proofLen))
	out = append(out, lenBuf[:]...)
	out = append(out, p.PokshoProof...)

	tsBytes := p.ReceiptExpirationTime.ToLeBytes()
	out = append(out, tsBytes[:]...)

	binary.LittleEndian.PutUint64(lenBuf[:], p.ReceiptLvl)
	out = append(out, lenBuf[:]...)

	out = append(out, p.ReceiptSerialBuf[:]...)

	return out
}

// DeserializeReceiptCredentialPresentation decodes a ReceiptCredentialPresentation
// from Rust bincode wire format. Returns ErrUnexpectedReservedByte if the first
// byte is not 0x00, or ErrDeserializationFailure for structural errors.
func DeserializeReceiptCredentialPresentation(data []byte) (*ReceiptCredentialPresentation, error) {
	const minLen = 1 + 5*32 + 8 + 8 + 8 + 16 // reserved + 5 points + poksho_len + ts + level + serial
	if len(data) < minLen {
		return nil, &ZkGroupDeserializationFailure{TypeName: "ReceiptCredentialPresentation"}
	}

	off := 0

	if data[off] != 0x00 {
		return nil, &ErrUnexpectedReservedByte{Value: data[off]}
	}
	off++

	decodePoint := func() (*ristretto255.Element, error) {
		if len(data) < off+32 {
			return nil, &ZkGroupDeserializationFailure{TypeName: "ReceiptCredentialPresentation"}
		}
		el := ristretto255.NewIdentityElement()
		if _, err := el.SetCanonicalBytes(data[off : off+32]); err != nil {
			return nil, &ZkGroupDeserializationFailure{TypeName: "ReceiptCredentialPresentation"}
		}
		return el, nil
	}

	cx0, err := decodePoint()
	if err != nil {
		return nil, err
	}
	off += 32

	cx1, err := decodePoint()
	if err != nil {
		return nil, err
	}
	off += 32

	cy1, err := decodePoint()
	if err != nil {
		return nil, err
	}
	off += 32

	cy2, err := decodePoint()
	if err != nil {
		return nil, err
	}
	off += 32

	cv, err := decodePoint()
	if err != nil {
		return nil, err
	}
	off += 32

	if len(data) < off+8 {
		return nil, &ZkGroupDeserializationFailure{TypeName: "ReceiptCredentialPresentation"}
	}
	// zkcredential.ReadBincodeU64Len guards against u64 >= 2^63 (negative after
	// int cast) and lengths that exceed remaining input, matching Rust's
	// reject_trailing_bytes + bounded-alloc behavior.
	pokshoLen, lerr := zkcredential.ReadBincodeU64Len(data, off, 1, "poksho_proof")
	if lerr != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "ReceiptCredentialPresentation"}
	}
	off += 8

	if len(data) < off+pokshoLen {
		return nil, &ZkGroupDeserializationFailure{TypeName: "ReceiptCredentialPresentation"}
	}
	pokshoProof := make([]byte, pokshoLen)
	copy(pokshoProof, data[off:off+pokshoLen])
	off += pokshoLen

	if len(data) < off+8+8+16 {
		return nil, &ZkGroupDeserializationFailure{TypeName: "ReceiptCredentialPresentation"}
	}

	var tsBytes [8]byte
	copy(tsBytes[:], data[off:off+8])
	ts := TimestampFromLeBytes(tsBytes)
	off += 8

	level := binary.LittleEndian.Uint64(data[off : off+8])
	off += 8

	var serial ReceiptSerialBytes
	copy(serial[:], data[off:off+16])
	off += 16

	// Rust's reject_trailing_bytes(): the entire input must be consumed.
	if off != len(data) {
		return nil, &ErrTrailingBytes{TypeName: "ReceiptCredentialPresentation", Count: len(data) - off}
	}

	return &ReceiptCredentialPresentation{
		Cx0:                   cx0,
		Cx1:                   cx1,
		Cy1:                   cy1,
		Cy2:                   cy2,
		CV:                    cv,
		PokshoProof:           pokshoProof,
		ReceiptExpirationTime: ts,
		ReceiptLvl:            level,
		ReceiptSerialBuf:      serial,
	}, nil
}

// SerializeBackupAuthCredentialPresentation encodes p as Rust bincode: version byte, level, type, time, proof, backup ID.
func SerializeBackupAuthCredentialPresentation(p *BackupAuthCredentialPresentation) []byte {
	proofBytes := zkcredential.EncodePresentationProofBincode(p.Proof)
	out := make([]byte, 0, 1+8+8+8+len(proofBytes)+16)

	out = append(out, 0x00) // version / reserved

	var u64Buf [8]byte

	binary.LittleEndian.PutUint64(u64Buf[:], uint64(p.Level))
	out = append(out, u64Buf[:]...)

	binary.LittleEndian.PutUint64(u64Buf[:], uint64(p.CredType))
	out = append(out, u64Buf[:]...)

	binary.LittleEndian.PutUint64(u64Buf[:], p.RedemptionTime.EpochSeconds())
	out = append(out, u64Buf[:]...)

	out = append(out, proofBytes...)

	out = append(out, p.BackupIdentifier[:]...)

	return out
}

// DeserializeBackupAuthCredentialPresentation decodes a
// BackupAuthCredentialPresentation from Rust bincode wire format.
func DeserializeBackupAuthCredentialPresentation(data []byte) (*BackupAuthCredentialPresentation, error) {
	const minFixed = 1 + 8 + 8 + 8 // version + level + credtype + redemption_time
	if len(data) < minFixed {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialPresentation"}
	}

	off := 0

	if data[off] != 0x00 {
		return nil, &ErrUnexpectedReservedByte{Value: data[off]}
	}
	off++

	level, err := parseBackupLevel(binary.LittleEndian.Uint64(data[off : off+8]))
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialPresentation"}
	}
	off += 8

	credType, err := parseBackupCredentialType(binary.LittleEndian.Uint64(data[off : off+8]))
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialPresentation"}
	}
	off += 8

	redemptionTime := NewTimestamp(binary.LittleEndian.Uint64(data[off : off+8]))
	off += 8

	proof, consumed, err := zkcredential.DecodePresentationProofBincode(data[off:])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialPresentation"}
	}
	off += consumed

	if len(data) < off+16 {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialPresentation"}
	}
	var backupID BackupID
	copy(backupID[:], data[off:off+16])
	off += 16

	// Rust's reject_trailing_bytes(): the entire input must be consumed.
	if off != len(data) {
		return nil, &ErrTrailingBytes{TypeName: "BackupAuthCredentialPresentation", Count: len(data) - off}
	}

	return &BackupAuthCredentialPresentation{
		Level:            level,
		CredType:         credType,
		RedemptionTime:   redemptionTime,
		Proof:            proof,
		BackupIdentifier: backupID,
	}, nil
}

// SerializeCallLinkAuthCredentialPresentation encodes p as Rust bincode: reserved byte, proof, ciphertext, redemption time.
func SerializeCallLinkAuthCredentialPresentation(p *CallLinkAuthCredentialPresentation) []byte {
	proofBytes := zkcredential.EncodePresentationProofBincode(p.Proof)
	ciphertextBytes := zkcredential.EncodeCiphertext(p.Ciphertext)
	out := make([]byte, 0, 1+len(proofBytes)+64+8)

	out = append(out, 0x00) // reserved

	out = append(out, proofBytes...)

	out = append(out, ciphertextBytes...)

	var tsBuf [8]byte
	binary.LittleEndian.PutUint64(tsBuf[:], p.RedemptionTime.EpochSeconds())
	out = append(out, tsBuf[:]...)

	return out
}

// DeserializeCallLinkAuthCredentialPresentation decodes a
// CallLinkAuthCredentialPresentation from Rust bincode wire format.
func DeserializeCallLinkAuthCredentialPresentation(data []byte) (*CallLinkAuthCredentialPresentation, error) {
	if len(data) < 1 {
		return nil, &ZkGroupDeserializationFailure{TypeName: "CallLinkAuthCredentialPresentation"}
	}

	if data[0] != 0x00 {
		return nil, &ErrUnexpectedReservedByte{Value: data[0]}
	}
	off := 1

	proof, consumed, err := zkcredential.DecodePresentationProofBincode(data[off:])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "CallLinkAuthCredentialPresentation"}
	}
	off += consumed

	if len(data) < off+64+8 {
		return nil, &ZkGroupDeserializationFailure{TypeName: "CallLinkAuthCredentialPresentation"}
	}

	ciphertext, err := zkcredential.DecodeCiphertext(data[off : off+64])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "CallLinkAuthCredentialPresentation"}
	}
	off += 64

	redemptionTime := NewTimestamp(binary.LittleEndian.Uint64(data[off : off+8]))
	off += 8

	// Rust's reject_trailing_bytes(): the entire input must be consumed.
	if off != len(data) {
		return nil, &ErrTrailingBytes{TypeName: "CallLinkAuthCredentialPresentation", Count: len(data) - off}
	}

	return &CallLinkAuthCredentialPresentation{
		Proof:          proof,
		Ciphertext:     ciphertext,
		RedemptionTime: redemptionTime,
	}, nil
}

// SerializeCreateCallLinkCredentialPresentation encodes p as Rust bincode: reserved byte, user ID ciphertext, timestamp, proof.
func SerializeCreateCallLinkCredentialPresentation(p *CreateCallLinkCredentialPresentation) []byte {
	ciphertextBytes := zkcredential.EncodeCiphertext(p.UserID)
	proofBytes := zkcredential.EncodePresentationProofBincode(p.Proof)
	out := make([]byte, 0, 1+64+8+len(proofBytes))

	out = append(out, 0x00) // reserved

	out = append(out, ciphertextBytes...)

	var tsBuf [8]byte
	binary.LittleEndian.PutUint64(tsBuf[:], p.Timestamp.EpochSeconds())
	out = append(out, tsBuf[:]...)

	out = append(out, proofBytes...)

	return out
}

// DeserializeCreateCallLinkCredentialPresentation decodes a
// CreateCallLinkCredentialPresentation from Rust bincode wire format.
func DeserializeCreateCallLinkCredentialPresentation(data []byte) (*CreateCallLinkCredentialPresentation, error) {
	const minLen = 1 + 64 + 8 // reserved + ciphertext + timestamp
	if len(data) < minLen {
		return nil, &ZkGroupDeserializationFailure{TypeName: "CreateCallLinkCredentialPresentation"}
	}

	if data[0] != 0x00 {
		return nil, &ErrUnexpectedReservedByte{Value: data[0]}
	}
	off := 1

	ciphertext, err := zkcredential.DecodeCiphertext(data[off : off+64])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "CreateCallLinkCredentialPresentation"}
	}
	off += 64

	timestamp := NewTimestamp(binary.LittleEndian.Uint64(data[off : off+8]))
	off += 8

	proof, consumed, err := zkcredential.DecodePresentationProofBincode(data[off:])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "CreateCallLinkCredentialPresentation"}
	}
	off += consumed

	// Rust's reject_trailing_bytes(): the entire input must be consumed.
	if off != len(data) {
		return nil, &ErrTrailingBytes{TypeName: "CreateCallLinkCredentialPresentation", Count: len(data) - off}
	}

	return &CreateCallLinkCredentialPresentation{
		UserID:    ciphertext,
		Timestamp: timestamp,
		Proof:     proof,
	}, nil
}
