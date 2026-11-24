package zkgroup

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// Wire-format sizes for [BackupAuthCredentialRequest] (fixed length).
const backupAuthCredentialRequestSize = 1 + 64 + 32 // reserved + BlindedPoint + BlindingPublicKey

// SerializeBackupAuthCredentialRequest encodes r as 97 bytes of Rust bincode: reserved byte, blinded backup ID, public key.
func SerializeBackupAuthCredentialRequest(r *BackupAuthCredentialRequest) []byte {
	out := make([]byte, 0, backupAuthCredentialRequestSize)
	out = append(out, 0x00) // reserved
	out = append(out, zkcredential.EncodeBlindedPoint(r.BlindedBackupID)...)
	out = append(out, zkcredential.EncodeBlindingPublicKey(r.PublicKey)...)
	return out
}

// DeserializeBackupAuthCredentialRequest decodes a
// [BackupAuthCredentialRequest] from the Rust bincode wire format.
func DeserializeBackupAuthCredentialRequest(data []byte) (*BackupAuthCredentialRequest, error) {
	if len(data) != backupAuthCredentialRequestSize {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialRequest"}
	}
	if data[0] != 0x00 {
		return nil, &ErrUnexpectedReservedByte{Value: data[0]}
	}

	bp, err := zkcredential.DecodeBlindedPoint(data[1:65])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialRequest"}
	}
	pk, err := zkcredential.DecodeBlindingPublicKey(data[65:97])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialRequest"}
	}
	return &BackupAuthCredentialRequest{
		BlindedBackupID: bp,
		PublicKey:       pk,
	}, nil
}

// SerializeBackupAuthCredentialResponse encodes r as Rust bincode: reserved byte, u64 LE time, level and type, credential, proof.
func SerializeBackupAuthCredentialResponse(r *BackupAuthCredentialResponse) []byte {
	proof := zkcredential.EncodeBlindedIssuanceProofBincode(r.BlindedCredential)
	out := make([]byte, 0, 1+8+8+8+len(proof))

	out = append(out, 0x00) // reserved

	var buf [8]byte

	binary.LittleEndian.PutUint64(buf[:], r.RedemptionTime.EpochSeconds())
	out = append(out, buf[:]...)

	binary.LittleEndian.PutUint64(buf[:], uint64(r.Level))
	out = append(out, buf[:]...)

	binary.LittleEndian.PutUint64(buf[:], uint64(r.CredType))
	out = append(out, buf[:]...)

	out = append(out, proof...)

	return out
}

// DeserializeBackupAuthCredentialResponse decodes a
// [BackupAuthCredentialResponse] from the Rust bincode wire format produced
// by [SerializeBackupAuthCredentialResponse].
func DeserializeBackupAuthCredentialResponse(data []byte) (*BackupAuthCredentialResponse, error) {
	const minFixed = 1 + 8 + 8 + 8 // reserved + redemption_time + level + credtype
	if len(data) < minFixed {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialResponse"}
	}

	off := 0
	if data[off] != 0x00 {
		return nil, &ErrUnexpectedReservedByte{Value: data[off]}
	}
	off++

	redemption := NewTimestamp(binary.LittleEndian.Uint64(data[off : off+8]))
	off += 8

	level, err := parseBackupLevel(binary.LittleEndian.Uint64(data[off : off+8]))
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialResponse"}
	}
	off += 8

	credType, err := parseBackupCredentialType(binary.LittleEndian.Uint64(data[off : off+8]))
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialResponse"}
	}
	off += 8

	proof, consumed, err := zkcredential.DecodeBlindedIssuanceProofBincode(data[off:])
	if err != nil {
		return nil, &ZkGroupDeserializationFailure{TypeName: "BackupAuthCredentialResponse"}
	}
	off += consumed

	// Rust's reject_trailing_bytes(): the entire input must be consumed.
	if off != len(data) {
		return nil, &ErrTrailingBytes{TypeName: "BackupAuthCredentialResponse", Count: len(data) - off}
	}

	return &BackupAuthCredentialResponse{
		RedemptionTime:    redemption,
		Level:             level,
		CredType:          credType,
		BlindedCredential: proof,
	}, nil
}
