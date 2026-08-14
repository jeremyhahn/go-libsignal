package zkgroup

import (
	"encoding/binary"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// Wire-format sizes for [BackupAuthCredentialRequest] (fixed length).
const backupAuthCredentialRequestSize = 1 + 64 + 32 // reserved + BlindedPoint + BlindingPublicKey

// SerializeBackupAuthCredentialRequest serializes a
// [BackupAuthCredentialRequest] to the Rust bincode wire format, producing
// byte-for-byte identical output to Rust's bincode::serialize on the same
// struct.
//
// Wire layout (matches Rust BackupAuthCredentialRequest at
// rust/zkgroup/src/api/backups/auth_credential.rs:153-158):
//
//	[0x00]   reserved byte (ReservedByte)
//	[64]     blinded_backup_id (BlindedPoint: D1 + D2, 32 bytes each)
//	[32]     public_key (BlindingPublicKey: Ypoint, 32 bytes)
//
// Total: 97 bytes.
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

// SerializeBackupAuthCredentialResponse serializes a
// [BackupAuthCredentialResponse] to the Rust bincode wire format.
//
// Wire layout (matches Rust BackupAuthCredentialResponse at
// rust/zkgroup/src/api/backups/auth_credential.rs:184-194):
//
//	[0x00]      reserved byte (ReservedByte)
//	[8 LE u64]  redemption_time (Timestamp = u64 seconds since epoch)
//	[8 LE u64]  backup_level (BackupLevel serialized as u64)
//	[8 LE u64]  credential_type (BackupCredentialType serialized as u64)
//	[128]       BlindedCredential (T + U + S1 + S2)
//	[8 LE u64]  poksho_proof vec length
//	[len]       poksho_proof bytes
//
// Total: 161 + len(poksho_proof) bytes.
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
