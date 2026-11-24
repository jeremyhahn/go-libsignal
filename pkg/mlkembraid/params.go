package mlkembraid

const (
	// HeaderSize is the size of a KEM header in bytes: ek_seed(32) || hek(32).
	HeaderSize = 64

	// MacSize is the size of a MAC tag in bytes (HMAC-SHA256 output).
	MacSize = 32

	// DefaultChunkSize is the default chunk size for erasure encoding.
	DefaultChunkSize = 32

	// EKSeedSize is the size of the ek_seed portion of an encapsulation key.
	EKSeedSize = 32

	// ProtocolInfo is the protocol identifier used in KDF and MAC labels.
	// Matches the Rust reference: Signal_PQCKA_V1_MLKEM768.
	ProtocolInfo = "Signal_PQCKA_V1_MLKEM768"
)

// ML-KEM 768 parameters per spec Section 2.2.
const (
	// MLKEM768EKSize is the ek_vector size for ML-KEM 768 (full ek minus ek_seed).
	MLKEM768EKSize = 1152

	// MLKEM768FullEKSize is the full encapsulation key size (ek_seed + ek_vector).
	MLKEM768FullEKSize = EKSeedSize + MLKEM768EKSize // 1184

	// MLKEM768CT1Size is the first ciphertext size for ML-KEM 768.
	MLKEM768CT1Size = 960

	// MLKEM768CT2Size is the second ciphertext (reconciliation) size for ML-KEM 768.
	MLKEM768CT2Size = 128

	// MLKEM768FullCTSize is the full ciphertext size (ct1 + ct2).
	MLKEM768FullCTSize = MLKEM768CT1Size + MLKEM768CT2Size // 1088

	// MLKEM768EncapStateSize is the size in bytes of the libcrux EncapsulationState
	// wire format produced by Encaps1 and consumed by Encaps2 / CompleteEncaps2.
	// Layout (per libcrux-ml-kem EncapsState): r_as_ntt(1536) || error2(512) || randomness(32).
	// Rust SPQR stores this 2080-byte blob in Unchunked.Ct1Sent.es.
	MLKEM768EncapStateSize = 2080
)
