package protocol

// CiphertextMessage is the interface for all encrypted message types.
type CiphertextMessage interface {
	Serialize() ([]byte, error)
	Type() uint32
}

// Protocol version constants.
const (
	UnsupportedVersion      = 1
	PreKyberVersion         = 3 // Backward compatible version without Kyber keys
	CurrentVersion          = 4 // PQXDH-aware current version
	SenderKeyCurrentVersion = 3 // SenderKey messages use version 3
)

// SenderKeySignatureLength is the length of the Ed25519 signature appended to SenderKey messages.
const SenderKeySignatureLength = 64

// Message types: the first four match Rust CiphertextMessageType; SENDERKEY_DISTRIBUTION_TYPE is a local tag never sent on the wire.
const (
	WHISPER_TYPE                = 2 // SignalMessage (Rust: Whisper = 2)
	PREKEY_TYPE                 = 3 // PreKeySignalMessage (Rust: PreKey = 3)
	SENDERKEY_TYPE              = 7 // SenderKeyMessage (Rust: SenderKey = 7)
	PLAINTEXT_TYPE              = 8 // PlaintextContent (Rust: Plaintext = 8)
	SENDERKEY_DISTRIBUTION_TYPE = 5 // Go-internal only; not a Rust wire type
)
