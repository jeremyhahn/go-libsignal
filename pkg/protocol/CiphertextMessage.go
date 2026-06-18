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

// Message type constants.
//
// WHISPER_TYPE, PREKEY_TYPE, SENDERKEY_TYPE, and PLAINTEXT_TYPE are wire
// values matching Rust's CiphertextMessageType enum at
// rust/protocol/src/protocol.rs:33-40.
//
// SENDERKEY_DISTRIBUTION_TYPE is a Go-internal tag only. It is NOT present
// in the Rust CiphertextMessageType enum and is NEVER sent on the wire.
// SenderKeyDistributionMessage has no CiphertextMessageType in Rust; this
// constant exists solely as a local dispatch tag for callers that need to
// distinguish distribution messages from encrypted messages in a common
// interface. Do not use this value in wire-format code.
const (
	WHISPER_TYPE                = 2 // SignalMessage (Rust: Whisper = 2)
	PREKEY_TYPE                 = 3 // PreKeySignalMessage (Rust: PreKey = 3)
	SENDERKEY_TYPE              = 7 // SenderKeyMessage (Rust: SenderKey = 7)
	PLAINTEXT_TYPE              = 8 // PlaintextContent (Rust: Plaintext = 8)
	SENDERKEY_DISTRIBUTION_TYPE = 5 // Go-internal only; not a Rust wire type
)
