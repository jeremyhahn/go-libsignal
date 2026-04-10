package protocol

// CiphertextMessage is the interface for all encrypted message types.
type CiphertextMessage interface {
	Serialize() ([]byte, error)
	Type() uint32
}

// Protocol version constants.
const (
	UnsupportedVersion       = 1
	PreKyberVersion          = 3 // Backward compatible version without Kyber keys
	CurrentVersion           = 4 // PQXDH-aware current version
	SenderKeyCurrentVersion  = 3 // SenderKey messages use version 3
)

// SenderKeySignatureLength is the length of the Ed25519 signature appended to SenderKey messages.
const SenderKeySignatureLength = 64

// Message type constants.
const (
	WHISPER_TYPE               = 2 // SignalMessage
	PREKEY_TYPE                = 3 // PreKeySignalMessage
	SENDERKEY_TYPE             = 7 // SenderKeyMessage
	PLAINTEXT_TYPE             = 8 // PlaintextContent
	SENDERKEY_DISTRIBUTION_TYPE = 5 // SenderKeyDistributionMessage
)
