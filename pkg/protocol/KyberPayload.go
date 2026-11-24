package protocol

// KyberPreKeyID is a typed identifier for Kyber pre-keys at the protocol layer.
// It mirrors the KyberPreKeyId newtype in the Rust reference at
// rust/protocol/src/state/kyber_prekey.rs:18.
//
// The record layer (state/record) defines its own KyberPreKeyID over the same
// underlying uint32 to avoid a circular import. Both represent the same wire value.
type KyberPreKeyID uint32

// KyberPayload bundles the Kyber pre-key ID with its encapsulation ciphertext,
// mirroring the Rust KyberPayload type in protocol/src/protocol.rs.
//
// It is consumed by PreKeySignalMessage construction and passed as an optional
// unit so that callers cannot accidentally supply one field without the other.
type KyberPayload struct {
	preKeyID   KyberPreKeyID
	ciphertext []byte
}

// NewKyberPayload creates a KyberPayload with the given pre-key ID and
// encapsulation ciphertext. The ciphertext slice is copied defensively so
// the caller may reuse or free the original buffer.
func NewKyberPayload(id KyberPreKeyID, ciphertext []byte) *KyberPayload {
	ct := make([]byte, len(ciphertext))
	copy(ct, ciphertext)
	return &KyberPayload{
		preKeyID:   id,
		ciphertext: ct,
	}
}

// PreKeyID returns the Kyber pre-key identifier.
func (k *KyberPayload) PreKeyID() KyberPreKeyID {
	return k.preKeyID
}

// Ciphertext returns a copy of the encapsulation ciphertext bytes.
// A copy is returned so the caller cannot mutate internal state.
func (k *KyberPayload) Ciphertext() []byte {
	ct := make([]byte, len(k.ciphertext))
	copy(ct, k.ciphertext)
	return ct
}
