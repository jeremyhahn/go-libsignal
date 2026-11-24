package protocol

// KyberPreKeyID identifies a Kyber pre-key at the protocol layer; state/record has its own type for the same wire value.
type KyberPreKeyID uint32

// KyberPayload pairs a Kyber pre-key ID with its ciphertext so neither is supplied alone.
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
