package ratchet

import (
	"errors"
	"testing"
)

// TestSenderChainKey_EmptyKeyRefusesToDerive checks that a sender chain
// key with no key material derives neither a message key nor the next
// chain key: WithBytes borrows it as nil, and HMAC under an empty key
// would give a predictable AES key, IV and chain.
func TestSenderChainKey_EmptyKeyRefusesToDerive(t *testing.T) {
	cases := map[string]*SenderChainKey{
		"nil key":    NewSenderChainKey(0, nil),
		"empty key":  NewSenderChainKey(0, []byte{}),
		"zero value": {},
	}
	for name, k := range cases {
		t.Run(name, func(t *testing.T) {
			var empty *ErrEmptyChainKey
			mk, err := k.SenderMessageKey()
			if !errors.As(err, &empty) || mk != nil {
				t.Fatalf("SenderMessageKey: want ErrEmptyChainKey and nil key, got %v, %v", mk, err)
			}
			next, err := k.Next()
			if !errors.As(err, &empty) || next != nil {
				t.Fatalf("Next: want ErrEmptyChainKey and nil key, got %v, %v", next, err)
			}
		})
	}
}

func TestSenderChainKey_NilReceiverRefusesToDerive(t *testing.T) {
	var k *SenderChainKey
	var empty *ErrEmptyChainKey
	if _, err := k.SenderMessageKey(); !errors.As(err, &empty) {
		t.Fatalf("want ErrEmptyChainKey, got %v", err)
	}
}

func TestSenderChainKey_NonEmptyKeyStillDerives(t *testing.T) {
	k := NewSenderChainKey(0, make([]byte, 32))
	defer k.Zeroize()
	if _, err := k.SenderMessageKey(); err != nil {
		t.Fatalf("SenderMessageKey: %v", err)
	}
	next, err := k.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	next.Zeroize()
}
