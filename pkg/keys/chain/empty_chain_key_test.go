package chain

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
)

// TestKey_EmptyKeyRefusesToDerive checks that a chain key with no key
// material derives no message keys: WithBytes borrows it as nil, and HMAC
// under an empty key would give predictable keys.
func TestKey_EmptyKeyRefusesToDerive(t *testing.T) {
	// A nil key is already refused at construction (secret.New rejects it).
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("NewKey(nil): want a panic")
			}
		}()
		NewKey(kdf.DeriveSecrets, nil, 0)
	}()

	cases := map[string]func() *Key{
		"empty key":    func() *Key { return NewKey(kdf.DeriveSecrets, []byte{}, 0) },
		"zero value":   func() *Key { return &Key{} },
		"nil receiver": func() *Key { return nil },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			k := mk()
			if _, err := k.baseMaterial(messageKeySeed); !errors.Is(err, ErrEmptyChainKey) {
				t.Fatalf("baseMaterial: want ErrEmptyChainKey, got %v", err)
			}
			if keys, err := k.MessageKeysWithSalt(nil); !errors.Is(err, ErrEmptyChainKey) || keys != nil {
				t.Fatalf("MessageKeysWithSalt: want ErrEmptyChainKey, got %v, %v", keys, err)
			}
			if keys, err := k.MessageKeysWithSeed(); !errors.Is(err, ErrEmptyChainKey) || keys != nil {
				t.Fatalf("MessageKeysWithSeed: want ErrEmptyChainKey, got %v, %v", keys, err)
			}
			assertPanicsWith(t, "BaseMaterial", ErrEmptyChainKey, func() { k.BaseMaterial(chainKeySeed) })
		})
	}
}

func assertPanicsWith(t *testing.T, name string, want error, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		err, ok := r.(error)
		if !ok || !errors.Is(err, want) {
			t.Fatalf("%s: want panic with %v, got %v", name, want, r)
		}
	}()
	fn()
}
