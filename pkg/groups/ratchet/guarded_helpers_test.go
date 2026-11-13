package ratchet

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

// mustGuard moves a copy of the given bytes into guarded memory, for building
// the sender-key structures these tests exercise. It returns the zero Secret
// for empty input, matching the convention of the persisted-state structures.
func mustGuard(t *testing.T, data []byte) secret.Secret {
	t.Helper()
	guarded, err := secret.NewValue(append([]byte(nil), data...))
	if err != nil {
		t.Fatalf("secret.NewValue: %v", err)
	}
	return guarded
}

// TestSenderChainKeyStructIsAnIndependentClone pins that the structure holds its
// own guarded copy rather than a view into the live key. Equality assertions
// cannot see the difference — a view compares equal too — so the check is that
// the structure survives the live key being destroyed.
func TestSenderChainKeyStructIsAnIndependentClone(t *testing.T) {
	key := NewSenderChainKey(3, []byte("sender-chain-key-material-32-byt"))

	structure, err := NewStructFromSenderChainKey(key)
	if err != nil {
		t.Fatalf("NewStructFromSenderChainKey: %v", err)
	}
	defer structure.Zeroize()

	key.Zeroize()
	if !secrettest.Matches(t, &structure.ChainKey, []byte("sender-chain-key-material-32-byt")) {
		t.Fatal("structure shares guarded memory with the live chain key")
	}
}

// TestSenderChainKeyFromStructIsAnIndependentClone is the mirror: building a key
// from a structure must not consume or alias the structure's material.
func TestSenderChainKeyFromStructIsAnIndependentClone(t *testing.T) {
	structure := &SenderChainKeyStructure{
		Iteration: 9,
		ChainKey:  mustGuard(t, []byte("another-chain-key-of-32-bytes!!!")),
	}
	defer structure.Zeroize()

	key, err := NewSenderChainKeyFromStruct(structure)
	if err != nil {
		t.Fatalf("NewSenderChainKeyFromStruct: %v", err)
	}
	if key.Iteration() != 9 {
		t.Fatalf("Iteration() = %d, want 9", key.Iteration())
	}

	key.Zeroize()
	if !secrettest.Matches(t, &structure.ChainKey, []byte("another-chain-key-of-32-bytes!!!")) {
		t.Fatal("NewSenderChainKeyFromStruct consumed or aliased the source structure")
	}
}

// TestSenderChainKeyFromStructNoMaterial covers the error path: a sender chain
// key is mandatory, so an absent one must be rejected rather than yielding a key
// that cannot ratchet.
func TestSenderChainKeyFromStructNoMaterial(t *testing.T) {
	for name, structure := range map[string]*SenderChainKeyStructure{
		"nil structure": nil,
		"zero key":      {Iteration: 2},
	} {
		t.Run(name, func(t *testing.T) {
			key, err := NewSenderChainKeyFromStruct(structure)
			if key != nil {
				t.Fatal("expected no key")
			}
			var missing *MissingKeyError
			if !errors.As(err, &missing) {
				t.Fatalf("expected *MissingKeyError, got %#v", err)
			}
		})
	}
}

// TestSenderMessageKeyStructIsAnIndependentClone pins the same property for the
// message key, across all three of its optional fields.
func TestSenderMessageKeyStructIsAnIndependentClone(t *testing.T) {
	key, err := NewSenderMessageKey(4, []byte("seed-material-for-message-key-32"))
	if err != nil {
		t.Fatalf("NewSenderMessageKey: %v", err)
	}
	// Digests, not copies. Retaining the plaintext to compare against would put
	// key material on the ordinary heap for the length of the test — the exact
	// exposure this change closes, committed by the test that polices it. A
	// SHA-256 digest identifies the material without being it. (Needed here and
	// not in the chain-key test above because that one compares against a source
	// literal, which is already in the binary.)
	ivDigest := sha256.Sum256(mustCopy(key.Iv()))
	cipherDigest := sha256.Sum256(mustCopy(key.CipherKey()))
	seedDigest := sha256.Sum256(mustCopy(key.Seed()))

	structure, err := NewStructFromSenderMessageKey(key)
	if err != nil {
		t.Fatalf("NewStructFromSenderMessageKey: %v", err)
	}
	defer structure.Zeroize()

	key.Zeroize()
	if secrettest.Digest(t, &structure.IV) != ivDigest ||
		secrettest.Digest(t, &structure.CipherKey) != cipherDigest ||
		secrettest.Digest(t, &structure.Seed) != seedDigest {
		t.Fatal("structure shares guarded memory with the live message key")
	}
}

// TestSenderMessageKeyOptionalFieldCombinations walks every present/absent
// combination of the three optional fields through both directions. The fields
// are independently optional — a stored key may carry only its seed, with the
// IV and cipher key re-derived later — so the combinations are the behaviour,
// not an exhaustiveness exercise.
func TestSenderMessageKeyOptionalFieldCombinations(t *testing.T) {
	material := map[string][]byte{
		"iv":     []byte("iv-16-bytes-pad!"),
		"cipher": []byte("cipher-key-of-32-bytes-exactly!!"),
		"seed":   []byte("seed-material-of-32-bytes-here!!"),
	}

	for _, combo := range []struct{ iv, cipher, seed bool }{
		{true, true, true},
		{true, false, false},
		{false, true, false},
		{false, false, true},
		{true, true, false},
		{false, false, false},
	} {
		name := fmt.Sprintf("iv=%v/cipher=%v/seed=%v", combo.iv, combo.cipher, combo.seed)
		t.Run(name, func(t *testing.T) {
			structure := &SenderMessageKeyStructure{Iteration: 11}
			if combo.iv {
				structure.IV = mustGuard(t, material["iv"])
			}
			if combo.cipher {
				structure.CipherKey = mustGuard(t, material["cipher"])
			}
			if combo.seed {
				structure.Seed = mustGuard(t, material["seed"])
			}
			defer structure.Zeroize()

			key, err := NewSenderMessageKeyFromStruct(structure)
			if err != nil {
				t.Fatalf("NewSenderMessageKeyFromStruct: %v", err)
			}
			if key.Iteration() != 11 {
				t.Fatalf("Iteration() = %d, want 11", key.Iteration())
			}

			// An absent field stays absent; a present one round-trips.
			checks := []struct {
				label   string
				present bool
				got     []byte
				want    []byte
			}{
				{"IV", combo.iv, absent(key.Iv()), material["iv"]},
				{"CipherKey", combo.cipher, absent(key.CipherKey()), material["cipher"]},
				{"Seed", combo.seed, absent(key.Seed()), material["seed"]},
			}
			for _, c := range checks {
				if c.present && !bytes.Equal(c.got, c.want) {
					t.Errorf("%s did not round-trip", c.label)
				}
				if !c.present && c.got != nil {
					t.Errorf("%s should be absent, got %x", c.label, c.got)
				}
			}

			// And back out again, preserving the same shape.
			back, err := NewStructFromSenderMessageKey(key)
			if err != nil {
				t.Fatalf("NewStructFromSenderMessageKey: %v", err)
			}
			defer back.Zeroize()

			if back.IV.IsZero() == combo.iv {
				t.Errorf("IV presence not preserved: IsZero=%v, present=%v", back.IV.IsZero(), combo.iv)
			}
			if back.CipherKey.IsZero() == combo.cipher {
				t.Errorf("CipherKey presence not preserved")
			}
			if back.Seed.IsZero() == combo.seed {
				t.Errorf("Seed presence not preserved")
			}
		})
	}
}
