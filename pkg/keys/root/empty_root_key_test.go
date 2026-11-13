package root

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
)

// TestCreateChain_EmptyRootKey checks that a root key with no material,
// borrowed as nil, is not used as the HKDF salt for the next chain.
func TestCreateChain_EmptyRootKey(t *testing.T) {
	theirKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	ourKP, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	kp, err := (&Key{}).CreateChain(theirKP.PublicKey(), ourKP)
	if !errors.Is(err, ErrEmptyRootKey) || kp != nil {
		t.Fatalf("want ErrEmptyRootKey, got %v, %v", kp, err)
	}
}
