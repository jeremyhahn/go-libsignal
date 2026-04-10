package tests

import (
	"encoding/base64"
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kdf"
	"testing"
)

// TestSharedSecret tests the key derivation function's ability to
// calculate a shared secret given two pairs of ECDH keys.
func TestSharedSecret(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString

	// Generate an keypair for Alice
	aliceKeyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Error("Error generating identity keys")
	}
	alicePrivateKey := aliceKeyPair.PrivateKey().Serialize()
	p := aliceKeyPair.PublicKey()
	alicePublicKey := p.PublicKey()

	// Generate an keypair for Bob
	bobKeyPair, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Error("Error generating identity keys")
	}
	bobPrivateKey := bobKeyPair.PrivateKey().Serialize()
	p = bobKeyPair.PublicKey()
	bobPublicKey := p.PublicKey()

	// Calculate the shared secret as Alice.
	aliceSharedSecret, err := kdf.CalculateSharedSecret(bobPublicKey, alicePrivateKey)
	if err != nil {
		t.Fatalf("Alice CalculateSharedSecret failed: %v", err)
	}
	aliceHashedSecret, _ := kdf.DeriveSecrets(aliceSharedSecret[:], nil, []byte("Dust"), 64)

	// Calculate the shared secret as Bob.
	bobSharedSecret, err := kdf.CalculateSharedSecret(alicePublicKey, bobPrivateKey)
	if err != nil {
		t.Fatalf("Bob CalculateSharedSecret failed: %v", err)
	}
	bobHashedSecret, _ := kdf.DeriveSecrets(bobSharedSecret[:], nil, []byte("Dust"), 64)

	// Check to make sure Alice and Bob calculated the same shared secret.
	if b64(aliceSharedSecret[:]) != b64(bobSharedSecret[:]) {
		t.Fatalf("Computed secrets do not match: %s != %s", b64(aliceSharedSecret[:]), b64(bobSharedSecret[:]))
	}

	// Check to make sure that Alice and Bob also hashed the same secret the same way using KDF.
	if b64(aliceHashedSecret) != b64(bobHashedSecret) {
		t.Fatalf("Hashed secrets do not match: %s != %s", b64(aliceHashedSecret), b64(bobHashedSecret))
	}
}
