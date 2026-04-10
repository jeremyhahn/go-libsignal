package tests

import (
	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/util/keyhelper"
	"testing"
)

// TestIdentityKeys checks generating, signing, and verifying of identity keys.
func TestIdentityKeys(t *testing.T) {
	// Generate an identity keypair
	identityKeyPair, err := keyhelper.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal("Error generating identity keys:", err)
	}
	privateKey := identityKeyPair.PrivateKey()
	publicKey := identityKeyPair.PublicKey()

	// Sign the text "Hello" with the identity key
	message := []byte("Hello")
	unsignedMessage := []byte("SHIT!")
	signature, err := ecc.CalculateSignature(privateKey, message)
	if err != nil {
		t.Fatal("Error calculating signature:", err)
	}

	// Validate the signature using the private key
	valid := ecc.VerifySignature(publicKey.PublicKey(), message, signature)
	if !valid {
		t.Error("Signature verification failed.")
	}

	// Try checking the signature on text that is different
	valid = ecc.VerifySignature(publicKey.PublicKey(), unsignedMessage, signature)
	if valid {
		t.Error("Signature verification should have failed here.")
	}

}
