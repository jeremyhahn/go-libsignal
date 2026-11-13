//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 14 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but the Double Ratchet specification (section 5.2, DH ratchet) requires
// it, so the fips140only build tag drops this file from the FIPS gate. `make
// test` and `make coverage` still run it.

package ratchet

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/kem"
	"github.com/jeremyhahn/go-libsignal/pkg/keys/identity"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

func genKP(t *testing.T) *ecc.ECKeyPair {
	t.Helper()
	kp, err := ecc.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	return kp
}

func genGuardedKyberKP(t *testing.T) *kem.GuardedKeyPair {
	t.Helper()
	guardedKEM := kem.NewGuardedKyber1024()
	kp, err := guardedKEM.Generate()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { kp.Destroy() })
	return kp
}

func genIDKeyPair(t *testing.T) *identity.KeyPair {
	t.Helper()
	kp := genKP(t)
	return identity.NewKeyPair(identity.NewKey(kp.PublicKey()), kp.PrivateKey())
}

// TestGenDiscontinuity verifies that genDiscontinuity returns a 32-byte array of 0xFF.
func TestGenDiscontinuity(t *testing.T) {
	d := genDiscontinuity()
	for i, b := range d {
		if b != 0xFF {
			t.Fatalf("expected 0xFF at index %d, got 0x%02X", i, b)
		}
	}
}

// TestCalculateSenderSession_RequiresKyber verifies that CalculateSenderSession
// returns ErrMissingKyberPreKey when no Kyber pre-key is provided (S-C3).
func TestCalculateSenderSession_RequiresKyber(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourBaseKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirSignedPreKey := genKP(t)
	theirRatchetKey := genKP(t)

	params := NewSenderParameters(
		ourIdentity,
		ourBaseKey,
		theirIdentity.PublicKey(),
		theirSignedPreKey.PublicKey(),
		theirRatchetKey.PublicKey(),
		nil,
	)

	_, _, err := CalculateSenderSession(params)
	if err == nil {
		t.Fatal("expected ErrMissingKyberPreKey")
	}
	if err != ErrMissingKyberPreKey {
		t.Fatalf("expected ErrMissingKyberPreKey, got: %v", err)
	}
}

// TestCalculateSenderSession verifies the PQXDH sender session calculation.
func TestCalculateSenderSession(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourBaseKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirSignedPreKey := genKP(t)
	theirRatchetKey := genKP(t)
	kyberKP := genGuardedKyberKP(t)

	params := NewSenderParameters(
		ourIdentity,
		ourBaseKey,
		theirIdentity.PublicKey(),
		theirSignedPreKey.PublicKey(),
		theirRatchetKey.PublicKey(),
		nil,
	)
	params.SetTheirKyberPreKey(kyberKP.Public)

	sessionKeys, kyberCt, err := CalculateSenderSession(params)
	if err != nil {
		t.Fatal(err)
	}
	if sessionKeys == nil {
		t.Fatal("session keys should not be nil")
	}
	if sessionKeys.RootKey == nil {
		t.Fatal("root key should not be nil")
	}
	if sessionKeys.ChainKey == nil {
		t.Fatal("chain key should not be nil")
	}
	if kyberCt == nil {
		t.Fatal("kyber ciphertext should not be nil for PQXDH session")
	}
}

// TestCalculateSenderSessionWithOneTimePreKey verifies with one-time prekey and Kyber.
func TestCalculateSenderSessionWithOneTimePreKey(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourBaseKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirSignedPreKey := genKP(t)
	theirRatchetKey := genKP(t)
	theirOneTimePreKey := genKP(t)
	kyberKP := genGuardedKyberKP(t)

	params := NewSenderParameters(
		ourIdentity,
		ourBaseKey,
		theirIdentity.PublicKey(),
		theirSignedPreKey.PublicKey(),
		theirRatchetKey.PublicKey(),
		theirOneTimePreKey.PublicKey(),
	)
	params.SetTheirKyberPreKey(kyberKP.Public)

	sessionKeys, _, err := CalculateSenderSession(params)
	if err != nil {
		t.Fatal(err)
	}
	if sessionKeys == nil {
		t.Fatal("session keys should not be nil")
	}
}

// TestCalculateReceiverSession_RequiresKyber verifies that CalculateReceiverSession
// returns ErrMissingKyberPreKey when no Kyber pre-key is provided (S-C3).
func TestCalculateReceiverSession_RequiresKyber(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourSignedPreKey := genKP(t)
	ourRatchetKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirBaseKey := genKP(t)

	params := NewReceiverParameters(
		ourIdentity,
		ourSignedPreKey,
		nil,
		ourRatchetKey,
		theirBaseKey.PublicKey(),
		theirIdentity.PublicKey(),
	)

	_, err := CalculateReceiverSession(params)
	if err == nil {
		t.Fatal("expected ErrMissingKyberPreKey")
	}
	if err != ErrMissingKyberPreKey {
		t.Fatalf("expected ErrMissingKyberPreKey, got: %v", err)
	}
}

// TestCalculateReceiverSession verifies the PQXDH receiver session calculation.
func TestCalculateReceiverSession(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourSignedPreKey := genKP(t)
	ourRatchetKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirBaseKey := genKP(t)

	// Generate Kyber keypair and encapsulate to get ciphertext
	kyberKP := genGuardedKyberKP(t)
	kemImpl := kem.NewKyber1024KEM()
	_, ct, err := kemImpl.Encapsulate(kyberKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	params := NewReceiverParameters(
		ourIdentity,
		ourSignedPreKey,
		nil,
		ourRatchetKey,
		theirBaseKey.PublicKey(),
		theirIdentity.PublicKey(),
	)
	params.SetOurKyberPreKeyPair(kyberKP)
	params.SetTheirKyberCiphertext(ct)

	sessionKeys, err := CalculateReceiverSession(params)
	if err != nil {
		t.Fatal(err)
	}
	if sessionKeys == nil {
		t.Fatal("session keys should not be nil")
	}
	if sessionKeys.RootKey == nil {
		t.Fatal("root key should not be nil")
	}
	if sessionKeys.ChainKey == nil {
		t.Fatal("chain key should not be nil")
	}
}

// TestCalculateReceiverSessionWithOneTimePreKey tests with one-time prekey and Kyber.
func TestCalculateReceiverSessionWithOneTimePreKey(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourSignedPreKey := genKP(t)
	ourOneTimePreKey := genKP(t)
	ourRatchetKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirBaseKey := genKP(t)

	// Generate Kyber keypair and encapsulate to get ciphertext
	kyberKP := genGuardedKyberKP(t)
	kemImpl := kem.NewKyber1024KEM()
	_, ct, err := kemImpl.Encapsulate(kyberKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	params := NewReceiverParameters(
		ourIdentity,
		ourSignedPreKey,
		ourOneTimePreKey,
		ourRatchetKey,
		theirBaseKey.PublicKey(),
		theirIdentity.PublicKey(),
	)
	params.SetOurKyberPreKeyPair(kyberKP)
	params.SetTheirKyberCiphertext(ct)

	sessionKeys, err := CalculateReceiverSession(params)
	if err != nil {
		t.Fatal(err)
	}
	if sessionKeys == nil {
		t.Fatal("session keys should not be nil")
	}
}

// TestCalculateSenderSessionWithKyber verifies the PQXDH sender path.
func TestCalculateSenderSessionWithKyber(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourBaseKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirSignedPreKey := genKP(t)
	theirRatchetKey := genKP(t)

	// Generate Kyber key pair for the receiver.
	kemImpl := kem.NewKyber1024KEM()
	kyberKP, err := kemImpl.Generate()
	if err != nil {
		t.Fatal(err)
	}

	params := NewSenderParameters(
		ourIdentity,
		ourBaseKey,
		theirIdentity.PublicKey(),
		theirSignedPreKey.PublicKey(),
		theirRatchetKey.PublicKey(),
		nil,
	)
	params.SetTheirKyberPreKey(kyberKP.Public)

	sessionKeys, kyberCt, err := CalculateSenderSession(params)
	if err != nil {
		t.Fatal(err)
	}
	if sessionKeys == nil {
		t.Fatal("session keys should not be nil")
	}
	if kyberCt == nil {
		t.Fatal("kyber ciphertext should not be nil with Kyber pre-key")
	}
}

// TestCalculateReceiverSessionWithKyber verifies the PQXDH receiver path.
func TestCalculateReceiverSessionWithKyber(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourSignedPreKey := genKP(t)
	ourRatchetKey := genKP(t)
	theirIdentity := genIDKeyPair(t)
	theirBaseKey := genKP(t)

	// Generate guarded Kyber key pair.
	kyberKP := genGuardedKyberKP(t)

	// Encapsulate to get ciphertext using the unguarded KEM (sender side).
	kemImpl := kem.NewKyber1024KEM()
	_, ct, err := kemImpl.Encapsulate(kyberKP.Public)
	if err != nil {
		t.Fatal(err)
	}

	params := NewReceiverParameters(
		ourIdentity,
		ourSignedPreKey,
		nil,
		ourRatchetKey,
		theirBaseKey.PublicKey(),
		theirIdentity.PublicKey(),
	)
	params.SetOurKyberPreKeyPair(kyberKP)
	params.SetTheirKyberCiphertext(ct)

	sessionKeys, err := CalculateReceiverSession(params)
	if err != nil {
		t.Fatal(err)
	}
	if sessionKeys == nil {
		t.Fatal("session keys should not be nil")
	}
}

// TestPQXDHSenderReceiverAgreement verifies that PQXDH sender and receiver
// derive the same session keys.
func TestPQXDHSenderReceiverAgreement(t *testing.T) {
	aliceIdentity := genIDKeyPair(t)
	aliceBaseKey := genKP(t)

	bobIdentity := genIDKeyPair(t)
	bobSignedPreKey := genKP(t)

	// Generate guarded Kyber key pair for Bob.
	kyberKP := genGuardedKyberKP(t)

	// Alice is sender with Kyber.
	senderParams := NewSenderParameters(
		aliceIdentity,
		aliceBaseKey,
		bobIdentity.PublicKey(),
		bobSignedPreKey.PublicKey(),
		bobSignedPreKey.PublicKey(),
		nil,
	)
	senderParams.SetTheirKyberPreKey(kyberKP.Public)

	senderKeys, kyberCt, err := CalculateSenderSession(senderParams)
	if err != nil {
		t.Fatal(err)
	}
	if kyberCt == nil {
		t.Fatal("kyber ciphertext should not be nil")
	}

	// Bob is receiver with Kyber.
	receiverParams := NewReceiverParameters(
		bobIdentity,
		bobSignedPreKey,
		nil,
		bobSignedPreKey,
		aliceBaseKey.PublicKey(),
		aliceIdentity.PublicKey(),
	)
	receiverParams.SetOurKyberPreKeyPair(kyberKP)
	receiverParams.SetTheirKyberCiphertext(kyberCt)

	receiverKeys, err := CalculateReceiverSession(receiverParams)
	if err != nil {
		t.Fatal(err)
	}

	// Both should produce the same root key.
	senderRootBytes := senderKeys.RootKey.Bytes()
	receiverRootBytes := receiverKeys.RootKey.Bytes()
	if len(senderRootBytes) != len(receiverRootBytes) {
		t.Fatal("PQXDH root key lengths should match")
	}
	for i := range senderRootBytes {
		if senderRootBytes[i] != receiverRootBytes[i] {
			t.Fatal("PQXDH root keys should match between sender and receiver")
		}
	}
}

// TestPQXDHReceiverSessionWithOPKAndKyber verifies that the receiver path
// handles all 6 components (discontinuity + DH1 + DH2 + DH3 + DH4 + KEM SS)
// without reallocation, exercising the fixed 32*6 capacity.
func TestPQXDHReceiverSessionWithOPKAndKyber(t *testing.T) {
	aliceIdentity := genIDKeyPair(t)
	aliceBaseKey := genKP(t)

	bobIdentity := genIDKeyPair(t)
	bobSignedPreKey := genKP(t)
	bobOneTimePreKey := genKP(t)

	kyberKP := genGuardedKyberKP(t)

	// Alice (sender) with OPK and Kyber.
	senderParams := NewSenderParameters(
		aliceIdentity,
		aliceBaseKey,
		bobIdentity.PublicKey(),
		bobSignedPreKey.PublicKey(),
		bobSignedPreKey.PublicKey(),
		bobOneTimePreKey.PublicKey(),
	)
	senderParams.SetTheirKyberPreKey(kyberKP.Public)

	senderKeys, kyberCt, err := CalculateSenderSession(senderParams)
	if err != nil {
		t.Fatal(err)
	}
	if kyberCt == nil {
		t.Fatal("kyber ciphertext should not be nil")
	}

	// Bob (receiver) with OPK and Kyber.
	receiverParams := NewReceiverParameters(
		bobIdentity,
		bobSignedPreKey,
		bobOneTimePreKey,
		bobSignedPreKey,
		aliceBaseKey.PublicKey(),
		aliceIdentity.PublicKey(),
	)
	receiverParams.SetOurKyberPreKeyPair(kyberKP)
	receiverParams.SetTheirKyberCiphertext(kyberCt)

	receiverKeys, err := CalculateReceiverSession(receiverParams)
	if err != nil {
		t.Fatal(err)
	}

	// Both must derive the same root key.
	senderRoot := senderKeys.RootKey.Bytes()
	receiverRoot := receiverKeys.RootKey.Bytes()
	if len(senderRoot) != len(receiverRoot) {
		t.Fatal("root key lengths should match")
	}
	for i := range senderRoot {
		if senderRoot[i] != receiverRoot[i] {
			t.Fatal("PQXDH+OPK root keys should match between sender and receiver")
		}
	}

	// Both must derive the same chain key.
	senderChain := senderKeys.ChainKey.Key()
	receiverChain := receiverKeys.ChainKey.Key()
	if len(senderChain) != len(receiverChain) {
		t.Fatal("chain key lengths should match")
	}
	for i := range senderChain {
		if senderChain[i] != receiverChain[i] {
			t.Fatal("PQXDH+OPK chain keys should match between sender and receiver")
		}
	}
}

// TestPQXDHReceiverSessionWithoutOPK verifies the PQXDH receiver path
// without a one-time prekey (5 components: F + DH1 + DH2 + DH3 + SS).
func TestPQXDHReceiverSessionWithoutOPK(t *testing.T) {
	aliceIdentity := genIDKeyPair(t)
	aliceBaseKey := genKP(t)

	bobIdentity := genIDKeyPair(t)
	bobSignedPreKey := genKP(t)

	kyberKP := genGuardedKyberKP(t)

	// Sender (no OPK, with Kyber).
	senderParams := NewSenderParameters(
		aliceIdentity,
		aliceBaseKey,
		bobIdentity.PublicKey(),
		bobSignedPreKey.PublicKey(),
		bobSignedPreKey.PublicKey(),
		nil,
	)
	senderParams.SetTheirKyberPreKey(kyberKP.Public)

	senderKeys, kyberCt, err := CalculateSenderSession(senderParams)
	if err != nil {
		t.Fatal(err)
	}
	if kyberCt == nil {
		t.Fatal("expected kyber ciphertext")
	}

	// Receiver (no OPK, with Kyber).
	receiverParams := NewReceiverParameters(
		bobIdentity,
		bobSignedPreKey,
		nil,
		bobSignedPreKey,
		aliceBaseKey.PublicKey(),
		aliceIdentity.PublicKey(),
	)
	receiverParams.SetOurKyberPreKeyPair(kyberKP)
	receiverParams.SetTheirKyberCiphertext(kyberCt)

	receiverKeys, err := CalculateReceiverSession(receiverParams)
	if err != nil {
		t.Fatal(err)
	}

	senderRoot := senderKeys.RootKey.Bytes()
	receiverRoot := receiverKeys.RootKey.Bytes()
	for i := range senderRoot {
		if senderRoot[i] != receiverRoot[i] {
			t.Fatal("PQXDH (no OPK) root keys should match")
		}
	}
}

// TestB64 verifies that the b64 alias works as expected.
func TestB64(t *testing.T) {
	data := []byte("hello")
	result := b64(data)
	if result != "aGVsbG8=" {
		t.Fatalf("unexpected b64 result: %s", result)
	}
}

// TestCalculateReceiverSession_NonCanonicalBaseKey verifies that the receiver
// session rejects a non-canonical base key (PQ-C3). This matches the Rust
// check in initialize_bob_session: if !parameters.their_base_key().is_canonical()
func TestCalculateReceiverSession_NonCanonicalBaseKey(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourSignedPreKey := genKP(t)
	ourRatchetKey := genKP(t)
	theirIdentity := genIDKeyPair(t)

	// Create a non-canonical public key with the high bit set (>= 2^255).
	var nonCanonicalBytes [32]byte
	nonCanonicalBytes[0] = 0x42
	nonCanonicalBytes[31] = 0x80 // High bit set - makes it >= 2^255.
	nonCanonicalPub := ecc.NewDjbECPublicKey(nonCanonicalBytes)

	params := NewReceiverParameters(
		ourIdentity,
		ourSignedPreKey,
		nil,
		ourRatchetKey,
		nonCanonicalPub,
		theirIdentity.PublicKey(),
	)

	_, err := CalculateReceiverSession(params)
	if err == nil {
		t.Fatal("expected error for non-canonical base key")
	}
	if err != ErrNonCanonicalBaseKey {
		t.Fatalf("expected ErrNonCanonicalBaseKey, got: %v", err)
	}
}

// TestCalculateReceiverSession_SmallOrderBaseKey verifies that a small-order
// (torsion) base key is rejected as non-canonical.
func TestCalculateReceiverSession_SmallOrderBaseKey(t *testing.T) {
	ourIdentity := genIDKeyPair(t)
	ourSignedPreKey := genKP(t)
	ourRatchetKey := genKP(t)
	theirIdentity := genIDKeyPair(t)

	// u=0 is the identity point (order 1, a torsion point).
	zeroPoint := ecc.NewDjbECPublicKey([32]byte{})

	params := NewReceiverParameters(
		ourIdentity,
		ourSignedPreKey,
		nil,
		ourRatchetKey,
		zeroPoint,
		theirIdentity.PublicKey(),
	)

	_, err := CalculateReceiverSession(params)
	if err == nil {
		t.Fatal("expected error for small-order base key")
	}
	if err != ErrNonCanonicalBaseKey {
		t.Fatalf("expected ErrNonCanonicalBaseKey, got: %v", err)
	}
}

// TestPQXDH_InitialPQRKey verifies that PQXDH sessions produce an InitialPQRKey
// as the third derived key from the 96-byte HKDF output.
func TestPQXDH_InitialPQRKey(t *testing.T) {
	aliceIdentity := genIDKeyPair(t)
	aliceBaseKey := genKP(t)

	bobIdentity := genIDKeyPair(t)
	bobSignedPreKey := genKP(t)

	kyberKP := genGuardedKyberKP(t)

	// Alice (sender) with Kyber.
	senderParams := NewSenderParameters(
		aliceIdentity,
		aliceBaseKey,
		bobIdentity.PublicKey(),
		bobSignedPreKey.PublicKey(),
		bobSignedPreKey.PublicKey(),
		nil,
	)
	senderParams.SetTheirKyberPreKey(kyberKP.Public)

	senderKeys, kyberCt, err := CalculateSenderSession(senderParams)
	if err != nil {
		t.Fatal(err)
	}
	if kyberCt == nil {
		t.Fatal("expected non-nil kyber ciphertext")
	}
	if senderKeys.InitialPQRKey == nil {
		t.Fatal("PQXDH sender should produce a non-nil InitialPQRKey")
	}
	if senderKeys.InitialPQRKey.Size() != 32 {
		t.Fatalf("InitialPQRKey should be 32 bytes, got %d", senderKeys.InitialPQRKey.Size())
	}

	// Bob (receiver) with Kyber.
	receiverParams := NewReceiverParameters(
		bobIdentity,
		bobSignedPreKey,
		nil,
		bobSignedPreKey,
		aliceBaseKey.PublicKey(),
		aliceIdentity.PublicKey(),
	)
	receiverParams.SetOurKyberPreKeyPair(kyberKP)
	receiverParams.SetTheirKyberCiphertext(kyberCt)

	receiverKeys, err := CalculateReceiverSession(receiverParams)
	if err != nil {
		t.Fatal(err)
	}
	if receiverKeys.InitialPQRKey == nil {
		t.Fatal("PQXDH receiver should produce a non-nil InitialPQRKey")
	}
	if receiverKeys.InitialPQRKey.Size() != 32 {
		t.Fatalf("InitialPQRKey should be 32 bytes, got %d", receiverKeys.InitialPQRKey.Size())
	}

	// Both sides must derive the same InitialPQRKey.
	if !secrettest.Same(t, senderKeys.InitialPQRKey, receiverKeys.InitialPQRKey) {
		t.Fatal("PQXDH sender and receiver must derive the same InitialPQRKey")
	}
	senderKeys.Zeroize()
	receiverKeys.Zeroize()
}
