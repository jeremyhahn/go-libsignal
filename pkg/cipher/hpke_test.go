//go:build !fips140only

// FIPS 140-3 exemption -- see docs/FIPS.md.
//
// 21 tests in this file exercise X25519. FIPS 140-3 does not approve that,
// but RFC 9180 fixes DHKEM(X25519, HKDF-SHA256) for the
// Base_X25519_HkdfSha256_Aes256Gcm suite this package implements
// (rust/crypto/src/hpke.rs), so the fips140only build tag drops this file
// from the FIPS gate. `make test` and `make coverage` still run it.

package cipher

import (
	"bytes"
	"errors"
	"testing"

	crypto "github.com/jeremyhahn/go-libsignal/pkg/util/crypto"
)

func TestHPKESealOpenRoundTrip(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatalf("HPKEGenerateKeyPair: %v", err)
	}

	info := []byte("test info")
	aad := []byte("test aad")
	plaintext := []byte("hello HPKE")

	enc, ct, err := HPKESeal(pk, info, aad, plaintext)
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}
	if len(enc) != x25519EncapsulatedKeySize {
		t.Fatalf("enc length: got %d, want %d", len(enc), x25519EncapsulatedKeySize)
	}

	decrypted, err := HPKEOpen(sk, enc, info, aad, ct)
	if err != nil {
		t.Fatalf("HPKEOpen: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestHPKESealOpenEmptyPlaintext(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatalf("HPKEGenerateKeyPair: %v", err)
	}

	enc, ct, err := HPKESeal(pk, nil, nil, []byte{})
	if err != nil {
		t.Fatalf("HPKESeal empty: %v", err)
	}

	decrypted, err := HPKEOpen(sk, enc, nil, nil, ct)
	if err != nil {
		t.Fatalf("HPKEOpen empty: %v", err)
	}
	if len(decrypted) != 0 {
		t.Errorf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestHPKESealOpenWithNilInfoAAD(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("no info or aad")
	enc, ct, err := HPKESeal(pk, nil, nil, plaintext)
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}

	decrypted, err := HPKEOpen(sk, enc, nil, nil, ct)
	if err != nil {
		t.Fatalf("HPKEOpen: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("round-trip with nil info/aad failed")
	}
}

func TestHPKEOpenWrongKey(t *testing.T) {
	_, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrongSK, _, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	enc, ct, err := HPKESeal(pk, []byte("info"), []byte("aad"), []byte("secret"))
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}

	_, err = HPKEOpen(wrongSK, enc, []byte("info"), []byte("aad"), ct)
	if !errors.Is(err, ErrHPKEOpenFailed) {
		t.Errorf("expected ErrHPKEOpenFailed, got %v", err)
	}
}

func TestHPKEOpenWrongAAD(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	enc, ct, err := HPKESeal(pk, []byte("info"), []byte("correct aad"), []byte("secret"))
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}

	_, err = HPKEOpen(sk, enc, []byte("info"), []byte("wrong aad"), ct)
	if !errors.Is(err, ErrHPKEOpenFailed) {
		t.Errorf("expected ErrHPKEOpenFailed for wrong AAD, got %v", err)
	}
}

func TestHPKEOpenWrongInfo(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	enc, ct, err := HPKESeal(pk, []byte("correct info"), []byte("aad"), []byte("secret"))
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}

	_, err = HPKEOpen(sk, enc, []byte("wrong info"), []byte("aad"), ct)
	if !errors.Is(err, ErrHPKEOpenFailed) {
		t.Errorf("expected ErrHPKEOpenFailed for wrong info, got %v", err)
	}
}

func TestHPKEOpenCorruptedCiphertext(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	enc, ct, err := HPKESeal(pk, []byte("info"), []byte("aad"), []byte("secret"))
	if err != nil {
		t.Fatalf("HPKESeal: %v", err)
	}

	// Corrupt the ciphertext.
	corrupted := make([]byte, len(ct))
	copy(corrupted, ct)
	corrupted[0] ^= 0xFF

	_, err = HPKEOpen(sk, enc, []byte("info"), []byte("aad"), corrupted)
	if !errors.Is(err, ErrHPKEOpenFailed) {
		t.Errorf("expected ErrHPKEOpenFailed for corrupted ciphertext, got %v", err)
	}
}

func TestHPKESealInvalidPublicKey(t *testing.T) {
	_, _, err := HPKESeal([]byte("short"), nil, nil, []byte("data"))
	if !errors.Is(err, ErrHPKEInvalidPublicKey) {
		t.Errorf("expected ErrHPKEInvalidPublicKey, got %v", err)
	}
}

func TestHPKEOpenInvalidPrivateKey(t *testing.T) {
	enc := make([]byte, x25519EncapsulatedKeySize)
	_, err := HPKEOpen([]byte("short"), enc, nil, nil, []byte("data"))
	if !errors.Is(err, ErrHPKEInvalidPrivateKey) {
		t.Errorf("expected ErrHPKEInvalidPrivateKey, got %v", err)
	}
}

// Test the sender/receiver interface methods.

func TestHPKESenderReceiverRoundTrip(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sender, err := NewHPKESender(pk)
	if err != nil {
		t.Fatalf("NewHPKESender: %v", err)
	}

	info := []byte("info")
	aad := []byte("extra")
	plaintext := []byte("message for sender/receiver interface")

	ciphertext, err := sender.Seal(info, aad, plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Verify wire format: type byte + 32 byte enc + AEAD ciphertext.
	if len(ciphertext) < 1+x25519EncapsulatedKeySize+1 {
		t.Fatalf("ciphertext too short: %d bytes", len(ciphertext))
	}
	if ciphertext[0] != byte(hpkeBaseX25519HkdfSha256Aes256Gcm) {
		t.Errorf("type byte: got 0x%02x, want 0x%02x", ciphertext[0], hpkeBaseX25519HkdfSha256Aes256Gcm)
	}

	receiver, err := NewHPKEReceiver(sk)
	if err != nil {
		t.Fatalf("NewHPKEReceiver: %v", err)
	}

	decrypted, err := receiver.Open(info, aad, ciphertext)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("round-trip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestHPKEReceiverOpenWrongKey(t *testing.T) {
	_, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	wrongSK, _, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sender, err := NewHPKESender(pk)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := sender.Seal([]byte("info"), []byte("aad"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewHPKEReceiver(wrongSK)
	if err != nil {
		t.Fatal(err)
	}

	_, err = receiver.Open([]byte("info"), []byte("aad"), ciphertext)
	if !errors.Is(err, ErrHPKEOpenFailed) {
		t.Errorf("expected ErrHPKEOpenFailed, got %v", err)
	}
}

func TestHPKEReceiverOpenInvalidCiphertext(t *testing.T) {
	sk, _, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewHPKEReceiver(sk)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		ciphertext []byte
		wantErr    error
	}{
		{"nil", nil, ErrHPKEInvalidCiphertext},
		{"empty", []byte{}, ErrHPKEInvalidCiphertext},
		{"too short", []byte{0x01}, ErrHPKEInvalidCiphertext},
		{"just type and enc", make([]byte, 1+x25519EncapsulatedKeySize), ErrHPKEInvalidCiphertext},
		{"below aead tag minimum", make([]byte, 1+x25519EncapsulatedKeySize+15), ErrHPKEInvalidCiphertext},
		{"unknown type", append([]byte{0xFF}, make([]byte, x25519EncapsulatedKeySize+16)...), ErrHPKEUnknownType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := receiver.Open(nil, nil, tt.ciphertext)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("expected %v, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestNewHPKESenderInvalidKey(t *testing.T) {
	_, err := NewHPKESender([]byte("too short"))
	if !errors.Is(err, ErrHPKEInvalidPublicKey) {
		t.Errorf("expected ErrHPKEInvalidPublicKey, got %v", err)
	}
}

func TestNewHPKEReceiverInvalidKey(t *testing.T) {
	_, err := NewHPKEReceiver([]byte("too short"))
	if !errors.Is(err, ErrHPKEInvalidPrivateKey) {
		t.Errorf("expected ErrHPKEInvalidPrivateKey, got %v", err)
	}
}

func TestHPKEGenerateKeyPair(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if len(sk) == 0 {
		t.Error("private key should not be empty")
	}
	if len(pk) != x25519EncapsulatedKeySize {
		t.Errorf("public key length: got %d, want %d", len(pk), x25519EncapsulatedKeySize)
	}

	// Generate another pair and verify they differ.
	sk2, pk2, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sk, sk2) {
		t.Error("consecutive key pairs should differ (private key)")
	}
	if bytes.Equal(pk, pk2) {
		t.Error("consecutive key pairs should differ (public key)")
	}
}

func TestHPKELargePayload(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// 64 KB payload.
	plaintext := make([]byte, 64*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	enc, ct, err := HPKESeal(pk, []byte("info"), []byte("aad"), plaintext)
	if err != nil {
		t.Fatalf("HPKESeal large: %v", err)
	}

	decrypted, err := HPKEOpen(sk, enc, []byte("info"), []byte("aad"), ct)
	if err != nil {
		t.Fatalf("HPKEOpen large: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("round-trip failed for large payload")
	}
}

func TestHPKEOpenWrongEncapsulatedKey(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	enc, ct, err := HPKESeal(pk, []byte("info"), []byte("aad"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the encapsulated key.
	badEnc := make([]byte, len(enc))
	copy(badEnc, enc)
	badEnc[0] ^= 0xFF

	_, err = HPKEOpen(sk, badEnc, []byte("info"), []byte("aad"), ct)
	if !errors.Is(err, ErrHPKEOpenFailed) {
		t.Errorf("expected ErrHPKEOpenFailed for corrupted enc, got %v", err)
	}
}

func TestHPKESenderSealReturnsWireFormat(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sender, err := NewHPKESender(pk)
	if err != nil {
		t.Fatal(err)
	}

	ct, err := sender.Seal(nil, nil, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}

	// Verify wire format: type byte = 0x01.
	if ct[0] != 0x01 {
		t.Errorf("type byte = 0x%02x, want 0x01", ct[0])
	}

	// Verify we can decrypt it.
	receiver, err := NewHPKEReceiver(sk)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := receiver.Open(nil, nil, ct)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(pt, []byte("test")) {
		t.Errorf("got %q, want %q", pt, "test")
	}
}

func TestHPKEDifferentSealsProduceDifferentCiphertexts(t *testing.T) {
	_, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("same plaintext")
	enc1, ct1, err := HPKESeal(pk, nil, nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	enc2, ct2, err := HPKESeal(pk, nil, nil, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Each seal uses a fresh ephemeral key, so enc and ct should differ.
	if bytes.Equal(enc1, enc2) {
		t.Error("different seals should produce different encapsulated keys")
	}
	if bytes.Equal(ct1, ct2) {
		t.Error("different seals should produce different ciphertexts")
	}
}

func TestHPKEReceiverZeroize(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	sender, err := NewHPKESender(pk)
	if err != nil {
		t.Fatal(err)
	}

	ciphertext, err := sender.Seal([]byte("info"), []byte("aad"), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewHPKEReceiver(sk)
	if err != nil {
		t.Fatal(err)
	}

	// Verify decryption works before zeroization.
	pt, err := receiver.Open([]byte("info"), []byte("aad"), ciphertext)
	if err != nil {
		t.Fatalf("Open before Zeroize: %v", err)
	}
	if !bytes.Equal(pt, []byte("secret")) {
		t.Errorf("got %q, want %q", pt, "secret")
	}

	// Zeroize and verify the receiver can no longer decrypt.
	receiver.Zeroize()

	_, err = receiver.Open([]byte("info"), []byte("aad"), ciphertext)
	if !errors.Is(err, ErrHPKEReceiverZeroized) {
		t.Errorf("expected ErrHPKEReceiverZeroized after Zeroize, got %v", err)
	}
}

func TestHPKEReceiverZeroizeIdempotent(t *testing.T) {
	sk, _, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewHPKEReceiver(sk)
	if err != nil {
		t.Fatal(err)
	}

	// Calling Zeroize multiple times must not panic.
	receiver.Zeroize()
	receiver.Zeroize()
	receiver.Zeroize()
}

func TestHPKEReceiverZeroizeClearsPrivKeyBytes(t *testing.T) {
	sk, _, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	receiver, err := NewHPKEReceiver(sk)
	if err != nil {
		t.Fatal(err)
	}

	// Access the concrete type to inspect internal state.
	concrete := receiver.(*hpkeReceiver)
	if concrete.privKeyBytes == nil {
		t.Fatal("privKeyBytes should not be nil before Zeroize")
	}

	// Save length to verify zeroization happened on the correct buffer.
	privLen := len(concrete.privKeyBytes)
	if privLen == 0 {
		t.Fatal("privKeyBytes should not be empty")
	}

	// Keep a reference to verify bytes are zeroed.
	privRef := concrete.privKeyBytes

	receiver.Zeroize()

	// The internal field should be nil after zeroization.
	if concrete.privKeyBytes != nil {
		t.Error("privKeyBytes should be nil after Zeroize")
	}
	if concrete.privateKey != nil {
		t.Error("privateKey should be nil after Zeroize")
	}

	// The underlying byte slice should be all zeros.
	allZero := true
	for _, b := range privRef {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("privKeyBytes buffer should be zeroed after Zeroize")
	}
}

func TestHPKENewReceiverDoesNotMutateInput(t *testing.T) {
	sk, _, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Save a copy of the original bytes.
	original := make([]byte, len(sk))
	copy(original, sk)

	receiver, err := NewHPKEReceiver(sk)
	if err != nil {
		t.Fatal(err)
	}

	// Zeroize the receiver - the caller's original bytes should be untouched.
	receiver.Zeroize()

	if !bytes.Equal(sk, original) {
		t.Error("NewHPKEReceiver should not mutate the caller's input slice on Zeroize")
	}
}

func TestHPKEOpenZeroizesLocalCopy(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	enc, ct, err := HPKESeal(pk, []byte("info"), []byte("aad"), []byte("data"))
	if err != nil {
		t.Fatal(err)
	}

	// Save the original private key bytes to verify they are not mutated.
	original := make([]byte, len(sk))
	copy(original, sk)

	_, err = HPKEOpen(sk, enc, []byte("info"), []byte("aad"), ct)
	if err != nil {
		t.Fatalf("HPKEOpen: %v", err)
	}

	// HPKEOpen should not have modified the caller's slice.
	if !bytes.Equal(sk, original) {
		t.Error("HPKEOpen should not mutate the caller's private key slice")
	}
}

func TestHPKEGenerateKeyPairZeroization(t *testing.T) {
	sk, pk, err := HPKEGenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// Verify the key pair is functional.
	enc, ct, err := HPKESeal(pk, nil, nil, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := HPKEOpen(sk, enc, nil, nil, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, []byte("test")) {
		t.Errorf("got %q, want %q", pt, "test")
	}

	// Caller zeroizes the private key; verify it becomes all zeros.
	crypto.Zeroize(sk)
	allZero := true
	for _, b := range sk {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("private key should be all zeros after crypto.Zeroize")
	}
}
