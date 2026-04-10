package tripleratchet

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/cipher"
	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
	"github.com/jeremyhahn/go-libsignal/pkg/spqr"
	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"
)

// =============================================================================
// KDF Tests
// =============================================================================

func TestKDFHybrid(t *testing.T) {
	ecMK := make([]byte, 32)
	pqMK := make([]byte, 32)
	fillRandom(t, ecMK, pqMK)

	keys, err := KDFHybrid(ecMK, pqMK)
	if err != nil {
		t.Fatalf("KDFHybrid returned error: %v", err)
	}

	if keys.CipherKey.Size() != CipherKeySize {
		t.Errorf("CipherKey length = %d, want %d", keys.CipherKey.Size(), CipherKeySize)
	}
	if keys.MacKey.Size() != MacKeySize {
		t.Errorf("MacKey length = %d, want %d", keys.MacKey.Size(), MacKeySize)
	}
	if keys.IV.Size() != IVSize {
		t.Errorf("IV length = %d, want %d", keys.IV.Size(), IVSize)
	}

	// Total output must be HybridKeySize bytes.
	totalLen := keys.CipherKey.Size() + keys.MacKey.Size() + keys.IV.Size()
	if totalLen != HybridKeySize {
		t.Errorf("total key material = %d bytes, want %d", totalLen, HybridKeySize)
	}

	// Keys should not be all zeros.
	assertNotAllZero(t, "CipherKey", keys.CipherKey.Bytes())
	assertNotAllZero(t, "MacKey", keys.MacKey.Bytes())
	assertNotAllZero(t, "IV", keys.IV.Bytes())
}

func TestKDFHybridEmptyECMK(t *testing.T) {
	pqMK := make([]byte, 32)
	fillRandom(t, pqMK)

	_, err := KDFHybrid(nil, pqMK)
	if err == nil {
		t.Fatal("expected error for nil ecMK")
	}
	var inputErr *ErrInvalidInput
	if !errorAs(err, &inputErr) {
		t.Errorf("expected ErrInvalidInput, got %T: %v", err, err)
	}
}

func TestKDFHybridEmptyPQMK(t *testing.T) {
	ecMK := make([]byte, 32)
	fillRandom(t, ecMK)

	_, err := KDFHybrid(ecMK, nil)
	if err == nil {
		t.Fatal("expected error for nil pqMK")
	}
	var inputErr *ErrInvalidInput
	if !errorAs(err, &inputErr) {
		t.Errorf("expected ErrInvalidInput, got %T: %v", err, err)
	}
}

func TestKDFHybridDeterminism(t *testing.T) {
	ecMK := make([]byte, 32)
	pqMK := make([]byte, 32)
	fillRandom(t, ecMK, pqMK)

	keys1, err := KDFHybrid(ecMK, pqMK)
	if err != nil {
		t.Fatalf("first KDFHybrid: %v", err)
	}

	keys2, err := KDFHybrid(ecMK, pqMK)
	if err != nil {
		t.Fatalf("second KDFHybrid: %v", err)
	}

	if !bytes.Equal(keys1.CipherKey.Bytes(), keys2.CipherKey.Bytes()) {
		t.Error("CipherKey not deterministic")
	}
	if !bytes.Equal(keys1.MacKey.Bytes(), keys2.MacKey.Bytes()) {
		t.Error("MacKey not deterministic")
	}
	if !bytes.Equal(keys1.IV.Bytes(), keys2.IV.Bytes()) {
		t.Error("IV not deterministic")
	}
}

func TestKDFHybridECOnly(t *testing.T) {
	ecMK := make([]byte, 32)
	fillRandom(t, ecMK)

	keys, err := KDFHybridECOnly(ecMK)
	if err != nil {
		t.Fatalf("KDFHybridECOnly returned error: %v", err)
	}

	if keys.CipherKey.Size() != CipherKeySize {
		t.Errorf("CipherKey length = %d, want %d", keys.CipherKey.Size(), CipherKeySize)
	}
	if keys.MacKey.Size() != MacKeySize {
		t.Errorf("MacKey length = %d, want %d", keys.MacKey.Size(), MacKeySize)
	}
	if keys.IV.Size() != IVSize {
		t.Errorf("IV length = %d, want %d", keys.IV.Size(), IVSize)
	}

	assertNotAllZero(t, "CipherKey", keys.CipherKey.Bytes())
	assertNotAllZero(t, "MacKey", keys.MacKey.Bytes())
	assertNotAllZero(t, "IV", keys.IV.Bytes())
}

func TestKDFHybridECOnlyEmptyInput(t *testing.T) {
	_, err := KDFHybridECOnly(nil)
	if err == nil {
		t.Fatal("expected error for nil ecMK")
	}
	var inputErr *ErrInvalidInput
	if !errorAs(err, &inputErr) {
		t.Errorf("expected ErrInvalidInput, got %T: %v", err, err)
	}
}

func TestKDFHybridECOnlyDeterminism(t *testing.T) {
	ecMK := make([]byte, 32)
	fillRandom(t, ecMK)

	keys1, err := KDFHybridECOnly(ecMK)
	if err != nil {
		t.Fatalf("first KDFHybridECOnly: %v", err)
	}

	keys2, err := KDFHybridECOnly(ecMK)
	if err != nil {
		t.Fatalf("second KDFHybridECOnly: %v", err)
	}

	if !bytes.Equal(keys1.CipherKey.Bytes(), keys2.CipherKey.Bytes()) {
		t.Error("EC-only CipherKey not deterministic")
	}
	if !bytes.Equal(keys1.MacKey.Bytes(), keys2.MacKey.Bytes()) {
		t.Error("EC-only MacKey not deterministic")
	}
	if !bytes.Equal(keys1.IV.Bytes(), keys2.IV.Bytes()) {
		t.Error("EC-only IV not deterministic")
	}
}

func TestKDFHybridDifferentInputs(t *testing.T) {
	ecMK1 := make([]byte, 32)
	ecMK2 := make([]byte, 32)
	pqMK := make([]byte, 32)
	fillRandom(t, ecMK1, ecMK2, pqMK)

	// Ensure the two EC keys are different.
	ecMK2[0] ^= 0xFF

	keys1, err := KDFHybrid(ecMK1, pqMK)
	if err != nil {
		t.Fatalf("KDFHybrid with ecMK1: %v", err)
	}

	keys2, err := KDFHybrid(ecMK2, pqMK)
	if err != nil {
		t.Fatalf("KDFHybrid with ecMK2: %v", err)
	}

	if bytes.Equal(keys1.CipherKey.Bytes(), keys2.CipherKey.Bytes()) {
		t.Error("different EC keys produced same CipherKey")
	}
	if bytes.Equal(keys1.MacKey.Bytes(), keys2.MacKey.Bytes()) {
		t.Error("different EC keys produced same MacKey")
	}
}

func TestKDFHybridVsECOnly(t *testing.T) {
	ecMK := make([]byte, 32)
	pqMK := make([]byte, 32)
	fillRandom(t, ecMK, pqMK)

	hybridKeys, err := KDFHybrid(ecMK, pqMK)
	if err != nil {
		t.Fatalf("KDFHybrid: %v", err)
	}

	ecOnlyKeys, err := KDFHybridECOnly(ecMK)
	if err != nil {
		t.Fatalf("KDFHybridECOnly: %v", err)
	}

	// Hybrid and EC-only should produce different keys for the same ecMK.
	if bytes.Equal(hybridKeys.CipherKey.Bytes(), ecOnlyKeys.CipherKey.Bytes()) {
		t.Error("hybrid and EC-only produced same CipherKey")
	}
}

func TestHybridKeysZeroize(t *testing.T) {
	ecMK := make([]byte, 32)
	pqMK := make([]byte, 32)
	fillRandom(t, ecMK, pqMK)

	keys, err := KDFHybrid(ecMK, pqMK)
	if err != nil {
		t.Fatalf("KDFHybrid: %v", err)
	}

	keys.Zeroize()

	if !keys.CipherKey.IsDestroyed() {
		t.Error("CipherKey should be destroyed after Zeroize")
	}
	if !keys.MacKey.IsDestroyed() {
		t.Error("MacKey should be destroyed after Zeroize")
	}
	if !keys.IV.IsDestroyed() {
		t.Error("IV should be destroyed after Zeroize")
	}
}

func TestHybridKeysZeroizeNil(t *testing.T) {
	// Should not panic on nil receiver.
	var keys *HybridKeys
	keys.Zeroize()
}

// =============================================================================
// Composite Header Tests
// =============================================================================

func TestCompositeHeaderSerializeDeserialize(t *testing.T) {
	ecHeader := []byte("test-ec-header-data-ratchet-key-counter")
	sckaMsg := &mlkembraid.Message{
		Epoch: 42,
		Type:  mlkembraid.MessageTypeHdr,
		Data:  []byte("chunk-data-here"),
	}

	header := &CompositeHeader{
		ECHeader: ecHeader,
		SCKAMsg:  sckaMsg,
	}

	data, err := header.Serialize()
	if err != nil {
		t.Fatalf("Serialize returned error: %v", err)
	}

	restored, err := DeserializeCompositeHeader(data)
	if err != nil {
		t.Fatalf("Deserialize returned error: %v", err)
	}

	if !bytes.Equal(restored.ECHeader, ecHeader) {
		t.Errorf("ECHeader mismatch: got %x, want %x", restored.ECHeader, ecHeader)
	}
	if restored.SCKAMsg.Epoch != 42 {
		t.Errorf("SCKA Epoch = %d, want 42", restored.SCKAMsg.Epoch)
	}
	if restored.SCKAMsg.Type != mlkembraid.MessageTypeHdr {
		t.Errorf("SCKA Type = %d, want %d", restored.SCKAMsg.Type, mlkembraid.MessageTypeHdr)
	}
	if !bytes.Equal(restored.SCKAMsg.Data, []byte("chunk-data-here")) {
		t.Errorf("SCKA Data mismatch: got %x", restored.SCKAMsg.Data)
	}
}

func TestCompositeHeaderSerializeNilECHeader(t *testing.T) {
	header := &CompositeHeader{
		ECHeader: nil,
		SCKAMsg:  &mlkembraid.Message{Epoch: 1, Type: mlkembraid.MessageTypeNone},
	}

	_, err := header.Serialize()
	if err == nil {
		t.Fatal("expected error for nil ECHeader")
	}
}

func TestCompositeHeaderSerializeNilSCKAMsg(t *testing.T) {
	header := &CompositeHeader{
		ECHeader: []byte("data"),
		SCKAMsg:  nil,
	}

	_, err := header.Serialize()
	if err == nil {
		t.Fatal("expected error for nil SCKAMsg")
	}
}

func TestCompositeHeaderEmptyData(t *testing.T) {
	// SCKA message with no chunk data (MessageTypeNone).
	header := &CompositeHeader{
		ECHeader: []byte("header"),
		SCKAMsg: &mlkembraid.Message{
			Epoch: 7,
			Type:  mlkembraid.MessageTypeNone,
			Data:  nil,
		},
	}

	data, err := header.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	restored, err := DeserializeCompositeHeader(data)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}

	if !bytes.Equal(restored.ECHeader, []byte("header")) {
		t.Error("ECHeader mismatch")
	}
	if restored.SCKAMsg.Epoch != 7 {
		t.Errorf("Epoch = %d, want 7", restored.SCKAMsg.Epoch)
	}
	if restored.SCKAMsg.Type != mlkembraid.MessageTypeNone {
		t.Errorf("Type = %d, want None", restored.SCKAMsg.Type)
	}
	if len(restored.SCKAMsg.Data) != 0 {
		t.Errorf("Data should be empty, got %d bytes", len(restored.SCKAMsg.Data))
	}
}

func TestDeserializeCompositeHeaderTooShort(t *testing.T) {
	_, err := DeserializeCompositeHeader([]byte{0x00, 0x01})
	if err == nil {
		t.Fatal("expected error for short data")
	}
	var compErr *ErrInvalidCompositeMessage
	if !errorAs(err, &compErr) {
		t.Errorf("expected ErrInvalidCompositeMessage, got %T", err)
	}
}

func TestDeserializeCompositeHeaderInvalidECLength(t *testing.T) {
	// EC header length of 9999 but only 20 bytes total.
	data := make([]byte, 20)
	data[0] = 0x00
	data[1] = 0x00
	data[2] = 0x27 // 9999
	data[3] = 0x0F

	_, err := DeserializeCompositeHeader(data)
	if err == nil {
		t.Fatal("expected error for invalid EC header length")
	}
}

func TestDeserializeCompositeHeaderInvalidSCKADataLength(t *testing.T) {
	// Valid EC header of length 1, then SCKA fields with corrupted data.
	// The SCKA portion uses varint encoding so we can't rely on fixed offsets.
	// Instead, we create a valid header and truncate the SCKA data to make
	// the deserialization fail on parsing.
	header := &CompositeHeader{
		ECHeader: []byte{0xAA},
		SCKAMsg: &mlkembraid.Message{
			Epoch: 1,
			Type:  mlkembraid.MessageTypeNone,
			Data:  []byte{0xBB},
		},
	}
	data, err := header.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Corrupt by truncating the SCKA portion after the EC header.
	// Keep only EC header len prefix + EC header + a few SCKA bytes.
	truncated := data[:ecHeaderLenSize+1+2]

	_, err = DeserializeCompositeHeader(truncated)
	if err == nil {
		t.Fatal("expected error for corrupted SCKA data")
	}
}

func TestCompositeHeaderAllMessageTypes(t *testing.T) {
	types := []mlkembraid.MessageType{
		mlkembraid.MessageTypeNone,
		mlkembraid.MessageTypeHdr,
		mlkembraid.MessageTypeEk,
		mlkembraid.MessageTypeEkCt1Ack,
		mlkembraid.MessageTypeCt1Ack,
		mlkembraid.MessageTypeCt1,
		mlkembraid.MessageTypeCt2,
	}

	for _, mt := range types {
		t.Run(mt.String(), func(t *testing.T) {
			header := &CompositeHeader{
				ECHeader: []byte("ec-data"),
				SCKAMsg: &mlkembraid.Message{
					Epoch: 100,
					Type:  mt,
					Data:  []byte("test"),
				},
			}

			data, err := header.Serialize()
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}

			restored, err := DeserializeCompositeHeader(data)
			if err != nil {
				t.Fatalf("Deserialize: %v", err)
			}

			if restored.SCKAMsg.Type != mt {
				t.Errorf("Type = %d, want %d", restored.SCKAMsg.Type, mt)
			}
		})
	}
}

// =============================================================================
// Composite Message Serialization Tests
// =============================================================================

func TestCompositeMessageSerializeDeserialize(t *testing.T) {
	header := &CompositeHeader{
		ECHeader: []byte("ec-header-ratchet"),
		SCKAMsg: &mlkembraid.Message{
			Epoch: 5,
			Type:  mlkembraid.MessageTypeCt1,
			Data:  []byte("scka-chunk"),
		},
	}
	ciphertext := []byte("encrypted-payload-data")

	msg, err := serializeCompositeMessage(header, ciphertext)
	if err != nil {
		t.Fatalf("serializeCompositeMessage: %v", err)
	}

	restoredHeader, restoredCT, err := deserializeCompositeMessage(msg)
	if err != nil {
		t.Fatalf("deserializeCompositeMessage: %v", err)
	}

	if !bytes.Equal(restoredHeader.ECHeader, header.ECHeader) {
		t.Error("ECHeader mismatch")
	}
	if restoredHeader.SCKAMsg.Epoch != 5 {
		t.Errorf("Epoch = %d, want 5", restoredHeader.SCKAMsg.Epoch)
	}
	if !bytes.Equal(restoredCT, ciphertext) {
		t.Errorf("ciphertext mismatch: got %x, want %x", restoredCT, ciphertext)
	}
}

func TestDeserializeCompositeMessageTooShort(t *testing.T) {
	_, _, err := deserializeCompositeMessage([]byte{0x00})
	if err == nil {
		t.Fatal("expected error for short message")
	}
}

func TestDeserializeCompositeMessageInvalidHeaderLen(t *testing.T) {
	// Header length = 999999 but message is only 12 bytes.
	data := make([]byte, 12)
	data[0] = 0x00
	data[1] = 0x0F
	data[2] = 0x42
	data[3] = 0x3F

	_, _, err := deserializeCompositeMessage(data)
	if err == nil {
		t.Fatal("expected error for oversized header length")
	}
}

func TestDeserializeCompositeMessageEmptyInput(t *testing.T) {
	_, _, err := deserializeCompositeMessage(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestErrorTypes(t *testing.T) {
	t.Run("ErrHybridKDFFailed", func(t *testing.T) {
		err := &ErrHybridKDFFailed{Err: &ErrInvalidInput{Field: "test", Reason: "testing"}}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
		if err.Unwrap() == nil {
			t.Error("Unwrap should return inner error")
		}
	})

	t.Run("ErrECRatchetFailed", func(t *testing.T) {
		err := &ErrECRatchetFailed{Op: "Encrypt", Err: &ErrInvalidInput{Field: "x", Reason: "y"}}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
		if err.Unwrap() == nil {
			t.Error("Unwrap should return inner error")
		}
	})

	t.Run("ErrSPQRFailed", func(t *testing.T) {
		err := &ErrSPQRFailed{Op: "Send", Err: &ErrInvalidInput{Field: "x", Reason: "y"}}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
		if err.Unwrap() == nil {
			t.Error("Unwrap should return inner error")
		}
	})

	t.Run("ErrInvalidCompositeMessage", func(t *testing.T) {
		err := &ErrInvalidCompositeMessage{Reason: "too short"}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
	})

	t.Run("ErrInvalidInput", func(t *testing.T) {
		err := &ErrInvalidInput{Field: "ecMK", Reason: "empty"}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
	})

	t.Run("ErrMACVerificationFailed", func(t *testing.T) {
		err := &ErrMACVerificationFailed{}
		if err.Error() == "" {
			t.Error("error message should not be empty")
		}
		if err.Error() != "tripleratchet: MAC verification failed" {
			t.Errorf("unexpected error message: %s", err.Error())
		}
	})
}

// =============================================================================
// XOR Keys Tests
// =============================================================================

func TestXorKeys(t *testing.T) {
	a := []byte{0xFF, 0x00, 0xAA, 0x55}
	b := []byte{0x0F, 0xF0, 0x55, 0xAA}

	result, err := xorKeys(a, b)
	if err != nil {
		t.Fatalf("xorKeys: %v", err)
	}
	defer result.Destroy()
	expected := []byte{0xF0, 0xF0, 0xFF, 0xFF}

	if !bytes.Equal(result.Bytes(), expected) {
		t.Errorf("xorKeys = %x, want %x", result.Bytes(), expected)
	}
}

func TestXorKeysDifferentLengths(t *testing.T) {
	a := []byte{0xFF, 0x00, 0xAA}
	b := []byte{0x0F, 0xF0}

	result, err := xorKeys(a, b)
	if err != nil {
		t.Fatalf("xorKeys: %v", err)
	}
	defer result.Destroy()
	if result.Size() != 2 {
		t.Errorf("xorKeys result length = %d, want 2", result.Size())
	}
	expected := []byte{0xF0, 0xF0}
	if !bytes.Equal(result.Bytes(), expected) {
		t.Errorf("xorKeys = %x, want %x", result.Bytes(), expected)
	}
}

func TestXorKeysIdentity(t *testing.T) {
	a := make([]byte, 32)
	fillRandom(t, a)

	zeros := make([]byte, 32)
	result, err := xorKeys(a, zeros)
	if err != nil {
		t.Fatalf("xorKeys: %v", err)
	}
	defer result.Destroy()
	if !bytes.Equal(result.Bytes(), a) {
		t.Error("XOR with zero should be identity")
	}
}

func TestXorKeysSelf(t *testing.T) {
	a := make([]byte, 32)
	fillRandom(t, a)

	result, err := xorKeys(a, a)
	if err != nil {
		t.Fatalf("xorKeys: %v", err)
	}
	defer result.Destroy()
	assertAllZero(t, "XOR with self", result.Bytes())
}

// =============================================================================
// SPQR Chain KDF Integration Tests
// =============================================================================

func TestSPQRChainKDFIntegration(t *testing.T) {
	// Verify the SPQR chain KDF produces keys compatible with KDFHybrid.
	sharedSecret := make([]byte, 32)
	fillRandom(t, sharedSecret)

	_, cks, _, err := spqr.KdfSckaInit(sharedSecret)
	if err != nil {
		t.Fatalf("KdfSckaInit: %v", err)
	}

	// Derive a message key from the send chain.
	mk, nextCK, kdfErr := spqr.KdfSckaCK(cks, 0)
	if kdfErr != nil {
		t.Fatalf("KdfSckaCK: %v", kdfErr)
	}
	if mk.Size() != 32 {
		t.Fatalf("message key length = %d, want 32", mk.Size())
	}
	if nextCK.Size() != 32 {
		t.Fatalf("next chain key length = %d, want 32", nextCK.Size())
	}
	defer mk.Destroy()
	defer nextCK.Destroy()

	// Use the PQ message key with an EC key in KDFHybrid.
	ecMK := make([]byte, 32)
	fillRandom(t, ecMK)

	keys, err := KDFHybrid(ecMK, mk.Bytes())
	if err != nil {
		t.Fatalf("KDFHybrid with SPQR chain key: %v", err)
	}

	assertNotAllZero(t, "hybrid CipherKey", keys.CipherKey.Bytes())

	// Verify derived keys can actually encrypt/decrypt.
	plaintext := []byte("test-plaintext-data-for-encryption")
	ct, err := cipher.Encrypt(keys.IV.Bytes(), keys.CipherKey.Bytes(), plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Re-derive keys (deterministic) and decrypt.
	keys2, err := KDFHybrid(ecMK, mk.Bytes())
	if err != nil {
		t.Fatalf("KDFHybrid re-derive: %v", err)
	}

	pt, err := cipher.Decrypt(keys2.IV.Bytes(), keys2.CipherKey.Bytes(), ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip failed: got %q, want %q", pt, plaintext)
	}
}

// =============================================================================
// Triple Ratchet Constructor Tests
// =============================================================================

func TestNewAliceNilCipher(t *testing.T) {
	_, err := NewAlice(nil, []byte("secret"), mlkembraid.NewMLKEM768IncrementalKEM(), 32)
	if err == nil {
		t.Fatal("expected error for nil ecCipher")
	}
}

func TestNewAliceEmptySecret(t *testing.T) {
	_, err := NewAlice(&mockECCipher{}, nil, mlkembraid.NewMLKEM768IncrementalKEM(), 32)
	if err == nil {
		t.Fatal("expected error for empty sharedSecret")
	}
}

func TestNewAliceNilKEM(t *testing.T) {
	_, err := NewAlice(&mockECCipher{}, []byte("secret"), nil, 32)
	if err == nil {
		t.Fatal("expected error for nil kemImpl")
	}
}

func TestNewBobNilCipher(t *testing.T) {
	_, err := NewBob(nil, []byte("secret"), mlkembraid.NewMLKEM768IncrementalKEM(), 32)
	if err == nil {
		t.Fatal("expected error for nil ecCipher")
	}
}

func TestNewBobEmptySecret(t *testing.T) {
	_, err := NewBob(&mockECCipher{}, nil, mlkembraid.NewMLKEM768IncrementalKEM(), 32)
	if err == nil {
		t.Fatal("expected error for empty sharedSecret")
	}
}

func TestNewBobNilKEM(t *testing.T) {
	_, err := NewBob(&mockECCipher{}, []byte("secret"), nil, 32)
	if err == nil {
		t.Fatal("expected error for nil kemImpl")
	}
}

func TestNewAliceBob(t *testing.T) {
	sharedSecret := make([]byte, 32)
	fillRandom(t, sharedSecret)

	kem := mlkembraid.NewMLKEM768IncrementalKEM()

	alice, err := NewAlice(&mockECCipher{}, sharedSecret, kem, mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}
	// Per spec Section 2.6: epoch=1 at initialization.
	if alice.Epoch() != 1 {
		t.Errorf("Alice initial epoch = %d, want 1", alice.Epoch())
	}

	bob, err := NewBob(&mockECCipher{}, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}
	if bob.Epoch() != 1 {
		t.Errorf("Bob initial epoch = %d, want 1", bob.Epoch())
	}
}

// =============================================================================
// Triple Ratchet Encrypt/Decrypt Tests
// =============================================================================

func TestTripleRatchetEncryptDecrypt(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	plaintext := []byte("Hello from Alice to Bob via Triple Ratchet!")

	// Alice encrypts.
	compositeMsg, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Alice.Encrypt: %v", err)
	}

	if len(compositeMsg) == 0 {
		t.Fatal("encrypted message should not be empty")
	}

	// Bob decrypts.
	decrypted, err := bob.Decrypt(compositeMsg)
	if err != nil {
		t.Fatalf("Bob.Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestTripleRatchetMultipleMessages(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	messages := []string{
		"Message 1: Hello!",
		"Message 2: How are you?",
		"Message 3: Fine, thanks.",
		"Message 4: Great to hear.",
		"Message 5: Goodbye!",
	}

	for i, msg := range messages {
		// Alice sends to Bob.
		ct, err := alice.Encrypt([]byte(msg))
		if err != nil {
			t.Fatalf("message %d: Alice.Encrypt: %v", i, err)
		}

		pt, err := bob.Decrypt(ct)
		if err != nil {
			t.Fatalf("message %d: Bob.Decrypt: %v", i, err)
		}

		if string(pt) != msg {
			t.Errorf("message %d: got %q, want %q", i, pt, msg)
		}
	}
}

func TestTripleRatchetBidirectional(t *testing.T) {
	// The ML-KEM Braid requires multiple message exchanges before the
	// state machine allows bidirectional operation. Alice starts as the
	// initiator sending header chunks; Bob cannot send meaningful Braid
	// messages until he has received Alice's full header. This test
	// exercises multiple messages in the same direction followed by
	// messages in the reverse direction to confirm the chain keys
	// advance independently.

	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	// Alice sends multiple messages to Bob.
	for i := 0; i < 3; i++ {
		msg := []byte("Alice message " + string(rune('A'+i)))
		ct, err := alice.Encrypt(msg)
		if err != nil {
			t.Fatalf("Alice.Encrypt %d: %v", i, err)
		}

		pt, err := bob.Decrypt(ct)
		if err != nil {
			t.Fatalf("Bob.Decrypt %d: %v", i, err)
		}

		if !bytes.Equal(pt, msg) {
			t.Errorf("message %d: got %q, want %q", i, pt, msg)
		}
	}

	// Bob sends multiple messages to Alice.
	// Note: Bob's braid may not accept receives from Alice at this stage,
	// but Bob can still send using his own braid+chain state.
	for i := 0; i < 3; i++ {
		msg := []byte("Bob message " + string(rune('X'+i)))
		ct, err := bob.Encrypt(msg)
		if err != nil {
			t.Fatalf("Bob.Encrypt %d: %v", i, err)
		}

		pt, err := alice.Decrypt(ct)
		if err != nil {
			t.Fatalf("Alice.Decrypt %d: %v", i, err)
		}

		if !bytes.Equal(pt, msg) {
			t.Errorf("message %d: got %q, want %q", i, pt, msg)
		}
	}
}

func TestTripleRatchetInitialEpoch(t *testing.T) {
	// Before the Braid produces an output key, messages are encrypted
	// using the initial SPQR chain keys derived from KdfSckaInit.
	// The root key should be retained for future epoch advancement.
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	// Verify root key is present (retained for epoch advancement).
	if alice.rootKey == nil || alice.rootKey.IsDestroyed() {
		t.Error("Alice should have a valid root key after initialization")
	}
	if bob.rootKey == nil || bob.rootKey.IsDestroyed() {
		t.Error("Bob should have a valid root key after initialization")
	}

	// Initial PQ epoch should be 0.
	if alice.pqEpoch != 0 {
		t.Errorf("Alice initial pqEpoch = %d, want 0", alice.pqEpoch)
	}

	plaintext := []byte("Initial epoch message")
	ct, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt in initial epoch: %v", err)
	}

	pt, err := bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt in initial epoch: %v", err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Errorf("initial epoch roundtrip failed: got %q, want %q", pt, plaintext)
	}
}

func TestTripleRatchetEncryptEmptyPlaintext(t *testing.T) {
	alice, _ := setupAliceBob(t)
	defer alice.Zeroize()

	_, err := alice.Encrypt(nil)
	if err == nil {
		t.Fatal("expected error for nil plaintext")
	}
}

func TestTripleRatchetDecryptEmptyMessage(t *testing.T) {
	_, bob := setupAliceBob(t)
	defer bob.Zeroize()

	_, err := bob.Decrypt(nil)
	if err == nil {
		t.Fatal("expected error for nil composite message")
	}
}

func TestTripleRatchetDecryptInvalidMessage(t *testing.T) {
	_, bob := setupAliceBob(t)
	defer bob.Zeroize()

	_, err := bob.Decrypt([]byte("invalid-garbage-data-too-short"))
	if err == nil {
		t.Fatal("expected error for invalid composite message")
	}
}

func TestTripleRatchetEpochStableWithinEpoch(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	initialAliceEpoch := alice.Epoch()
	initialBobEpoch := bob.Epoch()

	// Per spec, the epoch only advances on specific state transitions (5 and 13),
	// not on every Send call. Within a single epoch's handshake, the epoch
	// remains stable until the transition completes.
	ct, err := alice.Encrypt([]byte("message"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Alice's first Send transitions KeysUnsampled -> KeysSampled, but epoch
	// does not change until Transition 5 (EkSentCt1Received -> NoHeaderReceived).
	if alice.Epoch() != initialAliceEpoch {
		t.Errorf("Alice epoch should remain at %d within epoch handshake, got %d",
			initialAliceEpoch, alice.Epoch())
	}

	// Decrypt processes through the Braid for Bob.
	_, err = bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	// Bob's epoch also remains stable within the handshake.
	_ = initialBobEpoch
}

func TestTripleRatchetZeroize(t *testing.T) {
	alice, _ := setupAliceBob(t)

	alice.Zeroize()

	if !alice.rootKey.IsDestroyed() {
		t.Error("rootKey should be destroyed after Zeroize")
	}
	if !alice.sendChainKey.IsDestroyed() {
		t.Error("sendChainKey should be destroyed after Zeroize")
	}
	if !alice.recvChainKey.IsDestroyed() {
		t.Error("recvChainKey should be destroyed after Zeroize")
	}
}

// =============================================================================
// EC Cipher Error Handling Tests
// =============================================================================

func TestTripleRatchetEncryptECCipherError(t *testing.T) {
	sharedSecret := make([]byte, 32)
	fillRandom(t, sharedSecret)

	failCipher := &failingECCipher{encryptErr: &ErrInvalidInput{Field: "test", Reason: "mock error"}}

	alice, err := NewAlice(failCipher, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	_, err = alice.Encrypt([]byte("hello"))
	if err == nil {
		t.Fatal("expected error when EC cipher fails")
	}
	var ecErr *ErrECRatchetFailed
	if !errorAs(err, &ecErr) {
		t.Errorf("expected ErrECRatchetFailed, got %T: %v", err, err)
	}
}

func TestTripleRatchetDecryptECCipherError(t *testing.T) {
	sharedSecret := make([]byte, 32)
	fillRandom(t, sharedSecret)

	// Create a valid alice to produce a message.
	aliceCipher := newMockECCipher()
	alice, err := NewAlice(aliceCipher, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	ct, err := alice.Encrypt([]byte("test message"))
	if err != nil {
		t.Fatalf("Alice.Encrypt: %v", err)
	}

	// Create bob with a failing cipher.
	failCipher := &failingECCipher{decryptErr: &ErrInvalidInput{Field: "test", Reason: "mock error"}}
	bob, err := NewBob(failCipher, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}

	_, err = bob.Decrypt(ct)
	if err == nil {
		t.Fatal("expected error when EC cipher decrypt fails")
	}
	var ecErr *ErrECRatchetFailed
	if !errorAs(err, &ecErr) {
		t.Errorf("expected ErrECRatchetFailed, got %T: %v", err, err)
	}
}

func TestTripleRatchetEpochAdvancement(t *testing.T) {
	// Test that advancePQEpoch correctly derives new chain keys and
	// resets counters, matching Rust's Chain.add_epoch() behavior.
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	// Simulate a Braid epoch secret by advancing both sides identically.
	epochSecret := make([]byte, 32)
	fillRandom(t, epochSecret)

	// Send a message in epoch 0 first.
	plaintext0 := []byte("epoch 0 message")
	ct0, err := alice.Encrypt(plaintext0)
	if err != nil {
		t.Fatalf("Encrypt epoch 0: %v", err)
	}
	pt0, err := bob.Decrypt(ct0)
	if err != nil {
		t.Fatalf("Decrypt epoch 0: %v", err)
	}
	if !bytes.Equal(pt0, plaintext0) {
		t.Errorf("epoch 0 roundtrip: got %q, want %q", pt0, plaintext0)
	}

	// Advance both to epoch 1 with the same secret.
	aliceEpochSecret := make([]byte, len(epochSecret))
	copy(aliceEpochSecret, epochSecret)
	if err := alice.advancePQEpoch(aliceEpochSecret); err != nil {
		t.Fatalf("alice advancePQEpoch: %v", err)
	}
	bobEpochSecret := make([]byte, len(epochSecret))
	copy(bobEpochSecret, epochSecret)
	if err := bob.advancePQEpoch(bobEpochSecret); err != nil {
		t.Fatalf("bob advancePQEpoch: %v", err)
	}

	// Verify epoch was incremented.
	if alice.pqEpoch != 1 {
		t.Errorf("alice pqEpoch = %d, want 1", alice.pqEpoch)
	}
	if bob.pqEpoch != 1 {
		t.Errorf("bob pqEpoch = %d, want 1", bob.pqEpoch)
	}

	// Verify counters were reset.
	if alice.sendCounter != 0 {
		t.Errorf("alice sendCounter = %d, want 0 after epoch advance", alice.sendCounter)
	}
	if bob.recvCounter != 0 {
		t.Errorf("bob recvCounter = %d, want 0 after epoch advance", bob.recvCounter)
	}

	// Send a message in the new epoch.
	plaintext1 := []byte("epoch 1 message")
	ct1, err := alice.Encrypt(plaintext1)
	if err != nil {
		t.Fatalf("Encrypt epoch 1: %v", err)
	}
	pt1, err := bob.Decrypt(ct1)
	if err != nil {
		t.Fatalf("Decrypt epoch 1: %v", err)
	}
	if !bytes.Equal(pt1, plaintext1) {
		t.Errorf("epoch 1 roundtrip: got %q, want %q", pt1, plaintext1)
	}
}

func TestDeserializeCompositeMessageMissingCiphertextLen(t *testing.T) {
	// Create a message where header is valid but there's no room for ciphertext length.
	header := &CompositeHeader{
		ECHeader: []byte("ec"),
		SCKAMsg:  &mlkembraid.Message{Epoch: 1, Type: mlkembraid.MessageTypeNone},
	}
	headerBytes, err := header.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Build message with header but truncated before ciphertext length.
	buf := make([]byte, headerLenPrefixSize+len(headerBytes))
	binary.BigEndian.PutUint32(buf[0:], uint32(len(headerBytes)))
	copy(buf[headerLenPrefixSize:], headerBytes)

	_, _, err = deserializeCompositeMessage(buf)
	if err == nil {
		t.Fatal("expected error for missing ciphertext length")
	}
}

func TestDeserializeCompositeMessageOversizedCiphertext(t *testing.T) {
	header := &CompositeHeader{
		ECHeader: []byte("ec"),
		SCKAMsg:  &mlkembraid.Message{Epoch: 1, Type: mlkembraid.MessageTypeNone},
	}
	headerBytes, err := header.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	// Build message with valid header but ciphertext length pointing past end.
	buf := make([]byte, headerLenPrefixSize+len(headerBytes)+ciphertextLenPrefixSize)
	binary.BigEndian.PutUint32(buf[0:], uint32(len(headerBytes)))
	copy(buf[headerLenPrefixSize:], headerBytes)
	binary.BigEndian.PutUint32(buf[headerLenPrefixSize+len(headerBytes):], 0xFFFFFFFF)

	_, _, err = deserializeCompositeMessage(buf)
	if err == nil {
		t.Fatal("expected error for oversized ciphertext length")
	}
}

func TestSerializeCompositeMessageHeaderError(t *testing.T) {
	// A header with nil ECHeader should cause serialize to fail.
	header := &CompositeHeader{
		ECHeader: nil,
		SCKAMsg:  &mlkembraid.Message{Epoch: 1},
	}
	_, err := serializeCompositeMessage(header, []byte("ct"))
	if err == nil {
		t.Fatal("expected error for nil ECHeader in serialize")
	}
}

func TestNewAliceInvalidChunkSize(t *testing.T) {
	sharedSecret := make([]byte, 32)
	fillRandom(t, sharedSecret)

	_, err := NewAlice(&mockECCipher{}, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), 0)
	if err == nil {
		t.Fatal("expected error for invalid chunk size")
	}
	var spqrErr *ErrSPQRFailed
	if !errorAs(err, &spqrErr) {
		t.Errorf("expected ErrSPQRFailed, got %T: %v", err, err)
	}
}

func TestNewBobInvalidChunkSize(t *testing.T) {
	sharedSecret := make([]byte, 32)
	fillRandom(t, sharedSecret)

	_, err := NewBob(&mockECCipher{}, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), -1)
	if err == nil {
		t.Fatal("expected error for invalid chunk size")
	}
	var spqrErr *ErrSPQRFailed
	if !errorAs(err, &spqrErr) {
		t.Errorf("expected ErrSPQRFailed, got %T: %v", err, err)
	}
}

// =============================================================================
// MAC Authentication Tests
// =============================================================================

func TestTripleRatchetMACTamperedCiphertext(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	plaintext := []byte("Message that will be tampered with")
	compositeMsg, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Alice.Encrypt: %v", err)
	}

	// Parse the composite message to tamper with the ciphertext portion.
	header, ciphertext, err := deserializeCompositeMessage(compositeMsg)
	if err != nil {
		t.Fatalf("deserializeCompositeMessage: %v", err)
	}

	// Flip a bit in the encrypted payload (before the MAC).
	if len(ciphertext) <= HMACSize {
		t.Fatal("ciphertext too short to contain both payload and MAC")
	}
	ciphertext[0] ^= 0xFF

	// Re-serialize with tampered ciphertext.
	tamperedMsg, err := serializeCompositeMessage(header, ciphertext)
	if err != nil {
		t.Fatalf("serializeCompositeMessage: %v", err)
	}

	_, err = bob.Decrypt(tamperedMsg)
	if err == nil {
		t.Fatal("expected MAC verification error for tampered ciphertext")
	}
	var macErr *ErrMACVerificationFailed
	if !errorAs(err, &macErr) {
		t.Errorf("expected ErrMACVerificationFailed, got %T: %v", err, err)
	}
}

func TestTripleRatchetMACTamperedTag(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	plaintext := []byte("Message whose MAC tag will be tampered")
	compositeMsg, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Alice.Encrypt: %v", err)
	}

	// Parse the composite message to tamper with the MAC tag.
	header, ciphertext, err := deserializeCompositeMessage(compositeMsg)
	if err != nil {
		t.Fatalf("deserializeCompositeMessage: %v", err)
	}

	// Flip a bit in the MAC tag (last 32 bytes).
	ciphertext[len(ciphertext)-1] ^= 0xFF

	// Re-serialize with tampered MAC.
	tamperedMsg, err := serializeCompositeMessage(header, ciphertext)
	if err != nil {
		t.Fatalf("serializeCompositeMessage: %v", err)
	}

	_, err = bob.Decrypt(tamperedMsg)
	if err == nil {
		t.Fatal("expected MAC verification error for tampered MAC tag")
	}
	var macErr *ErrMACVerificationFailed
	if !errorAs(err, &macErr) {
		t.Errorf("expected ErrMACVerificationFailed, got %T: %v", err, err)
	}
}

func TestTripleRatchetMACCiphertextTooShortForMAC(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	plaintext := []byte("Short test message")
	compositeMsg, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Alice.Encrypt: %v", err)
	}

	// Parse the composite message and replace ciphertext with something too short.
	header, _, err := deserializeCompositeMessage(compositeMsg)
	if err != nil {
		t.Fatalf("deserializeCompositeMessage: %v", err)
	}

	// Create ciphertext shorter than HMACSize.
	shortCT := make([]byte, HMACSize-1)

	truncatedMsg, err := serializeCompositeMessage(header, shortCT)
	if err != nil {
		t.Fatalf("serializeCompositeMessage: %v", err)
	}

	_, err = bob.Decrypt(truncatedMsg)
	if err == nil {
		t.Fatal("expected error for ciphertext shorter than MAC size")
	}
}

func TestTripleRatchetMACAfterEpochAdvance(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	// Advance the PQ epoch so both sides have new chain keys.
	epochSecret := make([]byte, 32)
	fillRandom(t, epochSecret)
	aliceES := make([]byte, len(epochSecret))
	copy(aliceES, epochSecret)
	if err := alice.advancePQEpoch(aliceES); err != nil {
		t.Fatalf("alice advancePQEpoch: %v", err)
	}
	bobES := make([]byte, len(epochSecret))
	copy(bobES, epochSecret)
	if err := bob.advancePQEpoch(bobES); err != nil {
		t.Fatalf("bob advancePQEpoch: %v", err)
	}

	plaintext := []byte("Hybrid PQ+EC message with MAC authentication")
	ct, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt with PQ key: %v", err)
	}

	pt, err := bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt with PQ key: %v", err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip with PQ key and MAC failed: got %q, want %q", pt, plaintext)
	}

	// Also verify tampering is detected in hybrid mode.
	ct2, err := alice.Encrypt([]byte("second message"))
	if err != nil {
		t.Fatalf("Encrypt second: %v", err)
	}

	header, ciphertext, err := deserializeCompositeMessage(ct2)
	if err != nil {
		t.Fatalf("deserializeCompositeMessage: %v", err)
	}
	ciphertext[0] ^= 0xFF
	tamperedMsg, err := serializeCompositeMessage(header, ciphertext)
	if err != nil {
		t.Fatalf("serializeCompositeMessage: %v", err)
	}

	_, err = bob.Decrypt(tamperedMsg)
	if err == nil {
		t.Fatal("expected MAC verification error for tampered hybrid ciphertext")
	}
}

// =============================================================================
// Mock EC Cipher
// =============================================================================

// mockECCipher is a deterministic mock of the EC Double Ratchet cipher
// that uses a fixed key for testing the Triple Ratchet integration.
type mockECCipher struct {
	// sendCounter tracks messages sent for varying the mock EC header.
	sendCounter uint32
	// recvCounter tracks messages received.
	recvCounter uint32
	// chainKey is used to derive deterministic message keys.
	chainKey []byte
}

func newMockECCipher() *mockECCipher {
	key := make([]byte, 32)
	// Use a fixed seed so Alice and Bob derive matching keys.
	for i := range key {
		key[i] = byte(i + 1)
	}
	return &mockECCipher{chainKey: key}
}

func (m *mockECCipher) SendKey() ([]byte, []byte, error) {
	m.sendCounter++

	// Derive a message key from the chain key using SPQR's HKDF pattern.
	ckSecret, err := secret.New(append([]byte(nil), m.chainKey...))
	if err != nil {
		return nil, nil, err
	}
	mk, nextCK, err := spqr.KdfSckaCK(ckSecret, m.sendCounter)
	if err != nil {
		return nil, nil, err
	}
	copy(m.chainKey, nextCK.Bytes())
	nextCK.Destroy()

	// Create a simple EC header with the counter.
	ecHeader := make([]byte, 4)
	ecHeader[0] = byte(m.sendCounter >> 24)
	ecHeader[1] = byte(m.sendCounter >> 16)
	ecHeader[2] = byte(m.sendCounter >> 8)
	ecHeader[3] = byte(m.sendCounter)

	mkBytes := append([]byte(nil), mk.Bytes()...)
	mk.Destroy()

	return ecHeader, mkBytes, nil
}

func (m *mockECCipher) EncryptGetKey(plaintext []byte) ([]byte, []byte, []byte, error) {
	ecHeader, mkBytes, err := m.SendKey()
	if err != nil {
		return nil, nil, nil, err
	}

	// The ciphertext is just a copy of plaintext for the mock - the real
	// encryption happens in the Triple Ratchet layer using hybrid keys.
	ciphertext := make([]byte, len(plaintext))
	copy(ciphertext, plaintext)

	return ciphertext, ecHeader, mkBytes, nil
}

func (m *mockECCipher) ReceiveKey(_ []byte) ([]byte, error) {
	m.recvCounter++

	// Derive the matching message key.
	ckSecret, err := secret.New(append([]byte(nil), m.chainKey...))
	if err != nil {
		return nil, err
	}
	mk, nextCK, err := spqr.KdfSckaCK(ckSecret, m.recvCounter)
	if err != nil {
		return nil, err
	}
	copy(m.chainKey, nextCK.Bytes())
	nextCK.Destroy()

	mkBytes := append([]byte(nil), mk.Bytes()...)
	mk.Destroy()

	return mkBytes, nil
}

func (m *mockECCipher) DecryptGetKey(ecHeader []byte, ciphertext []byte) ([]byte, []byte, error) {
	mk, err := m.ReceiveKey(ecHeader)
	if err != nil {
		return nil, nil, err
	}

	// Return the ciphertext as-is and the message key.
	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)

	return plaintext, mk, nil
}

// TakeECSnapshot serializes the mock EC cipher state for rollback.
func (m *mockECCipher) TakeECSnapshot() ([]byte, error) {
	// Serialize: sendCounter(4) + recvCounter(4) + chainKey(32)
	data := make([]byte, 8+len(m.chainKey))
	binary.BigEndian.PutUint32(data[0:4], m.sendCounter)
	binary.BigEndian.PutUint32(data[4:8], m.recvCounter)
	copy(data[8:], m.chainKey)
	return data, nil
}

// RestoreECSnapshot restores the mock EC cipher state from a snapshot.
func (m *mockECCipher) RestoreECSnapshot(data []byte) error {
	if len(data) < 8 {
		return &ErrInvalidInput{Field: "ecSnapshot", Reason: "data too short"}
	}
	m.sendCounter = binary.BigEndian.Uint32(data[0:4])
	m.recvCounter = binary.BigEndian.Uint32(data[4:8])
	m.chainKey = make([]byte, len(data)-8)
	copy(m.chainKey, data[8:])
	return nil
}

// failingECCipher is a mock that returns errors on encrypt or decrypt.
type failingECCipher struct {
	encryptErr error
	decryptErr error
}

func (f *failingECCipher) SendKey() ([]byte, []byte, error) {
	if f.encryptErr != nil {
		return nil, nil, f.encryptErr
	}
	return []byte("hdr"), make([]byte, 32), nil
}

func (f *failingECCipher) EncryptGetKey(_ []byte) ([]byte, []byte, []byte, error) {
	if f.encryptErr != nil {
		return nil, nil, nil, f.encryptErr
	}
	return []byte("ct"), []byte("hdr"), make([]byte, 32), nil
}

func (f *failingECCipher) ReceiveKey(_ []byte) ([]byte, error) {
	if f.decryptErr != nil {
		return nil, f.decryptErr
	}
	return make([]byte, 32), nil
}

func (f *failingECCipher) DecryptGetKey(_ []byte, _ []byte) ([]byte, []byte, error) {
	if f.decryptErr != nil {
		return nil, nil, f.decryptErr
	}
	return []byte("pt"), make([]byte, 32), nil
}

// =============================================================================
// Test Helpers
// =============================================================================

// setupAliceBob creates a matched Alice/Bob Triple Ratchet pair for testing.
func setupAliceBob(t *testing.T) (*TripleRatchet, *TripleRatchet) {
	t.Helper()

	sharedSecret := make([]byte, 32)
	fillRandom(t, sharedSecret)

	aliceCipher := newMockECCipher()
	bobCipher := newMockECCipher()

	alice, err := NewAlice(aliceCipher, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}

	bob, err := NewBob(bobCipher, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}

	return alice, bob
}

func fillRandom(t *testing.T, bufs ...[]byte) {
	t.Helper()
	for _, buf := range bufs {
		if _, err := rand.Read(buf); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
	}
}

func assertNotAllZero(t *testing.T, name string, data []byte) {
	t.Helper()
	for _, b := range data {
		if b != 0 {
			return
		}
	}
	t.Errorf("%s is all zeros", name)
}

func assertAllZero(t *testing.T, name string, data []byte) {
	t.Helper()
	for i, b := range data {
		if b != 0 {
			t.Errorf("%s[%d] = 0x%02x, want 0x00", name, i, b)
			return
		}
	}
}

// =============================================================================
// Issue PQ-C2: Epoch-scoped skipped PQ keys
// =============================================================================

func TestPQSkippedKeyIDEpochScoping(t *testing.T) {
	// Verify that pqSkippedKeyID correctly distinguishes keys from
	// different epochs with the same counter value.
	id1 := pqSkippedKeyID{Epoch: 0, Counter: 5}
	id2 := pqSkippedKeyID{Epoch: 1, Counter: 5}
	id3 := pqSkippedKeyID{Epoch: 0, Counter: 5}

	if id1 == id2 {
		t.Error("keys from different epochs should not be equal")
	}
	if id1 != id3 {
		t.Error("keys from same epoch and counter should be equal")
	}

	// Verify they work correctly as map keys.
	m := make(map[pqSkippedKeyID]int)
	m[id1] = 1
	m[id2] = 2
	if len(m) != 2 {
		t.Errorf("expected 2 distinct map entries, got %d", len(m))
	}
	if m[id1] != 1 || m[id2] != 2 {
		t.Error("map lookup returned wrong values")
	}
}

func TestAdvancePQEpochRetainsRecentSkippedKeys(t *testing.T) {
	// Verify that advancePQEpoch only purges keys from epochs older than
	// the retention window (epochsToKeepPriorToSendEpoch = 1).
	alice, _ := setupAliceBob(t)
	defer alice.Zeroize()

	// Manually inject skipped keys from epoch 0.
	s0, err := secret.New([]byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	alice.skippedPQKeys[pqSkippedKeyID{Epoch: 0, Counter: 1}] = s0

	// Advance to epoch 1. With epochsToKeepPriorToSendEpoch = 1,
	// epoch 0 keys should be retained (minRetainEpoch = max(0, 1-1) = 0).
	epochSecret := make([]byte, 32)
	fillRandom(t, epochSecret)
	if err := alice.advancePQEpoch(epochSecret); err != nil {
		t.Fatalf("advancePQEpoch to epoch 1: %v", err)
	}

	if alice.pqEpoch != 1 {
		t.Fatalf("expected pqEpoch=1, got %d", alice.pqEpoch)
	}

	// Epoch-0 key should still exist (within retention window).
	keyID := pqSkippedKeyID{Epoch: 0, Counter: 1}
	if _, ok := alice.skippedPQKeys[keyID]; !ok {
		t.Error("epoch-0 skipped key should be retained after advancing to epoch 1")
	}

	// Add a key from epoch 1.
	s1, err := secret.New([]byte{0x04, 0x05, 0x06})
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}
	alice.skippedPQKeys[pqSkippedKeyID{Epoch: 1, Counter: 2}] = s1

	// Advance to epoch 2. Now epoch 0 keys should be purged
	// (minRetainEpoch = max(0, 2-1) = 1), but epoch 1 keys remain.
	fillRandom(t, epochSecret)
	if err := alice.advancePQEpoch(epochSecret); err != nil {
		t.Fatalf("advancePQEpoch to epoch 2: %v", err)
	}

	if alice.pqEpoch != 2 {
		t.Fatalf("expected pqEpoch=2, got %d", alice.pqEpoch)
	}

	// Epoch-0 key should be purged.
	if _, ok := alice.skippedPQKeys[pqSkippedKeyID{Epoch: 0, Counter: 1}]; ok {
		t.Error("epoch-0 skipped key should be purged after advancing to epoch 2")
	}

	// Epoch-1 key should still exist.
	if _, ok := alice.skippedPQKeys[pqSkippedKeyID{Epoch: 1, Counter: 2}]; !ok {
		t.Error("epoch-1 skipped key should be retained after advancing to epoch 2")
	}
}

func TestReceivePQKeyEpochScopedLookup(t *testing.T) {
	// Verify that receivePQKey uses epoch-scoped lookup for skipped keys.
	alice, _ := setupAliceBob(t)
	defer alice.Zeroize()

	// Advance epoch so we're not in the pre-negotiation state.
	epochSecret := make([]byte, 32)
	fillRandom(t, epochSecret)
	if err := alice.advancePQEpoch(epochSecret); err != nil {
		t.Fatalf("advancePQEpoch: %v", err)
	}

	// Skip ahead to counter 3, which stores keys for counters 1 and 2.
	mk3, err := alice.receivePQKey(3)
	if err != nil {
		t.Fatalf("receivePQKey(3): %v", err)
	}
	if mk3 == nil {
		t.Fatal("expected non-nil PQ message key for counter 3")
	}
	mk3.Destroy()

	// Skipped keys should be stored with epoch-scoped IDs.
	keyID1 := pqSkippedKeyID{Epoch: alice.pqEpoch, Counter: 1}
	keyID2 := pqSkippedKeyID{Epoch: alice.pqEpoch, Counter: 2}

	if _, ok := alice.skippedPQKeys[keyID1]; !ok {
		t.Error("expected skipped key for counter 1 with current epoch")
	}
	if _, ok := alice.skippedPQKeys[keyID2]; !ok {
		t.Error("expected skipped key for counter 2 with current epoch")
	}

	// Retrieve skipped key for counter 1.
	mk1, err := alice.receivePQKey(1)
	if err != nil {
		t.Fatalf("receivePQKey(1) from skipped: %v", err)
	}
	if mk1 == nil {
		t.Fatal("expected non-nil skipped PQ message key")
	}
	mk1.Destroy()

	// Should be removed from the map now.
	if _, ok := alice.skippedPQKeys[keyID1]; ok {
		t.Error("skipped key for counter 1 should be removed after retrieval")
	}
}

// =============================================================================
// Issue PQ-C3: Epoch-0/counter-0 pre-negotiation handling
// =============================================================================

func TestReceivePQKeyEpoch0Counter0ReturnsNil(t *testing.T) {
	// In the pre-negotiation state (epoch=0, counter=0), receivePQKey
	// should return nil to signal EC-only encryption.
	alice, _ := setupAliceBob(t)
	defer alice.Zeroize()

	// Verify initial state.
	if alice.pqEpoch != 0 {
		t.Fatalf("expected initial pqEpoch=0, got %d", alice.pqEpoch)
	}

	mk, err := alice.receivePQKey(0)
	if err != nil {
		t.Fatalf("receivePQKey(0) at epoch 0: unexpected error: %v", err)
	}
	if mk != nil {
		t.Error("receivePQKey at epoch=0, counter=0 should return nil (EC-only)")
		mk.Destroy()
	}
}

func TestReceivePQKeyNonZeroEpochCounter0NotNil(t *testing.T) {
	// After advancing past epoch 0, counter=0 should NOT trigger the
	// pre-negotiation path.
	alice, _ := setupAliceBob(t)
	defer alice.Zeroize()

	// Advance to epoch 1.
	epochSecret := make([]byte, 32)
	fillRandom(t, epochSecret)
	if err := alice.advancePQEpoch(epochSecret); err != nil {
		t.Fatalf("advancePQEpoch: %v", err)
	}

	if alice.pqEpoch != 1 {
		t.Fatalf("expected pqEpoch=1, got %d", alice.pqEpoch)
	}

	// Counter=0 at epoch 1 should still be treated as "counter already consumed"
	// since recvCounter starts at 0 after epoch advance and counter=0 is not
	// ahead of position 0. The guard `counter != 0 && counter <= tr.recvCounter`
	// won't trigger for counter=0, so it will try to derive a key at counter 1
	// (since the skip loop runs from recvCounter+1 up to counter, which is 0,
	// so no skip loop runs, then it increments to recvCounter=1).
	// Actually counter=0 with recvCounter=0 will attempt to derive at counter 1.
	// Wait -- let's trace the logic:
	// - pqEpoch=1, counter=0: the epoch-0/counter-0 check fails (pqEpoch != 0)
	// - skipped key lookup for {1, 0}: miss
	// - counter != 0 is false, so the "already consumed" check is skipped
	// - counter > recvCounter is false (0 > 0 is false), so maxJump check passes
	// - skip loop: recvCounter+1 (1) < counter (0) is false, no skipping
	// - derive: recvCounter++ = 1, derives key at counter 1
	// This is actually correct -- counter=0 at a non-zero epoch still derives normally.
	mk, err := alice.receivePQKey(0)
	if err != nil {
		t.Fatalf("receivePQKey(0) at epoch 1: %v", err)
	}
	if mk == nil {
		t.Error("receivePQKey at epoch=1, counter=0 should return a valid key")
	} else {
		mk.Destroy()
	}
}

func TestEncryptDecryptWithNilPQKey(t *testing.T) {
	// Test the EC-only fallback path in Encrypt/Decrypt when the PQ key
	// is nil (pre-negotiation state).
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	// Both start at epoch 0. First message roundtrip should work using
	// the initial chain keys from KdfSckaInit.
	plaintext := []byte("pre-negotiation message")
	ct, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	pt, err := bob.Decrypt(ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(pt, plaintext) {
		t.Errorf("roundtrip mismatch: got %q, want %q", pt, plaintext)
	}
}

// errorAs is a generic-free helper for errors.As matching.
func errorAs(err error, target interface{}) bool {
	// Use type switch approach for test simplicity.
	switch target := target.(type) {
	case **ErrInvalidInput:
		v, ok := err.(*ErrInvalidInput)
		if ok {
			*target = v
		}
		return ok
	case **ErrInvalidCompositeMessage:
		v, ok := err.(*ErrInvalidCompositeMessage)
		if ok {
			*target = v
		}
		return ok
	case **ErrHybridKDFFailed:
		v, ok := err.(*ErrHybridKDFFailed)
		if ok {
			*target = v
		}
		return ok
	case **ErrECRatchetFailed:
		v, ok := err.(*ErrECRatchetFailed)
		if ok {
			*target = v
		}
		return ok
	case **ErrSPQRFailed:
		v, ok := err.(*ErrSPQRFailed)
		if ok {
			*target = v
		}
		return ok
	case **ErrMACVerificationFailed:
		v, ok := err.(*ErrMACVerificationFailed)
		if ok {
			*target = v
		}
		return ok
	}
	return false
}

// =============================================================================
// EC Ratchet Rollback on MAC Failure Tests
// =============================================================================

// TestDecryptForgedMessageDoesNotAdvanceECRatchet verifies that when a forged
// message (bad MAC) is rejected, the EC ratchet state is rolled back so that
// the original uncorrupted message still decrypts correctly.
func TestDecryptForgedMessageDoesNotAdvanceECRatchet(t *testing.T) {
	sharedSecret := make([]byte, 32)
	fillRandom(t, sharedSecret)

	aliceCipher := newMockECCipher()
	bobCipher := newMockECCipher()

	alice, err := NewAlice(aliceCipher, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := NewBob(bobCipher, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}
	defer bob.Zeroize()

	// Send a legitimate message from Alice to Bob.
	plaintext1 := []byte("hello from alice")
	ct1, err := alice.Encrypt(plaintext1)
	if err != nil {
		t.Fatalf("Encrypt msg1: %v", err)
	}

	// Decrypt it to advance both sides normally.
	pt1, err := bob.Decrypt(ct1)
	if err != nil {
		t.Fatalf("Decrypt msg1: %v", err)
	}
	if !bytes.Equal(pt1, plaintext1) {
		t.Fatalf("msg1 roundtrip: got %q, want %q", pt1, plaintext1)
	}

	// Capture Bob's EC state before the forged message.
	bobECSnap, err := bobCipher.TakeECSnapshot()
	if err != nil {
		t.Fatalf("TakeECSnapshot: %v", err)
	}

	// Alice encrypts message 2. An attacker intercepts and corrupts the MAC.
	plaintext2 := []byte("second message")
	ct2, err := alice.Encrypt(plaintext2)
	if err != nil {
		t.Fatalf("Encrypt msg2: %v", err)
	}

	// Keep the original uncorrupted ciphertext for later.
	ct2Original := make([]byte, len(ct2))
	copy(ct2Original, ct2)

	// Corrupt the last byte of the MAC to make it fail verification.
	ct2[len(ct2)-1] ^= 0xFF

	// Attempt to decrypt the forged message - should fail with MAC error.
	_, err = bob.Decrypt(ct2)
	if err == nil {
		t.Fatal("expected MAC verification failure for forged message")
	}
	var macErr *ErrMACVerificationFailed
	if !errors.As(err, &macErr) {
		t.Fatalf("expected ErrMACVerificationFailed, got: %v", err)
	}

	// Verify that Bob's EC state was rolled back to before the forged message.
	bobECSnapAfter, err := bobCipher.TakeECSnapshot()
	if err != nil {
		t.Fatalf("TakeECSnapshot after: %v", err)
	}
	if !bytes.Equal(bobECSnap, bobECSnapAfter) {
		t.Error("EC ratchet state was mutated by forged message - rollback failed")
	}

	// Now decrypt the original uncorrupted message 2 - should succeed
	// because the EC state was properly rolled back.
	pt2, err := bob.Decrypt(ct2Original)
	if err != nil {
		t.Fatalf("Decrypt original msg2 after forged attempt: %v", err)
	}
	if !bytes.Equal(pt2, plaintext2) {
		t.Fatalf("msg2 roundtrip: got %q, want %q", pt2, plaintext2)
	}
}

// TestDecryptForgedMessageMultipleAttemptsDoNotDrift verifies that the same
// forged message replayed multiple times does not cause the EC ratchet to
// drift, and that the original message still decrypts after all attempts.
func TestDecryptForgedMessageMultipleAttemptsDoNotDrift(t *testing.T) {
	sharedSecret := make([]byte, 32)
	fillRandom(t, sharedSecret)

	aliceCipher := newMockECCipher()
	bobCipher := newMockECCipher()

	alice, err := NewAlice(aliceCipher, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewAlice: %v", err)
	}
	defer alice.Zeroize()

	bob, err := NewBob(bobCipher, sharedSecret, mlkembraid.NewMLKEM768IncrementalKEM(), mlkembraid.DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewBob: %v", err)
	}
	defer bob.Zeroize()

	// Alice encrypts a message. Keep the original.
	plaintext := []byte("important message")
	ct, err := alice.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ctOriginal := make([]byte, len(ct))
	copy(ctOriginal, ct)

	// Capture Bob's EC state before any forged attempts.
	initialECSnap, err := bobCipher.TakeECSnapshot()
	if err != nil {
		t.Fatalf("TakeECSnapshot: %v", err)
	}

	// Create corrupted version.
	ctForged := make([]byte, len(ct))
	copy(ctForged, ct)
	ctForged[len(ctForged)-1] ^= 0xFF

	// Replay the forged message 5 times.
	for i := 0; i < 5; i++ {
		_, decErr := bob.Decrypt(ctForged)
		if decErr == nil {
			t.Fatalf("forged attempt %d should have failed", i)
		}
		var macErr *ErrMACVerificationFailed
		if !errors.As(decErr, &macErr) {
			t.Fatalf("forged attempt %d: expected ErrMACVerificationFailed, got: %v", i, decErr)
		}
	}

	// Verify EC state is unchanged after all forged attempts.
	afterForgedSnap, err := bobCipher.TakeECSnapshot()
	if err != nil {
		t.Fatalf("TakeECSnapshot after forged: %v", err)
	}
	if !bytes.Equal(initialECSnap, afterForgedSnap) {
		t.Error("EC ratchet state drifted after multiple forged messages")
	}

	// The original message should still decrypt correctly.
	pt, err := bob.Decrypt(ctOriginal)
	if err != nil {
		t.Fatalf("Decrypt original after forged attempts: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("roundtrip: got %q, want %q", pt, plaintext)
	}
}

// TestMockECCipherImplementsSnapshotable verifies the mock implements the
// ECCipherSnapshotable interface at compile time.
func TestMockECCipherImplementsSnapshotable(t *testing.T) {
	var ec ECCipher = newMockECCipher()
	_, ok := ec.(ECCipherSnapshotable)
	if !ok {
		t.Fatal("mockECCipher does not implement ECCipherSnapshotable")
	}
}

// TestECSnapshotRestoreRoundtrip verifies that taking and restoring an EC
// snapshot produces identical state.
func TestECSnapshotRestoreRoundtrip(t *testing.T) {
	m := newMockECCipher()

	// Advance state.
	_, _, err := m.SendKey()
	if err != nil {
		t.Fatalf("SendKey: %v", err)
	}
	_, err = m.ReceiveKey([]byte{0, 0, 0, 1})
	if err != nil {
		t.Fatalf("ReceiveKey: %v", err)
	}

	// Snapshot.
	snap, err := m.TakeECSnapshot()
	if err != nil {
		t.Fatalf("TakeECSnapshot: %v", err)
	}

	// Advance further.
	_, _, err = m.SendKey()
	if err != nil {
		t.Fatalf("SendKey 2: %v", err)
	}

	// Restore.
	if err := m.RestoreECSnapshot(snap); err != nil {
		t.Fatalf("RestoreECSnapshot: %v", err)
	}

	// Verify restored state matches snapshot.
	snap2, err := m.TakeECSnapshot()
	if err != nil {
		t.Fatalf("TakeECSnapshot 2: %v", err)
	}
	if !bytes.Equal(snap, snap2) {
		t.Error("EC state not properly restored from snapshot")
	}
}
