package tripleratchet

import (
	"encoding/binary"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid"
)

// TestDeserializeCompositeHeaderInsufficientSCKAFields exercises the branch
// where the composite header has a valid EC header but insufficient remaining
// data for the SCKA fields (epoch + type + data length).
func TestDeserializeCompositeHeaderInsufficientSCKAFields(t *testing.T) {
	// Build data: 4 bytes EC header len (= 1) + 1 byte EC header + only 5 more bytes
	// (insufficient for epochSize(8) + messageTypeSize(1) + dataLenSize(4) = 13 bytes)
	ecLen := 1
	remaining := 5 // Less than epochSize + messageTypeSize + dataLenSize
	totalLen := ecHeaderLenSize + ecLen + remaining
	data := make([]byte, totalLen)
	binary.BigEndian.PutUint32(data[0:], uint32(ecLen))
	data[ecHeaderLenSize] = 0xAA // EC header byte

	_, err := DeserializeCompositeHeader(data)
	if err == nil {
		t.Fatal("expected error for insufficient SCKA header fields")
	}
	var compErr *ErrInvalidCompositeMessage
	if !errorAs(err, &compErr) {
		t.Errorf("expected ErrInvalidCompositeMessage, got %T: %v", err, err)
	}
}

// TestDeserializeCompositeMessageWithCorruptedHeader exercises the
// deserializeCompositeMessage path where the header bytes are valid length
// but cannot be deserialized as a CompositeHeader.
func TestDeserializeCompositeMessageWithCorruptedHeader(t *testing.T) {
	// Build a composite message with valid framing but garbage header content
	// that is too short to be a valid composite header.
	headerBytes := []byte{0x01, 0x02, 0x03} // Too short for compositeHeaderMinSize
	ctBytes := []byte("ciphertext")

	totalSize := headerLenPrefixSize + len(headerBytes) + ciphertextLenPrefixSize + len(ctBytes)
	buf := make([]byte, totalSize)

	offset := 0
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(headerBytes)))
	offset += headerLenPrefixSize
	copy(buf[offset:], headerBytes)
	offset += len(headerBytes)
	binary.BigEndian.PutUint32(buf[offset:], uint32(len(ctBytes)))
	offset += ciphertextLenPrefixSize
	copy(buf[offset:], ctBytes)

	_, _, err := deserializeCompositeMessage(buf)
	if err == nil {
		t.Fatal("expected error for corrupted header bytes")
	}
}

// TestTripleRatchetDecryptWithTruncatedCompositeMessage exercises the Decrypt
// path with a message that has valid framing but truncated content.
func TestTripleRatchetDecryptWithTruncatedCompositeMessage(t *testing.T) {
	_, bob := setupAliceBob(t)
	defer bob.Zeroize()

	// A message that passes the minimum size check but has invalid structure.
	invalidMsg := make([]byte, compositeMessageMinSize+10)
	binary.BigEndian.PutUint32(invalidMsg[0:], 0) // zero-length header
	// No valid composite header follows, so deserialization should fail.

	_, err := bob.Decrypt(invalidMsg)
	if err == nil {
		t.Fatal("expected error for truncated composite message")
	}
}

// TestTripleRatchetEncryptDecryptRoundTripConsistency verifies that multiple
// sequential encrypt/decrypt operations produce correct results with different
// hybrid key material each time.
func TestTripleRatchetEncryptDecryptRoundTripConsistency(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	for i := 0; i < 5; i++ {
		msg := []byte("message-" + string(rune('0'+i)))
		ct, err := alice.Encrypt(msg)
		if err != nil {
			t.Fatalf("Encrypt %d: %v", i, err)
		}

		pt, err := bob.Decrypt(ct)
		if err != nil {
			t.Fatalf("Decrypt %d: %v", i, err)
		}

		if string(pt) != string(msg) {
			t.Errorf("message %d: got %q, want %q", i, pt, msg)
		}
	}
}

// TestTripleRatchetDecryptCiphertextExactlyMACSize exercises the boundary
// where the ciphertext is exactly HMACSize bytes (no payload, only MAC).
func TestTripleRatchetDecryptCiphertextExactlyMACSize(t *testing.T) {
	alice, bob := setupAliceBob(t)
	defer alice.Zeroize()
	defer bob.Zeroize()

	// Encrypt a valid message to get a valid header.
	ct, err := alice.Encrypt([]byte("test"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// Parse and replace ciphertext with exactly HMACSize bytes (all zeros).
	header, _, err := deserializeCompositeMessage(ct)
	if err != nil {
		t.Fatalf("deserializeCompositeMessage: %v", err)
	}

	// Ciphertext of exactly HMACSize: empty payload + 32 byte MAC.
	exactMAC := make([]byte, HMACSize)
	modifiedMsg, err := serializeCompositeMessage(header, exactMAC)
	if err != nil {
		t.Fatalf("serializeCompositeMessage: %v", err)
	}

	// Should proceed to MAC verification (and fail due to wrong MAC).
	_, err = bob.Decrypt(modifiedMsg)
	if err == nil {
		t.Fatal("expected error for invalid MAC")
	}
}

// TestCompositeHeaderLargeECHeader exercises serialization with a large EC header
// to ensure the length encoding works for larger payloads.
func TestCompositeHeaderLargeECHeader(t *testing.T) {
	largeECHeader := make([]byte, 1024)
	for i := range largeECHeader {
		largeECHeader[i] = byte(i % 256)
	}

	header := &CompositeHeader{
		ECHeader: largeECHeader,
		SCKAMsg: &mlkembraid.Message{
			Epoch: 99,
			Type:  mlkembraid.MessageTypeCt2,
			Data:  []byte("large-header-test"),
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

	if len(restored.ECHeader) != 1024 {
		t.Errorf("ECHeader length = %d, want 1024", len(restored.ECHeader))
	}
	if restored.SCKAMsg.Epoch != 99 {
		t.Errorf("Epoch = %d, want 99", restored.SCKAMsg.Epoch)
	}
}

// TestComputeHMAC exercises the computeHMAC function directly.
func TestComputeHMAC(t *testing.T) {
	key := make([]byte, 32)
	fillRandom(t, key)
	data := []byte("test data for HMAC computation")

	mac1 := computeHMAC(key, data)
	if len(mac1) != HMACSize {
		t.Fatalf("HMAC length = %d, want %d", len(mac1), HMACSize)
	}

	// Same input should produce same MAC (deterministic).
	mac2 := computeHMAC(key, data)
	if string(mac1) != string(mac2) {
		t.Error("computeHMAC is not deterministic")
	}

	// Different data should produce different MAC.
	mac3 := computeHMAC(key, []byte("different data"))
	if string(mac1) == string(mac3) {
		t.Error("different data should produce different MAC")
	}
}

// TestCopyBytesNil exercises the nil path in copyBytes.
func TestCopyBytesNil(t *testing.T) {
	result := copyBytes(nil)
	if result != nil {
		t.Fatal("copyBytes(nil) should return nil")
	}
}

// TestCopyBytesNonNil exercises the non-nil path in copyBytes.
func TestCopyBytesNonNil(t *testing.T) {
	src := []byte{1, 2, 3, 4, 5}
	dst := copyBytes(src)
	if dst == nil {
		t.Fatal("copyBytes should return non-nil for non-nil input")
	}
	if len(dst) != len(src) {
		t.Fatalf("length mismatch: got %d, want %d", len(dst), len(src))
	}
	for i := range src {
		if dst[i] != src[i] {
			t.Fatalf("byte %d: got %d, want %d", i, dst[i], src[i])
		}
	}
	// Verify independence.
	src[0] = 0xFF
	if dst[0] == 0xFF {
		t.Fatal("copyBytes should return an independent copy")
	}
}

// TestCopyBytesEmpty exercises copyBytes with an empty slice.
func TestCopyBytesEmpty(t *testing.T) {
	result := copyBytes([]byte{})
	if result == nil {
		t.Fatal("copyBytes of empty slice should return non-nil empty slice")
	}
	if len(result) != 0 {
		t.Fatalf("expected empty slice, got %d bytes", len(result))
	}
}

// TestKDFHybridSuccess verifies successful hybrid key derivation.
func TestKDFHybridSuccess(t *testing.T) {
	ecMK := make([]byte, 32)
	pqMK := make([]byte, 32)
	fillRandom(t, ecMK)
	fillRandom(t, pqMK)

	keys, err := KDFHybrid(ecMK, pqMK)
	if err != nil {
		t.Fatalf("KDFHybrid: %v", err)
	}
	defer keys.Zeroize()

	if keys.CipherKey.Size() != CipherKeySize {
		t.Errorf("CipherKey size = %d, want %d", keys.CipherKey.Size(), CipherKeySize)
	}
	if keys.MacKey.Size() != MacKeySize {
		t.Errorf("MacKey size = %d, want %d", keys.MacKey.Size(), MacKeySize)
	}
	if keys.IV.Size() != IVSize {
		t.Errorf("IV size = %d, want %d", keys.IV.Size(), IVSize)
	}
}

// TestKDFHybridECOnlySuccess verifies successful EC-only key derivation.
func TestKDFHybridECOnlySuccess(t *testing.T) {
	ecMK := make([]byte, 32)
	fillRandom(t, ecMK)

	keys, err := KDFHybridECOnly(ecMK)
	if err != nil {
		t.Fatalf("KDFHybridECOnly: %v", err)
	}
	defer keys.Zeroize()

	if keys.CipherKey.Size() != CipherKeySize {
		t.Errorf("CipherKey size = %d, want %d", keys.CipherKey.Size(), CipherKeySize)
	}
}

// TestHybridKeysZeroizePartial verifies that Zeroize with nil fields is safe.
func TestHybridKeysZeroizePartial(t *testing.T) {
	hk := &HybridKeys{}
	hk.Zeroize() // must not panic
}

// TestXorKeysEmpty exercises xorKeys with empty inputs.
func TestXorKeysEmpty(t *testing.T) {
	result, err := xorKeys([]byte{}, []byte{1, 2, 3})
	if err != nil {
		t.Fatalf("xorKeys with empty first arg: %v", err)
	}
	if result.Size() != 0 {
		t.Errorf("xorKeys with empty first arg should return empty, got %d bytes", result.Size())
	}
	result.Destroy()

	result, err = xorKeys([]byte{1, 2, 3}, []byte{})
	if err != nil {
		t.Fatalf("xorKeys with empty second arg: %v", err)
	}
	if result.Size() != 0 {
		t.Errorf("xorKeys with empty second arg should return empty, got %d bytes", result.Size())
	}
	result.Destroy()
}
