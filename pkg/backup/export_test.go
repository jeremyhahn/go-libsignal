package backup

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	libcipher "github.com/jeremyhahn/go-libsignal/pkg/cipher"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

func TestGzipCompress(t *testing.T) {
	t.Run("empty data", func(t *testing.T) {
		compressed, err := GzipCompress([]byte{})
		if err != nil {
			t.Fatalf("GzipCompress: %v", err)
		}
		if len(compressed) == 0 {
			t.Fatal("expected non-empty compressed output for empty input")
		}
		// Decompress to verify.
		gzr, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatalf("gzip.NewReader: %v", err)
		}
		got, err := io.ReadAll(gzr)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("decompressed empty data should be empty, got %d bytes", len(got))
		}
	})

	t.Run("round trip", func(t *testing.T) {
		data := []byte("hello, this is backup data for testing gzip compression")
		compressed, err := GzipCompress(data)
		if err != nil {
			t.Fatalf("GzipCompress: %v", err)
		}
		if len(compressed) == 0 {
			t.Fatal("expected non-empty compressed output")
		}
		// Decompress and verify.
		gzr, err := gzip.NewReader(bytes.NewReader(compressed))
		if err != nil {
			t.Fatalf("gzip.NewReader: %v", err)
		}
		got, err := io.ReadAll(gzr)
		if err != nil {
			t.Fatalf("ReadAll: %v", err)
		}
		if !bytes.Equal(got, data) {
			t.Errorf("round trip mismatch: got %q, want %q", got, data)
		}
	})

	t.Run("compresses large data", func(t *testing.T) {
		data := bytes.Repeat([]byte("A"), 10000)
		compressed, err := GzipCompress(data)
		if err != nil {
			t.Fatalf("GzipCompress: %v", err)
		}
		if len(compressed) >= len(data) {
			t.Errorf("expected compression, but compressed (%d) >= original (%d)",
				len(compressed), len(data))
		}
	})
}

func TestPadGzippedBucketed(t *testing.T) {
	t.Run("small data padded to minimum", func(t *testing.T) {
		data := make([]byte, 100)
		padded := PadGzippedBucketed(data)
		if uint32(len(padded)) < 541 {
			t.Errorf("padded length %d, want >= 541", len(padded))
		}
		// Original data should be preserved at the start.
		if !bytes.Equal(padded[:100], data) {
			t.Error("original data not preserved in padded output")
		}
		// Padding bytes should be zero.
		for i := 100; i < len(padded); i++ {
			if padded[i] != 0 {
				t.Errorf("padding byte at index %d is %d, want 0", i, padded[i])
				break
			}
		}
	})

	t.Run("data at minimum stays at minimum", func(t *testing.T) {
		data := make([]byte, 541)
		padded := PadGzippedBucketed(data)
		if len(padded) != 541 {
			t.Errorf("padded length %d, want 541", len(padded))
		}
	})

	t.Run("larger data pads to bucket", func(t *testing.T) {
		data := make([]byte, 1000)
		padded := PadGzippedBucketed(data)
		if len(padded) < 1000 {
			t.Errorf("padded length %d, want >= 1000", len(padded))
		}
		expectedLen := PaddedLength(1000)
		if uint32(len(padded)) != expectedLen {
			t.Errorf("padded length %d, want %d", len(padded), expectedLen)
		}
	})

	t.Run("preserves original data", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
		padded := PadGzippedBucketed(data)
		if !bytes.Equal(padded[:5], data) {
			t.Error("original data not preserved at start of padded output")
		}
	})
}

func TestAESCBCEncryptExport(t *testing.T) {
	key := make([]byte, 32)
	iv := make([]byte, 16)
	for i := range key {
		key[i] = byte(i)
	}
	for i := range iv {
		iv[i] = byte(i + 32)
	}

	t.Run("encrypt and decrypt round trip", func(t *testing.T) {
		plaintext := []byte("this is backup export test data!")
		ciphertext, err := AESCBCEncryptExport(key, iv, plaintext)
		if err != nil {
			t.Fatalf("AESCBCEncryptExport: %v", err)
		}
		if len(ciphertext) == 0 {
			t.Fatal("expected non-empty ciphertext")
		}
		if len(ciphertext)%AESBlockSize != 0 {
			t.Errorf("ciphertext length %d not a multiple of %d", len(ciphertext), AESBlockSize)
		}
		// Decrypt using cipher package.
		decrypted, err := libcipher.AESCBCDecrypt(key, iv, ciphertext)
		if err != nil {
			t.Fatalf("AESCBCDecrypt: %v", err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Errorf("decrypt mismatch: got %q, want %q", decrypted, plaintext)
		}
	})

	t.Run("invalid key size", func(t *testing.T) {
		_, err := AESCBCEncryptExport([]byte("short"), iv, []byte("data"))
		if err == nil {
			t.Fatal("expected error for invalid key size")
		}
		exportErr, ok := err.(*ExportError)
		if !ok {
			t.Fatalf("expected *ExportError, got %T", err)
		}
		if exportErr.Op != "AES-CBC encrypt" {
			t.Errorf("Op = %q, want %q", exportErr.Op, "AES-CBC encrypt")
		}
	})

	t.Run("invalid IV size", func(t *testing.T) {
		_, err := AESCBCEncryptExport(key, []byte("short"), []byte("data"))
		if err == nil {
			t.Fatal("expected error for invalid IV size")
		}
	})

	t.Run("ciphertext differs from plaintext", func(t *testing.T) {
		plaintext := []byte("sensitive backup data here")
		ciphertext, err := AESCBCEncryptExport(key, iv, plaintext)
		if err != nil {
			t.Fatalf("AESCBCEncryptExport: %v", err)
		}
		if bytes.Equal(ciphertext, plaintext) {
			t.Error("ciphertext should differ from plaintext")
		}
	})
}

func TestHMACChecksum(t *testing.T) {
	t.Run("known value", func(t *testing.T) {
		hmacKey := make([]byte, 32)
		for i := range hmacKey {
			hmacKey[i] = byte(i)
		}
		iv := make([]byte, 16)
		for i := range iv {
			iv[i] = byte(i + 64)
		}
		data := []byte("encrypted backup contents")

		got := HMACChecksum(hmacKey, iv, data)
		if len(got) != 32 {
			t.Fatalf("HMAC length = %d, want 32", len(got))
		}

		// Verify against standard library HMAC.
		mac := hmac.New(sha256.New, hmacKey)
		mac.Write(iv)
		mac.Write(data)
		expected := mac.Sum(nil)
		if !bytes.Equal(got, expected) {
			t.Errorf("HMAC mismatch:\n  got  %s\n  want %s",
				hex.EncodeToString(got), hex.EncodeToString(expected))
		}
	})

	t.Run("different keys produce different HMACs", func(t *testing.T) {
		iv := make([]byte, 16)
		data := []byte("test data")
		key1 := make([]byte, 32)
		key2 := make([]byte, 32)
		key2[0] = 1

		hmac1 := HMACChecksum(key1, iv, data)
		hmac2 := HMACChecksum(key2, iv, data)
		if bytes.Equal(hmac1, hmac2) {
			t.Error("different keys should produce different HMACs")
		}
	})

	t.Run("different IVs produce different HMACs", func(t *testing.T) {
		hmacKey := make([]byte, 32)
		data := []byte("test data")
		iv1 := make([]byte, 16)
		iv2 := make([]byte, 16)
		iv2[0] = 1

		hmac1 := HMACChecksum(hmacKey, iv1, data)
		hmac2 := HMACChecksum(hmacKey, iv2, data)
		if bytes.Equal(hmac1, hmac2) {
			t.Error("different IVs should produce different HMACs")
		}
	})

	t.Run("empty data", func(t *testing.T) {
		hmacKey := make([]byte, 32)
		iv := make([]byte, 16)
		got := HMACChecksum(hmacKey, iv, nil)
		if len(got) != 32 {
			t.Fatalf("HMAC length = %d, want 32", len(got))
		}
	})
}

func TestExportErrorString(t *testing.T) {
	t.Run("with inner error", func(t *testing.T) {
		inner := io.ErrUnexpectedEOF
		e := &ExportError{Op: "compress", Err: inner}
		got := e.Error()
		if got != "backup export: compress: unexpected EOF" {
			t.Errorf("Error() = %q", got)
		}
		if e.Unwrap() != inner {
			t.Error("Unwrap() should return inner error")
		}
	})

	t.Run("without inner error", func(t *testing.T) {
		e := &ExportError{Op: "pad"}
		got := e.Error()
		if got != "backup export: pad" {
			t.Errorf("Error() = %q", got)
		}
		if e.Unwrap() != nil {
			t.Error("Unwrap() should return nil")
		}
	})
}

func TestExportFullPipeline(t *testing.T) {
	// Test the full export pipeline: compress -> pad -> encrypt -> HMAC.
	plaintext := []byte("this is a full backup frame content for integration testing")

	// Step 1: Gzip compress.
	compressed, err := GzipCompress(plaintext)
	if err != nil {
		t.Fatalf("GzipCompress: %v", err)
	}

	// Step 2: Pad to bucketed size.
	padded := PadGzippedBucketed(compressed)
	if uint32(len(padded)) < PaddedLength(uint32(len(compressed))) {
		t.Errorf("padded length %d < expected %d", len(padded), PaddedLength(uint32(len(compressed))))
	}

	// Step 3: Encrypt with AES-CBC.
	key := testKey()
	iv := make([]byte, AESIVSize)
	for i := range iv {
		iv[i] = byte(i)
	}
	ciphertext, err := []byte(nil), error(nil)
	secrettest.With(t, key.AESKey, func(k []byte) { ciphertext, err = AESCBCEncryptExport(k, iv, padded) })
	if err != nil {
		t.Fatalf("AESCBCEncryptExport: %v", err)
	}

	// Step 4: Compute HMAC.
	var checksum []byte
	secrettest.With(t, key.HMACKey, func(k []byte) { checksum = HMACChecksum(k, iv, ciphertext) })
	if len(checksum) != HMACLen {
		t.Fatalf("HMAC length = %d, want %d", len(checksum), HMACLen)
	}

	// Verify: decrypt and decompress should recover original.
	decrypted, err := []byte(nil), error(nil)
	secrettest.With(t, key.AESKey, func(k []byte) { decrypted, err = libcipher.AESCBCDecrypt(k, iv, ciphertext) })
	if err != nil {
		t.Fatalf("AESCBCDecrypt: %v", err)
	}

	// The decrypted data is padded gzip; decompress.
	// Disable multistream since padding bytes follow the gzip stream.
	gzr, err := gzip.NewReader(bytes.NewReader(decrypted))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	gzr.Multistream(false)
	recovered, err := io.ReadAll(gzr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Errorf("full pipeline round trip failed: got %q, want %q", recovered, plaintext)
	}
}
