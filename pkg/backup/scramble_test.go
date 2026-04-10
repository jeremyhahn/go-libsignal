package backup

import (
	"bytes"
	"testing"
)

func TestScramblerReplaceE164(t *testing.T) {
	s := NewScrambler()

	t.Run("first replacement starts at e164Start", func(t *testing.T) {
		got := s.ReplaceE164(12025551234)
		if got != e164Start {
			t.Errorf("first ReplaceE164 = %d, want %d", got, e164Start)
		}
	})

	t.Run("second replacement increments", func(t *testing.T) {
		got := s.ReplaceE164(12025555678)
		if got != e164Start+1 {
			t.Errorf("second ReplaceE164 = %d, want %d", got, e164Start+1)
		}
	})

	t.Run("same input returns same replacement", func(t *testing.T) {
		got := s.ReplaceE164(12025551234)
		if got != e164Start {
			t.Errorf("repeated ReplaceE164 = %d, want %d", got, e164Start)
		}
	})

	t.Run("third unique input gets next value", func(t *testing.T) {
		got := s.ReplaceE164(44207946000)
		if got != e164Start+2 {
			t.Errorf("third ReplaceE164 = %d, want %d", got, e164Start+2)
		}
	})
}

func TestScramblerReplaceServiceID(t *testing.T) {
	s := NewScrambler()

	t.Run("empty field unchanged", func(t *testing.T) {
		got := s.ReplaceServiceID(nil)
		if got != nil {
			t.Errorf("nil input should return nil, got %v", got)
		}
		got = s.ReplaceServiceID([]byte{})
		if len(got) != 0 {
			t.Errorf("empty input should return empty, got %v", got)
		}
	})

	t.Run("nil UUID unchanged", func(t *testing.T) {
		nilUUID := make([]byte, 16)
		got := s.ReplaceServiceID(nilUUID)
		if !bytes.Equal(got, nilUUID) {
			t.Errorf("nil UUID should be unchanged, got %x", got)
		}
	})

	t.Run("16 byte UUID replaced with v4 UUID", func(t *testing.T) {
		original := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		got := s.ReplaceServiceID(original)
		if len(got) != 16 {
			t.Fatalf("expected 16 byte result, got %d", len(got))
		}
		if bytes.Equal(got, original) {
			t.Error("UUID should be replaced")
		}
		// Verify v4 UUID format.
		if got[6]&0xf0 != 0x40 {
			t.Errorf("version nibble should be 4, got 0x%02x", got[6])
		}
		if got[8]&0xc0 != 0x80 {
			t.Errorf("variant bits should be 10xx, got 0x%02x", got[8])
		}
	})

	t.Run("17 byte ServiceId preserves type byte", func(t *testing.T) {
		original := make([]byte, 17)
		original[0] = 0x01 // PNI prefix
		for i := 1; i < 17; i++ {
			original[i] = byte(i)
		}
		got := s.ReplaceServiceID(original)
		if len(got) != 17 {
			t.Fatalf("expected 17 byte result, got %d", len(got))
		}
		if got[0] != 0x01 {
			t.Errorf("type byte should be preserved, got 0x%02x", got[0])
		}
	})

	t.Run("consistent replacement", func(t *testing.T) {
		original := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22,
			0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00}
		first := s.ReplaceServiceID(original)
		second := s.ReplaceServiceID(original)
		if !bytes.Equal(first, second) {
			t.Errorf("same input should produce same output:\n  first  %x\n  second %x",
				first, second)
		}
	})

	t.Run("odd length field padded with 0xff", func(t *testing.T) {
		original := make([]byte, 20)
		for i := range original {
			original[i] = byte(i + 0xf0)
		}
		got := s.ReplaceServiceID(original)
		if len(got) != 20 {
			t.Fatalf("expected 20 byte result, got %d", len(got))
		}
		// Bytes beyond UUID length should be 0xff.
		for i := 16; i < 20; i++ {
			if got[i] != 0xff {
				t.Errorf("padding byte at %d should be 0xff, got 0x%02x", i, got[i])
			}
		}
	})

	t.Run("replacement does not alias original", func(t *testing.T) {
		original := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		got := s.ReplaceServiceID(original)
		got[0] = 0xff
		got2 := s.ReplaceServiceID(original)
		if got2[0] == 0xff {
			t.Error("modifying returned slice should not affect cached replacement")
		}
	})
}

func TestScramblerNextUsername(t *testing.T) {
	s := NewScrambler()

	tests := []struct {
		want string
	}{
		{"user.01"},
		{"user.02"},
		{"user.03"},
	}
	for _, tt := range tests {
		got := s.NextUsername()
		if got != tt.want {
			t.Errorf("NextUsername() = %q, want %q", got, tt.want)
		}
	}
}

func TestScramblerRandomizeBytes(t *testing.T) {
	s := NewScrambler()
	data := make([]byte, 32)
	s.RandomizeBytes(data)

	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("randomized bytes should not all be zero")
	}
}

func TestScramblerRandomizeString(t *testing.T) {
	s := NewScrambler()

	t.Run("empty string unchanged", func(t *testing.T) {
		got := s.RandomizeString("")
		if got != "" {
			t.Errorf("empty string should remain empty, got %q", got)
		}
	})

	t.Run("same length", func(t *testing.T) {
		original := "hello world"
		got := s.RandomizeString(original)
		if len(got) != len(original) {
			t.Errorf("length mismatch: got %d, want %d", len(got), len(original))
		}
	})

	t.Run("alphanumeric characters only", func(t *testing.T) {
		got := s.RandomizeString("test string 12345")
		for _, c := range got {
			if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				t.Errorf("non-alphanumeric character %q in randomized string", c)
			}
		}
	})
}

func TestScramblerRandomizeIntegers(t *testing.T) {
	s := NewScrambler()

	t.Run("uint64", func(t *testing.T) {
		v := s.RandomizeUint64()
		// With seed 0 and xorshift, the result should be non-zero.
		if v == 0 {
			t.Error("randomized uint64 should not be zero with default seed")
		}
	})

	t.Run("uint32", func(t *testing.T) {
		v := s.RandomizeUint32()
		_ = v // Just verify it doesn't panic.
	})
}

func TestScramblerRandomUUID(t *testing.T) {
	s := NewScrambler()
	uuid := s.RandomUUID()

	if len(uuid) != 16 {
		t.Fatalf("UUID length = %d, want 16", len(uuid))
	}

	// Version 4.
	if uuid[6]&0xf0 != 0x40 {
		t.Errorf("version nibble = 0x%02x, want 0x40", uuid[6]&0xf0)
	}

	// Variant bits (10xx).
	if uuid[8]&0xc0 != 0x80 {
		t.Errorf("variant bits = 0x%02x, want 0x80", uuid[8]&0xc0)
	}

	// Generate another and verify they differ.
	uuid2 := s.RandomUUID()
	if bytes.Equal(uuid, uuid2) {
		t.Error("two sequential UUIDs should differ")
	}
}

func TestScrambleContentType(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"image/jpeg", "image/unknown"},
		{"video/mp4", "video/unknown"},
		{"application/pdf", "application/unknown"},
		{"text/plain", "text/unknown"},
		{"unknown", "unknown"},
		{"", "unknown"},
		{"audio/mpeg", "audio/unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ScrambleContentType(tt.input)
			if got != tt.want {
				t.Errorf("ScrambleContentType(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestReplacementConstants(t *testing.T) {
	if got := ReplacementBodyText(); got != replacementBodyText {
		t.Errorf("ReplacementBodyText() = %q", got)
	}
	if got := ReplacementEmoji(); got != replacementEmoji {
		t.Errorf("ReplacementEmoji() = %q", got)
	}
	if got := ReplacementURL(); got != replacementURL {
		t.Errorf("ReplacementURL() = %q", got)
	}
}

func TestScramblerDeterministic(t *testing.T) {
	// Two scramblers with the same seed should produce identical results.
	s1 := NewScramblerWithSeed(42)
	s2 := NewScramblerWithSeed(42)

	for i := 0; i < 10; i++ {
		if s1.RandomizeUint64() != s2.RandomizeUint64() {
			t.Fatalf("iteration %d: scramblers with same seed produced different uint64", i)
		}
	}

	// Strings should match too.
	str1 := s1.RandomizeString("hello world")
	str2 := s2.RandomizeString("hello world")
	if str1 != str2 {
		t.Errorf("scramblers with same seed produced different strings: %q vs %q", str1, str2)
	}
}

func TestScramblerDifferentSeeds(t *testing.T) {
	s1 := NewScramblerWithSeed(0)
	s2 := NewScramblerWithSeed(99)

	// Different seeds should (almost certainly) produce different output.
	v1 := s1.RandomizeUint64()
	v2 := s2.RandomizeUint64()
	if v1 == v2 {
		t.Error("different seeds should produce different output")
	}
}

func TestCryptoRandomUUID(t *testing.T) {
	uuid, err := CryptoRandomUUID()
	if err != nil {
		t.Fatalf("CryptoRandomUUID: %v", err)
	}
	if len(uuid) != 16 {
		t.Fatalf("UUID length = %d, want 16", len(uuid))
	}
	// Version 4.
	if uuid[6]&0xf0 != 0x40 {
		t.Errorf("version nibble = 0x%02x, want 0x40", uuid[6]&0xf0)
	}
	// Variant bits.
	if uuid[8]&0xc0 != 0x80 {
		t.Errorf("variant bits = 0x%02x, want 0x80", uuid[8]&0xc0)
	}
}

func TestCryptoRandomizeBytes(t *testing.T) {
	data := make([]byte, 32)
	if err := CryptoRandomizeBytes(data); err != nil {
		t.Fatalf("CryptoRandomizeBytes: %v", err)
	}
	allZero := true
	for _, b := range data {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("crypto randomized bytes should not all be zero")
	}
}

func TestCryptoRandomUint64(t *testing.T) {
	_, err := CryptoRandomUint64()
	if err != nil {
		t.Fatalf("CryptoRandomUint64: %v", err)
	}
}

func TestCryptoRandomUint32(t *testing.T) {
	_, err := CryptoRandomUint32()
	if err != nil {
		t.Fatalf("CryptoRandomUint32: %v", err)
	}
}

func TestScramblerErrorString(t *testing.T) {
	t.Run("with inner error", func(t *testing.T) {
		inner := &ScramblerError{Op: "inner op"}
		e := &ScramblerError{Op: "outer op", Err: inner}
		got := e.Error()
		if got != "scramble: outer op: scramble: inner op" {
			t.Errorf("Error() = %q", got)
		}
		if e.Unwrap() != inner {
			t.Error("Unwrap() should return inner error")
		}
	})

	t.Run("without inner error", func(t *testing.T) {
		e := &ScramblerError{Op: "test op"}
		got := e.Error()
		if got != "scramble: test op" {
			t.Errorf("Error() = %q", got)
		}
		if e.Unwrap() != nil {
			t.Error("Unwrap() should return nil")
		}
	})
}
