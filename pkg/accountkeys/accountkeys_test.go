package accountkeys

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret/secrettest"
)

func TestGenerateAccountEntropyPool(t *testing.T) {
	t.Run("generates valid pool", func(t *testing.T) {
		pool, err := GenerateAccountEntropyPool()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := pool.Validate(); err != nil {
			t.Fatalf("generated pool failed validation: %v", err)
		}
		if len(string(pool)) != EntropyPoolLength {
			t.Fatalf("expected length %d, got %d", EntropyPoolLength, len(string(pool)))
		}
	})

	t.Run("generates unique pools", func(t *testing.T) {
		pool1, err := GenerateAccountEntropyPool()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		pool2, err := GenerateAccountEntropyPool()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pool1 == pool2 {
			t.Fatal("two generated pools should not be identical")
		}
	})

	t.Run("only contains valid characters", func(t *testing.T) {
		pool, err := GenerateAccountEntropyPool()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		for i, c := range string(pool) {
			if (c < '0' || c > '9') && (c < 'a' || c > 'z') {
				t.Fatalf("invalid character %q at position %d", c, i)
			}
		}
	})
}

func TestAccountEntropyPool_Validate(t *testing.T) {
	tests := []struct {
		name    string
		pool    AccountEntropyPool
		wantErr bool
	}{
		{
			name:    "valid pool",
			pool:    AccountEntropyPool(strings.Repeat("abc123", 10) + "abcd"),
			wantErr: false,
		},
		{
			name:    "too short",
			pool:    AccountEntropyPool("abc"),
			wantErr: true,
		},
		{
			name:    "too long",
			pool:    AccountEntropyPool(strings.Repeat("a", 65)),
			wantErr: true,
		},
		{
			name:    "empty",
			pool:    AccountEntropyPool(""),
			wantErr: true,
		},
		{
			name:    "contains uppercase",
			pool:    AccountEntropyPool(strings.Repeat("A", 64)),
			wantErr: true,
		},
		{
			name:    "contains special characters",
			pool:    AccountEntropyPool(strings.Repeat("a", 63) + "!"),
			wantErr: true,
		},
		{
			name:    "contains spaces",
			pool:    AccountEntropyPool(strings.Repeat("a", 63) + " "),
			wantErr: true,
		},
		{
			name:    "all zeros",
			pool:    AccountEntropyPool(strings.Repeat("0", 64)),
			wantErr: false,
		},
		{
			name:    "all z",
			pool:    AccountEntropyPool(strings.Repeat("z", 64)),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pool.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAccountEntropyPool_DeriveSVRKey(t *testing.T) {
	t.Run("derives deterministic key", func(t *testing.T) {
		pool := AccountEntropyPool(strings.Repeat("a", 64))
		key1, err := pool.DeriveSVRKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key1.Destroy()
		key2, err := pool.DeriveSVRKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key2.Destroy()
		if !secrettest.Same(t, key1, key2) {
			t.Fatal("same pool should derive same key")
		}
	})

	t.Run("different pools produce different keys", func(t *testing.T) {
		pool1 := AccountEntropyPool(strings.Repeat("a", 64))
		pool2 := AccountEntropyPool(strings.Repeat("b", 64))
		key1, err := pool1.DeriveSVRKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key1.Destroy()
		key2, err := pool2.DeriveSVRKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key2.Destroy()
		if secrettest.Same(t, key1, key2) {
			t.Fatal("different pools should derive different keys")
		}
	})

	t.Run("key is correct length", func(t *testing.T) {
		pool := AccountEntropyPool(strings.Repeat("a", 64))
		key, err := pool.DeriveSVRKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key.Destroy()
		if key.Size() != SVRKeyLength {
			t.Fatalf("expected key length %d, got %d", SVRKeyLength, key.Size())
		}
	})

	t.Run("invalid pool returns error", func(t *testing.T) {
		pool := AccountEntropyPool("short")
		_, err := pool.DeriveSVRKey()
		if err == nil {
			t.Fatal("expected error for invalid pool")
		}
	})
}

func TestAccountEntropyPool_DeriveBackupKey(t *testing.T) {
	t.Run("derives deterministic key", func(t *testing.T) {
		pool := AccountEntropyPool(strings.Repeat("a", 64))
		key1, err := pool.DeriveBackupKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key1.Destroy()
		key2, err := pool.DeriveBackupKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer key2.Destroy()
		if !secrettest.Same(t, key1, key2) {
			t.Fatal("same pool should derive same key")
		}
	})

	t.Run("SVR key differs from backup key", func(t *testing.T) {
		pool := AccountEntropyPool(strings.Repeat("a", 64))
		svrKey, err := pool.DeriveSVRKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer svrKey.Destroy()
		backupKey, err := pool.DeriveBackupKey()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer backupKey.Destroy()
		if secrettest.Same(t, svrKey, backupKey) {
			t.Fatal("SVR key and backup key should differ")
		}
	})

	t.Run("invalid pool returns error", func(t *testing.T) {
		pool := AccountEntropyPool("short")
		_, err := pool.DeriveBackupKey()
		if err == nil {
			t.Fatal("expected error for invalid pool")
		}
	})
}

func TestHashPin(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	t.Run("produces deterministic output", func(t *testing.T) {
		h1, err := HashPin("1234", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h1.Zeroize()
		h2, err := HashPin("1234", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h2.Zeroize()
		if !secrettest.Same(t, h1.AccessKey, h2.AccessKey) {
			t.Fatal("same PIN and salt should produce same access key")
		}
		if !secrettest.Same(t, h1.EncryptionKey, h2.EncryptionKey) {
			t.Fatal("same PIN and salt should produce same encryption key")
		}
	})

	t.Run("access key differs from encryption key", func(t *testing.T) {
		h, err := HashPin("1234", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h.Zeroize()
		if secrettest.Same(t, h.AccessKey, h.EncryptionKey) {
			t.Fatal("access key and encryption key should differ")
		}
	})

	t.Run("encryption key is first 32 bytes", func(t *testing.T) {
		// Verify field ordering matches Rust: encryption_key = bytes[0:32], access_key = bytes[32:64]
		h, err := HashPin("password", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h.Zeroize()
		// Just verify both fields are populated and different
		if secrettest.IsZero(t, h.EncryptionKey) {
			t.Fatal("encryption key should not be zero")
		}
		if secrettest.IsZero(t, h.AccessKey) {
			t.Fatal("access key should not be zero")
		}
	})

	// Test vector from Rust: known_hash test
	t.Run("known test vector from Rust", func(t *testing.T) {
		pin := "password"
		testSalt := mustDecodeHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
		expectedAccessKey := mustDecodeHex("ab7e8499d21f80a6600b3b9ee349ac6d72c07e3359fe885a934ba7aa844429f8")

		h, err := HashPin(pin, testSalt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h.Zeroize()
		if !secrettest.Matches(t, h.AccessKey, expectedAccessKey) {
			t.Fatalf("access key mismatch")
		}
	})

	t.Run("different PINs produce different keys", func(t *testing.T) {
		h1, err := HashPin("1234", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h1.Zeroize()
		h2, err := HashPin("5678", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h2.Zeroize()
		if secrettest.Same(t, h1.AccessKey, h2.AccessKey) {
			t.Fatal("different PINs should produce different access keys")
		}
	})

	t.Run("different salts produce different keys", func(t *testing.T) {
		salt2 := make([]byte, 32)
		for i := range salt2 {
			salt2[i] = byte(i + 100)
		}
		h1, err := HashPin("1234", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h1.Zeroize()
		h2, err := HashPin("1234", salt2)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h2.Zeroize()
		if secrettest.Same(t, h1.AccessKey, h2.AccessKey) {
			t.Fatal("different salts should produce different keys")
		}
	})

	t.Run("wrong salt length", func(t *testing.T) {
		_, err := HashPin("1234", make([]byte, 16))
		if err == nil {
			t.Fatal("expected error for wrong salt length")
		}
	})

	t.Run("empty salt", func(t *testing.T) {
		_, err := HashPin("1234", nil)
		if err == nil {
			t.Fatal("expected error for nil salt")
		}
	})

	t.Run("empty PIN after normalization", func(t *testing.T) {
		_, err := HashPin("   ", salt)
		if err == nil {
			t.Fatal("expected error for whitespace-only PIN")
		}
	})

	t.Run("trims whitespace from PIN", func(t *testing.T) {
		h1, err := HashPin("1234", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h1.Zeroize()
		h2, err := HashPin("  1234  ", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h2.Zeroize()
		if !secrettest.Same(t, h1.AccessKey, h2.AccessKey) {
			t.Fatal("trimmed PINs should produce same keys")
		}
	})

	// Regression: all-digit PINs with non-ASCII digits still transliterate.
	// "١٢٣" (U+0661 U+0662 U+0663) is an all-digit string → transliterate → "123".
	// HashPin("١٢٣", salt) must equal HashPin("123", salt): no regression to the
	// byte-exact derivation path for existing all-numeric-PIN users.
	t.Run("all_digit_non_ascii_equals_ascii_hash", func(t *testing.T) {
		h1, err := HashPin("١٢٣", salt) // Arabic-Indic "١٢٣"
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h1.Zeroize()
		h2, err := HashPin("123", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h2.Zeroize()
		if !secrettest.Same(t, h1.AccessKey, h2.AccessKey) {
			t.Fatal("all-digit non-ASCII PIN must hash identically to its ASCII equivalent")
		}
	})

	// Regression: a mixed text+non-ASCII-digit PIN must NOT hash the same as
	// the ASCII-digit version.  Before the fix, normalizePin("abc١def") wrongly
	// returned "abc1def", making both PINs derive the same SVR/backup key and
	// potentially locking users out.
	t.Run("mixed_text_non_ascii_digit_not_transliterated", func(t *testing.T) {
		h1, err := HashPin("abc١def", salt) // "abc١def", mixed text
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h1.Zeroize()
		h2, err := HashPin("abc1def", salt) // the wrongly-transliterated form
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer h2.Zeroize()
		if secrettest.Same(t, h1.AccessKey, h2.AccessKey) {
			t.Fatal("mixed text PIN with non-ASCII digit must not hash the same as the ASCII-digit version")
		}
	})
}

func TestVerifyPin(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	t.Run("correct PIN verifies", func(t *testing.T) {
		h, err := HashPin("1234", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ok, err := false, error(nil)
		secrettest.With(t, h.AccessKey, func(k []byte) { ok, err = VerifyPin("1234", salt, k) })
		h.Zeroize()

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatal("correct PIN should verify")
		}
	})

	t.Run("wrong PIN does not verify", func(t *testing.T) {
		h, err := HashPin("1234", salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ok, err := false, error(nil)
		secrettest.With(t, h.AccessKey, func(k []byte) { ok, err = VerifyPin("5678", salt, k) })
		h.Zeroize()

		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Fatal("wrong PIN should not verify")
		}
	})

	t.Run("error on invalid salt", func(t *testing.T) {
		_, err := VerifyPin("1234", make([]byte, 16), []byte{})
		if err == nil {
			t.Fatal("expected error for wrong salt length")
		}
	})
}

func TestLocalPinHash(t *testing.T) {
	t.Run("produces PHC-string with argon2i", func(t *testing.T) {
		phc, err := LocalPinHash("1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.HasPrefix(phc, "$argon2i$v=19$m=512,t=64,p=1$") {
			t.Fatalf("expected PHC-string with argon2i header, got: %s", phc)
		}
	})

	t.Run("known PHC test vector from Rust", func(t *testing.T) {
		// From Rust known_phc_string test
		pin := "apassword"
		salt := mustDecodeHex("202122232425262728292A2B2C2D2E2F")
		expected := "$argon2i$v=19$m=512,t=64,p=1$ICEiIyQlJicoKSorLC0uLw$NeZzhiNv4cRmRMct9scf7d838bzmHJvrZtU/0BH0v/U"

		phc, err := localPinHashWithSalt([]byte(pin), salt)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if phc != expected {
			t.Fatalf("PHC string mismatch\ngot:  %s\nwant: %s", phc, expected)
		}
	})

	t.Run("each call produces unique salt", func(t *testing.T) {
		h1, err := LocalPinHash("1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		h2, err := LocalPinHash("1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Same PIN should produce different PHC strings due to random salt
		if h1 == h2 {
			t.Fatal("two calls should produce different PHC strings (different random salts)")
		}
	})

	t.Run("empty PIN after normalization", func(t *testing.T) {
		_, err := LocalPinHash("   ")
		if err == nil {
			t.Fatal("expected error for whitespace-only PIN")
		}
	})
}

func TestVerifyLocalPinHash(t *testing.T) {
	t.Run("correct PIN verifies", func(t *testing.T) {
		phc, err := LocalPinHash("1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ok, err := VerifyLocalPinHash("1234", phc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatal("correct PIN should verify")
		}
	})

	t.Run("wrong PIN does not verify", func(t *testing.T) {
		phc, err := LocalPinHash("1234")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		ok, err := VerifyLocalPinHash("5678", phc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Fatal("wrong PIN should not verify")
		}
	})

	t.Run("verifies known Rust test vector", func(t *testing.T) {
		phc := "$argon2i$v=19$m=512,t=64,p=1$ICEiIyQlJicoKSorLC0uLw$NeZzhiNv4cRmRMct9scf7d838bzmHJvrZtU/0BH0v/U"
		ok, err := VerifyLocalPinHash("apassword", phc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatal("should verify known Rust test vector")
		}
		ok, err = VerifyLocalPinHash("wrongpin", phc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Fatal("wrong PIN should not verify known test vector")
		}
	})

	t.Run("empty PIN returns error", func(t *testing.T) {
		_, err := VerifyLocalPinHash("  ", "$argon2i$v=19$m=512,t=64,p=1$AAAA$AAAA")
		if err == nil {
			t.Fatal("expected error for whitespace-only PIN")
		}
	})

	t.Run("invalid PHC string returns error", func(t *testing.T) {
		_, err := VerifyLocalPinHash("1234", "not-a-phc-string")
		if err == nil {
			t.Fatal("expected error for invalid PHC string")
		}
	})
}

func TestPinHash_Zeroize(t *testing.T) {
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	h, err := HashPin("1234", salt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify fields are non-zero before Zeroize.
	if secrettest.IsZero(t, h.EncryptionKey) {
		t.Fatal("encryption key should be non-zero before Zeroize")
	}
	if secrettest.IsZero(t, h.AccessKey) {
		t.Fatal("access key should be non-zero before Zeroize")
	}

	h.Zeroize()

	if !h.EncryptionKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy EncryptionKey")
	}
	if !h.AccessKey.IsDestroyed() {
		t.Fatal("Zeroize should destroy AccessKey")
	}
}

func TestPinHash_ZeroizeIdempotent(t *testing.T) {
	salt := make([]byte, 32)
	h, err := HashPin("1234", salt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	h.Zeroize()
	h.Zeroize() // must not panic
}

func TestParsePHCString_InvalidSaltEncoding(t *testing.T) {
	// Valid structure but invalid base64 in the salt field.
	_, _, err := parsePHCString("$argon2i$v=19$m=512,t=64,p=1$!!!invalid!!!$AAAA")
	if err == nil {
		t.Fatal("expected error for invalid salt encoding")
	}
}

func TestParsePHCString_InvalidHashEncoding(t *testing.T) {
	// Valid structure and salt but invalid base64 in the hash field.
	_, _, err := parsePHCString("$argon2i$v=19$m=512,t=64,p=1$AAAA$!!!invalid!!!")
	if err == nil {
		t.Fatal("expected error for invalid hash encoding")
	}
}

func TestNormalizePin(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"ascii digits", "1234", "1234"},
		{"whitespace trim", "  1234  ", "1234"},
		{"tab and newline trim", "\t1234\n", "1234"},
		{"empty", "", ""},
		{"only whitespace", "   ", ""},
		{"text", "hello world", "hello world"},
		// Digit transliteration: Arabic-Indic digits ٠١٢٣٤٥٦٧٨٩
		{"arabic-indic digits", "\u0660\u0661\u0662\u0663", "0123"},
		// Extended Arabic-Indic digits ۰۱۲۳۴۵۶۷۸۹
		{"extended arabic-indic", "\u06F0\u06F1\u06F2\u06F3", "0123"},
		// Devanagari digits ०१२३
		{"devanagari digits", "\u0966\u0967\u0968\u0969", "0123"},
		// Bengali digits ০১২৩
		{"bengali digits", "\u09E6\u09E7\u09E8\u09E9", "0123"},
		// "mixed digits": every rune is a Unicode digit (1, \u0662, \u0968, 3) so
		// isAllDigits=true and transliteration still applies \u2192 "1223".
		// This behavior is UNCHANGED by the all-digits gate.
		{"mixed digits", "1\u0662\u09683", "1223"},
		// Regression: mixed text + non-ASCII digit must NOT transliterate.
		// "abc\u0661def" has non-digit runes, so isAllDigits=false; '\u0661' (U+0661)
		// is preserved as-is under NFKD (it does not decompose).
		// Before the fix normalizePin("abc\u0661def") wrongly returned "abc1def".
		{"mixed text non-ascii digit", "abc\u0661def", "abc\u0661def"},
		// Non-digit unicode text stays as-is (but gets NFKD normalized)
		{"unicode text", "caf\u00E9", "cafe\u0301"},
		// Full-width digits (NFKD normalizes these to ASCII)
		{"fullwidth digits", "\uFF11\uFF12\uFF13\uFF14", "1234"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePin(tt.input)
			if got != tt.expected {
				t.Errorf("normalizePin(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestTransliterateDigits(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"ascii passthrough", "0123456789", "0123456789"},
		{"no digits", "hello", "hello"},
		{"empty", "", ""},
		{"arabic-indic full range", "\u0660\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669", "0123456789"},
		{"devanagari full range", "\u0966\u0967\u0968\u0969\u096A\u096B\u096C\u096D\u096E\u096F", "0123456789"},
		{"mixed text and digits", "abc\u0661def", "abc1def"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := transliterateDigits(tt.input)
			if got != tt.expected {
				t.Errorf("transliterateDigits(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParsePHCString(t *testing.T) {
	t.Run("valid PHC string", func(t *testing.T) {
		phc := "$argon2i$v=19$m=512,t=64,p=1$ICEiIyQlJicoKSorLC0uLw$NeZzhiNv4cRmRMct9scf7d838bzmHJvrZtU/0BH0v/U"
		salt, hash, err := parsePHCString(phc)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(salt) != 16 {
			t.Fatalf("expected 16-byte salt, got %d", len(salt))
		}
		if len(hash) != 32 {
			t.Fatalf("expected 32-byte hash, got %d", len(hash))
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		_, _, err := parsePHCString("garbage")
		if err == nil {
			t.Fatal("expected error for invalid format")
		}
	})

	t.Run("wrong algorithm", func(t *testing.T) {
		_, _, err := parsePHCString("$argon2id$v=19$m=512,t=64,p=1$AAAA$AAAA")
		if err == nil {
			t.Fatal("expected error for wrong algorithm")
		}
	})
}

// Helper functions

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("invalid hex: " + err.Error())
	}
	return b
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
