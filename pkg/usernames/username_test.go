package usernames

import (
	"strings"
	"testing"
)

func TestValidUsernames(t *testing.T) {
	for _, username := range []string{"He110.01", "usr.999999999", "_identifier.42", "LOUD.700"} {
		t.Run(username, func(t *testing.T) {
			parsed, err := New(username)
			if err != nil {
				t.Fatalf("unexpected error parsing %q: %v", username, err)
			}
			_ = parsed.Hash()
			if parsed.String() != username {
				t.Errorf("String() = %q, want %q", parsed.String(), username)
			}
		})
	}
}

func TestNoDiscriminator(t *testing.T) {
	_, err := New("no_discriminator")
	if err != ErrMissingSeparator {
		t.Fatalf("expected ErrMissingSeparator, got %v", err)
	}
}

func TestInvalidNicknames(t *testing.T) {
	tests := []struct {
		nickname string
		expected UsernameError
	}{
		{"", ErrNicknameCannotBeEmpty},
		{"s p a c e s", ErrBadNicknameCharacter},
		{"0start", ErrNicknameCannotStartWithDigit},
		{
			"nickname_too_big7890123456789012345678901234567890",
			ErrNicknameTooLong,
		},
	}
	for _, tt := range tests {
		t.Run(tt.nickname, func(t *testing.T) {
			_, err := FromParts(tt.nickname, "42", DefaultNicknameLimits())
			if err != tt.expected {
				t.Errorf("FromParts(%q) error = %v, want %v", tt.nickname, err, tt.expected)
			}
		})
	}
}

func TestInvalidDiscriminators(t *testing.T) {
	tests := []struct {
		discriminator string
		expected      UsernameError
	}{
		{"", ErrDiscriminatorCannotBeEmpty},
		{"0", ErrDiscriminatorCannotBeZero},
		{"00", ErrDiscriminatorCannotBeZero},
		{"001", ErrDiscriminatorCannotHaveLeadingZeros},
		{"0123", ErrDiscriminatorCannotHaveLeadingZeros},
		{"1", ErrDiscriminatorCannotBeSingleDigit},
		{"+1", ErrBadDiscriminatorCharacter},
		{"-1", ErrBadDiscriminatorCharacter},
		{"+01", ErrBadDiscriminatorCharacter},
		{"-01", ErrBadDiscriminatorCharacter},
		{"+123", ErrBadDiscriminatorCharacter},
		{"-123", ErrBadDiscriminatorCharacter},
		{"123456789012345678901234567890", ErrDiscriminatorTooLarge},
		{"a1", ErrBadDiscriminatorCharacter},
	}
	for _, tt := range tests {
		t.Run(tt.discriminator, func(t *testing.T) {
			_, err := FromParts("ehren", tt.discriminator, DefaultNicknameLimits())
			if err != tt.expected {
				t.Errorf("FromParts(ehren, %q) error = %v, want %v", tt.discriminator, err, tt.expected)
			}

			_, err2 := New("ehren." + tt.discriminator)
			if err2 == nil {
				t.Errorf("New(ehren.%s) unexpectedly succeeded", tt.discriminator)
			}
		})
	}
}

func TestNicknameLimits(t *testing.T) {
	_ = DefaultNicknameLimits() // should not panic

	limits := NewNicknameLimits(0, 42)
	if err := limits.validate(13); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNicknameSoftLimits(t *testing.T) {
	_, err := FromParts("abcd", "42", DefaultNicknameLimits())
	if err != nil {
		t.Fatalf("expected valid, got %v", err)
	}

	_, err = FromParts("abcd", "42", NewNicknameLimits(2, 3))
	if err != ErrNicknameTooLong {
		t.Fatalf("expected ErrNicknameTooLong, got %v", err)
	}

	_, err = FromParts("abcd", "42", NewNicknameLimits(5, 10))
	if err != ErrNicknameTooShort {
		t.Fatalf("expected ErrNicknameTooShort, got %v", err)
	}
}

func TestValidNicknameScalar(t *testing.T) {
	// The result should be 1 + 27*27 + 37*27*37^1 + 1*27*37^2 = 74656
	s, err := nicknameScalar("_z9_")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := scalarFromUint64(74656)
	if s.Equal(expected) != 1 {
		t.Errorf("nickname scalar mismatch for _z9_")
	}
}

func TestProofRoundTrip(t *testing.T) {
	tests := []struct {
		nickname      string
		discriminator string
	}{
		{"test_user", "42"},
		{"_SiGNA1", "100"},
		{"hello", "999999999"},
		{"a_b_c", "01"},
	}
	for _, tt := range tests {
		t.Run(tt.nickname+"."+tt.discriminator, func(t *testing.T) {
			username, err := FromParts(tt.nickname, tt.discriminator, DefaultNicknameLimits())
			if err != nil {
				t.Fatalf("FromParts error: %v", err)
			}
			hash := username.Hash()
			var randomness [32]byte
			for i := range randomness {
				randomness[i] = byte(i + 1)
			}
			proof, err := username.Proof(randomness)
			if err != nil {
				t.Fatalf("Proof error: %v", err)
			}
			if err := VerifyProof(proof, hash); err != nil {
				t.Fatalf("VerifyProof failed: %v", err)
			}
		})
	}
}

func TestProofVerificationFailsWithWrongHash(t *testing.T) {
	username, err := FromParts("test", "42", DefaultNicknameLimits())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var randomness [32]byte
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	proof, err := username.Proof(randomness)
	if err != nil {
		t.Fatalf("Proof error: %v", err)
	}

	// Use a different hash.
	wrongHash := username.Hash()
	wrongHash[0] ^= 0xff
	// This may fail at point decompression or at verification.
	err = VerifyProof(proof, wrongHash)
	if err == nil {
		t.Fatal("expected verification failure with wrong hash")
	}
}

func TestCandidatesFrom(t *testing.T) {
	candidates, err := CandidatesFrom("_SiGNA1", DefaultNicknameLimits())
	if err != nil {
		t.Fatalf("CandidatesFrom error: %v", err)
	}

	// Total candidates should be sum of candidatesPerRange.
	expectedCount := 0
	for _, c := range candidatesPerRange {
		expectedCount += c
	}
	if len(candidates) != expectedCount {
		t.Fatalf("expected %d candidates, got %d", expectedCount, len(candidates))
	}

	for _, c := range candidates {
		if !strings.HasPrefix(c, "_SiGNA1.") {
			t.Errorf("candidate %q does not start with '_SiGNA1.'", c)
		}
		// Each candidate should be parseable.
		u, err := New(c)
		if err != nil {
			t.Errorf("candidate %q is not parseable: %v", c, err)
			continue
		}

		// Should be able to generate and verify proof.
		hash := u.Hash()
		var randomness [32]byte
		for i := range randomness {
			randomness[i] = byte(i + 1)
		}
		proof, err := u.Proof(randomness)
		if err != nil {
			t.Errorf("Proof error for candidate %q: %v", c, err)
			continue
		}
		if err := VerifyProof(proof, hash); err != nil {
			t.Errorf("VerifyProof failed for candidate %q: %v", c, err)
		}
	}
}

func TestValidCharactersMapping(t *testing.T) {
	valid := "_abcdefghijklmnopqrstuvwxyz0123456789"
	var mapped []byte
	for _, c := range valid {
		b, ok := charToByte(c)
		if !ok {
			t.Fatalf("charToByte undefined for %c", c)
		}
		mapped = append(mapped, b)
	}
	// Verify the mapping is sorted (monotonically increasing).
	for i := 1; i < len(mapped); i++ {
		if mapped[i] <= mapped[i-1] {
			t.Errorf("mapping not sorted at index %d: %d <= %d", i, mapped[i], mapped[i-1])
		}
	}
}

func TestCaseInsensitiveHash(t *testing.T) {
	u1, err := New("TestUser.42")
	if err != nil {
		t.Fatal(err)
	}
	u2, err := New("testuser.42")
	if err != nil {
		t.Fatal(err)
	}
	if u1.Hash() != u2.Hash() {
		t.Error("hash should be case-insensitive")
	}
}
