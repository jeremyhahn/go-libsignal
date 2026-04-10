package poksho

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from Rust libsignal/rust/poksho/src/shohmacsha256.rs
func TestShoHmacSha256_RustVector1(t *testing.T) {
	sho := NewShoHmacSha256("asd")
	sho.AbsorbAndRatchet([]byte("asdasd"))
	out := sho.SqueezeAndRatchet(64)

	expected, _ := hex.DecodeString(
		"392cb9449373037fa0c11aebed69cca3b7d3bc9790878f341729c65d5506442f" +
			"04986cb5c9098f277c3ea640a4dc6e90372b433a90af9aea7072eaba3398c4fe")

	if !bytes.Equal(out, expected) {
		t.Errorf("HMAC vector 1 mismatch\ngot:  %s\nwant: %s", hex.EncodeToString(out), hex.EncodeToString(expected))
	}
}

func TestShoHmacSha256_RustVector2(t *testing.T) {
	sho := NewShoHmacSha256("asd")
	sho.AbsorbAndRatchet([]byte("asdasd"))
	out := sho.SqueezeAndRatchet(65)

	expected, _ := hex.DecodeString(
		"392cb9449373037fa0c11aebed69cca3b7d3bc9790878f341729c65d5506442f" +
			"04986cb5c9098f277c3ea640a4dc6e90372b433a90af9aea7072eaba3398c4fe7a")

	if !bytes.Equal(out, expected) {
		t.Errorf("HMAC vector 2 mismatch\ngot:  %s\nwant: %s", hex.EncodeToString(out), hex.EncodeToString(expected))
	}
}

func TestShoHmacSha256_RustVector3(t *testing.T) {
	sho := NewShoHmacSha256("")
	sho.AbsorbAndRatchet([]byte("abc"))
	sho.AbsorbAndRatchet(make([]byte, 63))
	sho.AbsorbAndRatchet(make([]byte, 64))
	sho.AbsorbAndRatchet(make([]byte, 65))
	sho.AbsorbAndRatchet(make([]byte, 127))
	sho.AbsorbAndRatchet(make([]byte, 128))
	sho.AbsorbAndRatchet(make([]byte, 129))
	sho.SqueezeAndRatchet(63)
	sho.SqueezeAndRatchet(64)
	sho.SqueezeAndRatchet(65)
	sho.SqueezeAndRatchet(127)
	sho.SqueezeAndRatchet(128)
	sho.SqueezeAndRatchet(129)
	sho.AbsorbAndRatchet([]byte("def"))
	out := sho.SqueezeAndRatchet(63)

	expected, _ := hex.DecodeString(
		"c5c13bcc6596c25fc4514eac9269dd6e3e57ef70f4bfb8d67fd3082ed9732d77" +
			"90d8d2686f19eb2533a65c94bb8ceda0a068e1b615c81bb26e411889da9fb7")

	if !bytes.Equal(out, expected) {
		t.Errorf("HMAC vector 3 mismatch\ngot:  %s\nwant: %s", hex.EncodeToString(out), hex.EncodeToString(expected))
	}
}

// Test vectors from Rust libsignal/rust/poksho/src/shosha256.rs
func TestShoSha256_RustVector1(t *testing.T) {
	sho := NewShoSha256("asd")
	sho.AbsorbAndRatchet([]byte("asdasd"))
	out := sho.SqueezeAndRatchet(64)

	expected, _ := hex.DecodeString(
		"ebe4ef29e18aa54137edd89c23f8bfeac2731c9f675da20e7c67d5ad68d7ee2d" +
			"40a45232b599552d46b520082fb27059" +
			"71f07b3158b072b63ab0934a05e6af64")

	if !bytes.Equal(out, expected) {
		t.Errorf("SHA256 vector 1 mismatch\ngot:  %s\nwant: %s", hex.EncodeToString(out), hex.EncodeToString(expected))
	}
}

func TestShoSha256_RustVector2(t *testing.T) {
	sho := NewShoSha256("asd")
	sho.AbsorbAndRatchet([]byte("asdasd"))
	out := sho.SqueezeAndRatchet(65)

	expected, _ := hex.DecodeString(
		"ebe4ef29e18aa54137edd89c23f8bfeac2731c9f675da20e7c67d5ad68d7ee2d" +
			"40a45232b599552d46b520082fb27059" +
			"71f07b3158b072b63ab0934a05e6af6448")

	if !bytes.Equal(out, expected) {
		t.Errorf("SHA256 vector 2 mismatch\ngot:  %s\nwant: %s", hex.EncodeToString(out), hex.EncodeToString(expected))
	}
}

func TestShoSha256_RustVector3(t *testing.T) {
	sho := NewShoSha256("")
	sho.AbsorbAndRatchet([]byte("abc"))
	sho.AbsorbAndRatchet(make([]byte, 63))
	sho.AbsorbAndRatchet(make([]byte, 64))
	sho.AbsorbAndRatchet(make([]byte, 65))
	sho.AbsorbAndRatchet(make([]byte, 127))
	sho.AbsorbAndRatchet(make([]byte, 128))
	sho.AbsorbAndRatchet(make([]byte, 129))
	sho.SqueezeAndRatchet(63)
	sho.SqueezeAndRatchet(64)
	sho.SqueezeAndRatchet(65)
	sho.SqueezeAndRatchet(127)
	sho.SqueezeAndRatchet(128)
	sho.SqueezeAndRatchet(129)
	sho.AbsorbAndRatchet([]byte("def"))
	out := sho.SqueezeAndRatchet(63)

	expected, _ := hex.DecodeString(
		"0ddeea973f3210f7725a3cdb2473f873aeab8feb32b80dee67f0cde7954e929a" +
			"4e787aefee6dbe91d3fff1621aab8d0d" +
			"29194f8af986d6f357add0150df7d9")

	if !bytes.Equal(out, expected) {
		t.Errorf("SHA256 vector 3 mismatch\ngot:  %s\nwant: %s", hex.EncodeToString(out), hex.EncodeToString(expected))
	}
}

func TestShoSha256_DeterministicSqueeze(t *testing.T) {
	s1 := NewShoSha256("test-label")
	s1.AbsorbAndRatchet([]byte("hello"))
	out1 := s1.SqueezeAndRatchet(32)

	s2 := NewShoSha256("test-label")
	s2.AbsorbAndRatchet([]byte("hello"))
	out2 := s2.SqueezeAndRatchet(32)

	if !bytes.Equal(out1, out2) {
		t.Error("same inputs produced different outputs")
	}
}

func TestShoSha256_DifferentLabels(t *testing.T) {
	s1 := NewShoSha256("label-a")
	out1 := s1.SqueezeAndRatchet(32)

	s2 := NewShoSha256("label-b")
	out2 := s2.SqueezeAndRatchet(32)

	if bytes.Equal(out1, out2) {
		t.Error("different labels produced same output")
	}
}

func TestShoSha256_DifferentData(t *testing.T) {
	s1 := NewShoSha256("test")
	s1.AbsorbAndRatchet([]byte("data1"))
	out1 := s1.SqueezeAndRatchet(32)

	s2 := NewShoSha256("test")
	s2.AbsorbAndRatchet([]byte("data2"))
	out2 := s2.SqueezeAndRatchet(32)

	if bytes.Equal(out1, out2) {
		t.Error("different data produced same output")
	}
}

func TestShoSha256_SqueezeVariousLengths(t *testing.T) {
	for _, length := range []int{1, 16, 32, 33, 64, 100} {
		s := NewShoSha256("test")
		s.AbsorbAndRatchet([]byte("data"))
		out := s.SqueezeAndRatchet(length)
		if len(out) != length {
			t.Errorf("SqueezeAndRatchet(%d) returned %d bytes", length, len(out))
		}
	}
}

func TestShoSha256_SqueezeZeroReturnsNil(t *testing.T) {
	s := NewShoSha256("test")
	out := s.SqueezeAndRatchet(0)
	if out != nil {
		t.Error("SqueezeAndRatchet(0) should return nil")
	}
}

func TestShoHmacSha256_Deterministic(t *testing.T) {
	s1 := NewShoHmacSha256("test-label")
	s1.AbsorbAndRatchet([]byte("hello"))
	out1 := s1.SqueezeAndRatchet(32)

	s2 := NewShoHmacSha256("test-label")
	s2.AbsorbAndRatchet([]byte("hello"))
	out2 := s2.SqueezeAndRatchet(32)

	if !bytes.Equal(out1, out2) {
		t.Error("same inputs produced different outputs")
	}
}

func TestShoHmacSha256_DiffersFromSha256(t *testing.T) {
	s1 := NewShoSha256("test-label")
	s1.AbsorbAndRatchet([]byte("data"))
	out1 := s1.SqueezeAndRatchet(32)

	s2 := NewShoHmacSha256("test-label")
	s2.AbsorbAndRatchet([]byte("data"))
	out2 := s2.SqueezeAndRatchet(32)

	if bytes.Equal(out1, out2) {
		t.Error("SHA-256 and HMAC-SHA-256 SHOs produced same output")
	}
}

func TestShoRatchet_ChangesState(t *testing.T) {
	s1 := NewShoSha256("test")
	s1.AbsorbAndRatchet([]byte("data"))
	afterRatchet := s1.SqueezeAndRatchet(32)

	s2 := NewShoSha256("test")
	s2.Absorb([]byte("data"))
	// Squeeze auto-ratchets, so this should produce the same result
	beforeSqueeze := s2.Squeeze(32)

	if !bytes.Equal(afterRatchet, beforeSqueeze) {
		t.Error("Squeeze (with auto-ratchet) should match AbsorbAndRatchet + SqueezeAndRatchet")
	}
}

func TestShoClone(t *testing.T) {
	s := NewShoSha256("test")
	s.AbsorbAndRatchet([]byte("data"))

	clone := s.Clone()

	out1 := s.SqueezeAndRatchet(32)
	out2 := clone.SqueezeAndRatchet(32)

	if !bytes.Equal(out1, out2) {
		t.Error("clone produced different output than original")
	}
}

func TestShoClone_Divergence(t *testing.T) {
	s := NewShoSha256("test")
	s.AbsorbAndRatchet([]byte("data"))

	clone := s.Clone()

	s.AbsorbAndRatchet([]byte("more"))
	out1 := s.SqueezeAndRatchet(32)

	clone.AbsorbAndRatchet([]byte("different"))
	out2 := clone.SqueezeAndRatchet(32)

	if bytes.Equal(out1, out2) {
		t.Error("clone and original should diverge after different operations")
	}
}

// TestShoClone_AbsorbingModeNoSideEffect verifies that Clone() in ABSORBING
// mode does NOT mutate the original. This is the critical fix for ZK-C1: the
// old implementation forced a ratchet on the original, which changed its state.
// Rust's #[derive(Clone)] produces a true deep copy with no side effects.
func TestShoClone_AbsorbingModeNoSideEffect(t *testing.T) {
	for _, tc := range []struct {
		name   string
		newSho func(string) *SHO
	}{
		{"HMAC-SHA-256", NewShoHmacSha256},
		{"SHA-256", NewShoSha256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Build the SHO to ABSORBING state (absorb without ratchet).
			s := tc.newSho("test")
			s.Absorb([]byte("partial-data"))

			// Verify we are in absorbing mode.
			if s.mode != modeAbsorbing {
				t.Fatal("expected SHO to be in ABSORBING mode before clone")
			}

			// Clone mid-absorb.
			clone := s.Clone()

			// Original must still be in ABSORBING mode (not ratcheted).
			if s.mode != modeAbsorbing {
				t.Fatal("Clone() must not change the original's mode")
			}
			if s.hasher == nil {
				t.Fatal("Clone() must not nil out the original's hasher")
			}

			// Clone must also be in ABSORBING mode.
			if clone.mode != modeAbsorbing {
				t.Fatal("clone must be in ABSORBING mode")
			}
			if clone.hasher == nil {
				t.Fatal("clone must have a non-nil hasher")
			}

			// Continue absorbing into both, then ratchet and squeeze.
			// They should produce identical output since they were cloned
			// at the same point.
			s.Absorb([]byte("-suffix"))
			s.Ratchet()
			out1 := s.SqueezeAndRatchet(32)

			clone.Absorb([]byte("-suffix"))
			clone.Ratchet()
			out2 := clone.SqueezeAndRatchet(32)

			if !bytes.Equal(out1, out2) {
				t.Errorf("clone diverged from original after identical operations\n"+
					"original: %x\nclone:    %x", out1, out2)
			}
		})
	}
}

// TestShoClone_AbsorbingModeDivergence verifies that after cloning in
// ABSORBING mode, feeding different data into original and clone produces
// different outputs.
func TestShoClone_AbsorbingModeDivergence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		newSho func(string) *SHO
	}{
		{"HMAC-SHA-256", NewShoHmacSha256},
		{"SHA-256", NewShoSha256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.newSho("test")
			s.Absorb([]byte("shared-prefix"))

			clone := s.Clone()

			// Feed different data into each branch.
			s.Absorb([]byte("-branch-A"))
			s.Ratchet()
			outA := s.SqueezeAndRatchet(32)

			clone.Absorb([]byte("-branch-B"))
			clone.Ratchet()
			outB := clone.SqueezeAndRatchet(32)

			if bytes.Equal(outA, outB) {
				t.Error("clone and original should diverge after different absorbs")
			}
		})
	}
}

// TestShoClone_AbsorbingModeOriginalUnchanged verifies that cloning in
// ABSORBING mode does not alter the original's final output compared to
// a reference SHO that was never cloned.
func TestShoClone_AbsorbingModeOriginalUnchanged(t *testing.T) {
	for _, tc := range []struct {
		name   string
		newSho func(string) *SHO
	}{
		{"HMAC-SHA-256", NewShoHmacSha256},
		{"SHA-256", NewShoSha256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Reference: no clone at all.
			ref := tc.newSho("test")
			ref.Absorb([]byte("hello"))
			ref.Absorb([]byte("world"))
			ref.Ratchet()
			refOut := ref.SqueezeAndRatchet(64)

			// Test subject: clone mid-absorb, then continue the original.
			s := tc.newSho("test")
			s.Absorb([]byte("hello"))
			_ = s.Clone() // clone and discard -- must not affect s
			s.Absorb([]byte("world"))
			s.Ratchet()
			sOut := s.SqueezeAndRatchet(64)

			if !bytes.Equal(refOut, sOut) {
				t.Errorf("Clone() altered the original's output\n"+
					"reference: %x\nactual:    %x", refOut, sOut)
			}
		})
	}
}

func TestShoMultipleAbsorbs_StreamingAccumulation(t *testing.T) {
	// Multiple absorbs without ratchet should accumulate data into the same
	// hasher. Absorb("hello") + Absorb("world") should differ from
	// Absorb("helloworld") because in Rust, the former is two separate
	// update() calls which IS equivalent to one update("helloworld").
	// Wait -- actually in Rust, multiple absorbs without ratchet DO just
	// concatenate. HMAC.update("hello"); HMAC.update("world") == HMAC.update("helloworld").
	// So they SHOULD be equal.
	s1 := NewShoHmacSha256("test")
	s1.Absorb([]byte("hello"))
	s1.Absorb([]byte("world"))
	s1.Ratchet()
	out1 := s1.SqueezeAndRatchet(32)

	s2 := NewShoHmacSha256("test")
	s2.Absorb([]byte("helloworld"))
	s2.Ratchet()
	out2 := s2.SqueezeAndRatchet(32)

	if !bytes.Equal(out1, out2) {
		t.Error("streaming absorbs should be equivalent to single concatenated absorb")
	}
}

func TestShoRatchet_IdempotentWhenRatcheted(t *testing.T) {
	s1 := NewShoHmacSha256("test")
	s1.AbsorbAndRatchet([]byte("data"))
	// Double ratchet should be no-op (second ratchet is idempotent).
	s1.Ratchet()
	out1 := s1.SqueezeAndRatchet(32)

	s2 := NewShoHmacSha256("test")
	s2.AbsorbAndRatchet([]byte("data"))
	out2 := s2.SqueezeAndRatchet(32)

	if !bytes.Equal(out1, out2) {
		t.Error("double ratchet should be idempotent")
	}
}

func TestShoSqueeze_BackwardCompatAutoRatchet(t *testing.T) {
	// Squeeze (backward compat) should auto-ratchet if in absorbing mode.
	s1 := NewShoSha256("test")
	s1.Absorb([]byte("data"))
	out1 := s1.Squeeze(32)

	s2 := NewShoSha256("test")
	s2.AbsorbAndRatchet([]byte("data"))
	out2 := s2.SqueezeAndRatchet(32)

	if !bytes.Equal(out1, out2) {
		t.Error("Squeeze with auto-ratchet should match AbsorbAndRatchet + SqueezeAndRatchet")
	}
}

func TestShoHash_Convenience(t *testing.T) {
	out1 := ShoHash(NewShoHmacSha256, "label", []byte("input"), 32)

	sho := NewShoHmacSha256("label")
	sho.AbsorbAndRatchet([]byte("input"))
	out2 := sho.SqueezeAndRatchet(32)

	if !bytes.Equal(out1, out2) {
		t.Error("ShoHash should produce same result as manual new/absorb/squeeze")
	}
}

// Verify that the first 64 bytes of a 65-byte squeeze match a 64-byte squeeze
// (both variants). This confirms block generation is consistent.
func TestShoHmacSha256_PrefixConsistency(t *testing.T) {
	s1 := NewShoHmacSha256("prefix")
	s1.AbsorbAndRatchet([]byte("data"))
	out64 := s1.SqueezeAndRatchet(64)

	s2 := NewShoHmacSha256("prefix")
	s2.AbsorbAndRatchet([]byte("data"))
	out65 := s2.SqueezeAndRatchet(65)

	if !bytes.Equal(out64, out65[:64]) {
		t.Error("first 64 bytes of 65-byte squeeze should match 64-byte squeeze")
	}
}

func TestShoSha256_PrefixConsistency(t *testing.T) {
	s1 := NewShoSha256("prefix")
	s1.AbsorbAndRatchet([]byte("data"))
	out64 := s1.SqueezeAndRatchet(64)

	s2 := NewShoSha256("prefix")
	s2.AbsorbAndRatchet([]byte("data"))
	out65 := s2.SqueezeAndRatchet(65)

	if !bytes.Equal(out64, out65[:64]) {
		t.Error("first 64 bytes of 65-byte squeeze should match 64-byte squeeze")
	}
}

// Verify that consecutive squeezes produce different output because the
// state is ratcheted after each squeeze.
func TestShoConsecutiveSqueezes_DifferentOutput(t *testing.T) {
	sho := NewShoHmacSha256("test")
	sho.AbsorbAndRatchet([]byte("data"))

	out1 := sho.SqueezeAndRatchet(32)
	out2 := sho.SqueezeAndRatchet(32)

	if bytes.Equal(out1, out2) {
		t.Error("consecutive squeezes should produce different output")
	}
}
