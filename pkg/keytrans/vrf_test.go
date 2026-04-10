package keytrans

import (
	"testing"
)

func TestNewVRFPublicKey(t *testing.T) {
	t.Run("invalid bytes", func(t *testing.T) {
		// Use bytes that are definitely not a valid edwards25519 point
		// The high bit of byte 31 being set with all other bytes 0xFF
		// is very unlikely to be a valid point encoding
		badKey := [32]byte{
			0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		}
		_, err := NewVRFPublicKey(badKey)
		if err == nil {
			t.Fatal("expected error for invalid curve point")
		}
		if err != ErrInvalidCurvePoint {
			t.Errorf("expected ErrInvalidCurvePoint, got %v", err)
		}
	})

	t.Run("identity point rejected", func(t *testing.T) {
		// The identity point on edwards25519 is encoded as all zeros
		// except the last byte which is 0x01
		var identityKey [32]byte
		identityKey[0] = 0x01
		_, err := NewVRFPublicKey(identityKey)
		// This will either fail as invalid point or as small-order point
		if err == nil {
			t.Fatal("expected error for identity/small-order point")
		}
	})

	t.Run("zero bytes rejected", func(t *testing.T) {
		var zeroKey [32]byte
		_, err := NewVRFPublicKey(zeroKey)
		// Zero bytes may parse as identity (small order)
		if err == nil {
			t.Fatal("expected error for zero key")
		}
	})
}

func TestVRFPublicKey_AsBytes(t *testing.T) {
	// Use a known valid Ed25519 public key (generator point)
	// The base point of Ed25519 compressed encoding
	basePoint := [32]byte{
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	}

	pk, err := NewVRFPublicKey(basePoint)
	if err != nil {
		t.Fatalf("failed to create VRF public key from base point: %v", err)
	}

	got := pk.AsBytes()
	if *got != basePoint {
		t.Error("AsBytes should return the original compressed key")
	}
}

func TestVRFPublicKey_ProofToHash(t *testing.T) {
	basePoint := [32]byte{
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	}

	pk, err := NewVRFPublicKey(basePoint)
	if err != nil {
		t.Fatalf("failed to create VRF public key: %v", err)
	}

	t.Run("invalid proof - all zeros", func(t *testing.T) {
		proof := &[80]byte{}
		_, err := pk.ProofToHash([]byte("test"), proof)
		// All-zero proof should fail verification
		if err == nil {
			t.Fatal("expected error for all-zero proof")
		}
	})

	t.Run("invalid gamma point", func(t *testing.T) {
		proof := &[80]byte{}
		for i := range proof {
			proof[i] = 0xFF
		}
		_, err := pk.ProofToHash([]byte("test"), proof)
		if err != ErrInvalidVRFProof {
			t.Errorf("expected ErrInvalidVRFProof, got %v", err)
		}
	})
}

func TestScalarFromUint64(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		s := scalarFromUint64(0)
		if s == nil {
			t.Fatal("scalar should not be nil")
		}
	})

	t.Run("small values", func(t *testing.T) {
		for _, v := range []uint64{1, 2, 8, 255, 65535} {
			s := scalarFromUint64(v)
			if s == nil {
				t.Fatalf("scalarFromUint64(%d) returned nil", v)
			}
		}
	})
}

func TestCofactorMultiply(t *testing.T) {
	// Test that cofactorMultiply doesn't panic on the generator point
	basePoint := [32]byte{
		0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
	}

	pk, err := NewVRFPublicKey(basePoint)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result := cofactorMultiply(pk.decompressed)
	if result == nil {
		t.Fatal("cofactor multiply should return non-nil point")
	}
}

func TestGenerateChallenge(t *testing.T) {
	pts := [5]*[32]byte{
		{1}, {2}, {3}, {4}, {5},
	}

	t.Run("deterministic", func(t *testing.T) {
		c1 := generateChallenge(pts)
		c2 := generateChallenge(pts)
		if c1 != c2 {
			t.Fatal("same inputs should produce same challenge")
		}
	})

	t.Run("different inputs produce different challenge", func(t *testing.T) {
		pts2 := [5]*[32]byte{
			{6}, {7}, {8}, {9}, {10},
		}
		c1 := generateChallenge(pts)
		c2 := generateChallenge(pts2)
		if c1 == c2 {
			t.Fatal("different inputs should produce different challenge")
		}
	})
}

func TestEncodeToCurveTryAndIncrement(t *testing.T) {
	t.Run("returns valid point", func(t *testing.T) {
		point, err := encodeToCurveTryAndIncrement([]byte("test-salt"), []byte("test-data"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if point == nil {
			t.Fatal("should return a valid point")
		}
	})

	t.Run("deterministic", func(t *testing.T) {
		p1, err := encodeToCurveTryAndIncrement([]byte("salt"), []byte("data"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		p2, err := encodeToCurveTryAndIncrement([]byte("salt"), []byte("data"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p1.Equal(p2) != 1 {
			t.Fatal("same inputs should produce same point")
		}
	})

	t.Run("different inputs produce different points", func(t *testing.T) {
		p1, err := encodeToCurveTryAndIncrement([]byte("salt1"), []byte("data"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		p2, err := encodeToCurveTryAndIncrement([]byte("salt2"), []byte("data"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p1.Equal(p2) == 1 {
			t.Fatal("different inputs should produce different points")
		}
	})
}
