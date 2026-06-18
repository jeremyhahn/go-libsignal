package mlkembraid

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/polynomial"
)

// ================== MLKEM768IncrementalKEM error paths ==================

// TestMLKEM768IncrementalKEM_Encaps1_WrongSeedSize verifies that Encaps1 returns
// an error when ekSeed is not exactly 32 bytes.
func TestMLKEM768IncrementalKEM_Encaps1_WrongSeedSize(t *testing.T) {
	k := NewMLKEM768IncrementalKEM()
	_, _, _, err := k.Encaps1(make([]byte, 5), make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for wrong ekSeed size")
	}
}

// TestMLKEM768IncrementalKEM_Encaps1_WrongHekSize verifies that Encaps1 returns
// an error when hek is not exactly 32 bytes.
func TestMLKEM768IncrementalKEM_Encaps1_WrongHekSize(t *testing.T) {
	k := NewMLKEM768IncrementalKEM()
	_, _, _, err := k.Encaps1(make([]byte, 32), make([]byte, 5))
	if err == nil {
		t.Fatal("expected error for wrong hek size")
	}
}

// TestMLKEM768IncrementalKEM_FullEncaps_WrongSeedSize verifies that FullEncaps
// returns an error when ekSeed is not 32 bytes.
func TestMLKEM768IncrementalKEM_FullEncaps_WrongSeedSize(t *testing.T) {
	k := NewMLKEM768IncrementalKEM()
	_, _, _, err := k.FullEncaps(make([]byte, 5), make([]byte, 100))
	if err == nil {
		t.Fatal("expected error for wrong ekSeed size")
	}
}

// TestMLKEM768IncrementalKEM_FullEncaps_EmptyVector verifies that FullEncaps
// returns an error when ekVector is empty.
func TestMLKEM768IncrementalKEM_FullEncaps_EmptyVector(t *testing.T) {
	k := NewMLKEM768IncrementalKEM()
	_, _, _, err := k.FullEncaps(make([]byte, 32), nil)
	if err == nil {
		t.Fatal("expected error for empty ekVector")
	}
}

// TestMLKEM768IncrementalKEM_Encaps2_InvalidInput verifies that Encaps2 returns
// an error when called with an invalid encapsSecret.
func TestMLKEM768IncrementalKEM_Encaps2_InvalidInput(t *testing.T) {
	k := NewMLKEM768IncrementalKEM()
	_, err := k.Encaps2(make([]byte, 5), make([]byte, 32), make([]byte, 100))
	if err == nil {
		t.Fatal("expected error for invalid encapsSecret")
	}
}

// TestMLKEM768IncrementalKEM_CompleteEncaps2_InvalidInput verifies that
// CompleteEncaps2 returns an error when called with an invalid encapsSecret.
func TestMLKEM768IncrementalKEM_CompleteEncaps2_InvalidInput(t *testing.T) {
	k := NewMLKEM768IncrementalKEM()
	_, _, _, err := k.CompleteEncaps2(make([]byte, 5), make([]byte, 32), make([]byte, 100))
	if err == nil {
		t.Fatal("expected error for invalid encapsSecret")
	}
}

// TestMLKEM768IncrementalKEM_Decaps_InvalidInput verifies that Decaps returns
// an error when called with invalid ciphertexts.
func TestMLKEM768IncrementalKEM_Decaps_InvalidInput(t *testing.T) {
	k := NewMLKEM768IncrementalKEM()
	_, err := k.Decaps(make([]byte, 100), make([]byte, 5), make([]byte, 5))
	if err == nil {
		t.Fatal("expected error for invalid decaps input")
	}
}

// ================== IncrementalMLKEM768KEM error paths ==================

// TestIncrementalMLKEM768KEM_Encaps1_WrongSeedSize verifies that Encaps1 returns
// an error when ekSeed is not 64 bytes.
func TestIncrementalMLKEM768KEM_Encaps1_WrongSeedSize(t *testing.T) {
	k := NewIncrementalMLKEM768KEM()
	_, _, _, err := k.Encaps1(make([]byte, 5), nil)
	if err == nil {
		t.Fatal("expected error for wrong ekSeed size")
	}
}

// TestIncrementalMLKEM768KEM_FullEncaps_WrongSeedSize verifies that FullEncaps
// returns an error when ekSeed is not 64 bytes.
func TestIncrementalMLKEM768KEM_FullEncaps_WrongSeedSize(t *testing.T) {
	k := NewIncrementalMLKEM768KEM()
	_, _, _, err := k.FullEncaps(make([]byte, 5), make([]byte, 1152))
	if err == nil {
		t.Fatal("expected error for wrong ekSeed size")
	}
}

// TestIncrementalMLKEM768KEM_FullEncaps_WrongVectorSize verifies that FullEncaps
// returns an error when ekVector is not 1152 bytes.
func TestIncrementalMLKEM768KEM_FullEncaps_WrongVectorSize(t *testing.T) {
	k := NewIncrementalMLKEM768KEM()
	_, _, _, err := k.FullEncaps(make([]byte, 64), make([]byte, 5))
	if err == nil {
		t.Fatal("expected error for wrong ekVector size")
	}
}

// TestIncrementalMLKEM768KEM_CompleteEncaps2_WrongSize verifies that
// CompleteEncaps2 returns an error when encapsSecret is not 3072 bytes.
func TestIncrementalMLKEM768KEM_CompleteEncaps2_WrongSize(t *testing.T) {
	k := NewIncrementalMLKEM768KEM()
	_, _, _, err := k.CompleteEncaps2(make([]byte, 5), make([]byte, 64), make([]byte, 1152))
	if err == nil {
		t.Fatal("expected error for wrong encapsSecret size")
	}
}

// TestIncrementalMLKEM768KEM_Decaps_InvalidInput verifies that Decaps returns
// an error when called with invalid ciphertexts.
func TestIncrementalMLKEM768KEM_Decaps_InvalidInput(t *testing.T) {
	k := NewIncrementalMLKEM768KEM()
	_, err := k.Decaps(make([]byte, 100), make([]byte, 5), make([]byte, 5))
	if err == nil {
		t.Fatal("expected error for invalid decaps input")
	}
}

// TestIncrementalMLKEM768KEM_Encaps2_InvalidInput verifies that Encaps2 returns
// an error when encapsSecret is invalid (wrong size).
func TestIncrementalMLKEM768KEM_Encaps2_InvalidInput(t *testing.T) {
	k := NewIncrementalMLKEM768KEM()
	// encapsSecret should be 2080 bytes (EncapsStateSize)
	_, err := k.Encaps2(make([]byte, 5), nil, make([]byte, 1152))
	if err == nil {
		t.Fatal("expected error for invalid encapsSecret")
	}
}

// ================== InitBob error paths ==================

// TestInitBob_NilKEM verifies that InitBob returns an error for a nil KEM.
func TestInitBob_NilKEM(t *testing.T) {
	_, err := InitBob([]byte("secret"), nil, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for nil KEM")
	}
}

// TestInitBob_InvalidChunkSize verifies that InitBob returns an error for
// a non-positive chunk size.
func TestInitBob_InvalidChunkSize(t *testing.T) {
	_, err := InitBob([]byte("secret"), NewMLKEM768IncrementalKEM(), 0)
	if err == nil {
		t.Fatal("expected error for zero chunk size")
	}
}

// TestInitAlice_NilKEM verifies that InitAlice returns an error for a nil KEM.
func TestInitAlice_NilKEM(t *testing.T) {
	_, err := InitAlice([]byte("secret"), nil, DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for nil KEM")
	}
}

// TestInitAlice_InvalidChunkSize verifies that InitAlice returns an error for
// a non-positive chunk size.
func TestInitAlice_InvalidChunkSize(t *testing.T) {
	_, err := InitAlice([]byte("secret"), NewMLKEM768IncrementalKEM(), -1)
	if err == nil {
		t.Fatal("expected error for negative chunk size")
	}
}

// TestInitBob_EmptySecret verifies that InitBob returns an error for empty secret.
func TestInitBob_EmptySecret(t *testing.T) {
	_, err := InitBob(nil, NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err == nil {
		t.Fatal("expected error for empty shared secret")
	}
}

// ================== NewEncoderFromInner error paths ==================

// TestNewEncoderFromInner_ExceedMaxChunkCount verifies that NewEncoderFromInner
// returns an error when the computed total exceeds MaxChunkIndex+1.
func TestNewEncoderFromInner_ExceedMaxChunkCount(t *testing.T) {
	data := make([]byte, 32)
	inner, err := polynomial.NewPolyEncoder(data)
	if err != nil {
		t.Fatalf("NewPolyEncoder: %v", err)
	}
	// Pass a msgLen that would result in (msgLen/32) > MaxChunkIndex+1.
	hugeLen := (MaxChunkIndex + 2) * ChunkDataSize
	_, err = NewEncoderFromInner(inner, 0, hugeLen)
	if err == nil {
		t.Fatal("expected error for excessive msgLen")
	}
}
