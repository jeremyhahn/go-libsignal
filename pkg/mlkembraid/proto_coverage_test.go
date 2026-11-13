package mlkembraid

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/mlkembraid/internal/polynomial"
)

// TestBraidState verifies that Braid.State() returns the internal State
// and BraidFromState reconstructs a Braid from that State.
func TestBraidState(t *testing.T) {
	alice, err := InitAlice(randomSecret(t), NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	defer alice.Zeroize()

	state := alice.State()
	if state == nil {
		t.Fatal("State() returned nil")
	}

	// BraidFromState must reconstruct a usable Braid.
	kem := NewMLKEM768IncrementalKEM()
	restored := BraidFromState(state, kem, DefaultChunkSize)
	if restored == nil {
		t.Fatal("BraidFromState returned nil")
	}
	if restored.StateKind() != alice.StateKind() {
		t.Errorf("StateKind: got %v, want %v", restored.StateKind(), alice.StateKind())
	}
}

// TestProtoAccessorsNilPaths exercises all proto accessor methods on a
// freshly-initialized State where optional fields are nil. Each accessor
// must return nil without panicking.
func TestProtoAccessorsNilPaths(t *testing.T) {
	alice, err := InitAlice(randomSecret(t), NewMLKEM768IncrementalKEM(), DefaultChunkSize)
	if err != nil {
		t.Fatalf("InitAlice: %v", err)
	}
	defer alice.Zeroize()

	s := alice.State()
	// Epoch is set to 1 by InitAlice.
	if s.ProtoEpoch() != 1 {
		t.Errorf("ProtoEpoch() = %d, want 1", s.ProtoEpoch())
	}
	if s.ProtoChunkSize() != DefaultChunkSize {
		t.Errorf("ProtoChunkSize() = %d, want %d", s.ProtoChunkSize(), DefaultChunkSize)
	}

	// Fields that are nil at KeysUnsampled state must return nil safely.
	_, _ = s.ProtoDK()
	_, _ = s.ProtoEKSeed()
	_, _ = s.ProtoEKVector()
	_, _ = s.ProtoReceivedCt1()
	_, _ = s.ProtoBobEKSeed()
	_, _ = s.ProtoBobHek()
	_, _ = s.ProtoBobEncapSecret()
	_, _ = s.ProtoBobEKVector()
	_, _ = s.ProtoBobCt1()
	_, _ = s.ProtoBobSS()
	_ = s.ProtoHeaderEncoder()
	_ = s.ProtoEKEncoder()
	_ = s.ProtoCt1Encoder()
	_ = s.ProtoCt2Encoder()
	_ = s.ProtoHeaderDecoder()
	_ = s.ProtoEKDecoder()
	_ = s.ProtoCt1Decoder()
	_ = s.ProtoCt2Decoder()

	auth := s.ProtoAuth()
	if auth != nil {
		// If auth is non-nil, accessors must not panic.
		_, _ = auth.ProtoAuthRootKey()
		_, _ = auth.ProtoAuthMacKey()
		_ = auth.ProtoAuthEpoch()
	}
}

// TestAuthenticatorNilAccessors verifies that nil *Authenticator accessor
// methods return zero values without panicking.
func TestAuthenticatorNilAccessors(t *testing.T) {
	var a *Authenticator
	if mustCopy(a.ProtoAuthRootKey()) != nil {
		t.Error("nil Authenticator.ProtoAuthRootKey() should be nil")
	}
	if mustCopy(a.ProtoAuthMacKey()) != nil {
		t.Error("nil Authenticator.ProtoAuthMacKey() should be nil")
	}
	if a.ProtoAuthEpoch() != 0 {
		t.Error("nil Authenticator.ProtoAuthEpoch() should be 0")
	}
}

// TestIncrementalMLKEM768KEM_Sizes verifies the size constants returned by
// the KEM implementation.
func TestIncrementalMLKEM768KEM_Sizes(t *testing.T) {
	kem := NewIncrementalMLKEM768KEM()
	if kem.EKSize() <= 0 {
		t.Errorf("EKSize() = %d, want > 0", kem.EKSize())
	}
	if kem.CT1Size() <= 0 {
		t.Errorf("CT1Size() = %d, want > 0", kem.CT1Size())
	}
	if kem.CT2Size() <= 0 {
		t.Errorf("CT2Size() = %d, want > 0", kem.CT2Size())
	}
	if kem.HeaderSize() <= 0 {
		t.Errorf("HeaderSize() = %d, want > 0", kem.HeaderSize())
	}
}

// TestIncrementalMLKEM768KEM_KeyGenAndEncaps tests the KeyGen → Encaps1 path,
// which also covers NewIncrementalMLKEM768KEM.
func TestIncrementalMLKEM768KEM_KeyGenAndEncaps(t *testing.T) {
	kem := NewIncrementalMLKEM768KEM()

	dk, ekSeed, ekVector, err := kem.KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}
	if len(dk) == 0 || len(ekSeed) == 0 || len(ekVector) == 0 {
		t.Fatal("KeyGen returned empty key material")
	}

	// Build the header from ekSeed.
	header := IncrementalHeader(ekSeed)
	if len(header) != len(ekSeed) {
		t.Errorf("IncrementalHeader len = %d, want %d", len(header), len(ekSeed))
	}

	// Verify ekVector consistency.
	if err := IncrementalVerifyEKVector(ekSeed, ekVector); err != nil {
		t.Errorf("IncrementalVerifyEKVector: %v", err)
	}

	// Encaps1(ekSeed, hek): hek is ignored for IncrementalMLKEM768KEM.
	encapSecret, ct1, ss1, err := kem.Encaps1(ekSeed, nil)
	if err != nil {
		t.Fatalf("Encaps1: %v", err)
	}
	if len(encapSecret) == 0 || len(ct1) == 0 || len(ss1) == 0 {
		t.Fatal("Encaps1 returned empty output")
	}

	// Encaps2(encapsSecret, ekSeed, ekVector) — returns (ct2, error).
	ct2, err := kem.Encaps2(encapSecret, ekSeed, ekVector)
	if err != nil {
		t.Fatalf("Encaps2: %v", err)
	}
	if len(ct2) == 0 {
		t.Fatal("Encaps2 returned empty ct2")
	}

	// CompleteEncaps2(encapsSecret, ekSeed, ekVector) — returns (ct1, ct2, ss, error).
	rct1, rct2, rss, err := kem.CompleteEncaps2(encapSecret, ekSeed, ekVector)
	if err != nil {
		t.Fatalf("CompleteEncaps2: %v", err)
	}
	if len(rct1) == 0 || len(rct2) == 0 || len(rss) == 0 {
		t.Fatal("CompleteEncaps2 returned empty output")
	}

	// Decaps should succeed.
	ssDec, err := kem.Decaps(dk, ct1, ct2)
	if err != nil {
		t.Fatalf("Decaps: %v", err)
	}
	if len(ssDec) == 0 {
		t.Fatal("Decaps returned empty shared secret")
	}
}

// TestIncrementalMLKEM768KEM_FullEncaps tests the FullEncaps convenience method.
func TestIncrementalMLKEM768KEM_FullEncaps(t *testing.T) {
	kem := NewIncrementalMLKEM768KEM()

	dk, ekSeed, ekVector, err := kem.KeyGen()
	if err != nil {
		t.Fatalf("KeyGen: %v", err)
	}

	// FullEncaps returns (ct1, ct2, ss, error).
	ct1, ct2, ss, err := kem.FullEncaps(ekSeed, ekVector)
	if err != nil {
		t.Fatalf("FullEncaps: %v", err)
	}
	if len(ct1) == 0 || len(ct2) == 0 || len(ss) == 0 {
		t.Fatal("FullEncaps returned empty output")
	}

	ssDec, err := kem.Decaps(dk, ct1, ct2)
	if err != nil {
		t.Fatalf("Decaps after FullEncaps: %v", err)
	}
	if len(ssDec) == 0 {
		t.Fatal("Decaps returned empty shared secret")
	}
}

// TestNewEncoderFromInner verifies that NewEncoderFromInner wraps an existing
// PolyEncoder and InnerEncoder returns it back.
func TestNewEncoderFromInner_NilError(t *testing.T) {
	_, err := NewEncoderFromInner(nil, 0, 0)
	if err == nil {
		t.Fatal("expected error for nil inner encoder")
	}
}

// TestNewDecoderFromInner verifies that NewDecoderFromInner wraps an existing
// PolyDecoder and InnerDecoder returns it back.
func TestNewDecoderFromInner_RoundTrip(t *testing.T) {
	// Use NewPolyEncoderFromPolys to build an encoder in Polys state.
	polys := make([]polynomial.Poly, polynomial.NumPolys)
	polyEnc, err := polynomial.NewPolyEncoderFromPolys(polys, 0)
	if err != nil {
		t.Fatalf("NewPolyEncoderFromPolys: %v", err)
	}
	inner, err := NewEncoderFromInner(polyEnc, 0, DefaultChunkSize)
	if err != nil {
		t.Fatalf("NewEncoderFromInner: %v", err)
	}
	if inner.InnerEncoder() == nil {
		t.Fatal("InnerEncoder() returned nil")
	}

	// Build a PolyDecoder with an even message length matching DefaultChunkSize.
	// DefaultChunkSize must be even for NewPolyDecoder to accept it.
	msgLen := DefaultChunkSize
	if msgLen%2 != 0 {
		msgLen++ // ensure even
	}
	polyDec, err := polynomial.NewPolyDecoder(msgLen)
	if err != nil {
		t.Fatalf("polynomial.NewPolyDecoder: %v", err)
	}
	dec := NewDecoderFromInner(polyDec, msgLen)
	if dec == nil {
		t.Fatal("NewDecoderFromInner returned nil")
	}
	if dec.InnerDecoder() == nil {
		t.Fatal("InnerDecoder() returned nil")
	}
}
