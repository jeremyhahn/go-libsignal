package incremental_mlkem768

import (
	"testing"
)

// TestFieldArithmetic verifies the modular field arithmetic primitives.
func TestFieldArithmetic(t *testing.T) {
	t.Run("fieldReduceOnce reduces values less than 2q", func(t *testing.T) {
		// values < q should remain unchanged
		if got := fieldReduceOnce(0); got != 0 {
			t.Errorf("fieldReduceOnce(0) = %d, want 0", got)
		}
		if got := fieldReduceOnce(q - 1); got != q-1 {
			t.Errorf("fieldReduceOnce(q-1) = %d, want %d", got, q-1)
		}
		// values >= q should be reduced
		if got := fieldReduceOnce(q); got != 0 {
			t.Errorf("fieldReduceOnce(q) = %d, want 0", got)
		}
		if got := fieldReduceOnce(2*q - 1); got != q-1 {
			t.Errorf("fieldReduceOnce(2q-1) = %d, want %d", got, q-1)
		}
	})

	t.Run("fieldAdd is correct modulo q", func(t *testing.T) {
		a := fieldElement(q - 1)
		b := fieldElement(1)
		if got := fieldAdd(a, b); got != 0 {
			t.Errorf("fieldAdd(q-1, 1) = %d, want 0", got)
		}
		if got := fieldAdd(100, 200); got != 300 {
			t.Errorf("fieldAdd(100, 200) = %d, want 300", got)
		}
	})

	t.Run("fieldSub is correct modulo q", func(t *testing.T) {
		if got := fieldSub(0, 1); got != q-1 {
			t.Errorf("fieldSub(0, 1) = %d, want %d", got, q-1)
		}
		if got := fieldSub(5, 5); got != 0 {
			t.Errorf("fieldSub(5, 5) = %d, want 0", got)
		}
	})

	t.Run("fieldMul is correct modulo q", func(t *testing.T) {
		// 2 * 3 = 6
		if got := fieldMul(2, 3); got != 6 {
			t.Errorf("fieldMul(2, 3) = %d, want 6", got)
		}
		// (q-1) * 2 mod q = q - 2
		if got := fieldMul(q-1, 2); got != q-2 {
			t.Errorf("fieldMul(q-1, 2) = %d, want %d", got, q-2)
		}
	})

	t.Run("compress then decompress is near-identity", func(t *testing.T) {
		// compress followed by decompress should be within rounding error
		for _, x := range []fieldElement{0, 1, q / 2, q - 1, 1664} {
			c := compress(x, 10)
			d := decompress(c, 10)
			// The error bound for d=10 is at most q/2^11 ~ 1.6
			diff := int32(x) - int32(d)
			if diff < 0 {
				diff = -diff
			}
			// Allow modular wrap-around
			if diff > int32(q)/2 {
				diff = int32(q) - diff
			}
			if diff > 2 {
				t.Errorf("compress/decompress(10) error too large for x=%d: got %d, diff=%d", x, d, diff)
			}
		}
	})
}

// TestNTT verifies NTT round-trip property.
func TestNTT(t *testing.T) {
	t.Run("nttForward + nttInverse = identity", func(t *testing.T) {
		// Use a simple polynomial with small coefficients.
		var f ringElement
		for i := range f {
			f[i] = fieldElement(i % q)
		}
		fhat := nttForward(f)
		freconstructed := nttInverse(fhat)
		for i := range f {
			if f[i] != freconstructed[i] {
				t.Errorf("NTT round-trip failed at index %d: got %d, want %d", i, freconstructed[i], f[i])
			}
		}
	})

	t.Run("nttForward of zero is zero", func(t *testing.T) {
		var f ringElement
		fhat := nttForward(f)
		for i, c := range fhat {
			if c != 0 {
				t.Errorf("NTT(0)[%d] = %d, want 0", i, c)
			}
		}
	})
}

// TestSampleNTT verifies sampleNTT produces coefficients in [0, q).
func TestSampleNTT(t *testing.T) {
	rho := make([]byte, 32)
	a := sampleNTT(rho, 0, 0)
	for i, c := range a {
		if uint16(c) >= q {
			t.Errorf("sampleNTT coefficient %d out of range: %d >= %d", i, c, q)
		}
	}

	// Two different (ii, jj) pairs should produce different elements.
	a00 := sampleNTT(rho, 0, 0)
	a01 := sampleNTT(rho, 0, 1)
	same := true
	for i := range a00 {
		if a00[i] != a01[i] {
			same = false
			break
		}
	}
	if same {
		t.Error("sampleNTT(0,0) == sampleNTT(0,1): expected different polynomials")
	}
}

// TestSamplePolyCBD verifies CBD sampling produces small coefficients.
func TestSamplePolyCBD(t *testing.T) {
	s := make([]byte, 32)
	f := samplePolyCBD(s, 0)
	// CBD with eta=2 produces coefficients in {-2,-1,0,1,2} mod q = {q-2, q-1, 0, 1, 2}.
	for i, c := range f {
		if uint16(c) >= q {
			t.Errorf("samplePolyCBD coefficient %d out of range: %d >= %d", i, c, q)
		}
		// Allowed values mod q.
		v := uint16(c)
		ok := v == 0 || v == 1 || v == 2 || v == q-1 || v == q-2
		if !ok {
			t.Errorf("samplePolyCBD coefficient %d has unexpected value %d", i, v)
		}
	}
}

// TestByteEncodeDecode12 verifies ByteEncode12 / ByteDecode12 round-trip.
func TestByteEncodeDecode12(t *testing.T) {
	t.Run("encode then decode = identity", func(t *testing.T) {
		// Build a polynomial with values in [0, q).
		var f nttElement
		for i := range f {
			f[i] = fieldElement(uint16(i*13) % q)
		}
		encoded := byteEncode12(nil, f)
		if len(encoded) != encodingSize12 {
			t.Fatalf("byteEncode12 output length %d, want %d", len(encoded), encodingSize12)
		}
		decoded, err := byteDecode12(encoded)
		if err != nil {
			t.Fatalf("byteDecode12 error: %v", err)
		}
		for i := range f {
			if f[i] != decoded[i] {
				t.Errorf("encode/decode round-trip failed at %d: got %d, want %d", i, decoded[i], f[i])
			}
		}
	})

	t.Run("byteDecode12 rejects unreduced coefficients", func(t *testing.T) {
		// Craft bytes that encode a value >= q.
		b := make([]byte, encodingSize12)
		// First coefficient pair: 0x0FFF = 4095 > q=3329.
		b[0] = 0xFF
		b[1] = 0x0F // d1 = 0x0FFF = 4095 >= q
		b[2] = 0x00
		_, err := byteDecode12(b)
		if err == nil {
			t.Error("byteDecode12 should reject coefficient >= q")
		}
	})
}

// TestEncapsStateRoundTrip verifies the 2080-byte encapsulation state serialization.
func TestEncapsStateRoundTrip(t *testing.T) {
	// Build test state with known values.
	var rAsNTT [k]nttElement
	for i := range rAsNTT {
		for j := range rAsNTT[i] {
			rAsNTT[i][j] = fieldElement(uint16(i*256+j) % q)
		}
	}
	var error2 ringElement
	for i := range error2 {
		// Use only small CBD-range values: {0, 1, 2, q-1, q-2}.
		switch i % 5 {
		case 0:
			error2[i] = 0
		case 1:
			error2[i] = 1
		case 2:
			error2[i] = 2
		case 3:
			error2[i] = q - 1
		case 4:
			error2[i] = q - 2
		}
	}
	var randomness [32]byte
	for i := range randomness {
		randomness[i] = byte(i * 7)
	}

	blob := encapsStateToBytes(rAsNTT, error2, randomness)
	if len(blob) != EncapsStateSize {
		t.Fatalf("encapsStateToBytes output size %d, want %d", len(blob), EncapsStateSize)
	}

	rOut, e2Out, randOut, err := encapsStateFromBytes(blob[:])
	if err != nil {
		t.Fatalf("encapsStateFromBytes error: %v", err)
	}

	for i := range rAsNTT {
		for j := range rAsNTT[i] {
			if rAsNTT[i][j] != rOut[i][j] {
				t.Errorf("r_as_ntt[%d][%d] mismatch: got %d, want %d", i, j, rOut[i][j], rAsNTT[i][j])
			}
		}
	}
	for i := range error2 {
		if error2[i] != e2Out[i] {
			t.Errorf("error2[%d] mismatch: got %d, want %d", i, e2Out[i], error2[i])
		}
	}
	if randomness != randOut {
		t.Error("randomness mismatch after round-trip")
	}
}

// TestEncaps1RoundTrip tests that Encaps1 produces outputs with correct sizes and
// that the ss is non-zero (basic sanity; full KAT requires Decaps which is not yet ported).
func TestEncaps1RoundTrip(t *testing.T) {
	// We use a known pk1 derived from a zero seed. This is not a real key pair;
	// we only test that Encaps1 runs and produces correctly-sized outputs.
	//
	// Real key-round-trip test requires GenerateKey + Decaps, which are TODO(#10).
	var pk1 [PublicKey1Size]byte
	// pk1[:32] = seed_for_A, pk1[32:] = H(ek). Use deterministic values.
	for i := range pk1[:32] {
		pk1[i] = byte(i + 1)
	}
	for i := range pk1[32:] {
		pk1[32+i] = byte(i + 0x80)
	}

	var randomness [SharedSecretSize]byte
	for i := range randomness {
		randomness[i] = byte(i + 0x42)
	}

	ct1, es, ss, err := Encaps1(pk1[:], randomness)
	if err != nil {
		t.Fatalf("Encaps1 error: %v", err)
	}
	if len(ct1) != Ciphertext1Size {
		t.Errorf("ct1 size %d, want %d", len(ct1), Ciphertext1Size)
	}
	if len(ss) != SharedSecretSize {
		t.Errorf("ss size %d, want %d", len(ss), SharedSecretSize)
	}

	// es should be non-zero (it holds the encapsulation state).
	esAllZero := true
	for _, b := range es {
		if b != 0 {
			esAllZero = false
			break
		}
	}
	if esAllZero {
		t.Error("Encaps1 returned all-zero encapsulation state")
	}

	// ss should be non-zero.
	allZero := true
	for _, b := range ss {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Encaps1 returned all-zero shared secret")
	}

	// ct1 should be non-zero.
	allZero = true
	for _, b := range ct1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Encaps1 returned all-zero ct1")
	}
}

// TestEncaps1InvalidInput verifies error handling for bad inputs.
func TestEncaps1InvalidInput(t *testing.T) {
	var randomness [SharedSecretSize]byte
	_, _, _, err := Encaps1(nil, randomness)
	if err == nil {
		t.Error("Encaps1 should reject nil pk1")
	}
	_, _, _, err = Encaps1(make([]byte, 32), randomness) // too short
	if err == nil {
		t.Error("Encaps1 should reject pk1 of length 32")
	}
}

// TestEncaps2InvalidInput verifies error handling for bad inputs.
func TestEncaps2InvalidInput(t *testing.T) {
	_, err := Encaps2(nil, make([]byte, PublicKey2Size))
	if err == nil {
		t.Error("Encaps2 should reject nil es")
	}
	_, err = Encaps2(make([]byte, EncapsStateSize), nil)
	if err == nil {
		t.Error("Encaps2 should reject nil pk2")
	}
	_, err = Encaps2(make([]byte, EncapsStateSize-1), make([]byte, PublicKey2Size))
	if err == nil {
		t.Error("Encaps2 should reject short es")
	}
}

// TestEncaps1Determinism verifies that the same inputs produce the same output.
func TestEncaps1Determinism(t *testing.T) {
	var pk1 [PublicKey1Size]byte
	var randomness [SharedSecretSize]byte
	for i := range pk1 {
		pk1[i] = byte(i)
	}
	for i := range randomness {
		randomness[i] = byte(i + 100)
	}

	ct1a, esa, ssa, err := Encaps1(pk1[:], randomness)
	if err != nil {
		t.Fatalf("Encaps1 first call error: %v", err)
	}
	ct1b, esb, ssb, err := Encaps1(pk1[:], randomness)
	if err != nil {
		t.Fatalf("Encaps1 second call error: %v", err)
	}

	if ct1a != ct1b {
		t.Error("Encaps1 is not deterministic: ct1 differs")
	}
	if esa != esb {
		t.Error("Encaps1 is not deterministic: es differs")
	}
	if ssa != ssb {
		t.Error("Encaps1 is not deterministic: ss differs")
	}
}

// TestErrorMessages covers Error() on all error types in this package.
func TestErrorMessages(t *testing.T) {
	t.Run("ErrInvalidInputLength", func(t *testing.T) {
		e := &ErrInvalidInputLength{Name: "dk", Expected: 2400, Got: 100}
		msg := e.Error()
		if msg == "" {
			t.Fatal("Error() returned empty string")
		}
		if len(msg) < 10 {
			t.Errorf("Error() message too short: %q", msg)
		}
	})

	t.Run("ErrInvalidCoefficient", func(t *testing.T) {
		e := &ErrInvalidCoefficient{Index: 5, Value: 4000}
		msg := e.Error()
		if msg == "" {
			t.Fatal("Error() returned empty string")
		}
	})

	t.Run("ErrInvalidPublicKey", func(t *testing.T) {
		e := ErrInvalidPublicKey{Detail: "hash mismatch"}
		msg := e.Error()
		if msg == "" {
			t.Fatal("Error() returned empty string")
		}
	})
}

// TestGenerateRandom verifies that GenerateRandom fills a buffer with random bytes.
func TestGenerateRandom(t *testing.T) {
	buf := make([]byte, 32)
	if err := GenerateRandom(buf); err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}
	// Very unlikely that all bytes are zero.
	allZero := true
	for _, b := range buf {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("GenerateRandom returned all zeros — likely broken entropy source")
	}
}
