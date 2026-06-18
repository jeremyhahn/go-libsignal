package zkgroup

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// buildV1Bytes constructs a valid V1/V2 presentation byte slice with the given
// version byte, 8 Ristretto255 points, a poksho_proof payload, and two
// ciphertexts. This mirrors the Rust bincode layout exactly.
//
// Wire layout:
//
//	[0]       version byte
//	[1..257]  8 × 32-byte compressed Ristretto255 points
//	[257..265] 8-byte LE u64: proof length
//	[265..N]  proof bytes
//	[N..N+64] uid_enc_ciphertext (EA1 ∥ EA2)
//	[N+64..]  profile_key_enc_ciphertext (EA1 ∥ EA2)
func buildLegacyPresentationBytes(version byte, points [8]*ristretto255.Element, proof []byte, uidCT, pkCT *zkcredential.Ciphertext) []byte {
	var buf bytes.Buffer
	buf.WriteByte(version)
	for _, pt := range points {
		buf.Write(pt.Bytes())
	}
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(proof)))
	buf.Write(lenBuf[:])
	buf.Write(proof)
	buf.Write(zkcredential.EncodeCiphertext(uidCT))
	buf.Write(zkcredential.EncodeCiphertext(pkCT))
	return buf.Bytes()
}

// makeTestPoints returns 8 distinct non-identity Ristretto255 points for use in tests.
func makeTestPoints() [8]*ristretto255.Element {
	var pts [8]*ristretto255.Element
	for i := range pts {
		sc := ristretto255.NewScalar()
		var b [32]byte
		b[0] = byte(i + 1)
		_, _ = sc.SetCanonicalBytes(b[:])
		pts[i] = new(ristretto255.Element).ScalarBaseMult(sc)
	}
	return pts
}

// makeTestCiphertext returns a non-zero ciphertext (EA1 = i*G, EA2 = (i+1)*G).
func makeTestCiphertext(i byte) *zkcredential.Ciphertext {
	sc1 := ristretto255.NewScalar()
	var b1 [32]byte
	b1[0] = i
	if i == 0 {
		b1[0] = 0x80
	}
	_, _ = sc1.SetCanonicalBytes(b1[:])

	sc2 := ristretto255.NewScalar()
	var b2 [32]byte
	b2[0] = i + 1
	_, _ = sc2.SetCanonicalBytes(b2[:])

	return &zkcredential.Ciphertext{
		EA1: new(ristretto255.Element).ScalarBaseMult(sc1),
		EA2: new(ristretto255.Element).ScalarBaseMult(sc2),
	}
}

// TestDeserializeAnyPresentationV1RoundTrip verifies that a well-formed V1
// presentation round-trips through DeserializeAnyProfileKeyCredentialPresentation
// and that the accessors return the correct ciphertexts.
func TestDeserializeAnyPresentationV1RoundTrip(t *testing.T) {
	pts := makeTestPoints()
	proof := bytes.Repeat([]byte{0xAB}, 320)
	uidCT := makeTestCiphertext(10)
	pkCT := makeTestCiphertext(20)

	raw := buildLegacyPresentationBytes(PresentationVersion1, pts, proof, uidCT, pkCT)
	if raw[0] != PresentationVersion1 {
		t.Fatalf("expected version byte 0x00, got 0x%02x", raw[0])
	}

	any, err := DeserializeAnyProfileKeyCredentialPresentation(raw)
	if err != nil {
		t.Fatalf("DeserializeAnyProfileKeyCredentialPresentation: %v", err)
	}
	if any.Version != PresentationVersion1 {
		t.Errorf("version: want %d, got %d", PresentationVersion1, any.Version)
	}
	if any.V1 == nil {
		t.Fatal("V1 field is nil")
	}
	if any.V2 != nil || any.V3 != nil || any.V4 != nil {
		t.Error("expected only V1 to be set")
	}

	gotUID := any.GetUUIDCiphertext()
	if gotUID == nil {
		t.Fatal("GetUUIDCiphertext returned nil")
	}
	if !gotUID.Ciphertext.Equal(uidCT) {
		t.Error("UID ciphertext mismatch after deserialization")
	}

	gotPK := any.GetProfileKeyCiphertext()
	if gotPK == nil {
		t.Fatal("GetProfileKeyCiphertext returned nil")
	}
	if !gotPK.Ciphertext.Equal(pkCT) {
		t.Error("profile key ciphertext mismatch after deserialization")
	}

	// V1 must not report an expiration time.
	if _, ok := any.GetExpirationTime(); ok {
		t.Error("V1 presentation must not have an expiration time")
	}
}

// TestDeserializeAnyPresentationV2RoundTrip verifies the same round-trip for V2.
func TestDeserializeAnyPresentationV2RoundTrip(t *testing.T) {
	pts := makeTestPoints()
	proof := bytes.Repeat([]byte{0xCD}, 320)
	uidCT := makeTestCiphertext(30)
	pkCT := makeTestCiphertext(40)

	raw := buildLegacyPresentationBytes(PresentationVersion2, pts, proof, uidCT, pkCT)
	if raw[0] != PresentationVersion2 {
		t.Fatalf("expected version byte 0x01, got 0x%02x", raw[0])
	}

	any, err := DeserializeAnyProfileKeyCredentialPresentation(raw)
	if err != nil {
		t.Fatalf("DeserializeAnyProfileKeyCredentialPresentation: %v", err)
	}
	if any.Version != PresentationVersion2 {
		t.Errorf("version: want %d, got %d", PresentationVersion2, any.Version)
	}
	if any.V2 == nil {
		t.Fatal("V2 field is nil")
	}
	if any.V1 != nil || any.V3 != nil || any.V4 != nil {
		t.Error("expected only V2 to be set")
	}

	gotUID := any.GetUUIDCiphertext()
	if gotUID == nil {
		t.Fatal("GetUUIDCiphertext returned nil")
	}
	if !gotUID.Ciphertext.Equal(uidCT) {
		t.Error("UID ciphertext mismatch after deserialization")
	}

	gotPK := any.GetProfileKeyCiphertext()
	if gotPK == nil {
		t.Fatal("GetProfileKeyCiphertext returned nil")
	}
	if !gotPK.Ciphertext.Equal(pkCT) {
		t.Error("profile key ciphertext mismatch after deserialization")
	}

	// V2 must not report an expiration time.
	if _, ok := any.GetExpirationTime(); ok {
		t.Error("V2 presentation must not have an expiration time")
	}
}

// TestDeserializeAnyPresentationV3V4RoundTrip verifies that a presentation
// produced by CreateExpiringProfileKeyCredentialPresentation can be serialized
// and then deserialized via DeserializeAnyProfileKeyCredentialPresentation for
// both V3 and V4 version bytes.
func TestDeserializeAnyPresentationV3V4RoundTrip(t *testing.T) {
	// Build a real expiring credential so we can create a real presentation.
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 7)
	}
	serverSecret, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverSecret.GetPublicParams()

	var aciUUID UIDBytes
	for i := range aciUUID {
		aciUUID[i] = byte(i + 0x61)
	}
	aci := NewACI(aciUUID)

	var pkBytes ProfileKeyBytes
	for i := range pkBytes {
		pkBytes[i] = byte(i + 1)
	}
	profileKey := NewProfileKey(pkBytes)

	var reqRandomness RandomnessBytes
	for i := range reqRandomness {
		reqRandomness[i] = byte(i + 20)
	}
	ctx, err := serverPublic.CreateProfileKeyCredentialRequestContext(reqRandomness, aci, profileKey)
	if err != nil {
		t.Fatalf("CreateProfileKeyCredentialRequestContext: %v", err)
	}

	commitment := profileKey.GetCommitment(aci)
	currentTime := NewTimestamp(SecondsPerDay * 200)
	expirationTime := NewTimestamp(SecondsPerDay * 203)

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 30)
	}
	response, err := serverSecret.IssueExpiringProfileKeyCredential(
		issueRandomness, ctx.GetRequest(), aci, commitment, expirationTime,
	)
	if err != nil {
		t.Fatalf("IssueExpiringProfileKeyCredential: %v", err)
	}

	credential, err := serverPublic.ReceiveExpiringProfileKeyCredential(ctx, response, currentTime)
	if err != nil {
		t.Fatalf("ReceiveExpiringProfileKeyCredential: %v", err)
	}

	groupParams, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	var presRandomness RandomnessBytes
	for i := range presRandomness {
		presRandomness[i] = byte(i + 40)
	}
	presentation, err := serverPublic.CreateExpiringProfileKeyCredentialPresentation(
		presRandomness, groupParams, credential, PresentationVersion3,
	)
	if err != nil {
		t.Fatalf("CreateExpiringProfileKeyCredentialPresentation: %v", err)
	}

	for _, tc := range []struct {
		name    string
		version byte
		checkV3 bool
	}{
		{"V3", PresentationVersion3, true},
		{"V4", PresentationVersion4, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := SerializeExpiringProfileKeyCredentialPresentation(tc.version, presentation)
			if raw[0] != tc.version {
				t.Errorf("version byte: want %d, got %d", tc.version, raw[0])
			}

			any, err := DeserializeAnyProfileKeyCredentialPresentation(raw)
			if err != nil {
				t.Fatalf("DeserializeAnyProfileKeyCredentialPresentation: %v", err)
			}
			if any.Version != tc.version {
				t.Errorf("version field: want %d, got %d", tc.version, any.Version)
			}

			var inner *ExpiringProfileKeyCredentialPresentation
			if tc.checkV3 {
				if any.V3 == nil {
					t.Fatal("V3 field is nil")
				}
				inner = any.V3
			} else {
				if any.V4 == nil {
					t.Fatal("V4 field is nil")
				}
				inner = any.V4
			}

			// Verify expiration time survived round-trip.
			gotExp, ok := any.GetExpirationTime()
			if !ok {
				t.Errorf("%s should have expiration time", tc.name)
			}
			if gotExp != expirationTime {
				t.Errorf("expiration: want %d, got %d", expirationTime.EpochSeconds(), gotExp.EpochSeconds())
			}

			// Verify the ciphertexts round-tripped correctly.
			origUID := presentation.GetUUIDCiphertext()
			if !inner.GetUUIDCiphertext().Ciphertext.Equal(origUID.Ciphertext) {
				t.Error("UID ciphertext mismatch after round-trip")
			}
			origPK := presentation.GetProfileKeyCiphertext()
			if !inner.GetProfileKeyCiphertext().Ciphertext.Equal(origPK.Ciphertext) {
				t.Error("profile key ciphertext mismatch after round-trip")
			}
		})
	}
}

// TestDeserializeAnyPresentationDispatchErrors verifies error cases for the
// DeserializeAnyProfileKeyCredentialPresentation dispatcher.
func TestDeserializeAnyPresentationDispatchErrors(t *testing.T) {
	t.Run("empty input returns ErrDataTooShort", func(t *testing.T) {
		_, err := DeserializeAnyProfileKeyCredentialPresentation([]byte{})
		if err == nil {
			t.Fatal("expected error for empty input")
		}
		var e *ErrDataTooShort
		if !errors.As(err, &e) {
			t.Errorf("expected *ErrDataTooShort, got %T: %v", err, err)
		}
	})

	t.Run("unknown version byte returns ErrUnknownPresentationVersion", func(t *testing.T) {
		for _, version := range []byte{0x04, 0x10, 0xFF} {
			_, err := DeserializeAnyProfileKeyCredentialPresentation([]byte{version, 0, 0, 0})
			if err == nil {
				t.Fatalf("expected error for version 0x%02x", version)
			}
			var e *ErrUnknownPresentationVersion
			if !errors.As(err, &e) {
				t.Errorf("version 0x%02x: expected *ErrUnknownPresentationVersion, got %T: %v", version, err, err)
			}
			if !errors.Is(err, ErrDeserializationFailure) {
				t.Errorf("version 0x%02x: expected error to wrap ErrDeserializationFailure", version)
			}
			if e != nil && e.Version != version {
				t.Errorf("version 0x%02x: ErrUnknownPresentationVersion.Version = %d", version, e.Version)
			}
		}
	})

	t.Run("truncated V1 input returns ErrDataTooShort", func(t *testing.T) {
		// 1 byte (version) + fewer than 265 bytes minimum.
		truncated := make([]byte, 100)
		truncated[0] = PresentationVersion1
		_, err := DeserializeAnyProfileKeyCredentialPresentation(truncated)
		if err == nil {
			t.Fatal("expected error for truncated V1 input")
		}
		var e *ErrDataTooShort
		if !errors.As(err, &e) {
			t.Errorf("expected *ErrDataTooShort, got %T: %v", err, err)
		}
	})

	t.Run("truncated V2 input returns ErrDataTooShort", func(t *testing.T) {
		truncated := make([]byte, 100)
		truncated[0] = PresentationVersion2
		_, err := DeserializeAnyProfileKeyCredentialPresentation(truncated)
		if err == nil {
			t.Fatal("expected error for truncated V2 input")
		}
		var e *ErrDataTooShort
		if !errors.As(err, &e) {
			t.Errorf("expected *ErrDataTooShort, got %T: %v", err, err)
		}
	})

	t.Run("V1 with declared proof length exceeding buffer returns ErrDataTooShort", func(t *testing.T) {
		// Build a well-formed header but claim a massive proof length.
		pts := makeTestPoints()
		var buf bytes.Buffer
		buf.WriteByte(PresentationVersion1)
		for _, pt := range pts {
			buf.Write(pt.Bytes())
		}
		// Claim proof is 10000 bytes, but provide nothing.
		var lenBuf [8]byte
		binary.LittleEndian.PutUint64(lenBuf[:], 10000)
		buf.Write(lenBuf[:])
		// Only append 10 actual proof bytes (far less than claimed).
		buf.Write(make([]byte, 10))

		_, err := DeserializeAnyProfileKeyCredentialPresentation(buf.Bytes())
		if err == nil {
			t.Fatal("expected error for overflowing proof length")
		}
		var e *ErrDataTooShort
		if !errors.As(err, &e) {
			t.Errorf("expected *ErrDataTooShort, got %T: %v", err, err)
		}
	})

	t.Run("V1 with invalid ristretto point returns deserialization error", func(t *testing.T) {
		// Build a presentation where the first proof point is all-zeros (invalid
		// for ristretto255 since the identity element is not a valid canonical
		// point in this context — actually identity IS valid in ristretto255 but
		// a non-canonical encoding is not). Use a byte sequence that is not a
		// valid Ristretto255 encoding (e.g., the all-0xFF sequence).
		raw := make([]byte, 713)
		raw[0] = PresentationVersion1
		// Set first point bytes to 0xFF...0xFF (invalid Ristretto255 encoding).
		for i := 1; i <= 32; i++ {
			raw[i] = 0xFF
		}
		_, err := DeserializeAnyProfileKeyCredentialPresentation(raw)
		if err == nil {
			t.Fatal("expected error for invalid Ristretto255 point encoding")
		}
		var desErr *ZkGroupDeserializationFailure
		if !errors.As(err, &desErr) {
			t.Errorf("expected *ZkGroupDeserializationFailure, got %T: %v", err, err)
		}
	})
}

// TestDeserializeAnyPresentationV1AccessorsViaAny verifies that accessor methods
// on AnyProfileKeyCredentialPresentation return the same values as the
// underlying V1 struct's accessors.
func TestDeserializeAnyPresentationV1AccessorsViaAny(t *testing.T) {
	pts := makeTestPoints()
	proof := bytes.Repeat([]byte{0x01}, 320)
	uidCT := makeTestCiphertext(5)
	pkCT := makeTestCiphertext(6)

	raw := buildLegacyPresentationBytes(PresentationVersion1, pts, proof, uidCT, pkCT)
	any, err := DeserializeAnyProfileKeyCredentialPresentation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Accessors via AnyProfileKeyCredentialPresentation.
	gotUID := any.GetUUIDCiphertext()
	if gotUID == nil {
		t.Fatal("GetUUIDCiphertext returned nil via Any")
	}

	// Accessor via the concrete V1 type directly.
	directUID := any.V1.GetUUIDCiphertext()
	if directUID == nil {
		t.Fatal("GetUUIDCiphertext returned nil via V1")
	}

	if gotUID != directUID {
		t.Error("Any.GetUUIDCiphertext() and V1.GetUUIDCiphertext() should return the same pointer")
	}

	gotPK := any.GetProfileKeyCiphertext()
	directPK := any.V1.GetProfileKeyCiphertext()
	if gotPK != directPK {
		t.Error("Any.GetProfileKeyCiphertext() and V1.GetProfileKeyCiphertext() should return the same pointer")
	}
}

// TestDeserializeAnyPresentationV2AccessorsViaAny verifies accessor delegation
// for V2 presentations.
func TestDeserializeAnyPresentationV2AccessorsViaAny(t *testing.T) {
	pts := makeTestPoints()
	proof := bytes.Repeat([]byte{0x02}, 320)
	uidCT := makeTestCiphertext(7)
	pkCT := makeTestCiphertext(8)

	raw := buildLegacyPresentationBytes(PresentationVersion2, pts, proof, uidCT, pkCT)
	any, err := DeserializeAnyProfileKeyCredentialPresentation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	gotUID := any.GetUUIDCiphertext()
	directUID := any.V2.GetUUIDCiphertext()
	if gotUID != directUID {
		t.Error("Any.GetUUIDCiphertext() and V2.GetUUIDCiphertext() should return the same pointer")
	}

	gotPK := any.GetProfileKeyCiphertext()
	directPK := any.V2.GetProfileKeyCiphertext()
	if gotPK != directPK {
		t.Error("Any.GetProfileKeyCiphertext() and V2.GetProfileKeyCiphertext() should return the same pointer")
	}
}

// TestProfileKeyCredentialPresentationV1DirectAccessors verifies that the
// direct accessor methods on ProfileKeyCredentialPresentationV1 work correctly.
func TestProfileKeyCredentialPresentationV1DirectAccessors(t *testing.T) {
	pts := makeTestPoints()
	proof := make([]byte, 10)
	uidCT := makeTestCiphertext(50)
	pkCT := makeTestCiphertext(60)

	raw := buildLegacyPresentationBytes(PresentationVersion1, pts, proof, uidCT, pkCT)
	any, err := DeserializeAnyProfileKeyCredentialPresentation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v1 := any.V1
	if v1 == nil {
		t.Fatal("V1 is nil")
	}

	if !v1.GetUUIDCiphertext().Ciphertext.Equal(uidCT) {
		t.Error("V1 UUID ciphertext does not match input")
	}
	if !v1.GetProfileKeyCiphertext().Ciphertext.Equal(pkCT) {
		t.Error("V1 profile key ciphertext does not match input")
	}
}

// TestProfileKeyCredentialPresentationV2DirectAccessors verifies direct
// accessor methods on ProfileKeyCredentialPresentationV2.
func TestProfileKeyCredentialPresentationV2DirectAccessors(t *testing.T) {
	pts := makeTestPoints()
	proof := make([]byte, 10)
	uidCT := makeTestCiphertext(70)
	pkCT := makeTestCiphertext(80)

	raw := buildLegacyPresentationBytes(PresentationVersion2, pts, proof, uidCT, pkCT)
	any, err := DeserializeAnyProfileKeyCredentialPresentation(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	v2 := any.V2
	if v2 == nil {
		t.Fatal("V2 is nil")
	}

	if !v2.GetUUIDCiphertext().Ciphertext.Equal(uidCT) {
		t.Error("V2 UUID ciphertext does not match input")
	}
	if !v2.GetProfileKeyCiphertext().Ciphertext.Equal(pkCT) {
		t.Error("V2 profile key ciphertext does not match input")
	}
}

// TestErrUnknownPresentationVersion verifies the typed error type, its message,
// and its Unwrap chain.
func TestErrUnknownPresentationVersion(t *testing.T) {
	err := &ErrUnknownPresentationVersion{Version: 0x99}

	msg := err.Error()
	if msg == "" {
		t.Error("error message must not be empty")
	}

	if !errors.Is(err, ErrDeserializationFailure) {
		t.Error("ErrUnknownPresentationVersion must unwrap to ErrDeserializationFailure")
	}

	var typed *ErrUnknownPresentationVersion
	if !errors.As(err, &typed) {
		t.Error("errors.As must succeed for *ErrUnknownPresentationVersion")
	}
	if typed.Version != 0x99 {
		t.Errorf("Version field: want 0x99, got 0x%02x", typed.Version)
	}
}

// TestSerializeExpiringProfileKeyCredentialPresentation verifies that the
// serialize function produces a byte slice whose first byte matches the
// requested version and that it is parseable back.
func TestSerializeExpiringProfileKeyCredentialPresentation(t *testing.T) {
	// Build a minimal but valid ExpiringProfileKeyCredentialPresentation.
	sc1 := ristretto255.NewScalar()
	var b [32]byte
	b[0] = 1
	_, _ = sc1.SetCanonicalBytes(b[:])
	el := new(ristretto255.Element).ScalarBaseMult(sc1)

	uidCT := makeTestCiphertext(11)
	pkCT := makeTestCiphertext(22)
	ts := NewTimestamp(SecondsPerDay * 300)

	pres := &ExpiringProfileKeyCredentialPresentation{
		Cx0:                      el,
		Cx1:                      el,
		Cy1:                      el,
		Cy2:                      el,
		Cy3:                      el,
		Cy4:                      el,
		Cy5:                      el,
		CV:                       el,
		PokshoProof:              []byte{1, 2, 3, 4},
		UIDEncCiphertext:         &UUIDCiphertext{Ciphertext: uidCT},
		ProfileKeyEncCiphertext:  &ProfileKeyCiphertext{Ciphertext: pkCT},
		CredentialExpirationTime: ts,
	}

	for _, version := range []byte{PresentationVersion3, PresentationVersion4} {
		raw := SerializeExpiringProfileKeyCredentialPresentation(version, pres)
		if len(raw) == 0 {
			t.Fatalf("version %d: empty output", version)
		}
		if raw[0] != version {
			t.Errorf("version %d: first byte is 0x%02x", version, raw[0])
		}

		// Must round-trip through the deserializer.
		any, err := DeserializeAnyProfileKeyCredentialPresentation(raw)
		if err != nil {
			t.Fatalf("version %d: DeserializeAnyProfileKeyCredentialPresentation: %v", version, err)
		}
		if any.Version != version {
			t.Errorf("version %d: got version field %d", version, any.Version)
		}

		gotTS, ok := any.GetExpirationTime()
		if !ok {
			t.Errorf("version %d: expected expiration time", version)
		}
		if gotTS != ts {
			t.Errorf("version %d: timestamp: want %d, got %d", version, ts.EpochSeconds(), gotTS.EpochSeconds())
		}
	}
}

// BenchmarkDeserializeAnyPresentationV1 measures the cost of deserializing
// a V1 presentation from wire bytes.
func BenchmarkDeserializeAnyPresentationV1(b *testing.B) {
	pts := makeTestPoints()
	proof := bytes.Repeat([]byte{0xAA}, 320)
	uidCT := makeTestCiphertext(1)
	pkCT := makeTestCiphertext(2)
	raw := buildLegacyPresentationBytes(PresentationVersion1, pts, proof, uidCT, pkCT)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeserializeAnyProfileKeyCredentialPresentation(raw)
	}
}

// BenchmarkDeserializeAnyPresentationV2 measures the cost of deserializing
// a V2 presentation from wire bytes.
func BenchmarkDeserializeAnyPresentationV2(b *testing.B) {
	pts := makeTestPoints()
	proof := bytes.Repeat([]byte{0xBB}, 320)
	uidCT := makeTestCiphertext(3)
	pkCT := makeTestCiphertext(4)
	raw := buildLegacyPresentationBytes(PresentationVersion2, pts, proof, uidCT, pkCT)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DeserializeAnyProfileKeyCredentialPresentation(raw)
	}
}
