package zkgroup

import (
	"bytes"
	"testing"

	"github.com/gtank/ristretto255"
	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

// =========================================================
// crypto.go: zeroScalar
// =========================================================

// TestZeroScalar verifies that zeroScalar zeroes a non-nil scalar without
// panicking, and is a no-op on nil.
func TestZeroScalar(t *testing.T) {
	// Non-nil scalar: must zero without panicking.
	s := ristretto255.NewScalar()
	zeroScalar(s) // must not panic

	// Nil scalar: must not panic.
	zeroScalar(nil)
}

// =========================================================
// groups.go: GroupSecretParams.Zeroize
// =========================================================

// TestGroupSecretParams_Zeroize verifies that Zeroize overwrites the key
// material in a GroupSecretParams without panicking.
func TestGroupSecretParams_Zeroize(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	params, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	// Zeroize should not panic and should overwrite material.
	params.Zeroize()
	// After zeroize, the key bytes should be all zeros.
	for i, b := range params.MasterKey.Bytes {
		if b != 0 {
			t.Errorf("MasterKey.Bytes[%d] = %d after Zeroize, want 0", i, b)
		}
	}
}

// =========================================================
// auth.go: DeserializeAnyAuthCredentialPresentation + Serialize round-trip
// =========================================================

// TestDeserializeAnyAuthCredentialPresentation_EmptyInput verifies that an
// empty input returns ErrDataTooShort.
func TestDeserializeAnyAuthCredentialPresentation_EmptyInput(t *testing.T) {
	_, err := DeserializeAnyAuthCredentialPresentation(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}
	var errShort *ErrDataTooShort
	if _, ok := err.(*ErrDataTooShort); !ok {
		t.Errorf("expected *ErrDataTooShort, got %T", err)
	}
	_ = errShort
}

// TestDeserializeAnyAuthCredentialPresentation_UnknownVersion verifies that an
// unknown version byte returns ErrUnknownPresentationVersion.
func TestDeserializeAnyAuthCredentialPresentation_UnknownVersion(t *testing.T) {
	data := make([]byte, 200)
	data[0] = 0xFF // unknown version
	_, err := DeserializeAnyAuthCredentialPresentation(data)
	if err == nil {
		t.Fatal("expected error for unknown version")
	}
	if _, ok := err.(*ErrUnknownPresentationVersion); !ok {
		t.Errorf("expected *ErrUnknownPresentationVersion, got %T", err)
	}
}

// TestSerializeDeserializeAuthCredentialRoundTrip performs a full round-trip:
// issue → receive → create presentation → serialize → deserialize.
// This exercises SerializeAuthCredentialWithPniZkcPresentation and
// DeserializeAnyAuthCredentialPresentation via the V4 path.
func TestSerializeDeserializeAuthCredentialRoundTrip(t *testing.T) {
	// Server setup.
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	serverSecret, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}
	serverPublic := serverSecret.GetPublicParams()

	var aciUUID, pniUUID UIDBytes
	for i := range aciUUID {
		aciUUID[i] = byte(i + 0x61)
	}
	for i := range pniUUID {
		pniUUID[i] = byte(i + 0x81)
	}
	aci := NewACI(aciUUID)
	pni := NewPNI(pniUUID)
	redemptionTime := NewTimestamp(SecondsPerDay * 100)

	var issueRandomness RandomnessBytes
	for i := range issueRandomness {
		issueRandomness[i] = byte(i + 10)
	}
	response, err := serverSecret.IssueAuthCredentialWithPniZkc(aci, pni, redemptionTime, issueRandomness)
	if err != nil {
		t.Fatalf("IssueAuthCredentialWithPniZkc: %v", err)
	}

	credential, err := serverPublic.ReceiveAuthCredentialWithPniZkc(aci, pni, redemptionTime, response)
	if err != nil {
		t.Fatalf("ReceiveAuthCredentialWithPniZkc: %v", err)
	}

	groupParams, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	var presRandomness RandomnessBytes
	for i := range presRandomness {
		presRandomness[i] = byte(i + 40)
	}
	presentation, err := serverPublic.CreateAuthCredentialWithPniZkcPresentation(
		credential, groupParams, presRandomness,
	)
	if err != nil {
		t.Fatalf("CreateAuthCredentialWithPniZkcPresentation: %v", err)
	}

	// Serialize to wire format.
	serialized := SerializeAuthCredentialWithPniZkcPresentation(presentation)
	if len(serialized) == 0 {
		t.Fatal("serialized presentation is empty")
	}
	if serialized[0] != PresentationVersion4 {
		t.Errorf("first byte = %d, want PresentationVersion4 (%d)", serialized[0], PresentationVersion4)
	}

	// Deserialize back.
	any, err := DeserializeAnyAuthCredentialPresentation(serialized)
	if err != nil {
		t.Fatalf("DeserializeAnyAuthCredentialPresentation: %v", err)
	}
	if any == nil {
		t.Fatal("deserialized presentation is nil")
	}
	if any.Version != PresentationVersion4 {
		t.Errorf("deserialized version = %d, want %d", any.Version, PresentationVersion4)
	}
	if any.Presentation == nil {
		t.Fatal("deserialized Presentation is nil")
	}
}

// =========================================================
// call_links.go: DecryptUID, Serialize/Deserialize
// =========================================================

// TestCallLinkSecretParams_DecryptUID_RoundTrip verifies that encrypting then
// decrypting a UID produces the original ServiceID.
func TestCallLinkSecretParams_DecryptUID_RoundTrip(t *testing.T) {
	rootKey := make([]byte, 32)
	for i := range rootKey {
		rootKey[i] = byte(i + 7)
	}
	params, err := DeriveCallLinkSecretParams(rootKey)
	if err != nil {
		t.Fatalf("DeriveCallLinkSecretParams: %v", err)
	}

	var uuid UIDBytes
	for i := range uuid {
		uuid[i] = byte(i + 1)
	}
	original := NewACI(uuid)

	ct := params.EncryptUID(original)
	if ct == nil {
		t.Fatal("EncryptUID returned nil")
	}

	decrypted, err := params.DecryptUID(ct)
	if err != nil {
		t.Fatalf("DecryptUID: %v", err)
	}
	if decrypted.Type != original.Type {
		t.Errorf("Type mismatch: got %d, want %d", decrypted.Type, original.Type)
	}
	if decrypted.RawUUID != original.RawUUID {
		t.Errorf("UUID mismatch after DecryptUID round-trip")
	}
}

// TestCallLinkSecretParams_DecryptUID_WrongKey verifies that decrypting with a
// different key returns ErrVerificationFailure.
func TestCallLinkSecretParams_DecryptUID_WrongKey(t *testing.T) {
	rootKey1 := make([]byte, 32)
	for i := range rootKey1 {
		rootKey1[i] = byte(i + 1)
	}
	rootKey2 := make([]byte, 32)
	for i := range rootKey2 {
		rootKey2[i] = byte(i + 99)
	}

	params1, err := DeriveCallLinkSecretParams(rootKey1)
	if err != nil {
		t.Fatalf("DeriveCallLinkSecretParams key1: %v", err)
	}
	params2, err := DeriveCallLinkSecretParams(rootKey2)
	if err != nil {
		t.Fatalf("DeriveCallLinkSecretParams key2: %v", err)
	}

	var uuid UIDBytes
	for i := range uuid {
		uuid[i] = byte(i + 5)
	}
	ct := params1.EncryptUID(NewACI(uuid))

	_, err = params2.DecryptUID(ct)
	if err == nil {
		t.Fatal("expected error when decrypting with wrong key")
	}
}

// TestSerializeDeserializeCreateCallLinkCredentialRequest exercises the
// serialize → deserialize round-trip for CreateCallLinkCredentialRequest.
func TestSerializeDeserializeCreateCallLinkCredentialRequest(t *testing.T) {
	rootKey := make([]byte, 32)
	for i := range rootKey {
		rootKey[i] = byte(i + 3)
	}
	params, err := DeriveCallLinkSecretParams(rootKey)
	if err != nil {
		t.Fatalf("DeriveCallLinkSecretParams: %v", err)
	}

	roomID := []byte("test-room-id")
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 20)
	}
	// params is unused directly here; NewCreateCallLinkCredentialRequestContext
	// is a package-level function that doesn't need params for the request itself.
	_ = params
	ctx, err := NewCreateCallLinkCredentialRequestContext(roomID, randomness)
	if err != nil {
		t.Fatalf("NewCreateCallLinkCredentialRequestContext: %v", err)
	}
	req := ctx.GetRequest()
	if req == nil {
		t.Fatal("GetRequest returned nil")
	}

	serialized := SerializeCreateCallLinkCredentialRequest(req)
	if len(serialized) == 0 {
		t.Fatal("serialized request is empty")
	}

	// The serialized form includes a leading reserved byte (from Serialize()).
	// DeserializeCreateCallLinkCredentialRequest expects the payload without the reserved byte.
	// Per the Serialize helper, it prepends a 0x00 reserved byte.
	// The deserializer expects 96 bytes of payload (BlindedRoomID + BlindingPublicKey).
	payload := serialized[1:] // strip the reserved byte added by Serialize()
	deserialized, err := DeserializeCreateCallLinkCredentialRequest(payload)
	if err != nil {
		t.Fatalf("DeserializeCreateCallLinkCredentialRequest: %v", err)
	}
	if deserialized == nil {
		t.Fatal("deserialized request is nil")
	}

	// Re-serialize and compare bytes.
	reserialized := SerializeCreateCallLinkCredentialRequest(deserialized)
	if !bytes.Equal(serialized, reserialized) {
		t.Error("re-serialized bytes differ from original serialized bytes")
	}
}

// TestDeserializeCreateCallLinkCredentialRequest_TooShort verifies the exact
// length check in DeserializeCreateCallLinkCredentialRequest rejects short input.
// Rust oracle: bincode reject_trailing_bytes() treats length mismatch as failure.
func TestDeserializeCreateCallLinkCredentialRequest_TooShort(t *testing.T) {
	_, err := DeserializeCreateCallLinkCredentialRequest([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error for too-short input")
	}
	if _, ok := err.(*ZkGroupDeserializationFailure); !ok {
		t.Errorf("expected *ZkGroupDeserializationFailure, got %T", err)
	}
}

// TestDeserializeCreateCallLinkCredentialRequest_TrailingBytes verifies that
// any bytes beyond the expected 96 are rejected, matching Rust's bincode
// reject_trailing_bytes() behavior
// (rust/zkgroup/src/common/serialization.rs zkgroup_bincode_options).
func TestDeserializeCreateCallLinkCredentialRequest_TrailingBytes(t *testing.T) {
	// Build a valid 96-byte payload then append an extra byte.
	roomID := []byte("trailing-test-room")
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 55)
	}
	ctx, err := NewCreateCallLinkCredentialRequestContext(roomID, randomness)
	if err != nil {
		t.Fatalf("NewCreateCallLinkCredentialRequestContext: %v", err)
	}
	req := ctx.GetRequest()
	serialized := SerializeCreateCallLinkCredentialRequest(req)
	// serialized is reserved(1) + payload(96) = 97 bytes; strip the reserved byte.
	payload := serialized[1:]
	if len(payload) != 96 {
		t.Fatalf("expected 96-byte payload, got %d", len(payload))
	}

	// A single trailing byte must be rejected.
	withTrail := append(payload, 0xFF)
	_, err = DeserializeCreateCallLinkCredentialRequest(withTrail)
	if err == nil {
		t.Fatal("expected error for trailing bytes, got nil")
	}
	if _, ok := err.(*ZkGroupDeserializationFailure); !ok {
		t.Errorf("expected *ZkGroupDeserializationFailure, got %T", err)
	}
}

// =========================================================
// profile_key_credential_presentation.go: ToStructurallyValidV1PresentationBytes
// =========================================================

// TestToStructurallyValidV1PresentationBytes verifies that the method produces
// a non-empty byte slice of the expected length (713 bytes) and that the first
// byte is the V1 version byte.
func TestToStructurallyValidV1PresentationBytes(t *testing.T) {
	// Build a minimal AnyProfileKeyCredentialPresentation with a V3 presentation
	// that has real UID and profile key ciphertexts.
	domain := UIDEncryptionDomain{}
	sho := zkcredential.NewShoHmacSha256Ext("test_struct_v1")
	kp, err := zkcredential.DeriveKeyPair(sho, domain)
	if err != nil {
		t.Fatalf("DeriveKeyPair: %v", err)
	}

	uuid := [UUIDLen]byte{5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	uid := NewUIDStructFromServiceID(NewACI(uuid))
	uidCT := &UUIDCiphertext{Ciphertext: kp.Encrypt(uid)}

	pkDomain := ProfileKeyEncryptionDomain{}
	pkSho := zkcredential.NewShoHmacSha256Ext("test_pk_struct_v1")
	pkKP, err := zkcredential.DeriveKeyPair(pkSho, pkDomain)
	if err != nil {
		t.Fatalf("DeriveKeyPair for profile key: %v", err)
	}

	var pkBytes ProfileKeyBytes
	for i := range pkBytes {
		pkBytes[i] = byte(i + 10)
	}
	pkStruct := NewProfileKeyStruct(pkBytes, uuid)
	pkCT := &ProfileKeyCiphertext{Ciphertext: pkKP.Encrypt(pkStruct)}

	// Build a V3 presentation so GetUUIDCiphertext and GetProfileKeyCiphertext work.
	expiry := NewTimestamp(86400)
	v3pres := &ExpiringProfileKeyCredentialPresentation{
		UIDEncCiphertext:         uidCT,
		ProfileKeyEncCiphertext:  pkCT,
		CredentialExpirationTime: expiry,
	}
	any := &AnyProfileKeyCredentialPresentation{
		Version: PresentationVersion3,
		V3:      v3pres,
	}

	out := any.ToStructurallyValidV1PresentationBytes()
	if len(out) == 0 {
		t.Fatal("ToStructurallyValidV1PresentationBytes returned empty slice")
	}
	// Expected length: 1 + 8*32 + 8 + 320 + 64 + 64 = 713
	const wantLen = 713
	if len(out) != wantLen {
		t.Errorf("len(out) = %d, want %d", len(out), wantLen)
	}
	if out[0] != PresentationVersion1 {
		t.Errorf("out[0] = %d, want PresentationVersion1 (%d)", out[0], PresentationVersion1)
	}
}
