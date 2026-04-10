package zkgroup

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

func TestDefaultExpiration(t *testing.T) {
	// Use a time that is well into the day
	currentTime := NewTimestamp(SecondsPerDay + 3600) // 1:00 AM day 2
	exp := DefaultExpiration(currentTime)

	if !exp.IsDayAligned() {
		t.Error("expiration should be day aligned")
	}

	remaining := exp.SaturatingSecondsSince(currentTime)
	if remaining < SecondsPerDay {
		t.Errorf("remaining = %d, should be >= %d", remaining, SecondsPerDay)
	}
}

func TestDefaultExpiration_NearEndOfDay(t *testing.T) {
	// Near end of day: should push to next day
	currentTime := NewTimestamp(2*SecondsPerDay - 1800) // 23:30 day 1
	exp := DefaultExpiration(currentTime)

	remaining := exp.SaturatingSecondsSince(currentTime)
	if remaining < SecondsPerDay+3600 {
		t.Errorf("remaining = %d, should be >= %d (near end of day bump)", remaining, SecondsPerDay+3600)
	}
}

func TestGroupSendDerivedKeyPairTagInfo(t *testing.T) {
	ts := NewTimestamp(2 * SecondsPerDay)
	sho := groupSendDerivedKeyPairTagInfo(ts)
	if sho == nil {
		t.Fatal("returned nil")
	}
}

func TestForExpiration(t *testing.T) {
	var randomness [zkcredential.RandomnessLen]byte
	for i := range randomness {
		randomness[i] = 42
	}
	rootKP, err := zkcredential.GenerateServerRootKeyPair(randomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair failed: %v", err)
	}

	expiration := NewTimestamp(2 * SecondsPerDay)
	derived, err := ForExpiration(expiration, rootKP)
	if err != nil {
		t.Fatalf("ForExpiration failed: %v", err)
	}
	if derived == nil {
		t.Fatal("returned nil")
	}
	if derived.KeyPair == nil {
		t.Fatal("KeyPair is nil")
	}
	if derived.Expiration != expiration {
		t.Error("expiration mismatch")
	}
}

func TestGroupSendToken_IntoFullToken(t *testing.T) {
	token := &GroupSendToken{RawToken: []byte("raw")}
	exp := NewTimestamp(86400)
	full := token.IntoFullToken(exp)
	if full == nil {
		t.Fatal("returned nil")
	}
	if string(full.RawToken) != "raw" {
		t.Error("RawToken mismatch")
	}
	if full.GetExpiration() != exp {
		t.Error("expiration mismatch")
	}
}

func TestGroupSendFullToken_Verify_Expired(t *testing.T) {
	token := &GroupSendFullToken{
		RawToken:   []byte("token"),
		Expiration: NewTimestamp(100),
	}
	now := NewTimestamp(200) // expired

	var randomness [zkcredential.RandomnessLen]byte
	for i := range randomness {
		randomness[i] = 42
	}
	rootKP, _ := zkcredential.GenerateServerRootKeyPair(randomness)
	expiration := NewTimestamp(100)
	derived, _ := ForExpiration(expiration, rootKP)

	err := token.Verify(nil, now, derived)
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestCombineGroupSendEndorsements(t *testing.T) {
	e1 := &GroupSendEndorsement{Endorsement: zkcredential.DefaultEndorsement()}
	e2 := &GroupSendEndorsement{Endorsement: zkcredential.DefaultEndorsement()}

	combined := CombineGroupSendEndorsements([]*GroupSendEndorsement{e1, e2})
	if combined == nil {
		t.Fatal("returned nil")
	}
}

func TestGroupSendEndorsement_Remove(t *testing.T) {
	e1 := &GroupSendEndorsement{Endorsement: zkcredential.DefaultEndorsement()}
	e2 := &GroupSendEndorsement{Endorsement: zkcredential.DefaultEndorsement()}

	result := e1.Remove(e2)
	if result == nil {
		t.Fatal("returned nil")
	}
}

func TestGroupSendEndorsement_Compress(t *testing.T) {
	e := &GroupSendEndorsement{Endorsement: zkcredential.DefaultEndorsement()}
	compressed := e.Compress()
	if compressed == nil {
		t.Fatal("returned nil")
	}
}

func TestGroupSendEndorsement_ToToken(t *testing.T) {
	e := &GroupSendEndorsement{Endorsement: zkcredential.DefaultEndorsement()}

	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	groupParams, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}

	token := e.ToToken(groupParams.UIDEncKeyPair)
	if token == nil {
		t.Fatal("returned nil")
	}
	if token.RawToken == nil {
		t.Fatal("RawToken is nil")
	}
}

func TestCompressedGroupSendEndorsement_Decompress(t *testing.T) {
	e := &GroupSendEndorsement{Endorsement: zkcredential.DefaultEndorsement()}
	compressed := e.Compress()
	decompressed, err := compressed.Decompress()
	if err != nil {
		t.Fatalf("Decompress failed: %v", err)
	}
	if decompressed == nil {
		t.Fatal("returned nil")
	}
}

func TestGroupSendToken_IntoFullToken2(t *testing.T) {
	token := &GroupSendToken{RawToken: []byte("test_token")}
	exp := NewTimestamp(2 * SecondsPerDay)
	full := token.IntoFullToken(exp)
	if full == nil {
		t.Fatal("returned nil")
	}
	if string(full.RawToken) != "test_token" {
		t.Error("RawToken mismatch")
	}
	if full.GetExpiration() != exp {
		t.Error("expiration mismatch")
	}
}

func TestGroupSendFullToken_Verify_NotExpired(t *testing.T) {
	// Token is not expired but token data is invalid
	var randomness [zkcredential.RandomnessLen]byte
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	rootKP, _ := zkcredential.GenerateServerRootKeyPair(randomness)
	expiration := NewTimestamp(2 * SecondsPerDay)
	derived, _ := ForExpiration(expiration, rootKP)

	token := &GroupSendFullToken{
		RawToken:   []byte("invalid"),
		Expiration: expiration,
	}
	now := NewTimestamp(SecondsPerDay) // not expired

	// Should fail because the token is invalid, not because it's expired
	err := token.Verify(nil, now, derived)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestDerivePublicSigningKey_NotDayAligned(t *testing.T) {
	resp := &GroupSendEndorsementsResponse{
		Expiration: NewTimestamp(SecondsPerDay + 1), // not day-aligned
	}
	now := NewTimestamp(SecondsPerDay)
	_, err := resp.ReceiveWithCiphertexts(nil, now, nil)
	if err == nil {
		t.Fatal("expected error for non-day-aligned expiration")
	}
}

func TestDerivePublicSigningKey_TooSoonToExpire(t *testing.T) {
	resp := &GroupSendEndorsementsResponse{
		Expiration: NewTimestamp(2 * SecondsPerDay),
	}
	// now is only 1 hour before expiration (< 2 hours required).
	now := NewTimestamp(2*SecondsPerDay - 3600)
	_, err := resp.ReceiveWithCiphertexts(nil, now, nil)
	if err == nil {
		t.Fatal("expected error for expiration too soon")
	}
}

func TestDerivePublicSigningKey_TooFarInFuture(t *testing.T) {
	resp := &GroupSendEndorsementsResponse{
		Expiration: NewTimestamp(10 * SecondsPerDay),
	}
	// now is so early that expiration - now > 7 days.
	now := NewTimestamp(SecondsPerDay)
	_, err := resp.ReceiveWithCiphertexts(nil, now, nil)
	if err == nil {
		t.Fatal("expected error for expiration too far in future")
	}
}

func TestGroupSendFullToken_Verify_NotExpiredButInvalid(t *testing.T) {
	var randomness [zkcredential.RandomnessLen]byte
	for i := range randomness {
		randomness[i] = byte(i + 5)
	}
	rootKP, _ := zkcredential.GenerateServerRootKeyPair(randomness)
	expiration := NewTimestamp(3 * SecondsPerDay)
	derived, _ := ForExpiration(expiration, rootKP)

	uuid := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	userIDs := []ServiceID{NewACI(uuid)}

	token := &GroupSendFullToken{
		RawToken:   []byte("bad token data"),
		Expiration: expiration,
	}
	now := NewTimestamp(SecondsPerDay) // not expired

	err := token.Verify(userIDs, now, derived)
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestCompressedGroupSendEndorsement_Decompress_Invalid(t *testing.T) {
	// Create a compressed endorsement with invalid point data.
	invalidBytes := make([]byte, 32)
	for i := range invalidBytes {
		invalidBytes[i] = 0xFF
	}
	badCompressed := &CompressedGroupSendEndorsement{
		Endorsement: &zkcredential.CompressedEndorsement{R: invalidBytes},
	}
	_, err := badCompressed.Decompress()
	if err == nil {
		t.Fatal("expected error for invalid compressed endorsement")
	}
}

func TestReceiveWithCiphertexts_VerificationFailure(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}

	rootKP, err := zkcredential.GenerateServerRootKeyPair(randomness)
	if err != nil {
		t.Fatal(err)
	}

	expiration := NewTimestamp(2 * SecondsPerDay)
	derived, err := ForExpiration(expiration, rootKP)
	if err != nil {
		t.Fatal(err)
	}

	groupParams, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}
	uuid1 := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	ct1 := groupParams.EncryptServiceID(NewACI(uuid1))
	memberCTs := []*UUIDCiphertext{ct1}

	resp, err := IssueGroupSendEndorsements(memberCTs, derived, randomness)
	if err != nil {
		t.Fatal(err)
	}

	// Use a different root key pair for verification -- should fail.
	var randomness2 RandomnessBytes
	for i := range randomness2 {
		randomness2[i] = byte(i + 99)
	}
	wrongRootKP, _ := zkcredential.GenerateServerRootKeyPair(randomness2)
	wrongPubKey := wrongRootKP.PublicKey()

	now := NewTimestamp(SecondsPerDay)
	_, err = resp.ReceiveWithCiphertexts(memberCTs, now, wrongPubKey)
	if err == nil {
		t.Fatal("expected verification failure with wrong public key")
	}
}

func TestDefaultExpiration_MidDay(t *testing.T) {
	// Mid-day: should get standard 2-day expiration.
	currentTime := NewTimestamp(SecondsPerDay + SecondsPerDay/2)
	exp := DefaultExpiration(currentTime)
	if !exp.IsDayAligned() {
		t.Error("expiration should be day aligned")
	}
}

func TestIssueAndReceiveGroupSendEndorsements(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}

	rootKP, err := zkcredential.GenerateServerRootKeyPair(randomness)
	if err != nil {
		t.Fatalf("GenerateServerRootKeyPair: %v", err)
	}

	expiration := NewTimestamp(2 * SecondsPerDay)
	derived, err := ForExpiration(expiration, rootKP)
	if err != nil {
		t.Fatalf("ForExpiration: %v", err)
	}

	groupParams, err := GenerateGroupSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateGroupSecretParams: %v", err)
	}
	uuid1 := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	uuid2 := [UUIDLen]byte{17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	ct1 := groupParams.EncryptServiceID(NewACI(uuid1))
	ct2 := groupParams.EncryptServiceID(NewACI(uuid2))

	memberCTs := []*UUIDCiphertext{ct1, ct2}
	resp, err := IssueGroupSendEndorsements(memberCTs, derived, randomness)
	if err != nil {
		t.Fatalf("IssueGroupSendEndorsements: %v", err)
	}

	// Receive with public key
	pubKey := rootKP.PublicKey()
	now := NewTimestamp(SecondsPerDay) // valid: expiration - now = 1 day (> 2h, < 7d)
	received, err := resp.ReceiveWithCiphertexts(memberCTs, now, pubKey)
	if err != nil {
		t.Fatalf("ReceiveWithCiphertexts: %v", err)
	}
	if len(received) != 2 {
		t.Fatalf("expected 2 endorsements, got %d", len(received))
	}
	for i, r := range received {
		if r.Compressed == nil {
			t.Fatalf("endorsement %d: Compressed is nil", i)
		}
		if r.Decompressed == nil {
			t.Fatalf("endorsement %d: Decompressed is nil", i)
		}
	}
}
