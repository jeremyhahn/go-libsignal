package zkgroup

import (
	"encoding/hex"
	"testing"
)

func TestGenerateServerSecretParams(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i)
	}
	params, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams failed: %v", err)
	}
	if params.SigKeyPair == nil {
		t.Fatal("SigKeyPair is nil")
	}
	if params.ReceiptCredentialsKeyPair == nil {
		t.Fatal("ReceiptCredentialsKeyPair is nil")
	}
	if params.ExpiringProfileKeyCredentialsKeyPair == nil {
		t.Fatal("ExpiringProfileKeyCredentialsKeyPair is nil")
	}
	if params.GenericCredentialKeyPair == nil {
		t.Fatal("GenericCredentialKeyPair is nil")
	}
	if params.EndorsementKeyPair == nil {
		t.Fatal("EndorsementKeyPair is nil")
	}
}

func TestGenerateServerSecretParams_Deterministic(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}

	params1, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("first generation failed: %v", err)
	}
	params2, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("second generation failed: %v", err)
	}

	// Signature key pair must be identical.
	if params1.SigKeyPair.SigningKey.Equal(params2.SigKeyPair.SigningKey) != 1 {
		t.Error("SigKeyPair signing keys differ between identical randomness")
	}
	if params1.SigKeyPair.PublicKey.Equal(params2.SigKeyPair.PublicKey) != 1 {
		t.Error("SigKeyPair public keys differ between identical randomness")
	}

	// Receipt credentials key pair must be identical.
	rpk1 := params1.ReceiptCredentialsKeyPair.PublicKey()
	rpk2 := params2.ReceiptCredentialsKeyPair.PublicKey()
	if rpk1.CW.Equal(rpk2.CW) != 1 {
		t.Error("ReceiptCredentials public keys differ between identical randomness")
	}

	// Expiring profile key credentials key pair must be identical.
	epk1 := params1.ExpiringProfileKeyCredentialsKeyPair.PublicKey()
	epk2 := params2.ExpiringProfileKeyCredentialsKeyPair.PublicKey()
	if epk1.CW.Equal(epk2.CW) != 1 {
		t.Error("ExpiringProfileKeyCredentials public keys differ between identical randomness")
	}
}

func TestGenerateServerSecretParams_ChainedSHOProducesDifferentKeys(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 1)
	}
	params, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("generation failed: %v", err)
	}

	// Receipt and expiring profile key credentials must differ since they are
	// drawn from different positions in the SHO state chain.
	rpk := params.ReceiptCredentialsKeyPair.PublicKey()
	epk := params.ExpiringProfileKeyCredentialsKeyPair.PublicKey()
	if rpk.CW.Equal(epk.CW) == 1 {
		t.Error("receipt and expiring profile key credentials have identical CW; SHO chaining is broken")
	}
}

func TestGenerateServerSecretParams_DifferentRandomnessProducesDifferentKeys(t *testing.T) {
	var r1, r2 RandomnessBytes
	for i := range r1 {
		r1[i] = byte(i)
		r2[i] = byte(i + 100)
	}
	p1, err := GenerateServerSecretParams(r1)
	if err != nil {
		t.Fatalf("first generation failed: %v", err)
	}
	p2, err := GenerateServerSecretParams(r2)
	if err != nil {
		t.Fatalf("second generation failed: %v", err)
	}

	if p1.SigKeyPair.SigningKey.Equal(p2.SigKeyPair.SigningKey) == 1 {
		t.Error("different randomness produced identical signing keys")
	}
	rpk1 := p1.ReceiptCredentialsKeyPair.PublicKey()
	rpk2 := p2.ReceiptCredentialsKeyPair.PublicKey()
	if rpk1.CW.Equal(rpk2.CW) == 1 {
		t.Error("different randomness produced identical receipt credential public keys")
	}
}

func TestServerSecretParams_GetPublicParams(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i)
	}
	params, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams failed: %v", err)
	}
	pub := params.GetPublicParams()
	if pub == nil {
		t.Fatal("returned nil")
	}
	if pub.SigPublicKey == nil {
		t.Fatal("SigPublicKey is nil")
	}
	if pub.ReceiptCredentialsPublicKey == nil {
		t.Fatal("ReceiptCredentialsPublicKey is nil")
	}
	if pub.ExpiringProfileKeyCredentialsPublicKey == nil {
		t.Fatal("ExpiringProfileKeyCredentialsPublicKey is nil")
	}
	if pub.GenericCredentialPublicKey == nil {
		t.Fatal("GenericCredentialPublicKey is nil")
	}
	if pub.EndorsementPublicKey == nil {
		t.Fatal("EndorsementPublicKey is nil")
	}
}

func TestServerSecretParams_GetEndorsementRootKeyPair(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i)
	}
	params, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams failed: %v", err)
	}
	ekp := params.GetEndorsementRootKeyPair()
	if ekp == nil {
		t.Fatal("returned nil")
	}
	if ekp.KeyPair == nil {
		t.Fatal("KeyPair is nil")
	}
	pub := ekp.PublicKey()
	if pub == nil {
		t.Fatal("PublicKey returned nil")
	}
}

func TestServerPublicParams_GetEndorsementPublicKey(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i)
	}
	params, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams failed: %v", err)
	}
	pub := params.GetPublicParams()
	epk := pub.GetEndorsementPublicKey()
	if epk == nil {
		t.Fatal("returned nil")
	}
	if epk.PublicKey == nil {
		t.Fatal("PublicKey is nil")
	}
}

func TestCheckAuthCredentialRedemptionTime(t *testing.T) {
	redemptionTime := NewTimestamp(2 * SecondsPerDay)

	t.Run("valid current time", func(t *testing.T) {
		currentTime := NewTimestamp(2 * SecondsPerDay) // at redemption time
		err := CheckAuthCredentialRedemptionTime(redemptionTime, currentTime)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("one second before start", func(t *testing.T) {
		currentTime := NewTimestamp(SecondsPerDay - 1) // one second before acceptable start
		err := CheckAuthCredentialRedemptionTime(redemptionTime, currentTime)
		if err == nil {
			t.Fatal("expected error for too early")
		}
	})

	t.Run("one second after end", func(t *testing.T) {
		currentTime := NewTimestamp(4*SecondsPerDay + 1) // one second after acceptable end
		err := CheckAuthCredentialRedemptionTime(redemptionTime, currentTime)
		if err == nil {
			t.Fatal("expected error for too late")
		}
	})

	t.Run("at acceptable start", func(t *testing.T) {
		currentTime := NewTimestamp(SecondsPerDay) // exactly at acceptable start
		err := CheckAuthCredentialRedemptionTime(redemptionTime, currentTime)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("at acceptable end", func(t *testing.T) {
		currentTime := NewTimestamp(4 * SecondsPerDay) // exactly at acceptable end
		err := CheckAuthCredentialRedemptionTime(redemptionTime, currentTime)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("underflow on sub", func(t *testing.T) {
		// redemptionTime too small to subtract SecondsPerDay
		smallTime := NewTimestamp(100)
		err := CheckAuthCredentialRedemptionTime(smallTime, NewTimestamp(50))
		if err == nil {
			t.Fatal("expected error for underflow")
		}
	})
}

func TestCheckAuthCredentialRedemptionTime_OverflowOnAdd(t *testing.T) {
	// redemptionTime is so large that adding 2*SecondsPerDay overflows.
	redemptionTime := NewTimestamp(^uint64(0) - SecondsPerDay + 1)
	currentTime := NewTimestamp(^uint64(0) - SecondsPerDay)
	err := CheckAuthCredentialRedemptionTime(redemptionTime, currentTime)
	if err == nil {
		t.Fatal("expected error for overflow on add")
	}
}

func TestLegacyCredentialConfigs(t *testing.T) {
	tests := []struct {
		name       string
		config     LegacyCredentialConfig
		storageLen int
		numAttrs   int
	}{
		{"auth", LegacyAuthCredentialConfig, 4, 3},
		{"profileKey", LegacyProfileKeyCredentialConfig, 4, 4},
		{"receipt", LegacyReceiptCredentialConfig, 4, 2},
		{"pni", LegacyPNICredentialConfig, 6, 6},
		{"expiringProfileKey", LegacyExpiringProfileKeyCredentialConfig, 5, 5},
		{"authWithPni", LegacyAuthWithPNICredentialConfig, 5, 5},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.config.StorageLen != tc.storageLen {
				t.Errorf("StorageLen = %d, want %d", tc.config.StorageLen, tc.storageLen)
			}
			if tc.config.NumAttrs != tc.numAttrs {
				t.Errorf("NumAttrs = %d, want %d", tc.config.NumAttrs, tc.numAttrs)
			}
		})
	}
}

func TestGenerateServerSecretParams_LegacySHOAlignment(t *testing.T) {
	// Verify that GenerateServerSecretParams produces the same keys regardless
	// of how many times we call it (deterministic SHO chaining).
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 42)
	}

	p1, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	p2, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("second: %v", err)
	}

	// Receipt credentials must be identical.
	rpk1 := p1.ReceiptCredentialsKeyPair.PublicKey()
	rpk2 := p2.ReceiptCredentialsKeyPair.PublicKey()
	if rpk1.CW.Equal(rpk2.CW) != 1 {
		t.Error("receipt CW differs between identical randomness")
	}

	// Expiring profile key credentials must be identical.
	epk1 := p1.ExpiringProfileKeyCredentialsKeyPair.PublicKey()
	epk2 := p2.ExpiringProfileKeyCredentialsKeyPair.PublicKey()
	if epk1.CW.Equal(epk2.CW) != 1 {
		t.Error("expiring profile key CW differs between identical randomness")
	}

	// Signature key pair must be identical.
	if p1.SigKeyPair.SigningKey.Equal(p2.SigKeyPair.SigningKey) != 1 {
		t.Error("sig keys differ between identical randomness")
	}
}

func TestCheckAuthCredentialRedemptionTime_ExactBoundary(t *testing.T) {
	redemptionTime := NewTimestamp(2 * SecondsPerDay)

	// Exactly at acceptable start (redemptionTime - SecondsPerDay)
	err := CheckAuthCredentialRedemptionTime(redemptionTime, NewTimestamp(SecondsPerDay))
	if err != nil {
		t.Fatalf("should accept exact start boundary: %v", err)
	}

	// Exactly at acceptable end (redemptionTime + 2*SecondsPerDay)
	err = CheckAuthCredentialRedemptionTime(redemptionTime, NewTimestamp(4*SecondsPerDay))
	if err != nil {
		t.Fatalf("should accept exact end boundary: %v", err)
	}
}

// TestServerSecretParams_Sign exercises the Sign method (line 116) against the
// KAT vector from tests/interop/fixtures/zkgroup/server_sig_known_answers.json.
// The expected_signature_hex was extracted from
// rust/zkgroup/tests/integration_tests.rs::test_server_sigs.
func TestServerSecretParams_Sign(t *testing.T) {
	// Server params generated from TEST_ARRAY_32 (0x00..0x1f).
	var serverRandomness RandomnessBytes
	for i := range serverRandomness {
		serverRandomness[i] = byte(i)
	}
	params, err := GenerateServerSecretParams(serverRandomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}

	// Message = TEST_ARRAY_32_1 (0x64..0x83); sign randomness = TEST_ARRAY_32_2 (0xc8..0xe7).
	message, err := hex.DecodeString("6465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f80818283")
	if err != nil {
		t.Fatalf("decode message: %v", err)
	}
	var signRandomness RandomnessBytes
	r2, err := hex.DecodeString("c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7")
	if err != nil {
		t.Fatalf("decode randomness: %v", err)
	}
	copy(signRandomness[:], r2)

	sig, err := params.Sign(signRandomness, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	want, err := hex.DecodeString("87d354564d35ef91edba851e0815612e864c227a0471d50c270698604406d003a55473f576cf241fc6b41c6b16e5e63b333c02fe4a33858022fdd7a4ab367b06")
	if err != nil {
		t.Fatalf("decode want: %v", err)
	}
	if len(sig) != len(want) {
		t.Fatalf("signature length mismatch: got %d, want %d", len(sig), len(want))
	}
	for i := range want {
		if sig[i] != want[i] {
			t.Fatalf("signature byte %d mismatch: got %02x, want %02x", i, sig[i], want[i])
		}
	}
}

// TestServerSecretParams_Sign_Verify confirms that Sign output passes
// verification with the corresponding public key, and that a tampered
// message does not verify.
func TestServerSecretParams_Sign_Verify(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = byte(i + 5)
	}
	params, err := GenerateServerSecretParams(randomness)
	if err != nil {
		t.Fatalf("GenerateServerSecretParams: %v", err)
	}

	message := []byte("test message for sign verify")
	var signRand RandomnessBytes
	for i := range signRand {
		signRand[i] = byte(i + 200)
	}

	sig, err := params.Sign(signRand, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub := params.GetPublicParams()
	if err := pub.SigPublicKey.Verify(message, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Tampered message must not verify.
	tampered := append([]byte(nil), message...)
	tampered[0] ^= 0xFF
	if err := pub.SigPublicKey.Verify(tampered, sig); err == nil {
		t.Fatal("Verify of tampered message unexpectedly succeeded")
	}
}

func TestGenerateGenericServerSecretParams(t *testing.T) {
	var randomness RandomnessBytes
	for i := range randomness {
		randomness[i] = 99
	}
	params := GenerateGenericServerSecretParams(randomness)
	if params == nil {
		t.Fatal("returned nil")
	}
	if params.CredentialKey == nil {
		t.Fatal("CredentialKey is nil")
	}

	pub := params.GetPublicParams()
	if pub == nil {
		t.Fatal("GetPublicParams returned nil")
	}
	if pub.CredentialKey == nil {
		t.Fatal("CredentialKey in public params is nil")
	}
}
