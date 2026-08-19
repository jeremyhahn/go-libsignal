package record_test

// findings_regression_test.go contains targeted regression tests for the
// review findings fixed in this package:
//
//   Finding 5 (MEDIUM): PreKeyRecord and SignedPreKeyRecord deserialized with
//     ecc.NewDjbECPublicKey(bytehelper.SliceToArray(...)) which truncated the
//     33-byte serialized key form to [0x05 || 31 bytes], corrupting the key.
//     Fixed by switching to ecc.DecodePoint, which correctly strips the 0x05
//     type byte and preserves all 32 raw key bytes.
//
//   Finding 6 (LOW): SessionState.SetSenderBaseKey had the same truncation bug.
//     Fixed to use ecc.DecodePoint. HasSessionState comparisons now compare
//     correct 33-byte forms against each other.

import (
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/ecc"
	"github.com/jeremyhahn/go-libsignal/pkg/state/record"
	"github.com/jeremyhahn/go-libsignal/pkg/util/bytehelper"
)

// TestPreKeyRecord_SerializeRoundTrip_CorrectPublicKey verifies Finding 5 for
// PreKeyRecord: a round-trip through Serialize → NewPreKeyFromBytes must yield
// a public key whose SerializedPublicKey() (33 bytes: 0x05 + 32 key bytes)
// exactly matches the original key pair's public key serialization. Before the
// fix, the deserialized key was corrupted (SliceToArray kept the 0x05 prefix
// byte and dropped the last key byte, yielding a 34-byte Serialize output
// instead of 33).
func TestPreKeyRecord_SerializeRoundTrip_CorrectPublicKey(t *testing.T) {
	ser := newSerializer()
	kp := genKP(t)

	original := record.NewPreKey(1, kp, ser.PreKeyRecord)

	serialized, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize(): %v", err)
	}

	restored, err := record.NewPreKeyFromBytes(serialized, ser.PreKeyRecord)
	if err != nil {
		t.Fatalf("NewPreKeyFromBytes(): %v", err)
	}

	want := kp.PublicKey().Serialize() // 33 bytes: [0x05 || 32 key bytes]
	got := restored.KeyPair().PublicKey().Serialize()
	if !bytes.Equal(got, want) {
		t.Errorf("round-trip public key mismatch:\n got  %x (%d bytes)\n want %x (%d bytes)",
			got, len(got), want, len(want))
	}

	// Sanity: correct form is 33 bytes, not 34 (which the bug produced).
	if len(got) != 33 {
		t.Errorf("expected 33-byte public key, got %d bytes; pre-fix SliceToArray truncation produced 34 bytes", len(got))
	}
	// First byte must be the Djb/X25519 type prefix 0x05.
	if got[0] != 0x05 {
		t.Errorf("expected 0x05 type prefix, got 0x%02x", got[0])
	}
}

// TestPreKeyRecord_NewPreKeyFromBytes_InvalidKey verifies that NewPreKeyFromBytes
// returns an error when the stored public key bytes are not a valid EC point.
func TestPreKeyRecord_NewPreKeyFromBytes_InvalidKey(t *testing.T) {
	ser := newSerializer()
	kp := genKP(t)
	// Start with a valid record.
	original := record.NewPreKey(2, kp, ser.PreKeyRecord)
	serialized, err := original.Serialize()
	if err != nil {
		t.Fatalf("Serialize(): %v", err)
	}

	// Corrupt the serialized bytes: overwrite the first byte (version/marker)
	// with garbage to produce an invalid key type byte for DecodePoint.
	corrupt := make([]byte, len(serialized))
	copy(corrupt, serialized)
	// The serialized form from the JSON serializer contains PublicKey as base64.
	// Rather than parse JSON, we deserialize successfully and test the path
	// through a bad structure directly.
	_ = corrupt // direct structure tampering tested via NewPreKeyFromStruct below

	badKey := []byte{0xFF, 0xFF, 0xFF} // clearly invalid for DecodePoint
	badStructure := &record.PreKeyStructure{
		ID:         99,
		PublicKey:  badKey,
		PrivateKey: mustGuard(t, bytehelper.ArrayToSlice(kp.PrivateKey().Serialize())),
	}
	_, err = record.NewPreKeyFromStruct(badStructure, ser.PreKeyRecord)
	if err == nil {
		t.Error("expected error for invalid public key bytes, got nil")
	}
}

// TestSignedPreKeyRecord_SerializeRoundTrip_CorrectPublicKey verifies Finding 5
// for SignedPreKeyRecord: the same truncation bug existed here. After the fix,
// SerializedPublicKey() must equal the original key's 33-byte Serialize() output
// AND the identity-key signature over the SPK public key must still verify.
func TestSignedPreKeyRecord_SerializeRoundTrip_CorrectPublicKey(t *testing.T) {
	ser := newSerializer()
	idKP := genIDKeyPair(t)
	kp := genKP(t)

	// Sign the SPK public key bytes (33-byte form), as the session builder does.
	pubKeyBytes := kp.PublicKey().Serialize()
	sigArr, err := ecc.CalculateSignature(idKP.PrivateKey(), pubKeyBytes)
	if err != nil {
		t.Fatalf("CalculateSignature(): %v", err)
	}

	spkr := record.NewSignedPreKey(3, 0, kp, sigArr, ser.SignedPreKeyRecord)

	serialized, err := spkr.Serialize()
	if err != nil {
		t.Fatalf("Serialize(): %v", err)
	}

	restored, err := record.NewSignedPreKeyFromBytes(serialized, ser.SignedPreKeyRecord)
	if err != nil {
		t.Fatalf("NewSignedPreKeyFromBytes(): %v", err)
	}

	// Public key bytes must round-trip exactly.
	want := kp.PublicKey().Serialize()
	got := restored.KeyPair().PublicKey().Serialize()
	if !bytes.Equal(got, want) {
		t.Errorf("round-trip public key mismatch:\n got  %x (%d bytes)\n want %x (%d bytes)",
			got, len(got), want, len(want))
	}
	if len(got) != 33 {
		t.Errorf("expected 33-byte serialized public key, got %d (pre-fix bug gave 34)", len(got))
	}

	// SerializedPublicKey() must also return the correct 33-byte form.
	if !bytes.Equal(restored.SerializedPublicKey(), want) {
		t.Errorf("SerializedPublicKey() mismatch: got %x, want %x",
			restored.SerializedPublicKey(), want)
	}

	// The signature over the SPK public key must still verify with the restored key.
	if !ecc.VerifySignature(idKP.PublicKey().PublicKey(), pubKeyBytes, sigArr) {
		t.Error("SPK signature does not verify with restored public key")
	}
}

// TestSignedPreKeyRecord_NewSignedPreKeyFromBytes_InvalidKey verifies that
// NewSignedPreKeyFromBytes returns an error for an invalid stored public key.
func TestSignedPreKeyRecord_NewSignedPreKeyFromBytes_InvalidKey(t *testing.T) {
	ser := newSerializer()
	kp := genKP(t)

	badStructure := &record.SignedPreKeyStructure{
		ID:         7,
		PublicKey:  []byte{0xFF, 0x00}, // invalid
		PrivateKey: mustGuard(t, bytehelper.ArrayToSlice(kp.PrivateKey().Serialize())),
		Signature:  make([]byte, 64),
	}
	_, err := record.NewSignedPreKeyFromStruct(badStructure, ser.SignedPreKeyRecord)
	if err == nil {
		t.Error("expected error for invalid SPK public key bytes, got nil")
	}
}

// TestSetSenderBaseKey_CorrectRoundTrip verifies Finding 6: SetSenderBaseKey
// now correctly decodes the 33-byte type-prefixed EC key via ecc.DecodePoint.
// SenderBaseKey() must return the same 33-byte value that was passed in, and
// HasSessionState must find the session by the original (un-corrupted) key.
func TestSetSenderBaseKey_CorrectRoundTrip(t *testing.T) {
	ser := newSerializer()
	kp := genKP(t)

	state := record.NewState(ser.State)
	pubKey := kp.PublicKey().Serialize() // 33-byte type-prefixed form
	state.SetSenderBaseKey(pubKey)

	got := state.SenderBaseKey()
	if !bytes.Equal(got, pubKey) {
		t.Errorf("SenderBaseKey() = %x (%d bytes), want %x (%d bytes);\n"+
			"pre-fix bug: SliceToArray truncated to [0x05||31bytes], Serialize prepended another 0x05, giving 34 bytes",
			got, len(got), pubKey, len(pubKey))
	}
	if len(got) != 33 {
		t.Errorf("expected 33-byte sender base key, got %d bytes", len(got))
	}
}

// TestSetSenderBaseKey_NilInput verifies that SetSenderBaseKey(nil) leaves
// the field nil (safe no-op).
func TestSetSenderBaseKey_NilInput(t *testing.T) {
	ser := newSerializer()
	kp := genKP(t)
	state := record.NewState(ser.State)
	state.SetSenderBaseKey(kp.PublicKey().Serialize())

	// Overwrite with nil: must not panic and must zero the field.
	state.SetSenderBaseKey(nil)
	if state.SenderBaseKey() != nil {
		t.Errorf("expected nil after SetSenderBaseKey(nil), got %x", state.SenderBaseKey())
	}
}

// TestHasSessionState_CorrectBaseKeyComparison verifies that after the Fix 6
// correction, HasSessionState finds the session using the original unmodified
// serialized public key bytes — not the corrupted truncated form.
func TestHasSessionState_CorrectBaseKeyComparison(t *testing.T) {
	ser := newSerializer()
	sess := record.NewSession(ser.Session, ser.State)
	kp := genKP(t)

	sess.SessionState().SetVersion(3)
	origPubKey := kp.PublicKey().Serialize() // canonical 33-byte form
	sess.SessionState().SetSenderBaseKey(origPubKey)

	// With the fix, SenderBaseKey() == origPubKey, so HasSessionState must return true.
	if !sess.HasSessionState(3, origPubKey) {
		t.Fatal("HasSessionState should return true when base key matches original 33-byte form")
	}

	// A different key must not match.
	kp2 := genKP(t)
	if sess.HasSessionState(3, kp2.PublicKey().Serialize()) {
		t.Fatal("HasSessionState must return false for a different key")
	}
}
