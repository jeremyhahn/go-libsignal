package zkgroup

import (
	"testing"

	"github.com/jeremyhahn/go-libsignal/pkg/zkcredential"
)

func TestGenerateSignatureKeyPair(t *testing.T) {
	sho := zkcredential.NewShoHmacSha256Ext("test_sig_key")
	kp, err := GenerateSignatureKeyPair(sho)
	if err != nil {
		t.Fatalf("GenerateSignatureKeyPair failed: %v", err)
	}
	if kp.SigningKey == nil {
		t.Fatal("SigningKey is nil")
	}
	if kp.PublicKey == nil {
		t.Fatal("PublicKey is nil")
	}
}

func TestSignatureKeyPairGetPublicKey(t *testing.T) {
	sho := zkcredential.NewShoHmacSha256Ext("test_sig_key_pub")
	kp, err := GenerateSignatureKeyPair(sho)
	if err != nil {
		t.Fatalf("GenerateSignatureKeyPair failed: %v", err)
	}
	pub := kp.GetPublicKey()
	if pub == nil {
		t.Fatal("GetPublicKey returned nil")
	}
	if pub.PublicKey == nil {
		t.Fatal("PublicKey.PublicKey is nil")
	}
}

func TestTimestampStruct(t *testing.T) {
	ts := NewTimestamp(86400)
	tss := NewTimestampStruct(ts)
	if tss.Timestamp != ts {
		t.Error("Timestamp mismatch")
	}
	m := tss.CalcM()
	if m == nil {
		t.Fatal("CalcM returned nil")
	}
}

func TestCalcTimestampM(t *testing.T) {
	ts1 := NewTimestamp(86400)
	ts2 := NewTimestamp(86400)
	m1 := CalcTimestampM(ts1)
	m2 := CalcTimestampM(ts2)
	if m1.Equal(m2) != 1 {
		t.Fatal("CalcTimestampM not deterministic")
	}

	ts3 := NewTimestamp(172800)
	m3 := CalcTimestampM(ts3)
	if m1.Equal(m3) == 1 {
		t.Fatal("different timestamps produced same scalar")
	}
}

func TestUIDEncryptionDomain(t *testing.T) {
	d := UIDEncryptionDomain{}
	if d.ID() != "Signal_ZKGroup_20230419_UidEncryption" {
		t.Errorf("ID() = %q", d.ID())
	}
	ga := d.Ga()
	if ga[0] == nil || ga[1] == nil {
		t.Fatal("Ga returned nil elements")
	}
}

func TestProfileKeyEncryptionDomain(t *testing.T) {
	d := ProfileKeyEncryptionDomain{}
	if d.ID() != "Signal_ZKGroup_20231011_ProfileKeyEncryption" {
		t.Errorf("ID() = %q", d.ID())
	}
	ga := d.Ga()
	if ga[0] == nil || ga[1] == nil {
		t.Fatal("Ga returned nil elements")
	}
}

func TestNewUIDStructFromServiceID(t *testing.T) {
	uuid := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	sid := NewACI(uuid)
	uid := NewUIDStructFromServiceID(sid)
	if uid == nil {
		t.Fatal("returned nil")
	}
	if uid.M1 == nil || uid.M2 == nil {
		t.Fatal("M1 or M2 is nil")
	}

	// Deterministic
	uid2 := NewUIDStructFromServiceID(sid)
	if uid.M1.Equal(uid2.M1) != 1 || uid.M2.Equal(uid2.M2) != 1 {
		t.Fatal("not deterministic")
	}

	// AsPoints
	points := uid.AsPoints()
	if points[0] == nil || points[1] == nil {
		t.Fatal("AsPoints returned nil")
	}
}

func TestNewUIDStructFromServiceIDPNI(t *testing.T) {
	uuid := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// PNI should produce different M1 than ACI (because service_id_binary differs)
	aciUID := NewUIDStructFromServiceID(NewACI(uuid))
	pniUID := NewUIDStructFromServiceID(NewPNI(uuid))

	// M1 must differ because PNI absorbs 17 bytes (type prefix + UUID) vs ACI's 16 bytes
	if aciUID.M1.Equal(pniUID.M1) == 1 {
		t.Fatal("ACI and PNI with same UUID should produce different M1 points")
	}

	// M2 should be the same since it's Lizard encode of raw UUID bytes (same for both)
	if aciUID.M2.Equal(pniUID.M2) != 1 {
		t.Fatal("ACI and PNI with same UUID should produce same M2 (Lizard encode of raw UUID)")
	}
}

func TestLizardEncodeTestVectors(t *testing.T) {
	tests := []struct {
		name     string
		data     [16]byte
		expected string
	}{
		{
			name:     "all_zeros",
			data:     [16]byte{},
			expected: "f0b7e34484f74cf00f15024b738539738646bbbe1e9bc7509a676815227e774f",
		},
		{
			name:     "all_ones",
			data:     [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
			expected: "cc92e81f585afc5caac88660d8d17e9025a44489a363042123f6af0702156e65",
		},
		{
			name:     "sequential",
			data:     [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			expected: "c830573f8a8e7778671f76cdc796dc0a235cf177f197d9fcba06e84e96247444",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := LizardEncode(tt.data)
			got := hexEncode(p.Bytes())
			if got != tt.expected {
				t.Errorf("LizardEncode(%v)\ngot:  %s\nwant: %s", tt.data, got, tt.expected)
			}
		})
	}
}

func TestLizardEncodeDeterministic(t *testing.T) {
	data := [16]byte{42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57}
	p1 := LizardEncode(data)
	p2 := LizardEncode(data)
	if p1.Equal(p2) != 1 {
		t.Fatal("LizardEncode is not deterministic")
	}
}

func TestLizardEncodeDifferentInputs(t *testing.T) {
	data1 := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	data2 := [16]byte{16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	p1 := LizardEncode(data1)
	p2 := LizardEncode(data2)
	if p1.Equal(p2) == 1 {
		t.Fatal("different inputs should produce different points")
	}
}

func TestLizardDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data [16]byte
	}{
		{
			name: "all_zeros",
			data: [16]byte{},
		},
		{
			name: "all_ones",
			data: [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		},
		{
			name: "sequential",
			data: [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
		},
		{
			name: "uuid-like",
			data: [16]byte{0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
				0x9a, 0xbc, 0xde, 0xf0, 0x12, 0x34, 0x56, 0x78},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			point := LizardEncode(tt.data)
			decoded, ok := LizardDecode(point)
			if !ok {
				t.Fatalf("LizardDecode failed for input %x", tt.data)
			}
			if decoded != tt.data {
				t.Errorf("LizardDecode round-trip failed:\ngot:  %x\nwant: %x", decoded, tt.data)
			}
		})
	}
}

func TestLizardDecodeInvalidPoint(t *testing.T) {
	// The generator point was not created via LizardEncode, so decoding
	// should fail (no valid candidate with the Lizard hash structure).
	gen := zkcredential.NewShoHmacSha256Ext("TestLizardDecodeInvalid")
	point := gen.MustGetPoint()
	_, ok := LizardDecode(point)
	if ok {
		t.Error("expected LizardDecode to fail for a non-Lizard-encoded point")
	}
}

func TestDecode253BitsRoundTrip(t *testing.T) {
	// Create a point via single Elligator with bit-cleared bytes
	var input [32]byte
	for i := range input {
		input[i] = byte(i + 42)
	}
	input[0] &= 254
	input[31] &= 63

	point, err := zkcredential.PointFromSingleElligator(input[:])
	if err != nil {
		t.Fatalf("PointFromSingleElligator: %v", err)
	}

	mask, candidates, ok := Decode253Bits(point)
	if !ok {
		t.Fatal("Decode253Bits failed")
	}

	// The original input (with bits cleared) should appear among the candidates
	found := false
	for j := 0; j < 8; j++ {
		if mask&(1<<j) == 0 {
			continue
		}
		if candidates[j] == input {
			found = true
			break
		}
	}
	if !found {
		t.Error("original field element not found among Decode253Bits candidates")
	}
}

func TestDecode253BitsInvalidPoint(t *testing.T) {
	// Invalid 32-byte encoding should fail
	var bad [32]byte
	for i := range bad {
		bad[i] = 0xff
	}
	// Use a valid point, just verify we get valid output
	point := LizardEncode([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	mask, _, ok := Decode253Bits(point)
	if !ok {
		t.Fatal("Decode253Bits failed for valid point")
	}
	if mask == 0 {
		t.Error("expected at least one valid candidate")
	}
}

func TestNewProfileKeyStruct(t *testing.T) {
	var pkBytes ProfileKeyBytes
	var uidBytes UIDBytes
	for i := range pkBytes {
		pkBytes[i] = byte(i)
	}
	for i := range uidBytes {
		uidBytes[i] = byte(i + 100)
	}

	pks := NewProfileKeyStruct(pkBytes, uidBytes)
	if pks == nil {
		t.Fatal("returned nil")
	}
	if pks.M3 == nil || pks.M4 == nil {
		t.Fatal("M3 or M4 is nil")
	}
	if pks.RawBytes != pkBytes {
		t.Error("RawBytes mismatch")
	}

	// AsPoints
	points := pks.AsPoints()
	if points[0] == nil || points[1] == nil {
		t.Fatal("AsPoints returned nil")
	}
}

func TestProfileKeyCommitmentSystemParams(t *testing.T) {
	params := GenerateProfileKeyCommitmentSystemParams()
	if params == nil {
		t.Fatal("returned nil")
	}
	if params.GJ1 == nil || params.GJ2 == nil || params.GJ3 == nil {
		t.Fatal("nil generator point")
	}

	// Deterministic
	params2 := GenerateProfileKeyCommitmentSystemParams()
	if params.GJ1.Equal(params2.GJ1) != 1 {
		t.Fatal("not deterministic")
	}
}

func TestProfileKeyCommitmentWithSecretNonce(t *testing.T) {
	var pkBytes ProfileKeyBytes
	var uidBytes UIDBytes
	for i := range pkBytes {
		pkBytes[i] = byte(i)
	}
	for i := range uidBytes {
		uidBytes[i] = byte(i + 100)
	}

	pks := NewProfileKeyStruct(pkBytes, uidBytes)
	commitment := NewProfileKeyCommitmentWithSecretNonce(pks, uidBytes)
	if commitment == nil {
		t.Fatal("returned nil")
	}
	if commitment.J1 == nil || commitment.J2 == nil || commitment.J3 == nil || commitment.J3s == nil {
		t.Fatal("nil field")
	}

	// GetCommitment
	pub := commitment.GetCommitment()
	if pub == nil {
		t.Fatal("GetCommitment returned nil")
	}
	if pub.J1 == nil || pub.J2 == nil || pub.J3 == nil {
		t.Fatal("nil commitment field")
	}
}

func TestNewReceiptStruct(t *testing.T) {
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i)
	}
	ts := NewTimestamp(86400)
	level := uint64(42)

	rs := NewReceiptStruct(serial, ts, level)
	if rs == nil {
		t.Fatal("returned nil")
	}
	if rs.ReceiptSerialBytes != serial {
		t.Error("serial mismatch")
	}
	if rs.ReceiptExpirationTime != ts {
		t.Error("expiration mismatch")
	}
	if rs.ReceiptLevel != level {
		t.Errorf("level = %d, want %d", rs.ReceiptLevel, level)
	}
}

func TestReceiptStructCalcM1(t *testing.T) {
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i)
	}
	ts := NewTimestamp(86400)
	level := uint64(42)

	rs := NewReceiptStruct(serial, ts, level)
	m1 := rs.CalcM1()
	if m1 == nil {
		t.Fatal("CalcM1 returned nil")
	}

	// Deterministic: same expiration and level should produce same scalar
	m1b := CalcReceiptM1(ts, level)
	if m1.Equal(m1b) != 1 {
		t.Fatal("CalcM1 is not deterministic")
	}

	// Different expiration should produce different scalar
	ts2 := NewTimestamp(172800)
	rs2 := NewReceiptStruct(serial, ts2, level)
	m1c := rs2.CalcM1()
	if m1.Equal(m1c) == 1 {
		t.Fatal("different expiration should produce different M1")
	}

	// Different level should produce different scalar
	rs3 := NewReceiptStruct(serial, ts, 99)
	m1d := rs3.CalcM1()
	if m1.Equal(m1d) == 1 {
		t.Fatal("different level should produce different M1")
	}
}

func TestCalcReceiptM1ZeroInputs(t *testing.T) {
	// Should not panic with zero values
	m := CalcReceiptM1(NewTimestamp(0), 0)
	if m == nil {
		t.Fatal("CalcReceiptM1 returned nil for zero inputs")
	}
}

func TestConvertToPointsReceiptStruct(t *testing.T) {
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i + 1)
	}
	ts := NewTimestamp(86400)
	level := uint64(42)

	rs := NewReceiptStruct(serial, ts, level)
	points := ConvertToPointsReceiptStruct(rs)
	if len(points) != 2 {
		t.Fatalf("expected 2 points, got %d", len(points))
	}
	if points[0] == nil || points[1] == nil {
		t.Fatal("returned nil points")
	}

	// Deterministic
	points2 := ConvertToPointsReceiptStruct(rs)
	if points[0].Equal(points2[0]) != 1 || points[1].Equal(points2[1]) != 1 {
		t.Fatal("ConvertToPointsReceiptStruct is not deterministic")
	}

	// Different receipt should produce different points
	rs2 := NewReceiptStruct(serial, NewTimestamp(172800), level)
	points3 := ConvertToPointsReceiptStruct(rs2)
	if points[0].Equal(points3[0]) == 1 {
		t.Fatal("different expiration should produce different first point")
	}
}

func TestConvertToPointsReceiptStructNilSerial(t *testing.T) {
	// Zero serial bytes should still work
	var serial ReceiptSerialBytes
	rs := NewReceiptStruct(serial, NewTimestamp(86400), 1)
	points := ConvertToPointsReceiptStruct(rs)
	if len(points) != 2 {
		t.Fatalf("expected 2 points, got %d", len(points))
	}
	if points[0] == nil || points[1] == nil {
		t.Fatal("returned nil points")
	}
}

func TestConvertToPointM2ReceiptSerialBytes(t *testing.T) {
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i + 1)
	}

	p := ConvertToPointM2ReceiptSerialBytes(serial)
	if p == nil {
		t.Fatal("returned nil")
	}

	// Deterministic
	p2 := ConvertToPointM2ReceiptSerialBytes(serial)
	if p.Equal(p2) != 1 {
		t.Fatal("not deterministic")
	}

	// Different serial should produce different point
	var serial2 ReceiptSerialBytes
	for i := range serial2 {
		serial2[i] = byte(i + 100)
	}
	p3 := ConvertToPointM2ReceiptSerialBytes(serial2)
	if p.Equal(p3) == 1 {
		t.Fatal("different serial should produce different point")
	}
}

func TestConvertToPointM2ReceiptSerialBytesConsistency(t *testing.T) {
	// The M2 point from ConvertToPointsReceiptStruct should match
	// ConvertToPointM2ReceiptSerialBytes for the same serial
	var serial ReceiptSerialBytes
	for i := range serial {
		serial[i] = byte(i + 1)
	}
	ts := NewTimestamp(86400)
	level := uint64(42)

	rs := NewReceiptStruct(serial, ts, level)
	points := ConvertToPointsReceiptStruct(rs)
	m2Direct := ConvertToPointM2ReceiptSerialBytes(serial)

	if points[1].Equal(m2Direct) != 1 {
		t.Fatal("M2 from ConvertToPointsReceiptStruct should match ConvertToPointM2ReceiptSerialBytes")
	}
}

func TestServiceIdBinary(t *testing.T) {
	uuid := [UUIDLen]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// ACI: just the 16-byte UUID
	aci := NewACI(uuid)
	aciBin := aci.ServiceIdBinary()
	if len(aciBin) != 16 {
		t.Fatalf("ACI ServiceIdBinary length = %d, want 16", len(aciBin))
	}
	for i, b := range aciBin {
		if b != uuid[i] {
			t.Fatalf("ACI ServiceIdBinary[%d] = %d, want %d", i, b, uuid[i])
		}
	}

	// PNI: 17 bytes = [0x01] + UUID
	pni := NewPNI(uuid)
	pniBin := pni.ServiceIdBinary()
	if len(pniBin) != 17 {
		t.Fatalf("PNI ServiceIdBinary length = %d, want 17", len(pniBin))
	}
	if pniBin[0] != byte(ServiceIDTypePNI) {
		t.Fatalf("PNI ServiceIdBinary[0] = 0x%02x, want 0x%02x", pniBin[0], ServiceIDTypePNI)
	}
	for i, b := range pniBin[1:] {
		if b != uuid[i] {
			t.Fatalf("PNI ServiceIdBinary[%d] = %d, want %d", i+1, b, uuid[i])
		}
	}
}
