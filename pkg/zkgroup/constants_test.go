package zkgroup

import "testing"

// TestConstantsMatchRust verifies that each exported wire-format constant in
// constants.go matches the corresponding pub const from
// rust/zkgroup/src/common/constants.rs at commit 98915c44.
func TestConstantsMatchRust(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"AuthCredentialLen", AuthCredentialLen, 181},
		{"AuthCredentialPresentationV2Len", AuthCredentialPresentationV2Len, 461},
		{"AuthCredentialResponseLen", AuthCredentialResponseLen, 361},
		{"AuthCredentialWithPniLen", AuthCredentialWithPniLen, 265},
		{"AuthCredentialWithPniResponseLen", AuthCredentialWithPniResponseLen, 425},
		{"ProfileKeyCiphertextLen", ProfileKeyCiphertextLen, 65},
		{"ProfileKeyCommitmentLen", ProfileKeyCommitmentLen, 97},
		{"ExpiringProfileKeyCredentialLen", ExpiringProfileKeyCredentialLen, 153},
		{"ProfileKeyCredentialPresentationV2Len", ProfileKeyCredentialPresentationV2Len, 713},
		{"ProfileKeyCredentialRequestLen", ProfileKeyCredentialRequestLen, 329},
		{"ProfileKeyCredentialRequestContextLen", ProfileKeyCredentialRequestContextLen, 473},
		{"ExpiringProfileKeyCredentialResponseLen", ExpiringProfileKeyCredentialResponseLen, 497},
		{"ReceiptCredentialLen", ReceiptCredentialLen, 129},
		{"ReceiptCredentialPresentationLen", ReceiptCredentialPresentationLen, 329},
		{"ReceiptCredentialRequestLen", ReceiptCredentialRequestLen, 97},
		{"ReceiptCredentialRequestContextLen", ReceiptCredentialRequestContextLen, 177},
		{"ReceiptCredentialResponseLen", ReceiptCredentialResponseLen, 409},
		{"GroupSecretParamsLen", GroupSecretParamsLen, 289},
		{"GroupPublicParamsLen", GroupPublicParamsLen, 97},
		{"ServerSecretParamsLen", ServerSecretParamsLen, 2721},
		{"ServerPublicParamsLen", ServerPublicParamsLen, 673},
		{"UUIDCiphertextLen", UUIDCiphertextLen, 65},
		{"NumAuthCredAttributes", NumAuthCredAttributes, 3},
		{"NumProfileKeyCredAttributes", NumProfileKeyCredAttributes, 4},
		{"NumReceiptCredAttributes", NumReceiptCredAttributes, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("%s = %d, want %d (Rust reference)", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestPresentationVersionBytesMatchRust verifies the presentation version byte
// constants match PRESENTATION_VERSION_1..4 in Rust constants.rs.
func TestPresentationVersionBytesMatchRust(t *testing.T) {
	tests := []struct {
		name string
		got  byte
		want byte
	}{
		{"PresentationVersionByte1", PresentationVersionByte1, 0},
		{"PresentationVersionByte2", PresentationVersionByte2, 1},
		{"PresentationVersionByte3", PresentationVersionByte3, 2},
		{"PresentationVersionByte4", PresentationVersionByte4, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.want {
				t.Errorf("%s = %d, want %d", tc.name, tc.got, tc.want)
			}
		})
	}
}

// TestPresentationVersionBytesConsistentWithLocalConstants verifies that the
// new PresentationVersionByte* names are consistent with the existing
// PresentationVersion1..4 constants declared in auth.go.
func TestPresentationVersionBytesConsistentWithLocalConstants(t *testing.T) {
	if int(PresentationVersionByte1) != PresentationVersion1 {
		t.Errorf("PresentationVersionByte1 (%d) != PresentationVersion1 (%d)", PresentationVersionByte1, PresentationVersion1)
	}
	if int(PresentationVersionByte2) != PresentationVersion2 {
		t.Errorf("PresentationVersionByte2 (%d) != PresentationVersion2 (%d)", PresentationVersionByte2, PresentationVersion2)
	}
	if int(PresentationVersionByte3) != PresentationVersion3 {
		t.Errorf("PresentationVersionByte3 (%d) != PresentationVersion3 (%d)", PresentationVersionByte3, PresentationVersion3)
	}
	if int(PresentationVersionByte4) != PresentationVersion4 {
		t.Errorf("PresentationVersionByte4 (%d) != PresentationVersion4 (%d)", PresentationVersionByte4, PresentationVersion4)
	}
}
