package zkgroup

// Wire-format lengths for zkgroup credential types. Every constant here has a
// corresponding Rust pub const in rust/zkgroup/src/common/constants.rs at
// commit 98915c44. Names are converted from SCREAMING_SNAKE_CASE to
// PascalCase per Go style.
//
// Only constants that affect the external wire format or are needed by
// external consumers are exported. Internal calculation constants remain
// package-private.
const (
	// AuthCredentialLen is the byte length of a serialized AuthCredential.
	// Rust: AUTH_CREDENTIAL_LEN = 181
	AuthCredentialLen = 181

	// AuthCredentialPresentationV2Len is the byte length of a serialized
	// AuthCredentialPresentationV2.
	// Rust: AUTH_CREDENTIAL_PRESENTATION_V2_LEN = 461
	AuthCredentialPresentationV2Len = 461

	// AuthCredentialResponseLen is the byte length of a serialized
	// AuthCredentialResponse.
	// Rust: AUTH_CREDENTIAL_RESPONSE_LEN = 361
	AuthCredentialResponseLen = 361

	// AuthCredentialWithPniLen is the byte length of a serialized
	// AuthCredentialWithPni.
	// Rust: AUTH_CREDENTIAL_WITH_PNI_LEN = 265
	AuthCredentialWithPniLen = 265

	// AuthCredentialWithPniResponseLen is the byte length of a serialized
	// AuthCredentialWithPniResponse.
	// Rust: AUTH_CREDENTIAL_WITH_PNI_RESPONSE_LEN = 425
	AuthCredentialWithPniResponseLen = 425

	// ProfileKeyCiphertextLen is the byte length of a serialized
	// ProfileKeyCiphertext.
	// Rust: PROFILE_KEY_CIPHERTEXT_LEN = 65
	ProfileKeyCiphertextLen = 65

	// ProfileKeyCommitmentLen is the byte length of a serialized
	// ProfileKeyCommitment.
	// Rust: PROFILE_KEY_COMMITMENT_LEN = 97
	ProfileKeyCommitmentLen = 97

	// ExpiringProfileKeyCredentialLen is the byte length of a serialized
	// ExpiringProfileKeyCredential.
	// Rust: EXPIRING_PROFILE_KEY_CREDENTIAL_LEN = 153
	ExpiringProfileKeyCredentialLen = 153

	// ProfileKeyCredentialPresentationV2Len is the byte length of a serialized
	// ProfileKeyCredentialPresentationV2 (also equals V1 length = 713).
	// Rust: PROFILE_KEY_CREDENTIAL_PRESENTATION_V2_LEN = 713
	ProfileKeyCredentialPresentationV2Len = 713

	// ProfileKeyCredentialRequestLen is the byte length of a serialized
	// ProfileKeyCredentialRequest.
	// Rust: PROFILE_KEY_CREDENTIAL_REQUEST_LEN = 329
	ProfileKeyCredentialRequestLen = 329

	// ProfileKeyCredentialRequestContextLen is the byte length of a serialized
	// ProfileKeyCredentialRequestContext.
	// Rust: PROFILE_KEY_CREDENTIAL_REQUEST_CONTEXT_LEN = 473
	ProfileKeyCredentialRequestContextLen = 473

	// ExpiringProfileKeyCredentialResponseLen is the byte length of a serialized
	// ExpiringProfileKeyCredentialResponse.
	// Rust: EXPIRING_PROFILE_KEY_CREDENTIAL_RESPONSE_LEN = 497
	ExpiringProfileKeyCredentialResponseLen = 497

	// ReceiptCredentialLen is the byte length of a serialized ReceiptCredential.
	// Rust: RECEIPT_CREDENTIAL_LEN = 129
	ReceiptCredentialLen = 129

	// ReceiptCredentialPresentationLen is the byte length of a serialized
	// ReceiptCredentialPresentation.
	// Rust: RECEIPT_CREDENTIAL_PRESENTATION_LEN = 329
	ReceiptCredentialPresentationLen = 329

	// ReceiptCredentialRequestLen is the byte length of a serialized
	// ReceiptCredentialRequest.
	// Rust: RECEIPT_CREDENTIAL_REQUEST_LEN = 97
	ReceiptCredentialRequestLen = 97

	// ReceiptCredentialRequestContextLen is the byte length of a serialized
	// ReceiptCredentialRequestContext.
	// Rust: RECEIPT_CREDENTIAL_REQUEST_CONTEXT_LEN = 177
	ReceiptCredentialRequestContextLen = 177

	// ReceiptCredentialResponseLen is the byte length of a serialized
	// ReceiptCredentialResponse.
	// Rust: RECEIPT_CREDENTIAL_RESPONSE_LEN = 409
	ReceiptCredentialResponseLen = 409

	// GroupSecretParamsLen is the byte length of serialized GroupSecretParams.
	// Rust: GROUP_SECRET_PARAMS_LEN = 289
	GroupSecretParamsLen = 289

	// GroupPublicParamsLen is the byte length of serialized GroupPublicParams.
	// Rust: GROUP_PUBLIC_PARAMS_LEN = 97
	GroupPublicParamsLen = 97

	// ServerSecretParamsLen is the byte length of serialized ServerSecretParams.
	// Rust: SERVER_SECRET_PARAMS_LEN = 2721
	ServerSecretParamsLen = 2721

	// ServerPublicParamsLen is the byte length of serialized ServerPublicParams.
	// Rust: SERVER_PUBLIC_PARAMS_LEN = 673
	ServerPublicParamsLen = 673

	// UUIDCiphertextLen is the byte length of a serialized UUIDCiphertext.
	// Rust: UUID_CIPHERTEXT_LEN = 65
	UUIDCiphertextLen = 65

	// NumAuthCredAttributes is the number of zkcredential attributes in an
	// AuthCredential.
	// Rust: NUM_AUTH_CRED_ATTRIBUTES = 3
	NumAuthCredAttributes = 3

	// NumProfileKeyCredAttributes is the number of zkcredential attributes in a
	// ProfileKeyCredential.
	// Rust: NUM_PROFILE_KEY_CRED_ATTRIBUTES = 4
	NumProfileKeyCredAttributes = 4

	// NumReceiptCredAttributes is the number of zkcredential attributes in a
	// ReceiptCredential.
	// Rust: NUM_RECEIPT_CRED_ATTRIBUTES = 2
	NumReceiptCredAttributes = 2
)

// Presentation version byte values. These appear as the first byte of every
// serialized credential presentation.
// Rust: PRESENTATION_VERSION_1..4 in rust/zkgroup/src/common/constants.rs.
const (
	// PresentationVersionByte1 is the version byte for V1 presentations (value 0x00).
	PresentationVersionByte1 byte = 0
	// PresentationVersionByte2 is the version byte for V2 presentations (value 0x01).
	PresentationVersionByte2 byte = 1
	// PresentationVersionByte3 is the version byte for V3 presentations (value 0x02).
	PresentationVersionByte3 byte = 2
	// PresentationVersionByte4 is the version byte for V4 presentations (value 0x03).
	PresentationVersionByte4 byte = 3
)
