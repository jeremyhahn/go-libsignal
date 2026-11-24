package prekey

// PreKeyID is a typed EC pre-key identifier (Rust PreKeyId).
type PreKeyID uint32

// SignedPreKeyID is a typed identifier for signed EC pre-keys.
// It mirrors the Rust SignedPreKeyId newtype at rust/protocol/src/state/signed_prekey.rs:18.
type SignedPreKeyID uint32
