package prekey

// PreKeyID is a typed identifier for EC pre-keys.
// It mirrors the Rust PreKeyId newtype at rust/protocol/src/state/prekey.rs:17.
// Using a distinct type rather than plain uint32 prevents accidental interchange
// with SignedPreKeyId, KyberPreKeyId, or other uint32 identifiers.
type PreKeyID uint32

// SignedPreKeyID is a typed identifier for signed EC pre-keys.
// It mirrors the Rust SignedPreKeyId newtype at rust/protocol/src/state/signed_prekey.rs:18.
type SignedPreKeyID uint32
