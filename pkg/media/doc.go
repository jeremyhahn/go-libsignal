// Package media provides structural validation of MP4 and WebP media files,
// matching the formats supported by Rust libsignal's media crate.
//
// Current state: Validate (formerly Sanitize) performs structural validation
// only. Real metadata stripping (mp4san / webpsan equivalent) is not yet
// ported from Rust; Sanitize explicitly documents this limitation.
//
// JPEG, PNG, and GIF support is NOT part of Rust libsignal's media crate.
// Callers needing those formats should use the sibling package
// pkg/media/goextensions, which provides go-libsignal-specific implementations
// of JPEG/PNG sanitization and GIF validation.
package media
