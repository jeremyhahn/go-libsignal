// Package goextensions provides JPEG, PNG, and GIF media sanitization
// and validation as go-libsignal-specific extensions.
//
// These formats are NOT supported by Rust libsignal's media crate. They are
// go-libsignal extensions provided as a convenience for callers; behavior is
// not constrained by upstream.
//
// For MP4 and WebP, which are supported by Rust libsignal, use the parent
// pkg/media package directly.
package goextensions
