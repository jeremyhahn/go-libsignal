// Package testseam holds hooks that tests in other packages of this module
// set to reach a failure path deterministically. Production code leaves
// every hook nil; being internal, it is not importable outside the module.
package testseam

import "github.com/jeremyhahn/go-libsignal/pkg/util/crypto/secret"

// SPQRBeforeCopyBorrow, when set, runs just before spqr copies a required
// secret out of guarded memory, so a test can destroy the source between
// lookup and borrow as a concurrent wipe would.
var SPQRBeforeCopyBorrow func(*secret.Secret)
