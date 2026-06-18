// Package secret provides secure key material storage backed by memguard.
//
// All secret values are stored in mlock'd memory pages that are protected from
// swap, core dumps, and other forms of unintended disclosure. The underlying
// memguard library uses guard pages and canary values to detect buffer overflows,
// and zeroizes memory on destruction.
//
// The package provides two primary types:
//
//   - Secret: a variable-length secure buffer for arbitrary key material.
//   - Secret32: a fixed 32-byte secure buffer optimized for the most common
//     cryptographic key sizes (EC private keys, chain keys, root keys, shared
//     secrets, HMAC keys).
//
// Secrets can be sealed into an Enclave for encrypted at-rest storage when
// they are not actively in use. This provides an additional layer of protection
// beyond mlock.
//
// # System requirements
//
// The memguard library requires the ability to call mlock(2) to prevent memory
// pages from being swapped to disk. On Linux, the default mlock limit is often
// 64 KiB per process. If your application manages many secrets concurrently,
// you may need to raise this limit:
//
//	ulimit -l unlimited
//
// Or in /etc/security/limits.conf:
//
//   - hard  memlock  unlimited
//   - soft  memlock  unlimited
//
// # Panic recovery
//
// memguard constructors call os.Exit on allocation failure rather than returning
// errors. This package wraps all memguard allocations with recover() to convert
// panics into typed errors, enabling graceful error handling in library code.
package secret
