// Package secret provides secure key material storage backed by go-enclave,
// the portfolio locked-memory primitive.
//
// All secret values are stored in mlock'd memory pages that are protected from
// swap, core dumps, and other forms of unintended disclosure. The underlying
// go-enclave MemoryEnclave uses guard pages and a canary to detect buffer
// overflows, and zeroizes memory on destruction.
//
// The package provides two primary types:
//
//   - Secret: a variable-length secure buffer for arbitrary key material.
//   - Secret32: a fixed 32-byte secure buffer optimized for the most common
//     cryptographic key sizes (EC private keys, chain keys, root keys, shared
//     secrets, HMAC keys).
//
// # System requirements
//
// Locked memory requires the ability to call mlock(2) to prevent memory pages
// from being swapped to disk. On Linux, the default mlock limit is often
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
// # Allocation failure
//
// Unlike memguard — which called os.Exit on allocation failure and purged every
// live locked buffer in the process when it reached RLIMIT_MEMLOCK — go-enclave
// maps its own memory and returns a typed error from construction. Reaching the
// ceiling fails exactly the allocation that reached it; every other secret in
// the process is untouched. The constructors surface that failure as
// ErrSecretAlloc, so library code handles it gracefully.
//
// # Locked-memory budget
//
// RLIMIT_MEMLOCK is shared by the whole process, so one path that allocates
// without bound can starve every other. SetAllocator installs a go-enclave
// Allocator that caps the locked memory this package holds; once installed,
// every constructor admits its allocation against the budget and Destroy
// returns it. It must be called before the first allocation, and is unset — no
// budget beyond the kernel's — by default.
package secret
