// Package secret provides secure key material storage backed by go-enclave,
// the portfolio locked-memory primitive.
//
// All secret values are stored in mlock'd memory pages that are protected from
// swap and core dumps. go-enclave surrounds each buffer with guard pages and a
// canary to detect overflows, and wipes the pages when the enclave is
// destroyed.
//
// The package provides two primary types:
//
//   - Secret: a variable-length secure buffer for arbitrary key material.
//   - Secret32: a fixed 32-byte secure buffer for the most common
//     cryptographic key sizes (EC private keys, chain keys, root keys, shared
//     secrets, HMAC keys).
//
// # Reading a secret
//
// A secret's material is reachable only through WithBytes, which is
// go-enclave's ByteAccess.WithBytes: it lends fn a view of the locked bytes
// for the duration of the call and nothing longer. The rules are those of the
// go-enclave contract:
//
//   - The view is valid only inside fn. fn must not retain it, return it, or
//     let it escape into a goroutine; copy what must outlive the call.
//   - The view may sit on read-only pages. Do not write to it, and do not pass
//     it to a function that wipes its input (such as New, or a constructor
//     built on New); copy it out first and wipe the copy afterwards.
//   - fn must not call a method on the same secret: the borrow holds the
//     enclave's lock, so re-entering it deadlocks. Borrowing two different
//     secrets at once, by nesting their WithBytes calls, is fine.
//
// A nil Secret, or one that holds no material, calls fn with a nil view. A
// destroyed Secret returns ErrSecretDestroyed without calling fn.
//
// Secret32 adds WithArray, which lends the same view as a *[32]byte. EqualTo
// compares a secret with a plain value in constant time.
//
// # Destruction
//
// Destroy wipes the locked pages and releases them. After Destroy every borrow
// returns ErrSecretDestroyed, so a released secret never yields its old
// material. Destroy is idempotent.
//
// # System requirements
//
// Locked memory requires the ability to call mlock(2). Each secret costs at
// least one locked page, so a process holding many secrets at once may need a
// higher RLIMIT_MEMLOCK than the distribution default:
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
// go-enclave maps its own memory and returns a typed error from construction.
// Reaching the ceiling fails exactly the allocation that reached it; every
// other secret in the process is untouched. The constructors surface that
// failure as ErrSecretAlloc, so library code can handle it.
//
// # Locked-memory budget
//
// RLIMIT_MEMLOCK is shared by the whole process, so one path that allocates
// without bound can starve every other. SetAllocator installs a go-enclave
// Allocator that caps the locked memory this package holds; once installed,
// every constructor admits its allocation against the budget and Destroy
// returns it. It must be called before the first allocation, and is unset (no
// budget beyond the kernel's) by default.
package secret
