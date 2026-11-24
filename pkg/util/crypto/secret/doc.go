// Package secret stores key material in go-enclave locked memory: mlock'd, guard-paged pages kept out of swap and core dumps and wiped on destruction.
//
// Secret holds variable-length material and Secret32 holds 32 bytes.
//
// # Reading a secret
//
// WithBytes lends fn a view of the locked bytes for the call only. fn must not keep or leak the view, write to it, pass it to a function that wipes its input such as New, or call a method on the same secret, which deadlocks; nesting borrows of two different secrets is fine. A nil or empty Secret lends a nil view; a destroyed one returns ErrSecretDestroyed. Secret32.WithArray lends a *[32]byte, and EqualTo compares in constant time.
//
// # Destruction
//
// Destroy wipes and releases the pages; later borrows return ErrSecretDestroyed. It is idempotent.
//
// # Locked memory
//
// Each secret takes at least one locked page, so raise RLIMIT_MEMLOCK (ulimit -l, or memlock in /etc/security/limits.conf) for many secrets. An allocation over the limit fails alone, as ErrSecretAlloc. SetAllocator, called before the first allocation, installs a go-enclave Allocator that caps this package's locked memory.
package secret
