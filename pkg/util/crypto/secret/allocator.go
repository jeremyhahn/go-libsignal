package secret

import (
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-enclave"
)

// unbudgeted marks a package that allocated before any budget was installed.
// It is compared by address only and never allocates.
var unbudgeted = new(allocSlot)

// allocSlot boxes an enclave.Allocator, an interface since go-enclave v0.9, so
// admission can hold it in an atomic.Pointer and unbudgeted can be a sentinel
// no installed Allocator can equal.
type allocSlot struct{ a enclave.Allocator }

var (
	allocatorOnce sync.Once

	// admission is nil until either the first locked allocation or a successful
	// SetAllocator, whichever comes first. The first allocation seals it to
	// unbudgeted; SetAllocator installs its Allocator only over nil. A single
	// compare-and-swap therefore decides the race between the two: no
	// allocation can run unbudgeted once SetAllocator has returned nil, and
	// SetAllocator cannot succeed once any allocation has run without it.
	admission atomic.Pointer[allocSlot]
)

// SetAllocator bounds the locked memory held by every Secret and Secret32 the
// package creates from now on to maxBytes, via an enclave.Allocator. Without it
// the package allocates unbudgeted, limited only by RLIMIT_MEMLOCK.
//
// The budget is in locked bytes and every secret costs at least one whole page;
// see enclave.NewAllocator for how to size it. An allocation the budget cannot
// admit fails with ErrSecretAlloc wrapping enclave.ErrBudgetExhausted, and
// Destroy returns a secret's reservation to the budget.
//
// SetAllocator takes effect once per process and must run before the package's
// first locked allocation. It returns ErrInvalidBudget for a non-positive
// maxBytes, ErrAllocatorAfterAllocation if a secret was already allocated
// unbudgeted, and ErrAllocatorAlreadySet on any call after the first valid one.
// The last two fail closed: the package stays as it was.
//
// Upstream: no Rust libsignal counterpart. Rust libsignal does not lock key
// memory; this budget belongs to the go-enclave backing store. It was added by
// go-libsignal#41 under the owner's Option (A) ruling.
func SetAllocator(maxBytes int64) error {
	a, err := enclave.NewAllocator(maxBytes)
	if err != nil {
		return &Error{kind: errInvalidBudget, cause: err}
	}
	err = &Error{kind: errAllocatorAlreadySet}
	allocatorOnce.Do(func() {
		if admission.CompareAndSwap(nil, &allocSlot{a: a}) {
			err = nil
			return
		}
		err = &Error{kind: errAllocatorAfterAllocation}
	})
	return err
}

// allocator returns the installed Allocator, or nil when the package runs
// unbudgeted. The first call on an unconfigured package seals it unbudgeted,
// so a later SetAllocator fails rather than budgeting only some live secrets.
func allocator() enclave.Allocator {
	a := admission.Load()
	if a == nil {
		if admission.CompareAndSwap(nil, unbudgeted) {
			return nil
		}
		// SetAllocator won the race.
		a = admission.Load()
	}
	if a == unbudgeted {
		return nil
	}
	return a.a
}

// newLocked moves data into a new frozen enclave, admitted against the budget
// when one is installed. data is wiped on every path.
func newLocked(data []byte) (enclave.ByteAccess, error) {
	if a := allocator(); a != nil {
		return a.New(data)
	}
	return enclave.NewMemory(data)
}

// newLockedSized returns a writable, zeroed enclave of n bytes, admitted
// against the budget when one is installed.
func newLockedSized(n int) (enclave.ByteAccess, error) {
	if a := allocator(); a != nil {
		return a.NewSized(n)
	}
	return enclave.NewMemorySized(n)
}

// resetAllocator returns the package to its unconfigured state. It exists for
// tests only and is not safe against concurrent allocation.
func resetAllocator() {
	allocatorOnce = sync.Once{}
	admission.Store(nil)
}
