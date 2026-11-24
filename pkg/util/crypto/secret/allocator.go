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

	// admission is set once by compare-and-swap, either to unbudgeted by the first allocation or by SetAllocator.
	admission atomic.Pointer[allocSlot]
)

// SetAllocator caps locked memory for new secrets at maxBytes, before the first allocation and once per process; it returns ErrInvalidBudget, ErrAllocatorAfterAllocation or ErrAllocatorAlreadySet.
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
