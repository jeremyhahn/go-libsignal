package secret

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

// The tests in this file change package-level state and must not run in
// parallel.

// page is the locked cost of one small secret: every enclave occupies at least
// one whole page.
var page = enclave.LockedSize(32)

// installBudget resets the package, installs a budget of maxBytes and restores
// the unconfigured state when the test ends.
func installBudget(t *testing.T, maxBytes int64) enclave.Allocator {
	t.Helper()
	resetAllocator()
	t.Cleanup(resetAllocator)
	if err := SetAllocator(maxBytes); err != nil {
		t.Fatalf("SetAllocator(%d): %v", maxBytes, err)
	}
	return admission.Load().a
}

// requireBudgetExhausted asserts that a constructor was refused by the budget.
func requireBudgetExhausted(t *testing.T, s *Secret, err error) {
	t.Helper()
	if err == nil {
		s.Destroy()
		t.Fatal("expected the allocation to be refused by the budget")
	}
	if s != nil {
		t.Error("expected a nil secret on refusal")
	}
	if !errors.Is(err, &Error{kind: errSecretAlloc}) {
		t.Errorf("error = %v, want an allocation error", err)
	}
	if !errors.Is(err, enclave.ErrBudgetExhausted) {
		t.Errorf("error = %v, want it to wrap enclave.ErrBudgetExhausted", err)
	}
}

func requireInUse(t *testing.T, a enclave.Allocator, want int64) {
	t.Helper()
	if got := a.InUse(); got != want {
		t.Errorf("InUse() = %d, want %d", got, want)
	}
}

func TestSetAllocator_ChargesAndReleasesOnDestroy(t *testing.T) {
	a := installBudget(t, 4*page)

	s, err := New(bytes.Repeat([]byte{0xAA}, 32))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	requireInUse(t, a, page)

	s.Destroy()
	requireInUse(t, a, 0)

	// A second Destroy must not release the reservation again.
	s.Destroy()
	requireInUse(t, a, 0)
}

func TestSetAllocator_InvalidBudget(t *testing.T) {
	resetAllocator()
	t.Cleanup(resetAllocator)

	for _, budget := range []int64{0, -1} {
		err := SetAllocator(budget)
		if !errors.Is(err, ErrInvalidBudget) {
			t.Errorf("SetAllocator(%d) = %v, want ErrInvalidBudget", budget, err)
		}
		if !errors.Is(err, enclave.ErrInvalidBudget) {
			t.Errorf("SetAllocator(%d) = %v, want it to wrap enclave.ErrInvalidBudget", budget, err)
		}
	}

	// A rejected budget does not use up the one installation.
	if err := SetAllocator(page); err != nil {
		t.Fatalf("SetAllocator after invalid budgets: %v", err)
	}
}

func TestSetAllocator_SecondCallFails(t *testing.T) {
	first := installBudget(t, page)

	err := SetAllocator(2 * page)
	if !errors.Is(err, ErrAllocatorAlreadySet) {
		t.Errorf("second SetAllocator = %v, want ErrAllocatorAlreadySet", err)
	}
	if admission.Load().a != first {
		t.Error("second SetAllocator replaced the installed allocator")
	}
}

func TestSetAllocator_AfterFirstAllocationFailsClosed(t *testing.T) {
	resetAllocator()
	t.Cleanup(resetAllocator)

	held, err := NewEmpty(32)
	if err != nil {
		t.Fatalf("NewEmpty: %v", err)
	}
	defer held.Destroy()

	// A budget below one page would refuse every allocation, so a later
	// allocation succeeding proves the package stayed unbudgeted.
	if err := SetAllocator(1); !errors.Is(err, ErrAllocatorAfterAllocation) {
		t.Fatalf("SetAllocator after allocation = %v, want ErrAllocatorAfterAllocation", err)
	}
	s, err := NewEmpty(32)
	if err != nil {
		t.Fatalf("NewEmpty after refused SetAllocator: %v", err)
	}
	s.Destroy()

	if err := SetAllocator(page); !errors.Is(err, ErrAllocatorAlreadySet) {
		t.Errorf("SetAllocator retry = %v, want ErrAllocatorAlreadySet", err)
	}
}

// TestSetAllocator_RaceWithFirstAllocation pins the all-or-nothing contract:
// if SetAllocator succeeds while allocations are in flight, every one of them
// was admitted against the budget, and if it fails, none was.
func TestSetAllocator_RaceWithFirstAllocation(t *testing.T) {
	const workers = 8
	t.Cleanup(resetAllocator)

	for iter := 0; iter < 50; iter++ {
		resetAllocator()

		start := make(chan struct{})
		secrets := make([]*Secret, workers)
		errs := make([]error, workers)
		var setErr error
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				secrets[i], errs[i] = NewEmpty(32)
			}(i)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			setErr = SetAllocator(workers * page)
		}()
		close(start)
		wg.Wait()

		for i, err := range errs {
			if err != nil {
				t.Fatalf("iteration %d: NewEmpty[%d]: %v", iter, i, err)
			}
		}

		a := allocator()
		switch {
		case setErr == nil:
			requireInUse(t, a, workers*page)
		case errors.Is(setErr, ErrAllocatorAfterAllocation):
			if a != nil {
				t.Fatalf("iteration %d: refused SetAllocator left an allocator installed", iter)
			}
		default:
			t.Fatalf("iteration %d: SetAllocator = %v", iter, setErr)
		}

		for _, s := range secrets {
			s.Destroy()
		}
		if a != nil {
			requireInUse(t, a, 0)
		}
	}
}

func TestNew_BudgetExhausted(t *testing.T) {
	a := installBudget(t, page)

	held, err := New(bytes.Repeat([]byte{0x01}, 32))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	data := bytes.Repeat([]byte{0xAB}, 32)
	s, err := New(data)
	requireBudgetExhausted(t, s, err)
	if !bytes.Equal(data, make([]byte, 32)) {
		t.Error("refused New must still zeroize its source")
	}
	requireInUse(t, a, page)

	// Destroy returns the reservation, so the budget admits again.
	held.Destroy()
	s, err = New(bytes.Repeat([]byte{0xAB}, 32))
	if err != nil {
		t.Fatalf("New after Destroy: %v", err)
	}
	s.Destroy()
}

func TestNewEmpty_BudgetExhausted(t *testing.T) {
	a := installBudget(t, 1)

	s, err := NewEmpty(32)
	requireBudgetExhausted(t, s, err)
	requireInUse(t, a, 0)
}

func TestNewRandom_BudgetExhaustedForScratch(t *testing.T) {
	a := installBudget(t, 1)

	s, err := NewRandom(32)
	requireBudgetExhausted(t, s, err)
	requireInUse(t, a, 0)
}

// TestNewRandom_BudgetExhaustedForFrozen admits the scratch region and refuses
// the frozen one; the scratch reservation must be returned.
func TestNewRandom_BudgetExhaustedForFrozen(t *testing.T) {
	a := installBudget(t, page)

	s, err := NewRandom(32)
	requireBudgetExhausted(t, s, err)
	requireInUse(t, a, 0)
}

func TestNewRandom_UnderBudgetHoldsOnlyFrozen(t *testing.T) {
	a := installBudget(t, 2*page)

	s, err := NewRandom(32)
	if err != nil {
		t.Fatalf("NewRandom: %v", err)
	}
	requireInUse(t, a, page)
	s.Destroy()
	requireInUse(t, a, 0)
}

func TestClone_BudgetExhausted(t *testing.T) {
	a := installBudget(t, page)

	src, err := New(bytes.Repeat([]byte{0x5A}, 32))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer src.Destroy()

	clone, err := src.Clone()
	requireBudgetExhausted(t, clone, err)
	if src.IsDestroyed() {
		t.Error("refused Clone must leave the source intact")
	}
	requireInUse(t, a, page)
}

func TestClone_UnderBudget(t *testing.T) {
	a := installBudget(t, 2*page)

	want := bytes.Repeat([]byte{0x5A}, 32)
	src, err := New(bytes.Clone(want))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer src.Destroy()

	clone, err := src.Clone()
	if err != nil {
		t.Fatalf("Clone: %v", err)
	}
	if !clone.EqualTo(want) {
		t.Error("clone does not hold the source material")
	}
	requireInUse(t, a, 2*page)
	clone.Destroy()
	requireInUse(t, a, page)
}

func TestSecret32Constructors_BudgetExhausted(t *testing.T) {
	tests := []struct {
		name string
		make func() (*Secret32, error)
	}{
		{"NewSecret32", func() (*Secret32, error) { return NewSecret32([32]byte{0x01}) }},
		{"NewSecret32FromSlice", func() (*Secret32, error) { return NewSecret32FromSlice(make([]byte, 32)) }},
		{"NewSecret32Random", NewSecret32Random},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := installBudget(t, 1)

			s, err := tc.make()
			if err == nil {
				s.Destroy()
				t.Fatal("expected the allocation to be refused by the budget")
			}
			if s != nil {
				t.Error("expected a nil secret on refusal")
			}
			if !errors.Is(err, enclave.ErrBudgetExhausted) {
				t.Errorf("error = %v, want it to wrap enclave.ErrBudgetExhausted", err)
			}
			requireInUse(t, a, 0)
		})
	}
}
