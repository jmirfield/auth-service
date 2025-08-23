package cache

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestSetGet_NoTTL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	c := NewMemory[int](ctx)

	if err := c.Set(ctx, "a", 42, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := c.Get(ctx, "a")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != 42 {
		t.Fatalf("Get = %v, want %v", got, 42)
	}

	// Ensure it still exists on repeated Get.
	got2, err := c.Get(ctx, "a")
	if err != nil {
		t.Fatalf("Get (second): %v", err)
	}
	if got2 != 42 {
		t.Fatalf("Get (second) = %v, want %v", got2, 42)
	}
}

func TestGet_ExpiredByTTL(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	c := NewMemory[string](ctx)

	ttl := 50 * time.Millisecond
	if err := c.Set(ctx, "k", "v", ttl); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Before expiry: value should be present.
	got, err := c.Get(ctx, "k")
	if err != nil {
		t.Fatalf("Get (before expiry): %v", err)
	}
	if got != "v" {
		t.Fatalf("Get (before expiry) = %q, want %q", got, "v")
	}

	// After expiry: Get should delete-and-return ErrNotFound.
	time.Sleep(ttl + 2*time.Second)

	_, err = c.Get(ctx, "k")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get (after expiry) err = %v, want ErrNotFound", err)
	}

	// Subsequent Get should still be ErrNotFound (deleted).
	_, err = c.Get(ctx, "k")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get (after delete) err = %v, want ErrNotFound", err)
	}
}

func TestDel_RemovesKey(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	c := NewMemory[struct{}](ctx)

	if err := c.Set(ctx, "gone", struct{}{}, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := c.Del(ctx, "gone"); err != nil {
		t.Fatalf("Del: %v", err)
	}
	_, err := c.Get(ctx, "gone")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Del err = %v, want ErrNotFound", err)
	}
}

func TestGet_NotFoundZeroValue(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	type widget struct {
		N int
		S string
	}
	c := NewMemory[widget](ctx)

	got, err := c.Get(ctx, "missing")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get err = %v, want ErrNotFound", err)
	}
	// Zero value check.
	if got.N != 0 || got.S != "" {
		t.Fatalf("Get zero value = %#v, want zero widget", got)
	}
}

func TestConcurrentAccess_NoRace(t *testing.T) {
	// Run with: go test -race
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	c := NewMemory[int](ctx)

	const (
		writers = 8
		readers = 16
		ops     = 200
	)

	var wg sync.WaitGroup

	// Writers
	wg.Add(writers)
	for w := 0; w < writers; w++ {
		w := w
		go func() {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				key := "k" + strconv.Itoa((w*ops)+i)
				_ = c.Set(ctx, key, i, 0)
				// Randomly delete some keys
				if i%37 == 0 {
					_ = c.Del(ctx, key)
				}
			}
		}()
	}

	// Readers
	wg.Add(readers)
	for r := 0; r < readers; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < ops*2; i++ {
				key := "k" + strconv.Itoa(i)
				_, _ = c.Get(ctx, key) // allow not found; we're stress testing for race
			}
		}()
	}

	wg.Wait()
}

func TestPointerTypeStillWorks(t *testing.T) {
	// Ensure T can be a pointer type; value semantics still fine.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	type thing struct{ X int }
	c := NewMemory[*thing](ctx)

	th := &thing{X: 7}
	if err := c.Set(ctx, "t", th, 0); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := c.Get(ctx, "t")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil || got.X != 7 {
		t.Fatalf("Get = %#v, want &thing{X:7}", got)
	}

	// Mutating through the pointer should be visible to subsequent Gets
	// because T is a pointer (we store by value, but that value is a pointer).
	got.X = 9
	got2, err := c.Get(ctx, "t")
	if err != nil {
		t.Fatalf("Get(2): %v", err)
	}
	if got2.X != 9 {
		t.Fatalf("mutation not observed: got2.X = %d, want 9", got2.X)
	}
}
