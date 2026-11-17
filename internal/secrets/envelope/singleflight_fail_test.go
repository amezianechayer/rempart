package envelope_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	"github.com/amezianechayer/rempart/internal/secrets/fake"
	"github.com/amezianechayer/rempart/internal/secrets/ports"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Obligation (dm) of docs/STATUS.md (M1-T02): the single flight of the DEK
// generation when the key manager fails, panics, or a waiter gives up.

var errKeyManager = errors.New("key manager down")

// failingKeyWrapper blocks the first generation until release, then fails it
// with errKeyManager (or panics); the next generations go to the fake.
type failingKeyWrapper struct {
	inner   ports.KeyWrapper
	panics  bool
	entered chan struct{}
	gate    chan struct{}
	once    sync.Once

	mu    sync.Mutex
	calls int
}

func newFailing(panics bool) *failingKeyWrapper {
	return &failingKeyWrapper{inner: fake.NewKeyWrapper(fakeSeed), panics: panics, entered: make(chan struct{}), gate: make(chan struct{})}
}

func (f *failingKeyWrapper) release() { f.once.Do(func() { close(f.gate) }) }

func (f *failingKeyWrapper) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *failingKeyWrapper) GenerateDataKey(ctx context.Context, tenant tenancy.ID) (secret.Bytes, []byte, error) {
	f.mu.Lock()
	f.calls++
	first := f.calls == 1
	f.mu.Unlock()
	if !first {
		return f.inner.GenerateDataKey(ctx, tenant)
	}
	close(f.entered)
	<-f.gate
	if f.panics {
		panic("key manager panicked in the test")
	}
	return secret.Bytes{}, nil, errKeyManager
}

func (f *failingKeyWrapper) UnwrapDataKey(ctx context.Context, tenant tenancy.ID, wrapped []byte) (secret.Bytes, error) {
	return f.inner.UnwrapDataKey(ctx, tenant, wrapped)
}

// sealLeader starts the leader Seal, recovering a panic, and waits until it is
// inside the key manager.
func sealLeader(t *testing.T, s *envelope.Sealer, ctx context.Context, f *failingKeyWrapper) <-chan sealResult {
	t.Helper()
	out := make(chan sealResult, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				out <- sealResult{err: fmt.Errorf("leader panicked: %v", r)}
			}
		}()
		sealed, err := s.Seal(ctx, []byte("leader"))
		out <- sealResult{sealed, err}
	}()
	select {
	case <-f.entered:
	case <-time.After(5 * time.Second):
		f.release()
		t.Fatal("the leader never reached the key manager")
	}
	return out
}

func waitResult(t *testing.T, ch <-chan sealResult, what string) sealResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not return", what)
		return sealResult{}
	}
}

// waitersQueued gives the waiters the time to join the flight.
func waitersQueued() { time.Sleep(200 * time.Millisecond) }

// TestSealSingleFlightError: the error of the leader is returned to every
// waiter, never cached: the next Seal generates again and succeeds.
func TestSealSingleFlightError(t *testing.T) {
	f := newFailing(false)
	t.Cleanup(f.release)
	s := newSealer(t, f, envelope.Options{})
	ctx := tenantCtx(t, demoTenant)
	leader := sealLeader(t, s, ctx, f)
	waiters := make([]<-chan sealResult, 8)
	for i := range waiters {
		waiters[i] = sealAsync(s, ctx, []byte("waiter"))
	}
	waitersQueued()
	f.release()
	if r := waitResult(t, leader, "leader"); !errors.Is(r.err, errKeyManager) {
		t.Errorf("leader: %v, want the key manager error", r.err)
	}
	for i, ch := range waiters {
		if r := waitResult(t, ch, "waiter"); !errors.Is(r.err, errKeyManager) {
			t.Errorf("waiter %d: %v, want the error of the leader", i, r.err)
		}
	}
	if n := f.count(); n != 1 {
		t.Errorf("%d generations during the flight, want 1", n)
	}
	if _, err := s.Seal(ctx, []byte("after")); err != nil || f.count() != 2 {
		t.Errorf("Seal after the failure: %v with %d generations; want a new generation that succeeds", err, f.count())
	}
}

// TestSealSingleFlightPanic: a panic of the key manager panics the leader,
// releases the waiters with an error that does not quote the panic, and
// removes the flight: the next Seal succeeds.
func TestSealSingleFlightPanic(t *testing.T) {
	f := newFailing(true)
	t.Cleanup(f.release)
	s := newSealer(t, f, envelope.Options{})
	ctx := tenantCtx(t, demoTenant)
	leader := sealLeader(t, s, ctx, f)
	waiters := make([]<-chan sealResult, 4)
	for i := range waiters {
		waiters[i] = sealAsync(s, ctx, []byte("waiter"))
	}
	waitersQueued()
	f.release()
	if r := waitResult(t, leader, "leader"); r.err == nil || !strings.Contains(r.err.Error(), "leader panicked") {
		t.Errorf("leader: %v, want the panic propagated", r.err)
	}
	for i, ch := range waiters {
		r := waitResult(t, ch, "waiter")
		if r.err == nil || strings.Contains(r.err.Error(), "in the test") {
			t.Errorf("waiter %d: %v, want an error that does not quote the panic", i, r.err)
		}
	}
	if _, err := s.Seal(ctx, []byte("after")); err != nil {
		t.Errorf("Seal after the panic: %v", err)
	}
}

// TestSealSingleFlightWaiterCanceled: a waiter whose context ends returns its
// context error without waiting for the leader, which completes normally.
func TestSealSingleFlightWaiterCanceled(t *testing.T) {
	g := newGated(demoTenant)
	t.Cleanup(g.release)
	s := newSealer(t, g, envelope.Options{})
	ctx := tenantCtx(t, demoTenant)
	leader := sealAsync(s, ctx, []byte("leader"))
	waitEntered(t, g)
	wctx, cancel := context.WithCancel(ctx)
	waiter := sealAsync(s, wctx, []byte("waiter"))
	waitersQueued()
	cancel()
	if r := waitResult(t, waiter, "canceled waiter"); !errors.Is(r.err, context.Canceled) {
		t.Errorf("canceled waiter: %v, want context.Canceled", r.err)
	}
	g.release()
	if r := waitResult(t, leader, "leader"); r.err != nil {
		t.Errorf("leader: %v", r.err)
	}
	if n := g.generations(demoTenant); n != 1 {
		t.Errorf("%d generations, want 1", n)
	}
}
