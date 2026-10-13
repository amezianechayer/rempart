package envelope_test

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	"github.com/amezianechayer/rempart/internal/secrets/fake"
	"github.com/amezianechayer/rempart/internal/secrets/ports"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Obligation (ct) of docs/STATUS.md, plan docs/plans/M1-codec-replay.md D1:
// GenerateDataKey runs outside the global lock of the Sealer, once per tenant
// and per rotation.

// gatedKeyWrapper blocks GenerateDataKey of one tenant until release is
// called (or the caller's context ends); the other tenants and UnwrapDataKey
// go straight to the fake. It counts generations per tenant at entry.
type gatedKeyWrapper struct {
	inner ports.KeyWrapper
	slow  tenancy.ID

	entered     chan struct{} // closed when the first slow generation starts
	enteredOnce sync.Once
	gate        chan struct{}
	gateOnce    sync.Once

	mu       sync.Mutex
	generate map[tenancy.ID]int
}

var _ ports.KeyWrapper = (*gatedKeyWrapper)(nil)

func newGated(slow tenancy.ID) *gatedKeyWrapper {
	return &gatedKeyWrapper{
		inner: fake.NewKeyWrapper(fakeSeed), slow: slow,
		entered: make(chan struct{}), gate: make(chan struct{}), generate: map[tenancy.ID]int{},
	}
}

func (g *gatedKeyWrapper) release() { g.gateOnce.Do(func() { close(g.gate) }) }

func (g *gatedKeyWrapper) generations(tenant tenancy.ID) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.generate[tenant]
}

func (g *gatedKeyWrapper) GenerateDataKey(ctx context.Context, tenant tenancy.ID) (secret.Bytes, []byte, error) {
	g.mu.Lock()
	g.generate[tenant]++
	g.mu.Unlock()
	if tenant == g.slow {
		g.enteredOnce.Do(func() { close(g.entered) })
		select {
		case <-g.gate:
		case <-ctx.Done():
			return secret.Bytes{}, nil, ctx.Err()
		}
	}
	return g.inner.GenerateDataKey(ctx, tenant)
}

func (g *gatedKeyWrapper) UnwrapDataKey(ctx context.Context, tenant tenancy.ID, wrapped []byte) (secret.Bytes, error) {
	return g.inner.UnwrapDataKey(ctx, tenant, wrapped)
}

type sealResult struct {
	sealed []byte
	err    error
}

func sealAsync(s *envelope.Sealer, ctx context.Context, plain []byte) <-chan sealResult {
	out := make(chan sealResult, 1)
	go func() {
		sealed, err := s.Seal(ctx, plain)
		out <- sealResult{sealed, err}
	}()
	return out
}

// waitEntered waits for the slow tenant to be inside GenerateDataKey.
func waitEntered(t *testing.T, g *gatedKeyWrapper) {
	t.Helper()
	select {
	case <-g.entered:
	case <-time.After(5 * time.Second):
		g.release()
		t.Fatal("the slow tenant never reached GenerateDataKey")
	}
}

// openBack opens sealed with a fresh Sealer on the same key wrapper (real
// unwrap) and with s (cache), and compares with plain.
func openBack(t *testing.T, s *envelope.Sealer, kw ports.KeyWrapper, ctx context.Context, sealed, plain []byte) {
	t.Helper()
	for name, sl := range map[string]*envelope.Sealer{"same": s, "fresh": newSealer(t, kw, envelope.Options{})} {
		got, err := sl.Open(ctx, sealed)
		if err != nil || !bytes.Equal(got, plain) {
			t.Errorf("Open (%s sealer) = %q, %v; want %q", name, got, err, plain)
		}
	}
}

// TestSealSlowTenantDoesNotBlockOthers (T94, D1): while the key manager hangs
// for tenant A, a Seal of tenant B returns within 2 s; once A is released,
// both sealed payloads open.
func TestSealSlowTenantDoesNotBlockOthers(t *testing.T) {
	g := newGated(demoTenant)
	t.Cleanup(g.release)
	s := newSealer(t, g, envelope.Options{})
	ctxA, ctxB := tenantCtx(t, demoTenant), tenantCtx(t, otherTenant)
	plainA, plainB := []byte("payload of tenant A"), []byte("payload of tenant B")

	resA := sealAsync(s, ctxA, plainA)
	waitEntered(t, g)
	resB := sealAsync(s, ctxB, plainB)

	var b sealResult
	select {
	case b = <-resB:
	case <-time.After(2 * time.Second):
		g.release()
		<-resA
		t.Fatal("Seal of tenant B blocked for 2 s while GenerateDataKey of tenant A hung (global lock held)")
	}
	if b.err != nil {
		t.Fatalf("Seal of tenant B: %v", b.err)
	}
	select {
	case a := <-resA:
		t.Fatalf("Seal of tenant A returned (%v) before its key manager answered", a.err)
	default:
	}
	g.release()
	var a sealResult
	select {
	case a = <-resA:
	case <-time.After(5 * time.Second):
		t.Fatal("Seal of tenant A did not return after the release")
	}
	if a.err != nil {
		t.Fatalf("Seal of tenant A: %v", a.err)
	}
	openBack(t, s, g, ctxA, a.sealed, plainA)
	openBack(t, s, g, ctxB, b.sealed, plainB)
	if n := g.generations(otherTenant); n != 1 {
		t.Errorf("%d generations for tenant B, want 1", n)
	}
}

// TestSealSingleFlightPerTenant (D1): 32 concurrent Seal of tenant A while its
// key manager hangs make exactly one GenerateDataKey call; the 32 payloads
// carry the same DEK id and open.
func TestSealSingleFlightPerTenant(t *testing.T) {
	const n = 32
	g := newGated(demoTenant)
	t.Cleanup(g.release)
	s := newSealer(t, g, envelope.Options{})
	ctx := tenantCtx(t, demoTenant)

	results := make([]<-chan sealResult, n)
	plains := make([][]byte, n)
	plains[0] = []byte("payload 0")
	results[0] = sealAsync(s, ctx, plains[0])
	waitEntered(t, g)
	for i := 1; i < n; i++ {
		plains[i] = fmt.Appendf(nil, "payload %d", i)
		results[i] = sealAsync(s, ctx, plains[i])
	}
	// Give every caller the time to reach the key manager if it would.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && g.generations(demoTenant) < n {
		time.Sleep(10 * time.Millisecond)
	}
	g.release()

	var id [16]byte
	for i, ch := range results {
		var r sealResult
		select {
		case r = <-ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("Seal %d did not return after the release", i)
		}
		if r.err != nil {
			t.Fatalf("Seal %d: %v", i, r.err)
		}
		h, err := envelope.ParseHeader(r.sealed)
		if err != nil {
			t.Fatalf("ParseHeader(seal %d): %v", i, err)
		}
		if i == 0 {
			id = h.DEKID
		} else if h.DEKID != id {
			t.Errorf("seal %d carries DEK %x, want %x (one DEK for the flight)", i, h.DEKID, id)
		}
		openBack(t, s, g, ctx, r.sealed, plains[i])
	}
	if got := g.generations(demoTenant); got != 1 {
		t.Errorf("%d GenerateDataKey calls for %d concurrent Seal, want exactly 1", got, n)
	}
}
