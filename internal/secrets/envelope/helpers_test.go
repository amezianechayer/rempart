package envelope_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	"github.com/amezianechayer/rempart/internal/secrets/fake"
	"github.com/amezianechayer/rempart/internal/secrets/ports"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Tenants of these tests: the demo tenant of cmd/rempart-evals and cmd/rempart-worker,
// a second customer tenant, and the reserved System tenant (ADR 0004).
const (
	demoTenant  tenancy.ID = "0d3e0000-0000-4000-8000-000000000001"
	otherTenant tenancy.ID = "7b1c2d3e-4f50-4a6b-9c7d-8e9fa0b1c2d3"
)

// Offsets of format v1 (docs/plans/M1-envelope-transit.md section 6), written
// here from the plan, independently of the production code.
const (
	offVersion = 0
	offTenant  = 1
	offDEKID   = 37
	offLen     = 53
	offWrapped = 55
	nonceLen   = 12
	tagLen     = 16
)

// fakeSeed is the deterministic seed of the fake KeyWrapper of these tests.
var fakeSeed = [32]byte{0x52, 0x45, 0x4d, 0x50, 0x41, 0x52, 0x54, 0x2d, 0x54, 0x30, 0x31}

// spyKeyWrapper wraps a KeyWrapper: it counts calls (at entry, before any
// error), retains a copy of every plaintext DEK and wrapped DEK it hands out,
// and can inject a transient error on UnwrapDataKey.
type spyKeyWrapper struct {
	inner ports.KeyWrapper

	mu        sync.Mutex
	generate  int
	unwrap    int
	plains    [][]byte
	wrapped   [][]byte
	unwrapErr error
}

var _ ports.KeyWrapper = (*spyKeyWrapper)(nil)

func newSpy(t *testing.T) *spyKeyWrapper {
	t.Helper()
	return &spyKeyWrapper{inner: fake.NewKeyWrapper(fakeSeed)}
}

func (s *spyKeyWrapper) GenerateDataKey(ctx context.Context, tenant tenancy.ID) (secret.Bytes, []byte, error) {
	s.mu.Lock()
	s.generate++
	s.mu.Unlock()
	plain, wrapped, err := s.inner.GenerateDataKey(ctx, tenant)
	if err != nil {
		return plain, wrapped, err
	}
	s.mu.Lock()
	s.plains = append(s.plains, bytes.Clone(plain.Reveal()))
	s.wrapped = append(s.wrapped, bytes.Clone(wrapped))
	s.mu.Unlock()
	return plain, wrapped, nil
}

func (s *spyKeyWrapper) UnwrapDataKey(ctx context.Context, tenant tenancy.ID, wrapped []byte) (secret.Bytes, error) {
	s.mu.Lock()
	s.unwrap++
	injected := s.unwrapErr
	s.mu.Unlock()
	if injected != nil {
		return secret.Bytes{}, injected
	}
	return s.inner.UnwrapDataKey(ctx, tenant, wrapped)
}

func (s *spyKeyWrapper) calls() (generate, unwrap int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generate, s.unwrap
}

func (s *spyKeyWrapper) setUnwrapErr(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.unwrapErr = err
}

// lastDEK returns the last plaintext and wrapped DEK handed out.
func (s *spyKeyWrapper) lastDEK(t *testing.T) (plain, wrapped []byte) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.plains) == 0 {
		t.Fatal("the spy handed out no data key")
	}
	return s.plains[len(s.plains)-1], s.wrapped[len(s.wrapped)-1]
}

// fataler is the part of testing.TB that *rapid.T also provides.
type fataler interface {
	Helper()
	Fatal(args ...any)
	Fatalf(format string, args ...any)
}

// tenantCtx returns a context carrying id.
func tenantCtx(t fataler, id tenancy.ID) context.Context {
	t.Helper()
	ctx, err := tenancy.WithTenant(context.Background(), id)
	if err != nil {
		t.Fatalf("tenancy.WithTenant(%q): %v", id, err)
	}
	return ctx
}

// newSealer builds a Sealer over kw with options o, failing the test on error.
func newSealer(t fataler, kw ports.KeyWrapper, o envelope.Options) *envelope.Sealer {
	t.Helper()
	s, err := envelope.NewSealer(kw, o)
	if err != nil {
		t.Fatalf("envelope.NewSealer: %v", err)
	}
	if s == nil {
		t.Fatal("envelope.NewSealer returned a nil Sealer without error")
	}
	return s
}

func randomBytes(t fataler, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// wrappedLen reads the big-endian length of the wrapped DEK at offset 53.
func wrappedLen(t fataler, sealed []byte) int {
	t.Helper()
	if len(sealed) < offWrapped {
		t.Fatalf("sealed payload of %d bytes is shorter than the fixed header", len(sealed))
	}
	return int(sealed[offLen])<<8 | int(sealed[offLen+1])
}

// clock is an injectable clock for Options.Now.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func newClock() *clock {
	return &clock{now: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) set(start time.Time, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = start.Add(d)
}

func short(b []byte) string {
	if len(b) > 24 {
		return hex.EncodeToString(b[:24]) + "..."
	}
	return hex.EncodeToString(b)
}
