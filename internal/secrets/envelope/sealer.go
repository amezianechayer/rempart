// Package envelope seals tenant data with AES-256-GCM under a per-tenant DEK
// wrapped by a KeyWrapper (ADR 0001, docs/plans/M1-envelope-transit.md).
package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/amezianechayer/rempart/internal/secrets/ports"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const (
	MaxPlaintext             = 256 << 10 // ADR 0001
	FormatV1            byte = 1
	DefaultDEKMaxAge         = 15 * time.Minute
	DefaultDEKMaxUses        = 1 << 20
	DefaultCacheEntries      = 1024
	maxCacheEntries          = 65536
)

var (
	ErrNoTenant        = errors.New("envelope: no tenant in context")
	ErrTenantMismatch  = errors.New("envelope: tenant mismatch")
	ErrPayloadTooLarge = errors.New("envelope: payload too large")
	ErrCorrupt         = errors.New("envelope: corrupt or unauthenticated payload")
	ErrInvalidOptions  = errors.New("envelope: invalid options")
)

// Options bound the DEK lifetime and the open cache. Zero values take defaults.
type Options struct {
	DEKMaxAge    time.Duration
	DEKMaxUses   uint64
	CacheEntries int
	Now          func() time.Time
}

type currentDEK struct {
	id      [16]byte
	wrapped []byte
	aead    cipher.AEAD
	created time.Time
	uses    uint64
}

// Sealer seals and opens tenant payloads. Safe for concurrent use.
type Sealer struct {
	kw      ports.KeyWrapper
	maxAge  time.Duration
	maxUses uint64
	now     func() time.Time

	mu      sync.Mutex
	current map[tenancy.ID]*currentDEK
	cache   *aeadCache
}

// NewSealer returns a Sealer: ErrInvalidOptions if kw is nil or o is out of bounds.
func NewSealer(kw ports.KeyWrapper, o Options) (*Sealer, error) {
	if kw == nil || o.DEKMaxAge < 0 || o.DEKMaxAge > DefaultDEKMaxAge || o.DEKMaxUses > DefaultDEKMaxUses ||
		o.CacheEntries < 0 || o.CacheEntries > maxCacheEntries {
		return nil, ErrInvalidOptions
	}
	s := &Sealer{kw: kw, maxAge: o.DEKMaxAge, maxUses: o.DEKMaxUses, now: o.Now, current: map[tenancy.ID]*currentDEK{}}
	if s.maxAge == 0 {
		s.maxAge = DefaultDEKMaxAge
	}
	if s.maxUses == 0 {
		s.maxUses = DefaultDEKMaxUses
	}
	if s.now == nil {
		s.now = time.Now
	}
	entries := o.CacheEntries
	if entries == 0 {
		entries = DefaultCacheEntries
	}
	s.cache = newAEADCache(entries, s.maxAge, s.maxUses)
	return s, nil
}

func newAEAD(dek secret.Bytes) (cipher.AEAD, error) {
	defer dek.Wipe()
	if dek.Len() != 32 {
		return nil, ErrCorrupt
	}
	block, err := aes.NewCipher(dek.Reveal())
	if err != nil {
		return nil, ErrCorrupt
	}
	return cipher.NewGCM(block)
}

func (s *Sealer) newDEK(ctx context.Context, tenant tenancy.ID, now time.Time) (*currentDEK, error) {
	plain, wrapped, err := s.kw.GenerateDataKey(ctx, tenant)
	if err != nil {
		plain.Wipe()
		return nil, fmt.Errorf("envelope: generate data key: %w", err)
	}
	if len(wrapped) < 1 || len(wrapped) > maxWrapped {
		plain.Wipe()
		return nil, errors.New("envelope: generate data key: wrapped key out of bounds")
	}
	a, err := newAEAD(plain)
	if err != nil {
		return nil, errors.New("envelope: generate data key: invalid data key")
	}
	d := &currentDEK{wrapped: append([]byte(nil), wrapped...), aead: a, created: now}
	_, _ = rand.Read(d.id[:])
	return d, nil
}

// Seal encrypts plaintext for the tenant of ctx.
func (s *Sealer) Seal(ctx context.Context, plaintext []byte) ([]byte, error) {
	tenant, err := tenancy.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoTenant, err)
	}
	if len(plaintext) > MaxPlaintext {
		return nil, ErrPayloadTooLarge
	}
	s.mu.Lock()
	now := s.now()
	d := s.current[tenant]
	if d == nil || now.Sub(d.created) >= s.maxAge || d.uses >= s.maxUses {
		if d, err = s.newDEK(ctx, tenant, now); err != nil {
			s.mu.Unlock()
			return nil, err
		}
		s.current[tenant] = d
		s.cache.put(cacheKey{tenant, d.id}, d.aead, now, 0)
	}
	d.uses++
	hdr := buildHeader(tenant, d.id, d.wrapped)
	a := d.aead
	s.mu.Unlock()

	out := make([]byte, len(hdr)+nonceSize, len(hdr)+nonceSize+len(plaintext)+tagSize)
	copy(out, hdr)
	nonce := out[len(hdr):]
	_, _ = rand.Read(nonce)
	return a.Seal(out, nonce, plaintext, hdr), nil
}

// Open decrypts a payload sealed for the tenant of ctx.
func (s *Sealer) Open(ctx context.Context, sealed []byte) ([]byte, error) {
	h, hlen, err := parseHeader(sealed)
	if err != nil {
		return nil, err
	}
	tenant, err := tenancy.FromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNoTenant, err)
	}
	if h.Tenant != tenant {
		return nil, ErrTenantMismatch
	}
	if len(sealed) < hlen+nonceSize+tagSize {
		return nil, ErrCorrupt
	}
	aad, nonce, ct := sealed[:hlen], sealed[hlen:hlen+nonceSize], sealed[hlen+nonceSize:]
	key := cacheKey{tenant, h.DEKID}

	s.mu.Lock()
	a := s.cache.get(key, s.now())
	s.mu.Unlock()
	fresh := a == nil
	if fresh {
		dek, err := s.kw.UnwrapDataKey(ctx, tenant, h.Wrapped)
		switch {
		case errors.Is(err, ports.ErrWrappedKeyRejected):
			return nil, ErrCorrupt
		case err != nil:
			return nil, fmt.Errorf("envelope: unwrap data key: %w", err)
		}
		if a, err = newAEAD(dek); err != nil {
			return nil, ErrCorrupt
		}
	}
	plain, err := a.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrCorrupt
	}
	if fresh {
		s.mu.Lock()
		s.cache.put(key, a, s.now(), 1)
		s.mu.Unlock()
	}
	if plain == nil {
		plain = []byte{}
	}
	return plain, nil
}
