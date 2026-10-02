// Package fake holds a deterministic KeyWrapper for tests and the demo target.
package fake

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/amezianechayer/rempart/internal/secrets/ports"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

var errFake = errors.New("fake keywrapper: internal error")

// KeyWrapper wraps DEKs with a per-tenant KEK derived from a seed.
type KeyWrapper struct {
	seed [32]byte

	mu               sync.Mutex
	generate, unwrap int
}

var _ ports.KeyWrapper = (*KeyWrapper)(nil)

// NewKeyWrapper returns a KeyWrapper whose KEK per tenant is
// HMAC-SHA256(seed, "rempart-fake-kek/" + tenant).
func NewKeyWrapper(seed [32]byte) *KeyWrapper { return &KeyWrapper{seed: seed} }

func (k *KeyWrapper) aead(tenant tenancy.ID) (cipher.AEAD, error) {
	m := hmac.New(sha256.New, k.seed[:])
	m.Write([]byte("rempart-fake-kek/" + string(tenant)))
	kek := m.Sum(nil)
	defer clear(kek)
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, errFake
	}
	return cipher.NewGCM(block)
}

// GenerateDataKey returns a random DEK and its wrapping under the tenant KEK.
func (k *KeyWrapper) GenerateDataKey(_ context.Context, tenant tenancy.ID) (secret.Bytes, []byte, error) {
	k.mu.Lock()
	k.generate++
	k.mu.Unlock()
	if _, err := tenancy.ParseID(string(tenant)); err != nil {
		return secret.Bytes{}, nil, err
	}
	a, err := k.aead(tenant)
	if err != nil {
		return secret.Bytes{}, nil, err
	}
	dek := make([]byte, 32)
	defer clear(dek)
	_, _ = rand.Read(dek)
	nonce := make([]byte, a.NonceSize())
	_, _ = rand.Read(nonce)
	wrapped := a.Seal(nonce, nonce, dek, []byte(tenant))
	return secret.NewBytes(dek), wrapped, nil
}

// UnwrapDataKey unwraps a DEK; any refusal is ports.ErrWrappedKeyRejected.
func (k *KeyWrapper) UnwrapDataKey(_ context.Context, tenant tenancy.ID, wrapped []byte) (secret.Bytes, error) {
	k.mu.Lock()
	k.unwrap++
	k.mu.Unlock()
	if _, err := tenancy.ParseID(string(tenant)); err != nil {
		return secret.Bytes{}, err
	}
	a, err := k.aead(tenant)
	if err != nil {
		return secret.Bytes{}, err
	}
	ns := a.NonceSize()
	if len(wrapped) < ns+a.Overhead() {
		return secret.Bytes{}, ports.ErrWrappedKeyRejected
	}
	dek, err := a.Open(nil, wrapped[:ns], wrapped[ns:], []byte(tenant))
	if err != nil || len(dek) != 32 {
		return secret.Bytes{}, ports.ErrWrappedKeyRejected
	}
	defer clear(dek)
	return secret.NewBytes(dek), nil
}

// Calls returns the number of calls, for tests.
func (k *KeyWrapper) Calls() (generate, unwrap int) {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.generate, k.unwrap
}
