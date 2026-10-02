// Package ports holds the interfaces of the secrets domain.
package ports

import (
	"context"
	"errors"

	"github.com/amezianechayer/rempart/internal/secrets/secret"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// ErrWrappedKeyRejected: the key manager refuses the wrapped data key (key of
// another tenant, altered bytes). Permanent: never retried. Any other error is
// deemed transient.
var ErrWrappedKeyRejected = errors.New("secrets: wrapped data key rejected")

// KeyWrapper wraps data encryption keys with a key of the tenant. Contract:
// plain is 32 bytes; wrapped is 1 to 1024 opaque bytes; the implementation
// checks tenant again (tenancy.ParseID) before any I/O (T35); it never logs;
// its errors carry no content.
type KeyWrapper interface {
	GenerateDataKey(ctx context.Context, tenant tenancy.ID) (plain secret.Bytes, wrapped []byte, err error)
	UnwrapDataKey(ctx context.Context, tenant tenancy.ID, wrapped []byte) (secret.Bytes, error)
}
