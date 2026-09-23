package tenancy

import (
	"context"
	"errors"
	"fmt"
)

// ID identifies a tenant: a canonical UUID of 36 lower-case characters
// (ADR 0004). The zero value is invalid. Build it with ParseID, never by
// converting an unchecked string: WithTenant, FromContext and Require check it
// again.
type ID string

// System is the reserved tenant of system workflows (ADR 0001). It is an
// RFC 9562 version 8 UUID, never assigned to a customer: customer tenants are
// version 4 UUIDs (ADR 0004).
const System ID = "00000000-0000-8000-8000-000000000001"

var (
	// ErrNoTenant: the context carries no tenant.
	ErrNoTenant = errors.New("tenancy: no tenant in context")
	// ErrInvalidTenant: the identifier is not in the canonical form of ADR 0004.
	ErrInvalidTenant = errors.New("tenancy: invalid tenant id")
	// ErrTenantMismatch: the context carries another tenant.
	ErrTenantMismatch = errors.New("tenancy: tenant mismatch")
	// ErrNilContext: a nil context was passed.
	ErrNilContext = errors.New("tenancy: nil context")
)

const (
	idLen   = 36
	nilUUID = "00000000-0000-0000-0000-000000000000"
	maxUUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
)

// ctxKey is the unexported context key: no other package can read or write the
// tenant except through WithTenant and FromContext.
type ctxKey struct{}

// ParseID accepts only the canonical form of ADR 0004 and never normalizes its
// input. The error wraps ErrInvalidTenant with a fixed reason and never quotes s.
func ParseID(s string) (ID, error) {
	if reason := invalidReason(s); reason != "" {
		return "", fmt.Errorf("%w: %s", ErrInvalidTenant, reason)
	}
	return ID(s), nil
}

// String returns the identifier unchanged.
func (id ID) String() string { return string(id) }

func (id ID) valid() bool { return invalidReason(string(id)) == "" }

// invalidReason returns "" for a valid identifier, otherwise a fixed reason.
func invalidReason(s string) string {
	if len(s) != idLen {
		return "length is not 36 bytes"
	}
	for i := range idLen {
		switch c := s[i]; i {
		case 8, 13, 18, 23:
			if c != '-' {
				return "hyphen expected at positions 8, 13, 18 and 23"
			}
		default:
			if !isLowerHex(c) {
				return "not a lower-case hexadecimal digit"
			}
		}
	}
	if s == nilUUID {
		return "nil UUID"
	}
	if s == maxUUID {
		return "max UUID"
	}
	if ID(s) == System {
		return ""
	}
	switch s[14] {
	case '4':
	default:
		return "version is not 4"
	}
	switch s[19] {
	case '8', '9', 'a', 'b':
	default:
		return "variant is not RFC 9562"
	}
	return ""
}

func isLowerHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f'
}

// WithTenant returns a child of ctx carrying id. If ctx already carries id, ctx
// itself is returned. A different tenant is never replaced (ErrTenantMismatch):
// acting for another tenant needs a context built from a tenant-free parent.
// On error the returned context is nil.
func WithTenant(ctx context.Context, id ID) (context.Context, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if !id.valid() {
		return nil, ErrInvalidTenant
	}
	cur, err := FromContext(ctx)
	switch {
	case err == nil && cur == id:
		return ctx, nil
	case err == nil:
		return nil, ErrTenantMismatch
	case errors.Is(err, ErrNoTenant):
		return context.WithValue(ctx, ctxKey{}, id), nil
	default:
		return nil, err
	}
}

// FromContext returns the tenant carried by ctx: ErrNoTenant if there is none,
// ErrInvalidTenant if the stored value is not a valid ID.
func FromContext(ctx context.Context) (ID, error) {
	if ctx == nil {
		return "", fmt.Errorf("%w: %w", ErrNoTenant, ErrNilContext)
	}
	v := ctx.Value(ctxKey{})
	if v == nil {
		return "", ErrNoTenant
	}
	id, ok := v.(ID)
	if !ok || !id.valid() {
		return "", ErrInvalidTenant
	}
	return id, nil
}

// Require checks, at a boundary, that ctx carries exactly want. An invalid want
// (including "") is always ErrInvalidTenant, whatever ctx holds.
func Require(ctx context.Context, want ID) error {
	if !want.valid() {
		return ErrInvalidTenant
	}
	got, err := FromContext(ctx)
	if err != nil {
		return err
	}
	if got != want {
		return ErrTenantMismatch
	}
	return nil
}
