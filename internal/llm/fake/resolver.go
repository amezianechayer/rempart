package fake

import (
	"context"
	"fmt"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/ports"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

var _ ports.RouteResolver = (*StaticResolver)(nil)

// StaticResolver has no default route; the caller runs CheckPolicy on the result.
type StaticResolver struct {
	policies map[tenancy.ID]domain.TenantPolicy
}

func NewStaticResolver(policies map[tenancy.ID]domain.TenantPolicy) (*StaticResolver, error) {
	cp := make(map[tenancy.ID]domain.TenantPolicy, len(policies))
	for id, pol := range policies {
		if _, err := tenancy.ParseID(string(id)); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidOptions, err)
		}
		cp[id] = pol
	}
	return &StaticResolver{policies: cp}, nil
}

func (r *StaticResolver) Resolve(ctx context.Context, tenant tenancy.ID) (domain.TenantPolicy, error) {
	if err := ctx.Err(); err != nil {
		return domain.TenantPolicy{}, err
	}
	if _, err := tenancy.ParseID(string(tenant)); err != nil {
		return domain.TenantPolicy{}, fmt.Errorf("%w: %w", domain.ErrNoRoute, err)
	}
	if r == nil {
		return domain.TenantPolicy{}, domain.ErrNoRoute
	}
	pol, ok := r.policies[tenant]
	if !ok {
		return domain.TenantPolicy{}, fmt.Errorf("%w: tenant not configured", domain.ErrNoRoute)
	}
	return pol, nil
}
