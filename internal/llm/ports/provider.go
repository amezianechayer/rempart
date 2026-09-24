// Package ports declares the model provider and route resolver interfaces (ADR 0002).
package ports

import (
	"context"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// ModelProvider is implemented by the fake and by each platform adapter. Every
// implementation builds its endpoint from route.Region only (no default region,
// no environment lookup), refuses a route of another platform, renders untrusted
// parts only with domain.RenderUntrusted, takes Response.Model from the platform
// response (never from the route) and returns Output raw.
type ModelProvider interface {
	// Structured exposes no tool. It is the only call allowed to carry an UntrustedBlock.
	Structured(ctx context.Context, route domain.Route, req domain.Request) (domain.Response, error)
	// WithTools returns domain.ErrUntrustedWithTools before any I/O when
	// req.HasUntrusted() is true, even with an empty tools slice.
	WithTools(ctx context.Context, route domain.Route, req domain.Request, tools []domain.ToolSpec) (domain.Response, error)
	// Capabilities is pure and static. Unknown route: RequiresRetention is true.
	Capabilities(route domain.Route) domain.Capabilities
}

// RouteResolver returns the explicit policy of a tenant. No default route: a
// tenant without one gets an error matching domain.ErrNoRoute, never a zero
// policy with a nil error. The caller runs domain.CheckPolicy on every call.
type RouteResolver interface {
	Resolve(ctx context.Context, tenant tenancy.ID) (domain.TenantPolicy, error)
}
