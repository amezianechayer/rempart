// Package calibration builds the only client that may run a real route
// absent from the registry of validated routes: the human calibration of
// rempart-evals (ADR 0006, D10). Importable by cmd/rempart-evals only
// (archtest rule llm-calibration-evals-cli-only).
package calibration

import (
	"errors"
	"fmt"
	"io/fs"
	"slices"

	"github.com/amezianechayer/rempart/internal/llm"
	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/ports"
)

// ErrRouteRefused: the route to calibrate is fake, malformed or not wired.
var ErrRouteRefused = errors.New("calibration: route refused")

// NewClient returns a client whose registry admits, in addition to
// cfg.ValidatedPairs, exactly the route r. The route must pass the shape
// checks of domain.CheckPolicy; r.Platform is never fake.
func NewClient(p ports.ModelProvider, rr ports.RouteResolver, promptFS fs.FS, cfg llm.Config, r domain.Route) (*llm.Client, error) {
	if r.Platform == domain.PlatformFake || r.Model == "" {
		return nil, ErrRouteRefused
	}
	shape := domain.TenantPolicy{Route: r, Residency: domain.ResidencyNone, Retention: domain.RetentionStandard}
	if err := domain.CheckPolicy(shape, domain.Capabilities{}); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRouteRefused, err)
	}
	cfg.ValidatedPairs = append(slices.Clone(cfg.ValidatedPairs), llm.Pair{Platform: r.Platform, Model: r.Model})
	return llm.NewClient(p, rr, promptFS, cfg)
}
