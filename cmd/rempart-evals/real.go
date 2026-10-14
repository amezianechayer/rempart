package main

import (
	"errors"
	"os"
	"time"

	"github.com/amezianechayer/rempart/internal/llm"
	"github.com/amezianechayer/rempart/internal/llm/adapters/openaicompat"
	"github.com/amezianechayer/rempart/internal/llm/apikey"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/loops/demo/activities"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Real mode (ADR 0008, M1-T09): the targets call a real model through
// OpenRouter, for synthetic evals only (residency none, standard retention).
// Run from the terminal of the human: the cloud environment cannot reach
// OpenRouter without a TLS-intercepting proxy, refused by design (D6).

const realTimeout = 90 * time.Second

var errRealKey = errors.New("clé " + apikey.EnvOpenRouter + " absente ou mal formée dans l'environnement")

// realModel is the route of the real mode and its provider.
type realModel struct {
	model    string
	provider *openaicompat.Provider
}

func listed(model string) bool {
	_, ok := lldomain.OpenRouterProvider(model)
	return ok
}

// realTargets returns the targets of the real mode: the demo target on the
// OpenRouter route of model, with the key of environ.
func realTargets(environ []string, platform, model string) (map[string]Target, error) {
	if platform != string(lldomain.PlatformOpenRouter) || !listed(model) {
		return nil, errors.New("plateforme ou modèle hors de la liste fermée (ADR 0008)")
	}
	key, err := apikey.FromEnviron(environ, apikey.EnvOpenRouter)
	if err != nil {
		return nil, errRealKey
	}
	prov, err := openaicompat.New(lldomain.PlatformOpenRouter, openaicompat.Config{APIKey: key, Timeout: realTimeout})
	if err != nil {
		return nil, errRealKey
	}
	return map[string]Target{"demo": demoTarget{log: os.Stderr, real: &realModel{model: model, provider: prov}}}, nil
}

// client returns the LLM client of the real mode: the demo tenant on the
// OpenRouter route, residency none (ADR 0008 D2).
func (r *realModel) client() (*llm.Client, error) {
	res, err := llmfake.NewStaticResolver(map[tenancy.ID]lldomain.TenantPolicy{demoTenant: {
		Route:     lldomain.Route{Platform: lldomain.PlatformOpenRouter, Model: r.model},
		Residency: lldomain.ResidencyNone, Retention: lldomain.RetentionStandard,
	}})
	if err != nil {
		return nil, err
	}
	return llm.NewClient(r.provider, res, nil, llm.Config{MaxTokensPerCall: activities.MaxTokensPerCall})
}
