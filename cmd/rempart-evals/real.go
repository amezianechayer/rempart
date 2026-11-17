package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	registry "github.com/amezianechayer/rempart/evals"
	"github.com/amezianechayer/rempart/internal/llm"
	"github.com/amezianechayer/rempart/internal/llm/adapters/openaicompat"
	"github.com/amezianechayer/rempart/internal/llm/apikey"
	"github.com/amezianechayer/rempart/internal/llm/calibration"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	llmfake "github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Real mode (ADR 0008, M1-T09): the targets call a real model through
// OpenRouter, for synthetic evals only (residency none, standard retention).
// Run from the terminal of the human: the cloud environment cannot reach
// OpenRouter without a TLS-intercepting proxy, refused by design (D6).

const realTimeout = 90 * time.Second

var errRealKey = errors.New("clé " + apikey.EnvOpenRouter + " absente ou mal formée dans l'environnement")

// realModel is the route of the real mode and its provider. Without
// calibrate, the route must be in the registry of suite (D8); with calibrate
// (the human writes the reference report of suite), the calibration client
// admits exactly this route in addition (D10).
type realModel struct {
	model     string
	provider  *openaicompat.Provider
	suite     string
	calibrate bool
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
	rm := &realModel{model: model, provider: prov}
	return map[string]Target{"demo": demoTarget{log: os.Stderr, real: rm}, "intent": intentTarget{log: os.Stderr, real: rm}}, nil
}

// client returns the LLM client of the real mode: the demo tenant on the
// OpenRouter route, residency none (ADR 0008 D2).
func (r *realModel) client(maxTokens int) (*llm.Client, error) {
	res, err := llmfake.NewStaticResolver(map[tenancy.ID]lldomain.TenantPolicy{demoTenant: {
		Route:     lldomain.Route{Platform: lldomain.PlatformOpenRouter, Model: r.model},
		Residency: lldomain.ResidencyNone, Retention: lldomain.RetentionStandard,
	}})
	if err != nil {
		return nil, err
	}
	cfg := llm.Config{MaxTokensPerCall: maxTokens}
	if cfg.ValidatedPairs, err = registry.RealPairs(r.suite); err != nil {
		return nil, err
	}
	if r.calibrate {
		return calibration.NewClient(r.provider, res, nil, cfg, lldomain.Route{Platform: lldomain.PlatformOpenRouter, Model: r.model})
	}
	return llm.NewClient(r.provider, res, nil, cfg)
}

// bindReal sets the suite and the calibration of the real targets of ts.
func bindReal(ts map[string]Target, suite string, calibrate bool) {
	for _, t := range ts {
		var rm *realModel
		switch x := t.(type) {
		case demoTarget:
			rm = x.real
		case intentTarget:
			rm = x.real
		}
		if rm != nil {
			rm.suite, rm.calibrate = suite, calibrate
		}
	}
}

// ttyConfirm asks on the terminal of the human, never on standard input
// (piped by a script) nor in an environment variable (D10, obligation (ed)).
func ttyConfirm(prompt string) bool {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false
	}
	defer func() { _ = tty.Close() }()
	if _, err := io.WriteString(tty, prompt); err != nil {
		return false
	}
	line, err := bufio.NewReader(io.LimitReader(tty, 64)).ReadString('\n')
	return err == nil && strings.TrimSpace(line) == "oui"
}
