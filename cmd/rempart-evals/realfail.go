package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/amezianechayer/rempart/internal/llm"
	"github.com/amezianechayer/rempart/internal/llm/adapters/openaicompat"
	lldomain "github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/ports"
)

// Real mode (calibration of 2026-11-18): the failures of the provider are
// counted by class, an HTTP status or a fixed name, never a body nor the key,
// so that the human sees why a run failed; a calibration with any failed
// call writes no baseline.

type failureLog struct {
	mu     sync.Mutex
	counts map[string]int
}

func newFailureLog() *failureLog { return &failureLog{counts: map[string]int{}} }

func (l *failureLog) add(err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts[failureClass(err)]++
}

// summary is the sorted list "class ×n" and the total of failures.
func (l *failureLog) summary() (string, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	parts, total := []string{}, 0
	for class, n := range l.counts {
		parts = append(parts, class+" ×"+strconv.Itoa(n))
		total += n
	}
	slices.Sort(parts)
	return strings.Join(parts, ", "), total
}

// failureClass names the class of a failure of the adapter; the message of
// the error is never used (it could quote the provider).
func failureClass(err error) string {
	var api *openaicompat.APIError
	switch {
	case errors.As(err, &api):
		return fmt.Sprintf("HTTP %d", api.StatusCode)
	case errors.Is(err, openaicompat.ErrProviderMismatch):
		return "fournisseur final différent"
	case errors.Is(err, openaicompat.ErrRefusal):
		return "refus du modèle"
	case errors.Is(err, openaicompat.ErrMaxTokens):
		return "sortie tronquée"
	case errors.Is(err, openaicompat.ErrInvalidUsage):
		return "usage invalide"
	case errors.Is(err, openaicompat.ErrUnexpectedResponse):
		return "réponse inattendue"
	case errors.Is(err, openaicompat.ErrTimeout), errors.Is(err, context.DeadlineExceeded):
		return "délai dépassé"
	case errors.Is(err, openaicompat.ErrTransport):
		return "transport"
	case errors.Is(err, openaicompat.ErrWrongRoute):
		return "route refusée par l'adaptateur"
	case errors.Is(err, lldomain.ErrInvalidRequest):
		return "requête refusée avant envoi"
	case errors.Is(err, llm.ErrModelMismatch):
		return "modèle de la réponse différent"
	case errors.Is(err, llm.ErrProviderFailed):
		return "usage hors bornes"
	}
	return "autre"
}

// loggedProvider records the failures of inner, and the responses that
// llm.Client refuses before any use (llm.CheckResponse).
type loggedProvider struct {
	inner ports.ModelProvider
	log   *failureLog
}

func (p loggedProvider) Structured(ctx context.Context, route lldomain.Route, req lldomain.Request) (lldomain.Response, error) {
	r, err := p.inner.Structured(ctx, route, req)
	p.record(route, r, err)
	return r, err
}

func (p loggedProvider) WithTools(ctx context.Context, route lldomain.Route, req lldomain.Request, tools []lldomain.ToolSpec) (lldomain.Response, error) {
	r, err := p.inner.WithTools(ctx, route, req, tools)
	p.record(route, r, err)
	return r, err
}

func (p loggedProvider) record(route lldomain.Route, r lldomain.Response, err error) {
	if err == nil {
		err = llm.CheckResponse(route, r)
	}
	if err != nil {
		p.log.add(err)
	}
}

func (p loggedProvider) Capabilities(route lldomain.Route) lldomain.Capabilities {
	return p.inner.Capabilities(route)
}

// failuresOf returns the failure log shared by the real targets of ts, nil in
// fake mode.
func failuresOf(ts map[string]Target) *failureLog {
	for _, t := range ts {
		switch x := t.(type) {
		case demoTarget:
			if x.real != nil {
				return x.real.failures
			}
		case intentTarget:
			if x.real != nil {
				return x.real.failures
			}
		}
	}
	return nil
}
