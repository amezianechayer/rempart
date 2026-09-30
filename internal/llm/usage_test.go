package llm

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/llm/schema"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// M0-T20, plan docs/plans/M0-worker-demo.md D10, obligation (av), threat T10:
// every failure after a provider call carries the declared usage and a bound
// on what the calls may have consumed, so that a loop budget counts it.

// wantRequestBytes is written independently of RequestBytes: the text a
// provider reads, system prompt, schema, text parts and rendered untrusted
// blocks.
func wantRequestBytes(req domain.Request) int {
	n := len(req.System) + len(req.Schema)
	for _, m := range req.Messages {
		for _, p := range m.Parts {
			switch {
			case p.Untrusted != nil:
				n += len(domain.RenderUntrusted(*p.Untrusted))
			default:
				n += len(p.Text)
			}
		}
	}
	return n
}

// usageErr returns the *UsageError of err; its message and chain are those of
// the wrapped error.
func usageErr(t *testing.T, err error, wants ...error) *UsageError {
	t.Helper()
	var ue *UsageError
	if !errors.As(err, &ue) || ue == nil {
		t.Fatalf("error %v (%T) holds no *UsageError", err, err)
	}
	if ue.Err == nil {
		t.Fatal("UsageError.Err is nil")
	}
	if err.Error() != ue.Err.Error() || ue.Error() != ue.Err.Error() {
		t.Errorf("message %q, want the wrapped message %q", err.Error(), ue.Err.Error())
	}
	if !errors.Is(errors.Unwrap(ue), ue.Err) {
		t.Errorf("Unwrap does not return the wrapped error")
	}
	for _, w := range wants {
		if !errors.Is(err, w) {
			t.Errorf("error %q does not match %q", err, w)
		}
	}
	return ue
}

func usageStep(output, model string, in, out int) fake.Step {
	s := step(output, model)
	s.Response.Usage = domain.Usage{InputTokens: in, OutputTokens: out}
	return s
}

func TestUsageErrorBound(t *testing.T) {
	outOfSchema := `{"greeting":1}`
	oneCorrection := Config{MaxCorrections: 1, MaxTokensPerCall: 256, AllowFakeRoute: true}

	t.Run("request_bytes", func(t *testing.T) {
		req := domain.Request{
			PromptID: greetingID, PromptHash: "h", System: "sys", Schema: json.RawMessage(greetingSchema), MaxTokens: 99,
			Messages: []domain.Message{
				userText("hello"),
				{Role: domain.RoleUser, Parts: []domain.Part{{Untrusted: &domain.UntrustedBlock{SourceID: "s1", Content: "bonjour"}}}},
				{Role: domain.RoleAssistant, Parts: []domain.Part{{Text: "é"}}},
			},
		}
		want := 3 + len(greetingSchema) + 5 + len(domain.RenderUntrusted(domain.UntrustedBlock{SourceID: "s1", Content: "bonjour"})) + 2
		if got := RequestBytes(req); got != want || got != wantRequestBytes(req) {
			t.Errorf("RequestBytes = %d, want %d", got, want)
		}
		if got := RequestBytes(domain.Request{}); got != 0 {
			t.Errorf("RequestBytes(empty) = %d, want 0", got)
		}
	})

	t.Run("provider_failure_first_call", func(t *testing.T) {
		for _, m := range bothMethods() {
			t.Run(m.name, func(t *testing.T) {
				e := newEnv(t, configK(), policyPA(), fake.Step{Err: "provider_unavailable"})
				o := m.run(e.c, ctxFor(t, tenantA), call0(t))
				assertFailed(t, o, ErrProviderFailed)
				ue := usageErr(t, o.err, ErrProviderFailed)
				reqs := e.fake.Requests()
				if len(reqs) != 1 {
					t.Fatalf("%d provider requests, want 1", len(reqs))
				}
				if want := 256 + wantRequestBytes(reqs[0]); ue.Bound != want {
					t.Errorf("Bound = %d, want MaxTokens 256 + request bytes = %d", ue.Bound, want)
				}
				if ue.Usage != (domain.Usage{}) {
					t.Errorf("Usage = %+v, want zero (nothing declared)", ue.Usage)
				}
			})
		}
	})

	t.Run("out_of_schema_after_correction", func(t *testing.T) {
		e := newEnv(t, oneCorrection, policyPA(), usageStep(outOfSchema, modelV1, 10, 5), usageStep(outOfSchema, modelV1, 10, 5))
		o := structuredM().run(e.c, ctxFor(t, tenantA), call0(t))
		assertFailed(t, o, schema.ErrOutOfSchema)
		ue := usageErr(t, o.err, schema.ErrOutOfSchema)
		if n := e.fake.Invocations(); n != 2 {
			t.Fatalf("%d provider calls, want 2", n)
		}
		if ue.Usage != (domain.Usage{InputTokens: 20, OutputTokens: 10}) || ue.Bound != 30 {
			t.Errorf("Usage %+v, Bound %d; want {20 10}, 30", ue.Usage, ue.Bound)
		}
	})

	t.Run("failure_after_correction", func(t *testing.T) {
		// Declared usage of the first call, then MaxTokens and the request
		// bytes of the failed second call.
		e := newEnv(t, oneCorrection, policyPA(), usageStep(outOfSchema, modelV1, 10, 5), fake.Step{Err: "provider_unavailable"})
		o := structuredM().run(e.c, ctxFor(t, tenantA), call0(t))
		ue := usageErr(t, o.err, ErrProviderFailed)
		reqs := e.fake.Requests()
		if len(reqs) != 2 {
			t.Fatalf("%d provider requests, want 2", len(reqs))
		}
		if want := 15 + 256 + wantRequestBytes(reqs[1]); ue.Bound != want || ue.Usage != (domain.Usage{InputTokens: 10, OutputTokens: 5}) {
			t.Errorf("Usage %+v, Bound %d; want {10 5}, %d", ue.Usage, ue.Bound, want)
		}
	})

	t.Run("model_mismatch", func(t *testing.T) {
		e := newEnv(t, configK(), policyPA(), usageStep(string(valueV), "fake-model-other", 12, 5))
		o := structuredM().run(e.c, ctxFor(t, tenantA), call0(t))
		assertFailed(t, o, ErrModelMismatch)
		ue := usageErr(t, o.err, ErrModelMismatch)
		if ue.Usage != (domain.Usage{InputTokens: 12, OutputTokens: 5}) || ue.Bound != 17 {
			t.Errorf("Usage %+v, Bound %d; want {12 5}, 17", ue.Usage, ue.Bound)
		}
	})

	t.Run("unknown_tool", func(t *testing.T) {
		s := usageStep(string(valueV), modelV1, 7, 3)
		s.Response.ToolCalls = []domain.ToolCall{{Name: "nope", Input: json.RawMessage(`{"name":"x"}`)}}
		e := newEnv(t, configK(), policyPA(), s)
		o := withToolsM([]domain.ToolSpec{toolT()}).run(e.c, ctxFor(t, tenantA), call0(t))
		assertFailed(t, o, ErrUnknownTool)
		ue := usageErr(t, o.err, ErrUnknownTool)
		if ue.Usage != (domain.Usage{InputTokens: 7, OutputTokens: 3}) || ue.Bound != 10 {
			t.Errorf("Usage %+v, Bound %d; want {7 3}, 10", ue.Usage, ue.Bound)
		}
	})

	t.Run("canceled_after_call", func(t *testing.T) {
		// A cancellation seen between a call and its correction still carries
		// the usage of the call made (D10: every failure after a call).
		f := newFake(t, usageStep(outOfSchema, modelV1, 10, 5), stepV())
		ctx, cancel := context.WithCancel(ctxFor(t, tenantA))
		defer cancel()
		rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: policyPA()})
		c := mustClient(t, &cancelling{inner: f, cancel: cancel}, rr, oneCorrection)
		o := structuredM().run(c, ctx, call0(t))
		ue := usageErr(t, o.err, context.Canceled)
		if n := f.Invocations(); n != 1 {
			t.Errorf("%d provider calls, want 1", n)
		}
		if ue.Usage != (domain.Usage{InputTokens: 10, OutputTokens: 5}) || ue.Bound != 15 {
			t.Errorf("Usage %+v, Bound %d; want {10 5}, 15", ue.Usage, ue.Bound)
		}
	})

	// Failures before any provider call are unchanged: no UsageError.
	before := []struct {
		name string
		run  func(t *testing.T) (env, outcome)
		want error
	}{
		{"no_route", func(t *testing.T) (env, outcome) {
			e := newEnv(t, configK(), policyPA(), stepV())
			return e, structuredM().run(e.c, ctxFor(t, tenantB), call0(t))
		}, domain.ErrNoRoute},
		{"prompt_mismatch", func(t *testing.T) (env, outcome) {
			e := newEnv(t, configK(), policyPA(), stepV())
			call := call0(t)
			call.PromptHash = "0000"
			return e, structuredM().run(e.c, ctxFor(t, tenantA), call)
		}, ErrPromptMismatch},
	}
	for _, c := range before {
		t.Run(c.name, func(t *testing.T) {
			e, o := c.run(t)
			assertFailed(t, o, c.want)
			var ue *UsageError
			if errors.As(o.err, &ue) {
				t.Errorf("error %v carries a UsageError %+v before any provider call", o.err, ue)
			}
			if n := e.fake.Invocations(); n != 0 {
				t.Errorf("%d provider calls, want 0", n)
			}
		})
	}
}
