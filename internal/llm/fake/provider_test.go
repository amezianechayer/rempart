package fake

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

const testPromptID = "demo.greeting.v1"

// fakeRoute is the route of every call unless a test says otherwise.
func fakeRoute() domain.Route {
	return domain.Route{Platform: domain.PlatformFake, Model: "fake-model-v1"}
}

// reqQ is the plain request Q of the plan: built fresh on every call.
func reqQ() domain.Request {
	return domain.Request{
		PromptID:  testPromptID,
		Messages:  []domain.Message{{Role: domain.RoleUser, Parts: []domain.Part{{Text: "hello"}}}},
		Schema:    json.RawMessage(`{"type":"object"}`),
		MaxTokens: 256,
	}
}

// reqU is Q plus one untrusted block.
func reqU() domain.Request {
	r := reqQ()
	r.Messages[0].Parts = append(r.Messages[0].Parts, domain.Part{
		Untrusted: &domain.UntrustedBlock{SourceID: "r-7f3a", Content: "CANARY"},
	})
	return r
}

// respW is the recorded answer W of the plan.
func respW() domain.Response {
	return domain.Response{
		Output:    json.RawMessage(`{"greeting":"bonjour"}`),
		Usage:     domain.Usage{InputTokens: 12, OutputTokens: 5},
		Model:     "fake-model-v1",
		RequestID: "fake-req-1",
	}
}

func testTools() []domain.ToolSpec {
	return []domain.ToolSpec{{
		Name:        "lookup_record",
		Description: "Look up a record",
		InputSchema: json.RawMessage(`{"type":"object"}`),
	}}
}

// deepCopyReq is written independently of the code under test.
func deepCopyReq(r domain.Request) domain.Request {
	c := r
	if r.Schema != nil {
		c.Schema = append(json.RawMessage{}, r.Schema...)
	}
	if r.Messages != nil {
		c.Messages = make([]domain.Message, len(r.Messages))
		for i, m := range r.Messages {
			c.Messages[i].Role = m.Role
			if m.Parts == nil {
				continue
			}
			c.Messages[i].Parts = make([]domain.Part, len(m.Parts))
			for j, pt := range m.Parts {
				c.Messages[i].Parts[j].Text = pt.Text
				if pt.Untrusted != nil {
					b := *pt.Untrusted
					c.Messages[i].Parts[j].Untrusted = &b
				}
			}
		}
	}
	return c
}

func mustNew(t *testing.T, opt Options) *Provider {
	t.Helper()
	p, err := New(opt)
	if err != nil {
		t.Fatalf("New: unexpected error %v", err)
	}
	if p == nil {
		t.Fatal("New: nil provider without error")
	}
	return p
}

func recordingOf(req domain.Request, resp domain.Response) Recording {
	return Recording{PromptID: req.PromptID, RequestHash: domain.RequestHash(req), Step: Step{Response: resp}}
}

// scriptedProvider answers Q once with W through a script, so that a refused
// call that advanced the cursor is visible on the next valid call.
func scriptedProvider(t *testing.T) *Provider {
	t.Helper()
	return mustNew(t, Options{Scripts: map[string][]Step{testPromptID: {{Response: respW()}}}})
}

func isZeroResponse(r domain.Response) bool {
	return reflect.DeepEqual(r, domain.Response{})
}

type providerCall func(p *Provider) (domain.Response, error)

// assertRefused checks the plan's "refused": every wanted error (errors.Is),
// a zero response, Invocations()+1, nothing captured, cursor intact.
func assertRefused(t *testing.T, call providerCall, wants ...error) {
	t.Helper()
	p := scriptedProvider(t)
	resp, err := call(p)
	if err == nil {
		t.Fatal("call accepted, want refusal")
	}
	for _, w := range wants {
		if !errors.Is(err, w) {
			t.Errorf("error %q does not match %q", err, w)
		}
	}
	if !isZeroResponse(resp) {
		t.Errorf("refused call returned a non-zero response %+v", resp)
	}
	if got := p.Invocations(); got != 1 {
		t.Errorf("Invocations() = %d after one refused call, want 1", got)
	}
	if got := len(p.Calls()); got != 0 {
		t.Errorf("refused call was captured: len(Calls()) = %d, want 0", got)
	}
	if got := len(p.Requests()); got != 0 {
		t.Errorf("refused call was captured: len(Requests()) = %d, want 0", got)
	}
	next, err := p.Structured(context.Background(), fakeRoute(), reqQ())
	if err != nil || !reflect.DeepEqual(next, respW()) {
		t.Errorf("script cursor moved by a refused call: next valid call = %+v, %v", next, err)
	}
}

func structuredWith(route domain.Route, req domain.Request) providerCall {
	return func(p *Provider) (domain.Response, error) {
		return p.Structured(context.Background(), route, req)
	}
}

func withToolsWith(route domain.Route, req domain.Request, tools []domain.ToolSpec) providerCall {
	return func(p *Provider) (domain.Response, error) {
		return p.WithTools(context.Background(), route, req, tools)
	}
}

func assertResponse(t *testing.T, label string, got domain.Response, err error, want domain.Response) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected error %v", label, err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s: response = %+v, want %+v", label, got, want)
	}
	if !bytes.Equal(got.Output, want.Output) {
		t.Errorf("%s: Output = %q, want %q", label, got.Output, want.Output)
	}
}

// Test 1.
func TestFakeDeterministic(t *testing.T) {
	ctx := context.Background()
	q := reqQ()
	opt := Options{Recordings: []Recording{recordingOf(q, respW())}}
	p1 := mustNew(t, opt)
	p2 := mustNew(t, opt)

	first, err := p1.Structured(ctx, fakeRoute(), q)
	assertResponse(t, "p1 call 1", first, err, respW())

	// A caller mutating its response must not alter what the fake returns next.
	first.Output[0] = 'X'
	first.Model = "mutated"
	got, err := p1.Structured(ctx, fakeRoute(), q)
	assertResponse(t, "p1 call 2 after mutating call 1", got, err, respW())

	// Mutating the options after New must not alter any provider built from them.
	opt.Recordings[0].Response.Output[0] = 'Y'
	opt.Recordings[0].Response.Model = "mutated"
	got, err = p1.Structured(ctx, fakeRoute(), q)
	assertResponse(t, "p1 call 3 after mutating options", got, err, respW())

	got, err = p2.Structured(ctx, fakeRoute(), q)
	assertResponse(t, "p2 call 1", got, err, respW())

	got, err = p1.Structured(ctx, fakeRoute(), deepCopyReq(q))
	assertResponse(t, "p1 deep copy of Q", got, err, respW())

	got, err = p1.WithTools(ctx, fakeRoute(), q, testTools())
	assertResponse(t, "p1 WithTools", got, err, respW())

	if n := p1.Invocations(); n != 5 {
		t.Errorf("p1.Invocations() = %d, want 5", n)
	}
	if n := p2.Invocations(); n != 1 {
		t.Errorf("p2.Invocations() = %d, want 1", n)
	}
}

// Test 2.
func TestFakeNoRecordingIsError(t *testing.T) {
	ctx := context.Background()

	t.Run("no options", func(t *testing.T) {
		p := mustNew(t, Options{})
		resp, err := p.Structured(ctx, fakeRoute(), reqQ())
		if !errors.Is(err, ErrNoRecording) {
			t.Fatalf("error = %v, want ErrNoRecording", err)
		}
		if !isZeroResponse(resp) {
			t.Errorf("response = %+v, want zero (no default answer)", resp)
		}
		resp, err = p.WithTools(ctx, fakeRoute(), reqQ(), testTools())
		if !errors.Is(err, ErrNoRecording) || !isZeroResponse(resp) {
			t.Errorf("WithTools = %+v, %v, want zero response and ErrNoRecording", resp, err)
		}
		reqs := p.Requests()
		if len(reqs) != 2 || !reflect.DeepEqual(reqs[0], reqQ()) || !reflect.DeepEqual(reqs[1], reqQ()) {
			t.Errorf("Requests() = %+v, want Q captured twice", reqs)
		}
		if n := p.Invocations(); n != 2 {
			t.Errorf("Invocations() = %d, want 2", n)
		}
	})

	nearMisses := map[string]func() domain.Request{
		"text differs by case": func() domain.Request {
			r := reqQ()
			r.Messages[0].Parts[0].Text = "hellO"
			return r
		},
		"other prompt id": func() domain.Request {
			r := reqQ()
			r.PromptID = "demo.other.v1"
			return r
		},
		"other max tokens": func() domain.Request {
			r := reqQ()
			r.MaxTokens = 257
			return r
		},
	}
	for name, build := range nearMisses {
		t.Run(name, func(t *testing.T) {
			p := mustNew(t, Options{Recordings: []Recording{recordingOf(reqQ(), respW())}})
			req := build()
			resp, err := p.Structured(ctx, fakeRoute(), req)
			if !errors.Is(err, ErrNoRecording) {
				t.Fatalf("error = %v, want ErrNoRecording", err)
			}
			if !isZeroResponse(resp) {
				t.Errorf("response = %+v, want zero", resp)
			}
			reqs := p.Requests()
			if len(reqs) != 1 || !reflect.DeepEqual(reqs[0], req) {
				t.Errorf("Requests() = %+v, want the request captured", reqs)
			}
		})
	}
}

func stepOut(id string) Step {
	return Step{Response: domain.Response{Output: json.RawMessage(`{"step":"` + id + `"}`), RequestID: id}}
}

// Test 3.
func TestFakeScriptOrderAndExhaustion(t *testing.T) {
	ctx := context.Background()

	t.Run("order and exhaustion", func(t *testing.T) {
		p := mustNew(t, Options{Scripts: map[string][]Step{
			testPromptID:    {stepOut("a"), {Err: "x"}, stepOut("b")},
			"demo.other.v1": {stepOut("c")},
		}})
		other := reqQ()
		other.PromptID = "demo.other.v1"

		got, err := p.Structured(ctx, fakeRoute(), reqQ())
		assertResponse(t, "step 1", got, err, stepOut("a").Response)

		// The other script has its own cursor.
		got, err = p.Structured(ctx, fakeRoute(), other)
		assertResponse(t, "other step 1", got, err, stepOut("c").Response)

		got, err = p.WithTools(ctx, fakeRoute(), reqQ(), nil)
		if !errors.Is(err, ErrScripted) || !isZeroResponse(got) {
			t.Errorf("step 2 = %+v, %v, want zero response and ErrScripted", got, err)
		}

		got, err = p.Structured(ctx, fakeRoute(), reqQ())
		assertResponse(t, "step 3", got, err, stepOut("b").Response)

		for i := range 2 {
			got, err = p.Structured(ctx, fakeRoute(), reqQ())
			if !errors.Is(err, ErrScriptExhausted) || !isZeroResponse(got) {
				t.Errorf("after the end, call %d = %+v, %v, want zero response and ErrScriptExhausted", i+1, got, err)
			}
		}
		got, err = p.Structured(ctx, fakeRoute(), other)
		if !errors.Is(err, ErrScriptExhausted) || !isZeroResponse(got) {
			t.Errorf("other after the end = %+v, %v, want ErrScriptExhausted", got, err)
		}
		if n := p.Invocations(); n != 7 {
			t.Errorf("Invocations() = %d, want 7", n)
		}
		if n := len(p.Calls()); n != 7 {
			t.Errorf("len(Calls()) = %d, want 7", n)
		}
	})

	t.Run("recording wins without moving the cursor", func(t *testing.T) {
		p := mustNew(t, Options{
			Recordings: []Recording{recordingOf(reqQ(), respW())},
			Scripts:    map[string][]Step{testPromptID: {stepOut("a"), stepOut("b")}},
		})
		unrecorded := reqQ()
		unrecorded.Messages[0].Parts[0].Text = "bonjour"

		got, err := p.Structured(ctx, fakeRoute(), reqQ())
		assertResponse(t, "recorded 1", got, err, respW())
		got, err = p.Structured(ctx, fakeRoute(), unrecorded)
		assertResponse(t, "scripted 1", got, err, stepOut("a").Response)
		got, err = p.WithTools(ctx, fakeRoute(), reqQ(), testTools())
		assertResponse(t, "recorded 2", got, err, respW())
		got, err = p.Structured(ctx, fakeRoute(), unrecorded)
		assertResponse(t, "scripted 2", got, err, stepOut("b").Response)
		got, err = p.Structured(ctx, fakeRoute(), reqQ())
		assertResponse(t, "recorded 3 after script end", got, err, respW())
	})
}

// Test 4.
func TestFakeWithToolsRefusesUntrusted(t *testing.T) {
	requests := map[string]func() domain.Request{
		"U": reqU,
		"block in assistant message": func() domain.Request {
			r := reqQ()
			r.Messages = append(r.Messages, domain.Message{
				Role:  domain.RoleAssistant,
				Parts: []domain.Part{{Untrusted: &domain.UntrustedBlock{SourceID: "r-1", Content: "earlier output"}}},
			})
			return r
		},
		"part with text and block": func() domain.Request {
			r := reqQ()
			r.Messages[0].Parts[0].Untrusted = &domain.UntrustedBlock{SourceID: "r-2", Content: "data"}
			return r
		},
		"empty block": func() domain.Request {
			r := reqQ()
			r.Messages[0].Parts[0] = domain.Part{Untrusted: &domain.UntrustedBlock{}}
			return r
		},
	}
	toolSets := map[string]func() []domain.ToolSpec{
		"nil tools":   func() []domain.ToolSpec { return nil },
		"empty tools": func() []domain.ToolSpec { return []domain.ToolSpec{} },
		"one tool":    testTools,
	}
	for rn, req := range requests {
		for tn, tools := range toolSets {
			t.Run(rn+"/"+tn, func(t *testing.T) {
				assertRefused(t, withToolsWith(fakeRoute(), req(), tools()), domain.ErrUntrustedWithTools)
			})
		}
	}

	t.Run("Structured accepts U", func(t *testing.T) {
		p := scriptedProvider(t)
		got, err := p.Structured(context.Background(), fakeRoute(), reqU())
		assertResponse(t, "Structured(U)", got, err, respW())
		reqs := p.Requests()
		if len(reqs) != 1 || !reflect.DeepEqual(reqs[0], reqU()) {
			t.Errorf("Requests() = %+v, want U captured", reqs)
		}
	})
}

// Test 5.
func TestFakeCapturesRequestsCopy(t *testing.T) {
	ctx := context.Background()
	p := mustNew(t, Options{Scripts: map[string][]Step{testPromptID: {{Response: respW()}, {Response: respW()}}}})
	u := reqU()
	q := reqQ()
	tools := testTools()

	if _, err := p.Structured(ctx, fakeRoute(), u); err != nil {
		t.Fatalf("Structured(U): %v", err)
	}
	if _, err := p.WithTools(ctx, fakeRoute(), q, tools); err != nil {
		t.Fatalf("WithTools(Q): %v", err)
	}

	// Mutate every caller-owned buffer after the calls.
	u.Messages[0].Parts[0].Text = "mutated"
	u.Messages[0].Parts[1].Untrusted.Content = "mutated"
	u.Schema[0] = 'X'
	u.Messages[0].Role = domain.RoleAssistant
	q.Messages[0].Parts[0].Text = "mutated"
	q.Schema[0] = 'X'
	tools[0].InputSchema[0] = 'X'
	tools[0].Name = "mutated"

	check := func(label string) {
		t.Helper()
		reqs := p.Requests()
		if len(reqs) != 2 || !reflect.DeepEqual(reqs[0], reqU()) || !reflect.DeepEqual(reqs[1], reqQ()) {
			t.Errorf("%s: Requests() = %+v, want [U, Q] unchanged", label, reqs)
		}
		calls := p.Calls()
		if len(calls) != 2 {
			t.Fatalf("%s: len(Calls()) = %d, want 2", label, len(calls))
		}
		want := []Call{
			{WithTools: false, Route: fakeRoute(), Request: reqU(), Tools: nil},
			{WithTools: true, Route: fakeRoute(), Request: reqQ(), Tools: testTools()},
		}
		if !reflect.DeepEqual(calls, want) {
			t.Errorf("%s: Calls() = %+v, want %+v", label, calls, want)
		}
	}
	check("after mutating the caller's values")

	// Mutate the returned slices: the next reads must not see it.
	reqs := p.Requests()
	reqs[0].Messages[0].Parts[0].Text = "mutated"
	reqs[0].Messages[0].Parts[1].Untrusted.Content = "mutated"
	reqs[0].Schema[0] = 'X'
	reqs[1].Messages[0].Role = domain.RoleAssistant
	calls := p.Calls()
	calls[1].Tools[0].InputSchema[0] = 'X'
	calls[1].Tools[0].Description = "mutated"
	calls[1].Request.Messages[0].Parts[0].Text = "mutated"
	calls[0].Request.Messages[0].Parts[1].Untrusted.SourceID = "mutated"
	calls[1].Request.Schema[0] = 'X'
	check("after mutating returned values")
}

// Test 9.
func TestFakeRefusesForeignRoute(t *testing.T) {
	routes := map[string]domain.Route{
		"anthropic":          {Platform: domain.PlatformAnthropic, Model: "fake-model-v1"},
		"bedrock eu-west-3":  {Platform: domain.PlatformBedrock, Region: "eu-west-3", Model: "fake-model-v1"},
		"empty platform":     {Model: "fake-model-v1"},
		"fake with a region": {Platform: domain.PlatformFake, Region: "local", Model: "fake-model-v1"},
	}
	for name, route := range routes {
		t.Run(name+"/Structured", func(t *testing.T) {
			assertRefused(t, structuredWith(route, reqQ()), domain.ErrInvalidRoute)
		})
		t.Run(name+"/WithTools", func(t *testing.T) {
			assertRefused(t, withToolsWith(route, reqQ(), testTools()), domain.ErrInvalidRoute)
		})
	}
	// The route check comes before the untrusted and request checks (D3).
	t.Run("route checked before untrusted", func(t *testing.T) {
		assertRefused(t, withToolsWith(routes["anthropic"], reqU(), testTools()), domain.ErrInvalidRoute)
	})
	t.Run("route checked before request", func(t *testing.T) {
		assertRefused(t, structuredWith(routes["anthropic"], domain.Request{PromptID: testPromptID}), domain.ErrInvalidRoute)
	})
}

// Test 10.
func TestFakeValidatesRequest(t *testing.T) {
	cases := map[string]struct {
		req  func() domain.Request
		want error
	}{
		"no message": {func() domain.Request {
			r := reqQ()
			r.Messages = nil
			return r
		}, domain.ErrInvalidRequest},
		"system role": {func() domain.Request {
			r := reqQ()
			r.Messages[0].Role = "system"
			return r
		}, domain.ErrInvalidRequest},
		"empty message": {func() domain.Request {
			r := reqQ()
			r.Messages[0].Parts = nil
			return r
		}, domain.ErrInvalidRequest},
		"empty part": {func() domain.Request {
			r := reqQ()
			r.Messages[0].Parts = []domain.Part{{}}
			return r
		}, domain.ErrInvalidPart},
	}
	for name, c := range cases {
		t.Run(name+"/Structured", func(t *testing.T) {
			assertRefused(t, structuredWith(fakeRoute(), c.req()), c.want)
		})
		t.Run(name+"/WithTools", func(t *testing.T) {
			assertRefused(t, withToolsWith(fakeRoute(), c.req(), testTools()), c.want)
		})
	}
}

// Test 11.
func TestFakeHonorsContext(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancelExpired()
	foreign := domain.Route{Platform: domain.PlatformAnthropic, Model: "fake-model-v1"}

	cases := map[string]struct {
		ctx   context.Context
		route domain.Route
		want  error
	}{
		"cancelled":                  {cancelled, fakeRoute(), context.Canceled},
		"deadline exceeded":          {expired, fakeRoute(), context.DeadlineExceeded},
		"cancelled on foreign route": {cancelled, foreign, context.Canceled},
	}
	for name, c := range cases {
		t.Run(name+"/Structured", func(t *testing.T) {
			assertRefused(t, func(p *Provider) (domain.Response, error) {
				return p.Structured(c.ctx, c.route, reqQ())
			}, c.want)
		})
		t.Run(name+"/WithTools", func(t *testing.T) {
			assertRefused(t, func(p *Provider) (domain.Response, error) {
				return p.WithTools(c.ctx, c.route, reqU(), testTools())
			}, c.want)
		})
	}
}

// Test 12.
func TestFakeCapabilities(t *testing.T) {
	known := domain.Capabilities{NativeStructuredOutput: true, StrictTools: true, RequiresRetention: false}
	models := map[string]domain.Capabilities{"fake-model-v1": known}
	p := mustNew(t, Options{Models: models})
	// Options are copied: a later change of the caller's map has no effect.
	models["fake-model-v1"] = domain.Capabilities{}
	models["fake-model-v9"] = known

	if got := p.Capabilities(fakeRoute()); got != known {
		t.Errorf("known model: Capabilities = %+v, want %+v", got, known)
	}
	closed := domain.Capabilities{RequiresRetention: true}
	unknown := map[string]struct {
		p     *Provider
		route domain.Route
	}{
		"unknown model":           {p, domain.Route{Platform: domain.PlatformFake, Model: "fake-model-v9"}},
		"nil Models":              {mustNew(t, Options{}), fakeRoute()},
		"same model on anthropic": {p, domain.Route{Platform: domain.PlatformAnthropic, Model: "fake-model-v1"}},
		"fake with a region":      {p, domain.Route{Platform: domain.PlatformFake, Region: "local", Model: "fake-model-v1"}},
	}
	for name, c := range unknown {
		if got := c.p.Capabilities(c.route); got != closed {
			t.Errorf("%s: Capabilities = %+v, want %+v", name, got, closed)
		}
	}
	if n := p.Invocations(); n != 0 {
		t.Errorf("Capabilities counted as an invocation: %d", n)
	}
}

// Test 13.
func TestNewValidatesOptions(t *testing.T) {
	q := reqQ()
	hash := domain.RequestHash(q)
	withErrAnd := func(mut func(*domain.Response)) Step {
		s := Step{Err: "provider_unavailable"}
		mut(&s.Response)
		return s
	}
	cases := map[string]Options{
		"hash of 63 characters": {Recordings: []Recording{{PromptID: testPromptID, RequestHash: hash[:63], Step: Step{Response: respW()}}}},
		"upper-case hash":       {Recordings: []Recording{{PromptID: testPromptID, RequestHash: strings.ToUpper(hash), Step: Step{Response: respW()}}}},
		"empty prompt id":       {Recordings: []Recording{{PromptID: "", RequestHash: hash, Step: Step{Response: respW()}}}},
		"duplicate recording": {Recordings: []Recording{
			recordingOf(q, respW()),
			{PromptID: testPromptID, RequestHash: hash, Step: Step{Err: "provider_unavailable"}},
		}},
		"recording with Err and Output": {Recordings: []Recording{{PromptID: testPromptID, RequestHash: hash, Step: withErrAnd(func(r *domain.Response) {
			r.Output = json.RawMessage(`{}`)
		})}}},
		"recording with Err and Model": {Recordings: []Recording{{PromptID: testPromptID, RequestHash: hash, Step: withErrAnd(func(r *domain.Response) {
			r.Model = "fake-model-v1"
		})}}},
		"script step with Err and RequestID": {Scripts: map[string][]Step{testPromptID: {withErrAnd(func(r *domain.Response) {
			r.RequestID = "fake-req-1"
		})}}},
		"empty script":     {Scripts: map[string][]Step{testPromptID: {}}},
		"nil script":       {Scripts: map[string][]Step{testPromptID: nil}},
		"empty script key": {Scripts: map[string][]Step{"": {{Response: respW()}}}},
		"empty model":      {Models: map[string]domain.Capabilities{"": {}}},
	}
	for name, opt := range cases {
		t.Run(name, func(t *testing.T) {
			p, err := New(opt)
			if !errors.Is(err, ErrInvalidOptions) {
				t.Errorf("error = %v, want ErrInvalidOptions", err)
			}
			if p != nil {
				t.Error("provider returned with an error")
			}
		})
	}

	t.Run("valid options", func(t *testing.T) {
		mustNew(t, Options{
			Recordings: []Recording{recordingOf(q, respW()), {PromptID: testPromptID, RequestHash: domain.RequestHash(reqU()), Step: Step{Err: "provider_unavailable"}}},
			Scripts:    map[string][]Step{testPromptID: {{Response: respW()}, {Err: "provider_unavailable"}}},
			Models:     map[string]domain.Capabilities{"fake-model-v1": {}},
		})
	})
}

// Test 14.
func TestFakeErrorsDoNotEchoInput(t *testing.T) {
	ctx := context.Background()
	canary := func(s string) string { return strings.Replace(s, "x", "CANARY", 1) }
	var errs []error
	var hashes []string
	add := func(err error) {
		t.Helper()
		if err == nil {
			t.Errorf("case %d: expected an error", len(errs))
		}
		errs = append(errs, err)
	}

	p := mustNew(t, Options{Scripts: map[string][]Step{testPromptID: {{Err: "CANARY failure"}}}})

	promptReq := reqQ()
	promptReq.PromptID = canary("demo.x.v1")
	textReq := reqQ()
	textReq.PromptID = "demo.unknown.v1"
	textReq.Messages[0].Parts[0].Text = "CANARY"
	blockReq := reqU()
	blockReq.PromptID = "demo.unknown.v1"
	invalidPart := reqU()
	invalidPart.Messages[0].Parts[0].Untrusted = &domain.UntrustedBlock{SourceID: "CANARY", Content: "CANARY"}
	hashes = append(hashes, domain.RequestHash(promptReq), domain.RequestHash(textReq), domain.RequestHash(blockReq), domain.RequestHash(invalidPart))

	_, err := p.Structured(ctx, fakeRoute(), promptReq)
	add(err)
	_, err = p.Structured(ctx, fakeRoute(), textReq)
	add(err)
	_, err = p.Structured(ctx, fakeRoute(), blockReq)
	add(err)
	_, err = p.WithTools(ctx, fakeRoute(), blockReq, testTools())
	add(err)
	_, err = p.Structured(ctx, fakeRoute(), invalidPart)
	add(err)
	_, err = p.Structured(ctx, domain.Route{Platform: "CANARY", Region: "CANARY", Model: "CANARY"}, reqQ())
	add(err)
	_, err = p.Structured(ctx, domain.Route{Platform: domain.PlatformFake, Region: "CANARY", Model: "CANARY"}, reqQ())
	add(err)
	_, err = p.Structured(ctx, fakeRoute(), reqQ()) // scripted Err "CANARY failure"
	add(err)
	_, err = p.Structured(ctx, fakeRoute(), reqQ()) // exhausted
	add(err)

	_, err = New(Options{Recordings: []Recording{{PromptID: "CANARY", RequestHash: "CANARY"}}})
	add(err)
	_, err = New(Options{Recordings: []Recording{
		recordingOf(promptReq, respW()), recordingOf(promptReq, respW()),
	}})
	add(err)
	_, err = New(Options{Scripts: map[string][]Step{"CANARY": {}}})
	add(err)

	fsys := fstest.MapFS{
		"unknown.json":  {Data: []byte(`{"version":1,"CANARY":true}`)},
		"nested.json":   {Data: []byte(`{"version":1,"scripts":{"CANARY.v1":[{"response":{"CANARY":"x"}}]}}`)},
		"notjson.json":  {Data: []byte(`CANARY`)},
		"trailing.json": {Data: []byte(`{"version":1} CANARY`)},
		"model.json":    {Data: []byte(`{"version":1,"models":{"CANARY":{}}}`)},
	}
	for _, name := range []string{"CANARY.json", "dir/CANARY/missing.json", "unknown.json", "nested.json", "notjson.json", "trailing.json", "model.json"} {
		_, err = LoadOptions(fsys, name)
		add(err)
	}

	for _, id := range []string{"CANARY", "canary-00-0000-4000-8000-000000000000"} {
		r, rerr := NewStaticResolver(map[tenancy.ID]domain.TenantPolicy{tenancy.ID(id): {}})
		if r != nil {
			t.Errorf("resolver returned for key %q", id)
		}
		add(rerr)
		ok, nerr := NewStaticResolver(nil)
		if nerr != nil {
			t.Fatalf("NewStaticResolver(nil): %v", nerr)
		}
		_, rerr = ok.Resolve(ctx, tenancy.ID(id))
		add(rerr)
	}

	for i, e := range errs {
		if e == nil {
			continue
		}
		msg := e.Error()
		if strings.Contains(strings.ToLower(msg), "canary") {
			t.Errorf("case %d: error echoes the input: %q", i, msg)
		}
		for _, h := range hashes {
			if strings.Contains(msg, h) {
				t.Errorf("case %d: error contains the request hash: %q", i, msg)
			}
		}
		if len(msg) >= 128 {
			t.Errorf("case %d: error of %d bytes, want less than 128: %q", i, len(msg), msg)
		}
	}
}

// Test 15.
func TestFakeResponseModelFromScript(t *testing.T) {
	ctx := context.Background()
	v2 := domain.Response{Output: json.RawMessage(`{"greeting":"salut"}`), Model: "fake-model-v2", RequestID: "fake-req-2"}
	bare := domain.Response{Output: json.RawMessage(`{}`)}
	p := mustNew(t, Options{Scripts: map[string][]Step{testPromptID: {{Response: v2}, {Response: bare}}}})

	got, err := p.Structured(ctx, fakeRoute(), reqQ())
	assertResponse(t, "scripted fake-model-v2", got, err, v2)
	if got.Model != "fake-model-v2" {
		t.Errorf("Model = %q, want the scripted fake-model-v2, not the route's model", got.Model)
	}

	got, err = p.WithTools(ctx, fakeRoute(), reqQ(), testTools())
	assertResponse(t, "scripted without model", got, err, bare)
	if got.Model != "" || got.RequestID != "" {
		t.Errorf("Model = %q, RequestID = %q, want both empty (nothing from the route or the hash)", got.Model, got.RequestID)
	}
}

// Test 16.
func TestFakeConcurrentUse(t *testing.T) {
	ctx := context.Background()

	t.Run("recording", func(t *testing.T) {
		p := mustNew(t, Options{Recordings: []Recording{recordingOf(reqQ(), respW())}})
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				for range 50 {
					got, err := p.Structured(ctx, fakeRoute(), reqQ())
					if err != nil || !reflect.DeepEqual(got, respW()) {
						t.Errorf("concurrent call = %+v, %v, want W", got, err)
						return
					}
				}
			})
		}
		wg.Wait()
		if n := p.Invocations(); n != 16*50 {
			t.Errorf("Invocations() = %d, want %d", n, 16*50)
		}
		if n := len(p.Calls()); n != 16*50 {
			t.Errorf("len(Calls()) = %d, want %d", n, 16*50)
		}
	})

	t.Run("script", func(t *testing.T) {
		const steps = 100
		script := make([]Step, steps)
		for i := range script {
			id := fmt.Sprintf("s-%03d", i)
			script[i] = Step{Response: domain.Response{Output: json.RawMessage(`{"s":"` + id + `"}`), RequestID: id}}
		}
		p := mustNew(t, Options{Scripts: map[string][]Step{testPromptID: script}})

		var mu sync.Mutex
		seen := map[string]int{}
		var wg sync.WaitGroup
		for range steps {
			wg.Go(func() {
				got, err := p.Structured(ctx, fakeRoute(), reqQ())
				if err != nil {
					t.Errorf("concurrent scripted call: %v", err)
					return
				}
				if want := `{"s":"` + got.RequestID + `"}`; string(got.Output) != want {
					t.Errorf("Output %q does not belong to step %q", got.Output, got.RequestID)
				}
				mu.Lock()
				seen[got.RequestID]++
				mu.Unlock()
			})
		}
		wg.Wait()
		for i := range steps {
			id := fmt.Sprintf("s-%03d", i)
			if seen[id] != 1 {
				t.Errorf("step %s served %d times, want 1", id, seen[id])
			}
		}
		if len(seen) != steps {
			t.Errorf("%d distinct steps served, want %d", len(seen), steps)
		}
		got, err := p.Structured(ctx, fakeRoute(), reqQ())
		if !errors.Is(err, ErrScriptExhausted) || !isZeroResponse(got) {
			t.Errorf("call after the script = %+v, %v, want ErrScriptExhausted", got, err)
		}
		if n := p.Invocations(); n != steps+1 {
			t.Errorf("Invocations() = %d, want %d", n, steps+1)
		}
	})
}
