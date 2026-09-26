package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/llm/redact"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

func objSchema(props, required string) string {
	return `{"type":"object","additionalProperties":false,"required":[` + required + `],"properties":{` + props + `}}`
}

// TestSecretInSchemasRefused (T44): a secret in any static schema text is
// refused before any I/O, the schema being strict or not.
func TestSecretInSchemasRefused(t *testing.T) {
	cases := map[string]string{
		"description":       objSchema(`"name":{"type":"string","description":"use `+fakeGitHub()+`"}`, `"name"`),
		"enum":              objSchema(`"name":{"type":"string","enum":["`+fakeAWSKey()+`"]}`, `"name"`),
		"property name":     objSchema(`"`+fakeAWSKey()+`":{"type":"string"}`, `"`+fakeAWSKey()+`"`),
		"root title":        `{"title":"` + fakeAWSSecret() + `","type":"object","additionalProperties":false}`,
		"non strict schema": `{"type":"object","description":"` + fakeGitHub() + `"}`,
	}
	for name, s := range cases {
		t.Run("tool "+name, func(t *testing.T) {
			e := newEnv(t, configK(), policyPA(), stepV())
			tools := []domain.ToolSpec{{Name: "lookup", Description: "Look up a record by name", InputSchema: json.RawMessage(s)}}
			o := withToolsM(tools).run(e.c, ctxFor(t, tenantA), call0(t))
			assertNoIO(t, e, o, ErrSecretInPrompt)
			if strings.Contains(o.err.Error(), "EXAMPLE") || strings.Contains(o.err.Error(), "FAKE") {
				t.Errorf("error %q echoes the secret", o.err)
			}
		})
	}
	const id = "test.schemaleak.v1"
	pfs := promptFS()
	pfs[id+"/system.txt"] = &fstest.MapFile{Data: []byte("Reply with a JSON greeting.\n")}
	pfs[id+"/schema.json"] = &fstest.MapFile{Data: []byte(objSchema(`"greeting":{"type":"string","description":"`+fakeGitHub()+`"}`, `"greeting"`))}
	p, err := prompts.LoadFS(pfs, id)
	if err != nil {
		t.Fatalf("witness: the leaky prompt must load: %v", err)
	}
	for _, m := range bothMethods() {
		t.Run("prompt schema, "+m.name, func(t *testing.T) {
			f := newFake(t, stepV())
			rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: policyPA()})
			c, err := NewClient(f, rr, pfs, configK())
			if err != nil {
				t.Fatal(err)
			}
			call := call0(t)
			call.PromptID, call.PromptHash = id, p.Hash
			assertNoIO(t, env{fake: f, rr: rr, c: c}, m.run(c, ctxFor(t, tenantA), call), ErrSecretInPrompt)
		})
	}
}

// toolSpy answers V and keeps the tool slice as received; during runs first.
type toolSpy struct {
	during func()
	got    []domain.ToolSpec
}

func (s *toolSpy) Structured(context.Context, domain.Route, domain.Request) (domain.Response, error) {
	return domain.Response{}, errors.New("unused")
}

func (s *toolSpy) WithTools(_ context.Context, route domain.Route, _ domain.Request, tools []domain.ToolSpec) (domain.Response, error) {
	s.during()
	s.got = tools
	return domain.Response{Output: append(json.RawMessage(nil), valueV...), Model: route.Model, RequestID: "spy"}, nil
}

func (s *toolSpy) Capabilities(domain.Route) domain.Capabilities { return domain.Capabilities{} }

// TestToolsCopiedBeforeCheck (D7): the provider receives the checked copy.
func TestToolsCopiedBeforeCheck(t *testing.T) {
	tools := []domain.ToolSpec{toolT()}
	spy := &toolSpy{during: func() {
		for i := range tools[0].InputSchema {
			tools[0].InputSchema[i] = ' '
		}
		tools[0].Name, tools[0].Description = "other", "changed"
	}}
	rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: policyPA()})
	c := mustClient(t, spy, rr, configK())
	if _, _, err := c.WithTools(ctxFor(t, tenantA), call0(t), tools); err != nil {
		t.Fatalf("WithTools: %v", err)
	}
	if !reflect.DeepEqual(spy.got, []domain.ToolSpec{toolT()}) {
		t.Errorf("provider saw %+v, want the checked copy of [T]", spy.got)
	}
}

// TestEscapedSecretInSchemasRefused (T44, T64): a secret written with JSON
// escapes is read by the model as the secret itself. Whichever check refuses
// it, it never reaches the provider and is never echoed.
func TestEscapedSecretInSchemasRefused(t *testing.T) {
	cases := map[string]struct{ schema, secret string }{
		"escaped key prefix":    {objSchema(`"name":{"type":"string","description":"use \u0041`+fakeAWSKey()[1:]+`"}`, `"name"`), fakeAWSKey()},
		"escaped token prefix":  {objSchema(`"name":{"type":"string","enum":["\u0067`+fakeGitHub()[1:]+`"]}`, `"name"`), fakeGitHub()},
		"escaped separator":     {`{"title":"` + strings.Replace(fakeAWSSecret(), "=", `\u003d`, 1) + `","type":"object","additionalProperties":false}`, fakeAWSSecret()},
		"escaped slashes":       {`{"title":"` + strings.ReplaceAll(fakeAWSSecret(), "/", `\/`) + `","type":"object","additionalProperties":false}`, fakeAWSSecret()},
		"escaped property name": {objSchema(`"\u0041`+fakeAWSKey()[1:]+`":{"type":"string"}`, `"\u0041`+fakeAWSKey()[1:]+`"`), fakeAWSKey()},
	}
	for name, c := range cases {
		t.Run("tool "+name, func(t *testing.T) {
			var decoded any
			if err := json.Unmarshal([]byte(c.schema), &decoded); err != nil || strings.Contains(c.schema, c.secret) ||
				!strings.Contains(fmt.Sprint(decoded), c.secret) {
				t.Fatalf("fixture: the escapes must hide the secret from the raw text only (%v)", err)
			}
			e := newEnv(t, configK(), policyPA(), stepV())
			tools := []domain.ToolSpec{{Name: "lookup", Description: "Look up a record by name", InputSchema: json.RawMessage(c.schema)}}
			o := withToolsM(tools).run(e.c, ctxFor(t, tenantA), call0(t))
			assertNoIO(t, e, o)
			if o.err != nil && (strings.Contains(o.err.Error(), "EXAMPLE") || strings.Contains(o.err.Error(), "FAKE")) {
				t.Errorf("error %q echoes the secret", o.err)
			}
		})
	}
	const id = "test.escapedleak.v1"
	pfs := promptFS()
	pfs[id+"/system.txt"] = &fstest.MapFile{Data: []byte("Reply with a JSON greeting.\n")}
	pfs[id+"/schema.json"] = &fstest.MapFile{Data: []byte(objSchema(`"greeting":{"type":"string","description":"\u0041`+fakeAWSKey()[1:]+`"}`, `"greeting"`))}
	p, err := prompts.LoadFS(pfs, id)
	if err != nil {
		if !errors.Is(err, prompts.ErrInvalidPrompt) {
			t.Fatalf("LoadFS = %v, want ErrInvalidPrompt or a refusal by the client", err)
		}
		return
	}
	for _, m := range bothMethods() {
		t.Run("prompt schema, "+m.name, func(t *testing.T) {
			f := newFake(t, stepV())
			rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: policyPA()})
			c, err := NewClient(f, rr, pfs, configK())
			if err != nil {
				t.Fatal(err)
			}
			call := call0(t)
			call.PromptID, call.PromptHash = id, p.Hash
			assertNoIO(t, env{fake: f, rr: rr, c: c}, m.run(c, ctxFor(t, tenantA), call), ErrSecretInPrompt)
		})
	}
}

// TestToolDescriptionAdmissionList (D3, T68): a tool description is static
// text sent to the model, under the admission list; refused without I/O and
// without quoting the character.
func TestToolDescriptionAdmissionList(t *testing.T) {
	for _, d := range []string{
		"Look up\u202e a record", "Look\u200bup", "Look\tup", "Look\rup", "Look\u00a0up",
		"\ufeffLook up", "Look\u2028up", "Look\x00up", "Look\u00d7up", "Look\xffup",
	} {
		e := newEnv(t, configK(), policyPA(), stepV())
		tools := []domain.ToolSpec{{Name: "lookup", Description: d, InputSchema: json.RawMessage(lookupSchema)}}
		o := withToolsM(tools).run(e.c, ctxFor(t, tenantA), call0(t))
		assertNoIO(t, e, o, ErrInvalidTools)
		if o.err != nil && strings.ContainsAny(o.err.Error(), "\t\r\x00\u00a0\u00d7\u200b\u2028\u202e\ufeff\ufffd") {
			t.Errorf("description %q: error %q quotes the character", d, o.err)
		}
	}
	e := newEnv(t, configK(), policyPA(), stepV())
	french := []domain.ToolSpec{{Name: "lookup", Description: "Cherche un élément par son nom : œuvre, Ÿ.\nDeux lignes.", InputSchema: json.RawMessage(lookupSchema)}}
	assertOK(t, withToolsM(french).run(e.c, ctxFor(t, tenantA), call0(t))) // witness
}

// maskedUnit is a short secret with a long mask: redaction multiplies its
// length by more than 5, so that the fixture stays under 200 KB (the
// redactor is slow under -race, point 10.3 of the plan).
const maskedUnit = "pwd=a "

// TestRedactedTextBounded (D8): masks cannot push the text over 1 MiB; the
// bound is inclusive, after redaction.
func TestRedactedTextBounded(t *testing.T) {
	masked, ms := redact.New().Redact(maskedUnit)
	if len(ms) != 1 || len(masked) <= 5*len(maskedUnit) {
		t.Fatalf("fixture: %q is masked as %q", maskedUnit, masked)
	}
	text := func(n, f int) string { return strings.Repeat(maskedUnit, n) + strings.Repeat("x", f) }
	if got, _ := redact.New().Redact(text(3, 5)); len(got) != 3*len(masked)+5 {
		t.Fatalf("fixture: units do not compose, %q", got)
	}
	// sized returns a text of length after once redacted.
	sized := func(after int) string {
		n := after / len(masked)
		return text(n, after-n*len(masked))
	}
	over, at := sized(MaxRequestTextBytes+1), sized(MaxRequestTextBytes)
	if len(over) > MaxRequestTextBytes/5 || len(at) > MaxRequestTextBytes/5 {
		t.Fatal("fixture: text too long before redaction")
	}
	type run struct {
		m    method
		text string
		ok   bool
	}
	runs := map[string]run{"Structured at the bound": {structuredM(), at, true}}
	for _, m := range bothMethods() {
		runs[m.name+" over the bound"] = run{m, over, false}
	}
	for name, r := range runs {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			e := newEnv(t, configK(), policyPA(), stepV())
			call := call0(t)
			call.Messages = []domain.Message{userText(r.text)}
			o := r.m.run(e.c, ctxFor(t, tenantA), call)
			if r.ok {
				assertOK(t, o)
				return
			}
			assertNoCall(t, e, o, ErrRequestTooLarge)
		})
	}
}
