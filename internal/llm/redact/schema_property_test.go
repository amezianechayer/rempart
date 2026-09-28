package redact_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"pgregory.net/rapid"

	"github.com/amezianechayer/rempart/internal/llm"
	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/fake"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/llm/redact"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// Property of amendment V2 (T44): a schema accepted by the client carries no
// secret in any text the model reads once the schema is decoded. The secrets
// are the positive cases of the redactor, written with the escapes that the
// admission list keeps (\", \\, \n).

const propTenant tenancy.ID = "0f8fad5b-d9cb-469f-a165-70867728950e"

const (
	propModel  = "fake-model-v1"
	propPrompt = "test.greeting.v1"
	propSchema = `{"type":"object","properties":{"greeting":{"type":"string"}},"required":["greeting"],"additionalProperties":false}`
)

// jsonText is s as the body of a JSON string, with \", \\ and \n only.
func jsonText(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

// placements put an encoded text e where a schema holds static text.
var placements = map[string]func(e string) string{
	"description": func(e string) string {
		return `{"type":"object","description":"` + e + `","properties":{},"required":[],"additionalProperties":false}`
	},
	"title": func(e string) string {
		return `{"type":"object","title":"` + e + `","properties":{},"required":[],"additionalProperties":false}`
	},
	"enum":  func(e string) string { return propObject(`{"type":"string","enum":["` + e + `"]}`) },
	"const": func(e string) string { return propObject(`{"const":"` + e + `"}`) },
	"const value": func(e string) string {
		return propObject(`{"const":{"note":"` + e + `"}}`)
	},
	"const key": func(e string) string { return propObject(`{"const":{"` + e + `":1}}`) },
}

func propObject(sub string) string {
	return `{"type":"object","additionalProperties":false,"required":["x"],"properties":{"x":` + sub + `}}`
}

// decodedTexts is the oracle, written apart from the code under test: every
// key and every string of the decoded document.
func decodedTexts(raw string) ([]string, error) {
	var doc any
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, err
	}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case map[string]any:
			for k, e := range x {
				out = append(out, k)
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(doc)
	return out, nil
}

// reaches reports whether a call with schema raw, as the input schema of a
// tool or as the prompt schema, reached the provider (a prompt call may reach
// it and then refuse the output, which the fake does not shape).
func reaches(raw string, asPrompt bool) (bool, error) {
	id := propPrompt
	pfs := fstest.MapFS{
		propPrompt + "/system.txt":  {Data: []byte("Reply with a JSON greeting.\n")},
		propPrompt + "/schema.json": {Data: []byte(propSchema)},
	}
	if asPrompt {
		id = "test.property.v1"
		pfs[id+"/system.txt"] = &fstest.MapFile{Data: []byte("Reply with a JSON greeting.\n")}
		pfs[id+"/schema.json"] = &fstest.MapFile{Data: []byte(raw)}
	}
	p, err := prompts.LoadFS(pfs, id)
	if err != nil {
		if errors.Is(err, prompts.ErrInvalidPrompt) {
			return false, nil
		}
		return false, err
	}
	step := fake.Step{Response: domain.Response{Output: json.RawMessage(`{"greeting":"bonjour"}`), Model: propModel, RequestID: "r"}}
	f, err := fake.New(fake.Options{Models: map[string]domain.Capabilities{propModel: {}}, Scripts: map[string][]fake.Step{id: {step}}})
	if err != nil {
		return false, err
	}
	rr, err := fake.NewStaticResolver(map[tenancy.ID]domain.TenantPolicy{propTenant: {
		Route: domain.Route{Platform: domain.PlatformFake, Model: propModel}, Residency: domain.ResidencyEU, Retention: domain.RetentionZero,
	}})
	if err != nil {
		return false, err
	}
	c, err := llm.NewClient(f, rr, pfs, llm.Config{MaxTokensPerCall: 256, AllowFakeRoute: true})
	if err != nil {
		return false, err
	}
	ctx, err := tenancy.WithTenant(context.Background(), propTenant)
	if err != nil {
		return false, err
	}
	call := llm.Call{PromptID: id, PromptHash: p.Hash, Messages: []domain.Message{{Role: domain.RoleUser, Parts: []domain.Part{{Text: "hello"}}}}, MaxTokens: 256}
	if asPrompt {
		_, err = c.Structured(ctx, call)
	} else {
		tools := []domain.ToolSpec{{Name: "lookup", Description: "Look up a record", InputSchema: json.RawMessage(raw)}}
		_, _, err = c.WithTools(ctx, call, tools)
	}
	n := f.Invocations()
	if !asPrompt && n > 0 != (err == nil) {
		return false, fmt.Errorf("%d provider invocations with error %w", n, err)
	}
	return n > 0, nil
}

// checkAccepted: accepted implies no decoded text holds a secret.
func checkAccepted(raw string, asPrompt bool) error {
	ok, err := reaches(raw, asPrompt)
	if err != nil || !ok {
		return err
	}
	texts, err := decodedTexts(raw)
	if err != nil {
		return fmt.Errorf("accepted schema does not decode: %w", err)
	}
	if slices.ContainsFunc(texts, redact.New().ContainsSecret) {
		return errors.New("accepted schema holds a secret once decoded")
	}
	return nil
}

// TestSchemaSecretProperty: every positive case, at every placement, as a tool
// or a prompt schema. At least one case hides its secret from the raw bytes,
// so that the property is not vacuous.
func TestSchemaSecretProperty(t *testing.T) {
	ins := redact.PositiveInputs()
	if len(ins) < 50 {
		t.Fatalf("%d positive cases", len(ins))
	}
	hidden := 0
	for i, in := range ins {
		if !redact.New().ContainsSecret(in) {
			t.Fatalf("positive case %d is not a secret", i)
		}
		for name, place := range placements {
			raw := place(jsonText(in))
			if !redact.New().ContainsSecret(raw) {
				hidden++
			}
			for _, asPrompt := range []bool{false, true} {
				if err := checkAccepted(raw, asPrompt); err != nil {
					t.Errorf("positive case %d, %s, prompt %v: %v", i, name, asPrompt, err)
				}
			}
		}
	}
	if hidden == 0 {
		t.Fatal("no case hides its secret from the raw bytes: vacuous property")
	}
	t.Logf("%d placements hide the secret from the raw bytes", hidden)
	for _, asPrompt := range []bool{false, true} { // witness: a clean schema reaches the provider
		if ok, err := reaches(placements["description"]("Look up a record."), asPrompt); !ok || err != nil {
			t.Fatalf("witness, prompt %v: reached %v, %v", asPrompt, ok, err)
		}
	}
}

// TestSchemaSecretPropertyWrapped: the same property with admitted text
// around the secret, drawn by rapid.
func TestSchemaSecretPropertyWrapped(t *testing.T) {
	ins := redact.PositiveInputs()
	names := make([]string, 0, len(placements))
	for name := range placements {
		names = append(names, name)
	}
	slices.Sort(names)
	around := rapid.StringOf(rapid.SampledFrom([]rune("ab Z9:=,{}[]-_\"\\\n")))
	rapid.Check(t, func(rt *rapid.T) {
		in := rapid.SampledFrom(ins).Draw(rt, "secret")
		name := rapid.SampledFrom(names).Draw(rt, "placement")
		text := around.Draw(rt, "prefix") + in + around.Draw(rt, "suffix")
		asPrompt := rapid.Bool().Draw(rt, "prompt")
		if err := checkAccepted(placements[name](jsonText(text)), asPrompt); err != nil {
			rt.Fatal(err)
		}
	})
}

// namedPlacements put a value v under a property called name, where the model
// reads the value together with the name (obligation (aa), D8).
var namedPlacements = map[string]func(name, v string) string{
	"const": func(name, v string) string { return namedObject(name, `{"const":"`+v+`"}`, "") },
	"enum":  func(name, v string) string { return namedObject(name, `{"type":"string","enum":["`+v+`"]}`, "") },
	"pattern": func(name, v string) string {
		return namedObject(name, `{"type":"string","pattern":"^`+v+`$"}`, "")
	},
	"ref enum": func(name, v string) string {
		return namedObject(name, `{"$ref":"#/$defs/l"}`, `{"l":{"enum":["`+v+`"]}}`)
	},
	"const object": func(name, v string) string {
		return namedObject(name, `{"const":{"`+name+`":"\n`+v+`"}}`, "")
	},
}

func namedObject(name, sub, defs string) string {
	s := `{"type":"object","additionalProperties":false,"required":["` + name + `"],"properties":{"` + name + `":` + sub + `}`
	if defs != "" {
		s += `,"$defs":` + defs
	}
	return s + `}`
}

// TestSchemaNamedValueProperty: a value that is a secret only when read with
// its property name ("api_key: v") never reaches the provider, whatever its
// placement, as a tool or a prompt schema. The oracle is the redactor applied
// to "api_key: " + v, computed here apart from schema.Texts; the same value
// under a neutral name reaches the provider, so that the refusal comes from
// the name. A run that retains no value fails (vacuous property).
func TestSchemaNamedValueProperty(t *testing.T) {
	r := redact.New()
	names := make([]string, 0, len(namedPlacements))
	for name := range namedPlacements {
		names = append(names, name)
	}
	slices.Sort(names)
	kept := 0
	rapid.Check(t, func(rt *rapid.T) {
		v := "FAKE" + rapid.StringMatching(`[A-Za-z0-9]{12,36}`).Draw(rt, "tail")
		if r.ContainsSecret(v) || !r.ContainsSecret("api_key: "+v) {
			return
		}
		kept++
		for _, name := range names {
			for _, asPrompt := range []bool{false, true} {
				ok, err := reaches(namedPlacements[name]("api_key", v), asPrompt)
				if err != nil || ok {
					rt.Fatalf("%s, prompt %v: value under api_key reached the provider (%v, %v)", name, asPrompt, ok, err)
				}
				if ok, err := reaches(namedPlacements[name]("note", v), asPrompt); !ok || err != nil {
					rt.Fatalf("%s, prompt %v: witness under note did not reach the provider (%v, %v)", name, asPrompt, ok, err)
				}
			}
		}
	})
	if kept == 0 {
		t.Fatal("no drawn value is a secret only with its name: vacuous property")
	}
	t.Logf("%d values retained", kept)
}
