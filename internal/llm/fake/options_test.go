package fake

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"testing/fstest"

	"github.com/amezianechayer/rempart/internal/llm/domain"
)

// Test 6.
func TestLoadOptionsRejectsUnknownFields(t *testing.T) {
	t.Run("scripted.json", func(t *testing.T) {
		opt, err := LoadOptions(os.DirFS("testdata"), "scripted.json")
		if err != nil {
			t.Fatalf("LoadOptions: %v", err)
		}
		wantScripts := map[string][]Step{testPromptID: {
			{Response: domain.Response{Output: json.RawMessage(`{"greeting":"bonjour"}`), Model: "fake-model-v1", RequestID: "fake-req-1"}},
			{Err: "provider_unavailable"},
		}}
		if !reflect.DeepEqual(opt.Scripts, wantScripts) {
			t.Errorf("Scripts = %+v, want %+v", opt.Scripts, wantScripts)
		}
		if len(opt.Recordings) != 0 {
			t.Errorf("Recordings = %+v, want none from a file", opt.Recordings)
		}
		wantCaps := domain.Capabilities{NativeStructuredOutput: true, StrictTools: true, RequiresRetention: false}
		wantModels := map[string]domain.Capabilities{"fake-model-v1": wantCaps}
		if !reflect.DeepEqual(opt.Models, wantModels) {
			t.Errorf("Models = %+v, want %+v", opt.Models, wantModels)
		}

		p := mustNew(t, opt)
		if got := p.Capabilities(fakeRoute()); got != wantCaps {
			t.Errorf("Capabilities = %+v, want %+v", got, wantCaps)
		}
		ctx := context.Background()
		got, err := p.Structured(ctx, fakeRoute(), reqQ())
		assertResponse(t, "step 1", got, err, wantScripts[testPromptID][0].Response)
		got, err = p.Structured(ctx, fakeRoute(), reqQ())
		if !errors.Is(err, ErrScripted) || !isZeroResponse(got) {
			t.Errorf("step 2 = %+v, %v, want ErrScripted", got, err)
		}
		got, err = p.Structured(ctx, fakeRoute(), reqQ())
		if !errors.Is(err, ErrScriptExhausted) || !isZeroResponse(got) {
			t.Errorf("step 3 = %+v, %v, want ErrScriptExhausted", got, err)
		}
	})

	const limit = 1 << 20
	padded := func(n int) []byte {
		b := []byte(`{"version":1}`)
		return append(b, bytes.Repeat([]byte(" "), n-len(b))...)
	}

	accepted := fstest.MapFS{
		"minimal.json":    {Data: []byte(`{"version":1}`)},
		"at_limit.json":   {Data: padded(limit)},
		"raw_output.json": {Data: []byte(`{"version":1,"scripts":{"demo.raw.v1":[{"response":{"output":"not json"}}]}}`)},
	}
	for _, name := range []string{"minimal.json", "at_limit.json"} {
		t.Run("accepts "+name, func(t *testing.T) {
			opt, err := LoadOptions(accepted, name)
			if err != nil {
				t.Fatalf("LoadOptions: %v", err)
			}
			mustNew(t, opt)
		})
	}
	t.Run("output is kept raw", func(t *testing.T) {
		opt, err := LoadOptions(accepted, "raw_output.json")
		if err != nil {
			t.Fatalf("LoadOptions: %v", err)
		}
		steps := opt.Scripts["demo.raw.v1"]
		if len(steps) != 1 || string(steps[0].Response.Output) != "not json" {
			t.Errorf("Scripts = %+v, want one step with the raw output", opt.Scripts)
		}
	})

	rejected := map[string]string{
		"unknown root field":           `{"version":1,"extra":true}`,
		"unknown response field":       `{"version":1,"scripts":{"demo.a.v1":[{"response":{"output":"{}","usage":{}}}]}}`,
		"unknown step field":           `{"version":1,"scripts":{"demo.a.v1":[{"response":{"output":"{}"},"delay":1}]}}`,
		"unknown model field":          `{"version":1,"models":{"fake-model-v1":{"requires_retention":true,"region":"local"}}}`,
		"recordings":                   `{"version":1,"recordings":[]}`,
		"second document":              `{"version":1}{"version":1}`,
		"trailing garbage":             `{"version":1} x`,
		"version 0":                    `{"version":0}`,
		"version 2":                    `{"version":2}`,
		"version absent":               `{"scripts":{}}`,
		"version as string":            `{"version":"1"}`,
		"not json":                     `not json`,
		"empty file":                   ``,
		"output as an object":          `{"version":1,"scripts":{"demo.a.v1":[{"response":{"output":{"a":1}}}]}}`,
		"requires_retention absent":    `{"version":1,"models":{"fake-model-v1":{"native_structured_output":true,"strict_tools":true}}}`,
		"requires_retention null":      `{"version":1,"models":{"fake-model-v1":{"requires_retention":null}}}`,
		"requires_retention as string": `{"version":1,"models":{"fake-model-v1":{"requires_retention":"false"}}}`,
	}
	fsys := fstest.MapFS{"too_large.json": {Data: padded(limit + 1)}}
	for name, doc := range rejected {
		fsys[name+".json"] = &fstest.MapFile{Data: []byte(doc)}
	}
	names := []string{"too_large.json", "absent.json"}
	for name := range rejected {
		names = append(names, name+".json")
	}
	for _, name := range names {
		t.Run("rejects "+name, func(t *testing.T) {
			opt, err := LoadOptions(fsys, name)
			if !errors.Is(err, ErrInvalidOptions) {
				t.Errorf("error = %v, want ErrInvalidOptions", err)
			}
			if !reflect.DeepEqual(opt, Options{}) {
				t.Errorf("options = %+v returned with an error, want zero", opt)
			}
		})
	}

	// LoadOptions output goes through New, which checks it again.
	t.Run("New checks loaded options", func(t *testing.T) {
		bad := fstest.MapFS{"err_and_output.json": {Data: []byte(
			`{"version":1,"scripts":{"demo.a.v1":[{"response":{"output":"{}"},"err":"provider_unavailable"}]}}`,
		)}}
		opt, err := LoadOptions(bad, "err_and_output.json")
		if err != nil {
			t.Fatalf("LoadOptions: %v", err)
		}
		if p, err := New(opt); !errors.Is(err, ErrInvalidOptions) || p != nil {
			t.Errorf("New = %v, %v, want nil and ErrInvalidOptions", p, err)
		}
	})
}
