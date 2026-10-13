package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"

	"github.com/amezianechayer/rempart/internal/loops/demo/activities"
	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	secretsfake "github.com/amezianechayer/rempart/internal/secrets/fake"
)

// M1-T02 (lean mode): the worker seals every Temporal payload with the codec
// of Rempart, over a Transit token unwrapped from standard input (D9, O5).

const testWrapping = "s.WrapCanary-5e1d"

// testSealer seals with the fake key wrapper (tests only, rule
// secrets-fake-dev-only).
func testSealer(t *testing.T) *envelope.Sealer {
	t.Helper()
	s, err := envelope.NewSealer(secretsfake.NewKeyWrapper([32]byte{0x57}), envelope.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// fakeOpenBao answers sys/wrapping/unwrap with a rempart-worker token.
func fakeOpenBao(t *testing.T) string {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/sys/wrapping/unwrap" || r.Header.Get("X-Vault-Token") != testWrapping {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"auth":{"client_token":"s.worker","policies":["rempart-worker"],`+
			`"token_policies":["rempart-worker"],"lease_duration":600}}`)
	}))
	t.Cleanup(ts.Close)
	return ts.URL
}

// registry counts the registrations of the demo.
type registry struct{ n int }

func (r *registry) RegisterWorkflowWithOptions(any, workflow.RegisterOptions) { r.n++ }
func (r *registry) RegisterActivityWithOptions(any, activity.RegisterOptions) { r.n++ }

// TestWorkerRequiresRempartConverter (N10, §4.1 of the threat model):
// registerDemo refuses options without the three converters of Rempart, of
// one same set, and registers nothing; the options of clientOptions pass.
func TestWorkerRequiresRempartConverter(t *testing.T) {
	t.Chdir("../..")
	cfg := demoConfig()
	cl, err := fakeClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	a := &activities.Activities{LLM: cl, Tenant: cfg.Tenant}
	good, err := clientOptions(cfg, testSealer(t))
	if err != nil {
		t.Fatalf("clientOptions: %v", err)
	}
	other, err := clientOptions(cfg, testSealer(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clientOptions(cfg, nil); err == nil {
		t.Error("clientOptions with a nil sealer succeeded")
	}
	for name, edit := range map[string]func(*client.Options){
		"no_converter": func(o *client.Options) {
			o.DataConverter, o.FailureConverter, o.ContextPropagators = nil, nil, nil
		},
		"default_data_converter":    func(o *client.Options) { o.DataConverter = converter.GetDefaultDataConverter() },
		"default_failure_converter": func(o *client.Options) { o.FailureConverter = temporal.GetDefaultFailureConverter() },
		"no_propagator":             func(o *client.Options) { o.ContextPropagators = nil },
		"two_propagators": func(o *client.Options) {
			o.ContextPropagators = append(o.ContextPropagators[:1:1], o.ContextPropagators[0])
		},
		"mixed_sets": func(o *client.Options) { o.FailureConverter = other.FailureConverter },
	} {
		t.Run(name, func(t *testing.T) {
			o := good
			edit(&o)
			r := &registry{}
			if err := registerDemo(r, o, a, denyAll{}); !errors.Is(err, ErrConverterRequired) || r.n != 0 {
				t.Errorf("registerDemo = %v with %d registrations, want ErrConverterRequired and none", err, r.n)
			}
		})
	}
	r := &registry{}
	if err := registerDemo(r, good, a, denyAll{}); err != nil || r.n == 0 {
		t.Errorf("registerDemo(clientOptions) = %v with %d registrations, want the demo registered", err, r.n)
	}
}

// TestReadWrappingToken (T95): one line of at most 256 bytes of
// [A-Za-z0-9._-], a final newline admitted; the token is never quoted.
func TestReadWrappingToken(t *testing.T) {
	got, err := readWrappingToken(strings.NewReader(testWrapping + "\n"))
	if err != nil || got.Reveal() != testWrapping {
		t.Fatalf("readWrappingToken = %d bytes, %v; want the token", len(got.Reveal()), err)
	}
	if got, err := readWrappingToken(strings.NewReader("hvs.CAES-x_y.z")); err != nil || got.Reveal() != "hvs.CAES-x_y.z" {
		t.Errorf("token without newline refused: %v", err)
	}
	for name, in := range map[string]string{
		"empty": "", "newline_only": "\n", "space": "s.a b\n", "two_lines": "s.a\ns.b\n",
		"crlf": "s.a\r\n", "too_long": strings.Repeat("a", 257), "quote": `s."a"`,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := readWrappingToken(strings.NewReader(in))
			if err == nil || !got.IsZero() {
				t.Fatalf("readWrappingToken(%q) accepted", in)
			}
			if q := strings.TrimSpace(in); q != "" && strings.Contains(err.Error(), q) {
				t.Errorf("error %q quotes the input", err)
			}
		})
	}
}

// TestOpenBaoAddress (D9): -openbao-addr is required, http on 127.0.0.1 or
// [::1] with a port only.
func TestOpenBaoAddress(t *testing.T) {
	refused(t, withFlag("openbao-addr"), ErrConfig)
	for _, bad := range []string{
		"http://10.0.0.1:8200", "http://localhost:8200", "http://127.0.0.1:8200/v1", "http://u@127.0.0.1:8200",
		"https://example.com", "http://127.0.0.1", "127.0.0.1:8200", "http://127.0.0.1:8200?x=1",
	} {
		refused(t, withFlag("openbao-addr", "-openbao-addr="+bad), ErrConfig, bad)
	}
	cfg, err := LoadConfig(withFlag("openbao-addr", "-openbao-addr=http://[::1]:8200"))
	if err != nil || cfg.OpenBaoAddress != "http://[::1]:8200" {
		t.Errorf("LoadConfig([::1]) = %+v, %v", cfg, err)
	}
}
