package openbao

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amezianechayer/rempart/internal/secrets/ports"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// White-box tests of the hardened OpenBao client (docs/plans/M1-envelope-transit.md
// D4, D5, U9), against httptest servers on 127.0.0.1.

const (
	testToken   = "s.TestWorkerToken-canary-7f3a"
	demoTenant  = tenancy.ID("0d3e0000-0000-4000-8000-000000000001")
	demoKeyName = "rempart-tenant-0d3e0000-0000-4000-8000-000000000001"
	bodyCanary  = "BODY-CANARY-91c4e2"
	wrappedDEK  = "vault:v1:d3JhcHBlZC1kZWstb3BhcXVlLWJ5dGVz"
)

var _ ports.KeyWrapper = (*Transit)(nil)

// dek32 is the plaintext DEK served by the fake Transit server.
var dek32 = bytes.Repeat([]byte{0xa5}, 32)

type recordedRequest struct {
	method, path, rawQuery, token string
	headers                       http.Header
	body                          []byte
}

// transitServer is a fake Transit endpoint on 127.0.0.1 that records requests.
type transitServer struct {
	*httptest.Server
	mu       sync.Mutex
	requests []recordedRequest
}

func newTransitServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, body []byte)) *transitServer {
	t.Helper()
	ts := &transitServer{}
	ts.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		ts.mu.Lock()
		ts.requests = append(ts.requests, recordedRequest{
			method: r.Method, path: r.URL.Path, rawQuery: r.URL.RawQuery,
			token: r.Header.Get("X-Vault-Token"), headers: r.Header.Clone(), body: body,
		})
		ts.mu.Unlock()
		handler(w, r, body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func (ts *transitServer) recorded() []recordedRequest {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return append([]recordedRequest(nil), ts.requests...)
}

// okHandler answers datakey/plaintext and decrypt like Transit.
func okHandler(w http.ResponseWriter, r *http.Request, _ []byte) {
	w.Header().Set("Content-Type", "application/json")
	switch {
	case strings.Contains(r.URL.Path, "/datakey/plaintext/"):
		_, _ = fmt.Fprintf(w, `{"data":{"plaintext":%q,"ciphertext":%q,"key_version":1}}`,
			base64.StdEncoding.EncodeToString(dek32), wrappedDEK)
	case strings.Contains(r.URL.Path, "/decrypt/"):
		_, _ = fmt.Fprintf(w, `{"data":{"plaintext":%q}}`, base64.StdEncoding.EncodeToString(dek32))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func newTestTransit(t *testing.T, addr string) (*Transit, Config) {
	t.Helper()
	cfg := Config{Addr: addr, Token: secret.New(testToken), Timeout: 5 * time.Second}
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient(%s): %v", addr, err)
	}
	tr, err := NewTransit(c, "")
	if err != nil {
		t.Fatalf("NewTransit(c, \"\"): %v", err)
	}
	return tr, cfg
}

// findTransports collects every http.Transport reachable from v, unexported
// fields included (read only: Value.IsNil works without Interface).
func findTransports(v reflect.Value, seen map[uintptr]bool, out *[]reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() || seen[v.Pointer()] {
			return
		}
		seen[v.Pointer()] = true
		findTransports(v.Elem(), seen, out)
	case reflect.Interface:
		if !v.IsNil() {
			findTransports(v.Elem(), seen, out)
		}
	case reflect.Struct:
		if v.Type() == reflect.TypeFor[http.Transport]() {
			*out = append(*out, v)
			return
		}
		for i := range v.NumField() {
			findTransports(v.Field(i), seen, out)
		}
	default:
	}
}

func TestTransitClientHardened(t *testing.T) {
	ctx := context.Background()

	t.Run("request_shape", func(t *testing.T) {
		ts := newTransitServer(t, okHandler)
		tr, _ := newTestTransit(t, ts.URL)

		plain, wrapped, err := tr.GenerateDataKey(ctx, demoTenant)
		if err != nil {
			t.Fatalf("GenerateDataKey: %v", err)
		}
		if !bytes.Equal(plain.Reveal(), dek32) || string(wrapped) != wrappedDEK {
			t.Errorf("GenerateDataKey returned a %d-byte DEK and wrapped %q, want the served DEK and ciphertext unchanged", plain.Len(), wrapped)
		}
		unwrapped, err := tr.UnwrapDataKey(ctx, demoTenant, wrapped)
		if err != nil {
			t.Fatalf("UnwrapDataKey: %v", err)
		}
		if !bytes.Equal(unwrapped.Reveal(), dek32) {
			t.Errorf("UnwrapDataKey returned a %d-byte DEK, want the served DEK", unwrapped.Len())
		}

		reqs := ts.recorded()
		if len(reqs) != 2 {
			t.Fatalf("%d requests, want 2", len(reqs))
		}
		for i, want := range []struct {
			path string
			body map[string]any
		}{
			{"/v1/transit/datakey/plaintext/" + demoKeyName, map[string]any{"bits": float64(256)}},
			{"/v1/transit/decrypt/" + demoKeyName, map[string]any{"ciphertext": wrappedDEK}},
		} {
			r := reqs[i]
			if r.method != http.MethodPost || r.path != want.path {
				t.Errorf("request %d: %s %s, want POST %s", i, r.method, r.path, want.path)
			}
			var body map[string]any
			if err := json.Unmarshal(r.body, &body); err != nil || !reflect.DeepEqual(body, want.body) {
				t.Errorf("request %d: body %s, want %v", i, r.body, want.body)
			}
			if r.token != testToken {
				t.Errorf("request %d: X-Vault-Token is not the configured token", i)
			}
			if strings.Contains(r.path+"?"+r.rawQuery, testToken) || bytes.Contains(r.body, []byte(testToken)) {
				t.Errorf("request %d: the token appears in the URL or the body", i)
			}
			for name, values := range r.headers {
				if name != "X-Vault-Token" && strings.Contains(strings.Join(values, ","), testToken) {
					t.Errorf("request %d: the token appears in header %s", i, name)
				}
			}
		}
	})

	t.Run("redirect_not_followed", func(t *testing.T) {
		var visits atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			visits.Add(1)
			okHandler(w, r, nil)
		}))
		t.Cleanup(target.Close)
		ts := newTransitServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
			location := target.URL + "/v1/transit/decrypt/" + demoKeyName
			if strings.Contains(r.URL.Path, "/datakey/") {
				location = target.URL + "/v1/transit/datakey/plaintext/" + demoKeyName
			}
			w.Header().Set("Location", location)
			w.WriteHeader(http.StatusTemporaryRedirect)
		})
		tr, _ := newTestTransit(t, ts.URL)
		if _, _, err := tr.GenerateDataKey(ctx, demoTenant); err == nil {
			t.Errorf("GenerateDataKey after a 307: no error, want an error")
		}
		if _, err := tr.UnwrapDataKey(ctx, demoTenant, []byte(wrappedDEK)); err == nil {
			t.Errorf("UnwrapDataKey after a 307: no error, want an error")
		}
		if n := visits.Load(); n != 0 {
			t.Errorf("the redirect target was visited %d times, want 0 (redirects are never followed)", n)
		}
	})

	t.Run("no_env_proxy", func(t *testing.T) {
		c, err := NewClient(Config{Addr: "https://openbao.example:8200", Token: secret.New(testToken)})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		var transports []reflect.Value
		findTransports(reflect.ValueOf(c), map[uintptr]bool{}, &transports)
		if len(transports) == 0 {
			t.Fatalf("no *http.Transport reachable from the Client: the client must build its own transport")
		}
		for i, tr := range transports {
			if !tr.FieldByName("Proxy").IsNil() {
				t.Errorf("transport %d: Proxy is set, want nil (no proxy from the environment)", i)
			}
		}
	})

	t.Run("error_without_body_or_token", func(t *testing.T) {
		// The body echoes the token the client sends (request_shape proves it is testToken).
		ts := newTransitServer(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = fmt.Fprintf(w, `{"errors":["%s token=%s"]}`, bodyCanary, testToken)
		})
		tr, cfg := newTestTransit(t, ts.URL)
		_, _, genErr := tr.GenerateDataKey(ctx, demoTenant)
		_, unwrapErr := tr.UnwrapDataKey(ctx, demoTenant, []byte(wrappedDEK))
		for name, err := range map[string]error{"GenerateDataKey": genErr, "UnwrapDataKey": unwrapErr} {
			if err == nil {
				t.Errorf("%s on a 500: no error", name)
				continue
			}
			msg := fmt.Sprintf("%v | %+v | %#v", err, err, err)
			if strings.Contains(msg, bodyCanary) || strings.Contains(msg, testToken) {
				t.Errorf("%s: the error carries the response body or the token", name)
			}
			if !errors.Is(err, ErrStatus) || errors.Is(err, ports.ErrWrappedKeyRejected) {
				t.Errorf("%s: error %v, want ErrStatus and not ErrWrappedKeyRejected", name, err)
			}
			if !strings.Contains(err.Error(), "500") {
				t.Errorf("%s: error %q does not name the HTTP status", name, err)
			}
		}
		c, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		for _, v := range []any{cfg, c, tr} {
			if s := fmt.Sprintf("%+v %#v %v", v, v, v); strings.Contains(s, testToken) {
				t.Errorf("printing a %T reveals the token", v)
			}
		}
	})

	t.Run("body_bounded", func(t *testing.T) {
		ts := newTransitServer(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"data":{"plaintext":%q,"ciphertext":%q},"padding":"%s"}`,
				base64.StdEncoding.EncodeToString(dek32), wrappedDEK, strings.Repeat("A", 2<<20))
		})
		tr, _ := newTestTransit(t, ts.URL)
		if plain, _, err := tr.GenerateDataKey(ctx, demoTenant); err == nil {
			t.Errorf("GenerateDataKey accepted a 2 MiB response (%d-byte DEK), want an error (body bounded to 64 KiB)", plain.Len())
		}
		if _, err := tr.UnwrapDataKey(ctx, demoTenant, []byte(wrappedDEK)); err == nil {
			t.Errorf("UnwrapDataKey accepted a 2 MiB response, want an error")
		}
	})

	t.Run("unwrap_400", func(t *testing.T) {
		ts := newTransitServer(t, func(w http.ResponseWriter, _ *http.Request, _ []byte) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"errors":["cipher: message authentication failed"]}`)
		})
		tr, _ := newTestTransit(t, ts.URL)
		plain, err := tr.UnwrapDataKey(ctx, demoTenant, []byte(wrappedDEK))
		if !errors.Is(err, ports.ErrWrappedKeyRejected) {
			t.Errorf("UnwrapDataKey on a 400: error %v, want ports.ErrWrappedKeyRejected", err)
		}
		if !plain.IsZero() {
			t.Errorf("UnwrapDataKey on a 400 returned a %d-byte DEK", plain.Len())
		}
	})

	t.Run("plaintext_length", func(t *testing.T) {
		short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
		ts := newTransitServer(t, func(w http.ResponseWriter, r *http.Request, _ []byte) {
			if strings.Contains(r.URL.Path, "/datakey/") {
				_, _ = fmt.Fprintf(w, `{"data":{"plaintext":%q,"ciphertext":%q}}`, short, wrappedDEK)
				return
			}
			_, _ = fmt.Fprintf(w, `{"data":{"plaintext":%q}}`, short)
		})
		tr, _ := newTestTransit(t, ts.URL)
		plain, wrapped, err := tr.GenerateDataKey(ctx, demoTenant)
		if err == nil || !plain.IsZero() || wrapped != nil {
			t.Errorf("GenerateDataKey with a 16-byte DEK: %d-byte DEK, wrapped %q, error %v, want an error and nothing else", plain.Len(), wrapped, err)
		}
		plain, err = tr.UnwrapDataKey(ctx, demoTenant, []byte(wrappedDEK))
		if err == nil || !plain.IsZero() {
			t.Errorf("UnwrapDataKey with a 16-byte DEK: %d-byte DEK, error %v, want an error", plain.Len(), err)
		}
	})

	t.Run("invalid_tenant_no_request", func(t *testing.T) {
		ts := newTransitServer(t, okHandler)
		tr, _ := newTestTransit(t, ts.URL)
		for _, id := range []tenancy.ID{
			"x",
			"",
			"00000000-0000-8000-8000-00000000000A", // System with an upper-case digit
			" 00000000-0000-8000-8000-000000000001",
			"00000000-0000-8000-8000-000000000001/../../../sys/policies/acl/root",
			"../../sys/policies/acl/rempart-worker",
		} {
			if plain, _, err := tr.GenerateDataKey(ctx, id); err == nil || !plain.IsZero() {
				t.Errorf("GenerateDataKey(%q): error %v, want an error", id, err)
			}
			if plain, err := tr.UnwrapDataKey(ctx, id, []byte(wrappedDEK)); err == nil || !plain.IsZero() {
				t.Errorf("UnwrapDataKey(%q): error %v, want an error", id, err)
			}
		}
		if n := len(ts.recorded()); n != 0 {
			t.Errorf("%d requests sent for invalid tenants, want 0 (T35)", n)
		}
	})

	t.Run("address_rules", func(t *testing.T) {
		tok := secret.New(testToken)
		for _, c := range []struct {
			name string
			cfg  Config
			ok   bool
		}{
			{"https_host", Config{Addr: "https://h:8200", Token: tok}, true},
			{"http_loopback_v4", Config{Addr: "http://127.0.0.1:8200", Token: tok}, true},
			{"http_loopback_v6", Config{Addr: "http://[::1]:8200", Token: tok}, true},
			{"timeout_60s", Config{Addr: "https://h:8200", Token: tok, Timeout: 60 * time.Second}, true},
			{"http_private_ip", Config{Addr: "http://10.0.0.1:8200", Token: tok}, false},
			{"http_localhost_name", Config{Addr: "http://localhost:8200", Token: tok}, false},
			{"userinfo", Config{Addr: "https://u:p@h", Token: tok}, false}, //nolint:gosec // G101: fixture of a refused address, not a credential.
			{"path", Config{Addr: "https://h:8200/v1", Token: tok}, false},
			{"query", Config{Addr: "https://h:8200?x=1", Token: tok}, false},
			{"fragment", Config{Addr: "https://h:8200#f", Token: tok}, false},
			{"other_scheme", Config{Addr: "ftp://h:8200", Token: tok}, false},
			{"no_scheme", Config{Addr: "h:8200", Token: tok}, false},
			{"empty", Config{Addr: "", Token: tok}, false},
			{"no_token", Config{Addr: "https://h:8200"}, false},
			{"timeout_61s", Config{Addr: "https://h:8200", Token: tok, Timeout: 61 * time.Second}, false},
		} {
			cl, err := NewClient(c.cfg)
			switch {
			case c.ok && (err != nil || cl == nil):
				t.Errorf("%s: NewClient(%q): %v, want a client", c.name, c.cfg.Addr, err)
			case !c.ok && !errors.Is(err, ErrConfig):
				t.Errorf("%s: NewClient(%q): error %v, want ErrConfig", c.name, c.cfg.Addr, err)
			case !c.ok && err != nil && strings.Contains(err.Error(), testToken):
				t.Errorf("%s: the error reveals the token", c.name)
			}
		}

		cl, err := NewClient(Config{Addr: "https://h:8200", Token: tok})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		for _, mount := range []string{"Transit", "transit/", "../sys", "a b", strings.Repeat("a", 65)} {
			if tr, err := NewTransit(cl, mount); err == nil || tr != nil {
				t.Errorf("NewTransit(c, %q): error %v, want an error and no Transit", mount, err)
			}
		}
		if _, err := NewTransit(nil, ""); err == nil {
			t.Errorf("NewTransit(nil, \"\"): no error")
		}
	})
}
