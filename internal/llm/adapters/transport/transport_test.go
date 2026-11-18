package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestTransportInjectionRefused (ADR 0008 D6, obligation (ay), T47): a new
// transport has no proxy; an injected one is refused unless it is a plain
// *http.Transport without proxy, custom dialers, TLS configuration or
// protocol upgrade hooks.
func TestTransportInjectionRefused(t *testing.T) {
	rt, err := Harden(nil)
	if err != nil {
		t.Fatalf("Harden(nil): %v", err)
	}
	if tr, ok := rt.(*http.Transport); !ok || tr.Proxy != nil {
		t.Fatalf("Harden(nil) = %T with a proxy, want a *http.Transport without proxy", rt)
	}
	if _, err := Harden(&http.Transport{}); err != nil {
		t.Errorf("plain transport refused: %v", err)
	}
	dial := func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("x") }
	plainDial := func(string, string) (net.Conn, error) { return nil, errors.New("x") }
	verify := func([][]byte, [][]*x509.Certificate) error { return nil }
	for name, tr := range map[string]http.RoundTripper{
		"proxy":        &http.Transport{Proxy: http.ProxyFromEnvironment},
		"dial":         &http.Transport{Dial: plainDial}, //nolint:staticcheck // SA1019: the deprecated hook must be refused too.
		"dial_context": &http.Transport{DialContext: dial},
		"dial_tls":     &http.Transport{DialTLS: plainDial}, //nolint:staticcheck // SA1019: idem.
		"dial_tls_ctx": &http.Transport{DialTLSContext: dial},
		"proxy_header": &http.Transport{GetProxyConnectHeader: func(context.Context, *url.URL, string) (http.Header, error) {
			return nil, nil
		}},
		"proxy_response": &http.Transport{OnProxyConnectResponse: func(context.Context, *url.URL, *http.Request, *http.Response) error {
			return nil
		}},
		"tls_next_proto":  &http.Transport{TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}},
		"tls_insecure":    &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // G402: refused by Harden, the point of the test.
		"tls_keylog":      &http.Transport{TLSClientConfig: &tls.Config{KeyLogWriter: io.Discard}},
		"tls_server_name": &http.Transport{TLSClientConfig: &tls.Config{ServerName: "x"}},
		"tls_verify_peer": &http.Transport{TLSClientConfig: &tls.Config{VerifyPeerCertificate: verify}}, //nolint:gosec // G123: refused by Harden, the point of the test.
		"not_a_transport": roundTripFunc(func(*http.Request) (*http.Response, error) { return nil, errors.New("x") }),
	} {
		if _, err := Harden(tr); !errors.Is(err, ErrTransportRefused) {
			t.Errorf("%s: Harden = %v, want ErrTransportRefused", name, err)
		}
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// TestClientBoundsAndRedirects (T49, T22): no redirect, a mandatory timeout,
// a response body bounded to MaxResponseBytes.
func TestClientBoundsAndRedirects(t *testing.T) {
	big := strings.Repeat("a", MaxResponseBytes+1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/ok", http.StatusFound)
		case "/big":
			_, _ = io.WriteString(w, big)
		default:
			_, _ = io.WriteString(w, "ok")
		}
	}))
	defer ts.Close()
	rt, err := Harden(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Client(rt, 0); !errors.Is(err, ErrTransportRefused) {
		t.Errorf("Client without timeout: %v, want ErrTransportRefused", err)
	}
	c, err := Client(rt, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/redirect", nil)
	if resp, err := c.Do(req); err == nil {
		_ = resp.Body.Close()
		t.Error("redirect followed")
	}
	req, _ = http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/big", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if _, err := io.ReadAll(resp.Body); !errors.Is(err, ErrResponseTooLarge) {
		t.Errorf("reading a body over the bound: %v, want ErrResponseTooLarge", err)
	}
}

// TestFreshTransportExplicit (obligation (dx), T47): a new transport is built
// field by field, never cloned from http.DefaultTransport (a package could
// have replaced it with a dialer, a proxy or a TLS configuration); an
// injected transport is cloned, so that a later change by its owner does not
// reach the hardened one.
func TestFreshTransportExplicit(t *testing.T) {
	saved := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = saved })
	dialed := false
	http.DefaultTransport = &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: "127.0.0.1:1"}),
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			dialed = true
			return nil, errors.New("hooked")
		},
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // G402: the hook the test proves absent
	}
	rt, err := Harden(nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := rt.(*http.Transport)
	if !ok || tr.Proxy != nil || tr.DialContext == nil || tr.TLSClientConfig != nil {
		t.Fatalf("fresh transport %+v: want no proxy, an own dialer, no TLS configuration", rt)
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "127.0.0.1:1"); dialed {
		t.Errorf("fresh transport dials with the hook of http.DefaultTransport (%v)", err)
	}

	injected := &http.Transport{}
	got, err := Harden(injected)
	if err != nil {
		t.Fatal(err)
	}
	if got == http.RoundTripper(injected) {
		t.Fatal("injected transport returned as is, want a clone")
	}
	injected.Proxy = http.ProxyFromEnvironment
	if gt, ok := got.(*http.Transport); !ok || gt.Proxy != nil {
		t.Error("a change of the injected transport reaches the hardened one")
	}
}
