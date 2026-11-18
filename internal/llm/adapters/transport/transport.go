// Package transport is the hardened HTTP transport shared by the model
// adapters (ADR 0008 D6, obligation (ay), T47, T49): no proxy, no injected
// dialer, TLS configuration or protocol hook, no redirect, a mandatory
// timeout and a bounded response body.
package transport

import (
	"errors"
	"io"
	"net"
	"net/http"
	"time"
)

const (
	MaxResponseBytes = 1 << 20
	MaxTimeout       = 10 * time.Minute
)

var (
	ErrTransportRefused = errors.New("transport: refused transport or timeout")
	ErrResponseTooLarge = errors.New("transport: response body too large")
	ErrRedirectRefused  = errors.New("transport: redirect refused")
)

// Harden returns a new transport without proxy for nil; an injected transport
// must be a plain *http.Transport: no proxy, no dialer, no TLS configuration,
// no protocol upgrade hook (TLSNextProto receives the decrypted connection).
func Harden(rt http.RoundTripper) (http.RoundTripper, error) {
	if rt == nil {
		return fresh(), nil
	}
	t, ok := rt.(*http.Transport)
	if !ok || t == nil || t.Proxy != nil || t.Dial != nil || t.DialContext != nil || t.DialTLS != nil || //nolint:staticcheck // SA1019: the deprecated hooks are refused too
		t.DialTLSContext != nil || t.GetProxyConnectHeader != nil || t.OnProxyConnectResponse != nil ||
		t.TLSNextProto != nil || t.TLSClientConfig != nil {
		return nil, ErrTransportRefused
	}
	return t.Clone(), nil // (dx): a later change by its owner does not reach the hardened transport
}

// fresh builds the transport field by field (obligation (dx), T47): never a
// clone of http.DefaultTransport, which any package can replace with a
// dialer, a proxy or a TLS configuration.
func fresh() *http.Transport {
	d := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Transport{
		DialContext:           d.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// Client returns a client over rt that follows no redirect, stops after
// timeout (1 ns to MaxTimeout) and bounds every response body.
func Client(rt http.RoundTripper, timeout time.Duration) (*http.Client, error) {
	if rt == nil || timeout <= 0 || timeout > MaxTimeout {
		return nil, ErrTransportRefused
	}
	return &http.Client{
		Transport:     capped{rt},
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return ErrRedirectRefused },
	}, nil
}

type capped struct{ rt http.RoundTripper }

func (c capped) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.rt.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &cappedBody{rc: resp.Body, left: MaxResponseBytes}
	return resp, nil
}

// cappedBody fails with ErrResponseTooLarge past MaxResponseBytes.
type cappedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.left < 0 {
		return 0, ErrResponseTooLarge
	}
	if int64(len(p)) > b.left+1 {
		p = p[:b.left+1]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	if b.left < 0 {
		return n, ErrResponseTooLarge
	}
	return n, err
}

func (b *cappedBody) Close() error { return b.rc.Close() }
