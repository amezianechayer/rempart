// Package openbao is the OpenBao adapter: a hardened HTTP client built on the
// standard library (no SDK) and the Transit KeyWrapper.
package openbao

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/amezianechayer/rempart/internal/secrets/secret"
)

var (
	ErrConfig = errors.New("openbao: invalid configuration")
	ErrStatus = errors.New("openbao: unexpected response")
)

const (
	defaultTimeout = 10 * time.Second
	maxTimeout     = 60 * time.Second
	maxBody        = 64 << 10
)

// Config configures a Client. Token is required.
type Config struct {
	Addr    string
	Token   secret.Value
	Timeout time.Duration
}

// Client is a hardened OpenBao HTTP client.
type Client struct {
	base  string
	token secret.Value
	http  *http.Client
}

// errHTTP is returned for transport errors without their details (which may
// quote the address).
var errHTTP = errors.New("openbao: request failed")

func validAddr(addr string) bool {
	u, err := url.Parse(addr)
	if err != nil || u.User != nil || u.Host == "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.RawFragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		ip, err := netip.ParseAddr(u.Hostname())
		return err == nil && ip.IsLoopback() && (ip == netip.MustParseAddr("127.0.0.1") || ip == netip.IPv6Loopback())
	default:
		return false
	}
}

// NewClient returns a Client: ErrConfig if cfg is invalid.
func NewClient(cfg Config) (*Client, error) {
	if !validAddr(cfg.Addr) || cfg.Token.IsZero() || cfg.Timeout < 0 || cfg.Timeout > maxTimeout {
		return nil, ErrConfig
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultTimeout
	}
	u, _ := url.Parse(cfg.Addr)
	return &Client{
		base:  u.Scheme + "://" + u.Host,
		token: cfg.Token,
		http: &http.Client{
			Transport: &http.Transport{Proxy: nil, ForceAttemptHTTP2: true, MaxIdleConns: 4, IdleConnTimeout: 90 * time.Second},
			Timeout:   timeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// post sends a JSON body to path and decodes the 200 response into out. The
// status code is returned on ErrStatus.
func (c *Client) post(ctx context.Context, op, path string, in, out any) (int, error) {
	data, err := json.Marshal(in)
	if err != nil {
		return 0, fmt.Errorf("openbao: %s: encoding the request", op)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(data))
	if err != nil {
		return 0, fmt.Errorf("openbao: %s: %w", op, errHTTP)
	}
	req.Header.Set("X-Vault-Token", c.token.Reveal())
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, fmt.Errorf("openbao: %s: %w", op, errHTTP)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("openbao: %s: %w", op, errHTTP)
	}
	defer clear(body)
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, fmt.Errorf("%w: %s: HTTP %d", ErrStatus, op, resp.StatusCode)
	}
	if len(body) > maxBody {
		return resp.StatusCode, fmt.Errorf("%w: %s: response too large", ErrStatus, op)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return resp.StatusCode, fmt.Errorf("%w: %s: malformed response", ErrStatus, op)
	}
	return resp.StatusCode, nil
}
