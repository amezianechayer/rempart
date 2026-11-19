package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/amezianechayer/rempart/internal/tenancy"
)

var (
	ErrConfig           = errors.New("rempart-worker: invalid configuration")
	ErrFakeRequiresDev  = errors.New("rempart-worker: -llm=fake requires -dev")
	ErrProviderRefused  = errors.New("rempart-worker: -llm=anthropic is not wired before M1")
	ErrDemoOnceRequired = errors.New("rempart-worker: -demo-once, -l1-once or -l2-once is required")
)

// Config holds no secret (D1): no key, no token, no environment value.
type Config struct {
	TemporalAddress, Namespace, LLMProvider, FakeScript string
	Dev, DemoOnce                                       bool
	Tenant                                              tenancy.ID
	OpenBaoAddress                                      string // M1-T02 D9: http on loopback only
	L1Once                                              bool   // M1-T05: run one L1 workflow (target l1-demo)
	L1Request                                           string // relative .txt path of the request, with -l1-once only
	L2Once                                              bool   // M2-T05: run one L2 workflow (target l2-demo)
	L2Input                                             string // relative .json path of the L2 input, with -l2-once only
}

// once is a string flag that refuses a second occurrence (D2).
type once struct {
	v   string
	set bool
}

func (o *once) String() string { return "" }

func (o *once) Set(s string) error {
	if o.set {
		return errors.New("flag repeated")
	}
	o.v, o.set = s, true
	return nil
}

// onceBool is a boolean flag set at most once, to true or false only (bg).
type onceBool struct{ v, set bool }

func (o *onceBool) String() string { return strconv.FormatBool(o != nil && o.v) }

func (o *onceBool) IsBoolFlag() bool { return true }

func (o *onceBool) Set(s string) error {
	if o.set || (s != "true" && s != "false") {
		return errors.New("flag repeated or not a boolean")
	}
	o.v, o.set = s == "true", true
	return nil
}

func LoadConfig(args []string) (Config, error) {
	set := flag.NewFlagSet("rempart-worker", flag.ContinueOnError)
	set.SetOutput(io.Discard) // flag errors quote values
	var addr, ns, provider, script, tenant, bao, l1Req, l2In once
	var dev, demoOnce, l1Once, l2Once onceBool
	var cfg Config
	set.Var(&addr, "temporal-address", "")
	set.Var(&ns, "namespace", "")
	set.Var(&provider, "llm", "")
	set.Var(&script, "fake-script", "")
	set.Var(&tenant, "tenant", "")
	set.Var(&bao, "openbao-addr", "")
	set.Var(&dev, "dev", "")
	set.Var(&demoOnce, "demo-once", "")
	set.Var(&l1Once, "l1-once", "")
	set.Var(&l1Req, "l1-request", "")
	set.Var(&l2Once, "l2-once", "")
	set.Var(&l2In, "l2-input", "")
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return Config{}, fmt.Errorf("%w: command line refused", ErrConfig)
	}
	cfg.Dev, cfg.DemoOnce, cfg.L1Once, cfg.L2Once = dev.v, demoOnce.v, l1Once.v, l2Once.v
	switch provider.v {
	case "fake":
	case "anthropic":
		return Config{}, ErrProviderRefused
	default:
		return Config{}, fmt.Errorf("%w: -llm is required", ErrConfig)
	}
	if !cfg.Dev {
		return Config{}, ErrFakeRequiresDev
	}
	switch modes := cfg.modes(); {
	case modes > 1:
		return Config{}, fmt.Errorf("%w: -demo-once, -l1-once and -l2-once exclude each other", ErrConfig)
	case modes == 0:
		return Config{}, ErrDemoOnceRequired
	case cfg.L1Once != l1Req.set || l1Req.set && (!fs.ValidPath(l1Req.v) || path.Ext(l1Req.v) != ".txt"):
		return Config{}, fmt.Errorf("%w: -l1-request", ErrConfig)
	case cfg.L2Once != l2In.set || l2In.set && (!fs.ValidPath(l2In.v) || path.Ext(l2In.v) != ".json"):
		return Config{}, fmt.Errorf("%w: -l2-input", ErrConfig)
	}
	id, err := tenancy.ParseID(tenant.v)
	if err != nil || id == tenancy.System {
		return Config{}, fmt.Errorf("%w: -tenant is not a customer tenant id", ErrConfig)
	}
	if !loopbackAddr(addr.v) || !validNamespace(ns.v) || !fs.ValidPath(script.v) || path.Ext(script.v) != ".json" {
		return Config{}, fmt.Errorf("%w: -temporal-address, -namespace or -fake-script", ErrConfig)
	}
	if !openBaoAddr(bao.v) {
		return Config{}, fmt.Errorf("%w: -openbao-addr", ErrConfig)
	}
	cfg.TemporalAddress, cfg.Namespace, cfg.LLMProvider, cfg.FakeScript, cfg.Tenant = addr.v, ns.v, provider.v, script.v, id
	cfg.OpenBaoAddress, cfg.L1Request, cfg.L2Input = bao.v, l1Req.v, l2In.v
	return cfg, nil
}

// modes counts the run modes set: exactly one is admitted.
func (c Config) modes() int {
	n := 0
	for _, m := range []bool{c.DemoOnce, c.L1Once, c.L2Once} {
		if m {
			n++
		}
	}
	return n
}

func loopbackAddr(a string) bool {
	host, port, err := net.SplitHostPort(a)
	ip := net.ParseIP(host)
	p, perr := strconv.Atoi(port)
	return err == nil && ip != nil && ip.IsLoopback() && perr == nil && p > 0 && p < 65536 && strconv.Itoa(p) == port
}

// openBaoAddr admits http://127.0.0.1:<port> or http://[::1]:<port> only.
func openBaoAddr(a string) bool {
	u, err := url.Parse(a)
	return err == nil && u.Scheme == "http" && u.User == nil && u.Path == "" && u.RawQuery == "" && !u.ForceQuery &&
		u.Fragment == "" && u.Opaque == "" && "http://"+u.Host == a && loopbackAddr(u.Host) &&
		(u.Hostname() == "127.0.0.1" || u.Hostname() == "::1")
}

func validNamespace(s string) bool {
	return s != "" && len(s) <= 63 && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}
