package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path"
	"strconv"
	"strings"

	"github.com/amezianechayer/rempart/internal/tenancy"
)

var (
	ErrConfig           = errors.New("rempart-worker: invalid configuration")
	ErrFakeRequiresDev  = errors.New("rempart-worker: -llm=fake requires -dev")
	ErrProviderRefused  = errors.New("rempart-worker: -llm=anthropic is not wired before M1")
	ErrDemoOnceRequired = errors.New("rempart-worker: -demo-once is required in M0")
)

// Config holds no secret (D1): no key, no token, no environment value.
type Config struct {
	TemporalAddress, Namespace, LLMProvider, FakeScript string
	Dev, DemoOnce                                       bool
	Tenant                                              tenancy.ID
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

func LoadConfig(args []string) (Config, error) {
	set := flag.NewFlagSet("rempart-worker", flag.ContinueOnError)
	set.SetOutput(io.Discard) // flag errors quote values
	var addr, ns, provider, script, tenant once
	var cfg Config
	set.Var(&addr, "temporal-address", "")
	set.Var(&ns, "namespace", "")
	set.Var(&provider, "llm", "")
	set.Var(&script, "fake-script", "")
	set.Var(&tenant, "tenant", "")
	set.BoolVar(&cfg.Dev, "dev", false, "")
	set.BoolVar(&cfg.DemoOnce, "demo-once", false, "")
	if err := set.Parse(args); err != nil || set.NArg() != 0 {
		return Config{}, fmt.Errorf("%w: command line refused", ErrConfig)
	}
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
	if !cfg.DemoOnce {
		return Config{}, ErrDemoOnceRequired
	}
	id, err := tenancy.ParseID(tenant.v)
	if err != nil || id == tenancy.System {
		return Config{}, fmt.Errorf("%w: -tenant is not a customer tenant id", ErrConfig)
	}
	if !loopbackAddr(addr.v) || !validNamespace(ns.v) || !fs.ValidPath(script.v) || path.Ext(script.v) != ".json" {
		return Config{}, fmt.Errorf("%w: -temporal-address, -namespace or -fake-script", ErrConfig)
	}
	cfg.TemporalAddress, cfg.Namespace, cfg.LLMProvider, cfg.FakeScript, cfg.Tenant = addr.v, ns.v, provider.v, script.v, id
	return cfg, nil
}

func loopbackAddr(a string) bool {
	host, port, err := net.SplitHostPort(a)
	ip := net.ParseIP(host)
	p, perr := strconv.Atoi(port)
	return err == nil && ip != nil && ip.IsLoopback() && perr == nil && p > 0 && p < 65536 && strconv.Itoa(p) == port
}

func validNamespace(s string) bool {
	return s != "" && len(s) <= 63 && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-") == ""
}
