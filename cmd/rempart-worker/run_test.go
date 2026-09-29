package main

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/amezianechayer/rempart/internal/loops"
	"github.com/amezianechayer/rempart/internal/loops/demo"
	loopsfake "github.com/amezianechayer/rempart/internal/loops/fake"
)

// countingListener accepts and closes every connection on 127.0.0.1:0 and
// counts them.
func countingListener(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var n atomic.Int64
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n.Add(1)
			_ = c.Close()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String(), &n
}

// TestRunRefusesFakeWithoutDev (D3, threat T41): run checks again -dev,
// -llm=fake and -demo-once before any input or output, even when LoadConfig
// is bypassed: no connection, nothing on stdout. The working directory is the
// repository root, so that only this check can stop the run.
func TestRunRefusesFakeWithoutDev(t *testing.T) {
	t.Chdir("../..")
	cases := []struct {
		name string
		edit func(*Config)
	}{
		{"dev_false", func(c *Config) { c.Dev = false }},
		{"anthropic", func(c *Config) { c.LLMProvider = "anthropic" }},
		{"no_provider", func(c *Config) { c.LLMProvider = "" }},
		{"demo_once_false", func(c *Config) { c.DemoOnce = false }},
		{"zero_config", func(c *Config) { *c = Config{TemporalAddress: c.TemporalAddress, Namespace: demoNS} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, conns := countingListener(t)
			cfg := demoConfig()
			cfg.TemporalAddress = addr
			tc.edit(&cfg)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			var stdout bytes.Buffer
			err := run(ctx, cfg, &stdout)
			if !errors.Is(err, ErrFakeRequiresDev) {
				t.Errorf("run = %v, want ErrFakeRequiresDev", err)
			}
			time.Sleep(50 * time.Millisecond) // let a late accept be counted
			if n := conns.Load(); n != 0 {
				t.Errorf("%d connections to the Temporal address, want 0", n)
			}
			if stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
		})
	}
}

// TestDenyAllVerifier (D8, threat T41): the verifier wired by the worker
// refuses every signature, the valid ones of the fake verifier included, and
// never fails (an error would be a verify_error, not a refusal).
func TestDenyAllVerifier(t *testing.T) {
	var v demo.ApprovalVerifier = denyAll{}
	hash := "5b0f0e9c4e1c6c1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091"
	for _, a := range []loops.Approval{
		{Approved: true, PlanHash: hash, Approver: "bob"},
		{Approved: false, PlanHash: hash, Approver: "bob"},
		{Approved: true, PlanHash: hash, Approver: "security@example.com"},
		{Approved: true, PlanHash: hash, Approver: "demo-author"},
	} {
		a.Signature = loopsfake.ExpectedSignature(a)
		ok, err := (&loopsfake.ApprovalVerifier{}).VerifyApproval(context.Background(), a)
		if err != nil || !ok.SignatureValid {
			t.Fatalf("fixture: fake verifier refuses %+v", a)
		}
		check, err := v.VerifyApproval(context.Background(), a)
		if err != nil || check != (loops.ApprovalCheck{}) {
			t.Errorf("denyAll.VerifyApproval(%+v) = %+v, %v; want a zero ApprovalCheck, nil", a, check, err)
		}
	}
}
