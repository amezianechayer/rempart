// Command rempart-evals runs the eval suites of evals/, compares each report
// with its baseline and is the eval gate of make verify (ADR 0005,
// docs/plans/M0-evals-cli.md). Development tooling, never shipped.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
