// Command rempart-worker runs the Rempart Temporal workers. M0: the demo loop
// only, once, behind -dev with the fake model (docs/plans/M0-worker-demo.md).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	os.Exit(realMain(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func realMain(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	cfg, err := LoadConfig(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "rempart-worker: %v\n", err)
		return 1
	}
	return 0
}
