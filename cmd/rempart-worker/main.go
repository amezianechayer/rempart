// Command rempart-worker runs the Rempart Temporal workers. M0: the demo loop
// only, once, behind -dev with the fake model (docs/plans/M0-worker-demo.md).
// M1-T02: every Temporal payload is sealed under the tenant key, over a Transit
// token unwrapped from a single-use wrapping token read on standard input.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/amezianechayer/rempart/internal/secrets/adapters/openbao"
	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	"github.com/amezianechayer/rempart/internal/secrets/secret"
)

var ErrWrappingToken = errors.New("rempart-worker: no valid wrapping token on standard input")

const maxWrappingToken = 256

func main() {
	os.Exit(realMain(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func realMain(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	cfg, err := LoadConfig(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	s, err := transitSealer(ctx, cfg, stdin)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rempart-worker: %v\n", err)
		return 1
	}
	if err := run(ctx, cfg, s, stdout); err != nil {
		_, _ = fmt.Fprintf(stderr, "rempart-worker: %v\n", err)
		return 1
	}
	return 0
}

// readWrappingToken reads one line of at most 256 bytes of [A-Za-z0-9._-],
// a final newline admitted; the error never quotes the input (T95).
func readWrappingToken(r io.Reader) (secret.Value, error) {
	buf := make([]byte, maxWrappingToken+2)
	n, err := io.ReadFull(io.LimitReader(r, maxWrappingToken+2), buf) // no intermediate buffer keeps a copy
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return secret.Value{}, ErrWrappingToken
	}
	b := buf[:n]
	defer clear(buf)
	if len(b) > 0 && b[len(b)-1] == '\n' {
		b = b[:len(b)-1]
	}
	if len(b) == 0 || len(b) > maxWrappingToken {
		return secret.Value{}, ErrWrappingToken
	}
	for _, c := range b {
		if !tokenByte(c) {
			return secret.Value{}, ErrWrappingToken
		}
	}
	return secret.New(string(b)), nil
}

// transitSealer unwraps the worker token (policies checked) and returns a
// Sealer over the Transit of OpenBao (D9).
func transitSealer(ctx context.Context, cfg Config, stdin io.Reader) (*envelope.Sealer, error) {
	wrapping, err := readWrappingToken(stdin)
	if err != nil {
		return nil, err
	}
	tok, err := openbao.UnwrapWorkerToken(ctx, cfg.OpenBaoAddress, wrapping)
	if err != nil {
		return nil, err
	}
	c, err := openbao.NewClient(openbao.Config{Addr: cfg.OpenBaoAddress, Token: tok})
	if err != nil {
		return nil, err
	}
	tr, err := openbao.NewTransit(c, "")
	if err != nil {
		return nil, err
	}
	return envelope.NewSealer(tr, envelope.Options{})
}

func tokenByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}
