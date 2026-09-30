// Command rempart is the Rempart command-line interface.
//
// Subcommand design (M1-T04): rempart design [--json | --cidr-only]
// [--superblock CIDR] [--reserve CIDR]... [--growth N] <ir.json>.
package main

import (
	"fmt"
	"io"
	"os"
)

const name = "rempart"

// Exit codes, stable (docs/04-INTERFACE.md section 8).
const (
	exitOK      = 0
	exitRefused = 1
	exitUsage   = 2
)

const usage = "usage: rempart design [--json | --cidr-only] [--superblock CIDR] [--reserve CIDR]... [--growth N] <ir.json>"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is the testable entry point: 0 success, 1 design refused, 2 usage.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "design" {
		_, _ = fmt.Fprintln(stderr, name+": "+usage)
		return exitUsage
	}
	return runDesign(args[1:], stdout, stderr)
}
