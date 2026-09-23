// Command rempart-runner is the customer-side runner that executes signed, approved plans.
//
// Stub (M0-T01): prints "not implemented" on stderr and exits with status 2.
package main

import (
	"fmt"
	"os"
)

const name = "rempart-runner"

func main() {
	_, _ = fmt.Fprintln(os.Stderr, name+": not implemented (M0)")
	os.Exit(2)
}
