// Command rempartd is the Rempart control plane API server.
//
// Stub (M0-T01): prints "not implemented" on stderr and exits with status 2.
package main

import (
	"fmt"
	"os"
)

const name = "rempartd"

func main() {
	_, _ = fmt.Fprintln(os.Stderr, name+": not implemented (M0)")
	os.Exit(2)
}
