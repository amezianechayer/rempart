// Package policies embeds the Rego policy packs of Rempart, read-only,
// compiled into the binary. Only the OPA adapter imports it (rule
// opa-confined, ADR 0011 D6); the adapter compiles every file but the tests.
package policies

import "embed"

// Design is the design pack (loop L2): design/*.rego, tests included in the
// embedded files and excluded by the adapter.
//
//go:embed design/*.rego
var Design embed.FS
