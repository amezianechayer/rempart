// Package archtest holds the repository architecture and configuration tests.
// Development tooling only, never shipped to customers.
//
// rules.go and packages.go hold the import rules R1 to R5 (docs/plans/M0-overview.md
// section 5.2) and their only process execution, `go list -json ./...`; the layout,
// go.mod, Makefile and golangci-lint checks live in the _test.go files.
package archtest
