// Package schemas embeds the versioned JSON Schemas of Rempart.
package schemas

import "embed"

// FS holds the schemas, read-only, compiled into the binary.
//
//go:embed intent/v1.json intent/draft-v1.json
var FS embed.FS

// Paths of the schemas inside FS.
const (
	IntentIR    = "intent/v1.json"
	IntentDraft = "intent/draft-v1.json"
)
