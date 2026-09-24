package prompts

import "embed"

// builtin: empty in M0-T09; M0-T19 adds "//go:embed demo.greeting.v1".
var builtin embed.FS

func Load(id string) (Prompt, error) { return LoadFS(builtin, id) }
