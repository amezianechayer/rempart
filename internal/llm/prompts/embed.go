package prompts

import "embed"

//go:embed demo.greeting.v1
var builtin embed.FS

func Load(id string) (Prompt, error) { return LoadFS(builtin, id) }
