package fake

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"

	"github.com/amezianechayer/rempart/internal/llm/domain"
)

const maxOptionsBytes = 1 << 20

type fileStep struct {
	Response struct {
		Output    string `json:"output"`
		Model     string `json:"model"`
		RequestID string `json:"request_id"`
	} `json:"response"`
	Err string `json:"err"`
}

type fileOptions struct {
	Version int                   `json:"version"`
	Scripts map[string][]fileStep `json:"scripts"`
	Models  map[string]struct {
		NativeStructuredOutput bool  `json:"native_structured_output"`
		StrictTools            bool  `json:"strict_tools"`
		RequiresRetention      *bool `json:"requires_retention"`
	} `json:"models"`
}

// LoadOptions reads a version 1 file; New checks the result again.
func LoadOptions(fsys fs.FS, path string) (Options, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return Options{}, fmt.Errorf("%w: cannot open file", ErrInvalidOptions)
	}
	defer func() { _ = f.Close() }()
	raw, err := io.ReadAll(io.LimitReader(f, maxOptionsBytes+1))
	if err != nil || len(raw) > maxOptionsBytes {
		return Options{}, fmt.Errorf("%w: unreadable or too large", ErrInvalidOptions)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var fo fileOptions
	if err := dec.Decode(&fo); err != nil {
		return Options{}, fmt.Errorf("%w: malformed document or unknown field", ErrInvalidOptions)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Options{}, fmt.Errorf("%w: data after the document", ErrInvalidOptions)
	}
	if fo.Version != 1 {
		return Options{}, fmt.Errorf("%w: unsupported version", ErrInvalidOptions)
	}
	opt := Options{Scripts: map[string][]Step{}, Models: map[string]domain.Capabilities{}}
	for id, steps := range fo.Scripts {
		for _, s := range steps {
			st := Step{Response: domain.Response{Model: s.Response.Model, RequestID: s.Response.RequestID}, Err: s.Err}
			if s.Response.Output != "" {
				st.Response.Output = []byte(s.Response.Output)
			}
			opt.Scripts[id] = append(opt.Scripts[id], st)
		}
	}
	for m, c := range fo.Models {
		if c.RequiresRetention == nil {
			return Options{}, fmt.Errorf("%w: requires_retention is mandatory", ErrInvalidOptions)
		}
		opt.Models[m] = domain.Capabilities{NativeStructuredOutput: c.NativeStructuredOutput, StrictTools: c.StrictTools, RequiresRetention: *c.RequiresRetention}
	}
	return opt, nil
}
