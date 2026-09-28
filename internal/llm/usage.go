package llm

import "github.com/amezianechayer/rempart/internal/llm/domain"

// UsageError: every failure after a provider call (av, T10). Bound: declared
// usage, plus MaxTokens and RequestBytes per call failed without usage.
type UsageError struct {
	Err   error
	Usage domain.Usage
	Bound int
}

func (e *UsageError) Error() string { return e.Err.Error() }

func (e *UsageError) Unwrap() error { return e.Err }

// RequestBytes is the size of the text a provider reads for req.
func RequestBytes(req domain.Request) int {
	n := len(req.System) + len(req.Schema)
	for _, m := range req.Messages {
		for _, p := range m.Parts {
			n += len(p.Text)
			if p.Untrusted != nil {
				n += len(domain.RenderUntrusted(*p.Untrusted))
			}
		}
	}
	return n
}
