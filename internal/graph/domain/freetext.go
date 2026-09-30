package domain

import (
	"encoding/json"
	"fmt"
	"io"
)

// freeTextPlaceholder is what every formatting of a FreeText prints.
const freeTextPlaceholder = "[free text]"

// FreeText is untrusted free text (user input, model output, cloud metadata).
// Its only field is unexported: no conversion to string exists; String, GoString
// and Format print a placeholder; only Untrusted returns the content.
type FreeText struct{ s string }

// NewFreeText wraps s.
func NewFreeText(s string) FreeText { return FreeText{s: s} }

// Untrusted returns the content, to be handled as untrusted data.
func (t FreeText) Untrusted() string { return t.s }

// String returns a placeholder, never the content.
func (t FreeText) String() string { return freeTextPlaceholder }

// GoString returns a placeholder, never the content.
func (t FreeText) GoString() string { return freeTextPlaceholder }

// Format prints a placeholder for every verb.
func (t FreeText) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, freeTextPlaceholder) }

// MarshalJSON encodes the content as a JSON string: the JSON encoder escapes
// control characters, so a terminal escape sequence never survives verbatim.
func (t FreeText) MarshalJSON() ([]byte, error) { return json.Marshal(t.s) }

// UnmarshalJSON decodes a JSON string.
func (t *FreeText) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	t.s = s
	return nil
}
