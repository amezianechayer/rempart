// Package secret holds secrets that fmt, log/slog, encoding/json,
// encoding/xml, encoding/gob and text templates never print (principle 9 of
// docs/00-VISION.md). Reveal is the only way to read a secret; a secret is
// never decoded from serialized data.
//
// Memory hygiene is best effort: Go does not guarantee that copies made by the
// runtime or by callers are erased. See Bytes.Wipe.
package secret

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// Redacted is printed and encoded in place of any secret.
const Redacted = "[REDACTED]"

// ErrDecodeRefused is returned by every decoding method of Value and Bytes.
var ErrDecodeRefused = errors.New("secret: decoding a secret from serialized data is refused")

// Value is a secret string. The zero value is the absent secret.
//
// The content sits behind a pointer: printing an unexported Value field by
// reflection shows an address, never the content. Value is not comparable.
type Value struct {
	_ [0]func()
	p *string
}

// New returns a Value holding s. New("") is the zero Value.
func New(s string) Value {
	if s == "" {
		return Value{}
	}
	return Value{p: &s}
}

// Reveal returns the secret, "" for the zero Value. Never log or print it.
func (v Value) Reveal() string {
	if v.p == nil {
		return ""
	}
	return *v.p
}

// IsZero reports whether v holds no secret (used by the json omitzero option).
func (v Value) IsZero() bool { return v.p == nil }

// String returns Redacted.
func (v Value) String() string { return Redacted }

// GoString returns Redacted.
func (v Value) GoString() string { return Redacted }

// Format writes Redacted for every verb, flag, width and precision.
func (v Value) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, Redacted) }

// MarshalJSON returns the JSON string "[REDACTED]".
func (v Value) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(Redacted)), nil }

// MarshalText returns Redacted.
func (v Value) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue returns Redacted, resolved by log/slog before any ReplaceAttr.
func (v Value) LogValue() slog.Value { return slog.StringValue(Redacted) }

// UnmarshalJSON always returns ErrDecodeRefused and leaves v unchanged.
func (v *Value) UnmarshalJSON([]byte) error { return ErrDecodeRefused }

// UnmarshalText always returns ErrDecodeRefused and leaves v unchanged.
func (v *Value) UnmarshalText([]byte) error { return ErrDecodeRefused }
