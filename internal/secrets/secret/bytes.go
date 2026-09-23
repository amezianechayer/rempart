package secret

import (
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"strconv"
)

// Bytes is a secret byte string, such as a data encryption key (ADR 0001).
// The zero value is the absent secret. Copies of a Bytes share its content:
// Wipe on one copy wipes them all. Concurrent reads are safe; Wipe must not
// run concurrently with any other method on the same Bytes or a copy.
//
// The content sits behind a pointer to a pointer: fmt dereferences a pointer
// to a slice when it prints an unexported field with an unsupported verb
// (%s, %q), but prints a pointer to a pointer as an address only.
type Bytes struct {
	_ [0]func()
	p **[]byte
}

// NewBytes returns a Bytes holding a copy of b with exact capacity. The caller
// still owns b and should clear it. NewBytes(nil) and NewBytes([]byte{}) are
// the zero Bytes.
func NewBytes(b []byte) Bytes {
	if len(b) == 0 {
		return Bytes{}
	}
	c := make([]byte, len(b))
	copy(c, b)
	pc := &c
	return Bytes{p: &pc}
}

// Reveal returns a view of the secret, not a copy: do not keep it, do not
// append to it (its capacity equals its length, so append reallocates a copy
// that Wipe never erases), do not convert it to a string. nil for the zero
// Bytes and after Wipe.
func (b Bytes) Reveal() []byte {
	if b.p == nil {
		return nil
	}
	return **b.p
}

// Len returns the length of the secret, 0 after Wipe.
func (b Bytes) Len() int { return len(b.Reveal()) }

// IsZero reports whether b holds no secret, which is the case after Wipe.
func (b Bytes) IsZero() bool { return b.Len() == 0 }

// Wipe overwrites the secret with zeros, including every view returned by
// Reveal, then empties b and all its copies. It is idempotent and a no-op on
// the zero Bytes. Best effort: see the package documentation.
func (b Bytes) Wipe() {
	if b.p == nil {
		return
	}
	s := **b.p
	clear(s)
	**b.p = nil
	runtime.KeepAlive(s)
}

// String returns Redacted.
func (b Bytes) String() string { return Redacted }

// GoString returns Redacted.
func (b Bytes) GoString() string { return Redacted }

// Format writes Redacted for every verb, flag, width and precision.
func (b Bytes) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, Redacted) }

// MarshalJSON returns the JSON string "[REDACTED]", never base64 content.
func (b Bytes) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(Redacted)), nil }

// MarshalText returns Redacted.
func (b Bytes) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue returns Redacted.
func (b Bytes) LogValue() slog.Value { return slog.StringValue(Redacted) }

// UnmarshalJSON always returns ErrDecodeRefused and leaves b unchanged.
func (b *Bytes) UnmarshalJSON([]byte) error { return ErrDecodeRefused }

// UnmarshalText always returns ErrDecodeRefused and leaves b unchanged.
func (b *Bytes) UnmarshalText([]byte) error { return ErrDecodeRefused }
