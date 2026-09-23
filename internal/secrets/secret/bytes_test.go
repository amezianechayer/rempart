package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
)

func assertWiped(t *testing.T, name string, b Bytes) {
	t.Helper()
	if got := b.Reveal(); got != nil {
		t.Errorf("%s: Reveal() after Wipe = %v, want nil", name, got)
	}
	if got := b.Len(); got != 0 {
		t.Errorf("%s: Len() after Wipe = %d, want 0", name, got)
	}
	if !b.IsZero() {
		t.Errorf("%s: IsZero() after Wipe = false, want true", name)
	}
}

func TestBytesWipe(t *testing.T) {
	t.Run("zeroes_revealed_view", func(t *testing.T) {
		b := NewBytes([]byte(canary))
		view := b.Reveal()
		b.Wipe()
		if len(view) != len(canary) {
			t.Fatalf("view length after Wipe = %d, want %d", len(view), len(canary))
		}
		for i, c := range view {
			if c != 0 {
				t.Errorf("view[%d] after Wipe = %#x, want 0", i, c)
			}
		}
	})
	t.Run("reveal_after_wipe_is_empty", func(t *testing.T) {
		b := NewBytes([]byte(canary))
		b.Wipe()
		assertWiped(t, "wiped secret", b)
	})
	t.Run("copies_share_state", func(t *testing.T) {
		b := NewBytes([]byte(canary))
		c := b
		b.Wipe()
		assertWiped(t, "copy of wiped secret", c)
	})
	t.Run("idempotent", func(t *testing.T) {
		b := NewBytes([]byte(canary))
		b.Wipe()
		b.Wipe()
		assertWiped(t, "secret wiped twice", b)
	})
	t.Run("zero_value", func(t *testing.T) {
		var z Bytes
		z.Wipe()
		if !z.IsZero() {
			t.Error("Bytes{} after Wipe: IsZero() = false, want true")
		}
	})
	t.Run("independent_secrets", func(t *testing.T) {
		in := []byte(canary)
		b1 := NewBytes(in)
		b2 := NewBytes(in)
		b1.Wipe()
		if got := b2.Reveal(); !bytes.Equal(got, []byte(canary)) {
			t.Errorf("second secret after wiping the first = %q, want %q", got, canary)
		}
	})
	t.Run("redacted_after_wipe", func(t *testing.T) {
		b := NewBytes([]byte(canary))
		b.Wipe()
		if got := fmt.Sprint(b); got != wantRedacted {
			t.Errorf("fmt.Sprint(wiped) = %q, want %q", got, wantRedacted)
		}
		got, err := json.Marshal(b)
		if err != nil {
			t.Fatalf("json.Marshal(wiped): %v", err)
		}
		if string(got) != `"[REDACTED]"` {
			t.Errorf("json.Marshal(wiped) = %s, want %q", got, `"[REDACTED]"`)
		}
	})
}

func TestNewBytesCopies(t *testing.T) {
	t.Run("input_mutation_not_seen", func(t *testing.T) {
		in := []byte(canary)
		b := NewBytes(in)
		for i := range in {
			in[i] = 'X'
		}
		if got := b.Reveal(); !bytes.Equal(got, []byte(canary)) {
			t.Errorf("secret after mutating the input = %q, want %q", got, canary)
		}
	})
	t.Run("distinct_backing_array", func(t *testing.T) {
		in := []byte(canary)
		b := NewBytes(in)
		view := b.Reveal()
		if len(view) == 0 {
			t.Fatal("Reveal() is empty")
		}
		if &view[0] == &in[0] {
			t.Error("NewBytes shares the backing array of its input")
		}
	})
	t.Run("exact_capacity", func(t *testing.T) {
		in := []byte(canary)
		b := NewBytes(in)
		if got := cap(b.Reveal()); got != len(in) {
			t.Errorf("cap(Reveal()) = %d, want %d (Wipe must cover the whole array)", got, len(in))
		}
	})
	t.Run("input_untouched", func(t *testing.T) {
		in := []byte(canary)
		b := NewBytes(in)
		b.Wipe()
		if string(in) != canary {
			t.Errorf("input after NewBytes and Wipe = %q, want %q (the caller owns it)", in, canary)
		}
	})
	t.Run("subslice_input", func(t *testing.T) {
		big := []byte("xx" + canary + "yy")
		in := big[2 : 2+len(canary)]
		b := NewBytes(in)
		view := b.Reveal()
		if !bytes.Equal(view, []byte(canary)) {
			t.Errorf("secret from a subslice = %q, want %q", view, canary)
		}
		if cap(view) != len(canary) {
			t.Errorf("cap(Reveal()) from a subslice = %d, want %d", cap(view), len(canary))
		}
	})
}

func TestConcurrentReads(t *testing.T) {
	const goroutines, iterations = 8, 200
	t.Run("value", func(t *testing.T) {
		v := New(canary)
		var wg sync.WaitGroup
		for range goroutines {
			wg.Go(func() {
				for range iterations {
					if got := v.Reveal(); got != canary {
						t.Errorf("concurrent Reveal() = %q, want %q", got, canary)
						return
					}
					if got := fmt.Sprint(v); got != wantRedacted {
						t.Errorf("concurrent fmt.Sprint = %q, want %q", got, wantRedacted)
						return
					}
					got, err := json.Marshal(v)
					if err != nil || string(got) != `"[REDACTED]"` {
						t.Errorf("concurrent json.Marshal = %s, %v; want %q", got, err, `"[REDACTED]"`)
						return
					}
				}
			})
		}
		wg.Wait()
	})
	t.Run("bytes", func(t *testing.T) {
		b := NewBytes([]byte(canary))
		var wg sync.WaitGroup
		for range goroutines {
			wg.Go(func() {
				for range iterations {
					if got := b.Reveal(); !bytes.Equal(got, []byte(canary)) {
						t.Errorf("concurrent Reveal() = %q, want %q", got, canary)
						return
					}
					if got := b.Len(); got != len(canary) {
						t.Errorf("concurrent Len() = %d, want %d", got, len(canary))
						return
					}
					if got := fmt.Sprint(b); got != wantRedacted {
						t.Errorf("concurrent fmt.Sprint = %q, want %q", got, wantRedacted)
						return
					}
					got, err := json.Marshal(b)
					if err != nil || string(got) != `"[REDACTED]"` {
						t.Errorf("concurrent json.Marshal = %s, %v; want %q", got, err, `"[REDACTED]"`)
						return
					}
				}
			})
		}
		wg.Wait()
	})
}
