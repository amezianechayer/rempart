package envelope_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"pgregory.net/rapid"

	"github.com/amezianechayer/rempart/internal/secrets/envelope"
	"github.com/amezianechayer/rempart/internal/secrets/ports"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

// U1: every size up to MaxPlaintext, for a customer tenant and System, opens
// back to the same bytes through the sealing Sealer (warm cache) and through a
// fresh Sealer on the same KeyWrapper (cold cache: real unwrap).
func TestSealOpenRoundTrip(t *testing.T) {
	sizes := []int{0, 1, 1 << 10, envelope.MaxPlaintext}
	for _, tenant := range []tenancy.ID{demoTenant, tenancy.System} {
		for _, size := range sizes {
			t.Run(fmt.Sprintf("%s/%d", tenant, size), func(t *testing.T) {
				spy := newSpy(t)
				ctx := tenantCtx(t, tenant)
				plain := randomBytes(t, size)

				sealer := newSealer(t, spy, envelope.Options{})
				sealed, err := sealer.Seal(ctx, plain)
				if err != nil {
					t.Fatalf("Seal(%d bytes): %v", size, err)
				}
				if got := len(sealed); got != 67+wrappedLen(t, sealed)+size+tagLen {
					t.Fatalf("sealed length %d, want 67 + L + %d + 16 (format v1)", got, size)
				}
				for _, c := range []struct {
					name string
					s    *envelope.Sealer
				}{
					{"same_sealer", sealer},
					{"fresh_sealer", newSealer(t, spy, envelope.Options{})},
				} {
					got, err := c.s.Open(ctx, sealed)
					if err != nil {
						t.Fatalf("%s: Open: %v", c.name, err)
					}
					if !bytes.Equal(got, plain) {
						t.Fatalf("%s: Open returned %d bytes (%s), want the %d sealed bytes (%s)",
							c.name, len(got), short(got), len(plain), short(plain))
					}
				}
				if _, unwrap := spy.calls(); unwrap != 1 {
					t.Errorf("UnwrapDataKey called %d times, want 1 (the fresh Sealer only)", unwrap)
				}
			})
		}
	}

	t.Run("concurrent", func(t *testing.T) {
		spy := newSpy(t)
		sealer := newSealer(t, spy, envelope.Options{})
		const goroutines, perGoroutine = 8, 200
		var wg sync.WaitGroup
		errs := make(chan error, goroutines)
		ctxs := [2]context.Context{tenantCtx(t, demoTenant), tenantCtx(t, tenancy.System)}
		for g := range goroutines {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx := ctxs[g%2]
				for i := range perGoroutine {
					plain := []byte(fmt.Sprintf("goroutine %d payload %d", g, i))
					sealed, err := sealer.Seal(ctx, plain)
					if err != nil {
						errs <- fmt.Errorf("goroutine %d, seal %d: %w", g, i, err)
						return
					}
					got, err := sealer.Open(ctx, sealed)
					if err != nil {
						errs <- fmt.Errorf("goroutine %d, open %d: %w", g, i, err)
						return
					}
					if !bytes.Equal(got, plain) {
						errs <- fmt.Errorf("goroutine %d, open %d: got %q, want %q", g, i, got, plain)
						return
					}
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
	})
}

// tamperCheck asserts that Open of a tampered payload fails closed: error
// ErrCorrupt or ErrTenantMismatch, no plaintext.
func tamperCheck(where string, s *envelope.Sealer, ctx context.Context, tampered []byte) error {
	got, err := s.Open(ctx, tampered)
	switch {
	case err == nil:
		return fmt.Errorf("%s: Open of a tampered payload succeeded (%d bytes returned)", where, len(got))
	case !errors.Is(err, envelope.ErrCorrupt) && !errors.Is(err, envelope.ErrTenantMismatch):
		return fmt.Errorf("%s: Open error %v, want ErrCorrupt or ErrTenantMismatch", where, err)
	case got != nil:
		return fmt.Errorf("%s: Open returned %d bytes along with an error, want nil", where, len(got))
	}
	return nil
}

// U2: any modified byte, any truncation and any extension of a sealed payload
// is refused, with a warm cache (the AEAD is reused without unwrapping: the
// whole header must be authenticated) and with a cold cache. A transient
// unwrap failure fails closed without being reported as corruption.
func TestTamperedByteFails(t *testing.T) {
	spy := newSpy(t)
	ctx := tenantCtx(t, demoTenant)
	warm := newSealer(t, spy, envelope.Options{})

	t.Run("every_byte", func(t *testing.T) {
		plain := []byte("a short payload, every byte of its envelope is flipped")
		sealed, err := warm.Seal(ctx, plain)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		for i := range sealed {
			for _, mask := range []byte{0x01, 0x80} {
				tampered := bytes.Clone(sealed)
				tampered[i] ^= mask
				where := fmt.Sprintf("byte %d xor %#02x", i, mask)
				if err := tamperCheck(where+", warm cache", warm, ctx, tampered); err != nil {
					t.Error(err)
				}
				if err := tamperCheck(where+", cold cache", newSealer(t, spy, envelope.Options{}), ctx, tampered); err != nil {
					t.Error(err)
				}
			}
		}
	})

	t.Run("property", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			plain := rapid.SliceOfN(rapid.Byte(), 0, 4<<10).Draw(rt, "plaintext")
			sealed, err := warm.Seal(ctx, plain)
			if err != nil {
				rt.Fatalf("Seal: %v", err)
			}
			cold := newSealer(rt, spy, envelope.Options{})
			// Witness: the untampered payload opens, so the refusals below are not vacuous.
			for name, s := range map[string]*envelope.Sealer{"warm": warm, "cold": cold} {
				got, err := s.Open(ctx, sealed)
				if err != nil || !bytes.Equal(got, plain) {
					rt.Fatalf("%s: Open of the untampered payload: %v", name, err)
				}
			}

			i := rapid.IntRange(0, len(sealed)-1).Draw(rt, "index")
			mask := rapid.ByteRange(1, 255).Draw(rt, "mask")
			tampered := bytes.Clone(sealed)
			tampered[i] ^= mask
			where := fmt.Sprintf("byte %d xor %#02x", i, mask)
			if err := tamperCheck(where+", warm cache", warm, ctx, tampered); err != nil {
				rt.Fatal(err)
			}
			if err := tamperCheck(where+", cold cache", newSealer(rt, spy, envelope.Options{}), ctx, tampered); err != nil {
				rt.Fatal(err)
			}

			n := rapid.IntRange(0, len(sealed)-1).Draw(rt, "truncate")
			for name, s := range map[string]*envelope.Sealer{"warm": warm, "cold": newSealer(rt, spy, envelope.Options{})} {
				got, err := s.Open(ctx, sealed[:n])
				if !errors.Is(err, envelope.ErrCorrupt) || got != nil {
					rt.Fatalf("%s: Open of the first %d of %d bytes: %d bytes, error %v, want nil and ErrCorrupt", name, n, len(sealed), len(got), err)
				}
			}

			extra := rapid.SliceOfN(rapid.Byte(), 1, 32).Draw(rt, "extension")
			extended := append(bytes.Clone(sealed), extra...)
			got, err := warm.Open(ctx, extended)
			if !errors.Is(err, envelope.ErrCorrupt) || got != nil {
				rt.Fatalf("Open of the payload extended by %d bytes: %d bytes, error %v, want nil and ErrCorrupt", len(extra), len(got), err)
			}
		})
	})

	t.Run("unwrap_unavailable", func(t *testing.T) {
		spy := newSpy(t)
		ctx := tenantCtx(t, demoTenant)
		sealed, err := newSealer(t, spy, envelope.Options{}).Seal(ctx, []byte("sealed before the outage"))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		outage := errors.New("transit: connection refused")
		spy.setUnwrapErr(outage)
		got, err := newSealer(t, spy, envelope.Options{}).Open(ctx, sealed)
		switch {
		case err == nil:
			t.Fatalf("Open succeeded while the KeyWrapper is unavailable (%d bytes): no fallback allowed", len(got))
		case errors.Is(err, envelope.ErrCorrupt):
			t.Errorf("Open error %v is ErrCorrupt: a transient failure must stay distinguishable (retryable)", err)
		case errors.Is(err, ports.ErrWrappedKeyRejected):
			t.Errorf("Open error %v is ErrWrappedKeyRejected, want a transient error", err)
		case !errors.Is(err, outage):
			t.Errorf("Open error %v does not wrap the KeyWrapper error", err)
		}
		if got != nil {
			t.Errorf("Open returned %d bytes along with an error, want nil", len(got))
		}
	})
}

// U3: a payload of tenant A is never opened under tenant B: the header check
// refuses it before any call to the KeyWrapper, and rewriting the tenant in the
// header is caught cryptographically.
func TestOpenOtherTenantFails(t *testing.T) {
	spy := newSpy(t)
	ctxA, ctxB := tenantCtx(t, demoTenant), tenantCtx(t, otherTenant)
	plain := []byte("tenant A's data")
	sealer := newSealer(t, spy, envelope.Options{})
	sealed, err := sealer.Seal(ctxA, plain)
	if err != nil {
		t.Fatalf("Seal under A: %v", err)
	}
	if got, err := newSealer(t, spy, envelope.Options{}).Open(ctxA, sealed); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("witness: Open under A: %v", err)
	}

	t.Run("context_mismatch", func(t *testing.T) {
		for name, s := range map[string]*envelope.Sealer{"same_sealer": sealer, "fresh_sealer": newSealer(t, spy, envelope.Options{})} {
			_, before := spy.calls()
			got, err := s.Open(ctxB, sealed)
			if !errors.Is(err, envelope.ErrTenantMismatch) {
				t.Errorf("%s: Open under B: error %v, want ErrTenantMismatch", name, err)
			}
			if got != nil {
				t.Errorf("%s: Open under B returned %d bytes", name, len(got))
			}
			if _, after := spy.calls(); after != before {
				t.Errorf("%s: Open under B called UnwrapDataKey %d times, want 0 (tenant checked first)", name, after-before)
			}
		}
	})

	t.Run("header_rewritten", func(t *testing.T) {
		forged := bytes.Clone(sealed)
		copy(forged[offTenant:offDEKID], otherTenant)
		h, err := envelope.ParseHeader(forged)
		if err != nil || h.Tenant != otherTenant {
			t.Fatalf("ParseHeader of the forged payload: tenant %q, error %v, want %q", h.Tenant, err, otherTenant)
		}
		for name, s := range map[string]*envelope.Sealer{"same_sealer": sealer, "fresh_sealer": newSealer(t, spy, envelope.Options{})} {
			got, err := s.Open(ctxB, forged)
			if !errors.Is(err, envelope.ErrCorrupt) || got != nil {
				t.Errorf("%s: Open under B of a header rewritten from A to B: %d bytes, error %v, want nil and ErrCorrupt", name, len(got), err)
			}
		}
	})
}

// U4: without a tenant in the context, nothing is sealed or opened, and the
// KeyWrapper is never called (no fallback on System).
func TestSealWithoutTenantFails(t *testing.T) {
	var nilCtx context.Context
	cases := []struct {
		name string
		ctx  context.Context
	}{
		{"background", context.Background()},
		{"nil_context", nilCtx},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spy := newSpy(t)
			sealer := newSealer(t, spy, envelope.Options{})
			out, err := sealer.Seal(c.ctx, []byte("no tenant"))
			if !errors.Is(err, envelope.ErrNoTenant) {
				t.Errorf("Seal: error %v, want ErrNoTenant", err)
			}
			if !errors.Is(err, tenancy.ErrNoTenant) {
				t.Errorf("Seal: error %v does not wrap tenancy.ErrNoTenant", err)
			}
			if out != nil {
				t.Errorf("Seal returned %d bytes along with an error", len(out))
			}
			if g, u := spy.calls(); g != 0 || u != 0 {
				t.Errorf("KeyWrapper called (generate %d, unwrap %d), want no call", g, u)
			}
		})
	}

	t.Run("open", func(t *testing.T) {
		spy := newSpy(t)
		sealed, err := newSealer(t, spy, envelope.Options{}).Seal(tenantCtx(t, demoTenant), []byte("sealed under the demo tenant"))
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		_, before := spy.calls()
		got, err := newSealer(t, spy, envelope.Options{}).Open(context.Background(), sealed)
		if !errors.Is(err, envelope.ErrNoTenant) || got != nil {
			t.Errorf("Open without tenant: %d bytes, error %v, want nil and ErrNoTenant", len(got), err)
		}
		if _, after := spy.calls(); after != before {
			t.Errorf("Open without tenant called UnwrapDataKey %d times, want 0", after-before)
		}
	})
}

// U5: payloads above 256 KiB are refused before any call to the KeyWrapper.
func TestPayloadTooLarge(t *testing.T) {
	if envelope.MaxPlaintext != 256<<10 {
		t.Fatalf("MaxPlaintext = %d, want %d (ADR 0001)", envelope.MaxPlaintext, 256<<10)
	}
	spy := newSpy(t)
	out, err := newSealer(t, spy, envelope.Options{}).Seal(tenantCtx(t, demoTenant), make([]byte, envelope.MaxPlaintext+1))
	if !errors.Is(err, envelope.ErrPayloadTooLarge) {
		t.Errorf("Seal(MaxPlaintext+1): error %v, want ErrPayloadTooLarge", err)
	}
	if out != nil {
		t.Errorf("Seal(MaxPlaintext+1) returned %d bytes", len(out))
	}
	if g, _ := spy.calls(); g != 0 {
		t.Errorf("GenerateDataKey called %d times, want 0", g)
	}
}

// U6: one DEK, 10 000 payloads, 10 000 distinct nonces.
func TestNoncesDistinct(t *testing.T) {
	spy := newSpy(t)
	ctx := tenantCtx(t, demoTenant)
	sealer := newSealer(t, spy, envelope.Options{})
	const n = 10000
	seen := make(map[[12]byte]int, n)
	for i := range n {
		sealed, err := sealer.Seal(ctx, []byte("same plaintext"))
		if err != nil {
			t.Fatalf("Seal %d: %v", i, err)
		}
		h, err := envelope.ParseHeader(sealed)
		if err != nil {
			t.Fatalf("ParseHeader %d: %v", i, err)
		}
		if j, dup := seen[h.Nonce]; dup {
			t.Fatalf("seal %d reuses the nonce of seal %d under the same DEK", i, j)
		}
		seen[h.Nonce] = i
	}
	if g, _ := spy.calls(); g != 1 {
		t.Errorf("GenerateDataKey called %d times, want 1 (a single DEK)", g)
	}
}

// U7: the DEK is renewed at its age or use bound, the open cache is bounded
// (LRU) and expires, and the options are bounded.
func TestDEKRotation(t *testing.T) {
	plain := []byte("rotation")

	t.Run("max_age", func(t *testing.T) {
		spy, clk := newSpy(t), newClock()
		start := clk.Now()
		ctx := tenantCtx(t, demoTenant)
		sealer := newSealer(t, spy, envelope.Options{Now: clk.Now})
		for _, step := range []struct {
			at   time.Duration
			want int
		}{
			{0, 1},
			{14*time.Minute + 59*time.Second, 1},
			{15 * time.Minute, 2},
		} {
			clk.set(start, step.at)
			if _, err := sealer.Seal(ctx, plain); err != nil {
				t.Fatalf("Seal at +%v: %v", step.at, err)
			}
			if g, _ := spy.calls(); g != step.want {
				t.Errorf("after a seal at +%v: %d data keys generated, want %d", step.at, g, step.want)
			}
		}
	})

	t.Run("max_uses", func(t *testing.T) {
		spy := newSpy(t)
		ctx := tenantCtx(t, demoTenant)
		sealer := newSealer(t, spy, envelope.Options{DEKMaxUses: 3})
		for i, want := range []int{1, 1, 1, 2} {
			if _, err := sealer.Seal(ctx, plain); err != nil {
				t.Fatalf("Seal %d: %v", i+1, err)
			}
			if g, _ := spy.calls(); g != want {
				t.Errorf("after seal %d: %d data keys generated, want %d", i+1, g, want)
			}
		}
	})

	t.Run("cache_bounded", func(t *testing.T) {
		spy := newSpy(t)
		ctx := tenantCtx(t, demoTenant)
		producer := newSealer(t, spy, envelope.Options{DEKMaxUses: 1})
		var payloads [3][]byte
		for i := range payloads {
			var err error
			if payloads[i], err = producer.Seal(ctx, plain); err != nil {
				t.Fatalf("Seal %d: %v", i, err)
			}
		}
		if g, _ := spy.calls(); g != 3 {
			t.Fatalf("%d data keys generated, want 3 distinct DEKs", g)
		}

		opener := newSealer(t, spy, envelope.Options{CacheEntries: 2})
		_, base := spy.calls()
		for _, step := range []struct {
			what    string
			payload int
			want    int
		}{
			{"first open of DEK 1", 0, 1},
			{"first open of DEK 2", 1, 2},
			{"first open of DEK 3 (evicts DEK 1)", 2, 3},
			{"DEK 1 again, evicted", 0, 4},
			{"DEK 3 again, still cached", 2, 4},
		} {
			if _, err := opener.Open(ctx, payloads[step.payload]); err != nil {
				t.Fatalf("%s: Open: %v", step.what, err)
			}
			if _, u := spy.calls(); u-base != step.want {
				t.Errorf("%s: %d unwraps in total, want %d", step.what, u-base, step.want)
			}
		}
	})

	t.Run("open_entry_expires", func(t *testing.T) {
		spy, clk := newSpy(t), newClock()
		start := clk.Now()
		ctx := tenantCtx(t, demoTenant)
		sealed, err := newSealer(t, spy, envelope.Options{}).Seal(ctx, plain)
		if err != nil {
			t.Fatalf("Seal: %v", err)
		}
		opener := newSealer(t, spy, envelope.Options{Now: clk.Now})
		for _, step := range []struct {
			at   time.Duration
			want int
		}{
			{0, 1},
			{14*time.Minute + 59*time.Second, 1},
			{15 * time.Minute, 2},
		} {
			clk.set(start, step.at)
			if _, err := opener.Open(ctx, sealed); err != nil {
				t.Fatalf("Open at +%v: %v", step.at, err)
			}
			if _, u := spy.calls(); u != step.want {
				t.Errorf("after an open at +%v: %d unwraps, want %d", step.at, u, step.want)
			}
		}
	})

	t.Run("options_bounds", func(t *testing.T) {
		spy := newSpy(t)
		for _, c := range []struct {
			name string
			kw   ports.KeyWrapper
			o    envelope.Options
			ok   bool
		}{
			{"defaults", spy, envelope.Options{}, true},
			{"upper_bounds", spy, envelope.Options{DEKMaxAge: 15 * time.Minute, DEKMaxUses: 1 << 20, CacheEntries: 65536}, true},
			{"max_age_16min", spy, envelope.Options{DEKMaxAge: 16 * time.Minute}, false},
			{"max_uses_over", spy, envelope.Options{DEKMaxUses: 1<<20 + 1}, false},
			{"cache_65537", spy, envelope.Options{CacheEntries: 65537}, false},
			{"cache_negative", spy, envelope.Options{CacheEntries: -1}, false},
			{"nil_keywrapper", nil, envelope.Options{}, false},
		} {
			s, err := envelope.NewSealer(c.kw, c.o)
			switch {
			case c.ok && (err != nil || s == nil):
				t.Errorf("%s: NewSealer: %v, want a Sealer", c.name, err)
			case !c.ok && !errors.Is(err, envelope.ErrInvalidOptions):
				t.Errorf("%s: NewSealer: error %v, want ErrInvalidOptions", c.name, err)
			case !c.ok && s != nil:
				t.Errorf("%s: NewSealer returned a Sealer along with an error", c.name)
			}
		}
	})
}

// U8: the sealed payload carries neither the plaintext nor the plaintext DEK,
// has the exact v1 length, and ParseHeader returns exactly its public fields.
func TestNoPlaintextInSealedMetadata(t *testing.T) {
	spy := newSpy(t)
	ctx := tenantCtx(t, demoTenant)
	canary := randomBytes(t, 1<<10)
	sealed, err := newSealer(t, spy, envelope.Options{}).Seal(ctx, canary)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	dek, wrapped := spy.lastDEK(t)

	for i := 0; i+16 <= len(canary); i++ {
		if bytes.Contains(sealed, canary[i:i+16]) {
			t.Fatalf("sealed payload contains the 16-byte window of the plaintext at offset %d", i)
		}
	}
	for i := 0; i+16 <= len(dek); i++ {
		if bytes.Contains(sealed, dek[i:i+16]) {
			t.Fatalf("sealed payload contains the plaintext DEK (16-byte window at offset %d)", i)
		}
	}

	l := len(wrapped)
	if got, want := len(sealed), 67+l+len(canary)+tagLen; got != want {
		t.Errorf("sealed length %d, want 67 + %d + %d + 16 = %d", got, l, len(canary), want)
	}
	if got := wrappedLen(t, sealed); got != l {
		t.Errorf("length field at offset 53 is %d, want the wrapped DEK length %d", got, l)
	}

	h, err := envelope.ParseHeader(sealed)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Version != envelope.FormatV1 || sealed[offVersion] != 1 {
		t.Errorf("version: header %d, byte 0 is %d, want 1", h.Version, sealed[offVersion])
	}
	if h.Tenant != demoTenant || string(sealed[offTenant:offDEKID]) != string(demoTenant) {
		t.Errorf("tenant: header %q, bytes 1 to 36 %q, want %q", h.Tenant, sealed[offTenant:offDEKID], demoTenant)
	}
	if !bytes.Equal(h.DEKID[:], sealed[offDEKID:offLen]) || h.DEKID == [16]byte{} {
		t.Errorf("DEK id %x, bytes 37 to 52 %x, want equal and non-zero", h.DEKID, sealed[offDEKID:offLen])
	}
	if !bytes.Equal(h.Wrapped, wrapped) || !bytes.Equal(sealed[offWrapped:offWrapped+l], wrapped) {
		t.Errorf("wrapped DEK: header %s, payload %s, want the KeyWrapper output %s",
			short(h.Wrapped), short(sealed[offWrapped:offWrapped+l]), short(wrapped))
	}
	if !bytes.Equal(h.Nonce[:], sealed[offWrapped+l:offWrapped+l+nonceLen]) || h.Nonce == [12]byte{} {
		t.Errorf("nonce %x, bytes at 55+L %x, want equal and non-zero", h.Nonce, sealed[offWrapped+l:offWrapped+l+nonceLen])
	}

	before := bytes.Clone(sealed)
	for i := range h.Wrapped {
		h.Wrapped[i] ^= 0xff
	}
	if !bytes.Equal(sealed, before) {
		t.Errorf("Header.Wrapped aliases the sealed payload, want a copy")
	}
}
