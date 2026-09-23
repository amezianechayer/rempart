package tenancy

import (
	"context"
	"encoding/hex"
	"errors"
	"regexp"
	"testing"

	"pgregory.net/rapid"
)

// genTenantV4 draws a canonical RFC 9562 version 4 UUID, built by the test itself.
func genTenantV4() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		b := rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "bytes")
		b[6] = b[6]&0x0f | 0x40 // version 4
		b[8] = b[8]&0x3f | 0x80 // variant 10xx
		h := hex.EncodeToString(b)
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	})
}

// genMutatedTenant substitutes one arbitrary byte of a valid version 4 id.
func genMutatedTenant() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		s := []byte(genTenantV4().Draw(t, "base"))
		pos := rapid.IntRange(0, 35).Draw(t, "pos")
		s[pos] = rapid.Byte().Draw(t, "byte")
		return string(s)
	})
}

// canonicalV4 is the oracle of ADR 0004 for customer tenants, independent of
// the production parser. In RE2, $ only matches at the end of the text.
var canonicalV4 = regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")

func TestRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := genTenantV4().Draw(t, "id")

		id, err := ParseID(s)
		if err != nil {
			t.Fatalf("ParseID(%q): unexpected error %v", s, err)
		}
		if id.String() != s {
			t.Fatalf("ParseID(%q).String() = %q, want the input unchanged", s, id.String())
		}
		again, err := ParseID(id.String())
		if err != nil || again != id {
			t.Fatalf("ParseID(id.String()) = %q, %v, want %q, nil", again, err, id)
		}

		ctx, err := WithTenant(context.Background(), id)
		if err != nil {
			t.Fatalf("WithTenant(%q): unexpected error %v", id, err)
		}
		got, err := FromContext(ctx)
		if err != nil || got != id {
			t.Fatalf("FromContext = %q, %v, want %q, nil", got, err, id)
		}
		if err := Require(ctx, id); err != nil {
			t.Fatalf("Require(ctx, %q): unexpected error %v", id, err)
		}
	})
}

func TestParseIDMatchesOracle(t *testing.T) {
	inputs := rapid.OneOf(
		rapid.String(),
		rapid.StringMatching("[0-9a-fA-F{}: -]{30,40}"),
		genMutatedTenant(),
		rapid.Just(systemLiteral),
	)
	rapid.Check(t, func(t *rapid.T) {
		s := inputs.Draw(t, "input")
		want := canonicalV4.MatchString(s) || s == systemLiteral

		id, err := ParseID(s)
		if (err == nil) != want {
			t.Fatalf("ParseID(%q): error %v, oracle says valid=%t", s, err, want)
		}
		if err != nil {
			if !errors.Is(err, ErrInvalidTenant) {
				t.Fatalf("ParseID(%q): error %v does not wrap ErrInvalidTenant", s, err)
			}
			return
		}
		if id.String() != s {
			t.Fatalf("ParseID(%q) = %q, want the input unchanged", s, id.String())
		}
	})
}
