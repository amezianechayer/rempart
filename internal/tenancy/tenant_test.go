package tenancy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Test constants are written out in full and never taken from production code.
const (
	tenantA       = "3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0d"
	tenantB       = "3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0e"
	systemLiteral = "00000000-0000-8000-8000-000000000001"
)

// foreignKey is a context key owned by the tests, distinct from the package key.
type foreignKey struct{}

// mustWithTenant builds a context carrying id or fails the test.
func mustWithTenant(t *testing.T, parent context.Context, id ID) context.Context {
	t.Helper()
	ctx, err := WithTenant(parent, id)
	if err != nil {
		t.Fatalf("WithTenant(%q): unexpected error %v", id, err)
	}
	if ctx == nil {
		t.Fatalf("WithTenant(%q): nil context without error", id)
	}
	return ctx
}

// assertCarries checks that ctx carries exactly want.
func assertCarries(t *testing.T, ctx context.Context, want ID) {
	t.Helper()
	got, err := FromContext(ctx)
	if err != nil {
		t.Fatalf("FromContext: unexpected error %v, want tenant %q", err, want)
	}
	if got != want {
		t.Fatalf("FromContext: got %q, want %q", got, want)
	}
}

func TestParseIDCanonicalOnly(t *testing.T) {
	const v = tenantA
	cases := []struct {
		name   string
		input  string
		valid  bool
		reason string
	}{
		{name: "v4_variant_8", input: "3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0d", valid: true},
		{name: "v4_variant_9", input: "3f2c8a1e-9b4d-4c7a-9e21-5d6f7a8b9c0d", valid: true},
		{name: "v4_variant_a", input: "3f2c8a1e-9b4d-4c7a-ae21-5d6f7a8b9c0d", valid: true},
		{name: "v4_variant_b", input: "a1b2c3d4-e5f6-4a7b-b8c9-d0e1f2a3b4c5", valid: true},
		{name: "system", input: "00000000-0000-8000-8000-000000000001", valid: true},
		{name: "empty", input: "", reason: "length"},
		{name: "uppercase", input: "3F2C8A1E-9B4D-4C7A-8E21-5D6F7A8B9C0D", reason: "hexadecimal"},
		{name: "one_uppercase", input: "3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0D", reason: "hexadecimal"},
		{name: "nil_uuid", input: "00000000-0000-0000-0000-000000000000", reason: "nil UUID"},
		{name: "max_uuid", input: "ffffffff-ffff-ffff-ffff-ffffffffffff", reason: "max UUID"},
		{name: "leading_space", input: " " + v, reason: "length"},
		{name: "trailing_space", input: v + " ", reason: "length"},
		{name: "trailing_newline", input: v + "\n", reason: "length"},
		{name: "space_instead_of_hyphen", input: "3f2c8a1e 9b4d-4c7a-8e21-5d6f7a8b9c0d", reason: "hyphen"},
		{name: "length_37", input: v + "0", reason: "length"},
		{name: "length_35", input: v[:35], reason: "length"},
		{name: "braces", input: "{" + v + "}", reason: "length"},
		{name: "urn_prefix", input: "urn:uuid:" + v, reason: "length"},
		{name: "no_hyphens", input: "3f2c8a1e9b4d4c7a8e215d6f7a8b9c0d", reason: "length"},
		{name: "hyphen_misplaced", input: "3f2c8a1e9-b4d-4c7a-8e21-5d6f7a8b9c0d", reason: "hyphen"},
		{name: "underscore", input: "3f2c8a1e_9b4d-4c7a-8e21-5d6f7a8b9c0d", reason: "hyphen"},
		{name: "non_hex_letter", input: "3f2c8a1g-9b4d-4c7a-8e21-5d6f7a8b9c0d", reason: "hexadecimal"},
		{name: "plus_sign", input: "3f2c8a1e-9b4d-4c7a-8e21-+d6f7a8b9c0d", reason: "hexadecimal"},
		{name: "hex_prefix", input: "0x2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0d", reason: "hexadecimal"},
		{name: "nul_byte", input: "3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0\x00", reason: "hexadecimal"},
		{name: "non_ascii_36_bytes", input: "3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9cé", reason: "hexadecimal"},
		{name: "version_0", input: "3f2c8a1e-9b4d-0c7a-8e21-5d6f7a8b9c0d", reason: "version"},
		{name: "version_1", input: "3f2c8a1e-9b4d-1c7a-8e21-5d6f7a8b9c0d", reason: "version"},
		{name: "version_7", input: "01928c3e-5f7a-7b2c-9d4e-6f8091a2b3c4", reason: "version"},
		{name: "version_8_not_system", input: "00000000-0000-8000-8000-000000000002", reason: "version"},
		{name: "version_f", input: "3f2c8a1e-9b4d-fc7a-8e21-5d6f7a8b9c0d", reason: "version"},
		{name: "variant_ncs", input: "3f2c8a1e-9b4d-4c7a-7e21-5d6f7a8b9c0d", reason: "variant"},
		{name: "variant_microsoft", input: "3f2c8a1e-9b4d-4c7a-ce21-5d6f7a8b9c0d", reason: "variant"},
		{name: "system_other_variant", input: "00000000-0000-8000-c000-000000000001", reason: "version"},
	}

	if len(cases) != 34 {
		t.Fatalf("table has %d cases, want 34", len(cases))
	}
	seen := make(map[string]string, len(cases))
	for _, tc := range cases {
		if prev, dup := seen[tc.input]; dup {
			t.Fatalf("cases %s and %s share the same input", prev, tc.name)
		}
		seen[tc.input] = tc.name
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := ParseID(tc.input)
			if tc.valid {
				if err != nil {
					t.Fatalf("%s: ParseID rejected a canonical id: %v", tc.name, err)
				}
				if id.String() != tc.input {
					t.Fatalf("%s: ParseID normalized the input: got %q, want %q", tc.name, id.String(), tc.input)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s: ParseID accepted a non canonical id, returned %q", tc.name, id)
			}
			if id != "" {
				t.Fatalf("%s: ParseID returned %q with an error, want the zero ID", tc.name, id)
			}
			if !errors.Is(err, ErrInvalidTenant) {
				t.Fatalf("%s: error %v does not wrap ErrInvalidTenant", tc.name, err)
			}
			if tc.reason != "" && !strings.Contains(err.Error(), tc.reason) {
				t.Fatalf("%s: error %q does not give the reason %q", tc.name, err.Error(), tc.reason)
			}
		})
	}
}

func TestFromContextWithoutTenant(t *testing.T) {
	cancelCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cases := []struct {
		name string
		ctx  context.Context
	}{
		{name: "background", ctx: context.Background()},
		{name: "todo", ctx: context.TODO()},
		{name: "test_context", ctx: t.Context()},
		{name: "with_cancel", ctx: cancelCtx},
		{name: "foreign_key_carrying_tenant", ctx: context.WithValue(context.Background(), foreignKey{}, ID(tenantA))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			id, err := FromContext(tc.ctx)
			if id != "" {
				t.Fatalf("%s: FromContext returned %q, want no tenant", tc.name, id)
			}
			if !errors.Is(err, ErrNoTenant) {
				t.Fatalf("%s: error %v, want ErrNoTenant", tc.name, err)
			}
			if errors.Is(err, ErrInvalidTenant) {
				t.Fatalf("%s: error %v must not be ErrInvalidTenant", tc.name, err)
			}
			if errors.Is(err, ErrNilContext) {
				t.Fatalf("%s: error %v must not be ErrNilContext", tc.name, err)
			}
		})
	}
}

func TestWithTenantRejectsInvalid(t *testing.T) {
	invalid := []struct {
		name string
		id   ID
	}{
		{name: "empty", id: ""},
		{name: "uppercase", id: ID(strings.ToUpper(tenantA))},
		{name: "nil_uuid", id: "00000000-0000-0000-0000-000000000000"},
		{name: "max_uuid", id: "ffffffff-ffff-ffff-ffff-ffffffffffff"},
		{name: "leading_space", id: ID(" " + tenantA)},
		{name: "length_37", id: ID(tenantA + "0")},
		{name: "version_7", id: "01928c3e-5f7a-7b2c-9d4e-6f8091a2b3c4"},
		{name: "version_8_not_system", id: "00000000-0000-8000-8000-000000000002"},
	}
	bare := t.Context()
	carryingA := mustWithTenant(t, t.Context(), ID(tenantA))
	parents := []struct {
		name   string
		ctx    context.Context
		holdsA bool
	}{
		{name: "bare", ctx: bare},
		{name: "carrying_a", ctx: carryingA, holdsA: true},
	}
	for _, p := range parents {
		t.Run(p.name, func(t *testing.T) {
			for _, tc := range invalid {
				t.Run(tc.name, func(t *testing.T) {
					got, err := WithTenant(p.ctx, tc.id)
					if got != nil {
						t.Fatalf("%s/%s: WithTenant returned a non nil context on error", p.name, tc.name)
					}
					if !errors.Is(err, ErrInvalidTenant) {
						t.Fatalf("%s/%s: error %v, want ErrInvalidTenant", p.name, tc.name, err)
					}
					if errors.Is(err, ErrTenantMismatch) {
						t.Fatalf("%s/%s: error %v must not be ErrTenantMismatch", p.name, tc.name, err)
					}
					cur, curErr := FromContext(p.ctx)
					if p.holdsA {
						if curErr != nil || cur != ID(tenantA) {
							t.Fatalf("%s/%s: parent changed: got %q, %v", p.name, tc.name, cur, curErr)
						}
						return
					}
					if !errors.Is(curErr, ErrNoTenant) {
						t.Fatalf("%s/%s: parent changed: got %q, %v", p.name, tc.name, cur, curErr)
					}
				})
			}
		})
	}
}

func TestRequireMismatch(t *testing.T) {
	ctxA := mustWithTenant(t, t.Context(), ID(tenantA))
	ctxSystem := mustWithTenant(t, t.Context(), System)
	bare := t.Context()

	cases := []struct {
		name        string
		ctx         context.Context
		want        ID
		wantErr     error
		notMismatch bool
	}{
		{name: "other_tenant", ctx: ctxA, want: ID(tenantB), wantErr: ErrTenantMismatch},
		{name: "same_tenant", ctx: ctxA, want: ID(tenantA)},
		{name: "client_vs_system", ctx: ctxA, want: System, wantErr: ErrTenantMismatch},
		{name: "system_vs_client", ctx: ctxSystem, want: ID(tenantA), wantErr: ErrTenantMismatch},
		{name: "system_vs_system", ctx: ctxSystem, want: System},
		{name: "no_tenant", ctx: bare, want: ID(tenantA), wantErr: ErrNoTenant, notMismatch: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Require(tc.ctx, tc.want)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("%s: Require: unexpected error %v", tc.name, err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("%s: Require: error %v, want %v", tc.name, err, tc.wantErr)
			}
			if tc.notMismatch && errors.Is(err, ErrTenantMismatch) {
				t.Fatalf("%s: Require: error %v must not be ErrTenantMismatch", tc.name, err)
			}
		})
	}

	t.Run("derived_context", func(t *testing.T) {
		child, cancel := context.WithCancel(ctxA)
		defer cancel()
		if err := Require(child, ID(tenantA)); err != nil {
			t.Fatalf("derived_context: Require(child, A): unexpected error %v", err)
		}
		if err := Require(child, ID(tenantB)); !errors.Is(err, ErrTenantMismatch) {
			t.Fatalf("derived_context: Require(child, B): error %v, want ErrTenantMismatch", err)
		}
	})
}

func TestSystemTenantIsValidAndDistinct(t *testing.T) {
	if string(System) != systemLiteral {
		t.Fatalf("System = %q, want the value fixed by ADR 0004 %q", System, systemLiteral)
	}
	id, err := ParseID(systemLiteral)
	if err != nil {
		t.Fatalf("ParseID(System literal): unexpected error %v", err)
	}
	if id != System {
		t.Fatalf("ParseID(System literal) = %q, want System", id)
	}
	if len(System) != 36 {
		t.Fatalf("len(System) = %d, want 36", len(System))
	}
	if System[14] != '8' {
		t.Fatalf("System version nibble = %q, want '8'", System[14])
	}
	if !strings.ContainsRune("89ab", rune(System[19])) {
		t.Fatalf("System variant nibble = %q, want one of 89ab", System[19])
	}
	if System[14] == '4' {
		t.Fatal("System is a version 4 UUID, it would collide with the customer tenant space")
	}
	if System == "00000000-0000-0000-0000-000000000000" {
		t.Fatal("System must not be the nil UUID")
	}
	if System == "ffffffff-ffff-ffff-ffff-ffffffffffff" {
		t.Fatal("System must not be the max UUID")
	}
	if System == ID(tenantA) {
		t.Fatal("System must differ from a customer tenant")
	}
	ctx := mustWithTenant(t, t.Context(), System)
	if err := Require(ctx, System); err != nil {
		t.Fatalf("Require(ctx, System): unexpected error %v", err)
	}
}

func TestWithTenantMismatch(t *testing.T) {
	ctxA := mustWithTenant(t, t.Context(), ID(tenantA))
	ctxSystem := mustWithTenant(t, t.Context(), System)

	refusals := []struct {
		name   string
		ctx    context.Context
		holds  ID
		target ID
	}{
		{name: "overwrite_refused", ctx: ctxA, holds: ID(tenantA), target: ID(tenantB)},
		{name: "client_to_system_refused", ctx: ctxA, holds: ID(tenantA), target: System},
		{name: "system_to_client_refused", ctx: ctxSystem, holds: System, target: ID(tenantA)},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WithTenant(tc.ctx, tc.target)
			if got != nil {
				t.Fatalf("%s: WithTenant returned a non nil context on mismatch", tc.name)
			}
			if !errors.Is(err, ErrTenantMismatch) {
				t.Fatalf("%s: error %v, want ErrTenantMismatch", tc.name, err)
			}
			assertCarries(t, tc.ctx, tc.holds)
		})
	}

	t.Run("same_tenant_is_noop", func(t *testing.T) {
		got, err := WithTenant(ctxA, ID(tenantA))
		if err != nil {
			t.Fatalf("same_tenant_is_noop: unexpected error %v", err)
		}
		if got != ctxA {
			t.Fatal("same_tenant_is_noop: WithTenant did not return the parent context itself")
		}
	})

	t.Run("refused_through_derived_contexts", func(t *testing.T) {
		cancelCtx, cancel := context.WithCancel(ctxA)
		defer cancel()
		timeoutCtx, cancelTimeout := context.WithTimeout(ctxA, time.Minute)
		defer cancelTimeout()
		derived := []struct {
			name string
			ctx  context.Context
		}{
			{name: "with_cancel", ctx: cancelCtx},
			{name: "with_timeout", ctx: timeoutCtx},
			{name: "without_cancel", ctx: context.WithoutCancel(ctxA)},
			{name: "with_foreign_value", ctx: context.WithValue(ctxA, foreignKey{}, 1)},
		}
		for _, d := range derived {
			got, err := WithTenant(d.ctx, ID(tenantB))
			if got != nil {
				t.Fatalf("%s: WithTenant returned a non nil context on mismatch", d.name)
			}
			if !errors.Is(err, ErrTenantMismatch) {
				t.Fatalf("%s: error %v, want ErrTenantMismatch", d.name, err)
			}
		}
	})
}

func TestFromContextInvalidStoredValue(t *testing.T) {
	cases := []struct {
		name  string
		value any
	}{
		{name: "empty_id", value: ID("")},
		{name: "garbage_id", value: ID("BAD")},
		{name: "nil_uuid_id", value: ID("00000000-0000-0000-0000-000000000000")},
		{name: "uppercase_id", value: ID(strings.ToUpper(tenantA))},
		// Right text, wrong type: an untyped string constant stored as any is a string, not an ID.
		{name: "string_type", value: tenantA},
		{name: "int_type", value: 42},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), ctxKey{}, tc.value)

			id, err := FromContext(ctx)
			if id != "" {
				t.Fatalf("%s: FromContext returned %q for an invalid stored value", tc.name, id)
			}
			if !errors.Is(err, ErrInvalidTenant) {
				t.Fatalf("%s: FromContext error %v, want ErrInvalidTenant", tc.name, err)
			}
			if errors.Is(err, ErrNoTenant) {
				t.Fatalf("%s: FromContext error %v must not be ErrNoTenant (fail closed)", tc.name, err)
			}

			got, err := WithTenant(ctx, ID(tenantA))
			if got != nil {
				t.Fatalf("%s: WithTenant overwrote an invalid stored value", tc.name)
			}
			if !errors.Is(err, ErrInvalidTenant) {
				t.Fatalf("%s: WithTenant error %v, want ErrInvalidTenant", tc.name, err)
			}

			if err := Require(ctx, ID(tenantA)); !errors.Is(err, ErrInvalidTenant) {
				t.Fatalf("%s: Require error %v, want ErrInvalidTenant", tc.name, err)
			}
		})
	}
}

func TestNilContext(t *testing.T) {
	var nilCtx context.Context

	got, err := WithTenant(nilCtx, ID(tenantA))
	if got != nil {
		t.Fatal("WithTenant(nil ctx): returned a non nil context")
	}
	if !errors.Is(err, ErrNilContext) {
		t.Fatalf("WithTenant(nil ctx): error %v, want ErrNilContext", err)
	}

	id, err := FromContext(nilCtx)
	if id != "" {
		t.Fatalf("FromContext(nil ctx): returned %q", id)
	}
	if !errors.Is(err, ErrNoTenant) || !errors.Is(err, ErrNilContext) {
		t.Fatalf("FromContext(nil ctx): error %v, want both ErrNoTenant and ErrNilContext", err)
	}

	err = Require(nilCtx, ID(tenantA))
	if !errors.Is(err, ErrNoTenant) || !errors.Is(err, ErrNilContext) {
		t.Fatalf("Require(nil ctx, A): error %v, want both ErrNoTenant and ErrNilContext", err)
	}

	if err := Require(nilCtx, ""); !errors.Is(err, ErrInvalidTenant) {
		t.Fatalf("Require(nil ctx, empty): error %v, want ErrInvalidTenant", err)
	}
}

func TestRequireInvalidWant(t *testing.T) {
	wants := []struct {
		name string
		id   ID
	}{
		{name: "empty", id: ""},
		{name: "uppercase", id: ID(strings.ToUpper(tenantA))},
		{name: "nil_uuid", id: "00000000-0000-0000-0000-000000000000"},
		{name: "max_uuid", id: "ffffffff-ffff-ffff-ffff-ffffffffffff"},
		{name: "trailing_space", id: ID(tenantA + " ")},
		{name: "version_8_not_system", id: "00000000-0000-8000-8000-000000000002"},
	}
	contexts := []struct {
		name string
		ctx  context.Context
	}{
		{name: "bare", ctx: t.Context()},
		{name: "carrying_a", ctx: mustWithTenant(t, t.Context(), ID(tenantA))},
		{name: "carrying_system", ctx: mustWithTenant(t, t.Context(), System)},
	}
	for _, c := range contexts {
		t.Run(c.name, func(t *testing.T) {
			for _, w := range wants {
				t.Run(w.name, func(t *testing.T) {
					err := Require(c.ctx, w.id)
					if err == nil {
						t.Fatalf("%s/%s: Require accepted an invalid want", c.name, w.name)
					}
					if !errors.Is(err, ErrInvalidTenant) {
						t.Fatalf("%s/%s: error %v, want ErrInvalidTenant", c.name, w.name, err)
					}
					if errors.Is(err, ErrTenantMismatch) || errors.Is(err, ErrNoTenant) {
						t.Fatalf("%s/%s: error %v must be ErrInvalidTenant only", c.name, w.name, err)
					}
				})
			}
		})
	}
}

func TestErrorsDoNotEchoInput(t *testing.T) {
	t.Run("parse_input_not_quoted", func(t *testing.T) {
		inputs := []struct {
			name  string
			input string
		}{
			{name: "canary_36_bytes", input: "zzzzzzzz-zzzz-4zzz-8zzz-CANARYCANARY"},
			{name: "canary_long", input: strings.Repeat("CANARY", 2000)},
			{name: "format_verbs", input: "%s%v%d" + tenantA},
		}
		for _, in := range inputs {
			_, err := ParseID(in.input)
			if err == nil {
				t.Fatalf("%s: ParseID accepted an invalid input", in.name)
			}
			msg := err.Error()
			for _, forbidden := range []string{"CANARY", "%s", tenantA} {
				if strings.Contains(msg, forbidden) {
					t.Fatalf("%s: error message echoes %q: %q", in.name, forbidden, msg)
				}
			}
			if len(msg) >= 128 {
				t.Fatalf("%s: error message is %d bytes, want less than 128", in.name, len(msg))
			}
		}
	})

	t.Run("mismatch_hides_tenants", func(t *testing.T) {
		ctxA := mustWithTenant(t, t.Context(), ID(tenantA))
		_, withErr := WithTenant(ctxA, ID(tenantB))
		reqErr := Require(ctxA, ID(tenantB))
		for name, err := range map[string]error{"with_tenant": withErr, "require": reqErr} {
			if err == nil {
				t.Fatalf("%s: expected a mismatch error", name)
			}
			msg := err.Error()
			for _, forbidden := range []string{tenantA, tenantB, tenantA[:8], tenantB[:8]} {
				if strings.Contains(msg, forbidden) {
					t.Fatalf("%s: error message reveals a tenant id (%q): %q", name, forbidden, msg)
				}
			}
		}
	})
}

func TestSentinelErrors(t *testing.T) {
	sentinels := []struct {
		name string
		err  error
	}{
		{name: "ErrNoTenant", err: ErrNoTenant},
		{name: "ErrInvalidTenant", err: ErrInvalidTenant},
		{name: "ErrTenantMismatch", err: ErrTenantMismatch},
		{name: "ErrNilContext", err: ErrNilContext},
	}
	for _, s := range sentinels {
		if s.err == nil {
			t.Fatalf("%s is nil", s.name)
		}
		if !strings.HasPrefix(s.err.Error(), "tenancy: ") {
			t.Fatalf("%s message %q does not start with %q", s.name, s.err.Error(), "tenancy: ")
		}
	}
	for i, a := range sentinels {
		for j, b := range sentinels {
			if i != j && errors.Is(a.err, b.err) {
				t.Fatalf("%s matches %s under errors.Is, want distinct sentinels", a.name, b.name)
			}
		}
	}
}

func TestTenantSurvivesDerivedContexts(t *testing.T) {
	ctxA := mustWithTenant(t, t.Context(), ID(tenantA))

	t.Run("with_cancel", func(t *testing.T) {
		child, cancel := context.WithCancel(ctxA)
		assertCarries(t, child, ID(tenantA))
		cancel()
		assertCarries(t, child, ID(tenantA))
	})
	t.Run("with_timeout", func(t *testing.T) {
		child, cancel := context.WithTimeout(ctxA, time.Minute)
		assertCarries(t, child, ID(tenantA))
		cancel()
		assertCarries(t, child, ID(tenantA))
	})
	t.Run("without_cancel", func(t *testing.T) {
		assertCarries(t, context.WithoutCancel(ctxA), ID(tenantA))
	})
	t.Run("with_foreign_value", func(t *testing.T) {
		assertCarries(t, context.WithValue(ctxA, foreignKey{}, 1), ID(tenantA))
	})
	t.Run("grandchild", func(t *testing.T) {
		child, cancel := context.WithCancel(ctxA)
		defer cancel()
		grandchild := context.WithValue(child, foreignKey{}, 2)
		assertCarries(t, grandchild, ID(tenantA))
	})
}
