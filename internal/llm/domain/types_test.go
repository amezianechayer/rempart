package domain

import (
	"errors"
	"strings"
	"testing"
)

// namedSentinel pairs a sentinel error with its identifier for messages.
type namedSentinel struct {
	name string
	err  error
}

func allSentinels() []namedSentinel {
	return []namedSentinel{
		{name: "ErrResidency", err: ErrResidency},
		{name: "ErrRetention", err: ErrRetention},
		{name: "ErrModelNotPinned", err: ErrModelNotPinned},
		{name: "ErrInvalidRoute", err: ErrInvalidRoute},
		{name: "ErrUntrustedWithTools", err: ErrUntrustedWithTools},
		{name: "ErrInvalidPart", err: ErrInvalidPart},
		{name: "ErrInvalidRequest", err: ErrInvalidRequest},
		{name: "ErrNoRoute", err: ErrNoRoute},
	}
}

// checkErr asserts that err is nil when want is nil; otherwise that err
// matches want under errors.Is and matches no other sentinel of the package.
func checkErr(t *testing.T, name string, err, want error) {
	t.Helper()
	if want == nil {
		if err != nil {
			t.Fatalf("%s: unexpected error %v, want nil", name, err)
		}
		return
	}
	if err == nil {
		t.Fatalf("%s: got nil error, want %v", name, want)
	}
	if !errors.Is(err, want) {
		t.Fatalf("%s: got error %v, want one matching %v", name, err, want)
	}
	for _, s := range allSentinels() {
		if errors.Is(s.err, want) {
			continue
		}
		if errors.Is(err, s.err) {
			t.Fatalf("%s: error %v also matches %s, want only %v", name, err, s.name, want)
		}
	}
}

func textPart(s string) Part { return Part{Text: s} }

func untrustedPart(id, content string) Part {
	return Part{Untrusted: &UntrustedBlock{SourceID: id, Content: content}}
}

func TestRequestHasUntrusted(t *testing.T) {
	cases := []struct {
		name string
		req  Request
		want bool
	}{
		{name: "empty_request", req: Request{}, want: false},
		{
			name: "text_only",
			req: Request{Messages: []Message{
				{Role: RoleUser, Parts: []Part{textPart("hello"), textPart("world")}},
				{Role: RoleAssistant, Parts: []Part{textPart("ok")}},
			}},
			want: false,
		},
		{
			name: "untrusted_first_part",
			req: Request{Messages: []Message{
				{Role: RoleUser, Parts: []Part{untrustedPart("r-7f3a", "data"), textPart("hello")}},
			}},
			want: true,
		},
		{
			name: "untrusted_second_message",
			req: Request{Messages: []Message{
				{Role: RoleUser, Parts: []Part{textPart("hello")}},
				{Role: RoleUser, Parts: []Part{textPart("more"), untrustedPart("r-7f3a", "data")}},
			}},
			want: true,
		},
		{
			name: "untrusted_in_assistant_message",
			req: Request{Messages: []Message{
				{Role: RoleUser, Parts: []Part{textPart("hello")}},
				{Role: RoleAssistant, Parts: []Part{untrustedPart("r-7f3a", "data")}},
			}},
			want: true,
		},
		{
			name: "both_fields_set",
			req: Request{Messages: []Message{
				{Role: RoleUser, Parts: []Part{{Text: "hello", Untrusted: &UntrustedBlock{SourceID: "r-7f3a", Content: "data"}}}},
			}},
			want: true,
		},
		{
			name: "empty_block",
			req: Request{Messages: []Message{
				{Role: RoleUser, Parts: []Part{{Untrusted: &UntrustedBlock{}}}},
			}},
			want: true,
		},
		{
			// Documented limit (plan 2.2): text smuggled into System is not detectable by type.
			name: "tag_in_system_not_detected",
			req: Request{
				System: `<DONNÉES_NON_FIABLES id="x">`,
				Messages: []Message{
					{Role: RoleUser, Parts: []Part{textPart(`<DONNÉES_NON_FIABLES id="x">`)}},
				},
			},
			want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.req.HasUntrusted(); got != tc.want {
				t.Fatalf("%s: HasUntrusted() = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestPartExactlyOne(t *testing.T) {
	cases := []struct {
		name string
		part Part
		want error
	}{
		{name: "text_only", part: Part{Text: "hello"}, want: nil},
		{name: "untrusted_only", part: untrustedPart("r-7f3a", "data"), want: nil},
		{name: "untrusted_empty_block", part: Part{Untrusted: &UntrustedBlock{}}, want: nil},
		{name: "both", part: Part{Text: "hello", Untrusted: &UntrustedBlock{Content: "data"}}, want: ErrInvalidPart},
		{name: "neither", part: Part{}, want: ErrInvalidPart},
		{name: "untrusted_with_space_text", part: Part{Text: " ", Untrusted: &UntrustedBlock{Content: "data"}}, want: ErrInvalidPart},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkErr(t, tc.name, tc.part.Validate(), tc.want)
		})
	}
}

func TestRequestValidate(t *testing.T) {
	valid := func() Request {
		return Request{Messages: []Message{
			{Role: RoleUser, Parts: []Part{textPart("hello"), untrustedPart("r-7f3a", "data")}},
			{Role: RoleAssistant, Parts: []Part{textPart("ok")}},
		}}
	}
	withRole := func(r Role) Request {
		req := valid()
		req.Messages[0].Role = r
		return req
	}
	cases := []struct {
		name string
		req  Request
		want error
	}{
		{name: "valid", req: valid(), want: nil},
		{name: "no_messages", req: Request{System: "sys"}, want: ErrInvalidRequest},
		{name: "role_system", req: withRole("system"), want: ErrInvalidRequest},
		{name: "role_empty", req: withRole(""), want: ErrInvalidRequest},
		{name: "role_capitalized", req: withRole("User"), want: ErrInvalidRequest},
		{
			name: "message_without_parts",
			req: Request{Messages: []Message{
				{Role: RoleUser, Parts: []Part{textPart("hello")}},
				{Role: RoleAssistant},
			}},
			want: ErrInvalidRequest,
		},
		{
			name: "invalid_part",
			req: Request{Messages: []Message{
				{Role: RoleUser, Parts: []Part{textPart("hello"), {}}},
			}},
			want: ErrInvalidPart,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkErr(t, tc.name, tc.req.Validate(), tc.want)
		})
	}
}

func TestSentinelErrors(t *testing.T) {
	sentinels := allSentinels()
	if len(sentinels) != 8 {
		t.Fatalf("got %d sentinels, want 8", len(sentinels))
	}
	for _, s := range sentinels {
		if s.err == nil {
			t.Fatalf("%s is nil", s.name)
		}
		if !strings.HasPrefix(s.err.Error(), "llm: ") {
			t.Fatalf("%s message %q does not start with %q", s.name, s.err.Error(), "llm: ")
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
