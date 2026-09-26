package domain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"testing"

	"pgregory.net/rapid"
)

var hashFormat = regexp.MustCompile(`^[0-9a-f]{64}$`)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func deepCopyRequest(r Request) Request {
	c := r
	if r.Schema != nil {
		c.Schema = append(json.RawMessage{}, r.Schema...)
	}
	if r.Messages != nil {
		c.Messages = make([]Message, len(r.Messages))
		for i, m := range r.Messages {
			cm := Message{Role: m.Role}
			if m.Parts != nil {
				cm.Parts = make([]Part, len(m.Parts))
				for j, p := range m.Parts {
					cp := Part{Text: p.Text}
					if p.Untrusted != nil {
						b := *p.Untrusted
						cp.Untrusted = &b
					}
					cm.Parts[j] = cp
				}
			}
			c.Messages[i] = cm
		}
	}
	return c
}

func genRole() *rapid.Generator[Role] {
	return rapid.OneOf(
		rapid.SampledFrom([]Role{RoleUser, RoleAssistant}),
		rapid.Map(rapid.String(), func(s string) Role { return Role(s) }),
	)
}

func genPart() *rapid.Generator[Part] {
	return rapid.Custom(func(t *rapid.T) Part {
		switch rapid.IntRange(0, 2).Draw(t, "kind") {
		case 0:
			return Part{Text: rapid.String().Draw(t, "text")}
		case 1:
			return Part{Untrusted: &UntrustedBlock{
				SourceID: rapid.String().Draw(t, "source_id"),
				Content:  rapid.String().Draw(t, "content"),
			}}
		default:
			return Part{
				Text: rapid.String().Draw(t, "text"),
				Untrusted: &UntrustedBlock{
					SourceID: rapid.String().Draw(t, "source_id"),
					Content:  rapid.String().Draw(t, "content"),
				},
			}
		}
	})
}

func genRequest() *rapid.Generator[Request] {
	return rapid.Custom(func(t *rapid.T) Request {
		r := Request{
			PromptID:   rapid.String().Draw(t, "prompt_id"),
			PromptHash: rapid.String().Draw(t, "prompt_hash"),
			System:     rapid.String().Draw(t, "system"),
			Schema:     json.RawMessage(rapid.String().Draw(t, "schema")),
			MaxTokens:  rapid.Int().Draw(t, "max_tokens"),
		}
		n := rapid.IntRange(0, 3).Draw(t, "messages")
		for range n {
			m := Message{Role: genRole().Draw(t, "role")}
			k := rapid.IntRange(0, 3).Draw(t, "parts")
			for range k {
				m.Parts = append(m.Parts, genPart().Draw(t, "part"))
			}
			r.Messages = append(r.Messages, m)
		}
		return r
	})
}

// oneChange returns a deep copy of r with exactly one field changed.
func oneChange(t *rapid.T, r Request) Request {
	c := deepCopyRequest(r)
	type change struct {
		name  string
		apply func()
	}
	changes := []change{
		{"prompt_id", func() { c.PromptID += "x" }},
		{"prompt_hash", func() { c.PromptHash += "x" }},
		{"system", func() { c.System += "x" }},
		{"schema", func() { c.Schema = append(c.Schema, 'x') }},
		{"max_tokens", func() { c.MaxTokens++ }},
		{"add_message", func() { c.Messages = append(c.Messages, Message{Role: RoleUser}) }},
	}
	for i := range c.Messages {
		m := &c.Messages[i]
		switch m.Role {
		case RoleUser:
			changes = append(changes, change{"role_to_assistant", func() { m.Role = RoleAssistant }})
		case RoleAssistant:
			changes = append(changes, change{"role_to_user", func() { m.Role = RoleUser }})
		}
		for j := range m.Parts {
			p := &m.Parts[j]
			changes = append(changes, change{"part_text", func() { p.Text += "x" }})
			if p.Untrusted != nil {
				changes = append(changes,
					change{"part_source_id", func() { p.Untrusted.SourceID += "x" }},
					change{"part_content", func() { p.Untrusted.Content += "x" }},
					change{"part_untrusted_to_nil", func() { p.Untrusted = nil }},
				)
			} else {
				changes = append(changes, change{"part_untrusted_to_empty", func() { p.Untrusted = &UntrustedBlock{} }})
			}
		}
	}
	i := rapid.IntRange(0, len(changes)-1).Draw(t, "change")
	t.Logf("change: %s", changes[i].name)
	changes[i].apply()
	return c
}

func TestRequestHashCanonical(t *testing.T) {
	t.Run("golden", func(t *testing.T) {
		req := Request{
			PromptID:   "demo.greeting.v1",
			PromptHash: "abc",
			System:     "sys <x> & y",
			Messages: []Message{{Role: RoleUser, Parts: []Part{
				{Text: "hello"},
				{Untrusted: &UntrustedBlock{SourceID: "r-7f3a", Content: "tag"}},
			}}},
			Schema:    json.RawMessage(`{"type":"object"}`),
			MaxTokens: 256,
		}
		// json.Marshal escapes <, > and & as \u003c, \u003e and \u0026 (plan P4).
		canon := `{"v":1,"prompt_id":"demo.greeting.v1","prompt_hash":"abc","system":"sys \u003cx\u003e \u0026 y","messages":[{"role":"user","parts":[{"text":"hello","untrusted":null},{"text":"","untrusted":{"source_id":"r-7f3a","content":"tag"}}]}],"schema":"{\"type\":\"object\"}","max_tokens":256}`
		if got, want := RequestHash(req), sha256Hex(canon); got != want {
			t.Fatalf("golden: RequestHash = %s, want %s (sha256 of %s)", got, want, canon)
		}
	})

	t.Run("golden_empty", func(t *testing.T) {
		canon := `{"v":1,"prompt_id":"","prompt_hash":"","system":"","messages":[],"schema":"","max_tokens":0}`
		if got, want := RequestHash(Request{}), sha256Hex(canon); got != want {
			t.Fatalf("golden_empty: RequestHash = %s, want %s (sha256 of %s)", got, want, canon)
		}
	})

	t.Run("golden_message_without_parts", func(t *testing.T) {
		canon := `{"v":1,"prompt_id":"","prompt_hash":"","system":"","messages":[{"role":"user","parts":[]}],"schema":"","max_tokens":0}`
		req := Request{Messages: []Message{{Role: "user"}}}
		if got, want := RequestHash(req), sha256Hex(canon); got != want {
			t.Fatalf("golden_message_without_parts: RequestHash = %s, want %s (sha256 of %s)", got, want, canon)
		}
	})

	t.Run("nil_equals_empty", func(t *testing.T) {
		pairs := []struct {
			name string
			a, b Request
		}{
			{name: "messages", a: Request{Messages: nil}, b: Request{Messages: []Message{}}},
			{
				name: "parts",
				a:    Request{Messages: []Message{{Role: RoleUser, Parts: nil}}},
				b:    Request{Messages: []Message{{Role: RoleUser, Parts: []Part{}}}},
			},
			{name: "schema", a: Request{Schema: nil}, b: Request{Schema: json.RawMessage{}}},
		}
		for _, p := range pairs {
			if RequestHash(p.a) != RequestHash(p.b) {
				t.Fatalf("nil_equals_empty/%s: nil and empty give different hashes", p.name)
			}
		}
	})

	t.Run("format", func(t *testing.T) {
		reqs := []Request{
			{},
			{PromptID: "demo.greeting.v1", Messages: []Message{{Role: RoleUser, Parts: []Part{{Text: "hello"}}}}},
		}
		for i, r := range reqs {
			if h := RequestHash(r); !hashFormat.MatchString(h) {
				t.Fatalf("format: request %d hash %q is not 64 lower-case hex characters", i, h)
			}
		}
	})

	t.Run("order_matters", func(t *testing.T) {
		m1 := Message{Role: RoleUser, Parts: []Part{{Text: "first"}}}
		m2 := Message{Role: RoleAssistant, Parts: []Part{{Text: "second"}}}
		a := Request{Messages: []Message{m1, m2}}
		b := Request{Messages: []Message{m2, m1}}
		if RequestHash(a) == RequestHash(b) {
			t.Fatal("order_matters: permuted messages give the same hash")
		}
	})

	t.Run("text_vs_untrusted", func(t *testing.T) {
		a := Request{Messages: []Message{{Role: RoleUser, Parts: []Part{{Text: "a"}}}}}
		b := Request{Messages: []Message{{Role: RoleUser, Parts: []Part{{Untrusted: &UntrustedBlock{Content: "a"}}}}}}
		if RequestHash(a) == RequestHash(b) {
			t.Fatal("text_vs_untrusted: trusted text and untrusted content give the same hash")
		}
	})

	t.Run("schema_bytes_matter", func(t *testing.T) {
		a := Request{Schema: json.RawMessage(`{"a":1}`)}
		b := Request{Schema: json.RawMessage(`{"a": 1}`)}
		if RequestHash(a) == RequestHash(b) {
			t.Fatal("schema_bytes_matter: schemas differing by one byte give the same hash")
		}
	})

	t.Run("property_copy", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			r := genRequest().Draw(rt, "request")
			if RequestHash(r) != RequestHash(deepCopyRequest(r)) {
				rt.Fatalf("a deep copy has a different hash")
			}
		})
	})

	t.Run("property_one_change", func(t *testing.T) {
		rapid.Check(t, func(rt *rapid.T) {
			r := genRequest().Draw(rt, "request")
			before := RequestHash(r)
			changed := oneChange(rt, r)
			if RequestHash(r) != before {
				rt.Fatalf("the original request was mutated by the change")
			}
			if RequestHash(changed) == before {
				rt.Fatalf("a one-field change gives the same hash")
			}
		})
	})
}
