package prompts

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

const (
	fixtureID  = "fixture.v1"
	fullOutput = `{"greeting":"Bonjour","count":3,"tags":[{"key":"env","level":"low"}]}`
	// smallSchema is a minimal strict schema for content tests.
	smallSchema = `{"type":"object","additionalProperties":false,"required":["a"],"properties":{"a":{"type":"string"}}}`
)

// countingFS implements only Open and counts its calls.
type countingFS struct {
	fsys  fs.FS
	opens int
}

func (c *countingFS) Open(name string) (fs.File, error) {
	c.opens++
	return c.fsys.Open(name)
}

// fixtureFiles returns the system.txt and schema.json bytes of testdata/fixture.v1.
func fixtureFiles(t *testing.T) (system, schemaRaw []byte) {
	t.Helper()
	dir := os.DirFS("testdata")
	system, err := fs.ReadFile(dir, fixtureID+"/system.txt")
	if err != nil {
		t.Fatal(err)
	}
	schemaRaw, err = fs.ReadFile(dir, fixtureID+"/schema.json")
	if err != nil {
		t.Fatal(err)
	}
	return system, schemaRaw
}

// promptFS is a MapFS holding one prompt directory.
func promptFS(id string, system, schemaRaw []byte) fstest.MapFS {
	return fstest.MapFS{
		id + "/system.txt":  {Data: system},
		id + "/schema.json": {Data: schemaRaw},
	}
}

func mustLoad(t *testing.T, fsys fs.FS, id string) Prompt {
	t.Helper()
	p, err := LoadFS(fsys, id)
	if err != nil {
		t.Fatalf("LoadFS(%q) = %v, want nil", id, err)
	}
	return p
}

// Test 10: the testdata fixture loads with its identifier, version, exact
// contents, a hex SHA-256 hash and a working schema.
func TestLoadFSFixture(t *testing.T) {
	system, schemaRaw := fixtureFiles(t)
	p := mustLoad(t, os.DirFS("testdata"), fixtureID)
	if p.ID != fixtureID {
		t.Errorf("ID = %q, want %q", p.ID, fixtureID)
	}
	if p.Version != 1 {
		t.Errorf("Version = %d, want 1", p.Version)
	}
	if p.System != string(system) {
		t.Errorf("System = %q, want the content of system.txt %q", p.System, system)
	}
	if p.Schema == nil {
		t.Fatal("Schema is nil")
	}
	if got := p.Schema.Raw(); string(got) != string(schemaRaw) {
		t.Errorf("Schema.Raw() differs from schema.json\n got: %q\nwant: %q", got, schemaRaw)
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(p.Hash) {
		t.Errorf("Hash = %q, want 64 lowercase hex digits", p.Hash)
	}
	if err := p.Schema.Validate([]byte(fullOutput)); err != nil {
		t.Errorf("Schema.Validate(FULL) = %v, want nil", err)
	}
}

// Test 11 (task sheet): the hash is the documented netstring SHA-256, stable,
// and sensitive to the identifier, the system prompt and every schema byte.
func TestPromptHashStableAndSensitive(t *testing.T) {
	system, schemaRaw := fixtureFiles(t)
	base := mustLoad(t, os.DirFS("testdata"), fixtureID)

	t.Run("golden", func(t *testing.T) {
		preimage := fmt.Sprintf("rempart-prompt-v1\n%d:%s,%d:%s,%d:%s,",
			len(fixtureID), fixtureID, len(system), system, len(schemaRaw), schemaRaw)
		sum := sha256.Sum256([]byte(preimage))
		if want := hex.EncodeToString(sum[:]); base.Hash != want {
			t.Errorf("Hash = %s, want %s", base.Hash, want)
		}
	})
	t.Run("stable", func(t *testing.T) {
		again := mustLoad(t, os.DirFS("testdata"), fixtureID)
		copied := mustLoad(t, promptFS(fixtureID, system, schemaRaw), fixtureID)
		if again.Hash != base.Hash || copied.Hash != base.Hash {
			t.Errorf("hash not stable: %s, %s, %s", base.Hash, again.Hash, copied.Hash)
		}
	})
	t.Run("system_changed", func(t *testing.T) {
		changed := append([]byte("Autre consigne. "), system...)
		p := mustLoad(t, promptFS(fixtureID, changed, schemaRaw), fixtureID)
		if p.Hash == base.Hash {
			t.Error("hash unchanged after a system prompt change")
		}
	})
	t.Run("schema_whitespace", func(t *testing.T) {
		spaced := append(append([]byte{}, schemaRaw...), ' ')
		p := mustLoad(t, promptFS(fixtureID, system, spaced), fixtureID)
		if p.Hash == base.Hash {
			t.Error("hash unchanged after a whitespace change in schema.json")
		}
	})
	t.Run("other_version", func(t *testing.T) {
		p := mustLoad(t, promptFS("fixture.v2", system, schemaRaw), "fixture.v2")
		if p.Version != 2 {
			t.Errorf("Version = %d, want 2", p.Version)
		}
		if p.Hash == base.Hash {
			t.Error("hash unchanged for another version with the same files")
		}
	})
	t.Run("other_name", func(t *testing.T) {
		p := mustLoad(t, promptFS("other.v1", system, schemaRaw), "other.v1")
		if p.Hash == base.Hash {
			t.Error("hash unchanged for another name with the same files")
		}
	})
}

// Test 12 (task sheet): an unknown prompt is refused with ErrUnknownPrompt.
func TestPromptUnknownID(t *testing.T) {
	system, schemaRaw := fixtureFiles(t)
	cases := []struct {
		name string
		load func() (Prompt, error)
	}{
		{"absent_in_fs", func() (Prompt, error) { return LoadFS(os.DirFS("testdata"), "absent.v1") }},
		{"load_absent", func() (Prompt, error) { return Load("absent.v1") }},
		{"testdata_not_embedded", func() (Prompt, error) { return Load(fixtureID) }},
		{"missing_schema", func() (Prompt, error) {
			return LoadFS(fstest.MapFS{fixtureID + "/system.txt": {Data: system}}, fixtureID)
		}},
		{"missing_system", func() (Prompt, error) {
			return LoadFS(fstest.MapFS{fixtureID + "/schema.json": {Data: schemaRaw}}, fixtureID)
		}},
		{"nil_fs", func() (Prompt, error) { return LoadFS(nil, fixtureID) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := tc.load()
			if !errors.Is(err, ErrUnknownPrompt) {
				t.Fatalf("%s: error = %v, want ErrUnknownPrompt", tc.name, err)
			}
			if p.ID != "" || p.Schema != nil || p.Hash != "" {
				t.Errorf("%s: non-zero prompt returned with an error: %+v", tc.name, p)
			}
		})
	}
}

// Test 13: a malformed or path-like identifier is refused with
// ErrInvalidPromptID before any file system access.
func TestPromptInvalidID(t *testing.T) {
	system, schemaRaw := fixtureFiles(t)
	backing := fstest.MapFS{
		fixtureID + "/system.txt":                {Data: system},
		fixtureID + "/schema.json":               {Data: schemaRaw},
		"testdata/" + fixtureID + "/system.txt":  {Data: system},
		"testdata/" + fixtureID + "/schema.json": {Data: schemaRaw},
	}
	invalid := []struct{ name, id string }{
		{"empty", ""},
		{"no_version", "fixture"},
		{"version_without_number", "fixture.v"},
		{"version_zero", "fixture.v0"},
		{"version_leading_zero", "fixture.v01"},
		{"uppercase_v", "fixture.V1"},
		{"uppercase_name", "Fixture.v1"},
		{"version_seven_digits", "fixture.v1234567"},
		{"parent_traversal", "../fixture.v1"},
		{"dot_prefix", "./fixture.v1"},
		{"subdirectory", "testdata/fixture.v1"},
		{"trailing_slash", "fixture.v1/"},
		{"inner_traversal", "fixture.v1/../fixture.v1"},
		{"empty_name", ".v1"},
		{"empty_segment", "a..b.v1"},
		{"hyphen", "a-b.v1"},
		{"trailing_newline", "fixture.v1\n"},
		{"trailing_nul", "fixture.v1\x00"},
		{"leading_space", " fixture.v1"},
		{"leading_digit", "1a.v1"},
		{"too_long_65", strings.Repeat("a", 62) + ".v1"},
	}
	witnesses := []struct{ name, id string }{
		{"witness_max_len_64", strings.Repeat("a", 61) + ".v1"},
		{"witness_segments_max_version", "a_b.c9.v123456"},
	}
	if len(invalid)+len(witnesses) != 23 {
		t.Fatalf("case table: %d cases, want 23", len(invalid)+len(witnesses))
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			c := &countingFS{fsys: backing}
			_, err := LoadFS(c, tc.id)
			if !errors.Is(err, ErrInvalidPromptID) {
				t.Errorf("LoadFS(%q) error = %v, want ErrInvalidPromptID", tc.id, err)
			}
			if c.opens != 0 {
				t.Errorf("LoadFS(%q) opened %d files, want 0", tc.id, c.opens)
			}
		})
	}
	for _, tc := range witnesses {
		t.Run(tc.name, func(t *testing.T) {
			c := &countingFS{fsys: backing}
			_, err := LoadFS(c, tc.id)
			if !errors.Is(err, ErrUnknownPrompt) {
				t.Errorf("LoadFS(%q) error = %v, want ErrUnknownPrompt", tc.id, err)
			}
			if c.opens == 0 {
				t.Errorf("LoadFS(%q) never opened a file, want a lookup", tc.id)
			}
		})
	}
}

// Test 14: invalid prompt contents are refused with ErrInvalidPrompt.
func TestPromptInvalidContent(t *testing.T) {
	const id = "p.v1"
	valid := []byte(smallSchema)
	cases := []struct {
		name    string
		fsys    fstest.MapFS
		wantErr bool
		wantMsg string
	}{
		{"empty_system", promptFS(id, []byte{}, valid), true, ""},
		{"system_cr", promptFS(id, []byte("line one\r\nline two\n"), valid), true, ""},
		{"system_invalid_utf8", promptFS(id, []byte("text \xff\n"), valid), true, ""},
		{"system_too_large", promptFS(id, []byte(strings.Repeat("a", MaxSystemBytes+1)), valid), true, ""},
		{"system_is_dir", fstest.MapFS{
			id + "/system.txt/inner.txt": {Data: []byte("text\n")},
			id + "/schema.json":          {Data: valid},
		}, true, ""},
		{"schema_not_strict", promptFS(id, []byte("text\n"), []byte(`{"type":"object"}`)), true, "llm: schema is not strict"},
		{"schema_not_json", promptFS(id, []byte("text\n"), []byte(`{"type":`)), true, "llm: invalid schema"},
		{"system_max_size", promptFS(id, []byte(strings.Repeat("a", MaxSystemBytes)), valid), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := LoadFS(tc.fsys, id)
			if !tc.wantErr {
				if err != nil {
					t.Fatalf("LoadFS = %v, want nil", err)
				}
				if p.ID != id || p.Schema == nil {
					t.Errorf("LoadFS returned an incomplete prompt: %+v", p)
				}
				return
			}
			if !errors.Is(err, ErrInvalidPrompt) {
				t.Fatalf("LoadFS error = %v, want ErrInvalidPrompt", err)
			}
			if tc.wantMsg != "" && !strings.Contains(err.Error(), tc.wantMsg) {
				t.Errorf("LoadFS error %q does not contain %q", err.Error(), tc.wantMsg)
			}
			if p.Schema != nil || p.Hash != "" {
				t.Errorf("non-zero prompt returned with an error: %+v", p)
			}
		})
	}
}

// Test 15: every embedded prompt directory loads.
func TestEmbeddedPromptsLoad(t *testing.T) {
	entries, err := fs.ReadDir(builtin, ".")
	if err != nil {
		t.Fatalf("fs.ReadDir(builtin) = %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			t.Errorf("embedded entry %q is not a directory", e.Name())
			continue
		}
		if _, err := Load(e.Name()); err != nil {
			t.Errorf("Load(%q) = %v, want nil", e.Name(), err)
		}
	}
}

// Test 16: the three exported sentinels are distinct and prefixed "llm: ".
func TestPromptSentinels(t *testing.T) {
	sentinels := []error{ErrInvalidPromptID, ErrUnknownPrompt, ErrInvalidPrompt}
	for i, a := range sentinels {
		if a == nil {
			t.Fatalf("sentinel %d is nil", i)
		}
		if !strings.HasPrefix(a.Error(), "llm: ") {
			t.Errorf("sentinel %q lacks the prefix %q", a.Error(), "llm: ")
		}
		for j, b := range sentinels {
			if i != j && (errors.Is(a, b) || a.Error() == b.Error()) {
				t.Errorf("sentinels %q and %q are not distinct", a.Error(), b.Error())
			}
		}
	}
}
