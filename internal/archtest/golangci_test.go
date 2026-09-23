package archtest

import (
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
)

// yamlDoc maps a dotted key path to its values: one for a scalar, n for a sequence.
type yamlDoc map[string][]string

// Analysis rules of parseYAMLSubset, a subset of block-style YAML
// (docs/plans/M0-squelette.md section 8.5):
//  1. indentation is made of spaces only; a tab at the start of a line is an error;
//  2. a comment is "#" at the start of a line (after spaces) or " #" after a
//     value, outside quotes;
//  3. "key:" opens a table; "key: value" records a scalar at the dotted path
//     (linters.settings.nolintlint.require-specific); single- and double-quoted
//     values are unquoted; keys are made of letters, digits, "-" and "_" only
//     (a dotted key would forge a path);
//  4. "- value" under a key (indentation greater than or equal to the key's)
//     appends an element to the sequence at the key's path;
//  5. "- key: value" (a table inside a sequence) is recorded as an opaque
//     element and its more indented lines are ignored (room for future
//     exclusion rules without interpreting them);
//  6. errors: duplicate key at the same path, flow sequence or table ("[", "{"),
//     anchor or alias ("&", "*"), tag ("!"), multi-line scalar ("|", ">"),
//     second document ("---" after content), a table mixed with a sequence,
//     inconsistent indentation, any other line.
var yamlKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

type yamlNode struct {
	indent      int
	path        string
	childIndent int // indentation of the child keys, -1 before the first one
	seqIndent   int // indentation of the sequence items, -1 before the first one
}

type yamlParser struct {
	doc    yamlDoc
	seen   map[string]bool
	stack  []*yamlNode
	opaque int // indentation of the dash of the opaque element being skipped, -1 if none
}

func parseYAMLSubset(src string) (yamlDoc, error) {
	p := yamlParser{
		doc:    yamlDoc{},
		seen:   map[string]bool{},
		stack:  []*yamlNode{{indent: -1, childIndent: -1, seqIndent: -1}},
		opaque: -1,
	}
	content := false
	for i, raw := range strings.Split(src, "\n") {
		num := i + 1
		line := strings.TrimSuffix(raw, "\r")
		body := strings.TrimLeft(line, " ")
		indent := len(line) - len(body)
		if strings.HasPrefix(body, "\t") {
			return nil, fmt.Errorf("line %d: tab in indentation (spaces only)", num)
		}
		body = strings.TrimRight(body, " \t")
		if body == "" || strings.HasPrefix(body, "#") {
			continue
		}
		if p.opaque >= 0 {
			if indent > p.opaque {
				continue
			}
			p.opaque = -1
		}
		if body == "---" || strings.HasPrefix(body, "--- ") {
			if content {
				return nil, fmt.Errorf("line %d: second YAML document not supported", num)
			}
			continue
		}
		content = true
		var err error
		if body == "-" || strings.HasPrefix(body, "- ") {
			err = p.sequenceItem(indent, strings.TrimSpace(body[1:]), num)
		} else {
			err = p.mappingEntry(indent, body, num)
		}
		if err != nil {
			return nil, err
		}
	}
	return p.doc, nil
}

func (p *yamlParser) top() *yamlNode { return p.stack[len(p.stack)-1] }

func (p *yamlParser) mappingEntry(indent int, body string, num int) error {
	key, rest, ok := splitYAMLKey(body)
	if !ok {
		return fmt.Errorf("line %d: expected \"key:\", \"key: value\" or \"- item\", got %q", num, body)
	}
	if !yamlKeyRe.MatchString(key) {
		return fmt.Errorf("line %d: unsupported key %q (letters, digits, - and _ only)", num, key)
	}
	for len(p.stack) > 1 && p.top().indent >= indent {
		p.stack = p.stack[:len(p.stack)-1]
	}
	parent := p.top()
	switch {
	case parent.seqIndent >= 0:
		return fmt.Errorf("line %d: key %q mixed with sequence items under %q", num, key, parent.path)
	case parent.childIndent < 0:
		parent.childIndent = indent
	case parent.childIndent != indent:
		return fmt.Errorf("line %d: inconsistent indentation of key %q (%d spaces, siblings have %d)",
			num, key, indent, parent.childIndent)
	}
	path := key
	if parent.path != "" {
		path = parent.path + "." + key
	}
	if p.seen[path] {
		return fmt.Errorf("line %d: duplicate key %q", num, path)
	}
	p.seen[path] = true
	value, present, err := parseYAMLScalar(rest, num)
	if err != nil {
		return err
	}
	if present {
		p.doc[path] = []string{value}
		return nil
	}
	p.stack = append(p.stack, &yamlNode{indent: indent, path: path, childIndent: -1, seqIndent: -1})
	return nil
}

func (p *yamlParser) sequenceItem(indent int, item string, num int) error {
	for len(p.stack) > 1 && p.top().indent > indent {
		p.stack = p.stack[:len(p.stack)-1]
	}
	parent := p.top()
	switch {
	case len(p.stack) == 1:
		return fmt.Errorf("line %d: sequence item %q outside a key", num, item)
	case parent.childIndent >= 0:
		return fmt.Errorf("line %d: sequence item %q mixed with keys under %q", num, item, parent.path)
	case parent.seqIndent < 0:
		parent.seqIndent = indent
	case parent.seqIndent != indent:
		return fmt.Errorf("line %d: inconsistent indentation of sequence item %q under %q", num, item, parent.path)
	}
	if item == "-" || strings.HasPrefix(item, "- ") {
		return fmt.Errorf("line %d: nested sequence not supported", num)
	}
	if key, _, ok := splitYAMLKey(item); item == "" || ok && yamlKeyRe.MatchString(key) {
		p.doc[parent.path] = append(p.doc[parent.path], item)
		p.opaque = indent
		return nil
	}
	value, present, err := parseYAMLScalar(item, num)
	if err != nil {
		return err
	}
	if present {
		p.doc[parent.path] = append(p.doc[parent.path], value)
	}
	return nil
}

// splitYAMLKey splits "key: rest" or "key:" at the first colon followed by a
// blank or ending the line.
func splitYAMLKey(body string) (key, rest string, ok bool) {
	for i := 0; i < len(body); i++ {
		if body[i] == ':' && (i+1 == len(body) || body[i+1] == ' ' || body[i+1] == '\t') {
			return strings.TrimSpace(body[:i]), strings.TrimSpace(body[i+1:]), true
		}
	}
	return "", "", false
}

// parseYAMLScalar reads a scalar value; present is false when there is no
// value (nothing or only a comment).
func parseYAMLScalar(v string, num int) (value string, present bool, err error) {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "#") {
		return "", false, nil
	}
	switch v[0] {
	case '[', '{':
		return "", false, fmt.Errorf("line %d: flow collection %q not supported (use block style)", num, v)
	case '&', '*':
		return "", false, fmt.Errorf("line %d: anchor or alias %q not supported", num, v)
	case '!':
		return "", false, fmt.Errorf("line %d: tag %q not supported", num, v)
	case '|', '>':
		return "", false, fmt.Errorf("line %d: multi-line scalar %q not supported", num, v)
	case '@', '`', '%', '?':
		return "", false, fmt.Errorf("line %d: reserved indicator in %q not supported", num, v)
	case '"', '\'':
		return parseQuotedScalar(v, num)
	}
	for _, marker := range []string{" #", "\t#"} {
		if i := strings.Index(v, marker); i >= 0 {
			v = v[:i]
		}
	}
	return strings.TrimSpace(v), true, nil
}

func parseQuotedScalar(v string, num int) (value string, present bool, err error) {
	end := -1
	if v[0] == '"' {
		for i := 1; i < len(v); i++ {
			if v[i] == '\\' {
				i++
				continue
			}
			if v[i] == '"' {
				end = i
				break
			}
		}
	} else {
		for i := 1; i < len(v); i++ {
			if v[i] != '\'' {
				continue
			}
			if i+1 < len(v) && v[i+1] == '\'' {
				i++
				continue
			}
			end = i
			break
		}
	}
	if end < 0 {
		return "", false, fmt.Errorf("line %d: unterminated quoted scalar %q", num, v)
	}
	if after := strings.TrimSpace(v[end+1:]); after != "" && !strings.HasPrefix(after, "#") {
		return "", false, fmt.Errorf("line %d: unexpected text after quoted scalar %q", num, v)
	}
	if v[0] == '\'' {
		return strings.ReplaceAll(v[1:end], "''", "'"), true, nil
	}
	s, err := strconv.Unquote(v[:end+1])
	if err != nil {
		return "", false, fmt.Errorf("line %d: invalid double-quoted scalar %q: %w", num, v, err)
	}
	return s, true, nil
}

// requiredLinters are demanded by the go-platform-conventions skill.
func requiredLinters() []string { return []string{"gosec", "errorlint", "contextcheck", "nolintlint"} }

// gosecNosecKey must be true: gosec then ignores its own suppression
// annotations, so that a gosec finding is only silenced by a nolint directive,
// which nolintlint checks (R1-c).
const gosecNosecKey = "linters.settings.gosec.config.global.nosec"

// checkGolangci applies rules 1 to 7 of docs/plans/M0-squelette.md section 8.5.
func checkGolangci(doc yamlDoc) []string {
	var problems problemList
	scalar := func(key string) string {
		if v := doc[key]; len(v) == 1 {
			return v[0]
		}
		return ""
	}
	if scalar("version") != "2" {
		problems.addf(".golangci.yml: version must be \"2\" (golangci-lint v2 format), got %q", doc["version"])
	}
	if d := scalar("linters.default"); d != "standard" && d != "all" {
		problems.addf(".golangci.yml: linters.default must be standard or all, got %q", doc["linters.default"])
	}
	for _, l := range requiredLinters() {
		if !slices.Contains(doc["linters.enable"], l) {
			problems.addf(".golangci.yml: linters.enable must contain %s", l)
		}
		if slices.Contains(doc["linters.disable"], l) {
			problems.addf(".golangci.yml: linters.disable must not contain %s", l)
		}
	}
	for _, key := range []string{
		"linters.settings.nolintlint.require-explanation",
		"linters.settings.nolintlint.require-specific",
	} {
		if scalar(key) != "true" {
			problems.addf(".golangci.yml: %s must be true, got %q", key, doc[key])
		}
	}
	if !slices.Contains(doc["formatters.enable"], "gofumpt") {
		problems.addf(".golangci.yml: formatters.enable must contain gofumpt")
	}
	if v, present := doc["run.tests"]; present && (len(v) != 1 || v[0] != "true") {
		problems.addf(".golangci.yml: run.tests must be true when present (tests are linted), got %q", v)
	}
	if scalar(gosecNosecKey) != "true" {
		problems.addf(".golangci.yml: %s must be true (gosec's own annotations must not silence it; "+
			"only a nolint directive checked by nolintlint may), got %q", gosecNosecKey, doc[gosecNosecKey])
	}
	return problems
}

// checkGolangciFiles requires .golangci.yml and no other golangci-lint
// configuration file, so that there is no doubt about the one being read.
func checkGolangciFiles(fsys fs.FS) []string {
	var problems problemList
	info, err := fs.Stat(fsys, ".golangci.yml")
	switch {
	case errors.Is(err, fs.ErrNotExist):
		problems.addf(".golangci.yml: file does not exist at repository root (created by M0-T01)")
	case err != nil:
		problems.addf(".golangci.yml: %v", err)
	case !info.Mode().IsRegular():
		problems.addf(".golangci.yml: not a regular file")
	}
	for _, other := range []string{".golangci.yaml", ".golangci.toml", ".golangci.json"} {
		_, err := fs.Stat(fsys, other)
		switch {
		case err == nil:
			problems.addf("%s: second golangci-lint configuration file (keep only .golangci.yml)", other)
		case !errors.Is(err, fs.ErrNotExist):
			problems.addf("%s: %v", other, err)
		}
	}
	return problems
}

// targetGolangci is the .golangci.yml of docs/plans/M0-squelette.md section
// 6.2, verbatim: the conforming negative control.
const targetGolangci = `# golangci-lint v2 (M0-T01). Pinned version: docs/SETUP.md, CI from M0-T04.
# Every nolint directive must name the linter and give a reason (nolintlint).
version: "2"

run:
  timeout: 5m
  tests: true
  modules-download-mode: readonly
  build-tags:
    - integration

linters:
  # standard = errcheck, govet, ineffassign, staticcheck, unused
  default: standard
  enable:
    # Required by the go-platform-conventions skill
    - contextcheck
    - errorlint
    - gosec
    - nolintlint
    # Resources, context, HTTP and SQL
    - bodyclose
    - fatcontext
    - noctx
    - rowserrcheck
    - sqlclosecheck
    # Correctness
    - copyloopvar
    - durationcheck
    - errchkjson
    - forcetypeassert
    - nilerr
    - predeclared
    - reassign
    - unconvert
    - usestdlibvars
    - wastedassign
    # Source integrity and supply chain
    - asciicheck
    - bidichk
    - gocheckcompilerdirectives
    - gomoddirectives
  settings:
    errcheck:
      check-type-assertions: true
    govet:
      enable-all: true
      disable:
        - fieldalignment
        - shadow
    gosec:
      config:
        global:
          # Ignore gosec's own nosec annotations: a gosec finding is silenced
          # only by a nolint directive naming gosec, which nolintlint checks.
          nosec: true
    nolintlint:
      require-explanation: true
      require-specific: true
      allow-unused: false

formatters:
  enable:
    - gofumpt
    - goimports
  settings:
    gofumpt:
      module-path: github.com/amezianechayer/rempart
    goimports:
      local-prefixes:
        - github.com/amezianechayer/rempart

issues:
  max-issues-per-linter: 0
  max-same-issues: 0
`

// minimalGolangci is a conforming variant: unquoted version, default all,
// sequence items at the key's indentation, quoted items and trailing comments.
const minimalGolangci = `version: 2
linters:
  default: all # every linter
  enable:
  - gosec
  - 'errorlint'
  - "contextcheck"
  - nolintlint
  settings:
    gosec:
      config:
        global:
          nosec: true # gosec annotations ignored
    nolintlint:
      require-explanation: true
      require-specific: true
formatters:
  enable:
  - gofumpt
`

func TestGolangciConfig(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		valid := targetGolangci
		const exclusions = "  exclusions:\n    rules:\n      - path: _test\\.go\n        linters:\n          - gosec\n\nformatters:\n"
		start, end := strings.Index(valid, "    gosec:\n"), strings.Index(valid, "    nolintlint:\n")
		if start < 0 || end < start {
			t.Fatalf("synthetic .golangci.yml: gosec block not found before nolintlint")
		}
		gosecBlock := valid[start:end]
		cases := []struct {
			name    string
			src     string
			wantErr string
			want    []string
		}{
			{name: "valid", src: valid},
			{name: "valid_minimal_variant", src: minimalGolangci},
			{name: "valid_with_exclusion_rules", src: mustReplace(t, valid, "\nformatters:\n", "\n"+exclusions)},
			{
				name: "v1_format",
				src: "run:\n  timeout: 5m\nlinters:\n  enable:\n    - gosec\n    - errorlint\n    - contextcheck\n    - nolintlint\n" +
					"linters-settings:\n  nolintlint:\n    require-explanation: true\n    require-specific: true\n",
				want: []string{
					".golangci.yml: version must be \"2\"",
					"linters.default must be standard or all",
					"linters.settings.nolintlint.require-explanation must be true",
				},
			},
			{name: "missing_gosec", src: mustReplace(t, valid, "    - gosec\n", ""), want: []string{"linters.enable must contain gosec"}},
			{
				name: "gosec_disabled",
				src:  mustReplace(t, valid, "  settings:\n    errcheck:", "  disable:\n    - gosec\n  settings:\n    errcheck:"),
				want: []string{"linters.disable must not contain gosec"},
			},
			{
				name: "default_none",
				src:  mustReplace(t, valid, "  default: standard\n", "  default: none\n"),
				want: []string{`linters.default must be standard or all, got ["none"]`},
			},
			{
				name: "default_none_with_misleading_comment",
				src:  mustReplace(t, valid, "  default: standard\n", "  default: none # standard\n"),
				want: []string{`linters.default must be standard or all, got ["none"]`},
			},
			{
				name: "exclusion_rule_does_not_enable",
				src:  mustReplace(t, mustReplace(t, valid, "    - gosec\n", ""), "\nformatters:\n", "\n"+exclusions),
				want: []string{"linters.enable must contain gosec"},
			},
			{
				name: "nolintlint_not_specific",
				src:  mustReplace(t, valid, "require-specific: true", "require-specific: false"),
				want: []string{"linters.settings.nolintlint.require-specific must be true"},
			},
			{
				name: "nolintlint_without_explanation",
				src:  mustReplace(t, valid, "      require-explanation: true\n", ""),
				want: []string{"linters.settings.nolintlint.require-explanation must be true"},
			},
			{
				name: "gofumpt_as_linter_only",
				src: mustReplace(t, mustReplace(t, valid, "  enable:\n    - gofumpt\n", "  enable:\n"),
					"    - gomoddirectives\n", "    - gomoddirectives\n    - gofumpt\n"),
				want: []string{"formatters.enable must contain gofumpt"},
			},
			{
				name: "tests_disabled",
				src:  mustReplace(t, valid, "  tests: true\n", "  tests: false\n"),
				want: []string{"run.tests must be true when present"},
			},
			{
				name: "gosec_nosec_honored",
				src:  mustReplace(t, valid, gosecBlock, ""),
				want: []string{gosecNosecKey + " must be true", "got []"},
			},
			{
				name: "gosec_nosec_false",
				src:  mustReplace(t, valid, "          nosec: true\n", "          nosec: false\n"),
				want: []string{gosecNosecKey + ` must be true`, `got ["false"]`},
			},
			{
				name: "gosec_nosec_commented_out",
				src:  mustReplace(t, valid, "          nosec: true\n", "          # nosec: true\n"),
				want: []string{gosecNosecKey + " must be true"},
			},
			{
				name: "gosec_nosec_under_other_linter",
				src: mustReplace(t, mustReplace(t, valid, gosecBlock, ""),
					"    errcheck:\n", "    errcheck:\n      config:\n        global:\n          nosec: true\n"),
				want: []string{gosecNosecKey + " must be true"},
			},
			{name: "tab_indentation", src: mustReplace(t, valid, "  timeout: 5m\n", "\ttimeout: 5m\n"), wantErr: "line 6: tab in indentation"},
			{
				name:    "flow_sequence",
				src:     mustReplace(t, minimalGolangci, "  enable:\n  - gosec\n", "  enable: [gosec]\n"),
				wantErr: `flow collection "[gosec]"`,
			},
			{name: "duplicate_key", src: valid + "version: \"2\"\n", wantErr: `duplicate key "version"`},
			{
				name:    "duplicate_nested_key",
				src:     mustReplace(t, valid, "  default: standard\n", "  default: standard\n  default: none\n"),
				wantErr: `duplicate key "linters.default"`,
			},
			{
				name:    "dotted_key_forging_a_path",
				src:     mustReplace(t, minimalGolangci, "linters:\n  default: all # every linter\n", "linters.default: all\nlinters:\n"),
				wantErr: `unsupported key "linters.default"`,
			},
			{name: "anchor", src: mustReplace(t, valid, "  default: standard\n", "  default: &d standard\n"), wantErr: "anchor or alias"},
			{name: "alias", src: mustReplace(t, valid, "  default: standard\n", "  default: *d\n"), wantErr: "anchor or alias"},
			{name: "tag", src: mustReplace(t, valid, "version: \"2\"\n", "version: !!str 2\n"), wantErr: "tag"},
			{
				name:    "multi_line_scalar",
				src:     mustReplace(t, valid, "  default: standard\n", "  default: >\n    standard\n"),
				wantErr: "multi-line scalar",
			},
			{name: "second_document", src: valid + "---\nversion: \"1\"\n", wantErr: "second YAML document"},
			{
				name:    "inconsistent_indentation",
				src:     mustReplace(t, valid, "  default: standard\n", "   default: standard\n"),
				wantErr: "inconsistent indentation",
			},
			{
				name:    "table_mixed_with_sequence",
				src:     mustReplace(t, valid, "    - gomoddirectives\n", "    - gomoddirectives\n    extra: true\n"),
				wantErr: "mixed with sequence items",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				doc, err := parseYAMLSubset(tc.src)
				if tc.wantErr != "" {
					expectError(t, err, tc.wantErr)
					return
				}
				if err != nil {
					t.Fatalf("parseYAMLSubset: %v", err)
				}
				expectProblems(t, checkGolangci(doc), tc.want)
			})
		}

		t.Run("valid_parse_structure", func(t *testing.T) {
			doc, err := parseYAMLSubset(mustReplace(t, valid, "\nformatters:\n", "\n"+exclusions))
			if err != nil {
				t.Fatalf("parseYAMLSubset: %v", err)
			}
			for path, want := range map[string][]string{
				"version":                                      {"2"},
				"run.build-tags":                               {"integration"},
				"linters.settings.govet.disable":               {"fieldalignment", "shadow"},
				"linters.exclusions.rules":                     {`path: _test\.go`},
				"formatters.settings.goimports.local-prefixes": {modulePath},
				gosecNosecKey:                                  {"true"},
			} {
				if got := doc[path]; !slices.Equal(got, want) {
					t.Errorf("%s = %q, want %q", path, got, want)
				}
			}
			if got := len(doc["linters.enable"]); got != 23 {
				t.Errorf("linters.enable has %d items, want 23 (comments are not items)", got)
			}
			if _, found := doc["linters.exclusions.rules.linters"]; found {
				t.Errorf("lines under an opaque sequence element were interpreted")
			}
		})

		fileCases := []struct {
			name  string
			files fstest.MapFS
			want  []string
		}{
			{name: "single_config_file", files: fstest.MapFS{".golangci.yml": {Data: []byte(valid)}}},
			{
				name: "second_config_file",
				files: fstest.MapFS{
					".golangci.yml":  {Data: []byte(valid)},
					".golangci.yaml": {Data: []byte(valid)},
				},
				want: []string{".golangci.yaml: second golangci-lint configuration file"},
			},
			{
				name:  "toml_config_file",
				files: fstest.MapFS{".golangci.yml": {Data: []byte(valid)}, ".golangci.toml": {Data: []byte("version = \"2\"\n")}},
				want:  []string{".golangci.toml: second golangci-lint configuration file"},
			},
			{
				name:  "missing_config_file",
				files: fstest.MapFS{".golangci.json": {Data: []byte("{}\n")}},
				want:  []string{".golangci.yml: file does not exist", ".golangci.json: second golangci-lint configuration file"},
			},
		}
		for _, tc := range fileCases {
			t.Run(tc.name, func(t *testing.T) {
				expectProblems(t, checkGolangciFiles(tc.files), tc.want)
			})
		}
	})

	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		files := checkGolangciFiles(fsys)
		reportProblems(t, files)
		src, err := readRepoFile(fsys, ".golangci.yml", "created by M0-T01")
		if err != nil {
			if len(files) == 0 {
				t.Fatal(err)
			}
			return
		}
		doc, err := parseYAMLSubset(src)
		if err != nil {
			t.Fatalf(".golangci.yml: %v", err)
		}
		reportProblems(t, checkGolangci(doc))
	})
}
