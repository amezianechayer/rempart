package archtest

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// minGoMinor is the lowest accepted Go minor version: the tool directive that
// pins govulncheck requires go 1.24 or later. The exact version (1.27.1 on
// 2026-09-23) is not coded here, so that an upgrade does not break the test.
const minGoMinor = 24

const govulncheckTool = "golang.org/x/vuln/cmd/govulncheck"

// goMod holds the go.mod directives these tests rely on.
type goMod struct {
	Module string
	Go     []string // value of every go directive met
	Tools  []string // paths of the tool directives (single line or block)
}

// goVersionRe accepts released versions only: 1.N or 1.N.P, no rc or beta.
var goVersionRe = regexp.MustCompile(`^1\.(\d+)(\.(\d+))?$`)

// parseGoMod reads the module, go and tool directives of a go.mod file.
// Analysis rules (docs/plans/M0-squelette.md section 8.3):
//   - a "//" comment runs to the end of the line and is removed first;
//   - "verb (" opens a block closed by a line holding ")" alone; every line in
//     between is an instance of verb; nested or unclosed blocks are errors;
//   - module (once), go and tool directives are recorded, quoted paths unquoted;
//     every other verb (require, replace, exclude, retract, toolchain, godebug,
//     ignore) is ignored.
func parseGoMod(src string) (goMod, error) {
	var m goMod
	block, blockLine := "", 0
	for i, raw := range strings.Split(src, "\n") {
		num := i + 1
		line := raw
		if j := strings.Index(line, "//"); j >= 0 {
			line = line[:j]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == ")" {
			if block == "" {
				return m, fmt.Errorf("go.mod line %d: \")\" without an open block", num)
			}
			block = ""
			continue
		}
		if strings.HasSuffix(line, "(") {
			verb := strings.TrimSpace(strings.TrimSuffix(line, "("))
			if block != "" || verb == "" || strings.ContainsAny(verb, " \t") {
				return m, fmt.Errorf("go.mod line %d: malformed or nested block %q", num, line)
			}
			block, blockLine = verb, num
			continue
		}
		fields := strings.Fields(line)
		verb, args := fields[0], fields[1:]
		if block != "" {
			verb, args = block, fields
		}
		if err := m.add(verb, args, num); err != nil {
			return m, err
		}
	}
	if block != "" {
		return m, fmt.Errorf("go.mod line %d: block %q is not closed", blockLine, block)
	}
	return m, nil
}

func (m *goMod) add(verb string, args []string, num int) error {
	switch verb {
	case "module":
		if len(args) != 1 {
			return fmt.Errorf("go.mod line %d: module directive needs exactly one path", num)
		}
		if m.Module != "" {
			return fmt.Errorf("go.mod line %d: second module directive", num)
		}
		m.Module = unquoteModPath(args[0])
	case "go":
		m.Go = append(m.Go, strings.Join(args, " "))
	case "tool":
		if len(args) != 1 {
			return fmt.Errorf("go.mod line %d: tool directive needs exactly one path", num)
		}
		m.Tools = append(m.Tools, unquoteModPath(args[0]))
	}
	return nil
}

func unquoteModPath(s string) string {
	if unquoted, err := strconv.Unquote(s); err == nil {
		return unquoted
	}
	return s
}

// checkGoMod requires the Rempart module path, exactly one released go
// directive not older than 1.minGoMinor and the govulncheck tool directive.
func checkGoMod(m goMod) []string {
	var problems []string
	if m.Module != modulePath {
		problems = append(problems, fmt.Sprintf("go.mod: module is %q, want %q", m.Module, modulePath))
	}
	switch len(m.Go) {
	case 0:
		problems = append(problems, fmt.Sprintf("go.mod: go directive missing (want exactly one, 1.%d or later)", minGoMinor))
	case 1:
		problems = append(problems, checkGoVersion(m.Go[0])...)
	default:
		problems = append(problems, fmt.Sprintf("go.mod: %d go directives %q, want exactly one", len(m.Go), m.Go))
	}
	if !slices.Contains(m.Tools, govulncheckTool) {
		problems = append(problems, "go.mod: tool directive "+govulncheckTool+
			" missing (make verify runs go tool govulncheck at the pinned version)")
	}
	return problems
}

func checkGoVersion(v string) []string {
	match := goVersionRe.FindStringSubmatch(v)
	if match == nil {
		return []string{fmt.Sprintf("go.mod: go directive %q is not a released version 1.N or 1.N.P (no rc, no beta)", v)}
	}
	minor, err := strconv.Atoi(match[1])
	if err != nil {
		return []string{fmt.Sprintf("go.mod: go directive %q: %v", v, err)}
	}
	if minor < minGoMinor {
		return []string{fmt.Sprintf("go.mod: go directive %q is older than 1.%d (required by the tool directive)", v, minGoMinor)}
	}
	return nil
}

func TestGoDirective(t *testing.T) {
	t.Run("negative_controls", func(t *testing.T) {
		const (
			header  = "module github.com/amezianechayer/rempart\n\n"
			tool    = "tool golang.org/x/vuln/cmd/govulncheck\n\n"
			require = "require (\n\tgolang.org/x/mod v0.41.0 // indirect\n\tgolang.org/x/vuln v1.8.0 // indirect\n)\n"
		)
		cases := []struct {
			name    string
			src     string
			wantErr string
			want    []string
		}{
			{name: "valid", src: header + "go 1.27.1\n\n" + tool + require},
			{
				name: "valid_tool_block",
				src:  header + "go 1.27.1\n\ntool (\n\tgolang.org/x/tools/cmd/stringer\n\tgolang.org/x/vuln/cmd/govulncheck\n)\n\n" + require,
			},
			{name: "valid_minimum_minor", src: header + "go 1.24\n\n" + tool},
			{
				name: "valid_quoted_path_and_trailing_comments",
				src:  "module \"github.com/amezianechayer/rempart\" // quoted\n\ngo 1.27.1 // pinned\n\ntool \"golang.org/x/vuln/cmd/govulncheck\" // T6\n",
			},
			{name: "too_old", src: header + "go 1.23\n\n" + tool, want: []string{`go directive "1.23" is older than 1.24`}},
			{name: "too_old_patch", src: header + "go 1.23.12\n\n" + tool, want: []string{`go directive "1.23.12" is older`}},
			{name: "missing_go", src: header + tool + require, want: []string{"go directive missing"}},
			{
				name: "duplicate_go",
				src:  header + "go 1.27.1\n\n" + tool + "go 1.26\n",
				want: []string{"2 go directives"},
			},
			{name: "prerelease", src: header + "go 1.28rc1\n\n" + tool, want: []string{`"1.28rc1" is not a released version`}},
			{name: "beta", src: header + "go 1.28beta1\n\n" + tool, want: []string{`"1.28beta1" is not a released version`}},
			{name: "major_version_two", src: header + "go 2.0\n\n" + tool, want: []string{`"2.0" is not a released version`}},
			{
				name: "wrong_module",
				src:  "module github.com/example/other\n\ngo 1.27.1\n\n" + tool,
				want: []string{`module is "github.com/example/other"`},
			},
			{
				name: "missing_govulncheck_tool",
				src:  header + "go 1.27.1\n\ntool golang.org/x/tools/cmd/stringer\n",
				want: []string{"tool directive golang.org/x/vuln/cmd/govulncheck missing"},
			},
			{
				name: "govulncheck_required_but_not_a_tool",
				src:  header + "go 1.27.1\n\n" + require,
				want: []string{"tool directive golang.org/x/vuln/cmd/govulncheck missing"},
			},
			{
				name: "commented_directive_ignored",
				src:  header + "// go 1.30\n\n" + tool,
				want: []string{"go directive missing"},
			},
			{
				name: "commented_tool_ignored",
				src:  header + "go 1.27.1\n\n// tool golang.org/x/vuln/cmd/govulncheck\n",
				want: []string{"tool directive golang.org/x/vuln/cmd/govulncheck missing"},
			},
			{
				name:    "unclosed_block",
				src:     header + "go 1.27.1\n\ntool (\n\tgolang.org/x/vuln/cmd/govulncheck\n",
				wantErr: `block "tool" is not closed`,
			},
			{
				name:    "second_module_directive",
				src:     header + "module github.com/example/other\n\ngo 1.27.1\n\n" + tool,
				wantErr: "second module directive",
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				m, err := parseGoMod(tc.src)
				if tc.wantErr != "" {
					expectError(t, err, tc.wantErr)
					return
				}
				if err != nil {
					t.Fatalf("parseGoMod: %v", err)
				}
				expectProblems(t, checkGoMod(m), tc.want)
			})
		}
	})

	t.Run("repository", func(t *testing.T) {
		_, fsys := repoRoot(t)
		src, err := readRepoFile(fsys, "go.mod", "created by M0-T01 step 0")
		if err != nil {
			t.Fatal(err)
		}
		m, err := parseGoMod(src)
		if err != nil {
			t.Fatalf("go.mod: %v", err)
		}
		reportProblems(t, checkGoMod(m))
	})
}
