package secret

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"testing"
)

type slogCase struct {
	name string
	// attr is the attribute name that must appear in the output.
	attr string
	log  func(logger *slog.Logger, x, px any)
	// text and json are the expected forms of the attribute in each handler.
	text string
	json string
}

func slogCases() []slogCase {
	const textKey = `key="?\[REDACTED\]"?`
	const jsonKey = `"key":"\[REDACTED\]"`
	return []slogCase{
		{
			name: "key_value", attr: "key",
			log:  func(l *slog.Logger, x, _ any) { l.Info("m", "key", x) },
			text: `(^| )` + textKey, json: jsonKey,
		},
		{
			name: "attr_any", attr: "key",
			log: func(l *slog.Logger, x, _ any) {
				l.LogAttrs(context.Background(), slog.LevelInfo, "m", slog.Any("key", x))
			},
			text: `(^| )` + textKey, json: jsonKey,
		},
		{
			name: "pointer", attr: "key",
			log:  func(l *slog.Logger, _, px any) { l.Info("m", slog.Any("key", px)) },
			text: `(^| )` + textKey, json: jsonKey,
		},
		{
			name: "group", attr: "key",
			log:  func(l *slog.Logger, x, _ any) { l.Info("m", slog.Group("g", slog.Any("key", x))) },
			text: `(^| )g\.` + textKey, json: `"g":\{` + jsonKey + `\}`,
		},
		{
			name: "with", attr: "key",
			log:  func(l *slog.Logger, x, _ any) { l.With("key", x).Info("m") },
			text: `(^| )` + textKey, json: jsonKey,
		},
		{
			name: "with_group", attr: "key",
			log:  func(l *slog.Logger, x, _ any) { l.WithGroup("g").Info("m", "key", x) },
			text: `(^| )g\.` + textKey, json: `"g":\{` + jsonKey + `\}`,
		},
		{
			name: "exported_field", attr: "cfg",
			log:  func(l *slog.Logger, x, _ any) { l.Info("m", slog.Any("cfg", struct{ Key any }{x})) },
			text: `cfg="?\{Key:\[REDACTED\]\}"?`, json: `"cfg":\{"Key":"\[REDACTED\]"\}`,
		},
		{
			name: "slice", attr: "keys",
			log:  func(l *slog.Logger, x, _ any) { l.Info("m", slog.Any("keys", []any{x, x})) },
			text: `keys="?\[\[REDACTED\] \[REDACTED\]\]"?`, json: `"keys":\["\[REDACTED\]","\[REDACTED\]"\]`,
		},
		{
			name: "error_value", attr: "err",
			log: func(l *slog.Logger, x, _ any) {
				l.Info("m", slog.Any("err", fmt.Errorf("connect: %v", x)))
			},
			text: `err="?connect: \[REDACTED\]"?`, json: `"err":"connect: \[REDACTED\]"`,
		},
	}
}

func newSlogHandler(kind string, buf *bytes.Buffer, opts *slog.HandlerOptions) slog.Handler {
	if kind == "json" {
		return slog.NewJSONHandler(buf, opts)
	}
	return slog.NewTextHandler(buf, opts)
}

func TestSlogRedacts(t *testing.T) {
	for _, kind := range []string{"text", "json"} {
		t.Run(kind, func(t *testing.T) {
			for _, sub := range subjects() {
				t.Run(sub.name, func(t *testing.T) {
					for _, tc := range slogCases() {
						t.Run(tc.name, func(t *testing.T) {
							var buf bytes.Buffer
							tc.log(slog.New(newSlogHandler(kind, &buf, nil)), sub.x, sub.px)
							out := buf.String()
							want := tc.text
							if kind == "json" {
								want = tc.json
							}
							if !strings.Contains(out, wantRedacted) {
								t.Errorf("case %s: output %q does not contain %s", tc.name, out, wantRedacted)
							}
							if !strings.Contains(out, tc.attr) {
								t.Errorf("case %s: output %q does not contain attribute %q", tc.name, out, tc.attr)
							}
							if !regexp.MustCompile(want).MatchString(out) {
								t.Errorf("case %s: output %q does not match %s", tc.name, out, want)
							}
							assertNoLeak(t, out)
						})
					}
					t.Run("replace_attr", func(t *testing.T) {
						var (
							buf  bytes.Buffer
							seen []slog.Value
						)
						opts := &slog.HandlerOptions{
							ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
								if len(groups) == 0 && a.Key == "key" {
									seen = append(seen, a.Value)
								}
								return a
							},
						}
						slog.New(newSlogHandler(kind, &buf, opts)).Info("m", "key", sub.x)
						out := buf.String()
						if len(seen) != 1 {
							t.Fatalf("ReplaceAttr saw the key attribute %d times, want 1", len(seen))
						}
						if got := seen[0].Kind(); got != slog.KindString {
							t.Errorf("ReplaceAttr saw kind %v, want %v (secret resolved before ReplaceAttr)", got, slog.KindString)
						}
						if got := seen[0].String(); got != wantRedacted {
							t.Errorf("ReplaceAttr saw %q, want %q", got, wantRedacted)
						}
						if !strings.Contains(out, wantRedacted) || !strings.Contains(out, "key") {
							t.Errorf("output %q does not contain key and %s", out, wantRedacted)
						}
						assertNoLeak(t, out)
						assertNoLeak(t, seen[0].String())
					})
				})
			}
		})
	}
}
