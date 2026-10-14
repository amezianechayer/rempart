package apikey

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Tests of ADR 0008 D5 (T20): the key of a model platform comes from one
// REMPART_LLM_KEY_* variable, read once, never quoted.

const canary = "sk-or-v1-CANARY-7d1e"

func TestKeyFromEnviron(t *testing.T) {
	env := []string{"PATH=/bin", EnvOpenRouter + "=" + canary, "HOME=/root"}
	v, err := FromEnviron(env, EnvOpenRouter)
	if err != nil || v.Reveal() != canary {
		t.Fatalf("FromEnviron = %d bytes, %v; want the key", len(v.Reveal()), err)
	}
	if s := fmt.Sprintf("%v %+v", v, v); strings.Contains(s, canary) {
		t.Error("printing the key reveals it")
	}
}

// TestKeyFromEnvUnset: absent, empty, duplicated or malformed keys are
// refused without quoting the value; only REMPART_LLM_KEY_* names are read.
func TestKeyFromEnvUnset(t *testing.T) {
	for name, c := range map[string]struct {
		env  []string
		want error
	}{
		"absent":    {[]string{"PATH=/bin"}, ErrNoKey},
		"empty":     {[]string{EnvOpenRouter + "="}, ErrNoKey},
		"twice":     {[]string{EnvOpenRouter + "=" + canary, EnvOpenRouter + "=" + canary}, ErrMalformedKey},
		"space":     {[]string{EnvOpenRouter + "=" + canary + " x"}, ErrMalformedKey},
		"newline":   {[]string{EnvOpenRouter + "=" + canary + "\n"}, ErrMalformedKey},
		"too_long":  {[]string{EnvOpenRouter + "=" + strings.Repeat("a", 513)}, ErrMalformedKey},
		"other_var": {[]string{"OPENROUTER_API_KEY=" + canary}, ErrNoKey},
	} {
		v, err := FromEnviron(c.env, EnvOpenRouter)
		if !errors.Is(err, c.want) || !v.IsZero() {
			t.Errorf("%s: FromEnviron = %d bytes, %v; want %v", name, len(v.Reveal()), err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), canary) {
			t.Errorf("%s: error %q quotes the key", name, err)
		}
	}
	if _, err := FromEnviron([]string{"OPENROUTER_API_KEY=" + canary}, "OPENROUTER_API_KEY"); !errors.Is(err, ErrInvalidName) {
		t.Errorf("non REMPART_LLM_KEY_ name: %v, want ErrInvalidName", err)
	}
}
