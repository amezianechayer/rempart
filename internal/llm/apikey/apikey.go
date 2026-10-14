// Package apikey reads the key of a model platform from one REMPART_LLM_KEY_*
// environment variable (ADR 0008 D5, T20). The key is never quoted by an
// error; cmd/rempart-evals is its only importer (llm-adapters-evals-cli-only).
package apikey

import (
	"errors"
	"strings"

	"github.com/amezianechayer/rempart/internal/secrets/secret"
)

// EnvOpenRouter holds the OpenRouter key: not OPENROUTER_API_KEY, which other
// tools read by default.
const EnvOpenRouter = "REMPART_LLM_KEY_OPENROUTER"

const (
	prefix    = "REMPART_LLM_KEY_"
	maxKeyLen = 512
)

var (
	ErrNoKey        = errors.New("apikey: no key in the environment")
	ErrMalformedKey = errors.New("apikey: malformed or repeated key")
	ErrInvalidName  = errors.New("apikey: not a REMPART_LLM_KEY_ variable")
)

// FromEnviron returns the value of name in environ (KEY=VALUE entries): set
// once, 1 to 512 printable ASCII bytes without blank.
func FromEnviron(environ []string, name string) (secret.Value, error) {
	if !strings.HasPrefix(name, prefix) || len(name) == len(prefix) {
		return secret.Value{}, ErrInvalidName
	}
	n, value := 0, ""
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok && k == name {
			n, value = n+1, v
		}
	}
	switch {
	case n > 1:
		return secret.Value{}, ErrMalformedKey
	case n == 0 || value == "":
		return secret.Value{}, ErrNoKey
	case len(value) > maxKeyLen:
		return secret.Value{}, ErrMalformedKey
	}
	for i := 0; i < len(value); i++ {
		if value[i] <= ' ' || value[i] > '~' {
			return secret.Value{}, ErrMalformedKey
		}
	}
	return secret.New(value), nil
}
