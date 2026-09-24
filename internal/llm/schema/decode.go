package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	reasonUTF8      = "invalid UTF-8"
	reasonNotJSON   = "not a single JSON value"
	reasonDuplicate = "duplicate object key"
	reasonDepth     = "nesting too deep"
	reasonNumber    = "number too long or in exponent form"
)

func decodeStrict(data []byte) (any, string) {
	if !utf8.Valid(data) {
		return nil, reasonUTF8
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	v, reason := decodeValue(dec, 0)
	if reason != "" {
		return nil, reason
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, reasonNotJSON
	}
	return v, ""
}

func decodeValue(dec *json.Decoder, depth int) (any, string) {
	tok, err := dec.Token()
	if err != nil {
		return nil, reasonNotJSON
	}
	if n, ok := tok.(json.Number); ok && (len(n) > MaxNumberLen || strings.ContainsAny(string(n), "eE")) {
		return nil, reasonNumber
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, ""
	}
	if depth >= MaxDepth {
		return nil, reasonDepth
	}
	obj, arr := map[string]any{}, []any{}
	for dec.More() {
		key := ""
		if delim == '{' {
			keyTok, err := dec.Token()
			k, isKey := keyTok.(string)
			if err != nil || !isKey {
				return nil, reasonNotJSON
			}
			if _, dup := obj[k]; dup {
				return nil, reasonDuplicate
			}
			key = k
		}
		v, reason := decodeValue(dec, depth+1)
		if reason != "" {
			return nil, reason
		}
		if delim == '{' {
			obj[key] = v
		} else {
			arr = append(arr, v)
		}
	}
	if _, err := dec.Token(); err != nil {
		return nil, reasonNotJSON
	}
	if delim == '{' {
		return obj, ""
	}
	return arr, ""
}
