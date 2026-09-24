package schema

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

const draft2020 = "https://json-schema.org/draft/2020-12/schema"

var (
	refPattern   = regexp.MustCompile(`^#/\$defs/([A-Za-z0-9_]{1,64})$`)
	nodeKeywords = set("type enum const properties required additionalProperties items minItems maxItems " +
		"minLength maxLength pattern minimum maximum anyOf oneOf $ref title description")
	typeNames = set("null boolean object array number integer string")
)

func set(words string) map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(words) {
		m[w] = true
	}
	return m
}

type checker struct {
	defs  map[string]any
	names map[string]bool
}

func notStrict(path, reason string) error {
	return fmt.Errorf("%w: %s at %s", ErrSchemaNotStrict, reason, path)
}

func checkStrict(doc any) (map[string]bool, error) {
	root, ok := doc.(map[string]any)
	if !ok || root["type"] != "object" {
		return nil, notStrict("#", "root must be a schema of type object")
	}
	if v, ok := root["$schema"]; ok && v != draft2020 {
		return nil, notStrict("#", "only draft 2020-12 is allowed")
	}
	c := checker{defs: map[string]any{}, names: map[string]bool{}}
	if d, ok := root["$defs"]; ok {
		if c.defs, ok = d.(map[string]any); !ok {
			return nil, notStrict("#", "$defs must be an object")
		}
	}
	for _, name := range slices.Sorted(maps.Keys(c.defs)) {
		if err := c.node(c.defs[name], "#/$defs/"+name, false, true); err != nil {
			return nil, err
		}
	}
	if err := c.node(root, "#", true, false); err != nil {
		return nil, err
	}
	return c.names, nil
}

func (c checker) node(v any, path string, root, inDefs bool) error {
	n, ok := v.(map[string]any)
	if !ok {
		return notStrict(path, "subschema must be an object")
	}
	for k := range n {
		allowed := nodeKeywords[k] || root && (k == "$schema" || k == "$defs")
		if !allowed {
			return notStrict(path, "keyword not allowed")
		}
	}
	if !hasAny(n, "type", "enum", "const", "$ref", "anyOf", "oneOf") {
		return notStrict(path, "subschema must constrain the type")
	}
	if ref, ok := n["$ref"]; ok {
		return c.ref(n, ref, path, inDefs)
	}
	if t, ok := n["type"]; ok {
		s, isString := t.(string)
		if !isString || !typeNames[s] {
			return notStrict(path, "type must be one type name")
		}
		if s == "object" {
			if err := c.object(n, path, inDefs); err != nil {
				return err
			}
		}
		if s == "array" {
			if err := c.node(n["items"], path+"/items", false, inDefs); err != nil {
				return err
			}
		}
	}
	for _, key := range []string{"anyOf", "oneOf"} {
		list, ok := n[key].([]any)
		if _, has := n[key]; has && (!ok || len(list) == 0) {
			return notStrict(path, key+" must be a non-empty array")
		}
		for i, item := range list {
			if err := c.node(item, fmt.Sprintf("%s/%s/%d", path, key, i), false, inDefs); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c checker) object(n map[string]any, path string, inDefs bool) error {
	if ap, ok := n["additionalProperties"].(bool); !ok || ap {
		return notStrict(path, "additionalProperties must be false")
	}
	props, ok := n["properties"].(map[string]any)
	if _, has := n["properties"]; has && !ok {
		return notStrict(path, "properties must be an object")
	}
	list, ok := n["required"].([]any)
	if _, has := n["required"]; has && !ok {
		return notStrict(path, "required must be an array")
	}
	required := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			return notStrict(path, "required must hold names")
		}
		required = append(required, s)
	}
	slices.Sort(required)
	if !slices.Equal(required, slices.Sorted(maps.Keys(props))) {
		return notStrict(path, "required must list every property exactly once")
	}
	for _, name := range slices.Sorted(maps.Keys(props)) {
		c.names[name] = true
		if err := c.node(props[name], path+"/properties/"+name, false, inDefs); err != nil {
			return err
		}
	}
	return nil
}

func (c checker) ref(n map[string]any, ref any, path string, inDefs bool) error {
	for k := range n {
		if k != "$ref" && k != "title" && k != "description" {
			return notStrict(path, "$ref allows only title and description beside it")
		}
	}
	s, isString := ref.(string)
	m := refPattern.FindStringSubmatch(s)
	if inDefs || !isString || m == nil {
		return notStrict(path, "$ref must be #/$defs/<name>, outside $defs")
	}
	if _, ok := c.defs[m[1]]; !ok {
		return notStrict(path, "$ref target is missing")
	}
	return nil
}

func hasAny(n map[string]any, keys ...string) bool {
	for _, k := range keys {
		if _, ok := n[k]; ok {
			return true
		}
	}
	return false
}
