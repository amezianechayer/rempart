# M0-T09 `llm-schema-prompts` : JSON Schema strict et prompts versionnés

2026-09-24, `architect`, proposé ; revue sécurité : oui. Sources : fiche M0-T09 (non élargie), `prompts/M0.md` critères 3 et 6, `llm-safety` règles 5 et 6, ADR 0002. `TestOutOfSchemaRejected` relève de T11. Pas d'ADR : dépendance confinée, profil et hash versionnés.

## 1. Objectif, périmètre, flux
Sortie LLM validée en échec fermé contre un schéma strict ; prompt chargé par `<nom>.v<N>` et haché. T11 : `p := prompts.Load(id)`, `Request{PromptID: p.ID, PromptHash: p.Hash, Schema: p.Schema.Raw()}`, `p.Schema.Validate(resp.Output)`.
- Dans : `internal/llm/schema/{schema,decode,strict}.go`, `internal/llm/prompts/{registry,embed}.go`, tests, `internal/llm/prompts/testdata/fixture.v1/{system.txt,schema.json}`, `go.mod`, `go.sum`, `docs/STATUS.md`.
- Hors : correction bornée, cache (T11) ; `output_config.format` (T12) ; prompt de démo (T19) ; nonce du délimiteur (T42).

## 2. Décisions (le code de la section 5 fait foi)
- **Strict** : racine de `type` `"object"` ; `$schema` absent ou exactement l'URI 2020-12 ; mots-clés limités à `nodeKeywords` (plus `$schema`, `$defs` à la racine) : refus de `$id`, `allOf`, `not`, `if`, `patternProperties`, `format`... ; tout sous-schéma est un objet portant `type`, `enum`, `const`, `$ref`, `anyOf` ou `oneOf` ; `type` est **un** nom (facultatif : `anyOf` avec `null`) ; **tout** objet, à toute profondeur, exige `additionalProperties: false` et `required` **exhaustif** ; `array` exige `items`.
- **`$ref`** : seulement `#/$defs/<nom>` existant, frères `title`, `description` seuls, jamais sous `$defs` (ni cycle ni récursion) ; chargeur qui refuse tout ; ressource sur le TLD réservé `.invalid`.
- **Décodage** : sortie `> 256 Kio` refusée avant tout ; schéma et `system.txt` 64 Kio ; 32 niveaux ; nombre de 40 octets au plus sans exposant ; UTF-8 valide ; une seule valeur JSON ; clé en double refusée.
- **Messages** : raison fixe ou `keyword <K> at /<chemin>` ; segment gardé s'il est un index ou une propriété déclarée dans le schéma, sinon `*` ; jamais de texte de bibliothèque ni d'octet de sortie.
- **Prompts** : `idPattern` et 64 octets vérifiés **avant** tout accès au FS ; `Version` = `N` ; `system.txt` non vide, UTF-8, sans `\r`. **Hash** : hex SHA-256 de `"rempart-prompt-v1\n"` puis netstrings `<len>:<octets>,` de l'identifiant, de `system.txt`, de `schema.json`. `builtin embed.FS` sans directive ; T19 ajoute `//go:embed demo.greeting.v1`.

## 3. Dépendance `github.com/santhosh-tekuri/jsonschema/v6` v6.0.3
Retenue : 2020-12 complet, Go pur, Apache-2.0, erreurs structurées (`InstanceLocation`, `KeywordPath`), `UseLoader`, `pattern` en RE2 ; contre : mainteneur unique, chargeur `file` par défaut (neutralisé). Écartées : `google/jsonschema-go` (pré-1.0, erreurs textuelles), validateur maison (sans suite de conformité), `xeipuuv`, `qri-io` (draft 7). **Étape 0** (après `phase tests`, sans `tidy`) : `go get github.com/santhosh-tekuri/jsonschema/v6@v6.0.3` ; `M` = son répertoire sous `$(go env GOMODCACHE)` ; écart : arrêt, amendement.

| Vérification | Attendu |
|---|---|
| `go mod graph \| grep '^github.com/santhosh-tekuri/jsonschema/v6@v6.0.3 ' \| cut -d' ' -f2 \| grep -v '^go@' \| sed 's/@.*//' \| sort -u` | inclus dans {`github.com/dlclark/regexp2`, `golang.org/x/text`} |
| `go mod verify` ; `head -3 "$M/LICENSE"` | `all modules verified` ; Apache License 2.0 |
| `grep -rlE --include='*.go' --exclude='*_test.go' '"(net/http\|os/exec)"' "$M" \| wc -l` | `0` |
| `go doc` des symboles de 5.1 | signatures utilisées en 5.1 |

## 4. Harnais (non patché)
Entrée : `phase=free`, `verify-quick` vert, arbre propre ; un seul tour de `phase tests` au premier `verify-quick` vert en impl. Tests internes ; seuls `undefined: X` au `go vet` ; tests de `prompts` sans import de `schema`. `git add go.mod go.sum internal/llm/schema/ internal/llm/prompts/` avant `phase impl`. Fixtures neutres (`CANARY`). Vérification sur copie avant gel (6.3) : écart tranché, jamais de correction silencieuse.

## 5. Code de référence (ancres de la section 8 au caractère près)

### 5.1 `internal/llm/schema/schema.go`
```go
// Package schema validates LLM outputs against strict JSON Schemas.
package schema

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

var (
	ErrOutOfSchema     = errors.New("llm: output does not match schema")
	ErrSchemaNotStrict = errors.New("llm: schema is not strict")
	ErrInvalidSchema   = errors.New("llm: invalid schema")
	errLoadDenied      = errors.New("schema: resource loading is denied")
)

const (
	MaxOutputBytes = 256 << 10
	MaxSchemaBytes = 64 << 10
	MaxDepth       = 32
	MaxNumberLen   = 40
	maxSegments    = 16
	resourceURL    = "https://rempart.invalid/llm/output.schema.json"
)

var keywordPattern = regexp.MustCompile(`^[A-Za-z$]{1,32}$`)

type Schema struct {
	raw      []byte
	names    map[string]bool
	compiled *jsonschema.Schema
}

type denyLoader struct{}

func (denyLoader) Load(string) (any, error) { return nil, errLoadDenied }

func CompileSchema(raw json.RawMessage) (*Schema, error) {
	if len(raw) > MaxSchemaBytes {
		return nil, fmt.Errorf("%w: too large", ErrInvalidSchema)
	}
	doc, reason := decodeStrict(raw)
	if reason != "" {
		return nil, fmt.Errorf("%w: %s", ErrInvalidSchema, reason)
	}
	names, err := checkStrict(doc)
	if err != nil {
		return nil, err
	}
	compiled, err := compileDoc(doc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidSchema, err)
	}
	return &Schema{raw: bytes.Clone(raw), names: names, compiled: compiled}, nil
}

func compileDoc(doc any) (*jsonschema.Schema, error) {
	c := jsonschema.NewCompiler()
	c.DefaultDraft(jsonschema.Draft2020)
	c.UseLoader(denyLoader{})
	if err := c.AddResource(resourceURL, doc); err != nil {
		return nil, err
	}
	return c.Compile(resourceURL)
}

func (s *Schema) Validate(output json.RawMessage) error {
	if s == nil || s.compiled == nil {
		return fmt.Errorf("%w: no schema", ErrOutOfSchema)
	}
	if len(output) > MaxOutputBytes {
		return fmt.Errorf("%w: output too large", ErrOutOfSchema)
	}
	v, reason := decodeStrict(output)
	if reason != "" {
		return fmt.Errorf("%w: %s", ErrOutOfSchema, reason)
	}
	err := s.compiled.Validate(v)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return fmt.Errorf("%w: validation failed", ErrOutOfSchema)
	}
	return fmt.Errorf("%w: %s", ErrOutOfSchema, describe(ve, s.names))
}

func (s *Schema) Raw() json.RawMessage {
	if s == nil {
		return nil
	}
	return bytes.Clone(s.raw)
}

func describe(ve *jsonschema.ValidationError, names map[string]bool) string {
	var leaves []string
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		for _, c := range e.Causes {
			walk(c)
		}
		if len(e.Causes) > 0 {
			return
		}
		kw := "?"
		if e.ErrorKind != nil {
			if p := e.ErrorKind.KeywordPath(); len(p) > 0 && keywordPattern.MatchString(p[len(p)-1]) {
				kw = p[len(p)-1]
			}
		}
		leaves = append(leaves, "keyword "+kw+" at "+pointer(e.InstanceLocation, names))
	}
	walk(ve)
	slices.Sort(leaves)
	return leaves[0]
}

func pointer(location []string, names map[string]bool) string {
	segs := make([]string, 0, maxSegments+1)
	for i, s := range location {
		if i == maxSegments {
			segs = append(segs, "*")
			break
		}
		if !isIndex(s) && !names[s] {
			s = "*"
		}
		segs = append(segs, s)
	}
	return "/" + strings.Join(segs, "/")
}

func isIndex(s string) bool {
	return s != "" && len(s) <= 10 && strings.Trim(s, "0123456789") == ""
}
```

### 5.2 `internal/llm/schema/decode.go`
```go
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
```

### 5.3 `internal/llm/schema/strict.go`
```go
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
```

### 5.4 `internal/llm/prompts/registry.go`
```go
// Package prompts loads versioned, hashed prompts (skill llm-safety, rule 6).
package prompts

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"strconv"
	"unicode/utf8"

	"github.com/amezianechayer/rempart/internal/llm/schema"
)

var (
	ErrInvalidPromptID = errors.New("llm: invalid prompt id")
	ErrUnknownPrompt   = errors.New("llm: unknown prompt")
	ErrInvalidPrompt   = errors.New("llm: invalid prompt")
)

const (
	MaxSystemBytes = 64 << 10
	maxIDLen       = 64
	hashDomain     = "rempart-prompt-v1\n"
)

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)*\.v([1-9][0-9]{0,5})$`)

type Prompt struct {
	ID      string
	Version int
	System  string
	Schema  *schema.Schema
	Hash    string
}

func LoadFS(fsys fs.FS, id string) (Prompt, error) {
	m := idPattern.FindStringSubmatch(id)
	if m == nil || len(id) > maxIDLen {
		return Prompt{}, ErrInvalidPromptID
	}
	version, err := strconv.Atoi(m[1])
	if err != nil {
		return Prompt{}, ErrInvalidPromptID
	}
	if fsys == nil {
		return Prompt{}, ErrUnknownPrompt
	}
	var files [2][]byte
	for i, name := range [2]string{"/system.txt", "/schema.json"} {
		b, err := fs.ReadFile(fsys, id+name)
		if errors.Is(err, fs.ErrNotExist) {
			return Prompt{}, ErrUnknownPrompt
		}
		if err != nil {
			return Prompt{}, fmt.Errorf("%w: unreadable file", ErrInvalidPrompt)
		}
		files[i] = b
	}
	system, raw := files[0], files[1]
	if reason := checkSystem(system); reason != "" {
		return Prompt{}, fmt.Errorf("%w: %s", ErrInvalidPrompt, reason)
	}
	s, err := schema.CompileSchema(raw)
	if err != nil {
		return Prompt{}, fmt.Errorf("%w: %w", ErrInvalidPrompt, err)
	}
	return Prompt{ID: id, Version: version, System: string(system), Schema: s, Hash: promptHash(id, system, raw)}, nil
}

func checkSystem(b []byte) string {
	switch {
	case len(b) == 0:
		return "empty system prompt"
	case len(b) > MaxSystemBytes:
		return "system prompt too large"
	case !utf8.Valid(b):
		return "system prompt is not valid UTF-8"
	case bytes.ContainsRune(b, '\r'):
		return "system prompt contains a carriage return"
	}
	return ""
}

func promptHash(id string, system, schemaRaw []byte) string {
	b := []byte(hashDomain)
	for _, part := range [][]byte{[]byte(id), system, schemaRaw} {
		b = strconv.AppendInt(b, int64(len(part)), 10)
		b = append(b, ':')
		b = append(b, part...)
		b = append(b, ',')
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
```

### 5.5 `internal/llm/prompts/embed.go`
```go
package prompts

import "embed"

// builtin: empty in M0-T09; M0-T19 adds "//go:embed demo.greeting.v1".
var builtin embed.FS

func Load(id string) (Prompt, error) { return LoadFS(builtin, id) }
```

### 5.6 Fixture `testdata/fixture.v1/`
`system.txt` : `Tu es un assistant de test. Réponds par un objet JSON conforme au schéma.` puis `\n`. `schema.json`, noté **F** (copié tel quel dans les tests de `schema`) :
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object", "additionalProperties": false, "required": ["count", "greeting", "tags"],
  "properties": {
    "greeting": {"type": "string", "minLength": 1, "maxLength": 200},
    "count": {"anyOf": [{"type": "integer", "minimum": 0}, {"type": "null"}]},
    "tags": {"type": "array", "maxItems": 5, "items": {
      "type": "object", "additionalProperties": false, "required": ["key", "level"],
      "properties": {"key": {"type": "string", "pattern": "^[a-z]+$"}, "level": {"$ref": "#/$defs/level"}}}}
  },
  "$defs": {"level": {"enum": ["low", "medium", "high"]}}
}
```

## 6. Tests (phase tests, `test-author`)
`R(p)` = `{"type":"object","additionalProperties":false,"required":["x"],"properties":{"x":p}}` ; `E_k` : `k` tableaux imbriqués ; `MIN` = `{"greeting":"a","count":null,"tags":[]}` ; `FULL` = `{"greeting":"Bonjour","count":3,"tags":[{"key":"env","level":"low"}]}` ; `pad(x,n)` : `x` complété d'espaces à `n` octets ; `a_{b,c}` : `a_b`, `a_c`. `errors.Is`, aucune autre sentinelle du paquet.

### 6.1 `internal/llm/schema` (`compile_test.go` : 1 à 3, 9 ; `validate_test.go` : 4 à 8)
1. **`TestCompileSchemaRequiresStrict`** (fiche), 48 cas. `nil` (7) : `fixture`, `no_schema_keyword`, `object_without_properties`, `nullable_string`, `anyof_strict_objects`, `depth_32` (`R({"enum":E_29})`), `max_size` (`pad(F,MaxSchemaBytes)`). `ErrSchemaNotStrict` (41) : `not_an_object`, `root_{type_array,type_missing,ap_missing,ap_true,ap_schema}`, `{nested,items,defs,anyof,oneof}_ap_missing`, `required_{incomplete,unknown,duplicate}`, `type_list` (`["string","null"]`), `type_list_with_object`, `unknown_type`, `boolean_{true,items}`, `empty_subschema` (`R({})`), `array_without_items`, `draft_07`, `schema_uri_fragment`, `external_ref_{https,file,local_fragment}` (le dernier : `https://rempart.invalid/o.json#/$defs/level`, `level` défini), `relative_ref`, `ref_{to_properties,missing_def,inside_defs,with_sibling_type}`, `defs_below_root`, `keyword_{id,anchor,dynamic_ref}`, `allof` (`R({"type":"string","allOf":[{"minLength":1}]})`), `not`, `if_then`, `pattern_properties`, `unevaluated_properties`, `format`.
2. **`TestCompileSchemaRejectsInvalid`**, `ErrInvalidSchema`, 11 cas : `not_json`, `empty`, `trailing_data`, `two_values`, `duplicate_key`, `invalid_utf8`, `too_large` (`pad(F,MaxSchemaBytes+1)`), `exponent` (`maxLength: 1e2`), `too_deep` (`R({"enum":E_30})`), `meta_invalid` (`minLength: -1`), `invalid_pattern` (`"("`).
3. **`TestCompilerNeverLoads`** : `{"type":"string"}` écrit (`0o600`) dans `t.TempDir()` ; `doc` = `decodeStrict(R({"$ref":"file://<chemin>"}))`. Témoin `jsonschema.NewCompiler()` sans `UseLoader` : compile. `compileDoc(doc)` : erreur ; idem `https://rempart.invalid/x.json` ; `compileDoc(F)` : `nil`.
4. **`TestValidateAcceptsConforming`** (fiche), F, 9 cas `nil` : `minimal`, `full`, `whitespace_around`, `key_order`, `unicode`, `escapes`, `number_40_digits`, `zero_count`, `exactly_max_bytes` (`pad(MIN,MaxOutputBytes)`).
5. **`TestValidateRejectsOutOfSchema`** (fiche), F, `ErrOutOfSchema`, message exact `llm: output does not match schema: ` + suffixe, 33 cas. `keyword required at /` : `missing_required`. `keyword additionalProperties at /` : `extra_field` ; `... at /tags/0` : `nested_extra_field`. `keyword type at /greeting` : `wrong_type`, `null_for_string`, `depth_32` (`E_31`). `keyword enum at /tags/0/level` : `enum_mismatch`. `keyword pattern at /tags/0/key` : `pattern_mismatch`. `keyword maxItems at /tags` : `too_many_items`. `keyword minLength at /greeting` : `empty_greeting`. `keyword minimum at /count` : `negative_count`. `keyword type at /count` : `float_count`. `keyword type at /` : `top_level_{array,string,null}`. `not a single JSON value` : `not_json`, `empty`, `whitespace_only`, `json_then_text`, `two_values`, `markdown_fence`, `trailing_comma`, `single_quotes`, `nan`. `duplicate object key` : `duplicate_key`, `duplicate_key_escaped` (seconde clé `greeting` avec un caractère en échappement Unicode). `invalid UTF-8` : `invalid_utf8`. `output too large` : `too_large` (`pad(MIN,MaxOutputBytes+1)`). `nesting too deep` : `too_deep` (`E_32`). `number too long or in exponent form` : `exponent`, `long_number` (41 chiffres). `no schema` : `nil_schema`, `zero_schema`.
6. **`TestValidationErrorDoesNotEchoOutput`** (fiche), 12 cas avec `CANARY` : clé en trop (racine, imbriquée, 50 clés, `"CANARY/../x"`), mauvais type, hors `enum`, hors `pattern`, trop longue, texte avant, texte après, clé en double, chaîne racine. Message sans `canary` (casse ignorée), 200 octets au plus, égal à `llm: output does not match schema: ` suivi d'une raison fixe de 5.1 ou 5.2, ou de `keyword K at /P` avec `K` dans `[A-Za-z$?]+` et `P` dans `[A-Za-z0-9_*/-]*`.
7. **`TestPointerFiltersSegments`**, `names` {`tags`,`level`} : `[]` : `/` ; `[tags 0 level]` : `/tags/0/level` ; `[CANARY]`, `[0x1]`, `[""]`, `[12345678901]` : `/*` ; 20 fois `0` : 16 `0` puis `*`.
8. **`TestSchemaRawIsCopy`** : modifier l'entrée puis un retour de `Raw()` ne change pas `Raw()` ; `(*Schema)(nil).Raw()` : `nil`. 9. **`TestSchemaSentinels`** : 3, distinctes, préfixe `llm: `.

### 6.2 `internal/llm/prompts` (`registry_test.go`)
`countingFS` : n'implémente que `Open`, compte les appels.
10. **`TestLoadFSFixture`** (`os.DirFS("testdata")`) : `ID`, `Version == 1`, `System` et `Raw()` égaux aux fichiers, `Hash` `^[0-9a-f]{64}$`, `Validate(FULL)` `nil`.
11. **`TestPromptHashStableAndSensitive`** (fiche), 6 cas : `golden` (hex de `sha256(fmt.Sprintf("rempart-prompt-v1\n%d:%s,%d:%s,%d:%s,", ...))` calculé dans le test), `stable`, `system_changed`, `schema_whitespace`, `other_version` (`fixture.v2`, `Version == 2`), `other_name`.
12. **`TestPromptUnknownID`** (fiche), `ErrUnknownPrompt`, 6 cas : `absent_in_fs`, `load_absent`, `testdata_not_embedded` (`Load("fixture.v1")`), `missing_{schema,system}`, `nil_fs`.
13. **`TestPromptInvalidID`**, 23 cas ; `ErrInvalidPromptID` et zéro `Open` : `""`, `fixture`, `fixture.v`, `fixture.v0`, `fixture.v01`, `fixture.V1`, `Fixture.v1`, `fixture.v1234567`, `../fixture.v1`, `./fixture.v1`, `testdata/fixture.v1`, `fixture.v1/`, `fixture.v1/../fixture.v1`, `.v1`, `a..b.v1`, `a-b.v1`, `"fixture.v1\n"`, `"fixture.v1\x00"`, `" fixture.v1"`, `1a.v1`, 62 `a` + `.v1` ; témoins `ErrUnknownPrompt` avec `Open` : 61 `a` + `.v1`, `a_b.c9.v123456`.
14. **`TestPromptInvalidContent`**, MapFS `p.v1`, 8 cas : `ErrInvalidPrompt` pour `empty_system`, `system_{cr,invalid_utf8,too_large,is_dir}`, `schema_not_strict` (contient `llm: schema is not strict`), `schema_not_json` (`llm: invalid schema`) ; `nil` pour `system_max_size`.
15. **`TestEmbeddedPromptsLoad`** : `fs.ReadDir(builtin, ".")` sans erreur ; chaque entrée est un répertoire chargé par `Load` (zéro en T09). 16. **`TestPromptSentinels`** : 3, distinctes, préfixe `llm: `.

### 6.3 Rouge et vérification sur copie
Rouge : aucun `.go` non test ; `go vet ./internal/llm/schema ./internal/llm/prompts 2>&1 | grep -E '\.go:[0-9]+:[0-9]+: ' | grep -vc 'undefined: '` : `0` ; après `git add`, `git status --porcelain` : `M  go.mod`, `M  go.sum`, `A ` pour 3 `_test.go` et 2 fixtures ; `phase impl` : `Phase : tests -> impl`. Copie (`cp -a`, scratchpad), section 5 telle quelle : `go mod tidy`, lint et `go test` des deux paquets à `rc=0`, critères 2, 4, 5, section 8 ; copie supprimée.

## 7. Critères d'acceptation (racine, `-count=1`)
| # | Commande | Attendu |
|---|---|---|
| 1 | `go test ./internal/llm/schema/... ./internal/llm/prompts/... -count=1 -v 2>&1 \| grep -cE '^--- PASS: (TestCompileSchemaRequiresStrict\|TestValidateAcceptsConforming\|TestValidateRejectsOutOfSchema\|TestValidationErrorDoesNotEchoOutput\|TestPromptHashStableAndSensitive\|TestPromptUnknownID) '` ; même sortie `grep -cE '^--- PASS: Test'` ; `grep -cE -- '--- (FAIL\|SKIP)'` | `6` ; `16` ; `0` |
| 2 | (`T`,`N`) : (`TestCompileSchemaRequiresStrict`,48), (`TestCompileSchemaRejectsInvalid`,11), (`TestValidateRejectsOutOfSchema`,33), (`TestValidationErrorDoesNotEchoOutput`,12), (`TestPromptInvalidID`,23) : `go test ./internal/llm/... -count=1 -v -run "^$T\$" 2>&1 \| grep -c -- "--- PASS: $T/"` | `N` |
| 3 | `make verify-quick; echo rc=$?` | `rc=0` |
| 4 | `go list -f '{{.ImportPath}} {{.Imports}} {{.TestImports}}' ./... \| grep jsonschema \| cut -d' ' -f1` | une ligne, `.../internal/llm/schema` |
| 5 | `go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./internal/llm/prompts \| grep -vcE '^(github.com/amezianechayer/rempart/internal/llm/\|github.com/santhosh-tekuri/jsonschema/v6\|golang.org/x/text)'` ; `go list -deps ./internal/llm/prompts \| grep -cE '^(net/http\|os/exec)$'` | `0` ; `0` |
| 6 | `go list -m -f '{{.Version}} {{.Indirect}}' github.com/santhosh-tekuri/jsonschema/v6` ; `go mod tidy -diff; echo rc=$?` ; `go tool govulncheck ./internal/llm/...` | `v6.0.3 false` ; `rc=0` ; `No vulnerabilities found.` |
| 7 | `go list -f '{{len .EmbedFiles}}' ./internal/llm/prompts` ; `grep -rn --include='*.go' --exclude='*_test.go' -E 'panic\(\|os\.Getenv\|\.Error\(\)' internal/llm/schema internal/llm/prompts \| wc -l` | `0` ; `0` |

## 8. Mutations sur copie (jamais dans le dépôt)
Script de `M0-tenancy.md` 8.3, ancre unique ; `go test ./internal/llm/schema/ ./internal/llm/prompts/ -count=1 2>&1 | grep -cE -- "--- FAIL: ($EXPECTED)"` au moins `1`, `EXPECTED` : test numéroté en section 6. `AF` : `OLD` suivi de ` && false`. `st`, `sc`, `de`, `re` : `strict.go`, `schema.go`, `decode.go`, `registry.go`.

| # | F | `OLD` | `NEW` | Test |
|---|---|---|---|---|
| M1 | st | `!ok \|\| ap {` | `(!ok \|\| ap) && false {` | 1 |
| M2 | st | `if !slices.Equal(` | `if false && !slices.Equal(` | 1 |
| M3 | st | `"/properties/"+name, false, inDefs); err != nil` | AF | 1 |
| M4 | st | `i), false, inDefs); err != nil` | AF | 1 |
| M5 | st | `` `^#/\$defs/`` | `` `#/\$defs/`` | 1 |
| M6 | st | `anyOf oneOf` | `anyOf oneOf allOf` | 1 |
| M7 | st | `return notStrict(path, "subschema must be an object")` | `return nil` | 1 |
| M8 | st | `if inDefs \|\| ` | `if ` | 1 |
| M9 | sc | `c.UseLoader(denyLoader{})` | vide | 3 |
| M10 | sc | `len(output) > MaxOutputBytes` | AF | 5 |
| M11 | sc | `"keyword "+kw+" at "+pointer(e.InstanceLocation, names)` | `kw + e.Error()` | 6 |
| M12 | sc | `!isIndex(s) && !names[s]` | `false` | 7 |
| M13 | de | `!errors.Is(err, io.EOF)` | AF | 5 |
| M14 | de | `; dup` | AF | 5 |
| M15 | de | `depth >= MaxDepth` | AF | 5 |
| M16 | de | `"eE"` | `""` | 5 |
| M17 | re | `` `^[a-z][a-z0-9_]*(?:`` | `` `^[a-z./][a-z0-9_./]*(?:`` | 13 |
| M18 | re | `[]byte(id), system, schemaRaw` | `system, schemaRaw` | 11 |

## 9. Revue sécurité, risques, menaces
Revue (PASS attendu ; un BLOCK qui change un test renvoie en phase tests) : propriété non déclarée (M1 à M8), chargement (tests 1, 3, M5, M9), décodage (M10, M13 à M16), sortie jamais recopiée (tests 6, 7), traversée (test 13, M17), hash (test 11), dépendance (critères 4 à 6). Boucle : sans objet. Risques : API v6 différente (`go doc`, témoin du test 3) ; mots-clés refusés par la sortie native d'un fournisseur (T12 tranche, la validation locale reste la garantie).
Menaces : **T2** vérifiable (tests 1, 5) ; **T6** dépendance épinglée ; **T7, T37** aucune sortie (qui peut porter un secret) dans une erreur ; **T42** inchangée. **Proposition T43** : schéma permissif ou référence externe (sortie non contrainte, lecture de fichier, requête réseau), sortie malformée exploitant un écart d'analyse ; transmise à `security-reviewer`.

## 10. Tâches ordonnées (un seul tour après validation humaine)
| # | Tâche | Qui | Vérification |
|---|---|---|---|
| A0 | Entrée, `phase tests`, étape 0 | principal | tableau de la section 3 |
| A1 | Tests 1 à 9, fixture, tests 10 à 16 | `test-author` | `undefined:` seulement |
| A2 | Copie (6.3) ; rouge, `git add`, `phase impl` | `test-author`, principal | 18 mutations détectées ; `Phase : tests -> impl` |
| I1 | `decode.go`, `strict.go`, `schema.go`, puis `registry.go`, `embed.go` | principal | tests 1 à 9, puis 10 à 16 |
| I2 | `go mod tidy`, `make verify-quick` | principal | critères 1 à 7 |
| F1 | Mutations sur copie finale ; `security-reviewer`, `acceptance-verifier` | principal, subagents | PASS |
| F2 | `docs/STATUS.md` (étape 0, obligations T11, T12, T19, T43) ; `phase free` ; commit `feat(llm): strict JSON schema validation and versioned prompts (M0-T09)` | principal | arbre propre |
