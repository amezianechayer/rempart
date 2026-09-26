# M0-T19a `llm-harden` : durcissements préalables de `internal/llm` (T43, T44)

2026-09-26, `architect`, proposé. Première des quatre tâches qui remplacent M0-T19 (section 2, amendement A3 à valider). Aucun ADR (changements internes réversibles). Revue sécurité : oui. Ni `internal/loops` ni le SDK Temporal ne sont touchés.

## 0. Amendements

(aucun)

## 1. Objet

Solder avant le premier prompt réel (M0-T19d) les obligations de `docs/STATUS.md` sur `internal/llm` : T43 (clés sœurs d'un `enum`, `anyOf`, `oneOf` ou d'un type scalaire non parcourues ; `LoadFS` qui lit tout avant la borne et suit les liens) ; T44 (secret dans l'`InputSchema` d'un outil ou le schéma du prompt ; copie profonde des outils) ; réserve basse de M0-T11 (texte rédigé au-delà de 1 Mio). Leçon de M0-T22 : listes d'admission fermées d'emblée.

Hors : `internal/llm/redact` (refonte, garde de `prompts/M1.md`), scripts du faux (M0-T20), adaptateurs, validation des sorties, `internal/loops`.

## 2. Décision structurante : découpage de M0-T19 (option A)

M0-T19 porte la fiche (8 tests, prompt, skill) et 16 obligations dans trois paquets : une tâche unique (option B) dépasserait un cycle tests puis impl et mélangerait trois revues. Ordre, chaque tâche avec revue sécurité :

| Tâche | Contenu | Dépend de |
|---|---|---|
| M0-T19a `llm-harden` (ce plan) | T43, T44, bornes de M0-T11 | T09, T11 |
| M0-T19b `loops-harden` | obligations (a), (h), (i), (m) côté `RunLoop`, (j), (n) | T14, T15 |
| M0-T19c `loops-archtest` | obligations (d), (p), (l), (k) | T02, T19b |
| M0-T19d `demo-workflow` | fiche M0-T19 selon A1, (m) côté démo, (o), (g) | T19a à T19c |

## 3. Décisions

| # | Décision |
|---|---|
| D1 | **Formes fermées** (T43) : un sous-schéma a exactement une forme (nom de type, `$ref`, `anyOf` ou `oneOf` ; sans aucune, `enum` puis `const`), chacune avec sa liste d'admission (`forms`) plus `title` et `description` ; la racine ajoute `$schema` et `$defs`. Tout autre mot-clé est refusé. |
| D2 | Un sous-schéma n'est admis que là où il s'applique, donc toujours parcouru ; les valeurs scalaires restent au méta-schéma (tests gelés de M0-T09 inchangés) ; `enum` et `const` sont des données, soumises à D3. |
| D3 | **Liste d'admission des textes** (`schema.AdmittedText`) : ASCII imprimable, saut de ligne, lettres du français (D17 de M0-T22 sans retour chariot), après décodage (`\u202e` compris), pour toute clé et chaîne d'un schéma et le prompt système : texte relu égal au texte envoyé (T64). Refus sans citer le caractère. |
| D4 | Noms : propriété `^[A-Za-z][A-Za-z0-9_]{0,63}$` (citée dans les erreurs renvoyées au modèle) ; définition `^[A-Za-z0-9_]{1,64}$`. |
| D5 | **Lecture bornée** (T43) : `fs.Lstat` du répertoire puis de chaque fichier (répertoire, puis fichier régulier exigés ; lien jamais suivi) ; taille déclarée comparée avant ouverture ; `io.LimitReader(limite + 1)`. Résidu : FS modifiable entre `Lstat` et `Open` (hors production : `embed.FS`). |
| D6 | **Secrets des schémas** (T44) : `ContainsSecret` sur le JSON brut de chaque `InputSchema` avant compilation et sur `Schema.Raw()` du prompt ; échec fermé. |
| D7 | `checkTools` rend une copie profonde vérifiée, seule transmise au fournisseur. |
| D8 | `textSize` recalculé après rédaction ; au-delà de 1 Mio, `ErrRequestTooLarge` (après la route, avant tout appel). |

## 4. Interfaces

Nouvelle : `func schema.AdmittedText(s string) bool`. Publiques inchangées. Interne : `checkTools(tools) ([]domain.ToolSpec, map[string]*schema.Schema, error)`.

## 5. Code de référence (normatif)

`admit.go` est complet ; ailleurs, chaque fonction citée est complète et remplace l'actuelle, le reste est identique à l'octet.

### 5.1 `internal/llm/schema/admit.go`
```go
package schema

// AdmittedText reports whether every rune of s is in the closed list of T43:
// printable ASCII, a line feed, or a French letter (U+00C0 to U+00FF but
// U+00D7 and U+00F7, U+0152, U+0153, U+0178). Invalid UTF-8 decodes to
// U+FFFD, which is not in the list.
func AdmittedText(s string) bool {
	for _, r := range s {
		switch {
		case r >= ' ' && r <= '~', r == '\n':
		case r >= 0xC0 && r <= 0xFF && r != 0xD7 && r != 0xF7, r == 0x152, r == 0x153, r == 0x178:
		default:
			return false
		}
	}
	return true
}

// admittedDoc reports whether every key and every string of a decoded
// document is admitted; JSON escapes are already decoded.
func admittedDoc(v any) bool {
	switch x := v.(type) {
	case string:
		return AdmittedText(x)
	case map[string]any:
		for k, e := range x {
			if !AdmittedText(k) || !admittedDoc(e) {
				return false
			}
		}
	case []any:
		for _, e := range x {
			if !admittedDoc(e) {
				return false
			}
		}
	}
	return true
}
```

### 5.2 `schema.go`, dans `CompileSchema`, entre le refus de `decodeStrict` et `checkStrict`
```go
	if !admittedDoc(doc) {
		return nil, fmt.Errorf("%w: character outside the admission list", ErrSchemaNotStrict)
	}
```

### 5.3 `strict.go`
`nodeKeywords` et `hasAny` supprimés ; `set`, `checker`, `notStrict` inchangés.
```go
var (
	refPattern = regexp.MustCompile(`^#/\$defs/([A-Za-z0-9_]{1,64})$`)
	defName    = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)
	propName   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	typeNames  = set("null boolean object array number integer string")
	// forms is the closed admission list of T43: the keywords of a subschema
	// of each form, besides title and description.
	forms = map[string][]string{
		"object":  {"type", "properties", "required", "additionalProperties"},
		"array":   {"type", "items", "minItems", "maxItems"},
		"string":  {"type", "minLength", "maxLength", "pattern", "enum", "const"},
		"integer": {"type", "minimum", "maximum", "enum", "const"},
		"number":  {"type", "minimum", "maximum", "enum", "const"},
		"boolean": {"type", "enum", "const"},
		"null":    {"type", "enum", "const"},
		"$ref":    {"$ref"},
		"anyOf":   {"anyOf"},
		"oneOf":   {"oneOf"},
		"enum":    {"enum"},
		"const":   {"const"},
	}
)
```
En tête de la boucle sur `c.defs` de `checkStrict`, puis de la boucle sur `props` d'`object` :
```go
		if !defName.MatchString(name) {
			return nil, notStrict("#/$defs", "definition name not allowed")
		}
```
```go
		if !propName.MatchString(name) {
			return notStrict(path, "property name not allowed")
		}
```
`node` et `ref` remplacées, `formOf` et `list` nouvelles :
```go
func (c checker) node(v any, path string, root, inDefs bool) error {
	n, ok := v.(map[string]any)
	if !ok {
		return notStrict(path, "subschema must be an object")
	}
	form, reason := formOf(n)
	if reason != "" {
		return notStrict(path, reason)
	}
	allowed := append(slices.Clone(forms[form]), "title", "description")
	if root {
		allowed = append(allowed, "$schema", "$defs")
	}
	for _, k := range slices.Sorted(maps.Keys(n)) {
		if !slices.Contains(allowed, k) {
			return notStrict(path, "keyword not allowed in a subschema of this form")
		}
	}
	switch form {
	case "$ref":
		return c.ref(n["$ref"], path, inDefs)
	case "object":
		return c.object(n, path, inDefs)
	case "array":
		return c.node(n["items"], path+"/items", false, inDefs)
	case "anyOf", "oneOf":
		return c.list(n[form], path+"/"+form, inDefs)
	}
	return nil
}

// formOf returns the form of n: exactly one of a type name, $ref, anyOf and
// oneOf; without any, enum then const. reason is empty when a form is found.
func formOf(n map[string]any) (form, reason string) {
	var keys []string
	for _, k := range []string{"type", "$ref", "anyOf", "oneOf"} {
		if _, ok := n[k]; ok {
			keys = append(keys, k)
		}
	}
	switch {
	case len(keys) > 1:
		return "", "a subschema has one of type, $ref, anyOf, oneOf"
	case len(keys) == 1 && keys[0] != "type":
		return keys[0], ""
	case len(keys) == 1:
		s, ok := n["type"].(string)
		if !ok || !typeNames[s] {
			return "", "type must be one type name"
		}
		return s, ""
	}
	for _, k := range []string{"enum", "const"} {
		if _, ok := n[k]; ok {
			return k, ""
		}
	}
	return "", "subschema must constrain the type"
}

func (c checker) list(v any, path string, inDefs bool) error {
	items, ok := v.([]any)
	if !ok || len(items) == 0 {
		return notStrict(path, "must be a non-empty array")
	}
	for i, item := range items {
		if err := c.node(item, fmt.Sprintf("%s/%d", path, i), false, inDefs); err != nil {
			return err
		}
	}
	return nil
}

// ref: the siblings of $ref are restricted by forms.
func (c checker) ref(ref any, path string, inDefs bool) error {
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
```

### 5.4 `internal/llm/prompts/registry.go`
Import `io` ajouté. Dans `LoadFS`, tout ce qui suit `if fsys == nil { ... }` et précède `checkSystem` (boucle `files` comprise) devient :
```go
	if _, err := entry(fsys, id, true); err != nil {
		return Prompt{}, err
	}
	system, err := readBounded(fsys, id+"/system.txt", MaxSystemBytes)
	if err != nil {
		return Prompt{}, err
	}
	raw, err := readBounded(fsys, id+"/schema.json", schema.MaxSchemaBytes)
	if err != nil {
		return Prompt{}, err
	}
```
Fonctions nouvelles, puis dernier cas de `checkSystem` (après le retour chariot) :
```go
// entry returns the fs.Lstat information of name, a directory if dir, a
// regular file otherwise; a missing entry is ErrUnknownPrompt. A link is
// never followed (T43).
func entry(fsys fs.FS, name string, dir bool) (fs.FileInfo, error) {
	fi, err := fs.Lstat(fsys, name)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, ErrUnknownPrompt
	case err != nil:
		return nil, fmt.Errorf("%w: unreadable entry", ErrInvalidPrompt)
	case dir && !fi.IsDir(), !dir && !fi.Mode().IsRegular():
		return nil, fmt.Errorf("%w: link or unexpected file type", ErrInvalidPrompt)
	}
	return fi, nil
}

// readBounded reads the regular file name: its declared size is checked
// before opening, the bytes read after, never more than limit + 1.
func readBounded(fsys fs.FS, name string, limit int) ([]byte, error) {
	fi, err := entry(fsys, name, false)
	if err != nil {
		return nil, err
	}
	if fi.Size() > int64(limit) {
		return nil, fmt.Errorf("%w: file too large", ErrInvalidPrompt)
	}
	f, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("%w: unreadable file", ErrInvalidPrompt)
	}
	b, rerr := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if cerr := f.Close(); rerr != nil || cerr != nil {
		return nil, fmt.Errorf("%w: unreadable file", ErrInvalidPrompt)
	}
	if len(b) > limit {
		return nil, fmt.Errorf("%w: file too large", ErrInvalidPrompt)
	}
	return b, nil
}
```
```go
	case !schema.AdmittedText(string(b)):
		return "system prompt contains a character outside the admission list"
```

### 5.5 `internal/llm/check.go` : `checkTools` (import `bytes`)
```go
// checkTools checks a deep copy of tools and returns it with the compiled
// schemas: the provider receives exactly the checked bytes (T44). A secret in
// a name, a description or the raw input schema is refused before compiling.
func checkTools(tools []domain.ToolSpec) ([]domain.ToolSpec, map[string]*schema.Schema, error) {
	if len(tools) == 0 {
		return nil, nil, fmt.Errorf("%w: no tool", ErrInvalidTools)
	}
	r := redact.New()
	checked := make([]domain.ToolSpec, len(tools))
	schemas := make(map[string]*schema.Schema, len(tools))
	for i, t := range tools {
		t.InputSchema = bytes.Clone(t.InputSchema)
		checked[i] = t
		if !toolName.MatchString(t.Name) {
			return nil, nil, fmt.Errorf("%w: malformed name", ErrInvalidTools)
		}
		if _, dup := schemas[t.Name]; dup {
			return nil, nil, fmt.Errorf("%w: duplicate name", ErrInvalidTools)
		}
		if r.ContainsSecret(t.Name) || r.ContainsSecret(t.Description) || r.ContainsSecret(string(t.InputSchema)) {
			return nil, nil, ErrSecretInPrompt
		}
		s, err := schema.CompileSchema(t.InputSchema)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: %w", ErrInvalidTools, err)
		}
		schemas[t.Name] = s
	}
	return checked, schemas, nil
}
```

### 5.6 `internal/llm/client.go`
S7, S12 et `loadPrompt` ci-dessous ; `c.provider.WithTools(ctx, route, req, tools)` devient `c.provider.WithTools(ctx, route, req, checked)`.
```go
	var (
		toolSchemas map[string]*schema.Schema
		checked     []domain.ToolSpec
	)
	if withTools { // S7: the provider gets the checked copy (T44)
		if checked, toolSchemas, err = checkTools(tools); err != nil {
			return Result{}, nil, err
		}
	}
```
```go
	msgs, redactions := redactMessages(call.Messages) // S12
	if textSize(msgs) > MaxRequestTextBytes {           // S12b: masks may lengthen the text
		return Result{}, nil, ErrRequestTooLarge
	}
```
```go
	r := redact.New() // a secret in the system prompt or its schema is refused, never masked
	if r.ContainsSecret(p.System) || r.ContainsSecret(string(p.Schema.Raw())) {
		return prompts.Prompt{}, ErrSecretInPrompt
	}
```

## 6. Tests (fichiers nouveaux ; tests gelés de M0-T09 et M0-T11 inchangés)

Les `\uXXXX` ci-dessous sont des échappements écrits en ASCII, jamais le caractère lui-même (bidichk, critère 5).

### 6.1 `internal/llm/schema/strict_test.go`
```go
package schema

import (
	"errors"
	"strings"
	"testing"
)

func wantNotStrict(t *testing.T, s string) {
	t.Helper()
	got, err := CompileSchema([]byte(s))
	if !errors.Is(err, ErrSchemaNotStrict) || got != nil {
		t.Fatalf("CompileSchema = %v, %v; want ErrSchemaNotStrict", got, err)
	}
	if strings.ContainsAny(err.Error(), "\t\r\u00a0\u00d7\u200b\u2028\u202e\ufeff") {
		t.Errorf("error %q quotes a refused character", err)
	}
}

// TestStrictClosedForms: each form admits only its keywords, at any depth (D1, D4).
func TestStrictClosedForms(t *testing.T) {
	obj := func(name string) string {
		return `{"type":"object","additionalProperties":false,"required":["` + name + `"],"properties":{"` + name + `":{"type":"string"}}}`
	}
	rejected := map[string]string{
		"string with properties":    wrap(`{"type":"string","properties":{"a":{"foo":1}}}`),
		"enum with properties":      wrap(`{"enum":["a"],"properties":{"a":{"type":"string"}}}`),
		"object with items":         wrap(`{"type":"object","additionalProperties":false,"items":{"type":"string"}}`),
		"type and anyOf":            wrap(`{"type":"string","anyOf":[{"type":"string"}]}`),
		"anyOf and oneOf":           wrap(`{"anyOf":[{"type":"null"}],"oneOf":[{"type":"null"}]}`),
		"enum and const":            wrap(`{"enum":["a"],"const":"a"}`),
		"sibling inside anyOf":      wrap(`{"anyOf":[{"type":"string","items":{"type":"string"}}]}`),
		"sibling inside defs":       withDefs(`{"$ref":"#/$defs/l"}`, `{"l":{"enum":["a"],"minimum":0}}`),
		"root with items":           `{"type":"object","additionalProperties":false,"items":{"type":"string"}}`,
		"property name with dash":   obj("a-b"),
		"property name non ascii":   obj(`\u00e9`),
		"definition name with dash": withDefs(`{"$ref":"#/$defs/l"}`, `{"l":{"enum":["a"]},"a-b":{"type":"string"}}`),
	}
	accepted := map[string]string{
		"string enum annotated": wrap(`{"type":"string","enum":["a","b"],"title":"t","description":"d"}`),
		"integer bounds const":  wrap(`{"type":"integer","minimum":0,"maximum":3,"const":1}`),
		"ref annotated":         withDefs(`{"$ref":"#/$defs/l","description":"x"}`, `{"l":{"enum":["a"]}}`),
		"property name a_B9":    obj("a_B9"),
	}
	if len(rejected) != 12 || len(accepted) != 4 {
		t.Fatalf("case table: %d rejected, %d accepted; want 12 and 4", len(rejected), len(accepted))
	}
	for name, s := range rejected {
		t.Run(name, func(t *testing.T) { wantNotStrict(t, s) })
	}
	for name, s := range accepted {
		t.Run(name, func(t *testing.T) {
			if _, err := CompileSchema([]byte(s)); err != nil {
				t.Fatalf("CompileSchema = %v, want nil", err)
			}
		})
	}
}

// TestSchemaAdmissionList: every key and string, escapes decoded, is admitted (D3).
func TestSchemaAdmissionList(t *testing.T) {
	for _, s := range []string{
		wrap(`{"type":"string","description":"a\u202eb"}`),
		wrap(`{"type":"string","title":"a\u200bb"}`),
		wrap(`{"type":"string","description":"a\tb"}`),
		wrap(`{"type":"string","description":"a\rb"}`),
		wrap(`{"type":"string","description":"a\u0000b"}`),
		wrap(`{"type":"string","pattern":"a\u00a0b"}`),
		wrap(`{"type":"string","enum":["a\u00d7b"]}`),
		wrap(`{"const":"a\u2028b"}`),
		wrap(`{"enum":[{"a\u202e":1}]}`),
		wrap(`{"type":"string","title":"\ufeffa"}`),
		wrap("{\"type\":\"string\",\"description\":\"a\u202eb\"}"), // interpreted: raw rune at run time
	} {
		wantNotStrict(t, s)
	}
	french := wrap(`{"type":"string","description":"Réponds en français.\nœ Œ Ÿ ÿ À","enum":["é"]}`)
	if _, err := CompileSchema([]byte(french)); err != nil {
		t.Errorf("French text refused: %v", err)
	}
}

// TestAdmittedText: the closed list of D3, rune by rune.
func TestAdmittedText(t *testing.T) {
	admitted := []rune{' ', '~', 'a', 'Z', '0', '\n', 0xC0, 0xD6, 0xD8, 0xF6, 0xF8, 0xFF, 0x152, 0x153, 0x178}
	refused := []rune{
		'\t', '\r', 0x00, 0x1F, 0x7F, 0x80, 0x9F, 0xA0, 0xAD, 0xBF, 0xD7, 0xF7, 0x100, 0x151,
		0x154, 0x177, 0x179, 0x200B, 0x202E, 0x2028, 0xFEFF, 0xFFFD, 0x1F600,
	}
	for _, r := range admitted {
		if !AdmittedText("a" + string(r) + "b") {
			t.Errorf("U+%04X refused", r)
		}
	}
	for _, r := range refused {
		if AdmittedText("a" + string(r) + "b") {
			t.Errorf("U+%04X admitted", r)
		}
	}
	if !AdmittedText("") || AdmittedText("a\xffb") {
		t.Error("empty text refused or invalid UTF-8 admitted")
	}
}
```

### 6.2 `internal/llm/prompts/loadfs_test.go`
```go
package prompts

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func writePrompt(t *testing.T, root string, system, schemaRaw []byte) {
	t.Helper()
	dir := filepath.Join(root, fixtureID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{"system.txt": system, "schema.json": schemaRaw} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func wantInvalid(t *testing.T, fsys fs.FS, id string) {
	t.Helper()
	p, err := LoadFS(fsys, id)
	if !errors.Is(err, ErrInvalidPrompt) || p.Schema != nil || p.Hash != "" {
		t.Fatalf("LoadFS = %+v, %v; want ErrInvalidPrompt", p, err)
	}
}

// TestLoadFSRejectsLinks: a link is never followed, file or directory (D5).
func TestLoadFSRejectsLinks(t *testing.T) {
	system, schemaRaw := fixtureFiles(t)
	outside := t.TempDir()
	writePrompt(t, outside, system, schemaRaw)
	mustLoad(t, os.DirFS(outside), fixtureID) // witness: the targets are valid
	link := func(t *testing.T, target, name string) {
		t.Helper()
		if err := os.Symlink(target, name); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("linked directory", func(t *testing.T) {
		root := t.TempDir()
		link(t, filepath.Join(outside, fixtureID), filepath.Join(root, fixtureID))
		wantInvalid(t, os.DirFS(root), fixtureID)
	})
	for _, name := range []string{"system.txt", "schema.json"} {
		t.Run("linked "+name, func(t *testing.T) {
			root := t.TempDir()
			writePrompt(t, root, system, schemaRaw)
			p := filepath.Join(root, fixtureID, name)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			link(t, filepath.Join(outside, fixtureID, name), p)
			wantInvalid(t, os.DirFS(root), fixtureID)
		})
	}
}

// sizedFS serves m, declares size for name and counts the bytes read from it.
type sizedFS struct {
	m    fstest.MapFS
	name string
	size int64
	read *int
}

func (s sizedFS) Open(name string) (fs.File, error) {
	f, err := s.m.Open(name)
	if err != nil || name != s.name {
		return f, err
	}
	return countingFile{File: f, read: s.read}, nil
}

func (s sizedFS) Lstat(name string) (fs.FileInfo, error) {
	fi, err := s.m.Lstat(name)
	if err != nil || name != s.name {
		return fi, err
	}
	return sizedInfo{FileInfo: fi, size: s.size}, nil
}

func (s sizedFS) ReadLink(name string) (string, error) { return s.m.ReadLink(name) }

type sizedInfo struct {
	fs.FileInfo
	size int64
}

func (i sizedInfo) Size() int64 { return i.size }

type countingFile struct {
	fs.File
	read *int
}

func (f countingFile) Read(p []byte) (int, error) {
	n, err := f.File.Read(p)
	*f.read += n
	return n, err
}

// TestLoadFSBoundedRead: declared size checked before opening, bytes read bounded (D5).
func TestLoadFSBoundedRead(t *testing.T) {
	small := []byte("text\n")
	cases := []struct {
		name, file string
		data       []byte
		declared   int64
		maxRead    int
	}{
		{"system longer than declared", "system.txt", []byte(strings.Repeat("a", MaxSystemBytes+10)), 10, MaxSystemBytes + 1},
		{"system declared too large", "system.txt", small, MaxSystemBytes + 1, 0},
		{"schema longer than declared", "schema.json", []byte(strings.Repeat(" ", 3<<16)), 10, 64<<10 + 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := promptFS("p.v1", small, []byte(smallSchema))
			m["p.v1/"+c.file] = &fstest.MapFile{Data: c.data}
			read := 0
			wantInvalid(t, sizedFS{m: m, name: "p.v1/" + c.file, size: c.declared, read: &read}, "p.v1")
			if read > c.maxRead {
				t.Errorf("%d bytes read, want at most %d", read, c.maxRead)
			}
		})
	}
	read := 0
	m := promptFS("p.v1", small, []byte(smallSchema))
	mustLoad(t, sizedFS{m: m, name: "p.v1/system.txt", size: int64(len(small)), read: &read}, "p.v1")
	if read != len(small) {
		t.Errorf("witness: %d bytes read, want %d", read, len(small))
	}
}

// TestLoadFSNonRegular: only a directory holding two regular files loads (D5).
func TestLoadFSNonRegular(t *testing.T) {
	for _, mode := range []fs.FileMode{fs.ModeDevice, fs.ModeNamedPipe, fs.ModeSocket, fs.ModeIrregular} {
		for _, file := range []string{"system.txt", "schema.json"} {
			m := promptFS("p.v1", []byte("text\n"), []byte(smallSchema))
			m["p.v1/"+file].Mode = mode
			wantInvalid(t, m, "p.v1")
		}
	}
	wantInvalid(t, fstest.MapFS{"p.v1": {Data: []byte("text\n")}}, "p.v1")
}

// TestSystemPromptAdmissionList: the system prompt uses the list of D3.
func TestSystemPromptAdmissionList(t *testing.T) {
	for _, s := range []string{"a\u202eb\n", "a\tb\n", "a\u00a0b\n", "\ufeffa\n", "a\u200bb\n", "a\u2028b\n", "a\x00b\n"} {
		_, err := LoadFS(promptFS("p.v1", []byte(s), []byte(smallSchema)), "p.v1")
		if !errors.Is(err, ErrInvalidPrompt) || strings.ContainsAny(err.Error(), "\u202e\t\u00a0\ufeff\u200b\u2028\x00") {
			t.Errorf("system %q: error %v", s, err)
		}
	}
	mustLoad(t, promptFS("p.v1", []byte("Réponds en français : œ, Ÿ.\n"), []byte(smallSchema)), "p.v1")
}
```

### 6.3 `internal/llm/harden_test.go`
```go
package llm

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/amezianechayer/rempart/internal/llm/domain"
	"github.com/amezianechayer/rempart/internal/llm/prompts"
	"github.com/amezianechayer/rempart/internal/tenancy"
)

func objSchema(props, required string) string {
	return `{"type":"object","additionalProperties":false,"required":[` + required + `],"properties":{` + props + `}}`
}

// TestSecretInSchemasRefused (T44): a secret in any static schema text is
// refused before any I/O, the schema being strict or not.
func TestSecretInSchemasRefused(t *testing.T) {
	cases := map[string]string{
		"description":       objSchema(`"name":{"type":"string","description":"use `+fakeGitHub()+`"}`, `"name"`),
		"enum":              objSchema(`"name":{"type":"string","enum":["`+fakeAWSKey()+`"]}`, `"name"`),
		"property name":     objSchema(`"`+fakeAWSKey()+`":{"type":"string"}`, `"`+fakeAWSKey()+`"`),
		"root title":        `{"title":"` + fakeAWSSecret() + `","type":"object","additionalProperties":false}`,
		"non strict schema": `{"type":"object","description":"` + fakeGitHub() + `"}`,
	}
	for name, s := range cases {
		t.Run("tool "+name, func(t *testing.T) {
			e := newEnv(t, configK(), policyPA(), stepV())
			tools := []domain.ToolSpec{{Name: "lookup", Description: "Look up a record by name", InputSchema: json.RawMessage(s)}}
			o := withToolsM(tools).run(e.c, ctxFor(t, tenantA), call0(t))
			assertNoIO(t, e, o, ErrSecretInPrompt)
			if strings.Contains(o.err.Error(), "EXAMPLE") || strings.Contains(o.err.Error(), "FAKE") {
				t.Errorf("error %q echoes the secret", o.err)
			}
		})
	}
	const id = "test.schemaleak.v1"
	pfs := promptFS()
	pfs[id+"/system.txt"] = &fstest.MapFile{Data: []byte("Reply with a JSON greeting.\n")}
	pfs[id+"/schema.json"] = &fstest.MapFile{Data: []byte(objSchema(`"greeting":{"type":"string","description":"`+fakeGitHub()+`"}`, `"greeting"`))}
	p, err := prompts.LoadFS(pfs, id)
	if err != nil {
		t.Fatalf("witness: the leaky prompt must load: %v", err)
	}
	for _, m := range bothMethods() {
		t.Run("prompt schema, "+m.name, func(t *testing.T) {
			f := newFake(t, stepV())
			rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: policyPA()})
			c, err := NewClient(f, rr, pfs, configK())
			if err != nil {
				t.Fatal(err)
			}
			call := call0(t)
			call.PromptID, call.PromptHash = id, p.Hash
			assertNoIO(t, env{fake: f, rr: rr, c: c}, m.run(c, ctxFor(t, tenantA), call), ErrSecretInPrompt)
		})
	}
}

// toolSpy answers V and keeps the tool slice as received; during runs first.
type toolSpy struct {
	during func()
	got    []domain.ToolSpec
}

func (s *toolSpy) Structured(context.Context, domain.Route, domain.Request) (domain.Response, error) {
	return domain.Response{}, errors.New("unused")
}

func (s *toolSpy) WithTools(_ context.Context, route domain.Route, _ domain.Request, tools []domain.ToolSpec) (domain.Response, error) {
	s.during()
	s.got = tools
	return domain.Response{Output: append(json.RawMessage(nil), valueV...), Model: route.Model, RequestID: "spy"}, nil
}

func (s *toolSpy) Capabilities(domain.Route) domain.Capabilities { return domain.Capabilities{} }

// TestToolsCopiedBeforeCheck (D7): the provider receives the checked copy.
func TestToolsCopiedBeforeCheck(t *testing.T) {
	tools := []domain.ToolSpec{toolT()}
	spy := &toolSpy{during: func() {
		for i := range tools[0].InputSchema {
			tools[0].InputSchema[i] = ' '
		}
		tools[0].Name, tools[0].Description = "other", "changed"
	}}
	rr := countingStatic(t, map[tenancy.ID]domain.TenantPolicy{tenantA: policyPA()})
	c := mustClient(t, spy, rr, configK())
	if _, _, err := c.WithTools(ctxFor(t, tenantA), call0(t), tools); err != nil {
		t.Fatalf("WithTools: %v", err)
	}
	if !reflect.DeepEqual(spy.got, []domain.ToolSpec{toolT()}) {
		t.Errorf("provider saw %+v, want the checked copy of [T]", spy.got)
	}
}

// TestRedactedTextBounded (D8): masks cannot push the text over 1 MiB.
func TestRedactedTextBounded(t *testing.T) {
	text := strings.Repeat(fakeAWSKey()+" ", 49_000)
	if len(text) > MaxRequestTextBytes {
		t.Fatal("fixture over the bound before redaction")
	}
	for _, m := range bothMethods() {
		t.Run(m.name, func(t *testing.T) {
			e := newEnv(t, configK(), policyPA(), stepV())
			call := call0(t)
			call.Messages = []domain.Message{userText(text)}
			assertNoCall(t, e, m.run(e.c, ctxFor(t, tenantA), call), ErrRequestTooLarge)
		})
	}
	e := newEnv(t, configK(), policyPA(), stepV())
	call := call0(t)
	call.Messages = []domain.Message{userText(strings.Repeat("a", len(text)))}
	assertOK(t, structuredM().run(e.c, ctxFor(t, tenantA), call)) // witness
}
```

## 7. Critères d'acceptation

`BASE` : commit consigné en section 0 avant la phase tests.

1. `go test ./internal/llm/... -run 'TestStrictClosedForms|TestSchemaAdmissionList|TestAdmittedText|TestLoadFSRejectsLinks|TestLoadFSBoundedRead|TestLoadFSNonRegular|TestSystemPromptAdmissionList|TestSecretInSchemasRefused|TestToolsCopiedBeforeCheck|TestRedactedTextBounded' -v 2>&1 | grep -c '^--- PASS'` : `10` ; avec `grep -c -- '--- FAIL'` : `0`.
2. `go test -race -count=1 ./internal/llm/...` : toutes les lignes commencent par `ok`.
3. `git diff --quiet BASE -- internal/llm/schema/compile_test.go internal/llm/schema/validate_test.go internal/llm/prompts/registry_test.go internal/llm/prompts/testdata internal/llm/client_test.go internal/llm/helpers_test.go internal/llm/route_test.go; echo rc=$?` : `rc=0`.
4. `git diff --name-only BASE -- internal/ cmd/ | grep -vxE 'internal/llm/schema/(admit|strict|schema|strict_test)\.go|internal/llm/prompts/(registry|loadfs_test)\.go|internal/llm/(check|client|harden_test)\.go' | wc -l` : `0`.
5. `grep -rnE '//[[:space:]]*(nolint|#nosec)' --include='*.go' internal/llm | wc -l` : `0` ; `grep -rnP '[\x{200B}-\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]' internal/llm docs/plans/M0-demo-prep.md | wc -l` : `0`.
6. `go test ./internal/archtest/ -run TestRepositoryConforms` : `ok`.
7. `make verify-quick; echo rc=$?` : `rc=0`.
8. Chaque mutation de la section 8, seule, sur copie : `go test ./internal/llm/...` rend `FAIL` (23 sur 23).

## 8. Mutations

| # | Mutation | Test qui échoue |
|---|---|---|
| M1 | `node` : boucle des mots-clés supprimée | ClosedForms |
| M2 | `"properties"` ajouté à `forms["string"]` | ClosedForms (string with properties) |
| M3 | `"items"` ajouté à `forms["object"]` | ClosedForms (object with items) |
| M4 | `formOf` : `case len(keys) > 1` supprimé | ClosedForms (type and anyOf) |
| M5 | contrôle `propName` supprimé | ClosedForms (property name with dash) |
| M6 | contrôle `defName` supprimé | ClosedForms (definition name with dash) |
| M7 | `case "anyOf", "oneOf"` retiré de `node` | ClosedForms (sibling inside anyOf) |
| M8 | `formOf` : `enum` et `const` cherchés avant `type` | ClosedForms (string enum annotated) |
| M9 | appel `admittedDoc` supprimé | SchemaAdmissionList |
| M10 | `admittedDoc` : `!AdmittedText(k) \|\|` retiré | SchemaAdmissionList (clé dans un `enum`) |
| M11 | `r == '\t'` admis | AdmittedText |
| M12 | `&& r != 0xD7` retiré | AdmittedText |
| M13 | borne `0xC0` remplacée par `0xA0` | AdmittedText |
| M14 | cas `AdmittedText` retiré de `checkSystem` | SystemPromptAdmissionList |
| M15 | `fs.Lstat` remplacé par `fs.Stat` | LoadFSRejectsLinks |
| M16 | `entry(fsys, id, true)` supprimé | LoadFSRejectsLinks (linked directory), LoadFSNonRegular |
| M17 | contrôle `fi.Size() > int64(limit)` supprimé | LoadFSBoundedRead (declared too large) |
| M18 | `io.ReadAll(f)` sans `LimitReader` | LoadFSBoundedRead |
| M19 | `!fi.Mode().IsRegular()` remplacé par `fi.IsDir()` | LoadFSNonRegular |
| M20 | `ContainsSecret(string(t.InputSchema))` retiré | SecretInSchemasRefused (tool) |
| M21 | contrôle de `p.Schema.Raw()` retiré | SecretInSchemasRefused (prompt schema) |
| M22 | `bytes.Clone` retiré, ou `tools` passé au lieu de `checked` | ToolsCopiedBeforeCheck |
| M23 | S12b retiré, ou calculé sur `call.Messages` | RedactedTextBounded |

## 9. Modèle de menace (mise à jour par l'agent principal)

- **T43** : mitigation complétée par D1 à D5 (7 tests de 6.1 et 6.2) ; résidu : FS non embarqué modifiable entre `Lstat` et `Open`.
- **T44** : soldée pour les schémas (D6, D7) ; résidu : rédacteur (T37, garde de `prompts/M1.md`).
- **T64** étendue ; ligne proposée **T68** : texte statique envoyé au modèle (prompt système, `title`, `description`, `enum`, `pattern`) portant un invisible, un bidi ou un sosie ; mitigation D3 ; résidu : homoglyphes visibles de la liste. Les plans sont contrôlés aussi (critère 5).
- Réserve basse de M0-T11 soldée par D8.

## 10. Points non vérifiés (à lever par `test-author` sur copie avant le gel)

1. Aucun schéma des tests existants n'est signalé par le rédacteur (critère 2).
2. `ContainsSecret` détecte chaque faux de 6.3 en contexte JSON ; un cas qui lui échappe est consigné en V1 pour la refonte M1 et retiré, sans affaiblir D6.
3. `TestRedactedTextBounded` sous `-race` en moins de 10 s.
4. `Lstat` de `fstest.MapFS` et `os.DirFS` (lu : `src/testing/fstest/mapfs.go` l. 170 à 208 ; `src/os/file.go` l. 823).
5. gofumpt, goimports, golangci-lint v2 ; échappements recopiés tels quels (critère 5).

## 11. Tâches ordonnées

1. Principal : A3 validé par l'humain ; `BASE` en section 0 ; `rempart-state phase tests`.
2. `test-author` : écrire 6.1 à 6.3 ; sur copie, appliquer la section 5 et lever la section 10 (écarts en V1) ; sur le dépôt, rouge : `undefined: AdmittedText`, assertions en échec dans `prompts` et `llm`.
3. Impl, cycle 1 : `admit.go`, `schema.go`, `strict.go` ; `go test ./internal/llm/schema/` vert.
4. Cycle 2 : `registry.go` ; `go test ./internal/llm/prompts/` vert.
5. Cycle 3 : `check.go`, `client.go` ; `go test -race ./internal/llm/...` vert.
6. `make verify-quick` ; mutations M1 à M23 sur copie.
7. `security-reviewer`, puis `acceptance-verifier` (critères 1 à 8).
8. Principal : `docs/STATUS.md`, modèle de menace, commit `fix(llm): closed schema forms, admission list, bounded prompt loading (M0-T19a)`, `phase free`.

## 12. Cadrage de la tâche suivante : M0-T19b `loops-harden`

`internal/loops` seulement, sans appel JSON nouveau dans un workflow. (a) Bornes dans `RunLoop`, refus `invalid_response` : charge utile et candidat à 64 Kio, 100 findings au plus, champs bornés, pour qu'un `LoopResult` tienne sous 256 Kio (codec M1). (h) Reprise seulement si la cause directe de l'`ActivityError` est une `ApplicationError` rejouable portant un `ProposeFailure` décodable ; cause directe testée par `reflect.TypeOf` (errorlint refuse l'assertion, `nolint` interdit), jamais par `errors.As`, qui atteindrait l'erreur cachée derrière un délai. (i) Tests : délai, panique et annulation du proposeur ; candidat vide après retrait des blancs JSON (`converter.RawValue`) ; échec sans finding à l'itération 1 ; tokens invalides tracés. (m) `ctx.Err()` aussi après un vérificateur réussi. (j) Signal d'approbation admis seulement sous forme canonique (octets égaux, blancs finaux exceptés, à l'objet reconstruit dans l'ordre `approved`, `plan_hash`, `approver`, `signature`, valeurs sans échappement possible) : doublons, casse inexacte, ordre différent et échappements donnent `malformed` (T57). (n) `IgnoredSignal.Approver` devient `DeclaredApprover`. Tests à adapter en phase tests, motif consigné : `TestRunLoopActivityFailureEscalates`, `TestRunLoopBudgetTokens`, `TestRunLoopProposerFailuresCounted`, assistant `ign`. Puis T19c (tests `go/ast` : `TestRunLoopNotRegistered`, `TestAwaitApprovalsNotRegistered`, `TestLoopSpecsAreConstants`, règle `loops-fake-tests-only`) et T19d (démo selon A1, 7 tests, faux fournisseur seulement).

## 13. Décisions humaines requises

1. Valider l'amendement A3 de `docs/plans/M0-overview.md` (M0-T19 devient T19a à T19d ; M0 passe à 22 tâches).
2. Contradiction : la demande cite l'ADR 0001 pour `ContinueAsNew` avant l'attente, mais A1, validé et prioritaire, le retire de T19. Ce plan retient A1 : T19d a 7 tests, `Input` sans `Phase` ni `Loop` (ce qui ferme aussi le démarrage direct en phase d'approbation, T18).
3. D3 limitée à l'ASCII et au français : une autre langue exigera un plan qui l'étende.
4. Avant T20 : `loops-fake-tests-only` interdit au worker le vérificateur factice, même en `-dev` : étiquette de build (ADR, T33), binaire de développement distinct ou vérificateur qui refuse tout.
5. Avant T20 : `-llm=anthropic` est à refuser en M0 (garde de `prompts/M1.md`) sauf décision contraire. T19 n'utilise que le faux fournisseur.
6. T19b : forme canonique du signal d'approbation, plus stricte que D2 de M0-T15, à confirmer avant M4.
