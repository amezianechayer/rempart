# M0-T05 `tenancy` : identifiant de tenant dans le contexte

- Date : 2026-09-23
- Auteur : subagent `architect`
- Statut : proposé à l'agent principal
- Fiche d'origine : `docs/plans/M0-overview.md` section 7 (M0-T05). Ce plan ne l'élargit pas ; les précisions sont listées en section 2.3.
- Décision structurante : ADR 0004 `docs/decisions/0004-identifiant-de-tenant-et-tenant-systeme.md` (statut proposé ; réversible sans coût en M0, acceptation exigée avant la première persistance d'un identifiant en M1).
- Sources lues : `docs/plans/M0-overview.md` (sections 2.2, 2.3, 5.1, 5.2, fiches T05, T08, T11, T16, T17, T20) ; `docs/plans/M0-squelette.md` (section 3) ; `docs/plans/M0-archtest-imports.md` (sections 3.2, 7.6, 7.7, 13) ; `docs/02-THREAT-MODEL.md` (T3, T14, T17, T23) ; ADR 0001 (tenant système, décodage `TenantMismatch`) ; ADR 0003 (RLS `::uuid`) ; skills `go-platform-conventions`, `secrets-and-identity` ; `internal/tenancy/doc.go` ; `internal/archtest/{rules.go,layout_test.go}` ; `.golangci.yml` ; `go.mod` ; `.claude/bin/rempart-state`.
- État de départ : M0-T01 et M0-T02 faites. `internal/tenancy/` ne contient que `doc.go` (suivi par Git). Go 1.27.1, golangci-lint v2.13.2. Harnais **non patché**.

---

## 1. Objectif

Fournir la primitive dont dépendent `llm.Client` (T11), la politique de route (T08), l'enveloppe et le codec (M1) : un identifiant de tenant à forme canonique unique, un tenant système réservé et structurellement distinct des tenants clients, un tenant porté par `context.Context` sous une clé non exportée, et une vérification explicite à chaque frontière (`Require`). Une frontière ne peut ni perdre ni changer silencieusement de tenant (T3).

---

## 2. Périmètre

### 2.1 Dans le périmètre
- `internal/tenancy/tenant.go` : `ID`, `System`, 4 erreurs sentinelles, `ParseID`, `String`, `WithTenant`, `FromContext`, `Require`, helpers non exportés.
- `internal/tenancy/doc.go` : commentaire de paquet mis à jour (il affirme « No code yet »).
- Tests : `internal/tenancy/tenant_test.go`, `internal/tenancy/property_test.go`.
- `go.mod`, `go.sum` : dépendance de test `pgregory.net/rapid` (étape 0, section 3.3).
- `docs/STATUS.md` à la clôture.

### 2.2 Hors périmètre
- RBAC, identités, sessions, authentification (M1 et au-delà, `doc.go` le rappelle).
- Propagateur de tenant Temporal (M0-T18, reporté en M1), sérialisation JSON ou SQL de `ID`, `slog.LogValuer`.
- Génération d'identifiants de tenant (PostgreSQL `gen_random_uuid()` en M1).
- Fonction de changement de tenant (un workflow système qui agit pour un tenant) : si le besoin apparaît en M1, fonction explicite, journalisée, par ADR ; jamais par `WithTenant`.
- Règle archtest « `pgregory.net/rapid` interdit hors tests » : preuve ici par le critère 9 ; règle proposée à la tâche de durcissement d'`internal/archtest` (changer `DefaultRules` exige fixtures et mise à jour de `TestDefaultRules`, hors de cette fiche).
- Cible de fuzzing native (`FuzzParseID`) : la propriété `rapid` contre un oracle indépendant (section 7.3) couvre le besoin ; à réévaluer si `ParseID` se complexifie.

### 2.3 Précisions par rapport à la fiche (sans élargissement)

| # | Point de la fiche | Précision retenue | Raison |
|---|---|---|---|
| P1 | `const System ID = "..."` | `00000000-0000-8000-8000-000000000001` (UUID version 8, variante RFC 9562) | ADR 0004 (S4) : non nul, non max, lisible, hors de l'espace des tenants clients par sa version. |
| P2 | `ParseID` refuse majuscules, accolades, UUID nul | Forme exacte : 36 octets, tirets en 8, 13, 18, 23, hexadécimal minuscule ailleurs ; UUID nul et max refusés explicitement ; hors `System`, version `4` et variante `8`, `9`, `a`, `b` ; aucune normalisation | ADR 0004 (F2) : sortie exacte de `gen_random_uuid()` ; une seule écriture par identifiant, donc `==` sûr. |
| P3 | Erreurs : 3 sentinelles | Ajout de `ErrNilContext` | Convention Go : jamais de contexte nil ; `context.WithValue` panique sur un parent nil, et le paquet n'a pas le droit de paniquer. |
| P4 | `WithTenant(ctx, id)` | Contexte portant déjà `id` : `ctx` renvoyé tel quel ; portant un autre tenant (y compris `System`) : `nil, ErrTenantMismatch`, jamais d'écrasement ; toute erreur renvoie un contexte `nil` | T3 : une frontière ne change jamais silencieusement de tenant. Contexte `nil` en erreur : un appelant qui ignorerait l'erreur échoue immédiatement au lieu de continuer sous un tenant inattendu. |
| P5 | `FromContext` | Revalide la valeur stockée ; type inattendu ou valeur invalide : `ErrInvalidTenant` (échec fermé, jamais `ErrNoTenant`) | La clé est non exportée, mais la revalidation coûte 36 comparaisons et ferme la porte à toute écriture future par le paquet lui-même. |
| P6 | `Require(ctx, want) // ErrNoTenant ou ErrTenantMismatch` | `want` validé **en premier** : invalide (dont `""`) donne `ErrInvalidTenant` quel que soit `ctx` ; puis erreurs de `FromContext` ; puis `ErrTenantMismatch` | La valeur zéro ne doit jamais « correspondre » ; une erreur de programmation (`want` vide) doit être visible même sans tenant dans le contexte. |
| P7 | Messages d'erreur | Sentinelle, éventuellement suivie d'une raison fixe ; jamais l'entrée de `ParseID`, jamais un identifiant de tenant | Entrée non fiable (injection dans les journaux, taille) ; un message d'erreur renvoyé au tenant B ne doit pas révéler l'identifiant de A. |
| P8 | Contexte nil | `WithTenant(nil, id)` : `nil, ErrNilContext` ; `FromContext(nil)` et `Require(nil, want valide)` : erreur qui satisfait à la fois `errors.Is(err, ErrNoTenant)` et `errors.Is(err, ErrNilContext)` | Aucun `panic` ; un appelant qui ne connaît que `ErrNoTenant` traite correctement le cas. |
| P9 | 6 tests nommés | 8 tests témoins ajoutés (section 7) | Chaque décision de P1 à P8 a sa preuve, et chaque garde du code a une mutation qui la fait échouer (section 8.3). |
| P10 | Implémentation | Bibliothèque standard seule (`context`, `errors`, `fmt`) ; pas de `github.com/google/uuid` ni d'expression régulière | `uuid.Parse` accepte majuscules, accolades et `urn:uuid:` : il faudrait le contourner. Une boucle sur 36 octets est plus simple à prouver. |

---

## 3. Conditions d'entrée et contraintes du harnais non patché

### 3.1 Conditions d'entrée
- `python3 .claude/bin/rempart-state show` : `jalon=M0 phase=free`.
- `make verify-quick; echo rc=$?` : `rc=0` sur `HEAD`.
- `git status --porcelain | wc -l` : `0`.
- Accès à `proxy.golang.org` (téléchargement de `pgregory.net/rapid`).

### 3.2 Contraintes (reprises de `docs/plans/M0-archtest-imports.md` section 3.2, appliquées à T05)
1. **Hook Stop** : `make verify-quick` doit être vert à chaque fin de tour de l'agent principal. Les tests rouges rendent `internal/tenancy` non compilable. **Tout le cycle, de `phase tests` au premier `make verify-quick` vert en phase impl, se fait donc dans un seul tour**, délégation à `test-author` comprise, sans question à l'humain entre les phases. La validation humaine de ce plan et de l'ADR 0004 se fait **avant** `phase tests`.
2. **`post_edit_check.py`** lance `go vet ./internal/tenancy` après chaque écriture d'un `.go`. En phase tests, message attendu : `undefined: ParseID` (etc.), informatif, fichier écrit. Tout autre message (import introuvable, erreur de syntaxe) est une mauvaise raison et se corrige avant de continuer. D'où l'étape 0 : sans `pgregory.net/rapid` dans `go.mod`, l'échec serait `no required module provides package pgregory.net/rapid`.
3. **Porte `phase impl`** : `internal/tenancy/` est suivi (`doc.go`), donc chaque nouveau `_test.go` apparaît individuellement (`?? internal/tenancy/tenant_test.go`) ; aucun `git add` nécessaire. La porte lance `go test ./internal/tenancy` sans tag : échec de compilation, passage accepté.
4. **`guard_edit`** : `internal/tenancy/*_test.go` modifiables en phase tests, gelés en impl ; `tenant.go` et `doc.go` interdits en phase tests. Aucun fichier `testdata/` n'est prévu (voir point 6).
5. **Lint des tests** : impossible sur un paquet qui ne compile pas ; parade par copie scratch avec stubs (section 7.6), comme T02.
6. **Fichiers d'échec de `rapid`** : quand une propriété échoue, `rapid` écrit `testdata/rapid/<Test>/*.fail` dans le paquet. Ce serait un fichier non prévu, sous `testdata/` (gelé en impl). Règle : toute exécution ciblée pendant la phase impl passe `-rapid.nofailfile` ; critère 11 en fin de tâche. `make verify-quick` ne passe pas ce drapeau : il n'est lancé qu'une fois les propriétés vertes.

### 3.3 Étape 0 (agent principal, juste après `phase tests`, avant délégation à `test-author`)

Justification de la dépendance (règle de la vue d'ensemble section 2.3) : `pgregory.net/rapid` est la bibliothèque de tests de propriété nommée par le skill `go-platform-conventions` et par la fiche (`TestRoundTrip`). Elle apporte la génération et la **réduction** des contre-exemples, absentes de `testing/quick` (gelé). Elle n'a aucune dépendance (vérifiée ci-dessous), n'est importée que par des `_test.go`, donc n'entre dans aucun binaire livré (critère 9) ni dans l'analyse de `govulncheck` des binaires. Licence MPL-2.0, compatible avec un usage limité aux tests (à consigner dans `docs/STATUS.md`).

```bash
python3 .claude/bin/rempart-state phase tests
go list -m -versions pgregory.net/rapid
V=$(go list -m -versions pgregory.net/rapid | tr ' ' '\n' | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -1)
echo "$V"                                   # dernière version stable, sans suffixe de pré-version ; à consigner
go get "pgregory.net/rapid@$V"
```

**Pas de `go mod tidy` à l'étape 0** : aucun fichier n'importe encore `rapid`, `tidy` la retirerait. `go get` l'inscrit avec `// indirect`, ce qui suffit à la compilation des tests ; le `tidy` de fin d'impl (tâche I5) la rend directe.

Vérifications de l'étape 0 :

| Commande | Résultat attendu |
|---|---|
| `go list -m pgregory.net/rapid` | `pgregory.net/rapid $V` |
| `grep -c 'pgregory.net/rapid' go.mod` | `1` |
| `go mod graph \| grep '^pgregory.net/rapid@' \| grep -vc ' go@'` | `0` (aucune dépendance transitive ; la seule ligne de rapid est son exigence `go@1.23`, exclue, constat du 2026-09-23) |
| `go mod verify` | `all modules verified` |
| `grep -rl 'rapid.nofailfile' "$(go env GOMODCACHE)/pgregory.net/rapid@$V/" \| wc -l` | au moins `1` (drapeau de la section 3.2 point 6 présent dans cette version ; sinon, remplacer partout `-rapid.nofailfile` par un nettoyage explicite et le consigner) |
| `head -3 "$(go env GOMODCACHE)/pgregory.net/rapid@$V/LICENSE"` | mention de la Mozilla Public License 2.0 |
| `git status --porcelain` | ` M go.mod`, ` M go.sum` seulement |

Aucun hook ne bloque ces commandes (Bash, pas d'Edit ; `guard_bash` ne vise ni `go get` ni `go mod`).

---

## 4. Fichiers exacts

| Fichier | Phase | Contenu |
|---|---|---|
| `go.mod`, `go.sum` | étape 0, puis `tidy` en I5 | section 3.3 |
| `internal/tenancy/tenant_test.go` | tests | sections 7.1 et 7.2 |
| `internal/tenancy/property_test.go` | tests | section 7.3 |
| `internal/tenancy/tenant.go` | impl | section 5 |
| `internal/tenancy/doc.go` | impl | section 5.3 |
| `docs/STATUS.md` | clôture | section 13, F3 |

---

## 5. Interfaces

### 5.1 `tenant.go` (code de référence ; les lignes marquées « ancre » sont normatives : les mutations de la section 8.3 les ciblent)

```go
package tenancy

import (
	"context"
	"errors"
	"fmt"
)

// ID identifies a tenant: a canonical UUID of 36 lower-case characters
// (ADR 0004). The zero value is invalid. Build it with ParseID, never by
// converting an unchecked string: WithTenant, FromContext and Require check it
// again.
type ID string

// System is the reserved tenant of system workflows (ADR 0001). It is an
// RFC 9562 version 8 UUID, never assigned to a customer: customer tenants are
// version 4 UUIDs (ADR 0004).
const System ID = "00000000-0000-8000-8000-000000000001"

var (
	ErrNoTenant       = errors.New("tenancy: no tenant in context")
	ErrInvalidTenant  = errors.New("tenancy: invalid tenant id")
	ErrTenantMismatch = errors.New("tenancy: tenant mismatch")
	ErrNilContext     = errors.New("tenancy: nil context")
)

const (
	idLen   = 36
	nilUUID = "00000000-0000-0000-0000-000000000000"
	maxUUID = "ffffffff-ffff-ffff-ffff-ffffffffffff"
)

// ctxKey is the unexported context key: no other package can read or write the
// tenant except through WithTenant and FromContext.
type ctxKey struct{}

// ParseID accepts only the canonical form of ADR 0004 and never normalizes its
// input. The error wraps ErrInvalidTenant with a fixed reason and never quotes s.
func ParseID(s string) (ID, error) {
	if reason := invalidReason(s); reason != "" {
		return "", fmt.Errorf("%w: %s", ErrInvalidTenant, reason)
	}
	return ID(s), nil
}

// String returns the identifier unchanged.
func (id ID) String() string { return string(id) }

func (id ID) valid() bool { return invalidReason(string(id)) == "" }

// invalidReason returns "" for a valid identifier, otherwise a fixed reason.
func invalidReason(s string) string {
	if len(s) != idLen {
		return "length is not 36 bytes"
	}
	for i := range idLen {
		switch c := s[i]; i {
		case 8, 13, 18, 23:
			if c != '-' {
				return "hyphen expected at positions 8, 13, 18 and 23"
			}
		default:
			if !isLowerHex(c) {
				return "not a lower-case hexadecimal digit"
			}
		}
	}
	if s == nilUUID { // ancre M6
		return "nil UUID"
	}
	if s == maxUUID {
		return "max UUID"
	}
	if ID(s) == System { // ancre M7
		return ""
	}
	switch s[14] {
	case '4': // ancre M5
	default:
		return "version is not 4"
	}
	switch s[19] {
	case '8', '9', 'a', 'b':
	default:
		return "variant is not RFC 9562"
	}
	return ""
}

func isLowerHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' // ancre M2
}

// WithTenant returns a child of ctx carrying id. If ctx already carries id, ctx
// itself is returned. A different tenant is never replaced (ErrTenantMismatch):
// acting for another tenant needs a context built from a tenant-free parent.
// On error the returned context is nil.
func WithTenant(ctx context.Context, id ID) (context.Context, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if !id.valid() { // ancre M8
		return nil, ErrInvalidTenant
	}
	cur, err := FromContext(ctx)
	switch {
	case err == nil && cur == id:
		return ctx, nil
	case err == nil:
		return nil, ErrTenantMismatch // ancre M1
	case errors.Is(err, ErrNoTenant):
		return context.WithValue(ctx, ctxKey{}, id), nil
	default:
		return nil, err
	}
}

// FromContext returns the tenant carried by ctx: ErrNoTenant if there is none,
// ErrInvalidTenant if the stored value is not a valid ID.
func FromContext(ctx context.Context) (ID, error) {
	if ctx == nil {
		return "", fmt.Errorf("%w: %w", ErrNoTenant, ErrNilContext)
	}
	v := ctx.Value(ctxKey{})
	if v == nil {
		return "", ErrNoTenant
	}
	id, ok := v.(ID)
	if !ok || !id.valid() { // ancre M4
		return "", ErrInvalidTenant
	}
	return id, nil
}

// Require checks, at a boundary, that ctx carries exactly want. An invalid want
// (including "") is always ErrInvalidTenant, whatever ctx holds.
func Require(ctx context.Context, want ID) error {
	if !want.valid() { // ancre M3
		return ErrInvalidTenant
	}
	got, err := FromContext(ctx)
	if err != nil {
		return err
	}
	if got != want {
		return ErrTenantMismatch
	}
	return nil
}
```

Les commentaires `// ancre Mx` ne font pas partie du code livré : l'agent principal ne les écrit pas ; seules les lignes qu'ils désignent sont normatives, au caractère près (section 8.3). Les commentaires de documentation des erreurs exportées sont libres (une ligne chacune).

Points de lint anticipés : `forcetypeassert` (assertion avec `ok`) ; `errorlint` (`errors.Is`, `%w`) ; `contextcheck` (contexte reçu de l'appelant) ; `staticcheck` SA1029 (clé de type propre, jamais `string`) ; aucune directive `nolint`.

### 5.2 Sémantique résumée

| Appel | Condition | Résultat |
|---|---|---|
| `ParseID(s)` | forme de l'ADR 0004 | `ID(s), nil` |
| `ParseID(s)` | sinon | `"", err` avec `errors.Is(err, ErrInvalidTenant)` ; message sans `s` |
| `WithTenant(ctx, id)` | `ctx == nil` | `nil, ErrNilContext` |
| | `id` invalide (vérifié avant le contenu de `ctx`) | `nil, ErrInvalidTenant` |
| | `ctx` sans tenant | enfant portant `id`, `nil` |
| | `ctx` porte déjà `id` | `ctx` lui-même, `nil` |
| | `ctx` porte un autre tenant | `nil, ErrTenantMismatch` |
| | `ctx` porte une valeur invalide | `nil, ErrInvalidTenant` |
| `FromContext(ctx)` | `ctx == nil` | `"", err` : `ErrNoTenant` et `ErrNilContext` |
| | aucune valeur | `"", ErrNoTenant` |
| | valeur de mauvais type ou invalide | `"", ErrInvalidTenant` |
| `Require(ctx, want)` | `want` invalide | `ErrInvalidTenant` (en premier) |
| | puis erreur de `FromContext` | cette erreur |
| | tenant différent | `ErrTenantMismatch` |

Comparaison par `==` : les identifiants ne sont pas des secrets (pas de comparaison en temps constant) et la forme canonique unique rend l'égalité textuelle exacte.

### 5.3 `doc.go` (impl)

```go
// Package tenancy handles tenant isolation, RBAC and identities.
//
// M0 (docs/plans/M0-tenancy.md, ADR 0004): the tenant identifier ID, the
// reserved System tenant, and the tenant carried by context.Context, checked
// at every boundary with Require. RBAC and identities come in later milestones.
package tenancy
```

La première ligne reste celle qu'exige `TestLayoutMatchesVision` (`Package tenancy `).

---

## 6. Flux de données

```
frontière (handler en M1, activité, méthode de Store, llm.Client en T11)
  entrée non fiable (chaîne) -> ParseID -> ID canonique | ErrInvalidTenant (raison fixe, entrée jamais citée)
  authentification (M1) -> WithTenant(ctx, id) -> ctx enfant, clé ctxKey{} non exportée
       refus : ctx nil, id invalide, autre tenant déjà présent (jamais d'écrasement)
  ... ctx transmis tel quel (WithCancel, WithTimeout, WithoutCancel conservent la valeur) ...
  frontière suivante -> Require(ctx, want) -> nil | ErrInvalidTenant | ErrNoTenant | ErrTenantMismatch
                      -> FromContext(ctx) pour lire le tenant (revalidé)
```

Aucun état global, aucune entrée-sortie, aucun journal émis par le paquet.

---

## 7. Tests (phase tests, subagent `test-author`)

### 7.1 Règles communes
- `package tenancy` (tests internes : `TestFromContextInvalidStoredValue` écrit sous `ctxKey{}`). Imports permis : bibliothèque standard, `pgregory.net/rapid` dans `property_test.go` seulement.
- Tables de cas, sous-tests en `snake_case`, messages en anglais qui nomment le cas ; pas de `t.Skip` ; rien n'est sauté sous `-short`.
- Contextes : `t.Context()` hors `rapid`, `context.Background()` dans les closures `rapid`. Contexte nil : `var nilCtx context.Context` passé en variable (un littéral `nil` déclenche `staticcheck` SA1012). Pas de réaffectation de `ctx` dans une boucle (`fatcontext`) : une variable par cas.
- Assertions d'erreur par `errors.Is` seulement, jamais par comparaison de message, sauf les raisons normatives de la section 7.2 (sous-chaîne).
- Constantes de test (écrites en toutes lettres dans les tests, jamais tirées du code de production) : `tenantA = "3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0d"`, `tenantB = "3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0e"` (diffère de A par le dernier caractère), `systemLiteral = "00000000-0000-8000-8000-000000000001"`.

### 7.2 `tenant_test.go`

**1. `TestParseIDCanonicalOnly`** (fiche) : table ; `V` désigne `tenantA`. Valide : `err == nil` et `id.String() == input`. Invalide : `id == ""`, `errors.Is(err, ErrInvalidTenant)`, et le message contient la raison indiquée quand elle est donnée.

| Sous-test | Entrée | Attendu |
|---|---|---|
| `v4_variant_8` | `3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0d` | valide |
| `v4_variant_9` | `3f2c8a1e-9b4d-4c7a-9e21-5d6f7a8b9c0d` | valide |
| `v4_variant_a` | `3f2c8a1e-9b4d-4c7a-ae21-5d6f7a8b9c0d` | valide |
| `v4_variant_b` | `a1b2c3d4-e5f6-4a7b-b8c9-d0e1f2a3b4c5` | valide |
| `system` | `00000000-0000-8000-8000-000000000001` | valide |
| `empty` | `""` | `length` |
| `uppercase` | `3F2C8A1E-9B4D-4C7A-8E21-5D6F7A8B9C0D` | `hexadecimal` |
| `one_uppercase` | `3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0D` | `hexadecimal` |
| `nil_uuid` | `00000000-0000-0000-0000-000000000000` | `nil UUID` |
| `max_uuid` | `ffffffff-ffff-ffff-ffff-ffffffffffff` | `max UUID` |
| `leading_space` | `" " + V` | `length` |
| `trailing_space` | `V + " "` | `length` |
| `trailing_newline` | `V + "\n"` | `length` |
| `space_instead_of_hyphen` | `3f2c8a1e 9b4d-4c7a-8e21-5d6f7a8b9c0d` | `hyphen` |
| `length_37` | `V + "0"` | `length` |
| `length_35` | `V[:35]` | `length` |
| `braces` | `"{" + V + "}"` | `length` |
| `urn_prefix` | `"urn:uuid:" + V` | `length` |
| `no_hyphens` | `3f2c8a1e9b4d4c7a8e215d6f7a8b9c0d` | `length` |
| `hyphen_misplaced` | `3f2c8a1e9-b4d-4c7a-8e21-5d6f7a8b9c0d` | `hyphen` |
| `underscore` | `3f2c8a1e_9b4d-4c7a-8e21-5d6f7a8b9c0d` | `hyphen` |
| `non_hex_letter` | `3f2c8a1g-9b4d-4c7a-8e21-5d6f7a8b9c0d` | `hexadecimal` |
| `plus_sign` | `3f2c8a1e-9b4d-4c7a-8e21-+d6f7a8b9c0d` | `hexadecimal` |
| `hex_prefix` | `0x2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0d` | `hexadecimal` |
| `nul_byte` | `"3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9c0\x00"` | `hexadecimal` |
| `non_ascii_36_bytes` | `3f2c8a1e-9b4d-4c7a-8e21-5d6f7a8b9cé` (34 octets ASCII puis `é` sur 2 octets) | `hexadecimal` |
| `version_0` | `3f2c8a1e-9b4d-0c7a-8e21-5d6f7a8b9c0d` | `version` |
| `version_1` | `3f2c8a1e-9b4d-1c7a-8e21-5d6f7a8b9c0d` | `version` |
| `version_7` | `01928c3e-5f7a-7b2c-9d4e-6f8091a2b3c4` | `version` |
| `version_8_not_system` | `00000000-0000-8000-8000-000000000002` | `version` |
| `version_f` | `3f2c8a1e-9b4d-fc7a-8e21-5d6f7a8b9c0d` | `version` |
| `variant_ncs` | `3f2c8a1e-9b4d-4c7a-7e21-5d6f7a8b9c0d` | `variant` |
| `variant_microsoft` | `3f2c8a1e-9b4d-4c7a-ce21-5d6f7a8b9c0d` | `variant` |
| `system_other_variant` | `00000000-0000-8000-c000-000000000001` | `version` |

Soit 34 sous-tests (5 valides, 29 invalides). Le test vérifie aussi, avant la table, que chaque entrée est unique.

**2. `TestFromContextWithoutTenant`** (fiche) : pour `context.Background()`, `context.TODO()`, `t.Context()`, un `WithCancel` de `Background`, et un contexte portant `tenantA` sous une clé étrangère `type foreignKey struct{}` : `id == ""`, `errors.Is(err, ErrNoTenant)`, `!errors.Is(err, ErrInvalidTenant)`, `!errors.Is(err, ErrNilContext)`. 5 sous-tests.

**3. `TestWithTenantRejectsInvalid`** (fiche) : ids `""`, majuscules de A, nul, max, `" " + A`, `A + "0"`, version 7 (`01928c3e-5f7a-7b2c-9d4e-6f8091a2b3c4`), `00000000-0000-8000-8000-000000000002` ; sur deux parents : `bare` (sans tenant) et `carrying_a` (portant `tenantA`). Attendu : contexte renvoyé `nil`, `errors.Is(err, ErrInvalidTenant)` (jamais `ErrTenantMismatch`, même sur `carrying_a`) ; le parent est inchangé (`FromContext(parent)` rend toujours `ErrNoTenant` ou `tenantA`). 16 sous-tests `<parent>/<cas>`.

**4. `TestRequireMismatch`** (fiche) :
- `other_tenant` : contexte A, `Require(ctx, B)` : `ErrTenantMismatch` ;
- `same_tenant` : contexte A, `Require(ctx, A)` : `nil` ;
- `client_vs_system` : contexte A, `Require(ctx, System)` : `ErrTenantMismatch` ;
- `system_vs_client` : contexte `System`, `Require(ctx, A)` : `ErrTenantMismatch` ;
- `system_vs_system` : contexte `System`, `Require(ctx, System)` : `nil` ;
- `no_tenant` : contexte nu, `Require(ctx, A)` : `ErrNoTenant` et pas `ErrTenantMismatch` ;
- `derived_context` : `WithCancel` d'un contexte A : `Require(child, A)` `nil`, `Require(child, B)` `ErrTenantMismatch`.

**5. `TestSystemTenantIsValidAndDistinct`** (fiche) : `string(System) == systemLiteral` (valeur figée par l'ADR 0004) ; `ParseID(systemLiteral)` rend `System, nil` ; `len == 36` ; `System[14] == '8'` et `System[19]` dans `89ab` (version 8, variante RFC) ; différent de l'UUID nul et du max ; `System[14] != '4'`, donc hors de l'espace des tenants clients ; `WithTenant(t.Context(), System)` réussit et `Require(ctx, System)` rend `nil` ; `System != ID(tenantA)`.

**6. `TestWithTenantMismatch`** (témoin de P4) :
- `overwrite_refused` : contexte A, `WithTenant(ctx, B)` : contexte `nil`, `ErrTenantMismatch` ; `FromContext(ctx)` rend toujours A ;
- `client_to_system_refused` et `system_to_client_refused` : idem avec `System` ;
- `same_tenant_is_noop` : contexte A, `WithTenant(ctx, A)` renvoie exactement `ctx` (`got == ctx`) et `nil` ;
- `refused_through_derived_contexts` : A puis `WithCancel`, `WithTimeout`, `WithoutCancel`, `WithValue(foreignKey{}, 1)` : chaque `WithTenant(child, B)` rend `ErrTenantMismatch`.

**7. `TestFromContextInvalidStoredValue`** (témoin de P5, écrit sous `ctxKey{}` par `context.WithValue`) : valeurs `ID("")`, `ID("BAD")`, `ID(nilUUID)` écrit en toutes lettres, `ID(strings.ToUpper(tenantA))`, `string(tenantA)` (bon texte, mauvais type), `42`. Pour chacune : `FromContext` rend `"", ErrInvalidTenant` ; `WithTenant(ctx, A)` rend `nil, ErrInvalidTenant` (ni écrasement ni `ErrNoTenant`) ; `Require(ctx, A)` rend `ErrInvalidTenant`. 6 sous-tests.

**8. `TestNilContext`** (témoin de P8), `var nilCtx context.Context` : `WithTenant(nilCtx, A)` : `nil, ErrNilContext` ; `FromContext(nilCtx)` : `""`, erreur qui satisfait `ErrNoTenant` **et** `ErrNilContext` ; `Require(nilCtx, A)` : idem ; `Require(nilCtx, "")` : `ErrInvalidTenant`. Aucun `panic` (un `panic` ferait échouer le test).

**9. `TestRequireInvalidWant`** (témoin de P6) : `want` parmi `""`, majuscules de A, nul, max, `A + " "`, `00000000-0000-8000-8000-000000000002` ; contexte parmi `bare`, `carrying_a`, `carrying_system`. Toujours `ErrInvalidTenant`, jamais `nil`, jamais `ErrTenantMismatch` ni `ErrNoTenant`. 18 sous-tests.

**10. `TestErrorsDoNotEchoInput`** (témoin de P7) :
- `parse_input_not_quoted` : `ParseID("zzzzzzzz-zzzz-4zzz-8zzz-CANARYCANARY")`, `ParseID(strings.Repeat("CANARY", 2000))`, `ParseID("%s%v%d" + tenantA)` : message sans `CANARY`, sans `%s`, sans `tenantA`, longueur inférieure à 128 octets ;
- `mismatch_hides_tenants` : contexte A ; erreurs de `WithTenant(ctx, B)` et de `Require(ctx, B)` : message sans `tenantA` ni `tenantB`, ni leurs 8 premiers caractères.

**11. `TestSentinelErrors`** : les 4 erreurs sont non nulles, deux à deux distinctes au sens d'`errors.Is`, et leur message commence par `tenancy: `.

**12. `TestTenantSurvivesDerivedContexts`** : contexte A, puis `WithCancel`, `WithTimeout(time.Minute)`, `WithoutCancel`, `WithValue(foreignKey{}, 1)`, et l'enfant d'un enfant : `FromContext` rend A pour chacun ; après `cancel()`, la valeur reste lisible (l'annulation ne retire pas le tenant). 5 sous-tests.

### 7.3 `property_test.go` (`pgregory.net/rapid`)

Générateur partagé, **indépendant du code de production** :

```go
// genTenantV4 draws a canonical RFC 9562 version 4 UUID, built by the test itself.
func genTenantV4() *rapid.Generator[string] {
	return rapid.Custom(func(t *rapid.T) string {
		b := rapid.SliceOfN(rapid.Byte(), 16, 16).Draw(t, "bytes")
		b[6] = b[6]&0x0f | 0x40 // version 4
		b[8] = b[8]&0x3f | 0x80 // variant 10xx
		h := hex.EncodeToString(b)
		return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
	})
}
```

**13. `TestRoundTrip`** (fiche) : `rapid.Check` ; `s := genTenantV4().Draw(t, "id")` ; `id, err := ParseID(s)` sans erreur ; `id.String() == s` ; `ParseID(id.String())` rend `id, nil` (propriété de la fiche) ; `WithTenant(context.Background(), id)` puis `FromContext` rend `id` ; `Require(ctx, id)` rend `nil`. Le nombre de cas par défaut (100) tourne dans `make verify-quick` ; le critère 3 en exige 10 000.

**14. `TestParseIDMatchesOracle`** (témoin de P2 sur des entrées arbitraires) : oracle écrit dans le test, `regexp.MustCompile("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")` (en RE2, `$` ne correspond qu'à la fin du texte, jamais avant un saut de ligne final). Entrée tirée par `rapid.OneOf` parmi :
- `rapid.String()` (toute chaîne UTF-8) ;
- `rapid.StringMatching("[0-9a-fA-F{}: -]{30,40}")` (chaînes proches d'un UUID) ;
- une mutation d'un `genTenantV4()` : position `rapid.IntRange(0, 35)`, octet `rapid.Byte()` substitué ;
- `rapid.Just(systemLiteral)`.

Propriété : `want := oracle.MatchString(s) || s == systemLiteral` ; `_, err := ParseID(s)` ; `(err == nil) == want` ; si `err != nil`, `errors.Is(err, ErrInvalidTenant)` ; si `err == nil`, l'identifiant rendu vaut `s` (aucune normalisation).

Récapitulatif : 14 tests de premier niveau, dont les 6 de la fiche (numéros 1 à 5 et 13).

### 7.4 Ordre d'écriture (limite les échecs transitoires de `go vet`)
`tenant_test.go` (tests 1 à 12, constantes, `foreignKey`), puis `property_test.go` (générateur, tests 13 et 14).

### 7.5 Preuve de rouge (fin de phase tests, avant `phase impl`)

| Commande | Résultat attendu |
|---|---|
| `test ! -e internal/tenancy/tenant.go; echo rc=$?` | `rc=0` |
| `git diff --quiet internal/tenancy/doc.go; echo rc=$?` | `rc=0` (doc.go intact) |
| `go vet ./internal/tenancy 2>&1 \| grep -c 'undefined: '` | au moins `1` |
| `go vet ./internal/tenancy 2>&1 \| grep -E '\.go:[0-9]+:[0-9]+: ' \| grep -vc 'undefined: '` | `0` (seule raison : symboles à écrire) |
| `go vet ./internal/tenancy 2>&1 \| grep -c 'no required module'` | `0` (étape 0 faite) |
| Section 7.6 (copie scratch avec stubs) : `go vet ./internal/tenancy; echo rc=$?` | `rc=0` |
| Section 7.6 : `golangci-lint run ./internal/tenancy/... 2>&1 \| grep -c '_test\.go:'` | `0` |
| `git status --porcelain \| grep -cE '^\?\? internal/tenancy/(tenant\|property)_test\.go$'` | `2` |
| `git status --porcelain \| grep -vcE '^( M go\.(mod\|sum)\|\?\? internal/tenancy/(tenant\|property)_test\.go)$'` | `0` |
| `python3 .claude/bin/rempart-state phase impl` | `Phase : tests -> impl` |

### 7.6 Copie scratch avec stubs (lint des tests avant gel)

```bash
S=<scratchpad de session>/t05 && rm -rf "$S" && mkdir -p "$S" && cp -a . "$S/r" && cd "$S/r"
# internal/tenancy/stubs.go, écrit dans la copie seulement : toutes les déclarations de la
# section 5.1 (ID, System, 4 erreurs, ctxKey, nilUUID, ParseID, String, valid, WithTenant,
# FromContext, Require) avec des corps minimaux sans panic
go vet ./internal/tenancy; echo rc=$?                                   # attendu rc=0
golangci-lint run ./internal/tenancy/... 2>&1 | grep -c '_test\.go:'   # attendu 0
```

La copie est supprimée ensuite. Aucun fichier de production n'est écrit dans le dépôt en phase tests.

---

## 8. Critères d'acceptation

Depuis la racine du dépôt, phase impl terminée ou phase free. `-count=1` partout.

### 8.1 Critères de la fiche, précisés

| # | Commande | Résultat attendu |
|---|---|---|
| 1 | `go test ./internal/tenancy/... -count=1 -v -rapid.nofailfile 2>&1 \| grep -cE '^--- PASS: (TestParseIDCanonicalOnly\|TestFromContextWithoutTenant\|TestWithTenantRejectsInvalid\|TestRoundTrip\|TestRequireMismatch\|TestSystemTenantIsValidAndDistinct) '` | `6` |
| 1 bis | même commande, `\| grep -cE '^--- PASS: Test'` puis `\| grep -cE -- '--- (FAIL\|SKIP)'` | `14` puis `0` |
| 2 | `make verify-quick; echo rc=$?` | dernière ligne `rc=0` |

### 8.2 Critères complémentaires

| # | Commande | Résultat attendu |
|---|---|---|
| 3 | `go test ./internal/tenancy/ -count=1 -run '^(TestRoundTrip\|TestParseIDMatchesOracle)$' -rapid.checks=10000 -rapid.nofailfile; echo rc=$?` | `rc=0` |
| 4 | `go test ./internal/tenancy/ -count=1 -v -run '^TestParseIDCanonicalOnly$' 2>&1 \| grep -c -- '--- PASS: TestParseIDCanonicalOnly/'` | `34` |
| 5 | `grep -cF 'const System ID = "00000000-0000-8000-8000-000000000001"' internal/tenancy/tenant.go` | `1` |
| 6 | `go list -f '{{range .Imports}}{{.}} {{end}}' ./internal/tenancy` | `context errors fmt ` (bibliothèque standard seule) |
| 7 | `go mod tidy -diff; echo rc=$?` | `rc=0` |
| 8 | `grep -cE 'pgregory\.net/rapid v[0-9]+\.[0-9]+\.[0-9]+$' go.mod` ; `go mod graph \| grep '^pgregory.net/rapid@' \| grep -vc ' go@'` | `1` (dépendance directe, sans `// indirect`) ; `0` (aucune dépendance transitive) |
| 9 | `go list -deps ./... \| grep -c '^pgregory.net/rapid'` | `0` (absente de tout code non test, donc de tout binaire) |
| 10 | `grep -rnE '//[[:space:]]*(nolint\|#nosec)' --include='*.go' . \| wc -l` | `0` |
| 11 | `test ! -e internal/tenancy/testdata; echo rc=$?` | `rc=0` (aucun fichier d'échec `rapid`) |
| 12 | `go test ./internal/archtest/ -count=1; echo rc=$?` | `rc=0` (arborescence, `doc.go`, règles R1 à R5 intacts) |
| 13 | `head -1 internal/tenancy/doc.go` ; `grep -c 'No code yet' internal/tenancy/doc.go` | `// Package tenancy handles tenant isolation, RBAC and identities.` ; `0` |
| 14 | `grep -cE 'panic\(\|context\.WithValue\(ctx, "' internal/tenancy/tenant.go` | `0` |
| 15 | `grep -cE '^var [a-z]\|^var \(' internal/tenancy/tenant.go` puis `awk '/^var \(/,/^\)/' internal/tenancy/tenant.go \| grep -c 'errors.New'` | `1` puis `4` (seul état de paquet : les 4 sentinelles ; commande corrigée le 2026-09-23, `-A5` ne couvrait pas les commentaires d'une ligne permis par la section 5.1) |

### 8.3 Preuves par mutation sur une copie (jamais dans le dépôt)

Chaque mutation part d'une copie neuve et remplace une ancre de la section 5.1 (présente exactement une fois, sinon l'assertion du script échoue et la preuve est invalide) :

```bash
S=<scratchpad de session>/t05m && rm -rf "$S" && mkdir -p "$S" && cp -a . "$S/r" && cd "$S/r"
python3 - "$OLD" "$NEW" <<'EOF'
import pathlib, sys
p = pathlib.Path("internal/tenancy/tenant.go")
s = p.read_text()
old, new = sys.argv[1], sys.argv[2]
assert s.count(old) == 1, "anchor not found exactly once"
p.write_text(s.replace(old, new))
EOF
go test ./internal/tenancy/ -count=1 -rapid.nofailfile 2>&1 | grep -cE -- "--- FAIL: ($EXPECTED)"
```

| # | `OLD` | `NEW` | `EXPECTED` : au moins `1` ligne |
|---|---|---|---|
| M1 | `return nil, ErrTenantMismatch` | `return context.WithValue(ctx, ctxKey{}, id), nil` | `TestWithTenantMismatch` |
| M2 | `return '0' <= c && c <= '9' \|\| 'a' <= c && c <= 'f'` | `return '0' <= c && c <= '9' \|\| 'a' <= c && c <= 'f' \|\| 'A' <= c && c <= 'F'` | `TestParseIDCanonicalOnly\|TestParseIDMatchesOracle` |
| M3 | `if !want.valid() {` | `if false {` | `TestRequireInvalidWant` |
| M4 | `if !ok \|\| !id.valid() {` | `if !ok {` | `TestFromContextInvalidStoredValue` |
| M5 | `case '4':` | `case '1', '4', '7', '8':` | `TestParseIDCanonicalOnly` |
| M6 | `if s == nilUUID {` | `if false {` | `TestParseIDCanonicalOnly` (raison `nil UUID` absente) |
| M7 | `if ID(s) == System {` | `if false {` | `TestSystemTenantIsValidAndDistinct` |
| M8 | `if !id.valid() {` | `if false {` | `TestWithTenantRejectsInvalid` |

Dans le tableau, `\|` est l'échappement Markdown de `|`. Après chaque mutation : la copie est supprimée ; aucune mutation ne touche le dépôt.

---

## 9. Revue sécurité (`security-reviewer`, diff de `internal/tenancy/`, `go.mod`, `go.sum`)

Obligatoire : primitive multi-tenant (T3). Points à vérifier, chacun avec sa preuve :
1. Forme canonique unique, sans normalisation, nul et max refusés, version et variante contrôlées : tests 1 et 14, critères 3 et 4, mutations M2, M5, M6.
2. Tenant système hors de l'espace des tenants clients, valeur figée : test 5, critère 5, M7 ; ADR 0004.
3. Aucun écrasement silencieux de tenant, contexte `nil` en erreur : test 6, M1.
4. Échec fermé sur valeur stockée invalide, `want` invalide, contexte nil : tests 7, 8, 9, M3, M4, M8.
5. Clé de contexte non exportée, aucune lecture par une autre clé : tests 2 et 7, critère 14.
6. Messages d'erreur sans entrée ni identifiant : test 10.
7. Aucun état global hors sentinelles, aucun `panic`, bibliothèque standard seule : critères 6, 14, 15.
8. Dépendance `rapid` : version exacte, sans transitive, absente des binaires : critères 8 et 9 ; licence consignée.

Verdict attendu : PASS. Un BLOCK qui exige de changer un test renvoie en phase tests (retour journalisé).

---

## 10. Spécification de boucle

Sans objet : T05 ne crée aucune boucle. `internal/loops` pourra importer `internal/tenancy` (R4) ; `tenancy` n'est pas un paquet `domain` (R1 ne s'y applique pas, et aucun `domain` ne peut l'importer : un type de domaine qui doit connaître le tenant le reçoit du port qui l'appelle, point à trancher en T08).

---

## 11. Risques

| # | Risque | Atténuation |
|---|---|---|
| K1 | `type ID string` : `tenancy.ID("x")` compile et contourne `ParseID` | Revalidation à chaque frontière (`WithTenant`, `FromContext`, `Require`) ; T08, T11, M1 : tout port qui reçoit un `tenancy.ID` en paramètre le compare au contexte par `Require` ; option T2 de l'ADR 0004 si une fausse valeur franchit une frontière. |
| K2 | Besoin futur de changer de tenant (workflow système qui agit pour un client) contourné par un contexte neuf non tracé | Hors périmètre (section 2.2) : fonction dédiée, journalisée, par ADR ; revue de chaque `context.Background()` ou `context.WithoutCancel` suivi d'un `WithTenant` dans le code de production (grep en revue de M1). |
| K3 | Identifiants de version 7 ou importés refusés | Voulu (ADR 0004) ; élargissement compatible par amendement. |
| K4 | Fichiers d'échec `rapid` écrits sous `testdata/` pendant l'impl | `-rapid.nofailfile` sur toute exécution ciblée ; critère 11. |
| K5 | Lint des tests impossible en phase tests | Copie scratch avec stubs (section 7.6). |
| K6 | Hook Stop : cycle en un seul tour, 3 échecs de `verify-quick` puis BLOCAGE | Incréments courts (section 13), `go test` ciblé après chacun, `make verify-quick` avant de rendre la main. |
| K7 | `go get` impossible (proxy, réseau) | Arrêt avant délégation, retour en phase free, consigné dans `docs/STATUS.md` ; ne jamais remplacer `rapid` par un générateur maison sans décision humaine. |
| K8 | `System` accepté par `ParseID` : une entrée externe pourrait nommer le tenant système | M1 : tenant fixé par l'authentification, jamais lu d'une requête ; refus explicite de `System` aux points d'entrée externes (`TestAPIRejectsSystemTenant`, à créer) ; menace proposée (section 12). |
| K9 | Contexte `nil` renvoyé en erreur : un appelant qui ignore l'erreur provoque un `panic` à l'usage | Voulu (échec bruyant plutôt que tenant inattendu) ; `errcheck` signale l'erreur ignorée hors affectation explicite à `_`. |

---

## 12. Impact sur le modèle de menace (`docs/02-THREAT-MODEL.md`)

- **T3 (accès inter-tenant)** : « tenant dans le contexte ET vérifié aux frontières » devient une API : `WithTenant` refuse tout changement de tenant, `Require` refuse valeur zéro, absence et différence. Preuves : tests 1 à 10, mutations M1 à M8. Les tests d'accès croisé par endpoint et par requête (M1) s'appuieront sur `Require`.
- **T14 (métadonnées en clair)** : identifiant version 4 sans horodatage ; messages d'erreur sans identifiant (test 10).
- **T23 (confusion de tenant par état partagé)** : aucun état global (critère 15), tenant porté par le contexte de chaque appel, forme unique qui empêche deux écritures d'un même tenant (préparation de `rempart.tenant_id::uuid` en M1).
- **ADR 0001** : `System` fournit le « tenant système explicite » ; le codec (M1) pourra appeler `FromContext` et refuser l'encodage sans tenant.
- **Menace nouvelle proposée à `security-reviewer` pour la clôture (H4)**, sans modification du modèle par ce plan : « Usurpation du tenant système » (S, E) : un appelant externe fournit `System` comme tenant, ou un code de production reconstruit un contexte `System` pour agir sur des données client. Atténuations : tenant fixé par l'authentification ; refus de `System` aux points d'entrée externes ; liste figée des workflows système (ADR 0001, M1). Tests : `TestAPIRejectsSystemTenant` (à créer, M1), test d'architecture de la liste des workflows système (M1).
- **ADR** : 0004 (proposé), section « Impact sécurité ».

---

## 13. Tâches ordonnées (un seul tour de l'agent principal, section 3.2)

Avant le tour : validation humaine de ce plan et de l'ADR 0004 (statut « accepté » ou « proposé, accepté pour M0 »).

Phase tests :

| # | Tâche | Qui | Vérification immédiate |
|---|---|---|---|
| A0 | Conditions d'entrée (section 3.1) ; `python3 .claude/bin/rempart-state phase tests` | agent principal | `Phase : free -> tests` |
| A1 | Étape 0 (section 3.3) : version de `rapid`, `go get`, vérifications | agent principal | tableau de la section 3.3 |
| A2 | `tenant_test.go` : constantes, `foreignKey`, tests 1 à 12 | `test-author` | message de `post_edit_check` limité à `undefined:` sur des symboles de la section 5.1 |
| A3 | `property_test.go` : `genTenantV4`, tests 13 et 14 | `test-author` | idem ; aucun `no required module` |
| A4 | Copie scratch avec stubs (section 7.6), preuve de rouge (section 7.5), `phase impl` | `test-author` puis agent principal | tableau 7.5 ; `Phase : tests -> impl` |

Phase impl (dans le même tour, `-rapid.nofailfile` sur chaque `go test` ciblé) :

| # | Incrément | Vérification immédiate |
|---|---|---|
| I1 | `tenant.go` : toutes les déclarations de la section 5.1, corps minimaux (valeurs zéro, sans `panic`) | `go vet ./internal/tenancy; echo rc=$?` : `rc=0` ; `go test ./internal/tenancy/ -count=1 -rapid.nofailfile` échoue sur des assertions, jamais à la compilation |
| I2 | `invalidReason`, `isLowerHex`, `ParseID`, `String`, `valid` | `-run '^(TestParseIDCanonicalOnly\|TestParseIDMatchesOracle\|TestSentinelErrors)$'` : `ok` |
| I3 | `ctxKey`, `FromContext`, `WithTenant`, `Require` | `go test ./internal/tenancy/ -count=1 -rapid.nofailfile` : `ok` ; critères 1, 3, 4 |
| I4 | `doc.go` (section 5.3) | critère 13 ; `go test ./internal/archtest/ -count=1 -run '^TestLayoutMatchesVision$'` : `ok` |
| I5 | `go mod tidy` (rend `rapid` directe), `golangci-lint run ./...`, puis `make verify-quick` | critères 2, 7, 8, 9, 10, 11 ; fin de tour possible |

Clôture :

| # | Étape | Vérification |
|---|---|---|
| F1 | Critères 1 à 15, puis mutations M1 à M8 sur copies | tableaux des sections 8.1 à 8.3 |
| F2 | `security-reviewer` (section 9), puis `acceptance-verifier` (critères 1 à 15, M1 à M8) | verdicts PASS |
| F3 | `docs/STATUS.md` : version exacte de `pgregory.net/rapid` et sa licence (MPL-2.0, tests seulement), précisions P1 à P10, ADR 0004 et son statut, menace proposée (section 12), contraintes pour T08, T11 et M1 (K1, K2, K8) ; note dans la fiche M0-T05 de `docs/plans/M0-overview.md` renvoyant à ce plan pour la valeur de `System` ; `python3 .claude/bin/rempart-state phase free --reason "tâche tenancy terminée"` ; commit `feat(tenancy): canonical tenant id, system tenant and context boundary checks (M0-T05)` | `git status --porcelain \| wc -l` : `0` après commit ; `make verify-quick; echo rc=$?` : `rc=0` |
