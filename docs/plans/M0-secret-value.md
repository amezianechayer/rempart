# M0-T06 `secret-value` : types `secret.Value` et `secret.Bytes`

- Date : 2026-09-23
- Auteur : subagent `architect`
- Statut : proposé à l'agent principal
- Fiche d'origine : `docs/plans/M0-overview.md` section 7 (M0-T06). Ce plan ne l'élargit pas ; les précisions sont listées en section 2.3.
- Décision structurante : **pas d'ADR**. Toutes les décisions de ce plan (sortie constante, refus du décodage, type non comparable, sémantique de `Wipe`) sont locales à un paquet sans consommateur à ce jour, sans format persisté, et réversibles en une tâche. Elles deviennent coûteuses à changer seulement quand l'enveloppe de M1 (ADR 0001) et les configurations de T12 et T20 les utiliseront : c'est l'objet des contraintes de la section 5.6.
- Sources lues : `docs/plans/M0-overview.md` (sections 0, 2.2, 5.1, 5.2, fiches T06, T12, T16, T17, T20, tableau de couverture des menaces) ; `docs/plans/M0-tenancy.md` (modèle de format) ; `docs/plans/M0-archtest-imports.md` (section 3.2) ; `docs/00-VISION.md` (principe 9) ; `docs/02-THREAT-MODEL.md` (T1, T7, T17, T20) ; ADR 0001 (`KeyWrapper` rend des `secret.Bytes`) ; skills `go-platform-conventions`, `secrets-and-identity`, `llm-safety` ; `internal/archtest/rules.go` (R4) ; `internal/secrets/doc.go` ; `.golangci.yml` ; `go.mod` ; `.claude/bin/rempart-state` ; hooks `guard_edit.py`, `post_edit_check.py`, `guard_bash.py` ; `docs/STATUS.md`.
- État de départ : M0-T01, T02 et T05 faites. `internal/secrets/` ne contient que `doc.go` (suivi) ; `internal/secrets/secret/` **n'existe pas**. Go 1.27.1, golangci-lint v2.13.2, `pgregory.net/rapid v1.3.0` déjà en dépendance directe (T05). Harnais **non patché**.

---

## 0. Amendement V1 (vérification 7.8, 2026-09-23, prime sur le reste du document)

La vérification préalable de `test-author` sur une copie contenant le code de référence a trouvé une **fuite réelle** : avec `p *[]byte`, un `Bytes` placé dans un champ non exporté et imprimé par un verbe que `fmt` ne sait pas appliquer à un pointeur (`%s`, `%q`, et tout verbe hors `v b o d x X`) passe par l'impression d'erreur de `fmt`, qui réimprime le pointeur en `%v` au premier niveau et **déréférence un pointeur vers une tranche** : `%!s(*[]uint8=&[70 65 75 ...])`, contenu en décimal. `TestNoLeakThroughUnexportedField/s` et `/q` échouaient. `Value` (`*string`, imprimé comme une adresse) n'est pas touché.

Correctif retenu (section 5.2 mise à jour) : `p **[]byte`. `fmt` n'imprime qu'une adresse pour un pointeur de pointeur, à tout niveau. Les copies partagent le pointeur extérieur, donc `Wipe` (`**b.p = nil`) vide toujours toutes les copies (sémantique P7 inchangée). Lignes d'ancre M12 à M14 adaptées. La ligne « champ non exporté (tous verbes) » de la section 5.3 vaut désormais pour les deux types. Vérifié par `test-author` sur copie : tests, `-rapid.checks=10000`, `go vet`, `golangci-lint`, archtest verts.

Correction de la section 7.7 : `go test` tronque la liste des erreurs (`too many errors`) ; le compte « aucune autre erreur que `undefined:` » se fait avec `go test -gcflags=-e ./internal/secrets/secret/`.

---

## 1. Objectif

Fournir les deux types par lesquels tout secret de Rempart circule dans le code Go : `secret.Value` (chaîne : clé d'API Anthropic en T12, jeton OpenBao en T20) et `secret.Bytes` (octets effaçables : DEK de l'enveloppe de M1, ADR 0001). Aucun canal générique de sortie (`fmt`, `log/slog`, `encoding/json`, `encoding/xml`, `encoding/gob`, `text/template`, `html/template`) n'affiche le contenu, y compris par réflexion sur un champ non exporté (principe 9 ; T1, T7, T20). Un secret ne revient jamais d'une forme sérialisée. `Reveal` est le seul accès au contenu, donc le seul point à relire en revue.

---

## 2. Périmètre

### 2.1 Dans le périmètre
- `internal/secrets/secret/value.go` : commentaire de paquet, `Redacted`, `ErrDecodeRefused`, `Value` et ses méthodes.
- `internal/secrets/secret/bytes.go` : `Bytes` et ses méthodes.
- Tests : `value_test.go`, `encoding_test.go`, `slog_test.go`, `bytes_test.go`, `property_test.go` dans `internal/secrets/secret/`.
- `docs/STATUS.md` à la clôture.

### 2.2 Hors périmètre
- `Equal` en temps constant : aucun consommateur en M0. Le premier besoin (signature de webhook, T25, M4) utilisera `hmac.Equal` ou `crypto/subtle.ConstantTimeCompare` sur `Reveal()` ; une méthode `Equal` sera ajoutée par la tâche qui en a besoin, avec son test. Le type non comparable (P3) empêche d'ici là l'erreur la plus probable (`==`).
- Lecture des secrets depuis une source (environnement en T20, OpenBao en M1) : responsabilité des adaptateurs, qui appellent `New` ou `NewBytes`.
- `driver.Valuer`, `MarshalBinary`, `GobEncode`, `encoding.TextAppender` : non implémentés, volontairement (section 5.3).
- Effacement garanti de la mémoire, `runtime/secret` (expérience du runtime Go annoncée pour Go 1.26 sous `GOEXPERIMENT`, fait à revérifier dans la documentation de Go 1.27) : à évaluer par la tâche de l'enveloppe en M1 (section 5.4).
- Règle archtest « appelants de `Reveal` en liste blanche » : proposée pour M1 (section 12), le critère 15 pose seulement la base (aucun appelant hors du paquet).
- `internal/secrets/doc.go` : inchangé (le paquet `secrets` lui-même reste sans code ; critère 12).

### 2.3 Précisions par rapport à la fiche (sans élargissement)

| # | Point de la fiche | Précision retenue | Raison |
|---|---|---|---|
| P1 | `Format(f fmt.State, verb rune)` | Écrit exactement `Redacted` pour **tout** verbe et tout drapeau ; largeur, précision et index ignorés. `%T` et `%p` ne passent pas par `Format` (traités par `fmt` avant l'interface) : `%T` affiche le nom du type ; `%p` et `%w` hors `Errorf` passent par l'impression d'erreur de `fmt`, qui désactive les méthodes et imprime par réflexion : on obtient une adresse, jamais le contenu (section 5.3). | Sortie indépendante du contenu, prouvable par une propriété (test 12). Honorer `%q` ou la largeur n'apporterait rien et multiplierait les cas. |
| P2 | Valeur zéro | `Value{}` et `Bytes{}` représentent l'absence de secret ; elles s'impriment aussi `Redacted`. `New("")` rend `Value{}` ; `NewBytes(nil)` et `NewBytes([]byte{})` rendent `Bytes{}`. `IsZero` existe sur les deux types (fiche : `Value` seulement) ; `Reveal` rend `""` ou `nil`. | Sortie constante, y compris pour l'absence ; `IsZero` est l'API de présence (validation de configuration, option `omitzero` d'`encoding/json`). Une forme unique de l'absence évite qu'un secret vide soit pris pour un secret présent. |
| P3 | `type Value struct{ p *string }` | Champ supplémentaire `_ [0]func()` en tête : `Value` et `Bytes` **ne sont pas comparables**, `==` et l'usage comme clé de map ne compilent pas. Taille inchangée (champ de taille nulle en tête, sans remplissage). | `==` comparerait des pointeurs : `New("a") == New("a")` serait faux, piège silencieux. Le refus à la compilation est mécanique ; `reflect.DeepEqual` reste possible dans les tests. |
| P4 | Décodage non mentionné | `UnmarshalJSON` et `UnmarshalText` existent (récepteur pointeur) et rendent **toujours** `ErrDecodeRefused`, sans modifier la valeur, pour toute entrée, `null` compris. Aucun secret n'est lu depuis JSON, XML, YAML, un drapeau `flag.TextVar` ou un payload Temporal. | Sans ces méthodes, une chaîne JSON échouerait mais `{}` et `null` rendraient silencieusement un secret vide. Surtout, un aller-retour transformerait un secret en la chaîne `[REDACTED]`, utilisée ensuite comme vrai secret. Le refus rend visible tout secret glissé dans une donnée sérialisée (payload Temporal en clair en M0, amendement A1). |
| P5 | Sérialisations autres que JSON | `MarshalText` rend `Redacted` (sert `encoding/xml` en élément et en attribut, les clés et bibliothèques YAML futures) ; pas de `MarshalBinary` ni de `GobEncode` : `encoding/gob` ignore `MarshalText` et refuse un type sans champ exporté, donc l'encodage échoue (échec fermé). | Tout canal d'encodage aboutit à `Redacted` ou à une erreur, jamais au contenu. |
| P6 | `Bytes.Reveal() // vue à ne pas conserver`, `Wipe() // remet les octets à zéro` | `Reveal` rend une **vue** (même tableau), jamais une copie. `Wipe` met à zéro le tableau (donc toute vue déjà rendue), puis vide l'état partagé : ensuite `Reveal()` rend `nil`, `Len()` rend 0, `IsZero()` rend vrai, pour **toutes les copies** du `Bytes`. Idempotent, sans effet sur la valeur zéro. `NewBytes` copie dans un tableau de capacité exacte et ne touche pas l'entrée. | Une clé effacée ne doit jamais être réutilisable : si `Reveal` rendait 32 octets nuls après `Wipe`, `aes.NewCipher` accepterait une clé nulle (échec ouvert). Une vue vide fait échouer `aes.NewCipher` (taille 0) : échec fermé. Capacité exacte : `Wipe` couvre tout le tableau. |
| P7 | Copies | Les copies d'un `Value` ou d'un `Bytes` partagent le pointeur. Sans conséquence pour `Value` (immuable). Pour `Bytes`, sémantique de référence, comme une tranche : `Wipe` sur une copie efface toutes les autres. Voulu (le cache de DEK de M1 efface à l'éviction, et un utilisateur en retard échoue en fermé), documenté, testé. | Aucune alternative en Go : pas de constructeur de copie ; un marqueur `noCopy` ferait signaler par `copylocks` chaque retour par valeur, dont la signature `GenerateDataKey(...) (secret.Bytes, ...)` de l'ADR 0001. |
| P8 | Concurrence | Lectures concurrentes sûres (`Reveal`, `Len`, `IsZero`, impression, encodage) sur les deux types. `Wipe` concurrent avec toute autre méthode sur un même `Bytes` ou une copie : **course de données**, non synchronisée par le paquet ; le propriétaire sérialise (contrainte pour M1, section 5.6). | Un verrou interne ne protégerait rien : la vue rendue par `Reveal` échappe au verrou. |
| P9 | 7 tests nommés | 7 tests témoins ajoutés (section 7), dont une propriété `rapid` | Chaque décision de P1 à P8 a sa preuve ; chaque ligne d'ancre a une mutation qui la fait échouer (section 8.3). |
| P10 | Fichiers `{value.go,bytes.go}` | Commentaire de paquet dans `value.go` ; pas de `doc.go` | `TestLayoutMatchesVision` n'exige `doc.go` que pour `internal/<domaine>` ; la fiche fixe deux fichiers. |
| P11 | Implémentation | Bibliothèque standard seule : `errors`, `fmt`, `io`, `log/slog`, `runtime`, `strconv` | Aucune dépendance pour un paquet importé partout (R4 le permet depuis `internal/loops`). |

---

## 3. Conditions d'entrée et contraintes du harnais non patché

### 3.1 Conditions d'entrée
- `python3 .claude/bin/rempart-state show` : `jalon=M0 phase=free`.
- `make verify-quick; echo rc=$?` : `rc=0` sur `HEAD`.
- `git status --porcelain | wc -l` : `0`.
- `test ! -e internal/secrets/secret; echo rc=$?` : `rc=0`.
- `grep -c '^require pgregory.net/rapid v1.3.0$' go.mod` : `1` (dépendance déjà directe : **pas d'étape 0**, aucun `go get`).

### 3.2 Contraintes (reprises de `docs/plans/M0-tenancy.md` section 3.2, appliquées à T06)
1. **Hook Stop** : `make verify-quick` doit être vert à chaque fin de tour de l'agent principal. Les tests rouges rendent `internal/secrets/secret` non compilable (et `golangci-lint` échoue dessus). **Tout le cycle, de `phase tests` au premier `make verify-quick` vert en phase impl, se fait donc dans un seul tour**, délégation à `test-author` comprise, sans question à l'humain entre les phases. La validation humaine de ce plan se fait **avant** `phase tests`.
2. **`post_edit_check.py`** lance `go vet ./internal/secrets/secret` après chaque écriture d'un `.go`. En phase tests, le dossier ne contient que des `_test.go`. Tous les tests sont en `package secret` (tests internes) : un paquet externe `secret_test` échouerait sur l'import d'un paquet sans fichier non test, mauvaise raison. Message attendu : `undefined: New`, `undefined: Value`, etc., informatif, fichier écrit. Si `go vet` répond seulement `no non-test Go files`, c'est aussi informatif ; la preuve de rouge se fait par `go test` (section 7.7), pas par `go vet`. Tout autre message (erreur de syntaxe, import introuvable) est une mauvaise raison et se corrige avant de continuer.
3. **Porte `phase impl`, dossier nouveau : `git add` obligatoire.** `rempart-state` lit `git status --porcelain` sans `-uall`. `internal/secrets/` est suivi (`doc.go`), mais `internal/secrets/secret/` est nouveau et ne contient aucun fichier suivi : Git l'affiche **groupé**, `?? internal/secrets/secret/`, chemin qui ne finit pas par `_test.go`. La porte répondrait `Refusé : aucun test nouveau ou modifié`. Donc, en fin de phase tests et avant `phase impl` : `git add internal/secrets/secret/` (le dossier ne contient alors que les 5 `_test.go`). Les fichiers apparaissent ensuite individuellement (`A  internal/secrets/secret/value_test.go`) ; la porte lance `go test ./internal/secrets/secret` sans tag : échec de compilation, passage accepté. Une fois des fichiers indexés dans le dossier, `value.go` et `bytes.go` apparaîtront individuellement (`?? internal/secrets/secret/value.go`) ; aucun autre `git add` n'est requis avant le commit de clôture. Précédent : M0-T01 (`docs/STATUS.md`, « `git add` des tests avant `phase impl` »). `guard_bash` ne vise pas `git add`.
4. **`guard_edit`** : `internal/secrets/secret/*_test.go` modifiables en phase tests, gelés en impl ; `value.go` et `bytes.go` interdits en phase tests. Aucun fichier `testdata/` n'est prévu (point 6). Le canari des tests contient `FAKE` et ne ressemble à aucun motif de la garde.
5. **Lint des tests et attentes gelées** : `golangci-lint` ne peut pas analyser un paquet qui ne compile pas, et certaines attentes dépendent du comportement exact de la bibliothèque standard de Go 1.27.1 (guillemets du gestionnaire texte de `slog`, `gob`, `xml`, `null` en JSON). Parade : copie scratch avec le **code de référence de la section 5** (section 7.8) ; `go vet`, `golangci-lint` et `go test` doivent y être verts **avant** le gel. Une attente fausse découverte là se corrige en phase tests, sans retour journalisé.
6. **Fichiers d'échec de `rapid`** : toute exécution ciblée pendant la phase impl passe `-rapid.nofailfile` (le paquet importe `rapid`, le drapeau est donc reconnu) ; critère 10 en fin de tâche.

---

## 4. Fichiers exacts

| Fichier | Phase | Contenu |
|---|---|---|
| `internal/secrets/secret/value_test.go` | tests | aides communes, tests 1, 2, 5, 8, 9, 14 |
| `internal/secrets/secret/encoding_test.go` | tests | tests 3, 10, 11 |
| `internal/secrets/secret/slog_test.go` | tests | test 4 |
| `internal/secrets/secret/bytes_test.go` | tests | tests 6, 7, 13 |
| `internal/secrets/secret/property_test.go` | tests | test 12 (`rapid`) |
| `internal/secrets/secret/value.go` | impl | section 5.1 |
| `internal/secrets/secret/bytes.go` | impl | section 5.2 |
| `docs/STATUS.md` | clôture | section 13, F3 |

---

## 5. Interfaces

### 5.1 `value.go` (code de référence ; les lignes marquées « ancre » sont normatives : les mutations de la section 8.3 les ciblent)

```go
// Package secret holds secrets that fmt, log/slog, encoding/json,
// encoding/xml, encoding/gob and text templates never print (principle 9 of
// docs/00-VISION.md). Reveal is the only way to read a secret; a secret is
// never decoded from serialized data.
//
// Memory hygiene is best effort: Go does not guarantee that copies made by the
// runtime or by callers are erased. See Bytes.Wipe.
package secret

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
)

// Redacted is printed and encoded in place of any secret.
const Redacted = "[REDACTED]"

// ErrDecodeRefused is returned by every decoding method of Value and Bytes.
var ErrDecodeRefused = errors.New("secret: decoding a secret from serialized data is refused")

// Value is a secret string. The zero value is the absent secret.
//
// The content sits behind a pointer: printing an unexported Value field by
// reflection shows an address, never the content. Value is not comparable.
type Value struct {
	_ [0]func() // ancre M8
	p *string
}

// New returns a Value holding s. New("") is the zero Value.
func New(s string) Value {
	if s == "" { // ancre M9
		return Value{}
	}
	return Value{p: &s}
}

// Reveal returns the secret, "" for the zero Value. Never log or print it.
func (v Value) Reveal() string {
	if v.p == nil {
		return ""
	}
	return *v.p
}

// IsZero reports whether v holds no secret (used by the json omitzero option).
func (v Value) IsZero() bool { return v.p == nil }

// String returns Redacted.
func (v Value) String() string { return Redacted } // ancre M2

// GoString returns Redacted.
func (v Value) GoString() string { return Redacted } // ancre M3

// Format writes Redacted for every verb, flag, width and precision.
func (v Value) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, Redacted) } // ancre M1

// MarshalJSON returns the JSON string "[REDACTED]".
func (v Value) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(Redacted)), nil } // ancre M4

// MarshalText returns Redacted.
func (v Value) MarshalText() ([]byte, error) { return []byte(Redacted), nil } // ancre M5

// LogValue returns Redacted, resolved by log/slog before any ReplaceAttr.
func (v Value) LogValue() slog.Value { return slog.StringValue(Redacted) } // ancre M6

// UnmarshalJSON always returns ErrDecodeRefused and leaves v unchanged.
func (v *Value) UnmarshalJSON([]byte) error { return ErrDecodeRefused } // ancre M7

// UnmarshalText always returns ErrDecodeRefused and leaves v unchanged.
func (v *Value) UnmarshalText([]byte) error { return ErrDecodeRefused }
```

### 5.2 `bytes.go` (code de référence)

```go
package secret

import (
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"strconv"
)

// Bytes is a secret byte string, such as a data encryption key (ADR 0001).
// The zero value is the absent secret. Copies of a Bytes share its content:
// Wipe on one copy wipes them all. Concurrent reads are safe; Wipe must not
// run concurrently with any other method on the same Bytes or a copy.
type Bytes struct {
	_ [0]func() // ancre M17
	p **[]byte
}

// NewBytes returns a Bytes holding a copy of b with exact capacity. The caller
// still owns b and should clear it. NewBytes(nil) and NewBytes([]byte{}) are
// the zero Bytes.
func NewBytes(b []byte) Bytes {
	if len(b) == 0 { // ancre M16
		return Bytes{}
	}
	c := make([]byte, len(b)) // ancre M15
	copy(c, b)
	pc := &c
	return Bytes{p: &pc} // ancre M14
}

// Reveal returns a view of the secret, not a copy: do not keep it, do not
// append to it, do not convert it to a string. nil for the zero Bytes and
// after Wipe.
func (b Bytes) Reveal() []byte {
	if b.p == nil {
		return nil
	}
	return **b.p
}

// Len returns the length of the secret, 0 after Wipe.
func (b Bytes) Len() int { return len(b.Reveal()) }

// IsZero reports whether b holds no secret, which is the case after Wipe.
func (b Bytes) IsZero() bool { return b.Len() == 0 }

// Wipe overwrites the secret with zeros, including every view returned by
// Reveal, then empties b and all its copies. It is idempotent and a no-op on
// the zero Bytes. Best effort: see the package documentation.
func (b Bytes) Wipe() {
	if b.p == nil {
		return
	}
	s := **b.p
	clear(s)   // ancre M12
	**b.p = nil // ancre M13
	runtime.KeepAlive(s)
}

// String returns Redacted.
func (b Bytes) String() string { return Redacted }

// GoString returns Redacted.
func (b Bytes) GoString() string { return Redacted }

// Format writes Redacted for every verb, flag, width and precision.
func (b Bytes) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, Redacted) } // ancre M10

// MarshalJSON returns the JSON string "[REDACTED]", never base64 content.
func (b Bytes) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(Redacted)), nil } // ancre M11

// MarshalText returns Redacted.
func (b Bytes) MarshalText() ([]byte, error) { return []byte(Redacted), nil }

// LogValue returns Redacted.
func (b Bytes) LogValue() slog.Value { return slog.StringValue(Redacted) }

// UnmarshalJSON always returns ErrDecodeRefused and leaves b unchanged.
func (b *Bytes) UnmarshalJSON([]byte) error { return ErrDecodeRefused }

// UnmarshalText always returns ErrDecodeRefused and leaves b unchanged.
func (b *Bytes) UnmarshalText([]byte) error { return ErrDecodeRefused }
```

Les commentaires `// ancre Mx` ne font pas partie du code livré : l'agent principal ne les écrit pas ; seules les lignes désignées sont normatives, au caractère près (section 8.3). Les récepteurs sont nommés (`v`, `b`) même inutilisés, pour que chaque mutation compile. Les commentaires de documentation sont libres.

Points de lint anticipés : `errcheck` (retour de `io.WriteString` affecté explicitement à `_`) ; `govet stdmethods` (signatures standard de `Format`, `MarshalJSON`, `UnmarshalJSON`) ; `govet printf` (`String` ne rappelle pas `fmt` sur son récepteur, aucune récursion) ; `govet copylocks` (aucun verrou, voir P7) ; aucune directive `nolint`.

### 5.3 Comportement par canal (tranché, avec preuve)

`R` désigne `[REDACTED]`. « Profondeur » : niveau d'imbrication dans l'impression par réflexion de `fmt`.

| Canal | Mécanisme de la bibliothèque standard | Sortie | Test |
|---|---|---|---|
| `fmt`, verbes `%v %+v %#v %s %q %x %X %d` et tout autre, tout drapeau (`+ - # espace 0`), largeur, précision, `*`, index `%[1]v` | `fmt.Formatter` est consulté avant `Stringer` et `GoStringer` | `R` exact | 1, 12 |
| `%T` | traité par `fmt` avant toute méthode | `secret.Value`, `secret.Bytes` (nom du type, pas un secret) | 1 |
| `%p` ; `%w` hors `Errorf` ou sur une non-erreur | impression d'erreur de `fmt` (`%!p(...)`), méthodes désactivées, réflexion | `%!p(secret.Value={[] 0xc...})` : adresse du pointeur interne, jamais le contenu | 1 |
| argument en trop | la liste `%!(EXTRA ...)` passe par les méthodes | `%!(EXTRA secret.Value=[REDACTED])` | 1 |
| `*Value`, `*Bytes` | méthodes à récepteur valeur dans l'ensemble du pointeur | `R` ; pointeur nil : `<nil>` (`fmt` intercepte la panique) | 1, 8 |
| champ exporté, élément de tranche ou de map, interface, `reflect.Value` | à profondeur non nulle, les méthodes sont appelées si la valeur est accessible (`CanInterface`) | `R` | 1 |
| champ **non exporté** (tous verbes, `slog` texte) | non accessible, donc impression par réflexion sans méthode ; le pointeur interne est à profondeur non nulle, `fmt` n'imprime que son adresse | `{[] 0xc000012345}` ; **l'adresse s'affiche, acceptée** : une adresse de tas ne permet rien en Go sûr et ne dit rien du contenu | 2 |
| `String()`, `GoString()` appelés directement ; `panic(v)` | le runtime imprime `String()` d'une valeur de panique | `R` (panique : conséquence, non testée) | 1 |
| `log/slog`, gestionnaires texte et JSON, attribut, `slog.Any`, pointeur, `slog.Group`, `With`, `WithGroup`, `LogAttrs` | `LogValuer` résolu par le gestionnaire **avant** `ReplaceAttr` | chaîne `R` ; un `ReplaceAttr` ne voit que `R` | 4 |
| `slog` : structure contenant un secret (`KindAny`) | texte : `%+v` ; JSON : `json.Marshal` | champ exporté `R` ; non exporté : adresse (texte), absent (JSON) | 2, 4 |
| gestionnaire tiers qui oublie `Resolve` (pont OpenTelemetry en M1) | reçoit le `Value` lui-même, qu'il imprimera par `fmt` ou JSON | `R` (double protection) | par construction |
| `json.Marshal`, `MarshalIndent`, `Encoder` | `json.Marshaler` prioritaire sur `TextMarshaler` | `"[REDACTED]"`, jamais de base64 pour `Bytes` ; `omitzero` omet un secret zéro (`IsZero`) ; `omitempty` sans effet (structure) | 3 |
| structure qui **embarque** un `Value` | méthodes promues : la structure entière devient `R` et refuse le décodage | sûr mais surprenant : embarquement proscrit par convention (risque K5) | 3 |
| `json.Unmarshal`, toute entrée, `null` compris | `json.Unmarshaler` appelé même pour `null` (documentation d'`encoding/json`) | `ErrDecodeRefused`, valeur inchangée | 10 |
| clé de map, `==` | type non comparable | erreur de compilation | 9, critère 14 |
| `encoding/xml`, élément et attribut | `encoding.TextMarshaler` | `<k>[REDACTED]</k>`, `a="[REDACTED]"` | 11 |
| `xml.Unmarshal` | `encoding.TextUnmarshaler` | erreur, valeur inchangée | 10 |
| `encoding/gob` | `gob` n'utilise que `GobEncoder` et `BinaryMarshaler` (le support de `TextMarshaler` est désactivé dans ses sources) et refuse un type sans champ exporté | `Encode` en erreur, flux sans contenu | 11 |
| `text/template`, `html/template` | impression par `fmt` | `R` | 11 |
| `flag.TextVar` | exige `TextUnmarshaler` | refus au `Parse` : un secret n'est jamais lu en argument de commande (visible dans `/proc`) | contrainte T20 (section 5.6) |
| `reflect.DeepEqual`, `go-cmp`, `go-spew`, testify, débogueur, vidage mémoire | réflexion profonde qui suit les pointeurs | **contenu visible : hors garantie** | risques K1, K2 |

### 5.4 Sécurité mémoire : ce qui est garanti et ce qui ne l'est pas

Garanti (testé) : après `Wipe`, le tableau détenu par le `Bytes` et toute vue rendue par `Reveal` contiennent des zéros ; `Reveal` rend `nil` pour toutes les copies ; `NewBytes` ne garde aucun alias de l'entrée.

Non garanti, par nature de Go (documenté dans le commentaire de paquet et consigné dans `docs/STATUS.md`) :
- `Value` n'est pas effaçable : les chaînes Go sont immuables, et la source (environnement, fichier, réponse HTTP) en garde d'autres copies. `Value` protège contre l'**affichage**, pas contre la lecture de la mémoire.
- L'entrée de `NewBytes` reste à la charge de l'appelant (il doit l'effacer) ; toute conversion `string(b.Reveal())`, tout `append` sur une vue, toute copie faite par une bibliothèque (planification de clé d'`crypto/aes`, tampons de `net/http`, piles de goroutines copiées lors de leur croissance) échappe à `Wipe`.
- `runtime.KeepAlive(s)` garde le tableau atteignable jusqu'après `clear` : il empêche qu'il soit libéré avant l'écriture, il ne garantit pas formellement contre une suppression d'écriture par le compilateur (le compilateur Go actuel ne supprime pas ces écritures). `Wipe` est un **effort**, pas une garantie cryptographique : l'atténuation de T17 reste l'absence de vidage mémoire et de `pprof` en production, et un cache de DEK borné.

### 5.5 Copies, égalité, concurrence : résumé

| Question | Réponse |
|---|---|
| `w := v` puis `w.Reveal()` | même contenu ; `Value` est immuable, le partage est sans effet |
| `c := b` puis `b.Wipe()` | `c` est vidé aussi (`Len() == 0`, `Reveal() == nil`) : sémantique de référence, voulue (P7) |
| `NewBytes(in)` deux fois, `Wipe` sur l'un | l'autre est intact (copies indépendantes) |
| `v1 == v2` | ne compile pas (P3) ; comparaison de contenu : `subtle.ConstantTimeCompare` sur `Reveal`, hors périmètre |
| lectures concurrentes | sûres (test 13, sous `-race` au critère 5) |
| `Wipe` concurrent avec une lecture ou un autre `Wipe` | course de données, à la charge du propriétaire (P8) |

### 5.6 Contraintes pour les consommateurs (à reporter dans leurs plans)
- **T12** (`anthropic.Config.APIKey`) : `Reveal` appelé uniquement pour construire l'en-tête d'authentification (`TestAPIKeyOnlyInHeader`).
- **T20** (`Config.BaoToken`, `Config.AnthropicKey`) : secrets lus par `getenv` puis `New`, jamais par un drapeau (`flag.TextVar` est refusé par construction ; un `flag.Func` ou un drapeau chaîne est interdit par revue) ; `TestConfigNeverPrintsSecrets` imprime la configuration par `%+v`, `%#v`, `slog` et JSON.
- **M1, enveloppe (ex-T16)** : `NewBytes` sur le clair rendu par Transit, puis `clear` du tampon source ; `Wipe` à l'éviction du cache, seulement quand aucun utilisateur ne tient le `Bytes` (compteur de références ou copie par usage), sinon course de données (P8) ; un utilisateur en retard après `Wipe` obtient une clé vide et échoue en fermé.
- **Tous** : aucun `secret.Value` ni `secret.Bytes` dans une entrée, une sortie, un signal ou une erreur de workflow Temporal. Le refus du décodage (P4) fait échouer bruyamment tout manquement.

---

## 6. Flux de données

```
source (T20 : getenv ; M1 : réponse Transit décodée)
  -> New(s) / NewBytes(b) puis clear(b) par l'appelant
  -> structures de configuration, retours de KeyWrapper (M1), paramètres de fonctions
       copies : pointeur partagé
       fmt, slog, json, xml, templates -> "[REDACTED]"
       gob -> erreur ; json/xml/text en entrée -> ErrDecodeRefused
  -> point d'usage unique : Reveal() (en-tête HTTP en T12, aes.NewCipher en M1)
  -> fin de vie (Bytes) : Wipe() -> zéros dans le tableau et les vues, Reveal() == nil partout
```

Aucun état global hors la constante `Redacted` et la sentinelle `ErrDecodeRefused`, aucune entrée-sortie, aucun journal émis par le paquet.

---

## 7. Tests (phase tests, subagent `test-author`)

### 7.1 Règles communes
- `package secret` (section 3.2 point 2), mais **API exportée uniquement** : aucun accès au champ `p`, aucun littéral `Value{p: ...}` (critère 9). Imports : bibliothèque standard ; `pgregory.net/rapid` dans `property_test.go` seulement.
- Tables de cas, sous-tests en `snake_case` minuscule, messages en anglais qui nomment le cas ; pas de `t.Skip` ; rien n'est sauté sous `-short`.
- Constante `canary = "FAKE-canary-7d41e9b2"` ; `R` désigne la constante littérale `"[REDACTED]"` écrite dans le test (jamais `Redacted`, sauf dans le test 14 qui compare les deux).
- Aide `leakForms(s string) []string` : `s`, hexadécimal minuscule et majuscule, base64 standard et URL sans remplissage, forme décimale `strings.Trim(fmt.Sprint([]byte(s)), "[]")`. Aide `assertNoLeak(t, out)` : aucune de ces formes n'apparaît dans `out`.
- Sujets : `subjects()` rend deux sujets, `value` (`New(canary)`, type `secret.Value`) et `bytes` (`NewBytes([]byte(canary))`, type `secret.Bytes`), chacun avec la valeur `x any`, son pointeur `px any` et le nom de type attendu par `%T`. Les cas qui exigent un type statique (champ non exporté, `omitzero`, embarquement, décodage) sont écrits par sujet.
- `govet printf` : les chaînes de format des tables sont des champs de structure (`fmt.Sprintf(tc.format, tc.args(x, px)...)`), donc non vérifiées par `vet`, ce qui permet `%w` et l'argument en trop ; les appels à format constant n'utilisent que des combinaisons valides.
- Assertions de type toujours avec `ok` (`forcetypeassert`) ; erreurs d'encodage toujours vérifiées (`errchkjson`, `errcheck`) ; goroutines lancées par `sync.WaitGroup.Go`, `t.Errorf` seulement dans les goroutines (`testinggoroutine`).
- Erreurs comparées par `errors.Is`, sauf `xml` et `gob` où seule la présence d'une erreur et l'absence du canari dans son message sont exigées.

### 7.2 `value_test.go`

**1. `TestValueNeverPrinted`** (fiche) : sous-tests `<sujet>/<cas>`, 34 cas par sujet, 68 sous-tests. Sortie exacte quand « = », sinon règle indiquée ; `assertNoLeak` dans tous les cas.

| # | Cas | Format et arguments | Attendu |
|---|---|---|---|
| 1 | `v` | `%v`, x | = `R` |
| 2 | `plus_v` | `%+v`, x | = `R` |
| 3 | `sharp_v` | `%#v`, x | = `R` |
| 4 | `s` | `%s`, x | = `R` |
| 5 | `q` | `%q`, x | = `R` (sans guillemets, P1) |
| 6 | `x` | `%x`, x | = `R` |
| 7 | `upper_x` | `%X`, x | = `R` |
| 8 | `d` | `%d`, x | = `R` |
| 9 | `sharp_x` | `%#x`, x | = `R` |
| 10 | `space_x` | `% x`, x | = `R` |
| 11 | `width` | `%20v`, x | = `R` |
| 12 | `left_width` | `%-20s\|`, x | = `R\|` |
| 13 | `precision` | `%.3s`, x | = `R` |
| 14 | `zero_pad` | `%020d`, x | = `R` |
| 15 | `star_width` | `%*v`, 12, x | = `R` |
| 16 | `indexed` | `%[1]v %[1]s %[1]q`, x | = `R R R` |
| 17 | `pointer` | `%v\|%+v\|%#v\|%s`, px quatre fois | = `R\|R\|R\|R` |
| 18 | `in_slice` | `%v`, `[]any{x, x}` | = `[R R]` |
| 19 | `in_map` | `%v`, `map[string]any{"k": x}` | = `map[k:R]` |
| 20 | `exported_field` | `%+v`, `struct{ Key any }{x}` | = `{Key:R}` |
| 21 | `exported_field_sharp` | `%#v`, `struct{ Key any }{x}` | contient `Key:[REDACTED]` |
| 22 | `reflect_value` | `%v`, `reflect.ValueOf(x)` | = `R` |
| 23 | `type` | `%T`, x | = nom du type du sujet |
| 24 | `bad_verb_p` | `%p`, x | commence par `%!p(<type>=` |
| 25 | `bad_verb_w` | `%w`, x (`Sprintf`) | commence par `%!w(<type>=` |
| 26 | `extra_arg` | `k`, x | = `k%!(EXTRA <type>=[REDACTED])` |
| 27 | `sprint` | `fmt.Sprint(x)` | = `R` |
| 28 | `sprint_mixed` | `fmt.Sprint("k=", x)` | = `k=R` |
| 29 | `sprintln` | `fmt.Sprintln(x)` | = `R\n` |
| 30 | `fprintln` | `fmt.Fprintln(&buf, "k", x)` | = `k R\n` |
| 31 | `errorf` | `fmt.Errorf("connect: %v", x).Error()` | = `connect: R` |
| 32 | `string_method` | `String()` via `fmt.Stringer` | = `R` |
| 33 | `gostring_method` | `GoString()` via `fmt.GoStringer` | = `R` |
| 34 | `log_value` | `LogValue().String()` via `slog.LogValuer` | = `R` |

Dans le tableau, `\|` est l'échappement Markdown de `|`. Le test vérifie avant la table que les noms de cas sont uniques.

**2. `TestNoLeakThroughUnexportedField`** (fiche) : `type holder struct { name string; key Value; raw Bytes; keyp *Value; rawp *Bytes }`, `name = "visible"`, les quatre secrets construits sur `canary`. 13 sous-tests : `v`, `plus_v`, `sharp_v`, `s`, `x`, `q`, `d` (verbes sur `h`), `pointer_plus_v` (`%+v` sur `&h`), `sprint`, `nested_plus_v` (`%+v` sur `struct{ H holder }{h}`), `slog_text` (`slog.Any("h", h)` via `slog.NewTextHandler`), `slog_json` (idem, `slog.NewJSONHandler`), `json` (`json.Marshal(h)` = `{}`). Pour chacun : `assertNoLeak`. Témoins de non-vacuité : `plus_v` et `slog_text` contiennent `visible` et au moins une adresse (`regexp.MustCompile("0x[0-9a-f]+")`) : la réflexion a bien atteint les champs et n'a imprimé qu'une adresse (décision de la section 5.3).

**5. `TestRevealReturnsValue`** (fiche), 6 sous-tests : `value` (`New(canary).Reveal() == canary`, `IsZero()` faux) ; `value_copy` (copie par affectation, même contenu) ; `value_binary` (`"é\x00\n\t[REDACTED]"` restitué exactement : le contenu `[REDACTED]` n'est pas confondu avec l'absence) ; `bytes` (`bytes.Equal`, `Len() == len(canary)`, `IsZero()` faux) ; `bytes_binary` (les 256 valeurs d'octet) ; `bytes_copy`.

**8. `TestZeroValues`** (témoin de P2), 7 sous-tests :
- `value_zero` : `var v Value` : `IsZero()`, `Reveal() == ""`, `fmt.Sprint(v) == R`, `json.Marshal(v)` rend `"[REDACTED]"`, `LogValue().String() == R` ;
- `value_new_empty` : `New("").IsZero()` vrai ;
- `value_new_space` : `New(" ").IsZero()` faux, `Reveal() == " "` ;
- `bytes_zero` : `var b Bytes` : `IsZero()`, `Len() == 0`, `Reveal() == nil`, `Wipe()` sans panique, `fmt.Sprint(b) == R` ;
- `bytes_new_nil` : `NewBytes(nil)` : `IsZero()`, `Reveal() == nil` ;
- `bytes_new_empty` : `NewBytes([]byte{})` : `IsZero()`, `Reveal() == nil` (et non une tranche vide non nulle) ;
- `nil_pointers` : `fmt.Sprint((*Value)(nil))` et `fmt.Sprint((*Bytes)(nil))` valent `<nil>` ; `json.Marshal((*Value)(nil))` vaut `null`.

**9. `TestNotComparable`** (témoin de P3), 2 sous-tests `value`, `bytes` : `reflect.TypeFor[Value]().Comparable()` et `reflect.TypeFor[Bytes]().Comparable()` sont faux.

**14. `TestSentinelAndConstant`** : `Redacted == "[REDACTED]"` ; `ErrDecodeRefused` non nulle, message commençant par `secret: `, sans `%`.

### 7.3 `encoding_test.go`

**3. `TestJSONRedacts`** (fiche), `<sujet>/<cas>`, 11 cas, 22 sous-tests ; erreur nulle et `assertNoLeak` partout :

| Cas | Entrée | Attendu |
|---|---|---|
| `direct` | `json.Marshal(x)` | = `"[REDACTED]"` |
| `pointer` | `json.Marshal(px)` | = `"[REDACTED]"` |
| `tagged_field` | `struct{ K any \`json:"api_key"\` }{x}` | = `{"api_key":"[REDACTED]"}` |
| `slice` | `[]any{x, x}` | = `["[REDACTED]","[REDACTED]"]` |
| `map_value` | `map[string]any{"k": x}` | = `{"k":"[REDACTED]"}` |
| `indent` | `json.MarshalIndent(struct{ K any }{x}, "", "  ")` | contient `"K": "[REDACTED]"` |
| `encoder` | `json.NewEncoder(&buf)`, `SetEscapeHTML(false)` | = `"[REDACTED]"\n` |
| `unexported_field` | `struct{ k <type> }` | = `{}` |
| `omitzero_zero` | `struct{ K <type> \`json:"k,omitzero"\` }{}` | = `{}` |
| `omitzero_set` | idem avec le secret | = `{"k":"[REDACTED]"}` |
| `embedded` | `struct{ <type>; Name string }{secret, "n"}` | = `"[REDACTED]"` (méthode promue, section 5.3) |

**10. `TestDecodeRefused`** (témoin de P4), `<sujet>/<cas>`, 8 cas, 16 sous-tests ; pour chacun : erreur non nulle, message sans aucune forme du canari, cible toujours zéro (ou inchangée pour `text`) :

| Cas | Entrée | Exigence sur l'erreur |
|---|---|---|
| `json_string_field` | `{"k":"FAKE-canary-7d41e9b2"}` dans `struct{ K <type> \`json:"k"\` }` | `errors.Is(err, ErrDecodeRefused)` |
| `json_redacted_literal` | `{"k":"[REDACTED]"}` | idem (un aller-retour ne fabrique jamais un faux secret) |
| `json_null_field` | `{"k":null}` | idem |
| `json_object_field` | `{"k":{}}` | idem |
| `json_direct` | `"x"` dans `&v` | idem |
| `json_roundtrip` | `json.Marshal` d'une structure contenant le secret, puis `json.Unmarshal` du résultat | idem |
| `text` | `UnmarshalText([]byte(canary))` sur un secret **non zéro** | idem ; `Reveal()` inchangé |
| `xml` | `<h><k>FAKE-canary-7d41e9b2</k></h>` dans `struct{ XMLName xml.Name \`xml:"h"\`; K <type> \`xml:"k"\` }` | `err != nil` |

**11. `TestOtherEncodersRedact`** (témoin de P5), `<sujet>/<cas>`, 6 cas, 12 sous-tests ; `assertNoLeak` partout :
- `marshal_text` : `MarshalText()` via `encoding.TextMarshaler` = `R` ;
- `xml_element` : `xml.Marshal(struct{ XMLName xml.Name \`xml:"h"\`; K any \`xml:"k"\` }{K: x})` contient `<k>[REDACTED]</k>` ;
- `xml_attr` : champ `A <type> \`xml:"a,attr"\`` : contient `a="[REDACTED]"` ;
- `gob` : `gob.NewEncoder(&buf).Encode(struct{ K <type> }{secret})` : `err != nil`, message et `buf` sans forme du canari ;
- `text_template` : `{{.K}} {{printf "%s" .K}} {{printf "%x" .K}}` sur `struct{ K any }{x}` = `R R R` ;
- `html_template` : `{{.K}}` = `R`.

### 7.4 `slog_test.go`

**4. `TestSlogRedacts`** (fiche) : sous-tests `<gestionnaire>/<sujet>/<cas>`, gestionnaires `text` et `json` écrivant dans un `bytes.Buffer`, 10 cas, 40 sous-tests. Pour chacun : la sortie contient `[REDACTED]` et le nom de l'attribut, `assertNoLeak`. Forme de l'attribut `key` : texte `key="?\[REDACTED\]"?` (guillemets selon les règles du gestionnaire), JSON `"key":"\[REDACTED\]"`.

| Cas | Appel |
|---|---|
| `key_value` | `logger.Info("m", "key", x)` |
| `attr_any` | `logger.LogAttrs(ctx, slog.LevelInfo, "m", slog.Any("key", x))` |
| `pointer` | `logger.Info("m", slog.Any("key", px))` |
| `group` | `logger.Info("m", slog.Group("g", slog.Any("key", x)))` : texte `g.key=`, JSON `"g":{"key":"[REDACTED]"}` |
| `with` | `logger.With("key", x).Info("m")` |
| `with_group` | `logger.WithGroup("g").Info("m", "key", x)` |
| `exported_field` | `slog.Any("cfg", struct{ Key any }{x})` : texte `{Key:[REDACTED]}`, JSON `{"Key":"[REDACTED]"}` |
| `slice` | `slog.Any("keys", []any{x, x})` |
| `error_value` | `slog.Any("err", fmt.Errorf("connect: %v", x))` |
| `replace_attr` | gestionnaire avec `ReplaceAttr` qui enregistre `a.Value` pour la clé `key` : valeur enregistrée de genre `slog.KindString` et égale à `R` (le secret est résolu avant `ReplaceAttr`) |

### 7.5 `bytes_test.go`

**6. `TestBytesWipe`** (fiche), 7 sous-tests :
- `zeroes_revealed_view` : `view := b.Reveal()` ; `b.Wipe()` ; `len(view) == len(canary)` et chaque octet de `view` vaut 0 ;
- `reveal_after_wipe_is_empty` : après `Wipe`, `Reveal() == nil`, `Len() == 0`, `IsZero()` ;
- `copies_share_state` : `c := b` ; `b.Wipe()` ; `c.Len() == 0`, `c.Reveal() == nil` (P7) ;
- `idempotent` : deux `Wipe` successifs, sans panique, état vide ;
- `zero_value` : `var z Bytes; z.Wipe()` sans panique, `z.IsZero()` ;
- `independent_secrets` : `b1`, `b2 := NewBytes(in)` deux fois ; `b1.Wipe()` ; `b2.Reveal()` égal à `in` ;
- `redacted_after_wipe` : `fmt.Sprint(b) == R`, `json.Marshal(b)` = `"[REDACTED]"`.

**7. `TestNewBytesCopies`** (fiche), 5 sous-tests :
- `input_mutation_not_seen` : `in := []byte(canary)` ; `b := NewBytes(in)` ; chaque octet de `in` remplacé par `'X'` ; `b.Reveal()` égal à `canary` ;
- `distinct_backing_array` : `&b.Reveal()[0] != &in[0]` ;
- `exact_capacity` : `cap(b.Reveal()) == len(in)` ;
- `input_untouched` : après `NewBytes` puis `b.Wipe()`, `in` vaut toujours `canary` (NewBytes n'efface pas l'entrée, P6) ;
- `subslice_input` : `big := []byte("xx" + canary + "yy")`, `in := big[2:2+len(canary)]` (capacité plus grande que la longueur) ; `b.Reveal()` égal à `canary` et `cap == len(canary)`.

**13. `TestConcurrentReads`** (témoin de P8), sous-tests `value`, `bytes` : 8 goroutines lancées par `wg.Go`, 200 itérations chacune, sur un même secret sans `Wipe` : `Reveal()` égal au canari, `fmt.Sprint == R`, `json.Marshal` = `"[REDACTED]"`, `Len()` (bytes) correct ; erreurs signalées par `t.Errorf`. Utile surtout sous `-race` (critère 5).

### 7.6 `property_test.go` (`pgregory.net/rapid`)

**12. `TestPropertyOutputIndependentOfContent`** (témoin de P1) : `rapid.Check` ; tire `s := rapid.String()`, un verbe parmi `v s q x X d`, un sous-ensemble de drapeaux parmi `+ - # espace 0` (sans répétition), une largeur facultative dans `[1, 40]`, une précision facultative dans `[0, 40]` ; construit `format` = `%` + drapeaux + largeur + `.`précision + verbe. Propriété : `fmt.Sprintf(format, New(s))`, `fmt.Sprintf(format, &v)` et `fmt.Sprintf(format, NewBytes([]byte(s)))` valent exactement `[REDACTED]` ; `json.Marshal(New(s))` et `json.Marshal(NewBytes([]byte(s)))` valent `"[REDACTED]"`. 100 cas par défaut dans `make verify-quick` ; le critère 4 en exige 10 000.

Récapitulatif : 14 tests de premier niveau, dont les 7 de la fiche (numéros 1 à 7).

### 7.7 Preuve de rouge (fin de phase tests, avant `phase impl`)

| Commande | Résultat attendu |
|---|---|
| `test ! -e internal/secrets/secret/value.go && test ! -e internal/secrets/secret/bytes.go; echo rc=$?` | `rc=0` |
| `git diff --quiet internal/secrets/doc.go; echo rc=$?` | `rc=0` |
| `ls internal/secrets/secret \| sort \| tr '\n' ' '` | `bytes_test.go encoding_test.go property_test.go slog_test.go value_test.go ` |
| `go test ./internal/secrets/secret 2>&1 \| grep -c 'undefined: '` | au moins `1` |
| `go test ./internal/secrets/secret 2>&1 \| grep -E '\.go:[0-9]+:[0-9]+: ' \| grep -vc 'undefined: '` | `0` (seule raison : symboles à écrire) |
| Section 7.8 : `go vet`, `golangci-lint`, `go test` sur la copie | verts |
| `git status --porcelain \| grep -c '^?? internal/secrets/secret/$'` | `1` (dossier groupé : la porte ne verrait aucun test) |
| `git add internal/secrets/secret/ && git status --porcelain \| grep -cE '^A  internal/secrets/secret/[a-z_]+_test\.go$'` | `5` |
| `git status --porcelain \| grep -vcE '^A  internal/secrets/secret/[a-z_]+_test\.go$'` | `0` |
| `python3 .claude/bin/rempart-state phase impl` | `Phase : tests -> impl` |

### 7.8 Copie scratch avec le code de référence (lint et attentes, avant gel)

```bash
S=<scratchpad de session>/t06 && rm -rf "$S" && mkdir -p "$S" && cp -a . "$S/r" && cd "$S/r"
# internal/secrets/secret/value.go et bytes.go, écrits dans la copie seulement :
# code des sections 5.1 et 5.2, sans les commentaires d'ancre
go vet ./internal/secrets/secret; echo rc=$?                                      # attendu rc=0
golangci-lint run ./internal/secrets/secret/... 2>&1 | grep -c '_test\.go:'      # attendu 0
go test ./internal/secrets/secret/ -count=1 -rapid.nofailfile; echo rc=$?         # attendu rc=0
```

Si un test échoue sur la copie, l'attente est corrigée en phase tests (comportement réel de Go 1.27.1 constaté et consigné), pas le code de référence, sauf si l'échec révèle une fuite : alors arrêt et retour à l'architecte. La copie est supprimée ensuite ; aucun fichier de production n'est écrit dans le dépôt en phase tests.

---

## 8. Critères d'acceptation

Depuis la racine du dépôt, phase impl terminée ou phase free. `-count=1` partout. `P=./internal/secrets/secret/`.

### 8.1 Critères de la fiche, précisés

| # | Commande | Résultat attendu |
|---|---|---|
| 1 | `go test $P -count=1 -v -rapid.nofailfile 2>&1 \| grep -cE '^--- PASS: (TestValueNeverPrinted\|TestNoLeakThroughUnexportedField\|TestJSONRedacts\|TestSlogRedacts\|TestRevealReturnsValue\|TestBytesWipe\|TestNewBytesCopies) '` | `7` |
| 1 bis | même commande, `\| grep -cE '^--- PASS: Test'` puis `\| grep -cE -- '--- (FAIL\|SKIP)'` | `14` puis `0` |
| 2 | `make verify-quick; echo rc=$?` | dernière ligne `rc=0` |

### 8.2 Critères complémentaires

| # | Commande | Résultat attendu |
|---|---|---|
| 3 | `go test $P -count=1 -v -rapid.nofailfile 2>&1 > "$S/out.txt"` puis, sur ce fichier : `grep -cE -- '--- PASS: TestValueNeverPrinted/(value\|bytes)/[a-z_]+ '` ; `... TestNoLeakThroughUnexportedField/[a-z_]+ '` ; `... TestJSONRedacts/(value\|bytes)/[a-z_]+ '` ; `... TestSlogRedacts/(text\|json)/(value\|bytes)/[a-z_]+ '` ; `... TestDecodeRefused/(value\|bytes)/[a-z_]+ '` ; `... TestOtherEncodersRedact/(value\|bytes)/[a-z_]+ '` | `68` ; `13` ; `22` ; `40` ; `16` ; `12` |
| 4 | `go test $P -count=1 -run '^TestPropertyOutputIndependentOfContent$' -rapid.checks=10000 -rapid.nofailfile; echo rc=$?` | `rc=0` |
| 5 | `CGO_ENABLED=1 go test $P -race -count=1 -run '^(TestConcurrentReads\|TestBytesWipe)$' -rapid.nofailfile; echo rc=$?` | `rc=0`. Si l'environnement n'a pas de compilateur C (`command -v gcc cc clang` vide, message `-race requires cgo`), critère consigné « non applicable ici » dans `docs/STATUS.md` avec la sortie, et repris à T04 (CI) |
| 6 | `go list -f '{{join .Imports " "}}' $P` | `errors fmt io log/slog runtime strconv` |
| 7 | `grep -rnE '//[[:space:]]*(nolint\|#nosec)' --include='*.go' . \| wc -l` | `0` |
| 8 | `cat internal/secrets/secret/{value,bytes}.go \| grep -cE '^var '` ; `cat internal/secrets/secret/{value,bytes}.go \| grep -c 'errors.New'` ; `cat internal/secrets/secret/{value,bytes}.go \| grep -vE '^[[:space:]]*//' \| grep -cE 'panic\(\|"unsafe"\|"reflect"'` | `1` ; `1` ; `0` (commande corrigée le 2026-09-23 : le mot « reflection » d'un commentaire imposé par la section 5.1 était compté) |
| 9 | `grep -nE '\.p\b\|(Value\|Bytes)\{[^}]*\bp:' internal/secrets/secret/*_test.go \| wc -l` | `0` (tests par l'API exportée seulement) |
| 10 | `test ! -e internal/secrets/secret/testdata; echo rc=$?` | `rc=0` |
| 11 | `go test ./internal/archtest/ -count=1; echo rc=$?` | `rc=0` (arborescence et R1 à R5 intacts) |
| 12 | `git diff --quiet HEAD -- internal/secrets/doc.go go.mod go.sum; echo rc=$?` ; `go mod tidy -diff; echo rc=$?` | `rc=0` ; `rc=0` (aucune dépendance nouvelle) |
| 13 | `grep -cF 'const Redacted = "[REDACTED]"' internal/secrets/secret/value.go` | `1` |
| 14 | Sur une copie scratch : fichier `internal/secrets/secret/cmp_probe.go` contenant `package secret` et `func probe() bool { return New("a") == New("b") }` ; `go vet $P 2>&1 \| grep -cE 'invalid operation\|cannot compare'` | au moins `1` (`==` ne compile pas) ; copie supprimée |
| 15 | `grep -rn '\.Reveal()' --include='*.go' . \| grep -v '^\./internal/secrets/secret/' \| wc -l` | `0` (aucun appelant hors du paquet : base de la revue des appelants en T12, T20, M1) |

### 8.3 Preuves par mutation sur une copie (jamais dans le dépôt)

Chaque mutation part d'une copie neuve et remplace une ancre des sections 5.1 et 5.2, présente exactement une fois dans `FILE` (sinon l'assertion échoue et la preuve est invalide) :

```bash
S=<scratchpad de session>/t06m && rm -rf "$S" && mkdir -p "$S" && cp -a . "$S/r" && cd "$S/r"
python3 - "$FILE" "$OLD" "$NEW" <<'EOF'
import pathlib, sys
p = pathlib.Path("internal/secrets/secret") / sys.argv[1]
s = p.read_text()
old, new = sys.argv[2], sys.argv[3]
assert s.count(old) == 1, "anchor not found exactly once"
p.write_text(s.replace(old, new))
EOF
go test ./internal/secrets/secret/ -count=1 -rapid.nofailfile 2>&1 | grep -cE -- "--- FAIL: ($EXPECTED)"
```

| # | `FILE` | `OLD` | `NEW` | `EXPECTED` : au moins `1` ligne |
|---|---|---|---|---|
| M1 | `value.go` | `_, _ = io.WriteString(f, Redacted) }` | `_, _ = io.WriteString(f, v.Reveal()) }` | `TestValueNeverPrinted\|TestPropertyOutputIndependentOfContent` |
| M2 | `value.go` | `func (v Value) String() string { return Redacted }` | `func (v Value) String() string { return v.Reveal() }` | `TestValueNeverPrinted` (`string_method`) |
| M3 | `value.go` | `func (v Value) GoString() string { return Redacted }` | `func (v Value) GoString() string { return v.Reveal() }` | `TestValueNeverPrinted` (`gostring_method`) |
| M4 | `value.go` | `func (v Value) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(Redacted)), nil }` | `func (v Value) MarshalJSON() ([]byte, error) { return []byte(strconv.Quote(v.Reveal())), nil }` | `TestJSONRedacts` |
| M5 | `value.go` | `func (v Value) MarshalText() ([]byte, error) { return []byte(Redacted), nil }` | `func (v Value) MarshalText() ([]byte, error) { return []byte(v.Reveal()), nil }` | `TestOtherEncodersRedact` |
| M6 | `value.go` | `func (v Value) LogValue() slog.Value { return slog.StringValue(Redacted) }` | `func (v Value) LogValue() slog.Value { return slog.StringValue(v.Reveal()) }` | `TestSlogRedacts` |
| M7 | `value.go` | `func (v *Value) UnmarshalJSON([]byte) error { return ErrDecodeRefused }` | `func (v *Value) UnmarshalJSON([]byte) error { return nil }` | `TestDecodeRefused` |
| M8 | `value.go` | `_ [0]func()` | `` (vide) | `TestNotComparable` |
| M9 | `value.go` | `if s == "" {` | `if false {` | `TestZeroValues` (`value_new_empty`) |
| M10 | `bytes.go` | `_, _ = io.WriteString(f, Redacted) }` | `_, _ = io.WriteString(f, string(b.Reveal())) }` | `TestValueNeverPrinted` |
| M11 | `bytes.go` | `return []byte(strconv.Quote(Redacted)), nil }` | `return []byte(strconv.Quote(string(b.Reveal()))), nil }` | `TestJSONRedacts` |
| M12 | `bytes.go` | `clear(s)` | `` (vide) | `TestBytesWipe` (`zeroes_revealed_view`) |
| M13 | `bytes.go` | `**b.p = nil` | `` (vide) (ancre adaptée par V1) | `TestBytesWipe` (`reveal_after_wipe_is_empty`, `copies_share_state`) |
| M14 | `bytes.go` | `pc := &c` | `pc := &b` (ancre adaptée par V1) | `TestNewBytesCopies` |
| M15 | `bytes.go` | `c := make([]byte, len(b))` | `c := make([]byte, len(b), 2*len(b))` | `TestNewBytesCopies` (`exact_capacity`) |
| M16 | `bytes.go` | `if len(b) == 0 {` | `if b == nil {` | `TestZeroValues` (`bytes_new_empty`) |
| M17 | `bytes.go` | `_ [0]func()` | `` (vide) | `TestNotComparable` |

Dans le tableau, `\|` est l'échappement Markdown de `|`. Le script est lancé avec `NEW=''` pour les suppressions ; toutes les mutations compilent (récepteurs nommés, imports toujours utilisés). Après chaque mutation, la copie est supprimée ; aucune mutation ne touche le dépôt.

---

## 9. Revue sécurité (`security-reviewer`, diff de `internal/secrets/secret/`)

Obligatoire : secrets (principe 9 ; T1, T7, T17, T20). Points à vérifier, chacun avec sa preuve :
1. Aucun verbe, drapeau ni chemin de `fmt` n'affiche le contenu, y compris `%p`, `%w`, l'argument en trop, les pointeurs, `reflect.Value` : test 1, propriété 12, critères 3 et 4, mutations M1 à M3, M10.
2. Champ non exporté : seule une adresse s'affiche ; acceptabilité de cette adresse : test 2, section 5.3.
3. `slog` résolu avant `ReplaceAttr`, dans les deux gestionnaires, groupes compris : test 4, M6.
4. JSON, XML, gob, templates : `R` ou erreur, jamais de base64 ni d'hexadécimal du contenu : tests 3 et 11, M4, M5, M11.
5. Décodage refusé partout, `null` compris, sans écho de l'entrée : test 10, M7.
6. `Wipe` : vues effacées, clé vide ensuite (échec fermé), copies vidées ; honnêteté des limites (section 5.4) : tests 6 et 7, M12 à M16.
7. `==` impossible : test 9, critère 14, M8, M17.
8. Bibliothèque standard seule, aucun `unsafe` ni `reflect` dans le code, aucun état global hors la sentinelle : critères 6 et 8.
9. Contraintes pour T12, T20 et M1 (section 5.6) correctes et suffisantes.

Verdict attendu : PASS. Un BLOCK qui exige de changer un test renvoie en phase tests (retour journalisé).

---

## 10. Spécification de boucle

Sans objet : T06 ne crée aucune boucle. `internal/loops` peut importer `internal/secrets/secret` (R4, `internal/archtest/rules.go`) ; ce n'est pas un paquet `domain`, R1 ne s'y applique pas, et aucun `internal/*/domain` ne peut l'importer : un type de domaine ne porte pas de secret, il le reçoit d'un port.

---

## 11. Risques

| # | Risque | Atténuation |
|---|---|---|
| K1 | Réflexion profonde (`reflect.DeepEqual` dans un message d'échec, `go-spew`, testify, `go-cmp` avec `Exporter`) ou débogueur qui suit le pointeur et affiche le contenu, par exemple dans un journal de CI public | Aucune de ces bibliothèques dans `go.mod` (constat du 2026-09-23) ; règle de revue : jamais de diff générique sur une structure qui contient un secret ; fixtures de secrets toujours marquées `FAKE` ou `EXAMPLE` ; menace proposée (section 12). `go-cmp` sans option panique sur un champ non exporté (échec bruyant). |
| K2 | `Reveal()` passé à un journal, à une erreur ou à un prompt | Point unique à relire ; critère 15 comme base ; règle archtest des appelants autorisés proposée pour M1 ; `TestNoSecretInOutgoingRequest` (T12) et le rédacteur (T07) couvrent les prompts. |
| K3 | Croyance que `Wipe` garantit l'effacement | Section 5.4, commentaire de paquet, note dans `docs/STATUS.md` ; T17 reste atténuée par l'exploitation (pas de vidage mémoire, pas de `pprof`). |
| K4 | `Wipe` concurrent d'un usage : course de données, ou clé vide en cours de chiffrement | Documenté (P8) ; contrainte explicite pour le cache de DEK de M1 (section 5.6) ; une clé vide fait échouer `aes.NewCipher` (échec fermé). |
| K5 | Embarquement d'un `Value` dans une structure : méthodes promues, la structure entière s'imprime `R` et refuse le décodage | Sûr (aucune fuite) mais déroutant ; test 3 `embedded` documente ; règle de revue : champ nommé, jamais embarqué. |
| K6 | Attente de test fausse sur un détail de Go 1.27.1 (guillemets de `slog`, `gob`, `xml`, `null` JSON, réimplémentation éventuelle d'`encoding/json` sur la v2) gelée en phase impl | Exécution sur copie avec le code de référence avant le gel (section 7.8) ; attentes robustes (`errors.Is` seulement là où la chaîne d'erreur est garantie). |
| K7 | Hook Stop : cycle en un seul tour, 3 échecs de `verify-quick` puis BLOCAGE | Incréments courts (section 13), `go test` ciblé après chacun, `make verify-quick` avant de rendre la main. |
| K8 | Porte `phase impl` aveugle au dossier nouveau | `git add internal/secrets/secret/` avant `phase impl` (section 3.2 point 3) ; preuve au tableau 7.7. |
| K9 | Adresse de tas visible dans une impression par réflexion | Accepté (section 5.3) : sans valeur pour un attaquant en Go sûr, sans lien avec le contenu. |
| K10 | Un secret vide (`New("")`) pris pour « absent » alors que la source contenait une chaîne vide volontaire | Voulu : un secret vide n'est jamais valide dans Rempart ; les chargeurs de configuration (T20) refusent `IsZero()` pour un secret requis. |

---

## 12. Impact sur le modèle de menace (`docs/02-THREAT-MODEL.md`)

- **Principe 9 et T1** : « pas de secret dans un log, une trace ou un état en clair » devient un type : `fmt`, `slog`, JSON, XML, gob et templates ne peuvent afficher le contenu ; un secret ne revient jamais d'une forme sérialisée, ce qui rend bruyante toute tentative de le mettre dans un payload Temporal (historique en clair en M0, §4.1). Preuves : tests 1 à 4, 10, 11, propriété 12, mutations M1 à M11 ; `TestValueNeverPrinted` et `TestNoLeakThroughUnexportedField` sont les preuves citées pour T1 dans `docs/plans/M0-overview.md` (tableau de couverture).
- **T7** : un `Value` interpolé par `fmt` dans un prompt donne `[REDACTED]` ; les chaînes brutes restent du ressort du rédacteur (T07) et de `TestNoSecretInOutgoingRequest` (T12).
- **T17** : `TestBytesWipe` (vérification citée par la menace) prouve l'effacement du tableau et des vues et l'échec fermé après effacement ; les limites de la section 5.4 sont à ajouter à la colonne « Atténuations » de T17 à la clôture (H4), sans modification du modèle par ce plan.
- **T20** : `TestConfigNeverPrintsSecrets` (T20) reposera sur ces types ; le refus de `flag.TextVar` empêche un secret en argument de commande.
- **Menace nouvelle proposée à `security-reviewer` pour la clôture (H4)**, sans modification du modèle par ce plan : « Contournement du masquage des secrets » (I) : réflexion profonde (`reflect`, `go-spew`, testify, `go-cmp`), débogueur ou vidage mémoire, `Reveal()` journalisé, conversion `string(b.Reveal())` ou copie non effacée. Atténuations : bibliothèques de dump interdites dans `go.mod` (test d'architecture à créer), appelants de `Reveal` en liste blanche par test d'architecture (à créer, M1, avant la première tâche qui manipule un identifiant cloud), revue de chaque appel à `Reveal`, pas de vidage mémoire ni `pprof` en production (T17). Tests : `TestRevealCallersAllowlist` et `TestNoDumpLibraries` (à créer, M1).

---

## 13. Tâches ordonnées (un seul tour de l'agent principal, section 3.2)

Avant le tour : validation humaine de ce plan.

Phase tests :

| # | Tâche | Qui | Vérification immédiate |
|---|---|---|---|
| A0 | Conditions d'entrée (section 3.1) ; `python3 .claude/bin/rempart-state phase tests` | agent principal | `Phase : free -> tests` |
| A1 | `value_test.go` : constantes, `leakForms`, `assertNoLeak`, `subjects`, tests 1, 2, 5, 8, 9, 14 | `test-author` | message de `post_edit_check` limité à `undefined:` (ou `no non-test Go files`) |
| A2 | `encoding_test.go` (tests 3, 10, 11), `slog_test.go` (test 4) | `test-author` | idem |
| A3 | `bytes_test.go` (tests 6, 7, 13), `property_test.go` (test 12) | `test-author` | idem ; aucun `no required module` |
| A4 | Copie scratch avec le code de référence (section 7.8) : `go vet`, `golangci-lint`, `go test` verts ; attentes corrigées si besoin | `test-author` | tableau 7.8 |
| A5 | Preuve de rouge (section 7.7), `git add internal/secrets/secret/`, `phase impl` | agent principal | tableau 7.7 ; `Phase : tests -> impl` |

Phase impl (dans le même tour, `-rapid.nofailfile` sur chaque `go test` ciblé) :

| # | Incrément | Vérification immédiate |
|---|---|---|
| I1 | `value.go` (section 5.1) et `bytes.go` (section 5.2), écrits ensemble : les tests de chaque type utilisent les deux sujets | `go vet ./internal/secrets/secret; echo rc=$?` : `rc=0` ; `go test ./internal/secrets/secret/ -count=1 -rapid.nofailfile` : `ok` ; critères 1, 3, 4 |
| I2 | `golangci-lint run ./...`, puis `make verify-quick` | critères 2, 6 à 13, 15 ; fin de tour possible |

Clôture :

| # | Étape | Vérification |
|---|---|---|
| F1 | Critères 1 à 15 (dont 5 et 14 sur l'environnement et la copie), puis mutations M1 à M17 sur copies | tableaux des sections 8.1 à 8.3 |
| F2 | `security-reviewer` (section 9), puis `acceptance-verifier` (critères 1 à 15, M1 à M17) | verdicts PASS |
| F3 | `docs/STATUS.md` : précisions P1 à P11, limites de la section 5.4, contraintes de la section 5.6 pour T12, T20 et M1, menace proposée (section 12), résultat du critère 5 (ou « non applicable » motivé) ; `python3 .claude/bin/rempart-state phase free --reason "tâche secret-value terminée"` ; commit `feat(secrets): redacting secret.Value and secret.Bytes types (M0-T06)` | `git status --porcelain \| wc -l` : `0` après commit ; `make verify-quick; echo rc=$?` : `rc=0` |
