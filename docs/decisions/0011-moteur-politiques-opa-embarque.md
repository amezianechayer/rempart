# 0011. Moteur de politiques OPA embarqué

- Statut : accepté le 2026-11-19 (décision humaine : « continue » en réponse à la demande d'acceptation, recommandations de l'agent retenues pour les questions 1 à 5)
- Date : 2026-11-19
- Jalon : M2 (étape humaine H0-M2.3), à accepter avant la phase tests de M2-T03 `policy-design`, qui met en oeuvre D1 à D9. M2-T04 consomme D4 (empreinte, `Controls`) ; M2-T05 consomme D5 (entrée) et D8 (`Evaluator`).
- Base : M2-T02 livrée (entrée du 2026-11-19 de `docs/STATUS.md`).
- Sources : `prompts/M2.md` (C1) ; `docs/plans/M2-overview.md` (D4, D5, D11 à D14, section 3.1, fiche M2-T03, section 7 ligne 0011, Q2, T108, T109, T114, risques R1, R3, R7) ; ADR 0010 (D2, D11, D12) ; skills `policy-as-code`, `go-platform-conventions`, `llm-safety` ; `docs/02-THREAT-MODEL.md` (T2, T3, T6, T8, T24) ; code : `internal/graph/{domain,reach}`, `internal/loops/domain/findings.go`, `internal/intent/domain/regions.go`, `internal/archtest/{rules.go,packages.go,loopsrc.go,makefile_test.go,gomod_test.go}`, `Makefile`, `go.mod`, `policies/`.

## Contexte

C1 exige au moins 40 règles de conception évaluées depuis Go. Aucun moteur n'existe : `internal/policy` ne contient que `doc.go`, `policies/{design,iac,k8s,runtime}` que des `.gitkeep` ; `make opa-test` se dit « sans objet » faute de `.rego` et appellerait sinon le binaire désigné par la variable `OPA` (défaut `opa`, figée par `$(value ...)`, T8). La CI n'installe pas `opa` ; la CLI locale est `/usr/local/bin/opa` 1.20.2, hors `go.mod`.

Mesures de l'agent principal (2026-11-19, copie jetable du module, dépôt intact) :
- `github.com/open-policy-agent/opa` v1.22.0 (2026-10-29) requiert `golang.org/x/crypto` v0.58.0, vulnérable (GO-2026-5932, non appelée, correctif seulement en pseudo-version) ; v1.22.4 (2026-11-12, dernière) : `go tool govulncheck ./...` sans vulnérabilité ; `go tool opa version` : 1.22.4.
- Graphe de modules (`go list -m all`) : 127 avant, 197 après bibliothèque et directive `tool` (la CLI tire badger, cobra, prometheus, non liés à nos binaires).
- Binaire qui n'importe que `opa/v1/rego` : 21 modules liés, 31,5 Mo (worker actuel : 27 modules, 35 Mo). Le paquet lie `net/http` (`v1/util`, `internal/gojsonschema`, `internal/providers/aws/v4`, `v1/logging`) et `os/exec` (`internal/compiler/wasm`) ; ni prometheus, ni otel, ni badger, ni gRPC.

Deux faits du code contraignent la section 3.1 du plan :
1. La règle archtest `domain-pure` (R1) interdit à `internal/policy/domain` d'importer `internal/graph/reach` : `DesignInput`, qui porte un `reach.Result`, ne peut pas y vivre.
2. `internal/intent/domain/regions.go` contient déjà une table de zones par nom de région (19 régions, sans cloud, sans source ni date, aucune région OVHcloud), utilisée par `CONTRA-RESIDENCY` en L1. Une seconde table divergerait (T114).

Ces choix sont difficiles à inverser : dépendance lourde dans le binaire du worker (T6) ; format des métadonnées et forme des sorties fixés par 45 règles et leurs tests ; empreinte du pack dans le modèle de menace (ADR 0010 D11) ; sens de `fr`, `eu`, `non_eu` repris par L1, L3, L6 et les preuves. Contraintes : aucune décision de sécurité par un LLM (le moteur ne lit ni ne produit de texte de modèle) ; entrée sans texte libre (T2, T111) ; calcul borné (T24, T112) ; échec fermé (une erreur n'est jamais une liste vide).

## Options envisagées

### Question 1 : forme du moteur
1. **(1a) Bibliothèque `opa/v1/rego` épinglée, CLI par `go tool opa` de même version (retenue).** Un seul `require` fixe la version du moteur et de `opa test` ; compilation une fois, évaluation en mémoire, sans processus ni réseau ; capacités et options tenues dans le code. Inconvénients : 21 modules liés ; `net/http` et `os/exec` présents dans le binaire.
2. **(1b) Binaire `opa eval` lancé par le worker.** Refusée : exécution de commande dans le worker (T8) ; version hors `go.mod` et `go.sum` (T6) sauf à livrer un binaire dans l'image ; un processus et une compilation par évaluation, ou un serveur `opa run` qui ajoute une surface réseau.
3. **(1c) Rego compilé en Wasm.** Refusée : deuxième chaîne (compilation par la CLI, moteur Wasm) ; le moteur Wasm de la bibliothèque OPA passe par cgo, que l'archtest refuse (`no-build-constraint`, `import "C"`), et un moteur pur Go exige d'écrire l'hôte de l'ABI OPA ; builtins partiellement réimplémentées côté hôte.

### Question 2 : version
1. **(2a) v1.22.4 (retenue)** : seule version mesurée sans vulnérabilité ; publiée depuis 7 jours.
2. **(2b) v1.22.0** : vulnérabilité connue dans une dépendance, contraire à la règle appliquée depuis (ex) (aucune vulnérabilité, même non appelée).
3. **(2c) 1.20.2, comme la CLI locale** : non mesurée, plus ancienne, sans gain.

### Question 3 : capacités
1. **(3a) Liste blanche fermée de builtins purs (retenue).**
2. **(3b) Liste noire (`http.send`, `net.*`, ...)** : refusée, toute builtin apportée par une montée de version serait admise sans revue.

### Question 4 : table de juridiction
1. **(4a) Une table (cloud, région), sourcée et datée, dans un paquet de domaine pur (retenue)**, importable par `internal/intent/domain`.
2. **(4b) Table dans `internal/policy`** (section 3.1) : refusée, L1 ne pourrait pas l'importer (R1) et `regions.go` resterait seule en L1.
3. **(4c) Table en Rego (`data`)** : refusée, la juridiction sert aussi en Go (L1, L3) ; un fichier de données chargé par `opa test` devrait l'être aussi par le moteur.

## Décision

### D1. Moteur : bibliothèque embarquée (option 1a)
- `opa/v1/rego` et `opa/v1/ast` importés par le seul paquet `internal/policy/adapters/opa` (D6).
- `NewDesign` compile le pack une fois (Rego v1, compilateur strict, annotations traitées), prépare une requête fixe (`PrepareForEval`) et rend un `Engine` immuable, sûr en concurrence, sans état entre évaluations (aucun magasin `data`, aucun cache inter-requêtes) : une évaluation ne voit rien de la précédente, quel que soit le tenant (T3). Un échec de `NewDesign` empêche le démarrage du binaire qui l'appelle (`rempart threat` en M2-T04, worker en M2-T05).
- Options `rego` en liste fermée : `Compiler`, `Query`, `StrictBuiltinErrors(true)` (une erreur de builtin devient une erreur, pas un indéfini qui ferait taire une règle), `EvalParsedInput` à l'évaluation. Jamais `Target` (Wasm), `Runtime`, `Load`, `LoadBundle`, `Store`, `Trace`, `PrintHook`, `EnablePrintStatements(true)`, ni builtin personnalisée (`Function*`, `RegisterBuiltin*`), ni plugin, bundle ou journal de décision.
- `net/http` et `os/exec` restent liés ; leur code n'est atteignable que par `http.send` (absente des capacités, D3) et par la cible Wasm (jamais choisie). `TestOPAConfined` lit les sources de l'adaptateur (`ReadSources`) et refuse tout sélecteur `rego.` hors de la liste ci-dessus. Risque résiduel 1.

### D2. Version et montée (option 2a)
- `require github.com/open-policy-agent/opa v1.22.4` et `tool github.com/open-policy-agent/opa` dans `go.mod` : la même ligne `require` sert le moteur et la CLI, la parité est structurelle. `TestGoDirective` exige cette directive `tool` et aucun `replace` sur ce module.
- Les montées de modules partagés tirées par OPA (`x/sys`, `x/sync`, protobuf, yaml) sont consignées dans `docs/STATUS.md` avec le diff de `go.mod`.
- Règle de montée : une ligne pour bibliothèque et outil ; `go tool govulncheck ./...` rc=0 ; `go mod verify` ; `capabilities.json` régénéré et son diff relu (D3) ; tests du pack et du moteur verts ; notes de version lues (builtins, mode strict) ; scan de l'outil (vérification 10) consigné.

### D3. Capacités en liste blanche, mode strict, bornes (option 3a)
- **Liste blanche**, littéral Go de l'adaptateur : `eq`, `assign`, `equal`, `neq`, `lt`, `lte`, `gt`, `gte`, `internal.member_2`, `internal.member_3`, `plus`, `minus`, `mul`, `div`, `rem`, `abs`, `count`, `sum`, `max`, `min`, `sort`, `and`, `or`, `intersection`, `union`, `array.concat`, `array.slice`, `object.get`, `object.keys`, `concat`, `startswith`, `endswith`, `contains`, `is_string`, `is_number`, `is_boolean`, `is_array`, `is_set`, `is_object`, `is_null`, `type_name`, `rego.metadata.rule`. Capacités = `ast.CapabilitiesForThisVersion()` restreintes à ces noms, `allow_net` vide, écrites dans `internal/policy/adapters/opa/capabilities.json` ; un test exige l'égalité du fichier et de la construction (une source pour le moteur et pour `opa check --capabilities`).
- **Familles refusées** : entrée-sortie et réseau (`http.send`, `net.*`, `net.cidr_*` compris : les adresses sont jugées en Go), environnement (`opa.runtime`), horloge (`time.*`), aléa (`rand.*`, `uuid.*`), `print`, `trace`, décodage et cryptographie (`io.jwt.*`, `crypto.*`, `base64.*`, `json.*`, `yaml.*` : aucun texte encodé dans l'entrée, surface d'analyse inutile), `regex.*`, `glob.*`, `walk`, `graph.*` (règle 2 du skill : Rego ne recalcule pas un graphe). Une builtin pure s'ajoute par revue du fichier (CODEOWNERS, D9) ; un test refuse toute builtin marquée `Nondeterministic` ou d'une famille refusée.
- **Double barrière** : avant compilation, l'adaptateur parcourt l'AST et refuse tout appel hors liste (le refus de `print` ne dépend pas du traitement que le compilateur lui réserve) ; puis le compilateur applique les capacités.
- **Schéma d'entrée** : `schemas/policy/design-input-v1.json` (autonome, `additionalProperties: false`), passé au compilateur et à `opa check --schema` : une référence à un champ inexistant (`input.graph.nodes[_].attrs.encrpted`) est une erreur de type, pas un indéfini silencieux (T119).
- **Bornes** : `Options{Timeout, MaxInputBytes, MaxFindings}`, défauts 10 s, 8 Mio d'entrée sérialisée, 10 000 sorties ; délai posé par `context.WithTimeout` à chaque évaluation. Au-delà : `ErrInputTooLarge`, `ErrEvaluation` (délai, erreur de builtin), `ErrPolicyOutput` (sorties en trop) ; jamais une liste vide ni tronquée. Dans L2, toute erreur mène à l'escalade (ADR 0012). Mesure en fin de M2-T03 (référence et candidat de 64 Kio) consignée ; au-delà de 1 s par évaluation, défauts revus par amendement.

### D4. Pack : embarquement, métadonnées, sorties, traduction, empreinte
- `policies/embed.go` : `package policies`, `//go:embed design/*.rego`, `var Design embed.FS`. L'adaptateur compile tous les fichiers sauf `*_test.rego` (un motif plutôt qu'une liste : un fichier ajouté ne peut être oublié). Aucun fichier de données sous `policies/` (`opa test` chargerait un `.json` ou un `.yaml` que le moteur ignore) : seuls `.rego`, `embed.go`, `.gitkeep`.
- **Paquets** : chaque module non test déclare `package rempart.design.<nom>` (`[a-z_]+`), sinon `ErrPackInvalid` ; `rempart.design.lib` (`policies/design/lib.rego`) porte les prédicats partagés, sans métadonnée ni `deny`. Requête fixe : `data.rempart.design[_].deny[_]`.
- **Un contrôle, une règle** : chaque règle `deny` porte un bloc `# METADATA` de portée `rule`, et tout bloc qui porte `custom.control_id` est sur une règle `deny` :
  ```
  # METADATA
  # title: Donnée sensible atteignable directement depuis Internet
  # custom:
  #   control_id: NET-001
  #   severity: critical
  #   remediation: make_private
  #   frameworks: {}
  deny contains f if { ...; meta := rego.metadata.rule(); f := {"control_id": meta.custom.control_id, "resource": id} }
  ```
- **Métadonnées vérifiées à la compilation, échec fermé** (`ErrPackInvalid`) : `title` non vide, au plus 120 octets, sans caractère de contrôle ni bidirectionnel ; clés de `custom` exactement `control_id`, `severity`, `remediation`, `frameworks` (faute de frappe ou `remediation_hint` refusées) ; `control_id` au motif `^[A-Z0-9]{2,5}-[0-9]{3}$`, unique ; `severity` dans `critical`, `high`, `medium`, `low` ; `remediation` dans le vocabulaire fermé de D5 du plan, `advisory` si et seulement si la sévérité est `medium` ou `low` ; `frameworks` objet vide (D13). Les 45 triplets (`control_id`, sévérité, remédiation) sont figés dans un test : abaisser une sévérité modifie un fichier de test, gelé en phase impl (T108). Un test lit l'AST et refuse une règle `deny` qui n'appelle pas `rego.metadata.rule()`.
- **Sortie d'une règle** : objet aux clés exactement `control_id` et `resource`. `ErrPolicyOutput` si une clé manque ou s'ajoute, si le `control_id` est inconnu, si `resource` n'est pas l'identifiant d'un nœud ou d'une arête de l'entrée.
- **Traduction** en `loopsdomain.Finding` : `Code` = `control_id` ; `Source` = `policy:design` ; `Severity` = sévérité des métadonnées, jamais de la sortie (hors domaine : poids critique, `Severity.Weight`) ; `Resource` = identifiant ; `Message` = `title` (texte du pack, relu) ; `File` vide, `Line` 0 ; doublons retirés, ordre de `loopsdomain.Sort`.
- **Écriture** : un attribut de sécurité se teste du côté sûr (`not node.attrs.encrypted == true` déclenche aussi sur un attribut absent). `lib_test.rego` : `ko(id, inp)` vrai si une sortie de `control_id` `id` existe `with input as inp`, `ok(id, inp)` sa négation ; au moins un `ok` et un `ko` par contrôle, plus les cas limites du skill.
- **Empreinte** (ADR 0010 D12, précisée) : SHA-256 hexadécimal minuscule de la suite des netstrings (chemin relatif à `policies/`, contenu) des fichiers compilés, triés par chemin ; une seule liste sert à la compilation et à l'empreinte. `Engine.Digest()` et `Engine.Controls()` (triés par `control_id`) ; L2 compose `threat.Pack` avec ses propres codes (ADR 0012).

### D5. Entrée des politiques
- `policy.DesignInput{Graph, Reach, Derived}` dans `internal/policy` (R1 interdit `internal/policy/domain`). Aucun type atteignable ne porte de `FreeText`.
- `Derived` : `Jurisdiction` (zone de chaque nœud qui porte `cloud` et `region`, et de chaque `K8sWorkload` d'après son cluster ; la zone d'une donnée est jointe en Rego par `STORES`) ; `UnconfirmedExposures` et `SourcesUnresolved` (identifiants d'arêtes `EXPOSES`, calculés en Go par L2, ADR 0012 : la dérogation elle-même n'entre jamais) ; `Constraints{AllowedRegions, ForbiddenClouds}` (liste vide : aucune contrainte, sens de l'IR) ; `Environment` (le plus exigeant de l'IR ou des `Network` ; vide lu `prod`) ; `Observability{Metrics, Logs}` (absente : faux).
- `policy.NewDesignInput` calcule `Jurisdiction`, vérifie que chaque identifiant cité existe et a le bon type, que régions, clouds et environnement suivent leur grammaire, trie, dédoublonne et remplace toute liste nulle par `[]` (un `count(null)` serait une erreur stricte) ; sinon `ErrDesignInput` (message fixe).
- Sérialisation par `encoding/json` (champs ordonnés, cartes triées par clé), convertie une fois en valeur AST. `TestEngineInputHasNoFreeText` : parcours des types par réflexion (aucun `FreeText`), validation contre le schéma de D3, IR à canaris dans tous ses champs de texte libre et aucun canari dans l'entrée sérialisée.

### D6. Confinement et `Makefile`
- Règle `opa-confined` (`Confine`) dans `DefaultRules` : cibles `github.com/open-policy-agent/...` et `<module>/policies/...`, importeur admis `<module>/internal/policy/adapters/opa/...`. Les tests qui lisent l'AST Rego vivent dans l'adaptateur. `TestOPAConfined` : règle présente, aucune violation, options `rego.` de D1, critère 5 de la fiche.
- `Makefile` : la variable `OPA` est **retirée** (`OPA ?=`, son `override`, son `export`) : aucun appelant ne choisit plus le binaire exécuté (T8). `opa-test` garde la recherche préalable de `.rego` et `POLICIES_DIR` figé et lu par le shell, puis exécute `go tool opa check --strict --capabilities internal/policy/adapters/opa/capabilities.json --schema schemas/policy/design-input-v1.json "$$POLICIES_DIR"` et `go tool opa test "$$POLICIES_DIR"` ; l'échec de `go tool` remplace le contrôle `command -v`. `internal/archtest/makefile_test.go` adapté en phase tests (variables d'appelant, recette, cas négatifs `opa` nu et `check` sans `--strict`) ; `docs/SETUP.md` ne demande plus d'installer OPA ; CI inchangée.

### D7. Juridiction (option 4a)
- **Sens** : localisation physique, déclarée par le fournisseur, des centres de données de la région. `fr` : France métropolitaine ; `eu` : un des 27 États membres (une région `fr` satisfait `eu`) ; `non_eu` : ailleurs, EEE hors UE, Suisse et Royaume-Uni compris (choix strict, réversible) ; `unknown` : couple absent de la table. La zone ne dit rien de la nationalité de l'opérateur ni des lois extraterritoriales : ces critères (qualification SecNumCloud par exemple) relèvent d'un fait et d'un contrôle distincts, hors M2 (T118).
- **Table** : `internal/policy/domain/jurisdiction.go`, littéral trié par (cloud, région) de lignes `{Cloud, Region, Zone, Source, Verified}` : cloud du schéma (`aws`, `azure`, `scaleway`, `ovhcloud`), région au motif du schéma du graphe, zone jamais `unknown`, `Source` URL `https` d'un domaine du fournisseur (liste fermée dans le test), `Verified` au format `AAAA-MM-JJ`. `Jurisdiction` rend `unknown` pour tout couple absent.
- **Contenu initial** : les 19 régions de `regions.go` sur leur cloud, les régions Public Cloud OVHcloud, au moins une région `non_eu` par cloud qui en a. Pages de départ : liste des régions AWS (`docs.aws.amazon.com`), liste des régions Azure (`learn.microsoft.com`), disponibilité par région Scaleway (`scaleway.com`), régions Public Cloud OVHcloud (`ovhcloud.com`) ; l'URL exacte lue est consignée par ligne.
- **Vérification** : à la mise en oeuvre, l'agent lit la page du fournisseur pour chaque ligne et consigne URL et date ; l'humain relit la table (étape H-jurisdiction, avec H-CODEOWNERS) ; relecture à chaque clôture de jalon. Aucun test ne dépend de la date du jour.
- **Usage** : RES-001 à RES-007 ; `unknown` pour l'hôte d'une donnée sensible donne RES-005 (haute, escalade), jamais un passage. `internal/intent/domain` garde sa table en M2 ; `TestRegionZonesAgreeWithJurisdiction` (dans ce paquet) exige l'accord des deux ; fusion par l'obligation (fd).

### D8. Interfaces Go (écarts à la section 3.1 du plan)
```go
package domain // internal/policy/domain : bibliothèque standard et internal/*/domain seulement
type Remediation string // vocabulaire fermé de D5 du plan
type Control struct{ ID, Title string; Severity loopsdomain.Severity; Remediation Remediation }
type Zone string // ZoneFR "fr", ZoneEU "eu", ZoneNonEU "non_eu", ZoneUnknown "unknown"
func Jurisdiction(cloud, region string) Zone
type Constraints struct{ AllowedRegions, ForbiddenClouds []string }
type Observability struct{ Metrics, Logs bool }
type Derived struct{ Jurisdiction map[string]Zone; UnconfirmedExposures, SourcesUnresolved []string; Constraints Constraints; Environment string; Observability Observability }

package policy // internal/policy
type DesignContext struct{ UnconfirmedExposures, SourcesUnresolved []string; Constraints policydomain.Constraints; Environment string; Observability policydomain.Observability }
type DesignInput struct{ Graph graphdomain.FactsGraph; Reach reach.Result; Derived policydomain.Derived }
var ErrDesignInput error
func NewDesignInput(g graphdomain.FactsGraph, r reach.Result, c DesignContext) (DesignInput, error)
type Evaluator interface {
	Evaluate(ctx context.Context, in DesignInput) ([]loopsdomain.Finding, error) // Code = control_id, Source = "policy:design"
	Controls() []policydomain.Control
	Digest() string
}

package opa // internal/policy/adapters/opa : seul importeur d'OPA et de policies
type Options struct{ Timeout time.Duration; MaxInputBytes, MaxFindings int }
var DefaultOptions = Options{Timeout: 10 * time.Second, MaxInputBytes: 8 << 20, MaxFindings: 10000}
var ErrPackInvalid, ErrEvaluation, ErrPolicyOutput, ErrInputTooLarge error
func NewDesign() (*Engine, error) // policies.Design, DefaultOptions ; *Engine implémente policy.Evaluator
```
Le constructeur sur un pack arbitraire reste non exporté (tests de l'adaptateur).

### D9. Harnais : proposition à l'humain (H-CODEOWNERS)
L'agent ne modifie pas le harnais. Proposition de `.github/CODEOWNERS`, propriétaire désigné par l'humain : `/policies/`, `/schemas/`, `/internal/policy/domain/jurisdiction.go`, `/internal/policy/adapters/opa/capabilities.json`, `/go.mod`, `/go.sum` ; protection de branche qui exige la revue des propriétaires.

## Conséquences
- Positives : un moteur, une version, parité structurelle avec `opa test` ; ni commande ni réseau à l'évaluation ; pack immuable lié au binaire et identifié par son empreinte ; politiques incapables d'entrée-sortie ou de non-déterminisme par construction ; échec fermé à la compilation comme à l'évaluation ; table de juridiction sourcée commune à L1 et L2.
- Négatives : 70 modules de plus au graphe, 21 liés dans `rempart` et le worker (binaires plus gros, mesure) ; le premier `go tool opa` compile la CLI (téléchargement unique des modules) ; la liste blanche impose des faits Go (pas de `net.cidr_*`, pas de regex) ; `makefile_test.go` à adapter ; table entretenue à la main ; deux tables de zones jusqu'à (fd).
- Difficile à changer : format des métadonnées et forme des sorties (45 règles et leurs tests) ; algorithme de l'empreinte (modèles de menace) ; sens des zones (L3, L6, preuves).

## Risques résiduels
1. **Code lié non atteint** (`os/exec`, `net/http`) : un défaut d'OPA ou une option interdite ajoutée plus tard le rendrait atteignable. Parade : options fermées testées, `govulncheck` (atteignabilité), conteneur sans shell et sortie réseau filtrée (T8, T22).
2. **Version de 7 jours** : défaut non encore signalé. Parade : D2, montée de correctif rapide.
3. **Parité partielle CLI et moteur** : `opa test` s'exécute sans `StrictBuiltinErrors` ; un test Rego peut passer là où le moteur échoue (erreur, donc escalade : échec fermé). Parade : `opa check --capabilities --schema`, `TestEngineFailsClosed`, cas de `evals/design` évalués par le moteur (M2-T07).
4. **Vérificateur de types OPA** : sous-ensemble de JSON Schema ; si une construction n'est pas prise en charge, le schéma d'entrée est simplifié (types et propriétés), la garde demeure.
5. **Table de juridiction** : erreur de lecture humaine ; une région ouverte après la date reste `unknown` (escalade pour une donnée sensible, `advisory` sinon).
6. **Règle qui ne déclenche jamais** (T119) : parade par `ko` par contrôle, catalogue figé, invariant Go indépendant du pack (ADR 0012).
7. **Mémoire de l'évaluation** bornée seulement par la taille d'entrée, le délai et le conteneur (T24).
8. **Dépendances de la CLI** hors de `govulncheck ./...` : scan de l'outil à chaque montée (vérification 10).

## Impact sur le modèle de menace

Menaces existantes :
- **T6** : version épinglée par `go.sum`, parité structurelle, `govulncheck` du module et de l'outil, `go mod verify`, CODEOWNERS (D9). Ajouter `TestGoDirective` (directive `tool` OPA) et les vérifications 8 à 10.
- **T8** : variable `OPA` retirée, plus aucun binaire choisi par l'appelant ; `POLICIES_DIR` reste figé et lu par le shell ; `os/exec` lié mais non atteint (D1). Ajouter `TestMakefileTargets` (cas `opa` nu) et `TestOPAConfined`.
- **T24** : bornes de D3 ; ajouter `TestEngineFailsClosed` (délai, taille, sorties).
- **T2** : entrée sans texte libre, sortie à clés fermées, `Message` tiré du pack ; ajouter `TestEngineInputHasNoFreeText`.
- **T3** : moteur sans état ; sous-cas de `TestEngineDeterministic` (évaluer A puis B donne le résultat de B seul).

Menaces proposées par le plan : **T108** confirmée, atténuation complétée (paquet hors `rempart.design.*`, `deny` sans métadonnée et clé inconnue refusés, catalogue figé, empreinte dans le modèle de menace, CODEOWNERS étendu), vérification complétée de `TestEngineFailsClosed`. **T109** confirmée (liste blanche, barrière AST, options fermées, aucun magasin, `StrictBuiltinErrors`), vérification complétée de `TestOPAConfined` et de la vérification 11. **T114** confirmée (une table sourcée et datée, accord avec L1 testé, `unknown` en échec fermé), vérification complétée de `TestRegionZonesAgreeWithJurisdiction`. **T111** et **T112** : en partie (D5, D3).

Menaces nouvelles proposées (numéros provisoires, confirmés par `security-reviewer` à l'insertion) :

| # | Menace | Cat. | Atténuation | Vérification |
|---|---|---|---|---|
| T118 | Confusion entre localisation et souveraineté : zone `fr` ou `eu` lue comme protection contre les lois extraterritoriales ou comme qualification ; donnée soumise à une exigence de souveraineté placée chez un opérateur qui ne la satisfait pas, sans finding | I | Sens de D7 écrit dans la table, les titres RES-xxx et les gabarits d'explication (« localisation ») ; exigence de souveraineté par un fait et un contrôle distincts | `TestJurisdictionTableClosed` (sens documenté) ; contrôle à créer avec le catalogue de conformité (M4) |
| T119 | Politique qui échoue ouverte : champ absent ou mal orthographié, erreur de builtin, règle hors du paquet interrogé ; la règle est indéfinie et ne produit aucun finding | T, E | Schéma d'entrée au compilateur et à `opa check`, `StrictBuiltinErrors`, paquets et portée des métadonnées vérifiés, attributs de sécurité requis (ADR 0010 D6), écriture du côté sûr, `ko` par contrôle, invariant Go indépendant | `TestEngineFailsClosed`, `TestEveryControlHasOkAndKo`, vérification 2 |

## Écarts au plan M2, à reporter dans `docs/plans/M2-overview.md` au début de M2-T03
1. Section 3.1 : `DesignInput` dans `internal/policy` (R1) ; `DesignContext`, `NewDesignInput`, `ErrDesignInput`, `Evaluator.Digest` ajoutés ; `Jurisdiction` dans `internal/policy/domain`, rend `Zone` (D5, D7, D8).
2. Fiche M2-T03, livrables : `internal/policy/jurisdiction.go` devient `internal/policy/domain/jurisdiction.go` ; ajout de `policies/design/lib.rego`, `internal/policy/adapters/opa/capabilities.json`, `schemas/policy/design-input-v1.json`.
3. Fiche M2-T03, `Makefile` : variable `OPA` retirée au lieu de valoir `go tool opa` (une valeur à espaces sort de la grammaire `OPA ?= [A-Za-z0-9._/-]+` et laisserait l'appelant choisir le binaire) ; `opa check` porte `--capabilities` et `--schema` (critère 2 inchangé, vérification 2 plus stricte).
4. Skill `policy-as-code`, règles 3 et 4 : `remediation` (vocabulaire fermé) remplace `remediation_hint` ; sortie limitée à `control_id` et `resource`, sévérité et message tirés des métadonnées ; `frameworks: {}`. Skill et références alignés en M2-T03, signalés dans `docs/STATUS.md`.
5. ADR 0010 D12 : empreinte précisée (netstrings du chemin et du contenu), principe inchangé.
6. Tests hors des 8 de la fiche : `TestRegionZonesAgreeWithJurisdiction` ; sous-cas dans `TestGoDirective` et `TestMakefileTargets`. Compte du critère 4 inchangé.
7. Obligation (fd) [moyen, avant M3] : `internal/intent/domain` lit la table de D7 et `regions.go` disparaît.

## Vérification
1. Critère 1 : `make -f Makefile opa-test; echo rc=$?` : `rc=0` ; `go tool opa test policies/ -v; echo rc=$?` : `rc=0`.
2. Critère 2, étendu : `go tool opa check --strict --capabilities internal/policy/adapters/opa/capabilities.json --schema schemas/policy/design-input-v1.json policies/; echo rc=$?` : `rc=0`.
3. Critère 3 : `ls policies/design/*.rego | grep -v '_test\.rego$' | xargs grep -h '^#[[:space:]]*control_id:' | sort -u | wc -l` : au moins `40` ; même commande avec `sort | uniq -d | wc -l` : `0`.
4. Critère 4 (huit tests nommés de la fiche) : `8`.
5. Critère 5 : `go list -deps ./internal/graph/... ./internal/design/... ./internal/threat/... ./internal/intent/... | grep -c open-policy-agent` : `0`.
6. Confinement : `go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./... | grep -E 'github.com/open-policy-agent/| github.com/amezianechayer/rempart/policies( |$)' | cut -d: -f1 | sort -u` : exactement `github.com/amezianechayer/rempart/internal/policy/adapters/opa`.
7. Empreinte liée : `go list -deps ./internal/policy/adapters/opa | grep -Ec 'prometheus|opentelemetry|dgraph-io/badger|google.golang.org/grpc'` : `0`.
8. Version : `go list -m github.com/open-policy-agent/opa` : `github.com/open-policy-agent/opa v1.22.4` ; `go tool opa version | grep -c '^Version: 1.22.4$'` : `1` ; `go mod edit -json | jq -e '([.Tool[].Path] | index("github.com/open-policy-agent/opa") != null) and ([(.Replace // [])[] | select(.Old.Path == "github.com/open-policy-agent/opa")] | length == 0)'` : `true`.
9. Critère 6 : `go tool govulncheck ./...; echo rc=$?` : `rc=0` ; `go mod verify` : `all modules verified`.
10. Mesure consignée, non bloquante en M2 (règle de montée de D2) : `d=$(mktemp -d) && go build -o "$d/opa" github.com/open-policy-agent/opa && go tool govulncheck -mode=binary "$d/opa"; echo rc=$?` ; `go list -m all | wc -l`.
11. Capacités : `jq -e '([.builtins[].name | select(test("^(http|net|opa|time|rand|uuid|io|crypto|regex|glob|graph|json|yaml|base64)[.]") or IN("print", "internal.print", "trace", "walk"))] | length) == 0 and (.allow_net == [])' internal/policy/adapters/opa/capabilities.json` : `true`.
12. `Makefile` : `grep -Ec '^(OPA \?=|override OPA )' Makefile` : `0` ; `grep -c 'go tool opa check --strict --capabilities' Makefile` : `1`.
13. `find policies -type f ! -name '*.rego' ! -name embed.go ! -name .gitkeep | wc -l` : `0`.
14. `go test ./internal/intent/domain/ -run TestRegionZonesAgreeWithJurisdiction -v 2>&1 | grep -c '^--- PASS: TestRegionZonesAgreeWithJurisdiction '` : `1`.
15. Critère 7 : `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
16. Mesure consignée (D3) : `go test ./internal/policy/adapters/opa/ -run '^$' -bench BenchmarkEvaluate -benchmem`.

## Ordre de mise en oeuvre

M2-T03 (phase tests puis impl ; coupe T03a et T03b après l'étape 7 si la garde de taille est atteinte) :
1. `go.mod` : bibliothèque et outil v1.22.4, `go mod tidy`, diff et nombre de modules consignés (`TestGoDirective` ; vérifications 8 à 10).
2. `Makefile`, `makefile_test.go`, `docs/SETUP.md` (D6 ; `opa-test` reste sans objet tant qu'aucun `.rego`).
3. `internal/policy/domain` : types, table de juridiction vérifiée à la source (`TestJurisdictionTableClosed`, `TestRegionZonesAgreeWithJurisdiction`).
4. `internal/policy` : `DesignInput`, `NewDesignInput`, schéma d'entrée (`TestEngineInputHasNoFreeText`).
5. Adaptateur sur un pack de test : capacités, barrière AST, métadonnées, compilation, évaluation, traduction, empreinte (`TestEngineCapabilitiesDenyIO`, `TestEngineFailsClosed`, `TestEngineDeterministic`).
6. Règle `opa-confined` (`TestOPAConfined`).
7. `policies/embed.go`, `lib.rego`, `lib_test.rego`, règles réseau et données (`TestPolicyMetadataComplete`, `TestEveryControlHasOkAndKo`).
8. Résidence, identités, Kubernetes, résilience ; catalogue figé à 45.
9. Skill `policy-as-code` aligné et signalé ; mesures consignées ; proposition CODEOWNERS (H-CODEOWNERS) et relecture de la table (H-jurisdiction) ; T118 et T119 soumises à `security-reviewer`.
