---
name: policy-as-code
description: Écriture, test et organisation des politiques OPA/Rego de Rempart sur quatre niveaux (conception sur le graphe, IaC via Conftest, runtime sur le graphe réel, Kubernetes), avec métadonnées de contrôle et mapping conformité. À utiliser dès qu'une tâche crée ou modifie une règle de sécurité, un pack de politiques, un contrôle de conformité ou le moteur d'évaluation, même pour une seule règle.
---

# Policy as code

## Références (le pack vivant, testé par `make opa-test`)
- Règles de conception : `policies/design/network.rego` (motif complet), `policies/design/lib.rego` (prédicats partagés).
- Tests : `policies/design/lib_test.rego` (entrée conforme `base`, aides `ok` et `ko`), `policies/design/network_test.rego`.
- Moteur et contrat : ADR 0011 ; `internal/policy/adapters/opa` (capacités dans `capabilities.go`, vérifications du pack) ; entrée typée par `schemas/policy/design-input-v1.json`.
- Vérifier : `go tool opa check --strict --capabilities internal/policy/adapters/opa/capabilities.json --schema schemas/policy/design-input-v1.json policies/` puis `go tool opa test policies/ -v` (jamais un `opa` du `PATH`).

## Quatre niveaux, un seul langage
| Dossier | Évaluée sur | Boucle |
|---|---|---|
| `policies/design/` | graphe d'architecture (JSON, avec atteignabilité pré-calculée par Go) | L2 |
| `policies/iac/` | plan OpenTofu JSON via Conftest | L3 |
| `policies/runtime/` | graphe de sécurité réel | L6 |
| `policies/k8s/` | manifestes et état Kubernetes | L2, L3, L6 |
Une intention de contrôle a idéalement sa déclinaison à chaque niveau pertinent, reliées par le même `control_id`.

## Règles d'écriture
1. Syntaxe Rego v1 (OPA 1.x) : `deny contains finding if { ... }`.
2. Le calcul lourd (atteignabilité, permissions effectives) est fait en Go et injecté dans `input`. Rego décide sur des faits, il ne recalcule pas un graphe.
3. Un contrôle, une règle `deny contains f if { ... }` précédée d'un bloc `# METADATA` de portée règle : `title` (120 octets au plus) et `custom` aux clés exactement `control_id` (`^[A-Z0-9]{2,5}-[0-9]{3}$`, unique), `severity` (`critical`, `high`, `medium`, `low`), `remediation` (vocabulaire fermé de `internal/policy/domain`, `advisory` si et seulement si `medium` ou `low`) et `frameworks: {}` (vide en M2). Le moteur refuse le pack sinon (ADR 0011 D4).
4. La sortie est exactement `{"control_id": meta.custom.control_id, "resource": <identifiant d'un nœud ou d'une arête de l'entrée>}` avec `meta := rego.metadata.rule()` dans le corps : sévérité et message viennent des métadonnées, jamais de la sortie ; aucun texte libre, aucune preuve recopiée (les faits sont dans l'entrée).
5. Pas de logique de contournement dans les règles (pas de « sauf si tag skip=true ») : les exceptions sont gérées hors Rego, par le système d'exceptions humaines avec expiration.
6. Paquet `rempart.design.<nom>` (`[a-z_]+`, sans chiffre : `k8s.rego` déclare `rempart.design.kubernetes`) ; prédicats partagés dans `rempart.design.lib` ; jamais de `with` ni d'annotation `schemas` dans le pack ; seulement les fonctions de la liste blanche (pas de `sprintf`, `regex`, `net.cidr_*`, horloge, aléa, `print`) : un fait qui demande plus est calculé en Go et ajouté à l'entrée.
7. Lire chaque attribut de sécurité du côté sûr : `not n.attrs.encrypted == true` déclenche aussi sur un attribut absent.
8. Ne jamais placer un appel de fonction à l'intérieur d'une comparaison niée (`not f(x) <= 100`) : OPA sort l'appel de la négation et un attribut absent rend la règle muette (échec ouvert, T119). Nier un prédicat nommé (`not lib.bounded_flow(e)`).

## Tests obligatoires
- Pour chaque règle : au moins un cas conforme `lib.ok("<id>", entrée)` et un cas non conforme `lib.ko("<id>", entrée)`, plus les cas limites (liste vide, champ absent) ; `TestEveryControlHasOkAndKo` lit l'arbre syntaxique des tests et l'exige.
- Les tests vivent dans `rempart.design_test.<nom>`, hors des paquets interrogés ; les entrées dérivent de `lib.base` (conforme) par `set_node`, `set_edge`, `with_nodes`, `with_edges`, `with_hops`, `with_derived`.
- `make verify-quick` lance la vérification stricte et les tests par `go tool opa`. Suivre la couverture (`go tool opa test --coverage policies/`).

## Mapping conformité
Les références (NIS2, DORA, SecNumCloud, ISO 27001, CIS) sont validées contre `compliance/catalog/*.yaml`. **Ne jamais inventer un numéro d'article ou de contrôle.** Si la correspondance n'est pas certaine, laisser vide et ouvrir une tâche de vérification humaine. Les références de l'exemple sont illustratives et doivent être vérifiées avant usage.
