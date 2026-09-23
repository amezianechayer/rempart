---
name: policy-as-code
description: Écriture, test et organisation des politiques OPA/Rego de Rempart sur quatre niveaux (conception sur le graphe, IaC via Conftest, runtime sur le graphe réel, Kubernetes), avec métadonnées de contrôle et mapping conformité. À utiliser dès qu'une tâche crée ou modifie une règle de sécurité, un pack de politiques, un contrôle de conformité ou le moteur d'évaluation, même pour une seule règle.
---

# Policy as code

## Références (testées avec OPA 1.x)
- Règle de conception complète : `references/network_exposure.rego`
- Ses tests : `references/network_exposure_test.rego`
Lance `opa test references/ -v` pour voir le motif attendu passer.

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
3. Chaque règle porte un bloc `# METADATA` avec `title` et `custom` : `control_id`, `severity`, `frameworks`, `remediation_hint`. Le finding reprend ces métadonnées via `rego.metadata.rule()`.
4. Chaque finding contient : `control_id`, `severity`, `resource`, `message`, `evidence` (le fait qui déclenche, ex. le chemin).
5. Pas de logique de contournement dans les règles (pas de « sauf si tag skip=true ») : les exceptions sont gérées hors Rego, par le système d'exceptions humaines avec expiration.

## Tests obligatoires
- Pour chaque règle : au moins un cas conforme et un cas non conforme, plus les cas limites (liste vide, champ absent).
- `opa test policies/ -v` et `opa check policies/` dans `make verify-quick`. Suivre la couverture (`opa test --coverage`).

## Mapping conformité
Les références (NIS2, DORA, SecNumCloud, ISO 27001, CIS) sont validées contre `compliance/catalog/*.yaml`. **Ne jamais inventer un numéro d'article ou de contrôle.** Si la correspondance n'est pas certaine, laisser vide et ouvrir une tâche de vérification humaine. Les références de l'exemple sont illustratives et doivent être vérifiées avant usage.
