---
name: secure-iac-generation
description: Génération et validation d'IaC OpenTofu sécurisée pour Rempart (modules internes, chaîne fmt/validate/tflint/checkov/trivy/conftest/infracost, findings normalisés, équivalence graphe/plan, état chiffré, FinOps). À utiliser pour toute tâche touchant les boucles L3, L7, L8, L10, les modules dans modules/, internal/iacgen, internal/validate, internal/plan, ou tout fichier .tf, même une petite modification.
---

# Génération IaC sécurisée

## Références et outils
- Chaîne de validation exécutable : `scripts/validate.sh <dossier_iac> <dossier_sortie>` produit `findings.json` normalisé, `fingerprint.txt` et `score.txt`. `internal/validate` en est la version Go et doit produire la même sortie sur les mêmes entrées.
- Normaliseur : `scripts/normalize_findings.py` (tofu validate, tflint, Checkov, Trivy, Conftest vers le format normalisé).
- Contrat d'un module interne : `references/module-contract.md`

## Principe : assembler plutôt qu'inventer
Le LLM compose des modules internes testés et durcis et ne génère du HCL brut qu'en dernier recours (stratégie `modules_plus_freeform`). Un bloc brut qui revient dans trois générations devient un candidat module (ADR).

## Ordre de la chaîne
1. `tofu fmt -check -recursive`
2. `tofu init -backend=false` puis `tofu validate -json`
3. `tflint --format json` (rulesets des providers utilisés)
4. `checkov -d . -o json` et `trivy config --format json .`
5. `tofu plan -out` puis `tofu show -json` et `conftest test --output json` avec `policies/iac/`
6. `infracost breakdown --format json` comparé au budget de l'IR
7. **Équivalence graphe/plan** (`internal/plan/equivalence`) : chaque ressource du plan correspond à un nœud ou une arête du graphe validé ; aucune ressource orpheline, aucune permission IAM, règle réseau ou exposition absente du graphe. C'est la barrière qui empêche le LLM d'ajouter discrètement quelque chose.
Toutes les sorties sont normalisées ; le vérificateur de L3 échoue sur tout finding `medium` ou plus.

## Interdits pour le proposeur LLM
- Écrire une exception de politique (`#checkov:skip`, `#trivy:ignore`, `tflint-ignore`, exceptions Conftest). Le vérificateur rejette tout candidat qui en contient. Une exception exige une justification humaine avec expiration, stockée hors du code généré, et figure dans le dossier de preuves.
- Mettre un secret, une clé ou un mot de passe en dur. Références OpenBao uniquement.
- Désépingler une version de provider ou de module.

## État
Backend distant par tenant et environnement, chiffré, verrouillé, versionné. En mode runner, l'état vit côté client.

## FinOps (L10)
Chaque changement porte son delta de coût (Infracost). Les recommandations d'économie (redimensionnement, réservations, arrêt hors heures en dev) passent par la même chaîne et ne doivent violer aucune politique de sécurité.
