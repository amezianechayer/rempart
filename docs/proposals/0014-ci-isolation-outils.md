# Proposition 0014 : isolation des outils en CI (ADR 0015, Q4)

- Date : 2026-11-26
- Statut : proposé, **à appliquer par l'humain** (`.github/` est protégé), à la fin de M3-T02b (étape H-CI-3 de `docs/plans/M3-overview.md`)
- Patch : `docs/proposals/0014-ci-isolation-outils.patch` (`.github/workflows/verify.yml` et son test d'architecture `internal/archtest/ci_test.go`, qui fige la forme du job et doit changer dans le même commit).
  - Vérifié par l'agent sur la tête de `main-6cpq6q` : le patch s'applique (`git apply --check`).
  - Dans une copie de travail jetable patchée, `go test -run 'TestCI|TestParseCIWorkflow' ./internal/archtest/` est vert ; il l'est aussi sur le dépôt non patché.
- Origine : ADR 0015 (D1, D12, hypothèse H1, question 4) ; menaces T157, T162.
- **Ordre avec la proposition 0011** (en attente de l'humain), qui modifie aussi `verify.yml` et `ci_test.go` :
  - si 0011 est appliquée d'abord, demander à l'agent de régénérer ce patch sur la nouvelle tête ;
  - appliquée seule, celle-ci n'en dépend pas.

## Pourquoi

1. **Restriction d'Ubuntu 24.04.** Ubuntu 24.04, l'image `runs-on` du job `verify`, restreint par AppArmor les espaces de noms utilisateur non privilégiés (`kernel.apparmor_restrict_unprivileged_userns=1`, hypothèse H1 de l'ADR 0015). Sans levée de cette restriction, la sonde de l'isolation échoue : aucun outil ne tourne, et les tests d'isolation sautent.
2. **Pas de vert vide.** Sans `REMPART_REQUIRE_SANDBOX=1`, un saut passe pour un succès. Avec la variable, un test d'isolation qui ne peut pas tourner échoue (D12, menace T162).

## Ce qui change

- **`verify.yml`** :
  - une étape « Tool isolation prerequisites », avant `dev-preflight`. Elle affiche le réglage AppArmor, le lève sur le runner éphémère (`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`), puis affiche le diagnostic de H1 : création d'espaces utilisateur, réseau, PID et montage, et présence de Landlock ;
  - la variable de job `REMPART_REQUIRE_SANDBOX: "1"`.
- **`ci_test.go`** :
  - la forme figée du job admet cette étape (constante `ciIsolationStep`) et cette variable ;
  - le workflow synthétique des contrôles négatifs les porte aussi.

## Écarté

- **Profil AppArmor par chemin** : les binaires de test changent de chemin à chaque compilation (ADR 0015, Q4).
- **Laisser sauter les tests** : ce serait un vert vide (T162).

## Limites

- **Portée de la levée** : elle ne vaut que pour le runner, détruit à la fin du job. Sur le poste de l'humain, voir `docs/SETUP.md`, section « Isolation des outils ».
- **Tests d'intégration des outils IaC** : ils exigent aussi la chaîne d'outils en CI (proposition 0012, M3-T03). Sans elle, `make verify` en CI échoue fermé sur ces tests, comme depuis M3-T02.

## Appliquer

```bash
git apply docs/proposals/0014-ci-isolation-outils.patch
go test -count=1 -run 'TestCI|TestParseCIWorkflow' ./internal/archtest/
git add .github/workflows/verify.yml internal/archtest/ci_test.go
git commit -m "ci: lift the user namespace restriction on the runner, require tool isolation"
git push
```
