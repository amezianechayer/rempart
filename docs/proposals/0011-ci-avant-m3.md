# Proposition 0011 : lot CI daté « avant M3 »

- Date : 2026-11-25
- Statut : proposé, **à appliquer par l'humain** (`.github/` est sous CODEOWNERS), à la fin de M3-T01 (étape H-CI-1 de `docs/plans/M3-overview.md`)
- Patch : `docs/proposals/0011-ci-avant-m3.patch` (`.github/workflows/verify.yml` et `internal/archtest/ci_test.go`, à appliquer ensemble : le test fige le workflow)
- Origine : obligations (ce), (cg) de la revue sécurité du jalon M0 ; (bq), (br) de M0-T04 ; lot CI de la section 8.2 du plan M2, daté « avant M3 »
- Vérifié par l'agent : le patch s'applique sur la tête de `main-6cpq6q` ; dans une copie de travail patchée, `go test ./internal/archtest/` passe (dont les 8 tests `TestCI*`) et `golangci-lint run ./internal/archtest/...` ne signale rien.

## Pourquoi

| Obligation | Menace | Défaut | Correctif |
|---|---|---|---|
| (ce) | T6 | `go install ...golangci-lint@v2.14.0` fait confiance au proxy de modules et à la base de sommes pour le contenu de la version. | Après l'installation, `go version -m` lit le hachage `h1:` du module dans le binaire ; il doit être égal au hachage épinglé dans le workflow. Un proxy ou une base de sommes qui servirait un autre contenu fait échouer le job. |
| (br) | T82 | Groupe de concurrence `verify-<numéro de PR ou ref>` : sur `main`, un run en attente est remplacé par le push suivant, si bien qu'un commit intermédiaire de `main` peut n'être jamais vérifié. | Groupe `verify-<numéro de PR ou SHA>` : un groupe par commit sur `main` (aucun remplacement), un seul run, le dernier, par pull request (annulation conservée). |
| (bq) | T82 | Seules les étapes `run` refusent une expression `${{ }}` ; une expression dans un nom d'étape, une condition `if`, un `with` ou un commentaire n'était pas contrôlée. Une clé `uses` entre guillemets échappait au contrôle de forme ligne à ligne. | `checkCIExpressions` : toute expression du fichier, commentaires compris, appartient à une liste fermée de trois expressions ; une ouverture `${{` non fermée sur la ligne est refusée. Toute ligne qui contient le mot `uses` suit la forme `uses: owner/repo@<sha> # vX.Y.Z`. |
| (cg) | T61 | Au premier push d'une branche, `github.event.before` vaut le SHA nul. | Déjà sûr côté exécuteur : un SHA nul donne `base_null` et toutes les suites (obligation (bs), cas `base_null` de `cmd/rempart-evals/git_test.go`). Le workflow le documente, et l'expression de `EVAL_BASE` est figée par la liste fermée de (bq) : aucune autre source ne peut s'y glisser. |

## Ce qui change

- `.github/workflows/verify.yml` : groupe de concurrence par SHA ; étape « Install golangci-lint » en deux commandes (installation, vérification du hachage) ; deux commentaires ((br), (cg)).
- `internal/archtest/ci_test.go` : `ciGroup` passe à `github.event.pull_request.number || github.sha` ; `golangciRunRe` exige l'installation suivie de la vérification d'un hachage `h1:` de la forme attendue ; nouveau `checkCIExpressions` et `TestCIExpressionsClosed` (six mutations refusées) ; une mutation de plus dans `TestCIActionsPinnedBySHA` (clé `"uses"`) et dans `TestCIRunsMakeVerify` (hachage retiré) ; `allCIChecks` inclut la nouvelle vérification.

Le hachage épinglé est celui du binaire `golangci-lint` v2.14.0 installé dans la session de l'agent (`go version -m`) : `h1:ot8QffRa4LzAAEgtvNYrVs9esxQ7xoTwoAv6uhp4ngA=`. À recouper si besoin sur `sum.golang.org` (`/lookup/github.com/golangci/golangci-lint/v2@v2.14.0`). À chaque montée de version de golangci-lint, le hachage change avec la version, dans le même commit.

## Appliquer

```bash
git apply docs/proposals/0011-ci-avant-m3.patch
go test ./internal/archtest/ -run 'TestCI'
git add .github/workflows/verify.yml internal/archtest/ci_test.go
git commit -m "ci: pin golangci-lint by hash, one concurrency group per main commit, closed expressions"
git push
```

## Risque résiduel

Le premier run après application vérifie le hachage réel du binaire : si la vérification échoue, ne pas changer le hachage sans avoir compris pourquoi (le contenu servi diffère de celui de la session de l'agent).
