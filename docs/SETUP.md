# Poste de développement

## Système
- Linux, macOS, ou Windows avec **WSL2** : lancer Claude Code et tous les outils depuis WSL, dépôt dans le système de fichiers Linux (`~/rempart`), pas sur `/mnt/c`.
- Éviter les dossiers synchronisés (OneDrive, Dropbox, iCloud) : ils abîment `.git` et verrouillent des fichiers.

## Récupérer le projet
```bash
git clone https://github.com/<ton-compte>/rempart.git
cd rempart
bash scripts/check-tools.sh
```
Propositions à appliquer par toi si ce n'est pas encore fait (le harnais est protégé contre l'agent) : `docs/proposals/0001-harnais-portable-et-tdd.md` (hooks) et `docs/proposals/0002-claude-md-trailer-commits.md` (CLAUDE.md).

## Outils

| Outil | Version | Quand | Source officielle |
|---|---|---|---|
| Python 3 (`python3`) | 3.8+ | M0 (hooks) | python.org ou paquet système |
| Git, make, bash, jq | récents | M0 | paquets système |
| Go | version de la directive `go` de `go.mod` (1.27.1 au 2026-09-23) ; un Go 1.21+ local télécharge cette chaîne via `GOTOOLCHAIN=auto` | M0 | go.dev/dl |
| Docker Engine + plugin compose | récent | M0 (`make dev`) | docs.docker.com/engine/install. Docker Desktop est payant pour les entreprises de plus de 250 salariés ou 10 M$ de chiffre d'affaires |
| golangci-lint | v2.13.2 (épinglée ; CI en M0-T04), compilée avec Go 1.27 ou plus : `GOTOOLCHAIN=go1.27.1 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2` ou binaire officiel | M0 | golangci-lint.run |
| govulncheck | v1.8.0, épinglée par la directive `tool` de `go.mod` et lancée par `go tool govulncheck` ; binaire séparé facultatif | M0 | `go install golang.org/x/vuln/cmd/govulncheck@v1.8.0` |
| gofumpt | récent | M0 | `go install mvdan.cc/gofumpt@latest` |
| OPA | 1.x | M0 (si `policies/` existe) | openpolicyagent.org |
| Conftest | récent | M2 | conftest.dev |
| OpenTofu | récent | M3 | opentofu.org (page Install) |
| tflint | récent | M3 | github.com/terraform-linters/tflint |
| Checkov | récent | M3 | `pipx install checkov` |
| Trivy | récent | M3 | trivy.dev |
| Infracost | récent | M3 | infracost.io (clé API gratuite, à garder hors du dépôt) |
| Temporal CLI | récent | utile | docs.temporal.io/cli (`temporal server start-dev` évite Docker pour Temporal) |
| GitHub CLI (`gh`) | récent | utile | cli.github.com |
| Node.js LTS | récent | M5 (web) | nodejs.org |
| aws, az, kubectl, helm | récents | M3+ (bac à sable) | sites officiels |

## Comptes (avant M3)
Comptes bac à sable AWS et Azure dédiés, avec alertes de budget. Aucun identifiant dans le dépôt.
