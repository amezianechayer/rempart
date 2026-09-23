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
Si le correctif du harnais n'est pas encore appliqué : `docs/proposals/0001-harnais-portable-et-tdd.md`.

## Outils

| Outil | Version | Quand | Source officielle |
|---|---|---|---|
| Python 3 (`python3`) | 3.8+ | M0 (hooks) | python.org ou paquet système |
| Git, make, bash, jq | récents | M0 | paquets système |
| Go | 1.23+ (prendre la dernière stable) | M0 | go.dev/dl |
| Docker Engine + plugin compose | récent | M0 (`make dev`) | docs.docker.com/engine/install. Docker Desktop est payant pour les entreprises de plus de 250 salariés ou 10 M$ de chiffre d'affaires |
| golangci-lint | récent | M0 | golangci-lint.run |
| govulncheck | récent | M0 | `go install golang.org/x/vuln/cmd/govulncheck@latest` |
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
