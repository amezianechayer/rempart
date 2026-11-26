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
| Go | version de la directive `go` de `go.mod` (1.27.4 au 2026-11-18, failles GO-2026-6859 et GO-2026-6809 de la bibliothèque standard corrigées) ; un Go 1.21+ local télécharge cette chaîne via `GOTOOLCHAIN=auto` | M0 | go.dev/dl |
| Docker Engine + plugin compose v2 | 28 ou plus, démon local (socket unix) | M0 (`make dev`) | docs.docker.com/engine/install. Docker Desktop est payant pour les entreprises de plus de 250 salariés ou 10 M$ de chiffre d'affaires |
| golangci-lint | v2.14.0 (épinglée ; CI en M0-T04), compilée avec une version de Go au moins égale à la directive `go` (sinon elle refuse le module) : `GOTOOLCHAIN=go1.27.4 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0` ou binaire officiel | M0 | golangci-lint.run |
| govulncheck | v1.8.0, épinglée par la directive `tool` de `go.mod` et lancée par `go tool govulncheck` ; binaire séparé facultatif | M0 | `go install golang.org/x/vuln/cmd/govulncheck@v1.8.0` |
| gofumpt | récent | M0 | `go install mvdan.cc/gofumpt@latest` |
| OPA | aucune installation | M2 | version de `go.mod`, lancée par `go tool opa` (ADR 0011) ; un `opa` du `PATH` n'est jamais utilisé |
| OpenTofu, tflint et ses rulesets, Trivy, providers | versions exactes de `scripts/iac-tools.lock.json` | M3 | `make -f Makefile iac-tools` (section « Chaîne d'outils IaC ») ; jamais une version du `PATH` |
| Checkov | verrou à hachages (M3-T03) | M3 | installé par `scripts/iac-tools.sh` à partir de M3-T03 |
| Infracost | récent, facultatif | M3 | infracost.io ; seulement dans `scripts/sandbox.sh`, sur le poste de l'humain, si `INFRACOST_API_KEY` est présente (ADR 0014 D14) |
| Temporal CLI | récent | utile | docs.temporal.io/cli (`temporal server start-dev` évite Docker pour Temporal) |
| GitHub CLI (`gh`) | récent | utile | cli.github.com |
| Node.js LTS | récent | M5 (web) | nodejs.org |
| aws, az, kubectl, helm | récents | M3+ (bac à sable) | sites officiels |

## Pile de développement (M0-T03, M0-T03b)
- Prérequis, vérifiés par `make dev-preflight` et avant toute commande `docker` passée à `dev-env.sh run` : Docker Engine 28 ou plus avec le plugin compose v2, démon joint par un socket unix local (`DOCKER_HOST` vide ou de la forme `unix:///<chemin>`, contexte Docker courant de même forme). Un démon distant (TCP, TLS, `ssh://`) est refusé.
- `make dev` : vérifie Docker (`dev-preflight`), crée `.env.dev` s'il manque (secrets aléatoires, droits 600, ignoré par Git), démarre PostgreSQL, Temporal et OpenBao en mode dev (`bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml up -d --wait`), puis crée le namespace Temporal `rempart` (rétention 7 jours). Idempotent.
- Dans OpenBao, `make dev` monte aussi le moteur Transit, crée une clé `rempart-tenant-<id>` (AES-256-GCM, suppression interdite) pour le tenant de démo et pour le tenant système, et écrit la politique `rempart-worker` (enveloppe et déballage de clés de données seulement, M1-T01).
- Ports publiés sur `127.0.0.1` seulement : Temporal `7233`, OpenBao `8200`. PostgreSQL n'est pas publié.
- `make dev-down` arrête la pile et garde le volume de données. Réinitialisation complète : `bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml down -v`, puis supprimer `.env.dev`. Si `.env.dev` a été perdu alors que le volume `rempart-dev_pgdata` existe, `make dev` refuse de continuer : supprimer le volume (`docker volume rm rempart-dev_pgdata`), puis relancer.
- Toute commande compose s'écrit `bash scripts/dev-env.sh run docker compose -p rempart-dev --env-file .env.dev -f docker-compose.yml <sous-commande>` : `dev-env.sh` valide `.env.dev` et exporte ses valeurs, qui priment sur celles du shell ; `-p` fixe le projet ; le `-f` explicite empêche la fusion d'un fichier `override`. Les variables `COMPOSE_*` du shell (`COMPOSE_PROJECT_NAME`, `COMPOSE_FILE`, `COMPOSE_ENV_FILES`, etc.) sont ignorées : `dev-env.sh run` les retire avant d'exécuter la commande.
- Ne jamais afficher les secrets : pas de `cat .env.dev`, pas de sous-commande `config` de compose sans filtre `jq` ciblé, pas de `docker inspect` sans `--format` ciblé. Les journaux d'OpenBao sont coupés, car la bannière du mode dev affiche le jeton root.
- Tests d'intégration, en deux passes (`make verify` les enchaîne) : `go test -tags=integration $(go list ./... | grep -v '/internal/archtest$')`, sans aucun secret, puis `bash scripts/dev-env.sh run go test -count=1 -tags=integration ./internal/archtest`, seul paquet qui reçoit les valeurs de `.env.dev` (le script valide le fichier avant de les exporter).
- Windows : Docker Desktop appelé depuis Git Bash est joint par un pipe nommé (`npipe://`), refusé par `dev-preflight`. Méthode vérifiée le 2026-11-17 : tout lancer depuis WSL2 Ubuntu, dépôt cloné dans `~/rempart`, Docker Engine installé dans la distribution (`sudo apt install -y docker.io docker-compose-v2`, `sudo systemctl enable --now docker`, `sudo usermod -aG docker $USER`, puis `wsl --shutdown` dans PowerShell) ; systemd actif dans WSL (`[boot]` puis `systemd=true` dans `/etc/wsl.conf`) ; intégration WSL de Docker Desktop désactivée pour cette distribution. Les commandes `wsl` se tapent dans PowerShell, jamais dans Ubuntu (le paquet Ubuntu `wsl` est un autre outil).
- Docker Hub limite les téléchargements anonymes (erreur 429). Parade : démon lancé avec un miroir, par exemple `dockerd --registry-mirror=https://mirror.gcr.io`, ou `"registry-mirrors"` dans `/etc/docker/daemon.json`. Les images restent épinglées par empreinte `sha256`, le miroir ne peut donc pas en substituer une autre.

## Chaîne d'outils IaC (M3-T02, ADR 0014 D15)
- `make -f Makefile iac-tools` (une fois, puis à chaque changement du verrou) : `bash scripts/iac-tools.sh install` télécharge OpenTofu, tflint, ses rulesets AWS et Azure, Trivy et les providers `aws`, `azurerm` et `helm` du verrou `scripts/iac-tools.lock.json`, vérifie chaque archive et chaque binaire par SHA-256, puis `verify` revérifie tout le cache (SHA-256, et somme `h1:` de chaque provider) et refuse toute entrée du miroir que le verrou ne nomme pas. Le script relit le verrou sous sa grammaire fermée avant toute écriture (code 2 sinon). URL du verrou : `github.com` (actifs de releases du dépôt figé de chaque outil) et `releases.hashicorp.com` seulement ; GitHub redirige les actifs vers ses hôtes de stockage (`release-assets.githubusercontent.com` ou `objects.githubusercontent.com`), suivis en `https` seulement (`--proto-redir =https`), la somme SHA-256 du verrou faisant foi ; aucun registre (`registry.opentofu.org`, `registry.terraform.io`) n'est utilisé.
- Cache hors dépôt : `REMPART_IAC_CACHE`, sinon `~/.cache/rempart/iac-tools` (`bash scripts/iac-tools.sh env` affiche la valeur). Disposition : `tools/<outil>/<version>/`, `tflint-plugins/<source>/<version>/`, `mirror/` (miroir fichier des providers), `dl/<sha256>/` (archives). Plateforme : linux_amd64 seulement (WSL2 sur Windows).
- Rempart n'exécute jamais un outil depuis le cache : `validate.LoadToolchain` en fait une copie privée en lecture seule, vérifiée (de même pour les archives de providers : OpenTofu lit ce miroir privé, et le `.terraform.lock.hcl` de chaque racine est rendu depuis le verrou, menace T156), et `toolexec.Run` revérifie la somme avant chaque exécution, sans shell, avec un environnement construit (aucune variable `AWS_*`, `ARM_*`, `TF_*` ni mandataire hérités) et un mandataire injoignable.
- Tests d'intégration de la chaîne (`go test -tags=integration ./internal/validate/...`, inclus dans `make verify`) : ils échouent tant que `make iac-tools` n'a pas été lancé.
- Relecture humaine du verrou (étape H-tools-lock) : versions publiées depuis au moins 14 jours, sommes, et signatures notées dans chaque entrée. À confirmer depuis le poste de l'humain : l'empreinte de la clé GPG d'OpenTofu (`E3E6 E43D 84CB 852E ADB0 051D 0C0A F313 E5FD 9F80`) sur opentofu.org ; celle de HashiCorp (`C874 011F 0AB4 0511 0D02 1055 3436 5D94 72D7 468F`) sur hashicorp.com/security ; la signature sans clé de tflint 0.66.0 avec `cosign verify-blob --certificate checksums.txt.pem --signature checksums.txt.keyless.sig --certificate-identity https://github.com/terraform-linters/tflint/.github/workflows/release.yml@refs/tags/v0.66.0 --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt` (le journal de transparence n'est pas joignable depuis la session de l'agent).
- Trivy : jamais les versions 0.69.4 à 0.69.6 (attaque de la chaîne d'approvisionnement de mars 2026, avis GHSA-69fq-xp46-6x23) ; `TestIaCToolsLockPinned` les refuse.

## Isolation des outils (M3-T02b, ADR 0015)
- **Ce que fait Rempart.** Chaque exécution d'un outil de la chaîne (OpenTofu, tflint, Trivy, puis Checkov) passe par un assistant : le binaire Rempart lui-même, relancé dans de nouveaux espaces de noms (utilisateur, montage, réseau, PID, IPC, UTS, cgroup).
  - L'outil voit un arbre fermé : `/usr`, un `/etc` synthétique, un `/dev` minimal, son `/proc`, la copie privée de la chaîne d'outils et l'arbre de travail, en lecture seule ; `data/`, `HOME` et `TMPDIR` éphémères en écriture.
  - Il n'a aucun réseau, aucune capacité, aucun terminal, et ne voit aucun autre processus.
  - Landlock s'ajoute en renfort quand le noyau l'offre.
- **Échec fermé.** Sans isolation complète, aucun outil ne tourne. `rempart check --static` (M3-T03) reste utilisable.
- **Prérequis.** Un noyau Linux qui admet les espaces de noms utilisateur non privilégiés. Sur Ubuntu 24.04, AppArmor les restreint par défaut :
  - levée sur le poste : `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` ;
  - levée persistante : `echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/60-rempart-userns.conf`.

  Sur WSL2, le noyau est fourni par Microsoft : vérifier avec les commandes ci-dessous.
- **Sonde du poste (étape H-isolation-probe, avant le premier `rempart check` avec outils).** Lancer ces commandes et coller la sortie :
  - `uname -r`
  - `sysctl kernel.apparmor_restrict_unprivileged_userns`
  - `unshare -U -r -n -p -f --mount-proc true; echo rc=$?`
  - `cat /sys/kernel/security/lsm`
  - `REMPART_REQUIRE_SANDBOX=1 go test ./internal/validate/toolexec/ -run '^TestIsolation' -v`
- **Variable `REMPART_REQUIRE_SANDBOX`.**
  - Sans elle, un test d'isolation saute, avec la raison, quand le noyau n'offre pas l'isolation.
  - Avec `REMPART_REQUIRE_SANDBOX=1`, il échoue. La CI la pose (proposition 0014), et les critères de M3-T02b sont lancés avec elle.

## Evals sur un vrai modèle (M1, ADR 0008)
- Seulement depuis le terminal de l'humain, jamais depuis un agent ni la CI (refus dans le binaire). Route vérifiée de bout en bout le 2026-11-18 : `--llm openrouter --model openai/gpt-4o-2024-08-06`.
- Compte OpenRouter **crédité** : la limite de dépense d'une clé n'est pas un solde. Tant qu'aucun crédit n'est acheté (`"is_free_tier": true` sur `GET https://openrouter.ai/api/v1/key`), chaque appel est refusé par un 402 : OpenRouter réserve avant l'appel le coût maximal de la requête (8 192 tokens de sortie pour L1, environ 0,09 $ par appel sur GPT-4o). Prévoir environ 10 $ pour une calibration et une mesure de la suite `intent` (28 cas, 3 exécutions).
- La clé se saisit sans écho, jamais en clair sur la ligne de commande (elle resterait dans `~/.bash_history`) : `( read -rs -p "Clé OpenRouter : " K && export REMPART_LLM_KEY_OPENROUTER="$K" && go run ./cmd/rempart-evals --suite intent --llm openrouter --model openai/gpt-4o-2024-08-06 )`. Ajouter `--write-baseline` pour la calibration. Chaque lancement, mesure ou calibration, se confirme par `oui` sur le terminal ; une calibration sous le seuil du critère 1 de M1 (succès 0,9, résistance aux injections 1) n'écrit rien. Une calibration dont un appel échoue n'écrit rien et affiche les échecs par classe (`HTTP 402 ×81`, etc.).

## Comptes (avant M3)
Comptes bac à sable AWS et Azure dédiés, avec alertes de budget. Aucun identifiant dans le dépôt.
