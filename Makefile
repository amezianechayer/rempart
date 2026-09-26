# Rempart : vérification et outillage. Issu de Makefile.template (M0-T01).
# Le hook Stop exige `make verify-quick` : cette cible ne demande ni réseau ni Docker
# (hors premier téléchargement des modules Go et de la chaîne d'outils).
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := verify-quick

EVAL ?= all
POLICIES_DIR ?= policies
OPA ?= opa

# Variables fournies par l'appelant (menace T8). $(value ...) fige le texte brut : une valeur
# passée en ligne de commande, par exemple SCENARIO='$(shell ...)', n'est jamais développée
# par make. Les recettes les lisent par le shell ("$$VAR"), jamais par make.
override SCENARIO := $(value SCENARIO)
override EVAL := $(value EVAL)
override POLICIES_DIR := $(value POLICIES_DIR)
override OPA := $(value OPA)
export SCENARIO EVAL POLICIES_DIR OPA

.PHONY: verify-quick verify opa-test arch-test evals update-baseline
.PHONY: dev dev-preflight dev-down sandbox-guard sandbox-plan sandbox-apply sandbox-destroy

verify-quick:
	go build ./...
	golangci-lint run ./...
	go test -short ./...
	$(MAKE) --no-print-directory opa-test
	$(MAKE) --no-print-directory arch-test

verify: verify-quick
	go test -tags=integration ./...
	go tool govulncheck ./...

# Étape OPA active seulement s'il existe au moins un fichier .rego sous POLICIES_DIR.
# Dans ce cas, opa absent est une erreur : jamais de saut silencieux.
opa-test:
	@if [ -z "$$(find "$$POLICIES_DIR" -type f -name '*.rego' -print -quit 2>/dev/null)" ]; then \
		echo "opa-test : aucun fichier .rego sous $$POLICIES_DIR, étape OPA sans objet."; \
	elif ! command -v "$$OPA" >/dev/null 2>&1; then \
		echo "opa-test : fichiers .rego présents sous $$POLICIES_DIR mais $$OPA introuvable (voir docs/SETUP.md)." >&2; \
		exit 2; \
	else \
		"$$OPA" check "$$POLICIES_DIR"; \
		"$$OPA" test "$$POLICIES_DIR"; \
	fi

arch-test:
	go test -count=1 ./internal/archtest/...
	go tool workflowcheck -config workflowcheck.config.yaml ./internal/loops/...

# Evals : livrées par M0-T23 (cmd/rempart-evals). Avant : code 2, aucune action.
evals:
	@test -d cmd/rempart-evals || { echo "evals : indisponible avant M0-T23 (cmd/rempart-evals absent) ; aucune action." >&2; exit 2; }
	@[[ "$${EVAL:-}" =~ ^[a-z0-9][a-z0-9/_-]{0,126}$$ ]] || { echo "EVAL requis, au format [a-z0-9/_-] (ex. EVAL=demo)." >&2; exit 2; }
	go run ./cmd/rempart-evals --suite "$$EVAL"

# Réservé aux humains (bloqué pour l'agent par le hook guard_bash). Fonctionnel à partir de M0-T23.
update-baseline:
	@test -d cmd/rempart-evals || { echo "update-baseline : indisponible avant M0-T23 (cmd/rempart-evals absent) ; aucune action." >&2; exit 2; }
	@[[ "$${EVAL:-}" =~ ^[a-z0-9][a-z0-9/_-]{0,126}$$ ]] || { echo "EVAL requis, au format [a-z0-9/_-] (ex. EVAL=demo)." >&2; exit 2; }
	go run ./cmd/rempart-evals --suite "$$EVAL" --write-baseline

# Pile de développement : livrée par M0-T03 (docker-compose.yml, dev-preflight en prérequis).
dev:
	@echo "dev : pile de développement livrée par M0-T03 (docker-compose.yml absent) ; aucune action." >&2
	@exit 2

# Vérifie Docker Engine, le plugin compose v2 et l'accès au démon, sans rien démarrer.
dev-preflight:
	@docker compose version >/dev/null 2>&1 || { echo "dev-preflight : Docker Engine et le plugin compose v2 sont requis (voir docs/SETUP.md)." >&2; exit 2; }
	@docker info >/dev/null 2>&1 || { echo "dev-preflight : démon Docker injoignable (voir docs/SETUP.md)." >&2; exit 2; }
	@echo "dev-preflight : Docker et compose v2 disponibles."

# Arrêt idempotent : rien à arrêter tant que M0-T03 n'a pas livré docker-compose.yml.
dev-down:
	@echo "dev-down : aucune pile à arrêter avant M0-T03 (docker-compose.yml absent)."

# Garde des trois cibles de bac à sable (scripts/sandbox.sh arrive en M3).
# Prérequis : s'exécute avant toute validation et toute question interactive.
sandbox-guard:
	@test -e scripts/sandbox.sh || { echo "sandbox : scripts/sandbox.sh absent (livré en M3) ; aucune action." >&2; exit 2; }
	@test -x scripts/sandbox.sh || { echo "sandbox : scripts/sandbox.sh non exécutable ; aucune action." >&2; exit 2; }

sandbox-plan: sandbox-guard
	@[[ "$${SCENARIO:-}" =~ ^[a-z0-9][a-z0-9-]{0,62}$$ ]] || { echo "SCENARIO requis, au format [a-z0-9-] (ex. SCENARIO=demo)." >&2; exit 2; }
	./scripts/sandbox.sh plan "$$SCENARIO"

# Approbation humaine exigée deux fois : permission "ask" de Claude Code ET confirmation
# tapée au terminal (lue sur /dev/tty : un tube sur l'entrée standard ne suffit pas).
sandbox-apply: sandbox-guard
	@[[ "$${SCENARIO:-}" =~ ^[a-z0-9][a-z0-9-]{0,62}$$ ]] || { echo "SCENARIO requis, au format [a-z0-9-] (ex. SCENARIO=demo)." >&2; exit 2; }
	@read -r -p "Appliquer $$SCENARIO sur le compte SANDBOX ? Tape 'oui' : " a </dev/tty; [ "$$a" = "oui" ]
	./scripts/sandbox.sh apply "$$SCENARIO"

sandbox-destroy: sandbox-guard
	@[[ "$${SCENARIO:-}" =~ ^[a-z0-9][a-z0-9-]{0,62}$$ ]] || { echo "SCENARIO requis, au format [a-z0-9-] (ex. SCENARIO=demo)." >&2; exit 2; }
	@read -r -p "Détruire $$SCENARIO sur le compte SANDBOX ? Tape 'oui' : " a </dev/tty; [ "$$a" = "oui" ]
	./scripts/sandbox.sh destroy "$$SCENARIO"
