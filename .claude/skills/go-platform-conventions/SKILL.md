---
name: go-platform-conventions
description: Conventions de code Go du backend Rempart (architecture hexagonale, ports et adaptateurs, erreurs, contexte et tenant, exécution de commandes sûre, tests unitaires, de propriété et d'intégration, Temporal, observabilité). À utiliser pour toute écriture ou modification de code Go dans cmd/ ou internal/, y compris les petites corrections.
---

# Conventions Go

## Référence
Arborescence type d'un domaine et exemple de port/adaptateur/faux : `references/hexagonal-layout.md`

## Structure
- `internal/<domaine>/` : `domain/` (types et logique pure, aucune dépendance externe), `ports/` (interfaces), `adapters/` (AWS, Azure, PostgreSQL, LLM, Git, OpenBao), `fake/` (implémentations déterministes pour les tests).
- La logique métier n'importe jamais un SDK cloud, le client LLM ou le driver SQL directement.

## Code
- Go 1.23+, `golangci-lint` strict (dont `gosec`, `errorlint`, `contextcheck`), `gofumpt`.
- `context.Context` en premier paramètre. Le tenant voyage dans le contexte **et** chaque frontière (handler, activité, requête SQL) vérifie explicitement sa présence et sa cohérence.
- Erreurs : `fmt.Errorf("...: %w", err)`, erreurs sentinelles par domaine, types d'erreur Temporal non rejouables pour les erreurs de validation. Pas de `panic` hors `init`.
- Pas d'état global ; configuration injectée ; pas de `init()` avec effet de bord.
- Journalisation `slog` structurée. Type `secret.Value` dont `String()`, `GoString()` et `MarshalJSON()` renvoient `[REDACTED]`.

## Exécution de commandes (`tofu`, scanners)
- `exec.CommandContext` avec arguments en tableau, **jamais** `sh -c`.
- Répertoire de travail éphémère par exécution, supprimé ensuite ; environnement minimal explicite (pas d'héritage de l'environnement du worker).
- Aucune donnée utilisateur ou cloud interpolée dans un nom de fichier ou un argument sans validation stricte (liste blanche de caractères).
- En production : exécution dans un conteneur sans privilège, système de fichiers en lecture seule sauf le répertoire de travail.

## Base de données
PostgreSQL avec row-level security par `tenant_id` ; la connexion applicative positionne le tenant par transaction. Migrations versionnées. Tests d'accès inter-tenant obligatoires.

## Tests
- Table-driven ; tests de propriété avec `pgregory.net/rapid` pour CIDR, permissions, atteignabilité, équivalence graphe/plan.
- Intégration derrière le build tag `integration`, avec testcontainers (PostgreSQL, Temporal).
- Workflows : `go.temporal.io/sdk/testsuite`.
- `govulncheck ./...` dans `make verify`.

## Observabilité
OpenTelemetry sur toutes les activités ; métriques Prometheus par boucle (`rempart_loop_iterations`, `rempart_loop_outcome_total{outcome}`, `rempart_loop_tokens_total`, `rempart_loop_duration_seconds`).
