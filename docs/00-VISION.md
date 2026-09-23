# Rempart : vision, positionnement, principes, architecture

> Document de référence stable. Les prompts de jalon (`prompts/`) et les skills s'y réfèrent. Toute modification passe par un ADR.

## 1. Mission

Rempart transforme une intention en langage naturel en infrastructure multicloud :
1. **conçue sécurisée avant d'être écrite** (modèle de menace et politiques évalués sur le graphe d'architecture),
2. **générée en IaC** OpenTofu et validée par une chaîne déterministe,
3. **déployée avec preuves** (chaque changement porte un dossier de preuves signé),
4. **surveillée en continu** (graphe de sécurité, chemins d'attaque validés sans action destructive),
5. **corrigée en boucle fermée** (finding, correctif IaC, re-scan, preuve de résolution),
6. **auditable** (preuves de conformité générées en continu).

L'IaC dans Git est la source de vérité. Rempart ne fait jamais de modification hors IaC.

## 2. Positionnement

Le marché converge depuis deux bouts sans fermer la boucle :
- agents de provisioning (Pulumi Neo, StackGen, Spacelift Intent, agents de code + Terraform) : ils construisent, la sécurité vient après ;
- plateformes de sécurité (Wiz et ses agents Red/Blue/Green, Datadog, Prisma) : elles détectent et délèguent la correction.

Rempart gagne sur sept axes. Toute fonctionnalité doit en renforcer au moins un.

| Axe | Promesse |
|---|---|
| A1 Sécurité par construction | Menaces et politiques évaluées sur l'architecture avant le code |
| A2 Boucle fermée prouvée | Aucun finding résolu sans re-scan qui le confirme |
| A3 Changements porteurs de preuves | Plan, diff de graphe, delta de menace, politiques, coût, rayon d'impact, signés |
| A4 Clouds souverains natifs | OVHcloud et Scaleway au même niveau qu'AWS et Azure |
| A5 Conformité native | NIS2, DORA, SecNumCloud, ISO 27001, CIS en contrôles exécutables |
| A6 Confiance par architecture | **Mode runner** : le plan de contrôle de Rempart ne détient jamais d'identifiant d'écriture ; un runner dans l'environnement du client exécute uniquement des plans signés et approuvés. Auto-hébergeable. Modèle LLM configurable, option UE |
| A7 Accessible | Utilisable par une ETI sans équipe plateforme, tarifé pour elle |

Cible initiale (à confirmer par `docs/03-DISCOVERY.md`) : ETI et PME européennes régulées (fintech, santé, secteur public, entités NIS2) sans budget Wiz ni équipe plateforme.

## 3. Principes non négociables

1. **Cœur déterministe, LLM en périphérie.** Le LLM traduit, propose, explique. Validation, politiques, permissions effectives, atteignabilité, classification du risque et décisions d'approbation sont du code déterministe testé.
2. **Tout passe par un vérificateur** indépendant du proposeur.
3. **Moindre privilège pour Rempart lui-même** : lecture seule pour le scan, écriture éphémère dérivée du plan, jamais d'identifiant long terme.
4. **Validation offensive non destructive** : raisonnement sur graphe et sondes passives, sur le périmètre du tenant propriétaire uniquement. Aucun code d'exploitation, aucune charge utile, aucune écriture.
5. **Toute donnée issue du cloud est non fiable** pour le LLM (noms, tags, descriptions, logs peuvent contenir des injections). Voir skill `llm-safety`.
6. **Autonomie graduée et réversible** (L0 à L3), coupe-circuit client.
7. **Échec sûr** : erreur, timeout ou approbation absente mènent à « ne rien faire ».
8. **Isolation stricte par tenant**, testée par des tests d'accès croisé.
9. **Pas de secret dans un prompt, un log, une trace ou un état en clair.**

## 4. Architecture

### Stack
Go 1.23+ (hexagonal) ; Temporal (boucles durables) ; OpenTofu ; OPA/Rego et Conftest ; tflint, Checkov, Trivy, Infracost ; PostgreSQL + Apache AGE pour le graphe (derrière une interface) ; OpenBao pour les secrets ; API Anthropic via SDK Go derrière `ModelProvider` ; Next.js ; CLI Go ; serveur MCP ; OpenTelemetry, Prometheus, Grafana, Loki ; Kubernetes + ArgoCD pour le déploiement de Rempart et comme cible gérée.

### Modules
```
cmd/            rempartd (API), rempart-worker (Temporal), rempart-runner (côté client), rempart (CLI), rempart-mcp
internal/
  intent/       Intent IR, NL vers IR, clarifications
  design/       graphe d'architecture, planification CIDR, patterns
  threat/       STRIDE sur le graphe d'architecture
  policy/       moteur OPA, packs, mapping conformité
  iacgen/       génération OpenTofu depuis le graphe validé
  validate/     chaîne de validation, normalisation des erreurs
  plan/         plan, rayon d'impact, risque, équivalence graphe/plan
  apply/        orchestration de l'apply (via runner), vérifications post-déploiement, rollback
  runner/       protocole runner : récupération de plans signés, exécution, attestations
  inventory/    collecteurs (aws, azure, ovh, scaleway, kubernetes)
  graph/        graphe de sécurité unifié, atteignabilité, permissions effectives
  attackpath/   chemins d'attaque non destructifs
  remediate/    finding vers source IaC vers correctif vers PR
  drift/        dérive
  finops/       coûts, anomalies, recommandations
  compliance/   contrôles, preuves, exports
  evidence/     dossiers de preuves signés, journal chaîné
  loops/        un workflow Temporal par boucle
  llm/          ModelProvider, prompts versionnés, rédaction, quarantaine des données non fiables
  secrets/      intégration OpenBao, identifiants dynamiques
  tenancy/      isolation, RBAC, identités
policies/       design/, iac/, runtime/, k8s/ + tests
modules/        modules OpenTofu internes + tests
schemas/        JSON Schemas versionnés (intent, graph, evidence, findings)
evals/          jeux d'évaluation par boucle + labo vulnérable
web/            interface
```

### Mode runner (A6)
- Le plan de contrôle calcule, valide, fait approuver et **signe** un plan (hash du plan OpenTofu + périmètre d'identifiants + approbations).
- Le runner, déployé dans le compte ou le cluster du client, tire les plans signés (connexion sortante uniquement), vérifie la signature et l'approbation, obtient lui-même des identifiants éphémères localement, exécute, renvoie une attestation (sorties, hash d'état, résultats de vérification).
- Conséquence : une compromission du plan de contrôle ne donne pas d'accès en écriture aux clouds clients.
- Le mode « hébergé » (plan de contrôle qui assume un rôle client) existe pour les petits clients, avec rôles éphémères et ExternalId.

## 5. Boucles
Spécifiées dans `docs/01-LOOPS.md` (L1 à L10).

## 6. Hors périmètre initial
GCP, bases de données on-premise, conformité organisationnelle (Rempart liste ces contrôles comme hors périmètre, sans prétendre les couvrir), tests d'intrusion actifs.
