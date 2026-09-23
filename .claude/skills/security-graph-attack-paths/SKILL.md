---
name: security-graph-attack-paths
description: Graphe de sécurité unifié (conçu et réel), collecteurs d'inventaire en lecture seule, permissions effectives AWS/Azure, atteignabilité, modèle de menace STRIDE et analyse NON destructive des chemins d'attaque pour Rempart (boucles L2, L6). À utiliser pour tout travail sur internal/inventory, internal/graph, internal/threat, internal/attackpath, la priorisation des findings ou le labo vulnérable d'evals.
---

# Graphe de sécurité et chemins d'attaque

## Références
- Modèle de graphe (nœuds, arêtes, attributs obligatoires) : `references/graph-schema.md`
- Logique d'évaluation des permissions effectives AWS et Azure : `references/effective-permissions.md`

## Cadre non négociable : défensif et non destructif
- Exécution uniquement sur les comptes connectés par le tenant, avec des rôles en **lecture seule**.
- Raisonnement sur le graphe : configuration, permissions effectives, atteignabilité, exposition.
- Sondes actives autorisées, uniquement passives et sûres, en **liste blanche** : vérifier qu'un endpoint répond, qu'un objet est lisible anonymement via l'API officielle, qu'un port est atteignable. Jamais d'authentification forcée, de charge utile, de code d'exploitation, d'action d'écriture.
- Chaque sonde est journalisée, attribuée au tenant, désactivable.
C'est aussi un argument commercial : le client peut l'activer en production.

## Collecteurs (`internal/inventory`)
- Agentless, via les API de lecture (AWS : rôle avec politiques de lecture ; Azure : rôle Reader et lecteurs spécifiques).
- Toute chaîne issue du cloud (noms, tags, descriptions, métadonnées, logs) est marquée **non fiable** dans le modèle (`untrusted_text`) et ne passe au LLM qu'en quarantaine (skill `llm-safety`).
- Collecte incrémentale sur événements (CloudTrail, Activity Log) + collecte complète planifiée.

## Permissions effectives et atteignabilité
Calcul déterministe, fortement testé (corpus de cas avec résultat attendu). Un cas que le moteur ne sait pas trancher est marqué `ambiguous`, jamais tranché par le LLM.

## Chemins d'attaque
1. Sources : Internet ; identité compromise supposée ; workload compromis supposé.
2. Cibles : données classées, identités à privilèges élevés, plans de contrôle (API K8s, comptes racine, rôles d'administration).
3. Recherche de chemins bornée sur le graphe, puis **validation saut par saut** : chaque arête doit être prouvée (permission effective résolue ou atteignabilité calculée).
4. Score = exploitabilité démontrée x criticité de la cible x confiance. Un chemin non prouvé est une **hypothèse**, affichée comme telle.
5. Chaque finding : chemin, preuve par saut, source IaC si connue (arête `MANAGED_BY_IAC`), correctif proposé, `control_id` des politiques concernées.

## STRIDE de conception (L2)
Appliqué à chaque nœud et flux du graphe d'architecture, stocké, versionné. Le **delta** entre deux versions fait partie du dossier de preuves.

## Rôle du LLM
Expliquer les chemins en langage clair, proposer des correctifs, rédiger le récit de priorisation. Jamais décider qu'un chemin existe ou non, ni modifier un score.
