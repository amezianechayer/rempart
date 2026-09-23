---
name: safe-autonomy
description: Niveaux d'autonomie L0 à L3, classification déterministe du risque, rayon d'impact, approbations liées au hash du plan, mode runner, identifiants éphémères, rollback et coupe-circuit pour Rempart (boucles L4, L5). À utiliser pour tout ce qui décide si un changement peut être appliqué, qui l'approuve, avec quels droits, et comment l'annuler.
---

# Autonomie sûre

## Références
- Règles de classification du risque (point de départ exécutable) : `references/risk-rules.yaml`

## Niveaux (par tenant et environnement)
- **L0 Suggestion** : Rempart propose, l'humain fait tout.
- **L1 PR** : PR avec dossier de preuves ; merge et apply humains. **Défaut en production.**
- **L2 Apply approuvé** : après approbation dans Rempart, le runner applique, vérifie, et annule si échec.
- **L3 Auto faible risque** : sans approbation, uniquement pour les changements classés `low` par les règles.

## Classification du risque (`internal/plan/risk`)
Déterministe, à partir du plan, du graphe avant/après, de l'environnement et de la criticité. Le niveau retenu est le **maximum** des règles déclenchées. Le LLM peut expliquer, jamais abaisser.

## Approbations
- Liées au **hash exact** du plan et au périmètre d'identifiants dérivé.
- `high` : réauthentification de l'approbateur. `critical` : deux approbateurs distincts, dont un rôle sécurité.
- L'approbateur ne peut pas être l'auteur de la demande pour `high` et `critical`.

## Mode runner et identifiants
- Plan signé par le plan de contrôle (clé KMS/HSM) ; le runner vérifie signature, approbations et hash avant tout.
- Le runner obtient localement des identifiants éphémères dont les permissions sont **générées depuis le plan** (actions et ressources nécessaires uniquement), courte durée, journalisés.
- En mode hébergé (sans runner) : AssumeRole avec ExternalId, ou fédération d'identité, même périmètre dérivé.

## Rollback
- Avant apply : plan de retour (révision IaC précédente) calculé et vérifié par `tofu plan`.
- Échec des vérifications post-déploiement : rollback automatique en L2/L3, alerte en L1.
- Opération destructive sur des données : snapshot préalable obligatoire, sinon blocage.

## Coupe-circuit
Le client peut geler toute écriture en un clic (plan de contrôle) et localement (runner). Retour immédiat en L0.
