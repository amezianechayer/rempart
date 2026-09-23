# Accès inter-comptes

> Vérifier les mécanismes et leurs limites dans la documentation officielle de chaque cloud au moment de l'implémentation.

## AWS
- Le client crée (via le modèle d'onboarding) :
  - `RempartReadOnly` : politiques de lecture (en partant de `SecurityAudit` et `ViewOnlyAccess`, complétées si nécessaire), relation de confiance vers le compte Rempart avec condition `sts:ExternalId` égale à l'identifiant unique du tenant.
  - `RempartApply` (mode hébergé uniquement) : permissions d'écriture bornées par une **permission boundary** définie par le client ; chaque session est encore réduite par une session policy dérivée du plan.
- Mode runner : le runner tourne dans le compte client (tâche ECS, pod EKS ou instance) avec une identité locale ; aucune relation de confiance d'écriture vers Rempart.

## Azure
- Application Entra ID ou identité managée côté client, avec **identifiants fédérés** (OIDC) faisant confiance à l'émetteur de jetons de Rempart pour un sujet propre au tenant. Pas de secret client.
- Rôle Reader (et lecteurs de sécurité nécessaires) pour le scan ; rôle d'écriture à portée limitée (groupe de ressources dédié quand c'est possible) pour le mode hébergé.
- Mode runner : identité managée du runner dans l'abonnement client.

## Vérifications automatiques à l'onboarding
- Le rôle de lecture ne permet aucune action d'écriture (test via simulation de politique quand disponible).
- L'ExternalId ou le sujet fédéré est bien propre au tenant.
- Le rôle d'écriture est absent en mode runner.
