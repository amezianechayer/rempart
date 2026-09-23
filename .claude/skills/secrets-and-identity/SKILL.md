---
name: secrets-and-identity
description: Gestion des secrets (OpenBao), identités et accès de Rempart aux clouds clients (rôles en lecture seule, écriture éphémère dérivée du plan, ExternalId, fédération d'identité, mode runner), identités de workload, rotation, signature des plans. À utiliser pour tout travail sur internal/secrets, internal/tenancy, internal/runner, l'onboarding d'un compte cloud, ou tout code qui manipule un identifiant ou un secret.
---

# Secrets et identités

## Référence
Schémas d'accès inter-comptes et d'onboarding par cloud : `references/cross-account-access.md`

## Règles
1. **Aucun identifiant long terme** stocké par Rempart pour accéder à un cloud client. AWS : AssumeRole avec ExternalId unique par tenant (protection contre le « confused deputy »). Azure : fédération d'identité de charge de travail (OIDC) vers une application ou identité managée du client. Scaleway/OVHcloud : utiliser les mécanismes les moins privilégiés disponibles, documentés en ADR, avec rotation automatique.
2. **Deux rôles séparés** par compte client : lecture (scan, inventaire) et écriture (apply). Le rôle d'écriture n'est jamais utilisé par le plan de contrôle en mode runner.
3. **Portée dérivée du plan** : pour chaque apply, les permissions de session sont calculées à partir des ressources et actions du plan (session policy AWS, portée d'attribution temporaire côté Azure si disponible), durée courte.
4. **OpenBao** pour les secrets de Rempart et les secrets générés (clés pré-partagées VPN, mots de passe de bases) ; moteurs dynamiques quand c'est possible ; jamais de secret dans l'état OpenTofu en clair, les logs, les traces, les prompts, les erreurs.
5. **Signature des plans** : clé asymétrique par tenant dans un KMS/HSM ; la clé privée ne quitte jamais le KMS ; rotation planifiée ; le runner connaît les clés publiques valides.
6. **Onboarding** guidé par un modèle IaC que le client applique lui-même (CloudFormation/OpenTofu pour AWS, Bicep/OpenTofu pour Azure) : le client voit exactement les permissions accordées.
