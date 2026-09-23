# Modèle de graphe Rempart

Un seul modèle pour le graphe **conçu** (L2) et le graphe **réel** (L6), afin de calculer le diff conçu/réel. Schéma JSON versionné dans `schemas/graph/v1.json`.

## Nœuds
| kind | Attributs obligatoires | Remarques |
|---|---|---|
| Account | cloud, account_id, tenant_id | Compte AWS, abonnement Azure, projet Scaleway/OVHcloud |
| Identity | subtype (user, role, service_principal, managed_identity, k8s_service_account), privileged (bool calculé) | |
| Policy | document (normalisé), attached_to | |
| Compute | subtype (vm, container, function, node), public_ip (bool) | |
| Network | subtype (vpc, vnet, subnet), cidr, tier | |
| SecurityRule | direction, action, protocol, ports, sources | |
| LoadBalancer | public (bool), listeners | |
| DataStore | subtype, classification, encrypted (bool), public_access (bool) | classification issue de l'IR ou déclarée par le client, jamais devinée par le LLM |
| Secret | store, rotation_days | jamais la valeur |
| K8sCluster, K8sNamespace, K8sWorkload | api_public (bool), version | |
| Internet | | nœud unique, source des chemins externes |

Tous les nœuds : `id` stable, `source` (`design` ou `observed`), `observed_at`, `untrusted_text` (dictionnaire des chaînes brutes issues du cloud, pour affichage seulement).

## Arêtes
| type | Sens | Attributs |
|---|---|---|
| CAN_ASSUME | Identity vers Identity | conditions résolues |
| HAS_PERMISSION | Identity vers ressource | actions effectives, `ambiguous` (bool) |
| CAN_REACH | nœud vers nœud | protocole, port, chemin réseau (liste d'ids) |
| EXPOSES | LoadBalancer ou Compute vers Internet | port |
| STORES | DataStore vers donnée classée | |
| RUNS_AS | Compute ou K8sWorkload vers Identity | |
| MEMBER_OF | ressource vers Network ou Account | |
| MANAGED_BY_IAC | ressource vers fichier IaC | repo, chemin, module, lignes, commit |

## Invariants testés
- Aucune arête `CAN_REACH` sans chemin réseau justificatif.
- Aucune arête `HAS_PERMISSION` sans trace de la politique source.
- Le diff conçu/réel liste : ressources réelles absentes du conçu (dérive ou shadow IT), arêtes réelles absentes du conçu (ouverture non prévue).
