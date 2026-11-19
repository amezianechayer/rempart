# Modèle de graphe Rempart

Un seul modèle pour le graphe **conçu** (L2) et le graphe **réel** (L6), afin de calculer le diff conçu/réel. Schéma JSON versionné dans `schemas/graph/v1.json`.

## État de v1 (M2, ADR 0010)

Les tables plus bas décrivent la cible (L3, L6). Le schéma v1 en porte aujourd'hui le sous-ensemble suivant ; tout autre élément arrive par amendement de l'ADR 0010 ou par une version suivante (règle de version de D5).

- **Nœuds** : `Internet` (identifiant `internet`), `Network` (`net:`), `Compute`, `K8sCluster`, `K8sWorkload`, `LoadBalancer` (`lb:` pour une exposition), `DataStore` (`wl:` ou `data:`), `Identity` (`id:`, sous-type `role` ou `k8s_service_account`, `cloud`, `credential` dans `workload_identity` et `static_key`), `Account` (`acct:`, `cloud`).
- **Arêtes** : `MEMBER_OF`, `EXPOSES` (`LoadBalancer` ou `Compute` vers Internet), `CAN_REACH` (protocole, `port_from`, `port_to`, chemin de nœuds `Network`), `STORES` (hôte vers donnée), `RUNS_AS` (`Compute`, `K8sCluster` ou `K8sWorkload` vers `Identity`), `HAS_PERMISSION` (`Identity` vers `DataStore`, `Account` ou `K8sCluster`, `actions` abstraites `read`, `write`, `admin`, `*`, jamais une action IAM concrète avant L3).
- **Attributs de sécurité**, requis là où ils s'appliquent et refusés ailleurs : `public_ip` (`Compute`), `public_access` (`DataStore`), `api_public`, `api_allowed_sources`, `audit_log`, `secrets_encryption`, `network_policy_default_deny`, `admission_policy`, `workload_identity` (`K8sCluster`), `public` et `listeners` (`LoadBalancer`, cohérents avec ses `EXPOSES`).
- **Sources** : préfixes IPv4 canoniques de longueur 1 à 32 ; tout Internet s'écrit par une liste vide, jamais `0.0.0.0/0`.
- **Texte libre** : seulement sous `untrusted_text`, 500 caractères au plus, sans caractère de contrôle ni bidirectionnel.
- **Atteignabilité** : `internal/graph/reach` lit un `FactsGraph` (jamais le texte libre) par la table fermée R1 à R6 de l'ADR 0010 (D2), sans deny implicite ; un attribut absent est lu au plus large.
- **Pas encore en v1** : `Policy`, `Secret`, `SecurityRule`, `K8sNamespace`, `CAN_ASSUME`, `MANAGED_BY_IAC`, `ambiguous`, `observed_at`, sources IPv6.

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
