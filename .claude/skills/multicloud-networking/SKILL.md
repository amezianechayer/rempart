---
name: multicloud-networking
description: Conception réseau multicloud sûre pour Rempart (planification CIDR déterministe, VPC/VNet, segmentation par tiers, VPN site à site AWS/Azure/Scaleway/OVHcloud, BGP, DNS privé, egress, atteignabilité). À utiliser dès qu'une tâche touche le graphe réseau, internal/design/cidr, internal/graph/reach, les modules réseau OpenTofu, l'interconnexion entre clouds ou les règles de pare-feu, même pour un simple ajout de sous-réseau.
---

# Réseau multicloud

Zone où les agents IA se trompent le plus. Tout ce qui suit est vérifié de façon déterministe, jamais laissé au jugement du LLM.

## Références et outils
- Vérificateur CIDR de référence (et générateur de tests de propriété) : `scripts/cidr_check.py`. Usage : `python3 scripts/cidr_check.py plan.json` ou `--selftest 1000`. L'implémentation Go de `internal/design/cidr` doit passer les mêmes cas.
- Interconnexion AWS/Azure pas à pas : `references/aws-azure-vpn.md`
- Scaleway et OVHcloud : `references/sovereign-clouds.md`

## Planification CIDR
- Allocateur central par tenant : superbloc privé (défaut 10.0.0.0/8) découpé par cloud, puis région, puis environnement, puis tier.
- Garanties : aucun chevauchement entre réseaux du tenant, y compris ceux découverts par l'inventaire et les plages on-premise déclarées ; tout sous-réseau est inclus dans son parent ; marge de croissance x4 par défaut.
- Tailles compatibles avec les services : avec le CNI VPC d'EKS, chaque pod consomme une IP du VPC, dimensionner large ou activer la délégation de préfixes ; le `GatewaySubnet` Azure doit exister et être dimensionné selon la recommandation Microsoft (/27 ou plus).

## Segmentation par défaut
- Tiers : `public` (LB, NAT uniquement), `app`, `data` (aucune route vers Internet), `mgmt`.
- Deny par défaut (security groups, NSG, pare-feu). Chaque autorisation = une arête explicite du graphe d'architecture, avec justification.
- Pas de `0.0.0.0/0` en entrée hors LB/WAF déclarés dans l'IR. Administration via accès identitaire (AWS SSM, Azure Bastion), jamais SSH/RDP public.
- Egress des tiers sensibles via NAT + liste d'autorisations.

## Interconnexion inter-cloud
- Deux tunnels IPsec minimum par lien, BGP recommandé, ASN distincts et documentés.
- Paramètres IKE/IPsec explicites et identiques des deux côtés. Jamais de défauts implicites.
- Clés pré-partagées générées et stockées dans OpenBao, jamais en clair dans l'IaC ni dans un état non chiffré.
- **Vérification post-déploiement obligatoire** : tunnels UP, routes BGP attendues apprises, connectivité attendue OK, **connectivité interdite effectivement bloquée**.

## DNS
Zones privées par cloud, résolution conditionnelle inter-cloud explicite, aucun nom interne dans le DNS public.

## Atteignabilité (`internal/graph/reach`)
Calcul déterministe depuis : tables de routage, security groups/NSG, NACL, pare-feu, peering/VPN, IP publiques, LB, Kubernetes NetworkPolicy. **Une seule implémentation** utilisée par L2 (conception), L5 (vérification post-déploiement) et L6 (chemins d'attaque). Tests de propriété : ajouter une règle deny ne crée jamais de chemin ; retirer une route ne crée jamais de chemin.
