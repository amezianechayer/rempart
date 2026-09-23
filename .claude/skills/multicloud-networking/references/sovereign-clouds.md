# Clouds souverains : Scaleway et OVHcloud

> Les capacités des providers OpenTofu de ces clouds évoluent vite. Avant d'implémenter un module, vérifier la documentation du provider et du service, et consigner dans un ADR : ressources disponibles, manques, contournements.

## Principes
- Même contrat de module que pour AWS/Azure (voir `secure-iac-generation/references/module-contract.md`) : chiffrement, journalisation, tags, pas d'exposition par défaut.
- Si un service managé manque (ex. VPN site à site managé), utiliser une passerelle IPsec auto-gérée durcie (strongSwan sur instance minimale, image durcie, mise à jour automatique, surveillance), documentée en ADR comme dette à résorber.
- Les collecteurs d'inventaire et les règles de politiques doivent couvrir ces clouds au même niveau : sinon A4 n'est pas tenu.

## Scaleway (provider `scaleway/scaleway`)
Briques à évaluer : Kubernetes Kapsule, Instances, VPC et Private Networks, Public Gateways, Load Balancer, Object Storage, bases managées, IAM (applications, politiques, clés API), Secret Manager, Cockpit (observabilité). Régions européennes (Paris, Amsterdam, Varsovie) : vérifier la liste courante.

## OVHcloud (providers `ovh/ovh` et OpenStack pour le Public Cloud)
Briques à évaluer : Managed Kubernetes Service, instances Public Cloud, vRack (réseau privé inter-services), réseaux privés, Load Balancer, Object Storage, bases managées, IAM. Certaines offres OVHcloud sont qualifiées SecNumCloud : vérifier lesquelles, dans quelles régions, et ce qui est pilotable en IaC.

## Autres pistes (hors MVP)
Outscale (qualifié SecNumCloud) et offres de cloud de confiance : à étudier si la découverte marché montre une demande SecNumCloud forte.
