# Interconnexion AWS / Azure par VPN site à site

> Référence de conception. Vérifier chaque paramètre dans la documentation officielle AWS et Microsoft au moment de l'implémentation : les SKU, plages et défauts évoluent. Consigner la version des docs consultées dans l'ADR du module.

## Topologie haute disponibilité (recommandée)
- Azure : VPN Gateway **active-active** (deux IP publiques), SKU compatible BGP (pas le SKU Basic), dans un `GatewaySubnet` dédié.
- AWS : une Virtual Private Gateway (ou une Transit Gateway si plusieurs VPC), **deux Customer Gateways** (une par IP publique Azure), donc **deux connexions VPN** de deux tunnels chacune : **quatre tunnels**.
- Azure : une Local Network Gateway par tunnel AWS (IP publique du tunnel + paramètres BGP), une connexion par Local Network Gateway.

## BGP
- ASN côté AWS (Amazon side ASN) et ASN côté Azure **distincts**. Les défauts courants sont 64512 (AWS) et 65515 (Azure) : les rendre explicites dans l'IaC.
- Adresses de peering dans l'espace link-local 169.254.0.0/16 : AWS attend un /30 par tunnel ; Azure impose une plage APIPA spécifique pour ces adresses personnalisées (vérifier la plage autorisée dans la doc Azure). Choisir des /30 compatibles des deux côtés et les allouer via l'allocateur, pas à la main.

## IKE/IPsec
- IKEv2, chiffrement AES-256 (GCM de préférence si supporté des deux côtés), intégrité SHA-256 ou mieux, groupe DH moderne, PFS activé.
- Côté Azure, définir une **politique IPsec personnalisée** sur la connexion ; côté AWS, restreindre les options de tunnel aux mêmes algorithmes. Des défauts divergents sont la première cause de tunnels instables.
- Clés pré-partagées générées aléatoirement, stockées dans OpenBao, injectées via des références ; rotation documentée.

## Routage et sécurité
- Propagation de routes : n'annoncer que les préfixes nécessaires (pas le superbloc entier).
- Security groups et NSG : n'autoriser à travers le VPN que les flux de l'IR (`connectivity[].ports`).
- Journalisation des tunnels activée des deux côtés, alertes sur tunnel DOWN.

## Vérifications post-déploiement (L5)
1. Les quatre tunnels sont UP (APIs AWS et Azure).
2. Les routes BGP attendues sont apprises des deux côtés, et seulement elles.
3. Connectivité attendue : tests depuis un pod ou une VM de test vers chaque port autorisé.
4. Connectivité interdite : un port non déclaré est bien bloqué.
5. Bascule : couper un tunnel (en sandbox) ne coupe pas la connectivité.
