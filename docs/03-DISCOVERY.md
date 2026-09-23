# Découverte marché (à faire par toi, en parallèle de M0 à M2)

Le code ne dira pas si le marché existe. Cette phase décide si la cible, le positionnement et le périmètre du MVP sont les bons. Elle se fait avec des humains, pas avec Claude Code.

## 1. Hypothèses à confirmer ou tuer
| # | Hypothèse | Signal qui la confirme | Signal qui la tue |
|---|---|---|---|
| H1 | Les ETI soumises à NIS2/DORA peinent à prouver la sécurité technique de leur cloud | Ils décrivent un audit récent douloureux, des preuves assemblées à la main | « Notre outil actuel le fait très bien » |
| H2 | Elles n'ont pas les moyens de Wiz ni une équipe plateforme | Budget sécurité cloud limité, 0 à 2 personnes sur l'infra | Ils ont déjà Wiz ou équivalent et en sont satisfaits |
| H3 | Laisser un agent modifier l'infra est acceptable si le client garde l'exécution (mode runner) et les approbations | Intérêt concret pour le mode runner | Refus de principe de toute automatisation d'écriture |
| H4 | Les clouds souverains (OVHcloud, Scaleway) sont un vrai critère d'achat | Exigences contractuelles ou réglementaires de localisation | Tout le monde est sur AWS/Azure et s'en satisfait |
| H5 | La valeur perçue est dans « conforme et prouvé », plus que dans « déployé vite » | Ils parlent d'audit, d'assureur cyber, de clients qui exigent des preuves | Ils parlent surtout de vitesse de livraison |

## 2. Qui interroger (10 à 15 entretiens)
RSSI, responsables infrastructure et CTO d'ETI de 50 à 1 000 personnes : fintech et assurtech, santé et medtech, éditeurs SaaS B2B vendant aux grands comptes, sous-traitants d'entités essentielles NIS2, collectivités. Commence par ton réseau Epitech et d'alternance, puis LinkedIn, meetups sécurité et cloud à Marseille et Aix, communautés OVHcloud et Scaleway.

## 3. Guide d'entretien (parler du passé, pas de ton idée)
Ne présente pas Rempart avant la fin. Des questions sur ce qu'ils ont fait, pas sur ce qu'ils feraient.
1. Racontez-moi la dernière fois que vous avez dû prouver la sécurité de votre infrastructure cloud (audit, client, assureur). Comment ça s'est passé ?
2. Qu'est-ce qui a pris le plus de temps ? Qui l'a fait ?
3. Comment savez-vous aujourd'hui qu'aucune ressource n'est exposée par erreur ? Quand avez-vous découvert la dernière ?
4. Comment se passe un changement d'infrastructure, de la demande à la production ?
5. Quels outils avez-vous essayés ou achetés pour ça ? Pourquoi gardés ou abandonnés ?
6. Combien ça vous coûte aujourd'hui (outils, jours-homme, consultants) ?
7. Qui déciderait d'un tel achat, et sur quel budget ?
Fin : présente l'idée en deux phrases, observe la réaction, demande « qu'est-ce qui vous empêcherait de l'utiliser ? ».

## 4. Critères de décision
- Au moins 6 entretiens sur 12 confirment H1 et H2 avec une douleur récente et chiffrable : continuer.
- H3 rejetée par la majorité : repositionner vers un produit en lecture seule + PR (L0/L1) d'abord.
- H4 non confirmée : sortir OVHcloud et Scaleway du MVP, les garder en feuille de route.
- Objectif de sortie : 2 à 3 **design partners** qui acceptent de tester sur un environnement réel non critique, contre accès gratuit et influence sur la feuille de route.

## 5. Hypothèses de prix à tester (pas à annoncer)
Par environnement cloud géré ou par nombre de ressources, avec un palier ETI nettement sous les solutions grands comptes. Teste la réaction à une fourchette, ne fixe rien avant les design partners.

## 6. Journal
Consigne chaque entretien dans `docs/discovery/AAAA-MM-JJ-<secteur>.md` (sans nom de personne ni d'entreprise si non autorisé) : contexte, douleurs citées, outils, budget, verbatims clés, hypothèses touchées.
