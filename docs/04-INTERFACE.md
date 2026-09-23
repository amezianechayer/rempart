# Interfaces et expérience utilisateur

Spécification de référence des interfaces de Rempart. Le subagent `architect` s'y réfère pour tout plan qui touche `web/`, la CLI, le serveur MCP, les commentaires de PR ou les notifications. Toute modification passe par un ADR.

## 1. Principes d'expérience

1. **La preuve avant la confiance.** Chaque chiffre, statut ou affirmation affiché est cliquable jusqu'à sa preuve (finding brut, chemin, résultat de politique, dossier signé). Rien n'est « vert » sans preuve consultable.
2. **Les faits d'abord, le LLM ensuite.** Les faits calculés (risque, sévérité, chemin, statut) sont affichés dans des composants structurés. Le texte rédigé par le LLM est toujours visuellement distinct (bloc « Explication générée ») et ne remplace jamais un fait.
3. **Aucune action irréversible sans récapitulatif lié au plan exact.** Toute approbation montre le hash du plan, le risque, le rayon d'impact et le retour arrière, et porte sur ce hash seulement.
4. **Le chemin plutôt que la liste.** Une faille se montre comme un chemin d'attaque de bout en bout, pas comme une ligne dans un tableau de 400 alertes.
5. **Calme par défaut.** Priorisation par exploitabilité démontrée, regroupement par cause racine, pas de rouge pour ce qui n'est pas urgent. L'utilisateur doit savoir en 10 secondes s'il a quelque chose à faire aujourd'hui.
6. **Deux niveaux de lecture.** Chaque écran a une vue « Résumé » (RSSI, direction) et une vue « Technique » (ingénieur), commutables, sur les mêmes données.
7. **Tout est faisable hors de l'interface.** Chaque action de l'interface web a son équivalent API et CLI. L'interface web n'a aucun pouvoir que l'API n'a pas.

## 2. Surfaces

| Surface | Public | Rôle | Jalon |
|---|---|---|---|
| CLI `rempart` | Ingénieurs, CI | Scanner, planifier, suivre, exporter, scripter | M0 à M8 (enrichie à chaque jalon) |
| Commentaires de PR (GitHub, GitLab) | Développeurs, ops | Résumé du changement et lien vers le dossier de preuves, là où le code est relu | M4 |
| Application web | RSSI, responsables infra, CTO, auditeurs | Pilotage complet | Vue findings en lecture seule en M5, complète en M8 |
| Serveur MCP | Développeurs sous Claude Code, Cursor | Proposer des changements et consulter depuis l'éditeur | M8 |
| Slack et Teams | Approbateurs | Alertes, approbations à faible risque | M8 |
| Courriel | Direction, RSSI | Synthèse hebdomadaire | M8 |
| API publique (OpenAPI) | Intégrateurs | Tout ce qui précède | M4 (interne), M8 (publique) |

## 3. Architecture de l'information (application web)

Navigation principale : **Accueil**, **Changements**, **Findings**, **Inventaire**, **Conformité**, **Coûts**, **Journal**, **Paramètres**.

Éléments globaux, visibles sur tous les écrans :
- sélecteur d'organisation et d'environnement (dev, staging, prod) ;
- recherche globale (ressources, changements, findings, contrôles) ;
- bouton « Nouveau changement » ;
- indicateur d'état du coupe-circuit (vert : écriture autorisée ; rouge : gelée), accessible en un clic pour les administrateurs ;
- centre de notifications (approbations en attente en premier).

## 4. Écrans

Pour chaque écran : objectif, contenu, actions, états particuliers.

### E1. Onboarding
- **Objectif** : du compte créé au premier scan en moins de 10 minutes ; au premier déploiement conforme en moins de 30 minutes.
- **Étapes** (barre de progression, reprise possible) :
  1. Organisation et SSO (OIDC ou SAML), invitation des membres.
  2. Connexion du dépôt Git (application GitHub ou GitLab, dépôts choisis explicitement).
  3. Connexion d'un cloud : Rempart génère un modèle d'onboarding (CloudFormation ou OpenTofu pour AWS, Bicep ou OpenTofu pour Azure). L'écran affiche **en clair la liste des permissions accordées**, un bouton de téléchargement et la commande à lancer. Vérification automatique : lecture seule effective, ExternalId correct.
  4. Installation du runner : commande Helm ou module OpenTofu préremplis, puis attente du premier battement de cœur (indicateur en direct).
  5. Choix des référentiels (NIS2, DORA, ISO 27001, CIS) et du niveau d'autonomie par environnement (défaut : L1 partout, explication de chaque niveau).
  6. Premier scan avec progression par cloud, puis écran « Ce qu'on a trouvé » : score, 3 chemins d'attaque prioritaires, état de conformité.
- **États** : échec de vérification des permissions (message précis et correction proposée), runner injoignable (diagnostic réseau sortant), dépôt sans droits d'écriture de PR.

### E2. Accueil (posture)
- **Contenu** : bandeau « À faire aujourd'hui » (approbations en attente, findings critiques nouveaux, blocages) ; cartes de métriques (score de posture et tendance, chemins d'attaque prouvés ouverts, conformité par référentiel en pourcentage de contrôles techniques couverts, coût mensuel et tendance) ; « Depuis hier » (changements appliqués, findings ouverts et fermés, dérives) ; changements en cours.
- **Actions** : ouvrir un élément, nouveau changement, basculer Résumé et Technique.
- **États** : environnement vide (invitation à lancer un premier scan ou un premier changement), scan en cours.

### E3. Nouveau changement
- **Disposition** : conversation à gauche, architecture en construction à droite.
- **Conversation** : l'utilisateur décrit son besoin ; les questions de clarification (3 au maximum) apparaissent en cartes avec la valeur par défaut préremplie et un choix en un clic ; un panneau « Ce que je suppose » liste les hypothèses, modifiables ; les demandes contraires aux défauts sûrs (overrides) apparaissent en avertissement avec le motif de refus ou la justification exigée.
- **Architecture** : graphe qui se construit à chaque étape (réseaux, workloads, flux, exposition), avec les failles corrigées à la conception signalées (« port SSH public retiré : accès via bastion »), le coût estimé et les référentiels couverts.
- **Actions** : modifier une hypothèse, valider l'intention (lance L2 et L3), enregistrer en brouillon, importer une intention YAML.
- **États** : escalade de boucle (affiche le diagnostic, les options proposées par Rempart et un bouton pour choisir), budget dépassé.

### E4. Revue d'un changement
L'écran le plus important : il concentre la conception sécurisée, la preuve et l'approbation.
- **En-tête** : identifiant, environnement, auteur, titre, badge de risque (avec le nombre d'approbations requises).
- **Avancement** : Intention, Conception, Code IaC, Approbation, Déploiement, Vérifié.
- **Architecture** : diff avant et après (ajouts, modifications, suppressions distingués par forme et couleur, pas par la couleur seule), failles corrigées à la conception.
- **Dossier de preuves** (chaque ligne cliquable vers la preuve brute) : politiques vérifiées, chemins Internet vers données sensibles, delta du modèle de menace, contrôles de conformité concernés, rayon d'impact (créées, modifiées, remplacées, détruites), coût, retour arrière vérifié, règles de risque déclenchées, exceptions humaines actives avec leur date d'expiration.
- **Code** : lien vers la PR, et aperçu du diff IaC.
- **Approbation** : hash court du plan, texte « Exécuté par le runner dans votre compte, approbation liée à ce plan exact », boutons « Voir la PR », « Demander des modifications », « Refuser », « Approuver ». Pour un risque élevé : réauthentification. Pour un risque critique : deux approbateurs distincts, dont un rôle sécurité, et l'auteur ne peut pas approuver.
- **États** : plan périmé (le dépôt a changé : nouveau plan requis), approbation partielle (1 sur 2), approbation expirée.

### E5. Suivi de déploiement
- Journal en direct du runner (filtré, sans secret), liste des vérifications post-déploiement avec statut (connectivité attendue, connectivité interdite bloquée, santé des services, conformité au runtime), état du retour arrière si déclenché, attestation du runner téléchargeable.
- **États** : échec avec rollback automatique (explication, preuves, bouton « Relancer la conception »), runner hors ligne.

### E6. Findings
- **Liste** : regroupée par cause racine, triée par score (exploitabilité démontrée, criticité de la cible, confiance) ; badges « Prouvé » ou « Hypothèse » ; filtres par cloud, sévérité, contrôle, propriétaire, statut.
- **Détail** : visualisation du chemin (Internet, puis load balancer, puis VM, puis rôle, puis base), preuve de chaque saut (règle réseau, permission effective résolue, politique source), ressource et fichier IaC responsables avec propriétaire, correctif proposé (diff), historique (détecté, PR ouverte, appliqué, re-scan, fermé).
- **Actions** : « Corriger » (lance L7, ouvre une PR), assigner, accepter le risque (justification, approbateur, date d'expiration obligatoires), marquer faux positif (avec justification, alimente les evals).
- **Règle** : un finding ne passe à « Fermé » qu'après un re-scan qui le confirme. L'interface ne propose aucun bouton « Fermer » manuel.

### E7. Inventaire
- Explorateur du graphe réel (filtres par cloud, compte, type, tag, exposition), fiche de ressource (attributs, identités, flux entrants et sortants, findings, source IaC), vue **diff conçu et réel** (ressources hors IaC, ouvertures non prévues), dérives avec action « Réconcilier » (lance L8).
- Les chaînes issues du cloud (noms, tags, descriptions) sont affichées comme texte brut, marquées « Donnée issue du cloud ».

### E8. Conformité
- Un onglet par référentiel activé : liste des contrôles avec statut (conforme, non conforme, partiel, hors périmètre), preuves horodatées par contrôle, ressources non conformes, historique.
- Les contrôles organisationnels sont listés avec le statut « Hors périmètre de Rempart », jamais présentés comme couverts.
- **Actions** : export PDF pour l'auditeur, export de l'archive JSON vérifiable, génération d'un lien d'accès auditeur temporaire en lecture seule.

### E9. Coûts
- Coût mensuel par environnement, par cloud, par changement ; anomalies ; recommandations FinOps chiffrées avec action « Proposer le changement » (passe par L3 et E4).

### E10. Journal
- Toutes les actions (humaines, Rempart, runner), filtrables ; bouton « Vérifier l'intégrité » qui recalcule la chaîne de hachage et vérifie les signatures, avec résultat affiché.

### E11. Paramètres
- Autonomie par environnement (L0 à L3, explication, historique des changements de niveau).
- Runners (état, version, dernier battement, clés publiques acceptées).
- Clouds connectés (permissions, dernière vérification, rotation).
- Politiques (packs activés, exceptions actives avec expiration, surcharges de sévérité).
- Membres et rôles, SSO, MFA obligatoire.
- Intégrations (Git, Slack, Teams, courriel, SIEM).
- Modèle LLM (fournisseur, option UE ou auto-hébergé, rétention).
- Données (rétention des preuves, export complet, suppression).
- Coupe-circuit : gel immédiat de toute écriture, confirmation explicite, journalisé.

## 5. Composants transverses
- **Badge de sévérité** : texte et icône en plus de la couleur (accessibilité).
- **Badge Prouvé ou Hypothèse**.
- **Bloc Explication générée** : fond distinct, mention « Rédigé par l'IA à partir des faits ci-dessus », jamais seul sur un écran de décision.
- **Visualiseur de chemin** : horizontal, un nœud par saut, preuve au survol et au clic.
- **Diff de graphe** : ajouts, modifications, suppressions distingués par forme et motif, pas seulement par couleur.
- **Carte de preuve** : résumé, puis au clic le JSON brut, la signature et un bouton de vérification.
- **Récapitulatif d'approbation** : hash du plan, risque, rayon d'impact, retour arrière, nombre d'approbations.

## 6. Rôles
| Rôle | Peut |
|---|---|
| Lecteur | Tout consulter sauf les paramètres sensibles |
| Ingénieur | Demander des changements, corriger des findings (PR) |
| Approbateur | Approuver jusqu'au risque élevé |
| Approbateur sécurité | Approuver les risques critiques, accepter un risque, gérer les exceptions |
| Administrateur | Paramètres, membres, runners, coupe-circuit |
| Auditeur | Lecture seule des preuves, de la conformité et du journal, exports |
Les droits sont vérifiés côté serveur ; l'interface ne fait que refléter ce que l'API autorise.

## 7. Commentaire de PR (M4)
Chaque PR ouverte par Rempart porte un commentaire au format suivant (Markdown, mis à jour à chaque nouveau plan) :

```
Rempart · CHG-0142 · staging · risque élevé (2 approbations)

Résumé : cluster EKS, 3 VM Azure, VPN site à site.
Politiques : 46/46 · Chemins Internet vers données sensibles : aucun
Rayon d'impact : 38 créées, 0 modifiée, 0 détruite · Coût : +1 240 €/mois
Retour arrière : vérifié · Plan : 7f3a…c912

Dossier de preuves complet et approbation : <lien Rempart>
Cette PR ne s'applique pas au merge : l'exécution passe par le runner après approbation.
```

## 8. CLI (`rempart`)
Sortie lisible par défaut, `--json` sur toutes les commandes, codes retour stables.

| Commande | Effet |
|---|---|
| `rempart login` | Authentification (navigateur, SSO) |
| `rempart scan [--cloud aws]` | Lance un scan et affiche le résumé |
| `rempart plan "<intention>"` ou `rempart plan -f intent.yaml` | Crée un changement, affiche questions et hypothèses, renvoie l'identifiant et le lien |
| `rempart status <CHG>` | État d'un changement |
| `rempart approve <CHG>` | Approuve (risque faible ou moyen uniquement ; au-delà, renvoie vers le web avec réauthentification) |
| `rempart findings [--severity critical]` / `rempart findings show <FND>` | Liste et détail |
| `rempart fix <FND>` | Lance la remédiation, renvoie la PR |
| `rempart check <dossier>` | Valide une IaC locale avec la chaîne Rempart (usage en CI) |
| `rempart compliance export --framework nis2` | Export PDF et JSON |
| `rempart runner install / status` | Installation et état du runner |
| `rempart freeze` / `rempart unfreeze` | Coupe-circuit (administrateur, confirmation) |

## 9. Serveur MCP
Outils exposés aux agents de code. **Aucun outil n'applique ni n'approuve** : un agent peut proposer, jamais exécuter.

| Outil | Effet |
|---|---|
| `rempart_describe_infra` | Décrit l'infrastructure d'un environnement (sous-graphe, sans secret) |
| `rempart_propose_change` | Crée un changement depuis une intention, renvoie identifiant, questions, lien |
| `rempart_change_status` | État d'un changement |
| `rempart_check_iac` | Valide une IaC locale et renvoie les findings normalisés |
| `rempart_list_findings` / `rempart_explain_finding` | Consultation |
Les réponses MCP contenant des données issues du cloud les marquent comme non fiables.

## 10. Notifications
- Slack et Teams : message avec résumé, risque et lien ; bouton « Approuver » **uniquement** pour les risques faible et moyen ; au-delà, lien vers E4 avec réauthentification.
- Courriel hebdomadaire : évolution de la posture, changements appliqués, findings ouverts et fermés, conformité.
- Paramétrables par rôle et par environnement ; regroupement pour éviter la fatigue d'alerte.

## 11. Sécurité de l'interface
- **Toute chaîne issue du cloud est affichée comme texte brut échappé**, jamais interprétée comme HTML ou Markdown (défense contre le XSS via tags et noms de ressources, complément de la défense contre l'injection de prompt).
- CSP stricte, pas de script tiers, cookies `HttpOnly`, `Secure`, `SameSite=Strict`, protection CSRF, expiration de session.
- SSO (OIDC, SAML) et MFA obligatoires pour les rôles approbateur et administrateur ; réauthentification pour les approbations à risque élevé ou critique.
- Aucun secret affiché, jamais.
- Tests automatisés d'injection : ressources de test dont les tags contiennent du HTML, du JavaScript et du Markdown, vérifiées sur tous les écrans qui les affichent.

## 12. Accessibilité, langues, appareils
- WCAG 2.2 niveau AA ; navigation complète au clavier ; information jamais portée par la couleur seule.
- Français et anglais dès M8 (i18n en place dès le premier écran).
- Mode clair et sombre.
- Responsive : consultation et approbations à risque faible ou moyen sur mobile ; les approbations critiques restent possibles sur mobile avec réauthentification.

## 13. Stack et qualité
- Next.js et TypeScript ; client API typé généré depuis la spécification OpenAPI produite par le backend Go.
- Bibliothèque de visualisation de graphe à trancher par ADR (React Flow ou Cytoscape.js), avec un test de performance sur un graphe de 5 000 nœuds.
- Système de design à base de tokens (couleurs, espacements, typographie), composants documentés dans Storybook.
- Tests : unitaires des composants, Playwright de bout en bout sur les parcours E1, E3, E4, E5, E6, tests visuels de non-régression, audit d'accessibilité automatisé (axe) sans violation sérieuse ou critique.

## 14. Critères d'acceptation UX (vérifiés en M8)
1. Onboarding : premier scan en moins de 10 minutes, premier déploiement conforme en moins de 30 minutes, chronométrés sur 3 personnes qui ne connaissent pas le produit.
2. Test utilisateur avec 5 personnes (dont 2 profils RSSI) : chacune trouve en moins de 10 secondes, depuis l'accueil, s'il y a une action urgente.
3. 100 % des chiffres et statuts des écrans E2, E4, E6 et E8 mènent à une preuve en deux clics au plus (test Playwright qui parcourt les liens).
4. Aucune chaîne injectée dans les tags de test n'est interprétée sur aucun écran (test automatisé).
5. Parcours Playwright E1, E3, E4, E5, E6 verts ; audit axe sans violation sérieuse ou critique.
6. Chaque action de l'interface a son équivalent API documenté dans OpenAPI (test de couverture).
