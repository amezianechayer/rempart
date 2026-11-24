# 0013. Périmètre fonctionnel élargi face à la concurrence

- Statut : accepté par l'humain le 2026-11-19 (« Oui je valide »). Cet ADR consigne la décision, en fixe les contours, les garde-fous et la place dans la feuille de route ; il ne la rediscute pas.
- Date : 2026-11-24
- Jalons : M5 (DSPM léger, ingestion CWPP), M6 (import multi-IaC, CWPP dans la priorisation), M8 (tickets, éditeur visuel), M9 nouveau (GCP, AI-SPM).
- Sources : `docs/00-VISION.md` (sections 2 à 4, 6) ; `docs/01-LOOPS.md` (L2, L3, L6, L7) ; `docs/04-INTERFACE.md` (E1, E3, E4, E6, E11, sections 2, 8, 10) ; `docs/02-THREAT-MODEL.md` (T2, T7, T8, T22, T26, T27, T114 à T118) ; ADR 0003, 0010 (D5), 0011 (D7), 0012 (D2, D3) ; skills `security-graph-attack-paths`, `secrets-and-identity`, `llm-safety`, `product-interface`, `secure-iac-generation`, `safe-autonomy`.

## Contexte

Les concurrents de la section 2 de la vision cochent des cases que Rempart n'avait pas prévues : découverte des données sensibles (DSPM), posture des services d'IA (AI-SPM), protection des workloads à l'exécution (CWPP), Google Cloud, tickets, édition visuelle, reprise d'une IaC existante. Une ETI régulée (cible de A7) compare sur ces cases. L'humain retient sept ajouts et en écarte deux. Les invariants ne bougent pas : cœur déterministe, toute donnée externe non fiable, lecture seule pour le scan, mode runner, OpenTofu source de vérité, tout passe par un vérificateur.

## Options envisagées

1. **Statu quo** : aucun coût, mais sept cases vides en avant-vente et GCP hors périmètre (section 6 de la vision).
2. **Tout prendre, catalogue libre-service et agent d'exécution maison compris** : le catalogue ne sert aucun axe ; un agent dans les workloads contredit A6 et le principe 3, et ouvre une surface noyau chez le client.
3. **Sept ajouts, chacun rattaché à un axe et à un jalon, GCP et AI-SPM regroupés dans un jalon M9 après M7 (retenue)** : M7 n'est pas retardé ; chaque ajout hérite des garde-fous du jalon qui l'accueille.

## Décision

### D0. Règles communes
1. **Lecture seule** : aucun ajout ne crée, modifie ni supprime de ressource client hors du chemin L3, L4, L5 ; aucune règle, politique, agent ni instantané installé ou créé par Rempart.
2. **Mode runner** : tout accès au contenu client (données échantillonnées, états IaC) se fait dans le runner ; seuls des faits typés en sortent (identifiants, classes, comptes).
3. **Quarantaine** : toute chaîne issue d'un cloud, d'un état IaC, d'un capteur d'exécution ou d'un outil de tickets est `untrusted_text`, affichée en texte brut, jamais lue par une décision ni passée à un appel doté d'outils (`llm-safety`).
4. **Monotonie** : un signal externe (DSPM, CWPP) peut relever une classification ou une priorité ; il ne l'abaisse jamais, ne ferme aucun finding et ne prouve aucun saut.
5. **Vérificateur** : tout graphe candidat (éditeur, import) passe par le vérificateur de L2 sous la forme graphe de l'ADR 0012 (D2), confirmation liée à l'empreinte (D3). L3 n'accepte qu'un sujet `ir` tant qu'un ADR ne lève pas T115.
6. **Aucune décision par un LLM** : aucun paquet de décision nouveau n'importe `internal/llm` (contrôle par `go list -deps`).

### D1. DSPM léger (M5)
- **Axes** : A1 (la classification qui pilote politiques et chemins d'attaque est confrontée au réel), A5 (inventaire des données réglementées).
- **Périmètre** : `internal/inventory/dspm`, exécuté par le runner. Buckets et partages d'objets, bases managées, volumes. Échantillonnage aléatoire borné (graine consignée ; objets par conteneur, octets par objet, octets et durée par scan, valeurs fixées par le plan M5). Détecteurs déterministes à validation (Luhn, clé IBAN, clé NIR, motifs de secrets du rédacteur), expressions RE2 seulement, formats en liste fermée. Bases : compte en lecture seule créé par le client, identifiant obtenu localement par le runner, transaction en lecture seule, délai par requête. Volumes : instantanés existants lus par une API de lecture ; un volume sans un tel accès est déclaré « non couvert ».
- **Sortie** : par conteneur `{store_id, classes, comptes par classe, taille d'échantillon, couverture}` ; jamais d'extrait, de valeur détectée ni de nom d'objet en clair (empreinte HMAC par tenant si un renvoi est nécessaire). Attribut observé `observed_classes` sur `DataStore` ; la classification déclarée (IR, graphe) n'est jamais réécrite. Classification effective : maximum de la déclarée et de l'observée. Écart : finding `DSPM-001` (classification sous-déclarée).
- **Garde-fous** : rôle `data-sample` distinct du rôle de lecture des métadonnées, activé par le client compte par compte et conteneur par conteneur, détenu par le runner seul (question 1) ; aucun contenu vers un LLM.
- **Menaces** : T123, T124, T125.
- **Acceptation** : `go test ./internal/inventory/dspm/ -run '^Test(DSPMOutputHasNoContent|DSPMNeverLowersClassification|DSPMSamplingBounded)$' -v 2>&1 | grep -c '^--- PASS'` : `3` ; `go list -deps ./internal/inventory/dspm/... | grep -c 'internal/llm'` : `0`.

### D2. Tickets Jira et ServiceNow (M8)
- **Axes** : A7 (s'insère dans les processus existants d'une ETI), A2 (suivi visible jusqu'au re-scan).
- **Périmètre** : `internal/ticketing`, création et mise à jour de tickets pour findings, changements et demandes d'approbation ; état du ticket lu pour affichage seulement. Action « Créer un ticket » dans E4 et E6, intégrations dans E11, commande `rempart findings ticket <FND>`.
- **Garde-fous** : aucun état, champ, commentaire ni webhook de ticket n'est lu par une décision ; un ticket ne vaut jamais approbation (`safe-autonomy`, section 10 de `docs/04-INTERFACE.md`) ni fermeture (seul un re-scan ferme, E6). Contenu minimal : identifiant Rempart, sévérité, `control_id`, statut, lien vers Rempart ; ni chemin d'attaque, ni chaîne issue du cloud, ni preuve. Jeton par tenant dans OpenBao, limité à un projet ; URL d'instance sur liste de domaines des éditeurs, adresses privées refusées après résolution (règles de T22) ; instance auto-hébergée joignable par le runner seulement (question 3) ; webhooks entrants authentifiés.
- **Menaces** : T126, T127.
- **Acceptation** : `go test ./internal/ticketing/... -run '^Test(TicketNeverApproves|TicketClosedDoesNotCloseFinding|TicketPayloadMinimal|TicketInstanceRejectsInternal)$' -v 2>&1 | grep -c '^--- PASS'` : `4`.

### D3. Google Cloud (M9, après M7)
- **Axes** : A7 (parc réel des ETI) ; A1 et A6 étendus à un cinquième cloud.
- **Périmètre** : `internal/inventory/gcp` en lecture seule (organisation, dossiers, projets) ; `modules/gcp/` au contrat de module ; permissions effectives IAM GCP (héritage, politiques de refus, conditions, usurpation de comptes de service ; non évaluable : `ambiguous`) ; table fermée de traduction des permissions abstraites, sans joker (T117) ; `gcp` dans l'énumération `cloud` du schéma (règle de version de l'ADR 0010 D5) ; lignes `gcp` de `internal/policy/domain/jurisdiction.go`, datées, sourcées sur un domaine Google ajouté à la liste fermée de `TestJurisdictionTableClosed`, relues par l'humain (H-jurisdiction) ; région absente : `unknown`.
- **Garde-fous** : fédération d'identité de charge de travail, aucune clé de compte de service ; rôle de lecture sans permission d'écriture, ni `setIamPolicy`, ni usurpation (`actAs`, `getAccessToken`, `signBlob`, `signJwt`), vérifié à l'onboarding ; rôles de base refusés au profit de rôles prédéfinis vérifiés à la source par l'ADR de mise en oeuvre de M9 ; mode runner identique à AWS et Azure.
- **Menaces** : T128, T129.
- **Acceptation** : critères 1 à 5 de `prompts/M9.md`, dont `go test ./internal/inventory/gcp/... -run '^TestGCPReadRoleHasNoWriteOrImpersonation$' -v 2>&1 | grep -c '^--- PASS'` : `1`.

### D4. Éditeur visuel (M8, web)
- **Axes** : A7 (concevoir sans écrire d'IR ni d'HCL), A1 (même vérificateur que L2).
- **Périmètre** : édition du graphe dans E3 (nœuds, flux, expositions), résultat du vérificateur affiché après chaque modification, diff de graphe de la section 5 de `docs/04-INTERFACE.md`.
- **Garde-fous** : l'éditeur produit un graphe candidat (`subject: graph`, `source: design`) ; le serveur le décode strictement, recalcule l'empreinte et lance L2. Le client n'envoie jamais de verdict, d'état « vérifié » ni de liste d'expositions (champ inconnu refusé). Toute modification change l'empreinte et invalide la confirmation ; le récapitulatif confirmé est celui du serveur. Rien n'atteint L3, L4 ou L5 sans sortie convergée de L2 pour l'empreinte exacte, et L3 refuse un sujet `graph` tant que T115 n'est pas levée (question 2).
- **Menace** : T130.
- **Acceptation** : `go test ./... -run '^Test(EditorRejectsClientVerdict|EditorEditInvalidatesConfirmation|EditorUnverifiedNeverReachesL3)$' -v 2>&1 | grep -c '^--- PASS'` : `3` ; parcours Playwright E3 : une exposition ajoutée affiche `L2-EXPOSURE-UNCONFIRMED` et bloque la validation jusqu'à la confirmation.

### D5. Import multi-IaC et ressources non gérées (M6)
- **Axes** : A2 (une ressource sans source IaC ne se corrige pas par PR), A7 (adoption sans réécriture).
- **Ordre** : état Terraform, puis CloudFormation, puis Pulumi ; les ressources non gérées (diff conçu et réel de L6) suivent le même chemin.
- **Chemin** : `internal/remediate/importer`. Le runner lit la source (état Terraform, ressources de pile CloudFormation par API de lecture, export d'état Pulumi remis par le client) et n'en extrait qu'une liste fermée de champs (type, adresse, identifiant cloud) ; il écrit des blocs `import` et lance `tofu plan -generate-config-out` (plan seulement). L'HCL produit passe par la chaîne de validation de L3 (`internal/validate`) ; ses findings deviennent des findings L6 et L7. Le graphe construit depuis l'IaC importée entre dans L2 sous forme graphe ; l'import ne passe pas par la génération de L3 (sujet `ir` seulement, T115), ses corrections passent par L7. Puis PR, L4 et L5 (plan d'import seul, état écrit chez le client). CLI : `rempart import --from terraform-state|cloudformation|pulumi`.
- **Garde-fous** : vérificateur d'import : chaque changement du plan est un import sans autre action ; HCL sans secret (rédacteur et détecteurs de la chaîne), attributs sensibles remplacés par des références OpenBao ; aucune expression de gabarit (`${`, `%{`) issue d'une valeur importée ; aucune exception de politique ; double gestion signalée (pile CloudFormation et OpenTofu sur une même ressource), avec l'étape client de rétention avant retrait de la pile.
- **Menaces** : T131, T132.
- **Acceptation** : `go test ./internal/remediate/importer/... -run '^Test(ImportPlanImportOnly|ImportedHCLHasNoSecret|ImportedHCLHasNoTemplateExpression|ImportStateNeverLeavesRunner)$' -v 2>&1 | grep -c '^--- PASS'` : `4` ; plan d'import du labo : `tofu show -json <plan> | jq '[.resource_changes[] | select(.change.actions != ["no-op"] or (.change.importing | not))] | length'` : `0`.

### D6. AI-SPM (M9)
- **Axes** : A1 (contrôles de conception sur les services d'IA), A4 et A5 (lieu d'exécution des modèles face à la résidence exigée des données).
- **Périmètre** : Amazon Bedrock, Azure OpenAI, Vertex AI, endpoints d'IA d'OVHcloud et de Scaleway (capacités réelles vérifiées, manques en ADR, comme en M7). Amendement du schéma (ADR 0010 D5) : nœud de service d'IA ; attributs `public_network`, `key_auth`, `invocation_logging`, `inference_regions` (destinations d'un profil interrégional ou d'un déploiement global) ; permission abstraite `invoke` ; chaque fait nouveau classé dans la table de `FromGraph` (`TestGraphSchemaExtension`, T116).
- **Contrôles** (`policies/design/`, `policies/runtime/`) : accès réseau public ; authentification par clé plutôt que par identité ; journalisation des invocations hors zone ; flux de donnée sensible vers un endpoint dont un lieu d'exécution sort de la zone exigée (workload qui lit la donnée et peut invoquer l'endpoint : hypothèse, sauf flux déclaré dans l'IR). Zone d'un endpoint : la plus large de ses destinations, lue dans une table fermée et sourcée `(cloud, type de déploiement, région)` à côté de la table de juridiction, jamais dans un nom ni un préfixe (doute consigné dans `docs/STATUS.md` sur le profil Bedrock `eu.`) ; `unknown` en échec fermé pour une donnée sensible (comme RES-005).
- **Garde-fous** : collecteurs à liste blanche d'opérations ; aucune API qui rend une clé ; journaux d'invocation jamais lus, seule leur configuration ; noms de modèles et de déploiements en `untrusted_text`.
- **Menaces** : T133, T134.
- **Acceptation** : `go test ./internal/policy/domain/ -run '^Test(InferenceTableClosed|InferenceZoneIsWidestDestination)$' -v 2>&1 | grep -c '^--- PASS'` : `2` ; critères 6 à 8 de `prompts/M9.md`.

### D7. CWPP par intégration (M5 puis M6)
- **Axes** : A2 (priorisation fondée sur un signal d'exécution), A6 (aucun code de Rempart dans les workloads), A7 (réutilise les outils du client).
- **M5** : `internal/inventory/runtime` ingère en lecture seule les événements de Falco ou de Tetragon déjà déployés par le client (sortie gRPC ou fichier lus par le runner, connexion sortante) ; liste fermée de champs (horodatage, règle, priorité, identifiants de pod, de conteneur, d'espace de noms, de nœud) ; rattachement aux nœuds `K8sWorkload` et `Compute` par identifiant seulement ; événement non rattaché compté puis écarté ; bornes par source et par tenant (T10, T24).
- **M6** : dans `internal/attackpath`, un signal récent sur un nœud d'un chemin relève sa priorité et apparaît comme « signal tiers » dans E6 ; il ne prouve aucun saut (badge « Prouvé » inchangé) et n'abaisse rien (D0.4).
- **Garde-fous** : rôle du runner dans le cluster sans `create`, `update`, `patch`, `delete` ; aucune règle Falco ni `TracingPolicy` installée ; aucun agent, DaemonSet ni conteneur privilégié livré par Rempart ; champs texte des événements en `untrusted_text`.
- **Menaces** : T135, T136.
- **Acceptation** : `go test ./internal/inventory/runtime/... ./internal/attackpath/... -run '^Test(RuntimeSignalAttachedByIDOnly|CWPPRoleReadOnly|RuntimeSignalNeverLowersPriority|RuntimeSignalNeverProvesHop)$' -v 2>&1 | grep -c '^--- PASS'` : `4` ; evals d'injection étendues aux événements : résistance de 100 % sur les décisions.

### D8. Écartés
- **Catalogue libre-service** : ne sert aucun axe ; Rempart part d'une intention vérifiée, pas d'un catalogue.
- **Agent d'exécution maison** : contredit A6 et le principe 3 ; D7 couvre le besoin sans code dans les workloads.

## Conséquences
- **Coût** (à affiner par les plans) : M5 plus 2 tâches (DSPM après L6 dans le découpage, ingestion CWPP) ; M6 plus 4 tâches (trois sources d'import, priorisation) ; M8 plus 2 tâches ; M9 jalon entier, de taille voisine de M7. Environ un jalon et demi de plus.
- **Positives** : sept cases couvertes sans agent ni identifiant d'écriture nouveau ; classification et priorisation nourries de faits observés ; une IaC existante devient corrigeable par PR.
- **Négatives** : surface accrue (contenu client échantillonné, outil de tickets tiers, états IaC chargés de secrets, analyseurs de formats hostiles) ; le rôle `data-sample` rompt la règle « Rempart ne lit que des métadonnées » ; tables de lieu d'exécution des modèles à maintenir face à des offres changeantes ; M5 et M6, déjà les plus lourds, s'alourdissent.
- **Risques** : glissement de M5 (signalé dans `docs/STATUS.md`, jamais silencieux) ; régions ou offres d'IA mal sourcées (échec fermé à `unknown`) ; double gestion IaC pendant un import (L8 la détecte).
- **Difficile à changer** : faits ajoutés au schéma (`observed_classes`, nœud d'IA, `invoke`, `gcp`), règle de monotonie D0.4, sortie fermée du DSPM.

## Impact sur le modèle de menace

Proposées, numéros à confirmer par `security-reviewer`, insertion dans `docs/02-THREAT-MODEL.md` avec les tâches qui les portent :

| # | Menace | Cat. | Atténuation principale | Vérification |
|---|---|---|---|---|
| T123 | Contenu client sorti du compte par le DSPM (extrait, valeur détectée, nom d'objet, journal, prompt, preuve) | I | Runner, sortie fermée sans chaîne libre, HMAC par tenant | `TestDSPMOutputHasNoContent` |
| T124 | Identité `data-sample` compromise ou détenue par le plan de contrôle : lecture des données de tous les clients (extension de T27) | E, I | Rôle distinct, activé par conteneur, runner seul, sessions courtes | `TestDataSampleRoleNeverInControlPlane` |
| T125 | Contenu hostile contre les détecteurs : bombe de décompression, fichier géant, format ou système de fichiers piégé, expression catastrophique | D, E | Formats fermés, bornes d'octets et de durée, RE2, analyseur sans privilège | `TestDSPMSamplingBounded` |
| T126 | Ticket utilisé comme canal d'approbation, de refus ou de fermeture (état posé par tout utilisateur de l'outil) | S, E | Aucun champ de ticket lu par une décision | `TestTicketNeverApproves`, `TestTicketClosedDoesNotCloseFinding` |
| T127 | Fuite du graphe vers l'outil de tickets, SSRF par l'URL d'instance, jeton trop large | I | Contenu minimal, domaines en liste, adresses privées refusées, jeton par projet | `TestTicketPayloadMinimal`, `TestTicketInstanceRejectsInternal` |
| T128 | Identité de scan GCP trop large : clé de compte de service, rôle de base, usurpation | E, I | Fédération d'identité, rôle fermé vérifié à l'onboarding | `TestGCPReadRoleHasNoWriteOrImpersonation` |
| T129 | Permissions effectives GCP fausses (héritage, refus, conditions, groupes, compte de service par défaut) : chemin manqué | E | Corpus, `ambiguous` pour le non évaluable | corpus de M9 à 100 % |
| T130 | Éditeur qui contourne le vérificateur : verdict du client, empreinte périmée confirmée, graphe non vérifié vers L3 | S, T, E | Empreinte du serveur, décodage strict, L3 sur sujet `ir` | `TestEditorRejectsClientVerdict`, `TestEditorEditInvalidatesConfirmation` |
| T131 | Secrets des états importés recopiés dans Git, le plan de contrôle, un journal ou un prompt | I | Runner, champs fermés, détecteurs sur l'HCL, références OpenBao | `TestImportStateNeverLeavesRunner`, `TestImportedHCLHasNoSecret` |
| T132 | Import qui devient un changement : plan non limité aux imports, expression `${` issue d'une valeur importée évaluée par `tofu plan` (T8), pile retirée qui détruit | T, E, D | Vérificateur d'import, littéraux échappés, étape de rétention | `TestImportPlanImportOnly`, `TestImportedHCLHasNoTemplateExpression` |
| T133 | Lieu d'exécution d'un modèle mal attribué (profil interrégional, déploiement global, préfixe) : donnée sensible traitée hors zone sans finding | I | Table fermée sourcée, zone la plus large, `unknown` en échec fermé | `TestInferenceZoneIsWidestDestination` |
| T134 | Collecteur d'IA qui lit une clé d'API ou un journal d'invocation (contenu client, injections) | I, T | Liste blanche d'opérations par collecteur | `TestAICollectorsOperationAllowlist` |
| T135 | Signal d'exécution forgé, supprimé ou en rafale depuis un workload compromis : injection, escalade forcée, priorité abaissée | S, T, D | Champs fermés, rattachement par identifiant, D0.4, bornes | `TestRuntimeSignalNeverLowersPriority`, evals d'injection |
| T136 | Intégration CWPP qui élargit les droits de Rempart dans le cluster (règles, `TracingPolicy`, socket en écriture, DaemonSet) | E | Rôle en lecture, rien d'installé | `TestCWPPRoleReadOnly` |

Menaces existantes touchées : T2 et T7 (données non fiables et contenu sensible nouveaux), T22 (URL d'instance), T27 (identités de scan), T114 et T118 (lignes `gcp`, lieu d'exécution des modèles), T115 (éditeur, import), T116 (faits nouveaux), T117 (traduction GCP).

## Amendements à faire par l'humain
- `docs/00-VISION.md` ne cite pas M0 à M8 ; la mention est dans `CLAUDE.md` ligne 3 (harnais) : « `prompts/M0.md` à `prompts/M8.md` » devient « à `prompts/M9.md` ».
- `docs/00-VISION.md` section 4, ligne `inventory/    collecteurs (aws, azure, ovh, scaleway, kubernetes)` : ajouter `gcp`, `dspm`, `runtime` (signaux d'exécution) ; ajouter le module `ticketing/` ; section 6 : retirer « GCP » des hors périmètre.
- `docs/04-INTERFACE.md` : section 2 (CLI « M0 à M8 »), E3 (éditeur), E4 et E6 (ticket, signal tiers), E11 (Jira, ServiceNow, Falco, Tetragon), section 8 (`rempart import`, `rempart findings ticket`) ; même ligne `inventory/` dans `MASTER_PROMPT.md`.

## Questions à l'humain
1. DSPM réservé au runner, donc indisponible en mode hébergé (oui).
2. Éditeur : ADR de L3 avant M8 qui admet un sujet `graph` seulement avec une confirmation signée (M4) et l'empreinte de la sortie convergée de L2 ; sans cet ADR, l'éditeur conçoit mais ne déploie pas (oui, ADR dédié).
3. Tickets vers une instance Jira ou ServiceNow auto-hébergée par le runner seulement, jamais depuis le plan de contrôle (oui).
4. M9 après M8, avec M7 pour seule dépendance : produit complet pour les design partners d'abord (oui).
