# Critique initiale de la spécification (session de démarrage)

- Date : 2026-09-23
- Auteur : Claude (session de démarrage, `prompts/00-bootstrap.md`)
- Statut : en attente des décisions humaines listées en fin de document

Portée : `CLAUDE.md`, `docs/`, les 14 skills et leurs références, les subagents, les commandes, `prompts/M0.md` à `M8.md`. Aucune ligne de code produit n'a été écrite. Les constats sur le harnais ont été vérifiés en exécutant les hooks avec des entrées simulées.

## En bref

1. Le harnais était inactif sur le poste de démarrage, et contient des failles sous Windows. Correctif proposé et testé : `docs/proposals/0001-harnais-portable-et-tdd.md`.
2. La promesse A6 (« compromettre Rempart ne donne pas d'accès en écriture ») ne tient pas avec la conception actuelle : le plan de contrôle signe les plans et enregistre lui-même les approbations.
3. Le LLM est placé là où il n'est pas nécessaire (L2, L3 sur infra neuve) et absent là où il serait utile (code IaC existant).
4. L'ordre des jalons contredit les hypothèses de marché : H1, H2 et H5 portent sur l'infra existante, alors que M1 à M4 construisent une infra neuve.
5. M0 à M8 représente plusieurs années de travail pour une équipe.

## 1. Harnais

| Constat | Preuve | Effet |
|---|---|---|
| `python3` absent sous Windows | Commande introuvable ; SessionStart n'a rien injecté | Tous les hooks échouent en code 127, non bloquant : aucune garde |
| Pas de dépôt git | `stop_verify.py` sort en 0 hors dépôt | Le hook Stop ne vérifie rien |
| `rel()` renvoie des `\` sous Windows | Écrire `.claude/settings.json` passe sous Windows, bloqué sous WSL | Protection du harnais et discipline TDD inopérantes |
| Entrée lue en cp1252, `read_input()` renvoie `{}` sur erreur | Clé AWS seule bloquée ; la même clé précédée de « Á » passe | Un caractère contourne la détection de secrets |
| Exemption par préfixe dans `guard_bash.py` | `python3 .claude/bin/rempart-state show; tofu apply -auto-approve` passe | Toute commande passe derrière ce préfixe |
| `git status --porcelain` sans `-uall` dans `rempart-state` | Nouveau package affiché `?? internal/` | Passage en impl refusé pour tout nouveau package |
| Baselines gelées seulement en phase impl | Motif appliqué seulement en impl | Baselines modifiables en phase tests ou free |
| Hook Stop exige `verify-quick` vert, alors qu'en phase tests les tests sont rouges | Lecture du code | Impossible de s'arrêter pour faire relire les tests : faux BLOCAGE après 3 tentatives |
| `post_edit_check` lance `go vet` sur un test qui appelle du code pas encore écrit | Lecture du code | Erreur à chaque test écrit en phase tests |
| `STATUS.md` lu et écrit en cp1252 | Lecture du code | « RÉSOLU » jamais reconnu, fichier corrompu |

## 2. Mode runner (A6)

- **Approbations falsifiables.** Les approbations du dossier de preuves sont des chaînes sans signature propre, et le plan de contrôle peut utiliser la clé KMS de signature. Correction : chaque approbateur signe le hash du plan avec sa propre clé (passkey ou WebAuthn), vérifiée par le runner contre des clés publiques enregistrées par l'administrateur du client dans la configuration du runner, jamais poussées par Rempart. Le runner applique aussi une politique locale indépendante (pas de suppression de stockage de données, pas de désactivation de journaux).
- **Qui lance `tofu plan` ?** En mode runner, l'état vit chez le client : c'est le runner qui planifie. Déroulé : PR, plan par le runner, envoi du JSON de plan expurgé, analyse, signature et approbations, puis apply du fichier de plan gardé par le runner si le hash correspond. `tofu show -json` écrit en clair les valeurs `sensitive` : expurger avant envoi, activer le chiffrement d'état d'OpenTofu.
- **Identifiants dérivés du plan.** Une session policy AWS ne fait que restreindre : l'identité de base du runner doit détenir tous les droits possibles. Déduire les actions IAM d'un plan est fragile, et Azure n'a pas d'équivalent. En M4 : un rôle par environnement borné par une permission boundary.
- **`tofu plan` exécute du code** (data sources `external` et `http`, code des providers ; `local-exec` à l'apply). Sur du HCL produit par un LLM, c'est de l'exécution de code chez le client, non couverte par T8. Correction : vérification déterministe avant tout plan, providers en liste blanche et épinglés.
- **Temporal stocke en clair** les entrées et sorties des activités. Dès M0 : Payload Codec avec chiffrement par tenant, versioning des workflows.
- **Squelette RunLoop** (`.claude/skills/loop-engineering/references/temporal-loop-skeleton.md`) : `AwaitApproval` s'arrête au premier signal, même avec un mauvais hash, et ne vérifie ni identité, ni quorum, ni exclusion de l'auteur. **Corrigé le 2026-09-23** (`AwaitApprovals`). Sur la stagnation, le compteur n'est pas remis à zéro au changement de stratégie : une troisième stratégie n'est atteinte que si l'erreur a changé entre-temps. Ce n'est pas un bug (c'est conforme au critère 2 de M0), mais un choix désormais écrit explicitement dans le skill ; à confirmer.
- **Retour arrière.** Revenir à l'IaC précédente ne restaure pas une donnée détruite. Retour arrière automatique seulement si le plan de retour ne détruit ni ne remplace aucune ressource avec état ; sinon gel et escalade.
- **Mode hébergé** : à retirer du MVP.

## 3. Boucles et rôle du LLM

- **L3** : un compilateur déterministe graphe vers HCL (modules internes) est équivalent au graphe par construction. Le LLM est utile pour modifier du HCL humain (L7), reprendre l'existant (L8), comprendre l'intention (L1), expliquer.
- **L2** : le proposeur n'est pas défini. Déterministe, une boucle de 5 itérations n'a pas de sens ; LLM, il choisirait l'architecture, ce que la spec interdit.
- **Intent IR** : `tenant_id` est produit par le LLM (injection possible vers un autre tenant) ; il doit être fixé par le serveur. `allowed_sources` accepte `0.0.0.0/0`. Les références croisées demandent un contrôle déterministe.
- **Scénario de référence** : VPN `bidirectional: true` sur 5432 et 9100, ouverture VM vers cluster inutile.
- **Règles de risque** : tags, labels ou journalisation seuls classés `low`, donc appliqués sans approbation, alors que couper les journaux efface les traces et que labels et tags pilotent NetworkPolicy et ABAC. `low` seulement si un recalcul prouve qu'atteignabilité et droits ne changent pas ; type de ressource inconnu classé `high`.
- **Critère M1 « zéro valeur inventée »** : à définir de façon vérifiable. Evals LLM en PR : réponses enregistrées ; exécutions réelles la nuit.

## 4. Modèle de menace

- Menace absente : l'application GitHub ou GitLab de Rempart, qui a des droits d'écriture sur les dépôts de tous les clients.
- Dossiers de preuves signés par une clé que Rempart détient : horodatage externe RFC 3161 (qualifié eIDAS si possible), canonicalisation RFC 8785.
- Option « modèle UE » : sur l'API Anthropic directe, `inference_geo` accepte seulement `us` ou `global`. La résidence UE passe par Bedrock (régions UE) ou Vertex (`eu`) : `ModelProvider` multi-plateforme dès M0, baseline d'evals par fournisseur.
- Rôle de scan en lecture détenu par le plan de contrôle : sa compromission donne la carte de tous les clients. Proposer un scan par le runner pour les clients sensibles.

## 5. Périmètre, ordre, marché

- **Point d'entrée proposé** : scan en lecture seule, chemins d'attaque prouvés, rapport NIS2/DORA avec preuves, correctifs en PR sur le dépôt Terraform existant (autonomie L0/L1). Pas de runner au départ. Génération d'infra neuve après les design partners.
- **Découverte** : 5 entretiens avant M1.
- **Concurrence oubliée** : Prowler (open source, conformité intégrée) + Checkov + Atlantis ; Firefly (dérive, reprise de l'existant) ; Vanta, Drata (preuve de conformité).
- **A7 et le runner** : Helm suppose Kubernetes ; prévoir une installation CloudFormation ou Bicep en un clic.
- **Apache AGE** : à ma connaissance absent de RDS ; les calculs sont en Go de toute façon. Tables PostgreSQL classiques avec RLS.
- **Incohérences M0** : `cmd/rempart-evals`, `internal/archtest`, `scripts/sandbox.sh` utilisés mais non prévus ; `make dev` suppose Docker.

## Décisions attendues avant `/milestone M0`

1. Appliquer le patch du harnais (`docs/proposals/0001-harnais-portable-et-tdd.md`).
2. Choisir le point d'entrée : lecture seule et preuves sur l'existant, ou feuille de route actuelle. Change M1 à M4, pas M0.
3. Valider les ADR de départ : plan calculé par le runner ; approbations signées par des clés du client ; L3 en compilateur déterministe ; pas de mode hébergé ; pas d'AGE ; données Temporal chiffrées.
4. Installer la chaîne d'outils (`docs/SETUP.md`).
