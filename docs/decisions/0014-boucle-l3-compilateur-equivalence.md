# 0014. Boucle L3 : compilateur déterministe, composition typée, équivalence et chaîne d'outils

- Statut : **accepté** par l'humain le 2026-11-26 : réponse « Continue » à la demande d'acceptation (sonde et mesure faites), lue comme acceptation avec les recommandations de l'agent sur les quatre questions de la section « Questions à l'humain » (oui à chacune), selon le précédent de l'ADR 0011 ; à corriger par l'humain si ce n'était pas son intention. Rédigé pendant M3-T01. Les deux sections mesurées avant l'acceptation sont complétées (2026-11-26) : « Résultat de la sonde », qui fixe la branche de Q2 (repli pour toute racine qui contient azurerm), et « Mesure de la dépendance » (D20). Mesure faite sur une copie de travail jetable : le dépôt n'a pas encore `hcl/v2`. L'humain accepte l'ADR avant la phase tests de M3-T02 (étape H0-M3.2). Les recommandations Q1 à Q13 du plan M3 ont été retenues par l'humain le 2026-11-25 (« validé, suis tes recommandations ») : cet ADR les consigne comme décisions et les précise sans les rediscuter. La branche de Q2 est fixée par la sonde.
- Date : 2026-11-25
- Jalon : M3. Mise en oeuvre par tâche :
  - M3-T02 : D6 (exécution confinée), D15, D20 et la sonde de D8 ;
  - M3-T03 : D6, D7, D9, D14 (port) et D16 (application) ;
  - M3-T04 et M3-T05 : D16 (fichier) et D19 ;
  - M3-T06 : D4, D5, D11 à D13 ;
  - M3-T07 : D8 (planificateur), D10 et D17 ;
  - M3-T08 : D1 à D3 et D18 ;
  - M3-T09 : D18 (evals, Q12).
- Base : M2 accepté le 2026-11-25 ; découpage `docs/plans/M3-overview.md` validé le même jour ; M3-T01 en cours (obligations (fk), (fl), (fd), (cf), durcissement T31).
- Sources :
  - prompt et plan : `prompts/M3.md` (C1 à C4) ; `docs/plans/M3-overview.md` (sections 2, 3, 3.1, 3.2, 4, ligne ADR 0014 de la section 6, sections 8, 11 et 12) ;
  - documents de référence : `docs/00-VISION.md` (sections 3, 4, mode runner) ; `docs/01-LOOPS.md` (L3, L4) ; `docs/02-THREAT-MODEL.md` (T2, T3, T6, T7, T8, T10, T16, T24, T27, T29 à T31, T115 à T117, section 4.2) ; `docs/04-INTERFACE.md` (section 8) ;
  - ADR : 0001, 0005, 0010 (D2, D10, D12), 0011 (D1 à D6, D8, vérifications 2, 12 et 13), 0012 (D2 à D6), 0013 (D0.5, question 2) ;
  - skills : `secure-iac-generation` (`references/module-contract.md`, `scripts/validate.sh`, `scripts/normalize_findings.py`), `policy-as-code`, `loop-engineering` (`references/loop-spec-template.md`) ;
  - code : `internal/loops/{spec.go,runloop.go,l2}`, `internal/design/{build.go,confirm,verify,cidr,fsread}`, `internal/graph/reach`, `internal/intent/irvalid`, `internal/policy/adapters/opa`, `policies/embed.go`, `internal/archtest/{rules.go,packages.go,packages_test.go}`, `cmd/rempart-evals/git.go`.

## Contexte

L3 doit transformer le graphe convergé de L2 en IaC OpenTofu composée de modules internes. Cette IaC doit passer toute la chaîne de validation et ne rien contenir hors du graphe (`prompts/M3.md`, C1 à C4).

Rien n'existe encore : `internal/{iacgen,validate,plan}` sont vides, `policies/iac/` ne contient que `.gitkeep`, `modules/` est vide et aucun outil IaC n'est installé.

Environnement mesuré le 2026-11-25 :
- téléchargeables : actifs de releases GitHub, PyPI, `releases.hashicorp.com` ;
- bloqués : API GitHub, `registry.opentofu.org`, `registry.terraform.io`, API de prix d'Infracost ;
- pas de démon Docker.

Faits du dépôt qui contraignent :
1. **`RunLoop`** :
   - bloque sur tout finding `medium` ou plus ;
   - calcule l'empreinte sur les couples (code, ressource) en netstrings ;
   - exige `Budget.MaxTokens` au moins 1 ;
   - borne charge et candidat à 64 Kio (`loops.MaxPayloadBytes`, `loops.MaxCandidateBytes`) ;
   - le premier `Propose` reçoit `Best` vide.
2. **Sortie de L2** : elle porte `subject`. T115 est ouverte : « L3 n'accepte qu'un sujet `ir`, sauf ADR » (ADR 0012 D2, ADR 0013 D0.5 et question 2).
3. **Briques réutilisables**, testées en M1 et M2 : `irvalid.ValidateIR`, `design.Build`, `confirm.DigestOfIR`, `confirm.Check`, `confirm.Uncovered`, `verify.Derives`, `verify.Candidate`, `reach.Result.SubsetOf`, `cidr.Check`, `loopsdomain.Fingerprint`, `loopsdomain.Score`.
4. **Moteur OPA** : il n'a qu'un pack (`policies.Design`, requête `data.rempart.design[_].deny[_]`), confiné par la règle `opa-confined`.
5. **`os/exec`** : hors tests, seuls `internal/archtest/packages.go` et `cmd/rempart-evals/git.go` l'importent. `checkExecUsage` refuse déjà `os.StartProcess` et `syscall.{Exec,ForkExec,StartProcess}`, mais seulement dans `internal/archtest`.
6. **Le script de référence du skill échoue ouvert** :
   - `validate.sh` saute en silence un outil absent (`have`) ;
   - il cherche les exceptions par expression régulière dans les seuls `*.tf`, sans voir la casse, `.tofu`, `.tf.json`, les commentaires de bloc ni les fichiers de configuration de scanner ;
   - il lance `tflint --init` par l'API GitHub ;
   - il ne lance Conftest que si l'appelant fournit `REMPART_PLAN` ;
   - `normalize_findings.py` calcule encore l'ancienne empreinte (note de M0-T19d).
7. **Documents de référence** : `docs/01-LOOPS.md` (L3) prévoit trois stratégies, dont une par LLM et une à état séparé, et place Conftest et Infracost dans la chaîne. La vision (section 4) cite elle aussi Conftest et Infracost.

Difficile à inverser :
- la forme de la composition (entrée `initial` des evals, futures L7 et L8, sortie de L3) ;
- l'algorithme d'empreinte du bundle (dossier de preuves et runner, M4) ;
- les codes `EQUIV-*` et d'escalade (graders, baseline humaine) ;
- le nom et la séquence du workflow (T16) ;
- le format du verrou d'outils ;
- la forme d'`IaCInput` et les métadonnées du pack `iac` ;
- la table de traduction des permissions.

Contraintes :
- aucune décision de sécurité par un LLM ;
- mode runner : le plan de contrôle ne détient aucun identifiant cloud, même en lecture ;
- toute donnée externe est non fiable ;
- l'IaC dans Git est la source de vérité ;
- isolation par tenant ;
- échec fermé ;
- chaque outil de la chaîne est du code tiers qui s'exécute sur une entrée potentiellement hostile (T8, section 4.2 du modèle de menace).

## Options envisagées

### Question 1 : proposeur et stratégies (Q1)
1. **(1a) Proposeur déterministe (retenue).**
   - Un compilateur traduit le graphe en composition de modules internes, un réparateur corrige par catalogue fermé.
   - Stratégies `repair` puis `recompile`, plus une forme d'entrée `initial`.
   - Ni prompt, ni route à calibrer, ni architecture envoyée à un fournisseur de modèle (T7), ni HCL libre à analyser (T142, T147).
   - C4 reste non trivial : les trappes partent d'une composition fautive, les stagnations sont réelles et la cible d'evals exécute la vraie chaîne.
2. **(1b) LLM qui écrit le HCL libre de `modules_plus_freeform`.** Écartée en M3 :
   - evals non déterministes (faux scripté en CI pour la mécanique, mesure réelle à trois exécutions par cas, crédit absent) ;
   - architecture envoyée à un fournisseur ;
   - surface d'analyse d'un HCL arbitraire.
3. **(1c) (1a), puis (1b) en troisième stratégie après stagnation.** Reportée : elle s'ajoutera par ADR, derrière le même vérificateur. `decompose_by_cloud` attend le runner (un état par cloud, VPN en racine d'interconnexion, plan en deux temps).

### Question 2 : forme du candidat
1. **(2a) Composition typée en JSON, HCL rendu par Go (retenue).**
   - Candidat borné, décodé strictement, sans expression.
   - Le rendu est la seule source d'HCL, et la réparation porte sur des valeurs typées.
   - L'équivalence de composition se juge avant tout outil.
2. **(2b) Arborescence de fichiers HCL** (gabarit du skill `loop-engineering`). Écartée :
   - tout octet du candidat devient du code évalué à l'`init` et au `plan` (T142) ;
   - réparer revient à éditer du texte ;
   - rien ne se juge avant les outils.
3. **(2c) Syntaxe JSON d'OpenTofu (`.tf.json`).** Écartée : ses chaînes sont des gabarits (`${...}` y est évalué), et la structure n'est pas plus fermée que le HCL.

### Question 3 : entrée et provenance (Q3, T115)
1. **(3a) Recalcul (retenue).**
   - Étapes : `ValidateIR`, `confirm.Check` sur `DigestOfIR`, `Derives(Build(ir), graph)`, vérificateur de L2 rejoué.
   - Déterministe et peu coûteux ; ferme T115 sans attendre M4.
2. **(3b) Confiance dans `subject: ir` de la sortie de L2.** Écartée : la sortie traverse l'historique, la CLI et bientôt l'API, et un champ déclaré ne prouve rien (même raisonnement que pour `confirmed_by`, T107).
3. **(3c) Sortie de L2 signée exigée.** Reportée à M4 (dossier de preuves, signatures). Elle s'ajoutera à (3a) sans la remplacer.

### Question 4 : plan dans la boucle (Q2)
1. **(4a) Plan hors ligne dans le plan de contrôle (retenue, branche nominale).**
   - `tofu plan` sur un état vide éphémère, providers sans identifiant, réseau coupé.
   - Équivalence de plan et pack `iac` à chaque vérification, dans la session comme en CI.
2. **(4b) Repli (retenue si la sonde l'impose, racine par racine).**
   - La boucle juge l'équivalence de composition et les manifestes de modules.
   - Le plan réel est lancé par l'humain en M3, par le runner en M4 ; l'un et l'autre rejouent la chaîne et l'équivalence.
3. **(4c) Identité de lecture détenue par le plan de contrôle.** Écartée : contraire au mode runner et à T27 ; l'agent ne détient aucun identifiant.
4. **(4d) Faux point d'authentification, service de métadonnées simulé ou émulateur d'API.** Écartée :
   - ce composant fabriquerait des jetons acceptés par les providers ;
   - un appel réel avec un jeton faux enverrait des métadonnées d'architecture au fournisseur ;
   - la fidélité n'est pas garantie.
5. **(4e) Fournisseurs simulés (`mock_provider`) pour le bundle.**
   - Écartée pour l'équivalence du bundle : les valeurs calculées sont inventées et le résultat diffère du plan du runner.
   - Retenue pour les tests de modules (C1).

### Question 5 : réglages hors ligne des providers
1. **(5a) Une variable du bundle, `rempart_offline_plan`, de défaut `false` (retenue).**
   - L'artefact planifié hors ligne est exactement le bundle, avec la même empreinte.
   - La règle de garde qui refuse toute surcharge reste absolue.
2. **(5b) Fichier de surcharge écrit par l'exécutant après la garde.** Écartée :
   - l'artefact planifié n'est plus le bundle ;
   - la fusion des surcharges masque le code relu (T142) ;
   - deux chemins de code.
3. **(5c) Environnement seul.** Écartée comme mécanisme unique : tous les réglages n'ont pas d'équivalent documenté par variable d'environnement (la sonde le confirmera). Les clés factices passent, elles, par l'environnement construit.

### Question 6 : providers (Q4)
1. **(6a) Miroir fichier peuplé depuis `releases.hashicorp.com` (retenue).**
   - Sommes `SHA256SUMS` signées vérifiées.
   - Version publiée depuis au moins 14 jours.
   - Configuration CLI en miroir seul.
   - C'est aussi la forme cible du runner (aucun registre au moment du plan) : même chemin en session, en CI et sur le poste de l'humain.
2. **(6b) Ouverture de `registry.opentofu.org` par l'humain.** Écartée :
   - registre joint au moment du plan ;
   - provenance moins contrôlée ;
   - chemin différent de celui du runner.

### Question 7 : politiques sur l'IaC (Q5)
1. **(7a) Second pack du moteur embarqué, faits du plan extraits en Go (retenue).**
   - Règle `opa-confined` inchangée.
   - Mêmes capacités, même barrière, mêmes métadonnées.
   - Parité avec `go tool opa test`, aucune commande de plus.
2. **(7b) Binaire Conftest.** Écartée :
   - OPA d'une autre version (parité perdue) ;
   - builtins d'entrée-sortie, dont `http.send`, disponibles sauf configuration ;
   - format de sortie différent ;
   - une exécution de commande de plus (T8) ;
   - règles écrites sur le plan brut et son texte libre (T2).

### Question 8 : coût (Q6)
1. **(8a) Clé Infracost dans l'environnement cloud, API de prix ouverte.** Écartée : la clé et des données d'architecture partiraient vers un tiers depuis la session et la CI (T7).
2. **(8b) Table de prix codée, datée, sourcée.** Écartée : entretien lourd, exacte seulement sur un sous-ensemble.
3. **(8c) `not_evaluated` en L3 en M3, blocage en L4 sur le plan réel (retenue).**
   - En M3, Infracost ne tourne que dans `sandbox.sh`, avec la clé que l'humain a sur son poste.
   - Le coût n'est pas une décision de sécurité, et Infracost est plus juste sur un plan réel.
   - L'humain a accepté le 2026-11-25 que la lecture « chaîne verte » de C2 exclue le coût.

### Question 9 : ressources de soutien et raffinements (Q7)
1. **(9a) Table fermée dans l'équivalence, allocations dérivées par `internal/design/cidr` (retenue).** Aucun changement de L2, du schéma ni de la baseline `design`.
2. **(9b) Porter au graphe les sous-réseaux par zone, `GatewaySubnet` et NAT.** Écartée en M3 : nouvelle version de schéma, nouvelle baseline humaine, L2 rouverte. Les arêtes de sortie entreront au graphe en M6.

### Question 10 : racines (Q8)
1. **(10a) Deux racines, `infra` puis `cluster` (retenue).** Les providers du cluster dépendent d'un cluster existant ; C2 porte sur `infra`.
2. **(10b) Racine unique.** Écartée : les providers `helm` et `kubernetes` seraient configurés par des valeurs inconnues avant l'apply ; le plan réel serait impossible.
3. **(10c) Une racine par cloud.** Reportée avec `decompose_by_cloud`.

### Question 11 : exceptions de scanners (Q9)
1. **(11a) Aucune annotation nulle part, fichier central revu et expirant (retenue).** Un seul mécanisme, auditable, conforme à T30.
2. **(11b) Annotations admises dans les modules internes.** Écartée :
   - deux mécanismes à tenir ;
   - la garde devrait distinguer module et code généré ;
   - une annotation recopiée dans un candidat échapperait à la revue.

### Question 12 : approbation du bac à sable (Q10, T31)
1. **(12a) Canal hors de portée de l'agent (retenue).**
   - Permission « ask » de Claude Code et identifiants d'écriture obtenus sous MFA par l'humain ; l'agent n'en a jamais.
   - Le script n'applique que le plan enregistré dont l'empreinte a été affichée.
   - Aucun apply en M3.
2. **(12b) Contrôle dans `scripts/sandbox.sh`, ou confirmation lue sur `/dev/tty`.** Écartée comme approbation :
   - l'agent peut modifier le script localement ;
   - un pseudo-terminal peut répondre « oui » (T29, T31).
   La confirmation sur `/dev/tty` reste une garde de plus, pas une approbation.

### Question 13 : admission Kubernetes (Q11)
1. **(13a) Pod Security Admission `restricted` (retenue).** Intégré à Kubernetes, aucun composant de plus.
2. **(13b) Kyverno ou Gatekeeper dès M3.** Écartée : composant et surface de plus. Le choix se fera par ADR en M5, avec `policies/k8s/`.

### Question 14 : analyse du HCL et forme de la garde (D7, D20)
1. **(14a) `hcl/v2` (`hclsyntax`, `hclwrite`), garde en liste blanche (retenue).** Analyse de l'arbre et des commentaires ; le rendu passe par le même module.
2. **(14b) Expressions régulières** (`validate.sh` actuel). Écartée : contournables (casse, commentaire de bloc, heredoc, `.tofu`, `.tf.json`) et aveugles aux expressions.
3. **(14c) Analyse par OpenTofu lui-même.** Écartée : elle exécute l'outil, `init` compris, avant la garde, et ne rend ni commentaires ni appels de fonction.
4. **(14d) Garde en liste de refus.** Écartée : un bloc, une fonction ou une source de données apportés par une montée de version (`ephemeral`, fonctions de provider) passeraient sans revue. C'est le raisonnement de l'option 3b de l'ADR 0011.

### Question 15 : traduction des permissions (D11)
1. **(15a) Table fermée, sourcée, datée ; rôles Azure personnalisés (retenue).**
2. **(15b) Politiques gérées AWS et rôles intégrés Azure.** Écartée : leur définition peut changer sans nous, d'où un élargissement silencieux (T117).
3. **(15c) Traduction proposée par un modèle.** Écartée : ce serait une décision de sécurité prise par un LLM.

### Question 16 : nom et place des evals (Q12)
1. **(16a) `evals/iac` (retenue).** Cible `iac`, `loop: L3-iac`, `runs: 1`, baseline hors registre des routes ; cohérent avec `evals/design`.
2. **(16b) `evals/L3/`** (gabarit du skill). Écartée : nommage différent des suites existantes.

## Décision

D1 à D20 reprennent la numérotation de la section 3 du plan. Correspondance avec les questions du plan :

| Question du plan | Décisions |
|---|---|
| Q1 | D1, D2 |
| Q2 | D8 |
| Q3 | D3 |
| Q4 | D15 |
| Q5 | D9 |
| Q6 | D14 |
| Q7 | D12, D13 |
| Q8 | D5 |
| Q9 | D16 |
| Q10 | D17 |
| Q11 | D19 |
| Q12 | D18 |
| Q13 | hors de cet ADR : (fd), (cf) et proposition CI 0011, traitées en M3-T01 |

### D1. Proposeur déterministe (option 1a)
- `iacgen.Compile(graph)` rend la composition compilée. Pour chaque élément irréalisable, il ajoute un finding critique : `L3-MODULE-MISSING` ou `L3-NO-TRANSLATION`.
- `repair.Repair` corrige la composition courante par le catalogue fermé de D2.
- En M3, L3 ne contient ni appel de modèle, ni prompt, ni texte de modèle.
- Aucun import de `internal/llm` sous `internal/iacgen`, `internal/validate`, `internal/plan` et `internal/loops/l3` (vérification 1).
- Le vérificateur (D6, D10) est indépendant du proposeur :
  - il ne lit ni `applied` ni l'historique des corrections ;
  - il juge `initial` comme toute autre composition.

### D2. Stratégies `repair` puis `recompile`, catalogue fermé (options 1a, 1c)
- `Spec().Strategies` = `[repair, recompile]` ; `SwitchAfter` 2, `EscalateAfter` 3 (règle 5 du skill `loop-engineering`).
- `repair` applique une correction par finding reconnu, et rien d'autre :

| Correction | Finding (étage `composition`) | Effet |
|---|---|---|
| `pin_version` | `L3-MODULE-VERSION` sur un appel (module du catalogue, version différente) | version de l'appel := version du catalogue |
| `remove_orphan` | `EQUIV-ORPHAN` sur un appel ou un `extra` | appel ou `extra` retiré |
| `add_missing` | `EQUIV-MISSING` sur un élément du graphe | ajout de l'appel compilé qui le réalise, sous le même identifiant |
| `set_from_graph` | `EQUIV-ATTR` sur une entrée d'appel | entrée := valeur compilée |

- **Propriété** testée par `TestRepairNeverAddsOutsideCompiler` (rapid, 1 000 tirages) :
  - tout appel, `extra` ou entrée de la composition réparée est soit compilé, soit d'origine et inchangé ;
  - aucune correction n'invente de valeur ;
  - `Applied` n'a d'entrée que si la composition a changé pour ce couple (code, ressource).
- **`recompile`** : la composition redevient `Compile(graph)`, et tout ce que le compilateur ne produit pas est abandonné.
- **Finding sans correction** (outils, pack, équivalence de plan, `L3-MODULE-MISSING`, `L3-NO-TRANSLATION`) : l'empreinte ne change pas, ce qui mène à la bascule puis à l'escalade codée (D18).
- **Stratégies reportées**, chacune soumise à un ADR :
  - `modules_plus_freeform` : route, baseline, emplacement `extra` ;
  - `decompose_by_cloud` : runner, plan en deux temps.
  `docs/01-LOOPS.md` est amendé en conséquence (amendement 1).

### D3. Entrée et provenance recalculée (option 3a, T115)
- `Input{IR, Confirmation, Graph, Initial?}`, sans tenant : c'est celui du worker qui fait foi.
- `l3.Prepare` est la première activité, déterministe et sans effet. Contrôles, dans cet ordre :
  1. bornes (entrée de 256 Kio au plus à la lecture) ; décodage strict dans des valeurs nulles ;
  2. tenant de l'IR, du graphe et d'`initial` égal à celui du worker ;
  3. `ValidateIR` ;
  4. `confirm.Check(DigestOfIR(ir), confirmation)` qui rend un ensemble vide de clés non confirmées (une sortie convergée de L2 les couvre toutes) ;
  5. `verify.Derives(Build(ir, défauts), graph)` ;
  6. vérificateur de L2 rejoué sur `graph` (pack `design` et invariants du cœur) : aucun finding critique ni haut, toutes les expositions couvertes ;
  7. `initial` décodé par `composition.Decode`, avec `TenantID` et `GraphRevision` égaux à ceux du graphe.
- **Tout échec** donne l'erreur non rejouable `InvalidL3Input`, avec un message fixe sans donnée citée, avant toute activité de boucle (`TestL3RefusesGraphSubject`, `TestL3TenantMismatchRefused`).
- **Escalade sans boucle** : seulement `payload_too_large`, quand la charge de `RunLoop` ou la composition compilée dépasse 64 Kio.
  - Un élément sans module ou sans traduction n'arrête pas `Prepare`.
  - La boucle le revoit à chaque itération, sans correction possible, et c'est la stagnation qui escalade (écart 5).
- **Aucun sujet `graph`** (éditeur, import) : une sortie de L2 sans IR ne peut pas former l'entrée.
  - Lever T115 exigera un ADR qui impose une confirmation signée et l'empreinte de la sortie convergée de L2 (M4 au plus tôt).
  - Cela tranche la question 2 de l'ADR 0013 : sans cet ADR, l'éditeur conçoit mais ne déploie pas.
- **`initial`** n'est jamais de confiance : c'est un point de départ que le vérificateur juge.

### D4. Composition typée, HCL rendu par Go (option 2a, T147)
- **Candidat** : une composition JSON, jamais du HCL. Paquet `internal/iacgen/composition`, qui n'importe que la bibliothèque standard et `internal/*/domain`.
- **`Decode`** est strict : champ inconnu, clé en double ou valeur après le document sont refusés ; taille au plus `loops.MaxCandidateBytes`. Grammaires fermées :

| Élément | Grammaire |
|---|---|
| identifiants d'appel et d'`extra` | `^[a-z][a-z0-9_]{0,62}$` |
| `ModuleRef.Name` | `^[a-z][a-z0-9-]{1,40}$` |
| `ModuleRef.Version` | au plus 32 caractères de `[0-9A-Za-z.~>=<!, -]` : une contrainte flottante se décode, puis le vérificateur la juge (`L3-MODULE-VERSION`) |
| type d'`extra` | `^(aws\|azurerm\|helm\|kubernetes)_[a-z0-9_]{1,64}$` |
| `Realizes` | identifiants du schéma du graphe |
| racines | `infra` puis `cluster`, dans cet ordre |
| `Value` | au plus 8 niveaux ; `Kind` dans {`string`, `number`, `bool`, `list`, `map`, `ref`} ; `Ref` vers une sortie d'un appel de la même racine |

- **Aucune expression** : une chaîne est toujours un littéral.
  - Le compilateur ne lit aucun texte libre du graphe ni de l'IR (`summary`, `justification`, `notes`, `purpose`).
  - Étiquettes et noms viennent de champs fermés.
- **`Render`** :
  - utilise `hclwrite`, dans un ordre total (racines, puis appels et `extra` par identifiant, puis entrées par clé) ;
  - échappe `${` et `%{` (en `$${` et `%%{`) dans toute chaîne ;
  - n'écrit aucun heredoc ;
  - n'écrit de référence que sous la forme `module.<appel>.<sortie>`, construite depuis des identifiants vérifiés ;
  - refuse, par une erreur, toute composition hors catalogue.
  Les variables des modules valident leurs entrées (contrat) : une chaîne hors grammaire échoue à l'étage `validate`.
- **Aucune référence entre racines** : `cluster` reçoit ce qu'elle tire d'`infra` par des variables fournies par l'exécutant, jamais par `terraform_remote_state`.
- **`extra`** : bloc de ressource typé (type en liste fermée par élément du graphe, attributs littéraux). C'est l'emplacement réservé au HCL libre d'une future stratégie.
  - Le compilateur de M3 n'en produit pas.
  - `initial` peut en porter (trappes) ; le vérificateur les juge.

### D5. Bundle (option 10a)
- **Deux racines**, appliquées dans cet ordre (une racine sans appel est omise) :
  - `infra` : réseaux, calcul, clusters, VPN ;
  - `cluster` : ArgoCD et applications.
- **C2** porte sur le plan réel d'`infra`. `cluster` est vérifiée par `tofu test` et par le plan hors ligne ; son plan réel n'aura lieu qu'après un `sandbox-apply` facultatif d'`infra`, hors critères.
- **Modules vendorisés depuis le binaire** :
  - `modules/embed.go`, avec la règle `modules-confined` : seul `internal/iacgen` importe le paquet `modules` ;
  - copiés dans `<racine>/modules/<nom>/` ;
  - manifeste SHA-256 par fichier à la racine du bundle ;
  - `CatalogDigest` = empreinte du catalogue embarqué.
- **Verrou des providers** (`.terraform.lock.hcl`, hachages `zh:` et `h1:`) : un par racine, rendu depuis un verrou commun du dépôt (mêmes versions et mêmes hachages pour un même provider).
- **Ce que le bundle ne contient pas** : aucun bloc `backend`, `cloud` ni `encryption`, aucun bloc `provider` porteur d'identifiant.
  - Les valeurs propres à l'exécutant sont des variables : `rempart_owner`, `rempart_change_id`, identifiants de compte et d'abonnement, zones de disponibilité.
  - L'état est chiffré par `TF_ENCRYPTION`, que fournit l'exécutant : l'humain en M3, le runner en M4. Le runner pose le backend distant par tenant (M4).
- **Empreinte du bundle** : SHA-256 hexadécimal minuscule de la suite des netstrings (chemin relatif, contenu) de tous les fichiers, triés par chemin.
- **Sortie de L3** : la composition et cette empreinte. `rempart iac compile` reconstruit le bundle à l'identique, si bien qu'aucun gros objet n'entre dans l'historique Temporal.

### D6. Chaîne (`internal/validate`, options 7a et 14a)
- **Ordre des étages**, du moins cher au plus cher, avec arrêt au premier étage bloquant (les suivants passent à `skipped`) :
  1. `composition` (L3 seulement, en Go, avant le rendu : `CheckComposition` et contrôle du catalogue, écart 1) ;
  2. `static` (D7 ; aucun outil ne tourne sur un arbre refusé) ;
  3. `fmt` ;
  4. `init` (miroir seul, `-backend=false`, `-lockfile=readonly`, `-input=false`) ;
  5. `validate` ;
  6. `tflint`, `checkov` et `trivy`, en parallèle ;
  7. `plan` (D8) ;
  8. `policy` (pack `iac`, D9) ;
  9. `equivalence` (plan, D10) ;
  10. `cost` (`not_evaluated`, D14).
  Les étages `plan`, `policy` et `equivalence` sont rendus racine par racine (`StageResult.Root`).
- **Un seul exécutant**, `toolexec.Run`, garanti par la règle `exec-confined` :
  - la règle porte sur `os/exec` ;
  - elle est complétée par un contrôle de sources, sur le modèle de `checkExecUsage` : `os.StartProcess`, `syscall.Exec`, `syscall.ForkExec`, `syscall.StartProcess` et `golang.org/x/sys/unix.Exec` sont refusés hors de `internal/validate/toolexec` (écart 8).
- **Conditions d'exécution** :
  - sans shell, arguments en tableau ;
  - environnement construit, sans aucune variable héritée parmi `AWS_*`, `ARM_*`, `TF_*`, `KUBECONFIG` et `HTTPS_PROXY` ;
  - `HOME`, `TMPDIR` et `TF_DATA_DIR` éphémères ;
  - `TF_CLI_CONFIG_FILE` pointe vers la configuration en miroir seul ; `CHECKPOINT_DISABLE=1` ;
  - un délai tue le groupe de processus ;
  - sorties bornées : au-delà de la borne, c'est une erreur, jamais une sortie tronquée qu'on lirait quand même ;
  - répertoire de travail éphémère ouvert par `os.Root`.
- **Échec fermé** : chacun des cas suivants donne un finding critique :
  - outil absent (`TOOL_MISSING`) ;
  - somme fausse, délai dépassé, code de sortie hors de la table documentée de l'outil (`TOOL_FAILED`) ;
  - sortie illisible ou au-delà de sa borne (`TOOL_OUTPUT_INVALID`) ;
  - sévérité inconnue.
  La correspondance des sévérités est une table fermée par outil.
- **Findings** :
  - format `loopsdomain.Finding`, empreinte et score de `loopsdomain` ;
  - les 100 plus graves sont rendus, avec un compteur d'omis ;
  - les 20 premiers sont renvoyés au proposeur.
- **Messages d'outil**, toujours non fiables :
  - caractères C0, C1, bidirectionnels et séquences ANSI échappés ;
  - 500 runes au plus ;
  - jamais lus par une décision : le proposeur ne lit que le code et la ressource.
- **Parité avec le script du skill** : `scripts/validate.sh` et `normalize_findings.py` sont alignés.
  - Mêmes `findings.json`, empreinte et score sur les mêmes sorties brutes (`TestNormalizeParityWithScript`, lancé par `python3 -I`, sur au moins 10 jeux).
  - Garde statique par `rempart check --static`.
  - Outil absent : finding critique.
  - Aucun Conftest.
  - Fichier d'exceptions et date passés en argument (D16).
- **Commande** : `rempart check [--module] [--static] [--json] [--graph-input <entrée L3>] [--plan <plan.json>] <dossier>`.
  - En M3, deux formes seulement : bundle Rempart (manifeste exigé) et module interne. Une IaC tierce relève de l'import (M6).
  - Codes de sortie : 0 (aucun finding bloquant), 1 (findings), 2 (usage).

### D7. Garde statique en liste blanche (options 14a et 14d, T30, T142 à T144)
- **Portée** :
  - elle travaille sur l'arbre analysé (`hclsyntax`, commentaires compris), jamais par expression régulière seule ;
  - elle s'applique en mode `bundle` comme en mode `module`, avant tout outil ;
  - elle rend toutes les violations, sans s'arrêter à la première.
- **Fichiers admis**, en liste fermée :
  - `*.tf` ;
  - `.terraform.lock.hcl` à la racine d'une racine, admis par la garde mais jamais lu : la chaîne l'écrase avec la sortie de `ProviderLockFile` avant `init` (D15 ; obligation (hm) : test qui montre qu'un `h1:` étranger venu de l'arbre n'atteint jamais tofu) ;
  - `README.md`, `SECURITY.md` ;
  - le manifeste ;
  - les archives de charts listées au manifeste ;
  - en mode `module` seulement : `tests/*.tftest.hcl` et `examples/basic/*.tf`.
  Tout autre fichier est refusé, notamment :
  - `*.tofu`, `*_override.tf`, `*.tf.json` ;
  - `.terraformrc`, `terraform.rc`, `.terraform/` ;
  - `.tflint.hcl` (celui de la chaîne vit hors de l'arbre), `.checkov.y*ml`, `.trivyignore*`, `trivy.y*ml`.
  Sont refusés aussi : les liens symboliques, les fichiers non UTF-8, les fichiers au-delà de leur borne.
- **Blocs admis**, en liste fermée :

| Bloc | Condition |
|---|---|
| `terraform` | `required_version` et `required_providers` seulement, version exacte et source en liste |
| `provider` | bundle seulement ; attributs en liste fermée par provider ; refusés : `endpoints`, `assume_role*`, `profile`, `shared_*`, clés, jetons, secrets et certificats de client |
| `variable`, `locals`, `output` | aucune condition propre |
| `module` | source `./modules/<nom>` présente au manifeste ; en mode `module`, `../..` admis dans `examples/` seulement |
| `resource` | `lifecycle` admis ; `provisioner` et `connection` refusés |
| `data` | types en liste fermée, calculés localement (par exemple `aws_iam_policy_document`) |

  Sont refusés :
  - les blocs `backend`, `cloud`, `encryption`, `import`, `removed`, `check`, `ephemeral` ;
  - les sources de données `external`, `http`, `terraform_remote_state`, et toute source qui appelle une API ;
  - les ressources `local_file` et `local_sensitive_file`.
- **Fonctions admises** : liste fermée de fonctions pures et déterministes (chaînes, collections, encodage, `cidrsubnet` et fonctions réseau voisines, hachage). Sont notamment refusées :
  - `file*`, `templatefile`, `templatestring`, `pathexpand`, `abspath` ;
  - `timestamp`, `plantimestamp`, `uuid*`, `bcrypt` ;
  - toute fonction de provider (`provider::*`).
- **Annotations** de scanner, dans tout commentaire (`#`, `//`, `/* */`) et quelle que soit la casse : `checkov:skip`, `trivy:ignore`, `tflint-ignore`, `tfsec:ignore`, `#nosec`. Chacune donne `FORBIDDEN_EXCEPTION`, critique, y compris dans les modules (D16).
- **Modules vendorisés** dont la somme diffère du manifeste : `MODULE_TAMPERED`.
- **Ce que la garde ne juge pas** : le type d'une ressource gérée, qui relève de l'équivalence (D10). Une ressource injectée passe la garde, et c'est l'équivalence qui l'arrête (C3).
- **Tenue des listes** (fichiers, blocs, attributs de provider, sources de données, fonctions) :
  - littéraux Go de `internal/validate`, sous CODEOWNERS ; tout ajout passe par revue ;
  - les refus nommés ci-dessus restent des cas de `TestStaticGateRefusesCodeExecution` et `TestStaticGateForbiddenAnnotations` (écart 2).

### D8. Plan hors ligne (options 4a, 4b, 5a)
- **Commande** : `tofu plan -refresh=false -lock=false -input=false -out=<fichier éphémère>` sur un état vide éphémère, puis `tofu show -json`.
  - Le résultat est décodé par `plan.Decode` : strict, borné, `format_version` en liste blanche, adresses en double refusées.
  - En L3, toute action autre que `create` donne `EQUIV-PLAN-INVALID`.
- **Aucun identifiant** :
  - les réglages hors ligne des providers sont portés par le bundle, sous une seule variable booléenne `rempart_offline_plan` (défaut `false`, rendue par Go), jamais par un fichier de surcharge ;
  - AWS : `skip_credentials_validation`, `skip_requesting_account_id`, `skip_metadata_api_check`, `skip_region_validation`, et des clés factices dans l'environnement construit ;
  - azurerm et helm : réglages fixés par la sonde.
  - Jamais de faux point d'authentification, de service de métadonnées simulé ni d'émulateur d'API.
- **Aucune source de données qui appelle une API** (D7) : zones de disponibilité, identifiants de compte et d'abonnement arrivent en variables.
- **Réseau coupé pour le processus** :
  - `HTTPS_PROXY` et `HTTP_PROXY` pointent vers une adresse locale injoignable, `NO_PROXY` est vide ;
  - en production, le processus outil n'a aucune route réseau (espace de noms réseau ou politique de sortie, M4 avec le déploiement) ;
  - une coupure par mandataire reste déclarative (risque résiduel 1).
- **Branche nominale**, quand la sonde classe chaque provider faisable, avec ou sans réglage :
  - étage `plan` dans `l3.Verify` et dans `rempart check` ;
  - `IaCInput`, pack `iac` et équivalence de plan calculés sur ce plan ;
  - L3 ne converge que si l'équivalence de plan passe.
- **Branche de repli**, quand au moins un provider est impossible. Elle s'applique racine par racine :
  - une racine dont un provider ne se planifie pas hors ligne a `plan`, `policy` et `equivalence` à `not_evaluated`, jamais `ok` ;
  - la boucle juge alors l'équivalence de composition et les manifestes de modules (tables fermées de D13, tenues par les tests `tofu test` à fournisseurs simulés de chaque module) ;
  - la sortie convergée le dit, racine par racine ;
  - aucun déploiement (L4, M4) n'est possible sans équivalence de plan passée sur le plan réel ;
  - le plan réel est lancé par l'humain en M3 (`make sandbox-plan`, qui rejoue chaîne et équivalence), par le runner en M4 ;
  - C3 se démontre sur un scénario dont la racine `infra` n'emploie que le provider AWS (écart 6).
- **Choix de la branche** : il découle de la section « Résultat de la sonde », figée par `TestOfflinePlanProbe` (intégration).

### D9. Pack `policies/iac` dans le moteur embarqué (option 7a, amende ADR 0011 D1, D4, D5, D6, D8, vérifications 2, 12 et 13)
- **Constructeur** : `opa.NewIaC()`, dans le seul adaptateur OPA. Il suit le même chemin de compilation que `NewDesign`, paramétré par pack : système de fichiers embarqué, préfixe de paquet, requête, schéma. Il partage avec le pack `design` :
  - la barrière AST (références `data` limitées à `data.rempart.iac`, obligation (fk)) ;
  - les capacités (`capabilities.json` unique) ;
  - les options `rego.` ;
  - les métadonnées ;
  - les bornes et l'échec fermé.
  La règle `opa-confined` ne change pas.
- **Embarquement et nommage** :
  - `policies/embed.go` porte `//go:embed iac/*.rego` et `var IaC embed.FS` ;
  - paquets `rempart.iac.<nom>`, prédicats partagés dans `rempart.iac.lib`, tests dans `rempart.iac_test.<nom>` ;
  - requête `data.rempart.iac[_].deny[_]`.
- **Entrée `policy.IaCInput`** :
  - faits typés par ressource du plan, extraits en Go par `NewIaCInput(plan, facts)` ;
  - schéma `schemas/policy/iac-input-v1.json` (`additionalProperties: false`), passé au compilateur et à `opa check` ;
  - jamais le plan brut, jamais de texte libre ;
  - un type de ressource sans extracteur donne `ErrIaCInput`, et l'étage `policy` échoue (critique).
- **Sortie** `{control_id, resource}` :
  - `resource` est l'adresse d'une ressource de l'entrée ; `Source` vaut `policy:iac` ;
  - `control_id` est unique dans le pack ;
  - il est repris de `policies/design` quand l'intention est la même, avec la même sévérité (sous-cas de `TestIaCPackMetadataComplete`).
- **Contenu** : au moins 10 contrôles en M3-T03 (liste de la fiche), chacun avec un cas `ok` et un cas `ko` (`TestIaCEveryControlHasOkAndKo`).
- **`Makefile`** : une invocation par pack (deux en tout) de `go tool opa check --strict --capabilities internal/policy/adapters/opa/capabilities.json --schema schemas/policy/<pack>-input-v1.json policies/<pack>`, puis `go tool opa test policies/`.
- Conftest n'est utilisé nulle part (vérification 10).

### D10. Équivalence à deux niveaux (option 9a, T146)
- **Niveau composition** (`CheckComposition`, Go pur, étage `composition`) :
  - chaque appel et chaque `extra` réalise des éléments existants du graphe, sinon `EQUIV-ORPHAN` ; un `extra` dont le type n'est pas dans la table fermée de l'élément qu'il réalise est lui aussi orphelin ;
  - chaque élément du graphe est réalisé, sinon `EQUIV-MISSING` ;
  - chaque module appartient au catalogue, à la version exacte, sinon `L3-MODULE-VERSION` ;
  - les entrées de sécurité sont égales à celles que dicte le graphe, sinon `EQUIV-ATTR`.
- **Niveau plan** (`CheckPlan`, étage `equivalence`) :
  - chaque ressource du plan, gérée ou donnée, se rattache à un appel de la composition par son adresse de module (`module.<appel>...`), ou à un `extra` par `<type>.<id>` ; jamais par son nom ni par une étiquette (`rempart_node` est ignoré) ;
  - son type figure dans la table fermée du module pour l'élément réalisé, à la cardinalité attendue (`count` et `for_each` compris) ;
  - l'atteignabilité tirée des règles SG et NSG du plan est incluse dans celle du graphe (`reach.SubsetOf`, une seule implémentation) ;
  - les actions IAM du plan sont incluses dans la traduction (D11) ;
  - les adresses publiques ne portent que sur les éléments exposés du graphe ;
  - les attributs de sécurité sont présents (chiffrement, journaux, API privée).
- **Codes** :
  - critiques : `EQUIV-ORPHAN`, `EQUIV-MISSING`, `EQUIV-REACH`, `EQUIV-IAM`, `EQUIV-PUBLIC`, `EQUIV-ATTR`, `EQUIV-PLAN-INVALID` (plan tronqué, forgé ou d'un autre run, action autre que `create` en L3) ;
  - non bloquant : `EQUIV-EGRESS` (`low`) signale l'egress par NAT (D13, T150).
- **Plan jugé** : celui du même run (fichier éphémère produit par `Planner`), jamais un plan reçu. Deux exceptions, jugées avec les mêmes règles : `rempart check --plan` et `sandbox.sh`, qui décodent le plan réel.

### D11. Traduction des permissions (option 15a, T117)
- **Table** : littéral Go trié de `internal/iacgen/iam`. Lignes `{Cloud, Target, Subtype, Action, Mode, Actions, Source, Verified}`, clé (cloud, type et sous-type de cible, action abstraite), versionnée.
  - `Source` : URL `https` d'un domaine du fournisseur, en liste fermée ;
  - `Verified` : date au format `AAAA-MM-JJ`.
- **Vérification des lignes** :
  - lignes AWS vérifiées par l'agent sur `docs.aws.amazon.com` ;
  - lignes Azure en attente de l'humain (H-permissions), figées par test comme l'ont été les lignes Azure de juridiction ;
  - une ligne en attente n'est pas utilisée : `L3-NO-TRANSLATION`.
- **Règles de traduction** :
  - aucun joker (`*`, `?`) ;
  - aucune action d'une autre catégorie (`read` ne contient aucun verbe d'écriture ni d'administration) ;
  - portée : la ressource elle-même ;
  - Azure : rôles personnalisés aux `Actions` et `DataActions` exactes, jamais un rôle intégré ;
  - `admin` et `*` ne sont jamais traduits en M3 ;
  - `dataset` hébergé par un `Compute` : ligne `host_local` (aucune permission cloud).
- **Sans ligne** : `L3-NO-TRANSLATION`, critique, puis escalade `no_translation`.

### D12. Allocations dérivées (option 9a, T116, T150)
- Toutes passent par `internal/design/cidr` et sont contrôlées par `cidr.Check` sur l'union avec le plan du graphe :
  - sous-réseaux par zone de disponibilité, contenus dans le sous-réseau du graphe (EKS et LB exigent deux zones) ;
  - `GatewaySubnet` /27, dans l'espace libre du VNet ;
  - /30 APIPA dans la plage Azure ;
  - ASN explicites : 64512 (AWS) et 65515 (Azure).
- Les sources des règles réseau sont calculées depuis les `MEMBER_OF`, jamais depuis `path`.

### D13. Ressources de soutien (option 9a)
- **Table fermée** (module, type d'élément) vers (types, cardinalité exacte, attributs contraints), par exemple :
  - passerelle Internet d'un VPC à tier public ;
  - NAT d'un cluster à nœuds privés ;
  - tables de routage, journaux de flux ;
  - clés KMS et Key Vault, groupes de journaux ;
  - rôles de plate-forme EKS et AKS, dont les politiques gérées sont épinglées par ARN dans la table.
- **Egress par NAT** : signalé à part (`EQUIV-EGRESS`). Les points de terminaison privés à la place du NAT restent une option de l'humain.
- **Un seul lieu de vérité** : cette table sert aux manifestes de modules (tests `tofu test`) et à l'équivalence de plan.

### D14. Coût (option 8c)
- **Port `CostEstimator`** : en M3, l'étage `cost` rend `not_evaluated`, sans finding bloquant.
- **Blocage en L4**, sur le plan réel (M4).
- **Infracost** ne tourne que dans `sandbox.sh`, avec la clé que l'humain a dans son environnement. Le résultat y est affiché, jamais bloquant en M3.
- **Lieu d'exécution en L4** (runner ou API de prix) : décidé par l'ADR de L4.

### D15. Outils et providers (option 6a, T6, T143)
- **Script et verrou** : `scripts/iac-tools.sh` (`install`, `verify`, `mirror`, `env`) travaille sur le verrou `scripts/iac-tools.lock.json`.
  - Chaque outil y porte : nom, version exacte, URL `https` sur un hôte listé, SHA-256, date de publication, empreinte de la clé de signature.
  - Les binaires vont dans un cache hors dépôt.
  - Règle de version : la plus récente publiée depuis au moins 14 jours, sauf correctif de sécurité consigné.
- **Providers** :
  - miroir fichier peuplé depuis `releases.hashicorp.com`, sommes vérifiées sur `SHA256SUMS` signé ;
  - le verrou porte, pour chaque provider, la somme `zh:` de l'archive et la somme `h1:` du paquet (dirhash Hash1 de son contenu) ; `LoadToolchain` vérifie que le `h1:` est celui de l'archive vérifiée ;
  - OpenTofu lit un **miroir privé** : chaque archive du verrou y est copiée et hachée pendant la copie, rien d'autre. Toute entrée du miroir du cache que le verrou ne nomme pas (paquet dépaqueté, autre version, autre provider, lien) fait refuser le chargement (T156) ;
  - configuration CLI `provider_installation` en miroir seul (aucun `direct`, `network_mirror` ni `credentials`) ;
  - le `.terraform.lock.hcl` de chaque racine est rendu depuis le verrou (`ProviderLockFile` : version, `h1:` et `zh:`), jamais repris de la racine, puis OpenTofu s'initialise avec `-lockfile=readonly`. **Correction issue de la revue de M3-T02** : un verrou de racine qui ne porte que des sommes `zh:` n'authentifie rien. OpenTofu 1.13.2 installe alors un paquet dépaqueté planté à côté de l'archive vérifiée, avec un simple avertissement (« unauthenticated »). Seule la somme `h1:` le fait refuser (`TestOfflineInitRefusesPlantedPackage`).
- **Vérification au moment de l'exécution** : `LoadToolchain` revérifie la somme sur une copie privée en lecture seule placée dans le répertoire éphémère, et l'outil s'exécute depuis cette copie. Il n'y a donc pas de fenêtre entre vérification et exécution sur un fichier modifiable par un tiers.
- **Checkov** :
  - venv installé par `pip --require-hashes` (`scripts/checkov-requirements.lock`) ;
  - arbre haché et vérifié au démarrage du worker ;
  - lancé par `python3 -I` avec `--skip-download`.
- **Trivy** : tourne sur ses règles embarquées, sans mise à jour (option exacte vérifiée en T02). L'incident signalé sur ses artefacts au premier semestre 2026 doit être vérifié à la source avant d'épingler (R3).
- **tflint** : rulesets et charts Helm pris depuis les actifs de releases GitHub, sommes au verrou ; jamais `tflint --init`.
- **Revue** : l'humain relit le verrou (H-tools-lock). Le verrou est sous CODEOWNERS (proposition 0013). Il n'a **pas** de garde d'écriture : la proposition 0013 l'exclut, car l'agent doit pouvoir le monter de version. Résidu : un verrou modifié par l'agent sous injection n'est arrêté que par sa grammaire fermée (Go, script, archtest), par la relecture humaine et par les code owners.

### D16. Exceptions de scanners (option 11a, T30, T148)
- **Aucune annotation**, nulle part, modules compris.
- **Fichier central `modules/scanner-exceptions.json`**, sous CODEOWNERS et sous garde d'écriture du harnais. Une entrée par (outil, check, module, adresse) :
  - justification de 20 caractères au moins ;
  - expiration à 180 jours au plus de l'approbation ;
  - approbateur humain et date d'approbation.
- **Erreurs** : une entrée périmée, au-delà de 180 jours, mal formée ou sans finding correspondant est une erreur.
- **Date d'évaluation** : injectée (`Options.Today`) ; aucun test ne dépend du jour.
- **Périmètre** : les findings de tflint, Checkov et Trivy sur le code des modules vendorisés, et rien d'autre. Ne sont jamais couverts : la garde statique, le pack `iac`, l'équivalence, les échecs d'outil, le code rendu hors des modules.
- **Traçabilité** : un finding couvert sort du calcul de `OK` et de l'empreinte, mais il est listé à part (`Report.Excepted`) pour le futur dossier de preuves. Il n'est jamais passé sous silence.

### D17. Bac à sable (option 12a, T31, T149)
- **Plan** : seule action exigée en M3.
  - Identité en lecture (AWS `ReadOnlyAccess`, Azure `Reader`), fournie par l'environnement de l'humain.
  - Sans elle : code 2, avant tout appel d'outil, avec le message « identifiants de bac à sable absents ; aucune action ».
- **`apply` et `destroy`** : seulement sur le fichier de plan enregistré dont l'empreinte a été affichée, après la permission « ask » et des identifiants d'écriture obtenus sous MFA par l'humain. Aucun apply en M3.
- **Sortie** : résumé JSON sans identifiant de compte (`plan_real`, `chain_ok`, `equivalence_ok`, `plan_sha256`, `findings_blocking`).
- **Données locales** : `.sandbox/` est ignoré par git ; état et plan sont chiffrés par le chiffrement natif d'OpenTofu.
- **Comptes** : dédiés, alertes de budget, régions limitées à `eu-west-3` et `francecentral` (H-sandbox-accounts).
- **Recettes du `Makefile`** : durcies en M3-T01 (ligne unique chaînée par `&&`, préfixe `-`, `.IGNORE` et `MAKEFLAGS` refusés).

### D18. Boucle, workflow, worker, evals (option 16a)
- **`Spec()`**, littéral constant :
  - identifiant `L3-iac` ; activités `l3.Propose` et `l3.Verify` ;
  - 8 itérations, `MaxTokens` 1 (aucun modèle), 30 minutes ;
  - `ActivityTimeout` de 10 minutes ; seuils 2 et 3 ;
  - délai d'exécution du workflow calculé par `LoopSpec` (T10).
  `Prepare` et `Finalize` : 2 minutes, trois tentatives, types non rejouables de `loops`.
- **Activités** : `Propose` décode le meilleur candidat dans une valeur nulle (règle T122).
- **`Finalize`** :
  - rejoue la garde statique et l'équivalence de composition sur le candidat final ;
  - lie le rapport à l'empreinte du bundle ;
  - rend une explication codée en cas d'escalade.
- **Escalade** : ni composition, ni bundle, ni `best` (analogue de T98). Codes :
  - `module_missing`, `no_translation`, `equivalence_violation`, `chain_failed` ;
  - `tool_unavailable`, `payload_too_large`, `evaluation_failed`, `manual_fix_required`.
  Le gabarit français est fixe pour chaque code, paramétré seulement par un code de finding et une ressource vérifiés par grammaire.
- **Workflow** :
  - nom `rempart.l3.v1`, file `rempart-l3`, historique chiffré (ADR 0001) ;
  - tout changement ultérieur de séquence passe par `workflow.GetVersion`, avec un identifiant `l3-<objet>` déclaré dans `internal/loops/versions.go` ;
  - historique de référence enregistré si la pile est disponible, sinon obligation datée (R13).
- **Worker** :
  - options `-l3-once` (exclusive des autres `-*-once`) et `-l3-input` (chemin relatif `.json`, strict, 256 Kio au plus, lu par `internal/design/fsread`) ;
  - avant toute connexion à Temporal : `LoadToolchain`, `opa.NewDesign()` et `opa.NewIaC()` ; un échec arrête le processus sans enregistrement ;
  - `codec.Check` avant l'enregistrement ;
  - `prctl(PR_SET_DUMPABLE, 0)` avant tout outil.
- **Evals (Q12)** :
  - `evals/iac`, cible `iac`, `loop: L3-iac`, `runs: 1`, 21 cas ;
  - la cible exige la vraie chaîne : si elle est absente, c'est une erreur d'exécution, jamais un succès (T151) ;
  - baseline humaine `evals/iac/baseline.json`, hors registre des routes ; amendement de l'ADR 0005 si besoin.

### D19. Faits Kubernetes réalisés (option 13a)
- **`admission_policy`** : Pod Security Admission `restricted` sur les espaces de noms hors système.
- **`network_policy_default_deny`** : moteur de politique réseau activé (VPC CNI, AKS) et NetworkPolicy deny par défaut dans chaque espace de noms.
- **`audit_log`, `secrets_encryption`, `workload_identity`** : réalisés par les entrées des modules EKS et AKS.
- **Exclusion** : `kubernetes_manifest` n'est employé par aucun module, car il exige l'API du cluster au moment du plan.

### D20. Dépendance `github.com/hashicorp/hcl/v2` (option 14a, T6)
- **Usage** : `hcl/v2` (`hclsyntax` pour la garde, `hclwrite` pour le rendu) et `github.com/zclconf/go-cty`.
- **Confinement** : importés par `internal/validate` et `internal/iacgen` seulement, sous la règle archtest `hcl-confined` (`Confine`, écart 7 ; vérification 5).
- **Mesure** : faite le 2026-11-26 (section « Mesure de la dépendance ») : v2.25.0, 10 modules de plus au graphe, 6 liés par binaire, environ 1,3 Mo par binaire, ni `net/http` ni `os/exec` tirés, aucune vulnérabilité ; licence MPL-2.0 de `hcl/v2` signalée à l'humain.
- **Règle de montée** :
  - `go tool govulncheck ./...` rend 0 ; `go mod verify` passe ;
  - l'empreinte du bundle de référence ne change pas, ou son diff est relu (golden de `TestCompileReferenceScenario`) ;
  - notes de version lues ;
  - version publiée depuis au moins 14 jours, sauf correctif de sécurité.

### Interfaces Go (écarts à la section 3.1 du plan)

```go
package domain // internal/validate/domain
const StageComposition Stage = "composition" // en tête, L3 seulement (D6)
type StageResult struct{ Stage Stage; Status StageStatus; Tool, Version, Root string } // Root : plan, policy, equivalence
// Report gagne Excepted []loopsdomain.Finding : findings couverts par une exception (D16), hors OK et hors empreinte

package iacgen
const CodeModuleVersion = "L3-MODULE-VERSION"
const OfflinePlanVariable = "rempart_offline_plan" // défaut false (D8)
func CatalogDigest() string

package validate
type Options struct{ Timeout time.Duration; MaxOutputBytes int64; MaxFindings int; Today time.Time }
type Exception struct{ Tool, Check, Module, Address, Justification, Expires, ApprovedBy, ApprovedOn string }
func LoadExceptions(raw []byte, today time.Time) ([]Exception, error) // mal formée, périmée, au-delà de 180 jours : erreur

package equivalence
const CodeEgress = "EQUIV-EGRESS" // low, non bloquant
```

Le reste de la section 3.1 du plan est inchangé.

## Conséquences

- **Positives** :
  - L3 sans modèle, evals déterministes ;
  - une seule source d'HCL (le rendu), et aucun texte libre n'y entre ;
  - aucun outil ne tourne sur un arbre non gardé ;
  - un seul exécutant de commandes et un seul moteur de politiques ;
  - plan de contrôle sans identifiant cloud ;
  - équivalence à deux niveaux ;
  - bundle reproductible et identifié par son empreinte (preuves de M4) ;
  - T115, T116 et T117 fermées.
- **Négatives** :
  - aucun HCL libre : tout besoin hors catalogue escalade (`module_missing`) jusqu'à l'arrivée d'un module (stockage objet et base managée en M7) ;
  - huit modules, leurs tables de soutien et la table de traduction à entretenir ;
  - chaîne lente (1 à 2 minutes par vérification complète) ;
  - providers de plusieurs centaines de Mo ;
  - listes blanches de la garde à revoir à chaque montée d'OpenTofu ou d'un provider ;
  - une dépendance Go de plus (`hcl/v2`) ;
  - en branche de repli, l'équivalence de plan de certaines racines n'est prouvée qu'au plan réel.
- **Difficile à changer** :
  - forme de la composition et empreinte du bundle ;
  - codes `EQUIV-*`, `L3-*` et d'escalade ;
  - nom et séquence du workflow ;
  - format du verrou ;
  - forme d'`IaCInput` et métadonnées du pack `iac` ;
  - table de traduction.

## Impact sécurité

### Rattachement des décisions aux menaces

| Décision | Menaces |
|---|---|
| D1 | T2, T7, T147, T151 |
| D2 | T146 (réparateur borné au compilé), T10 |
| D3 | T115, T3 ; T12 et T107 en résidu (confirmation déclarée) |
| D4 | T147, T142, T24 |
| D5 | T6, T143, T144 |
| D6 | T8, T145, T24 |
| D7 | T30, T142, T143, T144, T6 |
| D8 | T142, T27, T8, T22 |
| D9 | T109, T119, T2, T6 |
| D10 | T146, T116, T117 |
| D11 | T117 |
| D12 | T116, T150 |
| D13 | T146, T150 |
| D14 | T7 |
| D15 | T6, T143 |
| D16 | T30, T148 |
| D17 | T31, T149, T29 |
| D18 | T16, T10, T3, T17, T151 |
| D19 | T146 (complétude des faits) |
| D20 | T6 |

### Menaces existantes complétées (insertion par les tâches, confirmée par `security-reviewer`)
- **T6** : la vérification « signature dans la chaîne L3 » devient :
  - `MODULE_TAMPERED` (manifeste SHA-256 des modules vendorisés) ;
  - `-lockfile=readonly` ;
  - `TestIaCToolsLockPinned`, `TestChartsPinned` ;
  - règle de montée de D20.
- **T8** : un seul exécutant (`toolexec`, `exec-confined` et son contrôle de sources), sans shell, environnement construit, réseau coupé, sorties bornées. Vérification : `TestToolexecNoShell`, `TestToolexecEnvBuilt`, `TestToolexecChecksum`, `TestToolexecBounds`, `TestExecConfined`.
- **T30** : annotations des scanners IaC refusées partout, fichiers de configuration de scanner refusés, exceptions centralisées et datées. Vérification : `TestStaticGateForbiddenAnnotations`, `TestScannerExceptionsClosed`.
- **T31** :
  - ligne unique chaînée, préfixe `-`, `.IGNORE` et `MAKEFLAGS` refusés ;
  - approbation hors de portée de l'agent : permission « ask » et identifiants sous MFA ;
  - vérification : `TestSandboxRecipesChained`, `TestSandboxIgnoreErrorsNeverCalls`, `TestSandboxScriptPlanOnly`.
- **T115** : garde de L3 par recalcul (D3) ; `TestL3RefusesGraphSubject`.
- **T116** : sources des règles réseau tirées de `MEMBER_OF`, `path` ignoré ; `TestCompileIgnoresEdgePath`, `TestDerivedCIDRsInsideGraph`.
- **T117** : table fermée, sans joker, en échec fermé, rôles Azure personnalisés, IAM du plan incluse dans la traduction ; `TestTranslationTableClosed`, `TestTranslateFailsClosed`, `TestEquivalenceIAMSubset`.
- **Section 4.2, second point** (exécution de code pendant `tofu plan`) : formalisé par T142.
- **Autres menaces touchées** :
  - T2 et T7 : aucun modèle, aucun texte libre rendu ;
  - T3 : tenant du worker, refus avant la boucle ;
  - T10 : budget, aucun jeton ;
  - T16 : `GetVersion` ;
  - T24 : bornes de la composition et des sorties d'outil ;
  - T27 : aucune identité cloud dans le plan de contrôle.

### Menaces nouvelles proposées (numéros provisoires, à confirmer par `security-reviewer`)

| # | Menace | Cat. | Décisions | Vérification |
|---|---|---|---|---|
| T142 | Code exécuté à l'`init` ou au `plan` d'une IaC générée, réparée ou locale : sources de données `external` et `http`, provisioners, fonctions de fichier, `ephemeral`, fonctions de provider, `endpoints` de provider, surcharges et `.tofu` qui masquent le code relu. Conséquences : secrets du worker lus, SSRF, exfiltration par la sortie du plan | E, I | D4, D6, D7, D8, D18 | `TestStaticGateRefusesCodeExecution`, `TestToolexecEnvBuilt`, critère 4 de M3-T03 |
| T143 | Outil, provider, module ou chart substitué ou compromis : version flottante, registre, miroir contourné par une configuration CLI héritée ou un `.terraformrc`, publication piégée récente, binaire modifié entre vérification et exécution | T, E | D5, D7, D15 | `TestIaCToolsLockPinned`, `TestTofuCLIConfigMirrorOnly`, `TestToolexecChecksum`, `TestChartsPinned` |
| T144 | Backend, état ou chiffrement de l'état dans le code généré : état envoyé à un tiers, état d'un autre tenant lu | I, T | D5, D7, D17 | `TestStaticGateRefusesCodeExecution` (cas `backend`, `cloud`, `encryption`, `terraform_remote_state`), vérification 13 |
| T145 | Sortie d'outil non fiable : JSON géant lu comme « aucun finding », sévérité inconnue rabaissée, séquences de contrôle affichées à un humain | T, D | D6 | `TestNormalizeFailsClosed`, `TestChainUntrustedMessage`, `TestNormalizeParityWithScript` |
| T146 | Équivalence contournée : adresse, nom ou étiquette trompeurs, `count` ou `for_each` qui multiplie, ressource de soutien trop large, plan tronqué ou forgé, garantie du graphe non réalisée | E, T | D2, D10, D13, D19 | C3 ; `TestEquivalenceRefusesMisleadingAddress`, `TestEquivalenceReachSubset`, `TestEquivalenceCompleteness`, `TestEquivalenceSupportTableClosed` |
| T147 | Texte non fiable du graphe ou de l'IR rendu dans l'HCL (`${`, `%{`, heredoc, guillemet) | T, E | D1, D4 | `TestCompileIgnoresFreeText`, `TestRenderEscapesTemplates`, cas d'injection de `evals/iac` |
| T148 | Exception de scanner élargie : globale par `check`, sans expiration, écrite par l'agent sans revue, périmée, ou étendue à la garde ou à l'équivalence | T | D16 | `TestScannerExceptionsClosed` |
| T149 | Bac à sable détourné : plan réel lancé par l'agent avec les identifiants de l'humain, données de compte lues ou commitées, apply d'un plan autre que celui affiché | E, I | D17 | `TestSandboxScriptPlanOnly`, `TestSandboxRefusesWithoutCredentials`, `TestSandboxOutputHasNoAccountData` |
| T150 | Allocations et soutien hors graphe qui chevauchent ou ouvrent un egress non modélisé | I, E | D12, D13 | `TestDerivedCIDRsInsideGraph` ; `EQUIV-EGRESS` ; résidu jusqu'en M6 |
| T151 | Evals de L3 rendues triviales : chaîne simulée dans la cible, trappes qui ne déclenchent rien | T, R | D18 | `TestIaCSuiteComposition`, `TestIaCTargetRunsCase` |

## Risques résiduels
1. **Coupure réseau déclarative** dans la session, en CI et sur le poste : un provider ou un outil peut ignorer le mandataire.
   - Parade : environnement construit, aucun identifiant à exfiltrer, garde statique.
   - En production : espace de noms réseau ou politique de sortie (M4).
2. **Code des providers et des outils exécuté sur l'hôte du worker** : un artefact compromis malgré les sommes et l'âge minimal exécute du code avec les droits du processus outil.
   - Parade : `PR_SET_DUMPABLE`, environnement sans secret, `HOME` éphémère.
   - Obligation pour M4 : utilisateur distinct ou bac à sable en production.
3. **Plan hors ligne différent du plan réel** (valeurs calculées inconnues, aucune source de données) : l'équivalence hors ligne est nécessaire, pas suffisante.
   - Parade : rejeu sur le plan réel (humain en M3 ; runner et L4 en M4).
4. **Branche de repli** : pour les racines concernées, aucune équivalence de plan dans la boucle avant le plan réel.
5. **Listes blanches et table de soutien à entretenir** : une omission refuse plutôt qu'elle n'admet (échec fermé), au prix d'escalades.
6. **Règles des scanners figées** par la version de l'outil : un nouveau contrôle n'arrive qu'à la montée du verrou.
7. **Lignes Azure de la table de traduction** invérifiables depuis la session : tant qu'elles sont en attente, elles ne servent pas (`L3-NO-TRANSLATION`).
8. **Empreinte du bundle liée à `hclwrite`** : une montée peut changer l'empreinte (golden et règle de montée de D20).
9. **Confirmation déclarée**, non signée jusqu'en M4 (T12, T107) : le recalcul prouve la cohérence entre IR, confirmation et graphe, pas l'identité du confirmateur.

## Amendements (appliqués par l'agent après l'acceptation de cet ADR par l'humain)

Les amendements 4 et 5 modifient des skills : ils seront signalés dans `docs/STATUS.md` et relus par l'humain à l'étape H-skills.

### Amendement 1 : `docs/01-LOOPS.md` (M3-T08, avec `docs/loops/L3.md`)

Ligne L3 du tableau, texte cible :

`| L3 | Génération IaC | graphe convergé de L2 sur une IR confirmée (provenance recalculée) | chaîne de validation verte + équivalence graphe/plan ; coût évalué en L4 sur le plan réel | 8 itérations, stagnation à 2 | secure-iac-generation |`

Section « L3. Génération IaC », texte cible :

```
### L3. Génération IaC
- Entrée : IR confirmée, sa confirmation et le graphe convergé de L2 sur cette IR ; L3 recalcule la provenance (`Build`, `Derives`, vérificateur de L2) et refuse un sujet `graph` tant qu'un ADR ne lève pas T115 (ADR 0014 D3).
- Proposeur déterministe : compilation du graphe en composition typée de modules internes épinglés, HCL rendu par Go ; aucun appel de modèle (ADR 0014 D1, D4).
- Stratégies successives : `repair` (catalogue fermé de corrections de la composition courante), puis `recompile` (retour à la composition compilée). `modules_plus_freeform` (HCL libre proposé par un LLM derrière le même vérificateur) et `decompose_by_cloud` (un état par cloud, VPN en deux temps) sont reportées, chacune à un ADR.
- Étapes : équivalence de composition ; rendu ; garde statique ; fmt, init, validate ; tflint, Checkov, Trivy ; plan hors ligne sans identifiant ; pack `policies/iac` du moteur OPA embarqué ; équivalence graphe/plan ; coût (`not_evaluated` en L3). Findings normalisés renvoyés au proposeur ; arrêt au premier étage bloquant.
- Vérificateur : aucun finding `medium` ou plus ; aucune exception de politique dans le code généré (annotations et fichiers de configuration de scanner refusés ; exceptions humaines centralisées, datées, hors du code) ; **équivalence graphe/plan** (rien dans le plan qui ne soit dans le graphe, tout le graphe dans le plan) ; coût : `not_evaluated` en L3, bloquant en L4 sur le plan réel.
- Budget : 8 itérations, 30 minutes, aucun jeton de modèle ; même empreinte d'erreur deux fois, stratégie suivante ; trois fois, escalade.
```

Si la sonde retient la branche de repli, ajouter à la ligne « Étapes » : « une racine dont un provider ne se planifie pas hors ligne a plan, pack et équivalence de plan à `not_evaluated` ; l'équivalence de plan est alors prouvée sur le plan réel avant tout déploiement ».

Section « L4 », ligne « Étapes », texte cible :

« `tofu plan` ; **coût du plan réel comparé au budget de l'IR, bloquant au-delà** (repris de L3, ADR 0014 D14) ; rayon d'impact ; classification déterministe du risque ; plan de retour arrière vérifié ; dossier de preuves signé ; PR ; attente d'approbation selon le niveau d'autonomie. »

### Amendement 2 : `docs/00-VISION.md`, section 4, ligne « Stack » (M3-T03)

Remplacer « OPA/Rego et Conftest ; tflint, Checkov, Trivy, Infracost » par :

« OPA/Rego, moteur embarqué dans les binaires (packs `design` et `iac`, ADR 0011 et 0014) ; tflint, Checkov, Trivy, exécutés sans shell, sans réseau ni identifiant (ADR 0014) ; Infracost hors du plan de contrôle (poste de l'humain en M3 ; lieu en L4 fixé par l'ADR de L4) »

Le reste de la ligne est inchangé.

### Amendement 3 : ADR 0011 (M3-T03, avec `NewIaC`)

À la ligne « Statut », ajouter : « amendé par l'ADR 0014 (D9) : second pack `iac` ».

| Endroit | Texte cible |
|---|---|
| D1, deuxième point | « `NewDesign` et `NewIaC` compilent chacun leur pack une fois, par le même chemin de code paramétré par pack (système de fichiers embarqué, préfixe de paquet, requête, schéma) [...] ». La suite est inchangée. |
| D4, premier point | « `policies/embed.go` : `package policies`, `//go:embed design/*.rego` pour `var Design embed.FS` et `//go:embed iac/*.rego` pour `var IaC embed.FS` ; un pack par répertoire de premier niveau, aucun sous-répertoire de second niveau. » La suite est inchangée. |
| D4, « Paquets » | « Chaque module non test d'un pack `<p>` (`design`, `iac`) déclare `package rempart.<p>.<nom>` ; prédicats partagés dans `rempart.<p>.lib` ; requête fixe par pack : `data.rempart.<p>[_].deny[_]` ; toute référence `data` hors `data.rempart.<p>` est refusée par la barrière AST. » |
| D4, « Métadonnées » | ajouter : « `control_id` unique dans son pack ; un `control_id` repris d'un autre pack désigne la même intention et porte la même sévérité. » |
| D4, « Sortie d'une règle » | « `resource` : identifiant d'un nœud ou d'une arête de l'entrée (pack `design`), adresse d'une ressource de l'entrée (pack `iac`) ». |
| D4, « Traduction » | « `Source` = `policy:<p>` ». |
| D5 | ajouter : « Pack `iac` : `policy.IaCInput` (ADR 0014 D9), schéma `schemas/policy/iac-input-v1.json`. » |
| D6 | règle `opa-confined` inchangée. `Makefile` : « `opa-test` exécute, pour chaque pack, `go tool opa check --strict --capabilities internal/policy/adapters/opa/capabilities.json --schema schemas/policy/<p>-input-v1.json policies/<p>`, puis `go tool opa test policies/` ». |
| D8 | ajouter `func NewIaC() (*IaCEngine, error) // policies.IaC, DefaultOptions ; implémente validate.PolicyEvaluator`. |
| Vérification 2 | une commande par pack, chacune avec son schéma. |
| Vérification 12 | « `grep -c 'go tool opa check --strict --capabilities' Makefile` : `2` ». |
| Vérification 13 | ajouter : « `go test ./internal/archtest/ -run TestPoliciesTreeClosed -v 2>&1 \| grep -c '^--- PASS: TestPoliciesTreeClosed '` : `1` (chaque répertoire qui contient un `.rego`, `design` et `iac`, est embarqué par un constructeur de l'adaptateur) ». |

### Amendement 4 : skill `secure-iac-generation` (M3-T03)

**Description**, texte cible : « Génération et validation d'IaC OpenTofu sécurisée pour Rempart (modules internes, composition typée, garde statique, chaîne fmt/init/validate/tflint/checkov/trivy, plan hors ligne, pack policies/iac du moteur OPA embarqué, findings normalisés, équivalence graphe/plan, état chiffré, FinOps). » La suite (« À utiliser ... ») est inchangée.

**Références**, texte cible :
- `scripts/validate.sh` : même sortie que `internal/validate` sur les mêmes sorties brutes ; un outil absent ou en échec donne un finding critique ; garde statique par `rempart check --static`.
- `normalize_findings.py` : tofu validate, tflint, Checkov, Trivy ; sévérité inconnue critique ; empreinte en netstrings de `loopsdomain` ; exceptions centrales appliquées.

**Principe**, texte cible : « Le proposeur de L3 est déterministe : `iacgen.Compile` traduit le graphe en composition typée de modules internes épinglés, rendue en HCL par Go, sans aucun texte libre. Le HCL libre (`modules_plus_freeform`) exige un ADR. Un bloc `extra` qui revient dans trois compositions devient un candidat module (ADR). »

**Ordre de la chaîne**, texte cible :
1. Équivalence de composition (Go, avant le rendu).
2. Garde statique sur l'arbre analysé (`hclsyntax`), en liste blanche : fichiers, blocs, attributs de provider, sources de données, fonctions. Annotations de scanner et fichiers de configuration refusés. Aucun outil sur un arbre refusé.
3. `tofu fmt -check -recursive`.
4. `tofu init -backend=false -input=false -lockfile=readonly` sur le miroir de providers seul, puis `tofu validate -json`.
5. En parallèle : `tflint --format json` (rulesets du verrou, jamais `--init`), `checkov -d . -o json --skip-download`, `trivy config --format json` (règles embarquées).
6. Plan hors ligne : `tofu plan -refresh=false -lock=false -input=false -out` sur un état vide éphémère, sans identifiant, réseau coupé (`rempart_offline_plan`), puis `tofu show -json`.
7. Pack `policies/iac` du moteur OPA embarqué, sur `IaCInput` (faits extraits du plan en Go).
8. **Équivalence graphe/plan** (`internal/plan/equivalence`). Le texte actuel est conservé, complété de : « rattachement par adresse de module, jamais par nom ni étiquette ; tout le graphe réalisé ».
9. Coût : `not_evaluated` en L3 ; bloquant en L4 sur le plan réel ; Infracost seulement dans `scripts/sandbox.sh`, avec la clé de l'humain.

Arrêt au premier étage bloquant. Échec fermé : outil absent, somme fausse ou sortie illisible donnent un finding critique.

**Interdits**, texte cible : « Pour tout candidat (composition compilée, réparée ou initiale) :
- aucune annotation d'exception (`checkov:skip`, `trivy:ignore`, `tflint-ignore`, `tfsec:ignore`, `#nosec`, dans tout commentaire et toute casse) ;
- aucun fichier de configuration de scanner.
Une exception exige une entrée de `modules/scanner-exceptions.json` (outil, check, module, adresse, justification, expiration de 180 jours au plus, approbateur humain). Elle ne couvre que les findings de scanners sur le code des modules et figure dans le rapport. » Les points « secret » et « désépingler » sont inchangés.

**État**, texte cible : « Le bundle ne contient ni `backend`, ni `cloud`, ni `encryption`, ni `terraform_remote_state`. L'exécutant fournit backend et chiffrement (`TF_ENCRYPTION`) : l'humain en M3, le runner en M4. L3 planifie sur un état vide éphémère. En mode runner, l'état vit côté client : distant par tenant et environnement, chiffré, verrouillé, versionné. »

**FinOps**, texte cible : « Chaque changement porte son delta de coût, calculé hors du plan de contrôle et bloquant en L4 sur le plan réel. » La suite est inchangée.

**`references/module-contract.md`**, textes cibles :

| Rubrique | Texte cible |
|---|---|
| IAM | « aucune action `*` ni ressource `*` écrite dans le module ; politiques gérées seulement par ARN listé dans la table de soutien (ADR 0014 D13) » |
| Versions | « module versionné dans le catalogue embarqué (`modules/embed.go`, manifeste SHA-256) ; la composition référence une version exacte ; source `./modules/<nom>` seulement ; aucun bloc `provider` dans un module » |
| Tests | « `tofu test` avec `mock_provider` (aucun compte réel) ; `rempart check --module` sans finding `medium` ou plus hors exception centrale » |
| Exceptions | « jamais d'annotation ; `SECURITY.md` cite les entrées de `modules/scanner-exceptions.json` qui visent le module » |

### Amendement 5 : skill `policy-as-code` (M3-T03)

| Endroit | Texte cible |
|---|---|
| Description | « (conception sur le graphe, IaC sur les faits du plan, runtime sur le graphe réel, Kubernetes) ». La suite est inchangée. |
| Références | ajouter `policies/iac/`, `schemas/policy/iac-input-v1.json`, ADR 0014 D9 ; « Vérifier » : une commande `opa check` par pack, chacune avec son schéma. |
| Ligne `policies/iac/` du tableau | « faits extraits en Go du plan OpenTofu (`IaCInput`), moteur embarqué, pack `rempart.iac` \| L3 ». |
| Ligne `policies/k8s/` du tableau | « manifestes et état Kubernetes (à partir de M5, moteur d'admission choisi par ADR) ». |
| Règle 4 | `resource` est l'identifiant d'un nœud ou d'une arête (pack `design`), ou l'adresse d'une ressource de l'entrée (pack `iac`). |
| Règle 6 | « Paquet `rempart.<pack>.<nom>` (`design` ou `iac`), prédicats partagés dans `rempart.<pack>.lib` ». |
| Règles | ajouter : « un `control_id` repris d'un autre pack garde la même sévérité ». |
| Tests | paquets de test `rempart.<pack>_test.<nom>` ; `TestIaCEveryControlHasOkAndKo` pour le pack `iac`. |

### Amendement 6 : `docs/04-INTERFACE.md`, section 8 (M3-T03)

Ligne `rempart check`, texte cible :

« `rempart check [--module] [--static] [--json] [--graph-input <entrée L3>] [--plan <plan.json>] <dossier>` | Valide un bundle Rempart ou un module interne avec la chaîne Rempart, sans réseau ni identifiant (usage en CI) ; codes 0, 1, 2 »

### Amendement 7 : `docs/02-THREAT-MODEL.md` (par tâche, après `security-reviewer`)

- Colonnes de vérification complétées pour T6, T8, T30, T31, T115, T116 et T117, selon la section « Impact sécurité ».
- Section 4.2, second point : renvoi à T142.
- Insertion de T142 à T151, une fois leurs numéros confirmés.

### Skill `loop-engineering` et ADR 0005

- **`loop-engineering`** : aucun amendement. L'exemple de `references/loop-spec-template.md` reste illustratif ; la fiche normative est `docs/loops/L3.md`.
- **ADR 0005** : amendé en M3-T09 seulement si la cible `iac` l'exige (`runs: 1`, baseline hors registre des routes, comme pour `design`).

## Résultat de la sonde (mesuré les 2026-11-25 et 2026-11-26, avant la phase tests de M3-T02)

**Protocole** (étape 0 de M3-T02 ; rien n'entre dans le dépôt) :
1. Outils et providers du verrou dans un cache hors dépôt, sommes et signatures vérifiées.
2. Racines jetables hors dépôt, une par provider (tableau ci-dessous).
3. `tofu init` sur le miroir fichier seul.
4. `tofu plan -refresh=false -lock=false -input=false -out`, avec l'environnement construit de D6 et D8, sans identifiant.
5. Réseau coupé par un espace de noms sans interface si la session le permet (`unshare -rn`), sinon par un mandataire injoignable. La méthode employée est consignée.

**Classement** :
- **faisable** : code 0 sans autre réglage que ceux de D8 ;
- **faisable avec réglage** : code 0 avec un réglage de provider consigné, sans identifiant réel ni faux point d'authentification ;
- **impossible** : tout autre cas ; l'erreur est résumée sans donnée sensible.

Une racine est planifiable hors ligne si tous ses providers sont faisables, avec ou sans réglage.

| Champ | Valeur |
|---|---|
| Date de la sonde | 2026-11-25 et 2026-11-26 |
| Version d'OpenTofu | 1.13.2 (actifs de release GitHub, publiés le 2026-10-21 ; somme SHA256SUMS vérifiée, signature non vérifiée dans la sonde) |
| Méthode de coupure réseau | environnement construit (`env -i`) et mandataire injoignable (`HTTPS_PROXY=http://127.0.0.1:9`), puis `unshare -rn` (espace de noms sans interface, disponible dans la session) : résultats identiques |

| Provider | Version | Racine de sonde | Résultat (faisable, faisable avec réglage, impossible) | Réglage retenu | Preuve (commande, code) |
|---|---|---|---|---|---|
| `hashicorp/aws` | 6.72.0 (2026-11-04) | VPC, deux sous-réseaux, groupe de sécurité, clé KMS, rôle IAM, EKS chiffré, `aws_iam_user` injecté | faisable avec réglage | `skip_credentials_validation`, `skip_requesting_account_id`, `skip_metadata_api_check`, `skip_region_validation`, clés factices marquées FAKE (jamais de la forme d'un vrai identifiant : la garde de secrets refuse `AKIA...`) | `tofu plan -refresh=false -lock=false -out` code 0, 8 ressources dont `aws_iam_user.injected` |
| `hashicorp/azurerm` | 5.13.0 (2026-11-05) | groupe de ressources, VNet, sous-réseau, interface, VM Linux | **impossible** (plan) ; `validate` faisable ; `tofu test` avec `mock_provider` faisable avec réglage | aucun pour le plan : le provider demande un jeton à `login.microsoftonline.com` dès sa configuration (`building account: could not acquire access token`) ; seul un faux point d'authentification le contournerait (exclu par D8). Pour `tofu test` : `mock_resource` avec des `defaults` d'identifiants Azure bien formés (l'azurerm valide la forme des identifiants et de la clé publique SSH) | plan code 1 ; `tofu validate -json` valid ; `tofu test` 1 passé |
| `hashicorp/helm` | 3.3.0 (2026-09-16) | release d'un chart local, cluster injoignable | faisable | aucun | plan code 0, 1 ressource |
| `hashicorp/kubernetes` (si un module l'emploie) | non mesuré | espace de noms étiqueté, NetworkPolicy | à mesurer si un module l'emploie (T05) | | |

**Branche retenue** : nominale pour une racine AWS seule ou Helm seule ; **repli** pour toute racine qui contient azurerm, donc pour la racine `infra` du scénario de référence (AWS et Azure) : équivalence de composition et manifestes de modules dans la boucle, plan réel par l'humain (`sandbox.sh`) puis par le runner (M4). L'écart 6 (C3 démontré sur un scénario AWS seul) s'applique. Les modules Azure sont testés par `tofu test` avec `mock_provider` (C1). Miroir fichier : `init` code 0 pour les trois providers, sans registre ; versions choisies par la règle des 14 jours ; `api.releases.hashicorp.com` est bloqué, les dates viennent de l'en-tête `Last-Modified` du fichier SHA256SUMS de chaque version.

**Reports qui en découlent** :
- réglages exacts dans D8 ;
- texte de repli de l'amendement 1, si besoin ;
- écart 6, si repli ;
- valeurs figées par `TestOfflinePlanProbe` ;
- entrée dans `docs/STATUS.md`.

## Mesure de la dépendance (D20, mesurée le 2026-11-26)

Comme l'ADR 0011 pour OPA, la mesure se fait sur une copie jetable du module, dépôt intact. Elle est consignée ici et dans `docs/STATUS.md`.

| Mesure | Valeur |
|---|---|
| Version de `github.com/hashicorp/hcl/v2` et date de publication | v2.25.0, 2026-09-15 (proxy de modules Go) ; licence MPL-2.0 (copyleft au niveau du fichier : usage sans modification des fichiers de hcl sans obligation pour Rempart ; toute modification de ces fichiers serait à publier) |
| Version de `github.com/zclconf/go-cty` | v1.19.0 (2026-07-06), choisie par la sélection de version minimale, licence MIT ; v1.20.0 non requise |
| Nombre de modules au graphe, avant et après | 252, puis 262 |
| Modules ajoutés (diff de `go list -m all`) et leurs licences | `hcl/v2` v2.25.0 (MPL-2.0), `go-cty` v1.19.0 (MIT), `go-textseg/v15` v15.0.0 et `/v17` v17.0.1 (MIT), `agext/levenshtein` v1.2.1 (Apache-2.0), `mitchellh/go-wordwrap` v1.0.1 (MIT), et, pour les tests de ces modules seulement, `go-test/deep`, `vmihailenco/msgpack/v5`, `vmihailenco/tagparser/v2`, `zclconf/go-cty-debug` |
| Modules liés dans `rempart` et `rempart-worker`, avant et après | `rempart` 23 puis 29, `rempart-worker` 40 puis 46 (ajoutés : `hcl/v2`, `go-cty`, `go-textseg/v17`, `agext/levenshtein`, `go-wordwrap`, `google/go-cmp`) |
| Taille des deux binaires, avant et après | `rempart` 33,9 puis 35,2 Mo ; `rempart-worker` 55,3 puis 56,8 Mo |
| Paquets `net/http` ou `os/exec` tirés par `hclsyntax` et `hclwrite` | 0 |
| `go tool govulncheck ./...` | aucune vulnérabilité (code 0) |
| `go mod verify` | « all modules verified » |

Commandes :
1. `go list -m github.com/hashicorp/hcl/v2 github.com/zclconf/go-cty`
2. `go list -m all | wc -l`, avant et après
3. `go version -m <binaire> | grep -c 'dep'`, pour `rempart` et `rempart-worker`
4. `go list -deps github.com/hashicorp/hcl/v2/hclsyntax github.com/hashicorp/hcl/v2/hclwrite | grep -cE '^(net/http|os/exec)$'`
5. `go tool govulncheck ./...; echo rc=$?`
6. `go mod verify`

## Écarts au plan M3, à reporter dans `docs/plans/M3-overview.md` au début de M3-T02

Sauf mention contraire, les comptes des critères d'acceptation ne changent pas.

1. **D6, étage `composition`** : en tête de la chaîne de L3, en Go, avant le rendu. `Stage` gagne `composition`, et `StageResult` gagne `Root`.
2. **D7, liste blanche** : la garde porte sur les fichiers, les blocs, les attributs de provider, les sources de données et les fonctions. Refus ajoutés :
   - blocs `ephemeral`, `import`, `removed`, `check` ;
   - fonction `templatestring`, fonctions non déterministes, fonctions de provider ;
   - attributs `endpoints` et d'identité des providers.
3. **D8, réglages hors ligne** : portés par la variable `rempart_offline_plan` du bundle.
4. **D2, catalogue de réparation** : codes fixés, `L3-MODULE-VERSION` ajouté.
5. **D3 et fiche L3** : `Prepare` n'escalade sans boucle que pour `payload_too_large` ; `module_missing` et `no_translation` passent par la stagnation.
6. **Branche de repli seulement** : les critères 2 et 3 de M3-T07 portent sur `internal/iacgen/testdata/aws-only-input.json` (racine `infra` sans azurerm). La référence, qui mêle AWS et azurerm dans `infra`, n'a pas de plan hors ligne.
7. **D20, règle `hcl-confined`** : ajoutée à `DefaultRules`, vérifiée par `TestRepositoryConforms`.
8. **D6, `exec-confined`** : complétée d'un contrôle de sources (`os.StartProcess`, `syscall.*`, `unix.Exec`), sous-cas de `TestExecConfined`.
9. **D16** : périmètre des exceptions précisé ; `Report.Excepted`, `Options.Today`, `LoadExceptions` ajoutés ; parité avec le script étendue aux exceptions.
10. **D10** : `EQUIV-EGRESS` (`low`).
11. **D9** : un `control_id` partagé garde la même sévérité ; un type sans extracteur échoue fermé ; sous-cas des tests existants.
12. **D4** : le compilateur de M3 ne produit aucun `extra`.

## Vérifications

1. **Aucun LLM** : `go list -deps ./internal/iacgen/... ./internal/validate/... ./internal/plan/... ./internal/loops/l3/... | grep -c '/internal/llm'` : `0`.
2. **`exec-confined`** :
   - `go test ./internal/archtest/ -run TestExecConfined -v 2>&1 | grep -c '^--- PASS: TestExecConfined '` : `1` ;
   - critère 4 de M3-T02 : `0`.
3. **`modules-confined`** :
   - `go test ./internal/archtest/ -run TestModulesConfined -v 2>&1 | grep -c '^--- PASS: TestModulesConfined '` : `1` ;
   - `go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./... | grep -E ' github.com/amezianechayer/rempart/modules( |$)' | cut -d: -f1 | sort -u` : exactement `github.com/amezianechayer/rempart/internal/iacgen`.
4. **`opa-confined` inchangé** :
   - `go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./... | grep -E 'github.com/open-policy-agent/| github.com/amezianechayer/rempart/policies( |$)' | cut -d: -f1 | sort -u` : exactement `github.com/amezianechayer/rempart/internal/policy/adapters/opa` ;
   - `go test ./internal/archtest/ -run TestOPAConfined -v 2>&1 | grep -c '^--- PASS: TestOPAConfined '` : `1`.
5. **`hcl-confined`** : `go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./... | grep -E ' github.com/hashicorp/hcl/v2' | cut -d: -f1 | grep -vE '/internal/(validate|iacgen)(/|$)' | wc -l` : `0`.
6. **Provenance (T115)** : `go test -race ./internal/loops/l3/... -run 'Test(L3RefusesGraphSubject|L3TenantMismatchRefused)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(L3RefusesGraphSubject|L3TenantMismatchRefused) '` : `2`.
7. **Garde statique (T30, T142, T144)** :
   - `go test ./internal/validate/... -run 'Test(StaticGateForbiddenAnnotations|StaticGateRefusesCodeExecution|StaticGateModuleSources)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(StaticGateForbiddenAnnotations|StaticGateRefusesCodeExecution|StaticGateModuleSources) '` : `3` ;
   - critères 3 et 4 de M3-T03 : `true`.
8. **Exécution confinée (T8)** : `go test ./internal/validate/... -run 'Test(ToolexecNoShell|ToolexecEnvBuilt|ToolexecChecksum|ToolexecBounds)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(ToolexecNoShell|ToolexecEnvBuilt|ToolexecChecksum|ToolexecBounds) '` : `4`.
9. **Chaîne d'approvisionnement (T6, T143)** :
   - `go test ./internal/validate/... ./internal/archtest/ -run 'Test(IaCToolsLockPinned|TofuCLIConfigMirrorOnly|ChartsPinned)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(IaCToolsLockPinned|TofuCLIConfigMirrorOnly|ChartsPinned) '` : `3` ;
   - critère 5 de M3-T02 : `true` ;
   - `bash scripts/iac-tools.sh verify; echo rc=$?` : `rc=0`.
10. **Conftest absent (D9)** :
    - `grep -rIil conftest internal cmd scripts policies Makefile | wc -l` : `0` ;
    - après les amendements 2, 4 et 5 : `grep -rIil conftest docs/00-VISION.md docs/01-LOOPS.md .claude/skills/secure-iac-generation .claude/skills/policy-as-code | wc -l` : `0`.
11. **Pack `iac` (D9)** :
    - `make -f Makefile opa-test; echo rc=$?` : `rc=0` ;
    - critère 5 de M3-T03 : au moins `10` ;
    - `grep -c 'go tool opa check --strict --capabilities' Makefile` : `2` ;
    - `go test ./internal/policy/... -run 'Test(IaCInputHasNoFreeText|IaCPackMetadataComplete|IaCEveryControlHasOkAndKo)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(IaCInputHasNoFreeText|IaCPackMetadataComplete|IaCEveryControlHasOkAndKo) '` : `3`.
12. **Composition et rendu (T147, T116)** :
    - `go test ./internal/iacgen/... -run 'Test(CompileIgnoresFreeText|RenderEscapesTemplates|CompileDeterministic|CompileIgnoresEdgePath)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(CompileIgnoresFreeText|RenderEscapesTemplates|CompileDeterministic|CompileIgnoresEdgePath) '` : `4` ;
    - critère 3 de M3-T06 : `1`.
13. **Bundle sans état ni backend (D5, T144)** : `d=$(mktemp -d) && go run ./cmd/rempart iac compile --out "$d" internal/iacgen/testdata/reference-input.json >/dev/null && grep -rIlE '^[[:space:]]*(backend|cloud|encryption)[[:space:]]*("[^"]*"[[:space:]]*)?\{' "$d" | wc -l` : `0`.
14. **Traduction (T117)** : `go test ./internal/iacgen/... ./internal/plan/... -run 'Test(TranslationTableClosed|TranslateFailsClosed|EquivalenceIAMSubset)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(TranslationTableClosed|TranslateFailsClosed|EquivalenceIAMSubset) '` : `3`.
15. **Équivalence (T146, C3)** :
    - critère 2 de M3-T07 : `true`, et son témoin, le critère 3 : `true` (scénario de l'écart 6 en branche de repli) ;
    - `go test ./internal/plan/... -run 'Test(EquivalenceRefusesMisleadingAddress|EquivalenceReachSubset|EquivalenceCompleteness|EquivalenceSupportTableClosed)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(EquivalenceRefusesMisleadingAddress|EquivalenceReachSubset|EquivalenceCompleteness|EquivalenceSupportTableClosed) '` : `4`.
16. **Réparateur et stagnation (D2)** :
    - `go test ./internal/iacgen/repair/ -run TestRepairNeverAddsOutsideCompiler -rapid.checks=1000 -v 2>&1 | grep -c '^--- PASS: TestRepairNeverAddsOutsideCompiler '` : `1` ;
    - `go test -race ./internal/loops/l3/... -run 'Test(L3StallSwitchesToRecompile|L3StallEscalates|L3EscalationHasNoComposition)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(L3StallSwitchesToRecompile|L3StallEscalates|L3EscalationHasNoComposition) '` : `3`.
17. **Fiche (D2, D18)** :
    - `grep -c '^strategies: \[repair, recompile\]$' docs/loops/L3.md` : `1` ;
    - `grep -c '^budget: {max_iterations: 8, max_tokens: 1, max_wall_time: 30m' docs/loops/L3.md` : `1`.
18. **Bac à sable (T31, T149)** :
    - critère 3 de M3-T01 : `3` ;
    - critère 4 de M3-T07 : `rc=2` ;
    - `go test ./internal/plan/... ./internal/archtest/ -run 'Test(SandboxScriptPlanOnly|SandboxRefusesWithoutCredentials|SandboxOutputHasNoAccountData)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(SandboxScriptPlanOnly|SandboxRefusesWithoutCredentials|SandboxOutputHasNoAccountData) '` : `3` ;
    - `git check-ignore -q .sandbox/x; echo rc=$?` : `rc=0`.
19. **Exceptions (T30, T148)** :
    - `go test ./internal/archtest/ -run TestScannerExceptionsClosed -v 2>&1 | grep -c '^--- PASS: TestScannerExceptionsClosed '` : `1` ;
    - critère 4 de M3-T04 : `true` ;
    - `grep -rIiE 'checkov:skip|trivy:ignore|tflint-ignore|tfsec:ignore|#nosec' modules | wc -l` : `0`.
20. **Sonde (D8)**, avec les outils : `go test -tags=integration ./internal/validate/... -run 'Test(OfflineInitFromMirror|OfflinePlanProbe)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(OfflineInitFromMirror|OfflinePlanProbe) '` : `2`.
21. **Dépendance (D20)** :
    - `go list -m github.com/hashicorp/hcl/v2` : la version consignée dans « Mesure de la dépendance » ;
    - `go tool govulncheck ./...; echo rc=$?` : `rc=0` ;
    - `go mod verify` : `all modules verified`.
22. **Amendement 1** :
    - `grep -c 'modules + HCL libre' docs/01-LOOPS.md` : `0` ;
    - `grep -c 'not_evaluated' docs/01-LOOPS.md` : au moins `1`.
23. **Arbre `policies/` fermé** : `find policies -type f ! -name '*.rego' ! -name embed.go ! -name .gitkeep | wc -l` : `0`. C'est la vérification 13 de l'ADR 0011, amendée.
24. **Verts finaux** :
    - `make -f Makefile verify-quick; echo rc=$?` : `rc=0`, sans outil IaC installé ;
    - avec les outils : `make -f Makefile verify; echo rc=$?` : `rc=0`.

## Ordre de mise en oeuvre
1. **M3-T02, étape 0** : sonde ; sections « Résultat de la sonde » et « Mesure de la dépendance » complétées ; acceptation par l'humain (H0-M3.2).
2. **M3-T02** :
   - D15 (verrou, miroir, `make iac-tools`) ;
   - `toolexec` et `exec-confined` avec son contrôle de sources ;
   - `LoadToolchain` ;
   - proposition harnais 0013.
3. **M3-T03** :
   - `hcl-confined` et D20 ;
   - D7, D6, D16 (chargement), D14 (port) ;
   - `plan.Decode`, D9 ;
   - `rempart check` ;
   - parité avec le script ;
   - amendements 2 à 6.
4. **M3-T04 et M3-T05** : modules, `modules/scanner-exceptions.json`, tables de soutien de chaque module (D13), D19.
5. **M3-T06** : D4, D5, D11, D12, `rempart iac compile`, `modules-confined`.
6. **M3-T07** : `Planner` (D8), D10, D17 ; puis l'humain lance H-sandbox-plan.
7. **M3-T08** : D1 à D3, D18, fiche `docs/loops/L3.md`, amendement 1 ; T142 à T151 soumises à `security-reviewer`.
8. **M3-T09** : evals `iac` (D18), puis H3-iac.

## Questions à l'humain
1. **Branche de repli** : C3 serait démontré sur un scénario AWS seul (écart 6), et la référence n'aurait d'équivalence de plan qu'au plan réel lancé par l'humain. Recommandation : oui.
2. **Réglages hors ligne dans le bundle** (`rempart_offline_plan`, défaut `false`) plutôt qu'un fichier de surcharge écrit par l'exécutant. Conséquence : le code livré au runner porte ce commutateur, inerte par défaut. Recommandation : oui.
3. **Garde statique en liste blanche**, fonctions et sources de données comprises. Un module légitime peut buter sur une fonction non listée ; on l'ajoute alors par revue sous CODEOWNERS. Recommandation : oui.
4. **Périmètre des exceptions centrales** : seulement les findings des scanners sur le code des modules ; jamais la garde, le pack `iac`, l'équivalence ni un échec d'outil. Recommandation : oui.
