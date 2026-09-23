# Boucles du produit

Chaque boucle suit le gabarit du skill `loop-engineering` et a sa fiche détaillée dans `docs/loops/<id>.md`, rédigée avant l'implémentation. Une boucle sans vérificateur indépendant ou sans budget est un bug.

| Id | Boucle | Déclencheur | Vérificateur | Budget par défaut | Skills |
|---|---|---|---|---|---|
| L1 | Intention | demande utilisateur | schéma Intent IR + règles de complétude + confirmation humaine | 3 corrections, 3 tours de questions | intent-to-spec, llm-safety |
| L2 | Conception sécurisée | IR validée | zéro violation critique/haute, CIDR sans conflit, aucun chemin Internet vers donnée sensible non justifié | 5 itérations | multicloud-networking, policy-as-code, security-graph-attack-paths |
| L3 | Génération IaC | graphe validé | chaîne de validation verte + équivalence graphe/plan + coût dans le budget | 8 itérations, stagnation à 2 | secure-iac-generation |
| L4 | Plan et approbation | IaC validée | dossier de preuves complet et signé, risque classé | attente d'approbation avec timeout sûr | safe-autonomy, compliance-evidence |
| L5 | Application et vérification | plan signé et approuvé | vérifications post-déploiement (connectivité attendue ET interdite, santé, conformité) | 1 apply, rollback auto si échec | safe-autonomy, multicloud-networking |
| L6 | Posture continue | planifié + événements cloud | chaque finding porte preuves par saut et score de confiance | par scan | security-graph-attack-paths, llm-safety |
| L7 | Remédiation fermée | finding priorisé | re-scan ciblé confirme la disparition | 8 itérations sur le correctif | secure-iac-generation, safe-autonomy |
| L8 | Dérive | écart état réel / IaC | état réel = IaC après réconciliation | par écart | secure-iac-generation |
| L9 | Conformité | continu | chaque contrôle technique a une preuve horodatée et traçable | par cycle | compliance-evidence, policy-as-code |
| L10 | FinOps | quotidien + après apply | recommandations chiffrées, aucune ne dégrade une politique de sécurité | par cycle | secure-iac-generation |

## Enchaînements
L1 vers L2 vers L3 vers L4 vers L5 (création). L6 vers L7 vers L4 vers L5 vers re-scan (remédiation). L8 et L10 alimentent L4. L9 consomme les sorties de toutes les boucles.

## Règles transverses
- Toute sortie LLM : schéma JSON strict, validée, jamais exécutée directement.
- Toute donnée issue du cloud passée au LLM : quarantaine (skill `llm-safety`).
- Chaque itération : span OpenTelemetry (itération, empreinte d'erreur, tokens, décision).
- Chaque boucle : jeu d'evals dans `evals/<id>/` (skill `agent-evals`).

## Détail des boucles

### L1. Intention
- Entrée : texte libre + contexte du tenant (clouds connectés, contraintes, référentiels de conformité).
- Étapes : texte vers Intent IR (JSON Schema) ; détection déterministe des contradictions ; questions de clarification (3 au maximum par tour, chacune avec un défaut sûr) ; IR confirmée par l'utilisateur.
- Vérificateur : validation de schéma + règles de complétude (clouds, régions, exposition, classification des données) + confirmation humaine.
- Particularités : aucune valeur inventée hors `assumptions` ; le LLM ne choisit jamais de CIDR, d'ASN ni de rôle IAM ; les demandes contraires aux défauts sûrs vont dans `explicit_overrides` et sont tranchées par L2.

### L2. Conception sécurisée (cœur de A1)
- Entrée : IR validée.
- Étapes : IR vers graphe d'architecture (réseaux, sous-réseaux, calcul, identités, données, points d'entrée ; flux et permissions) ; allocation CIDR déterministe ; calcul d'atteignabilité ; STRIDE par nœud et par flux ; évaluation des politiques `policies/design/` et `policies/k8s/` ; révision.
- Vérificateur : zéro violation critique ou haute ; aucun chemin Internet vers une donnée sensible ; CIDR sans conflit ; chaque override justifié par un humain.
- Budget : 5 itérations, puis escalade expliquant les contraintes incompatibles.

### L3. Génération IaC
- Entrée : graphe d'architecture validé.
- Stratégies successives : modules internes seuls ; modules + HCL libre ; décomposition par cloud.
- Étapes : génération OpenTofu ; chaîne de validation (fmt, validate, tflint, Checkov, Trivy, Conftest, Infracost) ; findings normalisés renvoyés au proposeur ; correction ciblée.
- Vérificateur : aucun finding `medium` ou plus ; aucune exception de politique dans le code généré ; **équivalence graphe/plan** (rien dans le plan qui ne soit dans le graphe) ; coût dans le budget.
- Budget : 8 itérations ; même empreinte d'erreur deux fois, stratégie suivante ; trois fois, escalade.

### L4. Plan et approbation
- Étapes : `tofu plan` ; rayon d'impact ; classification déterministe du risque ; plan de retour arrière vérifié ; dossier de preuves signé ; PR ; attente d'approbation selon le niveau d'autonomie.
- Vérificateur : dossier complet et signé ; approbation liée au hash exact du plan ; réauthentification pour `high`, deux approbateurs pour `critical`.
- Échec sûr : timeout d'approbation, rien ne se passe.

### L5. Application et vérification
- Étapes : le **runner** côté client tire le plan signé, vérifie signature, hash et approbations, obtient localement des identifiants éphémères dérivés du plan, applique ; vérifications post-déploiement générées depuis le graphe (connectivité attendue, **connectivité interdite bloquée**, santé des services, conformité au runtime) ; rollback automatique si échec (L2/L3) ; attestation renvoyée.
- Vérificateur : état réel conforme au graphe validé ; attestation archivée dans le dossier de preuves.

### L6. Posture continue
- Déclencheur : planifié + événements (CloudTrail, Activity Log, audit Kubernetes).
- Étapes : inventaire agentless en lecture seule ; mise à jour du graphe réel ; diff conçu/réel ; permissions effectives ; atteignabilité ; chemins d'attaque validés saut par saut ; déduplication ; priorisation par exploitabilité démontrée.
- Vérificateur : chaque finding porte sa preuve par saut, sa source, un score de confiance ; un chemin non prouvé est affiché comme hypothèse.
- Sécurité : toutes les chaînes issues du cloud sont non fiables et ne passent au LLM qu'en quarantaine.

### L7. Remédiation fermée (cœur de A2)
- Entrée : finding priorisé.
- Étapes : localisation de la source IaC (module, fichier, lignes, propriétaire) ; si ressource non gérée, proposition d'import dans l'IaC ; correctif minimal passé par L3 ; vérification qu'aucun flux légitime du graphe conçu n'est coupé ; PR ; après merge et apply via L4/L5, **re-scan ciblé**.
- Vérificateur : le finding a disparu au re-scan ; sinon la boucle reprend ou escalade.

### L8. Dérive
- Étapes : détection des écarts état réel / IaC ; classification (changement légitime à absorber dans l'IaC, ou changement à annuler) ; PR dans le bon sens.
- Vérificateur : après réconciliation, état réel = IaC.

### L9. Conformité
- Étapes : mapping contrôles, politiques, ressources ; collecte continue des preuves produites par toutes les boucles ; rapports par référentiel (NIS2, DORA, SecNumCloud, ISO 27001, CIS) ; exports PDF et JSON vérifiables.
- Vérificateur : chaque contrôle technique a une preuve horodatée et traçable ; les contrôles organisationnels sont listés hors périmètre.

### L10. FinOps
- Étapes : delta de coût de chaque changement ; détection d'anomalies ; recommandations (redimensionnement, réservations, arrêt hors heures en dev) passées par L3.
- Vérificateur : chaque recommandation est chiffrée et ne viole aucune politique de sécurité.
