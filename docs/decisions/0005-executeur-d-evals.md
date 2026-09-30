# 0005. Exécuteur d'evals : exécution en processus, contrat de sortie, sélection qui échoue fermée

- Statut : accepté le 2026-09-30 (décision humaine)
- Date : 2026-09-30
- Jalon : M0 (tâche M0-T23), portée M1 et au-delà

## Contexte
M0-T23 livre `cmd/rempart-evals`, qui exécute les suites de `evals/`, compare à la baseline et sert de porte de fusion (`make verify` en CI). Trois choix engagent les jalons suivants, où chaque boucle (L1 à L7) aura sa suite :

1. **Où tourne une boucle pendant une eval.** Les boucles sont des workflows Temporal (`internal/loops`). Les faire tourner contre la pile `make dev` exige Docker et le réseau local, et rend les evals dépendantes de l'état de la pile ; les faire tourner dans l'environnement de test du SDK (`go.temporal.io/sdk/testsuite`) les rend autonomes, rapides et à horloge simulée, mais ce paquet est conçu pour `go test`.
2. **Contrat de sortie.** Le `Makefile`, la CI et l'humain (étape H3) consomment les codes de sortie et la sortie standard ; les changer plus tard casse la porte.
3. **Sélection `changed`.** `make verify` ne rejoue que les suites concernées par le diff depuis `EVAL_BASE` ; une sélection qui échoue ouverte (moins d'evals) masque une régression (T61).

Faits vérifiés sur le SDK épinglé (v1.49.0) : `WorkflowTestSuite.NewTestWorkflowEnvironment` n'exige pas de `*testing.T` ; le paquet importe `testing` et testify (déjà dépendances du module) ; son journal par défaut écrit sur **la sortie standard** (`internal/log/default_logger.go`) ; son délai par défaut est de 3 s d'horloge réelle, porté à 24 h si `TEMPORAL_DEBUG` est défini ; des variables `TEMPORAL_SDK_FLAG_<n>` modifient son comportement au chargement du paquet. `testsuite` contient aussi `StartDevServer`, qui télécharge et exécute un binaire : il ne doit jamais être appelé.

## Options envisagées
1. **Exécution contre la pile `make dev`** (client Temporal réel, worker dans le processus) : fidèle à la production ; exige Docker, ports locaux, pile démarrée ; `make evals` n'est plus utilisable sans Docker ; variabilité (délais, état des namespaces) ; le délai d'approbation de 5 s de la démo est réellement attendu.
2. **Exécution en processus dans l'environnement de test du SDK** : aucune dépendance réseau ni Docker, horloge simulée (délais d'approbation franchis sans attente), une instance neuve par exécution de cas ; écart connu avec la production (pas de sérialisation par le serveur, pas de rejeu réel), couvert par les tests d'intégration de `internal/loops/demo` ; exige de rediriger le journal du SDK et de refuser les variables d'environnement qui changent son comportement.
3. **Appel direct des activités sans workflow** : le plus simple, mais n'évalue pas `RunLoop` (budget, stagnation, escalade), qui est précisément ce que la baseline doit protéger.

Pour le contrat de sortie :
- (a) codes distincts `0` conforme, `1` régression, `2` usage ou configuration, `3` baseline absente, `4` erreur d'exécution ; un seul document JSON sur la sortie standard, messages sur la sortie d'erreur ;
- (b) code unique non nul et texte libre.

Pour la sélection :
- (i) diff depuis la base, toute incertitude (base absente, nulle, invalide, non ancêtre, `git` en échec, sortie trop grande) : toutes les suites ;
- (ii) incertitude : aucune suite et avertissement.

## Décision
Option 2, contrat (a), sélection (i).

- La cible d'une suite (`target` de `suite.yaml`) est une implémentation Go enregistrée par nom dans `cmd/rempart-evals` ; pour une boucle, elle exécute le vrai workflow dans une `TestWorkflowEnvironment` neuve par exécution, avec un journal du SDK dirigé vers la sortie d'erreur au niveau `Warn`, un délai de test explicite, et refuse de démarrer (code 2) si `TEMPORAL_DEBUG` ou une variable `TEMPORAL_SDK_FLAG_*` est définie. `StartDevServer` n'est jamais appelé (contrôle par `grep` à l'acceptation).
- La sortie standard porte exactement un document JSON (le rapport de la suite demandée, ou un document de sélection pour `all` et `changed`) et seulement pour les codes 0 et 1 dans le mode à suite nommée.
- La baseline n'est écrite que par `--write-baseline` sur une suite nommée, lancé par l'humain (`make update-baseline`), jamais par l'agent (gardes du harnais, CODEOWNERS).
- La référence de base n'est admise que sous forme d'identifiant d'objet hexadécimal complet (40 ou 64 caractères, non nul), passée à `git` après `--end-of-options`, sans shell, avec un environnement réduit à une liste blanche.

## Conséquences
- Positives : `make evals` tourne sans Docker ni réseau, en quelques secondes ; la porte est déterministe pour le faux LLM ; une suite par boucle se branche en ajoutant une cible ; la sélection ne peut que rejouer trop, jamais trop peu.
- Négatives : l'exécution en processus n'exerce ni le serveur Temporal ni le rejeu (ce dernier relève des tests de rejeu de M1) ; la cible `demo` reproduit le câblage de `cmd/rempart-worker` (faux fournisseur, route, tenant) : dérive possible, surveillée par la revue et par les tests des deux binaires ; une base symbolique (`origin/main`) est refusée et fait tout rejouer.
- Plus difficile à changer : les codes de sortie et la forme du document JSON (consommés par le `Makefile`, la CI, l'étape H3 et les critères d'acceptation) ; l'emplacement des baselines reste celui de l'ADR 0002.
- Réversibilité : passer à l'option 1 pour une suite donnée revient à écrire une autre cible, sans toucher au contrat ni au noyau `internal/evals`.

## Impact sécurité
- T8 : seule exécution de `cmd/rempart-evals` : `git`, arguments fixes en tableau, référence hexadécimale, `--end-of-options`, environnement en liste blanche, sorties bornées ; résidu : `git` résolu par `PATH`.
- T58, T63 : baseline écrite par l'humain seulement ; résidu : le code de l'exécuteur (`cmd/rempart-evals`, `internal/evals`) n'est pas couvert par CODEOWNERS, d'où la menace proposée T83 et la proposition de harnais 0010.
- T61 : sélection qui échoue fermée, `--no-renames`, fichiers non suivis inclus.
- Nouvelle menace proposée T84 : sortie ou comportement de l'exécuteur modifiés par l'environnement (journal du SDK sur la sortie standard, `TEMPORAL_DEBUG`, `TEMPORAL_SDK_FLAG_*`, variables `GIT_*`).
