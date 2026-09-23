---
name: loop-engineering
description: Méthode pour concevoir, implémenter et tester les boucles agentiques de Rempart (workflows Temporal avec proposeur, vérificateur indépendant, erreurs normalisées, budget, détection de stagnation, escalade, approbation humaine). À utiliser systématiquement dès qu'une tâche touche une boucle L1 à L10, internal/loops, un workflow Temporal, un appel LLM itératif, une logique de retry ou d'auto-correction, même si le mot "boucle" n'est pas prononcé.
---

# Loop engineering

Une boucle agentique fiable est un système de contrôle, pas « le LLM réessaie jusqu'à ce que ça marche » : une proposition, un vérificateur indépendant, un signal d'erreur exploitable, un budget, une sortie propre.

## Quand lire quoi
- Rédiger la fiche d'une boucle : `references/loop-spec-template.md`
- Implémenter en Go/Temporal : `references/temporal-loop-skeleton.md` (squelette complet de `RunLoop` et de l'attente d'approbation)
- Format des erreurs renvoyées au proposeur : `references/normalized-findings.md`

## Les neuf règles
1. **Vérificateur déterministe et indépendant du proposeur.** Un juge LLM peut compléter, jamais être le vérificateur principal d'une décision de sécurité.
2. **Signal d'erreur structuré** (format normalisé), trié par gravité, tronqué à l'essentiel. Jamais un log brut.
3. **Correction ciblée** : corriger les erreurs listées sans régénérer le reste. Conserver le meilleur candidat vu.
4. **Empreinte d'erreur** = hash des couples (code, ressource) triés. Base de la détection de stagnation.
5. **Stagnation** : même empreinte deux fois de suite, passer à la stratégie suivante (ex. modules, puis génération libre, puis décomposition) ; trois fois ou plus de stratégies, escalader.
6. **Budgets explicites** : itérations, tokens, temps, coût. Dépassement = escalade documentée, jamais un échec silencieux.
7. **Idempotence** : activités rejouables, clés d'idempotence pour tout effet externe (PR, apply, notification).
8. **Humain dans la boucle = signal Temporal** avec timeout ; défaut au timeout : ne rien faire. L'approbation porte sur un hash précis.
9. **Traçabilité** : un span OpenTelemetry par itération (itération, stratégie, empreinte, nombre de findings, tokens, décision).

## Anti-motifs à refuser
- Le LLM juge sa propre sortie et décide que c'est bon.
- Retry automatique Temporal sur une erreur de validation (ce n'est pas une erreur transitoire : `NonRetryableErrorTypes`).
- Boucle sans budget ou sans escalade.
- Retour au LLM de 2 000 lignes de sortie d'outil.
- Régénération complète à chaque itération (perte des parties déjà correctes).

## Tests obligatoires par boucle (testsuite Temporal)
Convergence ; stagnation puis changement de stratégie ; stagnation puis escalade ; dépassement de budget (itérations, tokens, temps) ; timeout d'approbation ; approbation sur un mauvais hash ; rejeu idempotent.

## Ta propre boucle de construction
Même discipline, imposée par le harnais : plan, tests rouges (phase tests), implémentation (phase impl), `make verify-quick`, revue, acceptation. Voir `/task`.
