---
description: Exécuter une tâche selon le protocole Rempart (plan, tests rouges, implémentation, vérification, revue)
argument-hint: <description de la tâche>
---

Tâche : $ARGUMENTS

Applique strictement ce protocole, sans sauter d'étape :

1. **Contexte** : `python3 .claude/bin/rempart-state show`, lis `docs/STATUS.md` et les skills pertinents.
2. **Plan** : délègue au subagent `architect` la production de `docs/plans/<jalon>-<slug>.md`. Relis le plan ; s'il contient un critère invérifiable, fais-le corriger.
3. **Phase tests** : `python3 .claude/bin/rempart-state phase tests`, puis délègue au subagent `test-author`. Vérifie que les tests échouent pour la bonne raison.
4. **Phase impl** : `python3 .claude/bin/rempart-state phase impl`. Implémente par petits incréments. Après chaque incrément, lance les tests concernés.
5. **Diagnostic** : en cas d'échec, identifie la cause racine avant de modifier. Même échec deux fois : change d'approche et note-le dans `docs/STATUS.md`. Si un test te semble faux, arrête-toi et explique, ne le contourne pas.
6. **Vérification** : `make verify-quick` doit être vert (le hook Stop l'impose de toute façon).
7. **Revue** : si la tâche touche un domaine sensible (liste dans le subagent `security-reviewer`), délègue-lui la revue. BLOCK : corrige et relance la revue.
8. **Acceptation** : délègue au subagent `acceptance-verifier`. FAIL : retour à l'étape 4.
9. **Clôture** : `python3 .claude/bin/rempart-state phase free --reason "tâche <slug> terminée"`, mise à jour de `docs/STATUS.md` (fait, preuves, reste à faire), commit atomique avec message conventionnel.
