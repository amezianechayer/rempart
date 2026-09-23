---
description: Clore un jalon après vérification indépendante de tous ses critères
argument-hint: <M0|M1|...|M8>
---

Clôture du jalon $ARGUMENTS.

1. Lance `make verify` complet et `make evals`.
2. Délègue au subagent `acceptance-verifier` la vérification de tous les critères de `prompts/$ARGUMENTS.md`.
3. Délègue au subagent `security-reviewer` une revue du diff complet du jalon (`git diff <tag du jalon précédent>..HEAD`).
4. Si les deux verdicts sont PASS : ajoute dans `docs/STATUS.md` une section « $ARGUMENTS ACCEPTÉ » avec les preuves, puis propose-moi la commande de tag git (je la lance moi-même).
5. Sinon : liste précise de ce qui manque, et plan pour y remédier. Ne marque rien comme accepté.
