---
description: Démarrer un jalon (M0 à M8) à partir de son prompt dédié
argument-hint: <M0|M1|...|M8>
---

Démarre le jalon $ARGUMENTS.

1. `python3 .claude/bin/rempart-state milestone $ARGUMENTS`
2. Lis `prompts/$ARGUMENTS.md`, `docs/00-VISION.md`, `docs/01-LOOPS.md`, `docs/02-THREAT-MODEL.md` et `docs/STATUS.md`.
3. Vérifie que le jalon précédent est marqué ACCEPTÉ dans `docs/STATUS.md`. Sinon, arrête-toi et signale-le.
4. Délègue au subagent `architect` le découpage du jalon en tâches ordonnées (`docs/plans/$ARGUMENTS-overview.md`).
5. Présente-moi le découpage, les risques et les questions ouvertes. **Attends ma validation** avant d'exécuter la première tâche avec `/task`.
