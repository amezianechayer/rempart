---
name: agent-evals
description: Conception et exécution des évaluations des boucles agentiques de Rempart (cas nominaux, pièges, injections, régressions, graders déterministes, métriques, baselines, labo vulnérable, blocage des régressions en CI). À utiliser dès qu'une tâche modifie un prompt, un modèle, une boucle ou un vérificateur, ou crée une boucle : toute modification de ce type s'accompagne d'evals.
---

# Évaluations des agents

## Référence
Format d'un cas et d'un rapport : `references/case-format.md`

## Structure
```
evals/<boucle>/
  cases/*.yaml     entrée, contexte, attendu
  graders/         vérificateurs de résultat, déterministes d'abord
  baseline.json    métriques de référence des suites sans LLM (modifiable uniquement par PR humaine)
  baseline/<plateforme>/<modèle>.json   une baseline par couple plateforme et modèle pour les suites qui appellent un LLM (ADR 0002)
evals/security/lab/        IaC d'un environnement volontairement vulnérable + failles attendues
evals/security/injection/  ressources dont noms/tags/descriptions contiennent des injections
```

## Types de cas (proportions minimales)
- Nominaux : 40 %. Pièges (architectures dangereuses, contradictions) : 25 %. Injections : 15 %. Limites (grands graphes, clouds rares, budgets impossibles) : 10 %. Régressions (chaque bug de production devient un cas) : le reste, en croissance.

## Métriques par boucle
Taux de succès ; taux d'escalade **correcte** (escalader quand il faut, pas quand il ne faut pas) ; itérations moyennes ; tokens et coût moyens ; durée. Sécurité : faux positifs et faux négatifs sur le labo ; taux de résistance aux injections (doit être 100 % : une injection qui change une décision est un bug critique).

## Règles
- Graders déterministes chaque fois que possible. Juge LLM uniquement pour des propriétés non vérifiables autrement (clarté d'une explication), avec grille explicite et jamais sur une décision de sécurité.
- 3 exécutions par cas non déterministe ; comparer des distributions, pas des valeurs uniques.
- Régression significative par rapport à la baseline : merge bloqué. La baseline change uniquement par PR humaine explicite (le hook bloque `make update-baseline`, `--write-baseline` et toute écriture de baseline par l'agent).
- Chaque changement de couple plateforme et modèle déclenche la suite complète ; un changement de région pour un même couple, une suite de fumée (ADR 0002). Le rapport indique `platform` et `region`.
- Une route LLM dont le couple plateforme et modèle n'a pas de baseline validée est refusée à partir de M1 (ADR 0002).
