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
  baseline.json    métriques de référence (modifiable uniquement par PR humaine)
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
- Régression significative par rapport à `baseline.json` : merge bloqué. La baseline change uniquement par PR humaine explicite (le hook bloque `make update-baseline` pour l'agent).
- Chaque changement de modèle LLM déclenche la suite complète.
