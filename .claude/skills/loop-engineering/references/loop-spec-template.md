# Fiche de boucle : gabarit

Fichier : `docs/loops/<id>.md`. À rédiger et faire valider avant tout code.

```yaml
id: L3-iac-generation
purpose: produire une IaC OpenTofu équivalente au graphe d'architecture validé
trigger: signal "graph.validated" émis par L2
inputs:
  - architecture_graph   # schemas/graph/v1.json
  - tenant_context       # clouds, régions, référentiels, budget
  - module_catalog       # modules internes disponibles et versions
strategies: [modules_only, modules_plus_freeform, decompose_by_cloud]
steps:
  propose: activité ProposeIaC (LLM, contexte minimal, sortie = arborescence de fichiers)
  verify: activité VerifyIaC (chaîne déterministe, voir skill secure-iac-generation)
  diagnose: findings normalisés, top 20 par gravité, renvoyés au proposeur
verifier:
  success_when:
    - aucun finding de gravité >= medium
    - équivalence graphe/plan : aucune ressource, permission ou ouverture hors graphe
    - coût estimé <= budget de l'IR
budget: {max_iterations: 8, max_tokens: 400000, max_wall_time: 20m, max_cost_eur: 4}
stall_detection: {same_fingerprint_switch_strategy: 2, same_fingerprint_escalate: 3}
escalation:
  to: tâche humaine dans l'interface + notification
  payload: [meilleur candidat, findings restants, historique des empreintes, stratégies essayées, 2 options proposées]
outputs: [iac_bundle, validation_report, loop_trace]
idempotency_keys: [tenant_id, change_id, iteration]
security_notes: le proposeur ne reçoit aucune donnée issue du cloud réel ; seulement le graphe validé
evals: evals/L3/
```

## Questions à se poser avant de valider la fiche
- Le vérificateur peut-il être trompé par le proposeur ? (ex. le proposeur écrit des exceptions de politique : interdit.)
- Que se passe-t-il au pire cas de budget ? Coût maximal par exécution et par tenant ?
- Quelle donnée non fiable entre dans la boucle, et par où ?
- L'escalade donne-t-elle à l'humain de quoi décider en moins de 5 minutes ?
