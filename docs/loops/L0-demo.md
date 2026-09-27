# L0-demo : boucle de démonstration

Fiche de la boucle de démonstration de M0 (gabarit `.claude/skills/loop-engineering/references/loop-spec-template.md`), recopiée de `docs/plans/M0-overview.md` section 5.4 et ajustée par l'amendement A1 et le plan `docs/plans/M0-demo-workflow.md` (M0-T19d). Écrite avant tout code de la démo.

Écarts à la fiche 5.4 : pas d'entrée `canary` ni de `ContinueAsNew` (A1, tâches de l'ADR 0001 en M1) ; entrée fermée et sans défaut (D3) ; tenant fixé par le worker, jamais par l'entrée (D2) ; échec facturable du proposeur compté 1024 tokens (D5) ; historique Temporal en clair en M0, sans aucune donnée client (A1, risque accepté).

```yaml
id: L0-demo
workflow: rempart.demo.v1
purpose: démontrer RunLoop et AwaitApprovals de bout en bout, sans aucune logique métier
trigger: démarrage manuel (make demo, M0-T20), test d'intégration, cible d'eval "demo"
inputs:                   # validées avant toute activité, erreur InvalidDemoInput non rejouable, message sans valeur (D3)
  - target                # [a-z0-9 -]{1,64}, synthétique (ex. "bonjour")
  - author                # identité déclarée jusqu'à M4, exclue des approbateurs
  - approval_timeout      # de 1 s à 1 h, aucun défaut (make demo passe 5 s)
tenant: fixé par la racine de composition du worker (option -tenant de M0-T20), jamais lu dans l'entrée (D2, T75)
strategies: [direct, reformulate]
steps:
  propose: activité demo.Propose (llm.Client.Structured, prompt demo.greeting.v1 à hash épinglé, aucun outil, cible transmise seulement en bloc non fiable)
  verify: activité demo.Verify (déterministe : schéma, puis égalité greeting == target ; recharge le prompt et exige son hash)
  diagnose: findings normalisés DEMO-MISMATCH et DEMO-SCHEMA (ressource "candidate", gravité high), top 20
proposer_failures:        # D5
  billed: ErrProviderFailed, ErrOutOfSchema, ErrModelMismatch, ErrUnknownTool -> ApplicationError ProposeFailed, détail ProposeFailure{tokens: 1024}, rejouable sauf ErrModelMismatch
  refused_without_io: non rejouable, sans détail
verifier:
  success_when:
    - candidat conforme au schéma de sortie
    - candidate.greeting == target
budget: {max_iterations: 4, max_tokens: 4000, max_wall_time: 1m, max_cost_eur: 0}
activity_timeout: 30s
stall_detection: {same_fingerprint_switch_strategy: 2, same_fingerprint_escalate: 3}
escalation:
  to: résultat du workflow (statut escalated, raison codée), aucune attente d'approbation
  payload: [meilleur candidat, findings restants, trace des itérations, stratégies essayées]
approval:
  required: 1
  needs_security_role: false
  waits_per_workflow: 1          # obligation (o), sans purge du canal de signaux (D6)
  max_ignored_signals: 20
  on_timeout: ne rien faire
  verifier: vérificateur factice réservé aux tests ; make demo (M0-T20) enregistre un vérificateur qui refuse tout
commit: activité demo.Commit, sans effet en M0, une tentative, 10 s ; ctx.Err() contrôlé entre approbation et commit (obligation (m), D7)
plan_hash: SHA-256 hexadécimal de "rempart-demo-plan-v1\n" suivi du meilleur candidat, calculé dans le workflow (D8)
outputs: [loop_result, approval_result, plan_hash, committed]
idempotency_keys: [tenant_id, workflow_id, plan_hash]
security_notes: aucune donnée cloud ; faux fournisseur LLM seulement en M0 ; historique en clair en M0 (A1), chiffré par tenant en M1 [ADR-0001]
evals: evals/demo/ (M0-T23)
```
