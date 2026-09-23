# Rempart : instructions permanentes

Plateforme agentique d'infrastructure multicloud sécurisée par construction. Référence complète : `docs/00-VISION.md` (vision), `docs/01-LOOPS.md` (boucles), `docs/02-THREAT-MODEL.md` (menaces sur Rempart lui-même), `docs/04-INTERFACE.md` (interfaces et expérience). Jalons : `prompts/M0.md` à `prompts/M8.md`.

## Le harnais (ce qui est imposé mécaniquement)
- Tu ne peux pas modifier `CLAUDE.md`, `.claude/settings.json`, `.claude/hooks/`, `.claude/bin/`, `.claude/state/`, `.claude/agents/`, `.claude/commands/`. Si le harnais te gêne, explique pourquoi et propose un diff à l'humain.
- Les skills (`.claude/skills/`) restent modifiables pour les enrichir, mais toute modification est signalée dans `docs/STATUS.md` pour revue humaine.
- Phases TDD (`python3 .claude/bin/rempart-state phase ...`) : en **tests**, seul le code de test est modifiable ; en **impl**, les tests, cas d'eval et baselines sont gelés ; passer en impl exige des tests qui échouent.
- Tu ne peux pas terminer un tour si `make verify-quick` est rouge (hook Stop, 3 tentatives puis BLOCAGE consigné).
- Pas d'apply/destroy direct, pas de commande cloud destructive, pas de push forcé, pas de `--no-verify`, pas de secret en clair.

## Protocole
- Toute tâche passe par `/task`. Tout jalon démarre par `/milestone Mx` et se clôt par `/close-milestone Mx`.
- Subagents : `architect` (plan, ADR), `test-author` (tests), `security-reviewer` (verdict PASS/BLOCK), `acceptance-verifier` (verdict PASS/FAIL avec preuves).
- Même échec deux fois : change d'approche et note-le dans `docs/STATUS.md`. Plus de 6 cycles sans progrès : arrête-toi et présente deux options.
- Décision structurante : ADR (`/adr`).
- Après une compaction ou une pause : `/resume`.

## Invariants produit
- L'IaC (OpenTofu) dans Git est la source de vérité.
- Cœur déterministe, LLM en périphérie : aucune décision de sécurité prise par un LLM.
- Toute donnée issue du cloud est non fiable (skill `llm-safety`).
- Validation offensive non destructive uniquement.
- Mode runner par défaut : le plan de contrôle ne détient pas d'identifiant d'écriture.
- Isolation stricte par tenant, testée.

## Commandes make
`verify-quick` (build, lint, tests unitaires, opa test, test d'architecture) ; `verify` (+ intégration, govulncheck, evals ciblées) ; `evals` ; `dev` ; `sandbox-plan` ; `sandbox-apply` et `sandbox-destroy` (approbation humaine).

## Style
Code, identifiants, commits en anglais (commits conventionnels). Documentation et ADR en français. Pas de tiret cadratin dans les textes produits.
