# rempart

Harnais complet pour construire Rempart avec Claude Code en loop engineering : la discipline n'est pas seulement demandée, elle est **imposée par des hooks**.

## Contenu
```
MASTER_PROMPT.md          prompt maître complet et autonome (toute la spécification en un fichier)
CLAUDE.md                 instructions permanentes (lues à chaque session)
Makefile.template         point de départ du Makefile (cibles dont dépendent les hooks)
docs/
  00-VISION.md            vision, 7 axes de supériorité, principes, architecture, mode runner
  01-LOOPS.md             les 10 boucles du produit
  02-THREAT-MODEL.md      modèle de menace de Rempart lui-même (12 menaces, atténuations, tests)
  03-DISCOVERY.md         découverte marché : hypothèses, guide d'entretien, critères de décision
  04-INTERFACE.md         interfaces : principes, écrans E1 à E11, CLI, MCP, PR, notifications, critères UX
  STATUS.md               état du projet (tenu par l'agent et le harnais)
  SKILL-TRIGGER-TESTS.md  vérification du déclenchement des skills
  decisions/              ADR (gabarit fourni)
prompts/
  00-bootstrap.md         première session : critique de la spec, sans coder
  M0.md ... M8.md         un prompt par jalon, critères d'acceptation exécutables
.claude/
  settings.json           permissions + câblage des hooks
  hooks/                  garde-fous (testés), voir ci-dessous
  bin/rempart-state       seul moyen de changer de phase TDD ou de jalon
  agents/                 architect, test-author, security-reviewer, acceptance-verifier
  commands/               /task /milestone /close-milestone /verify /review /adr /resume
  skills/                 14 skills avec références, exemples et scripts
```

## Ce que font les hooks
| Hook | Effet |
|---|---|
| SessionStart | Injecte jalon, phase, derniers commits, STATUS et blocages non résolus |
| PreToolUse (édition) | Protège le harnais (`CLAUDE.md`, settings, hooks, état, subagents, commandes) ; gèle les tests en phase impl et le code en phase tests ; bloque les secrets en clair et les `t.Skip` |
| PreToolUse (Bash) | Bloque apply/destroy directs, commandes cloud destructives, push forcé, `--no-verify`, modification du harnais, mise à jour des baselines |
| PostToolUse | Formate et vérifie immédiatement (go vet, opa check, tofu fmt, JSON) pendant que le contexte est frais |
| Stop | Empêche de finir si `make verify-quick` est rouge ; coupe-circuit après 3 échecs avec BLOCAGE consigné |

La porte TDD de `rempart-state` refuse le passage en implémentation si les nouveaux tests passent déjà (ils ne prouvent rien).

## Démarrage
1. Installe les prérequis : Go 1.23+, Docker, OpenTofu, OPA, Conftest, tflint, Checkov, Trivy, Infracost, Python 3, jq ; comptes sandbox AWS et Azure avec alertes de budget.
2. Le dossier `rempart/` est la racine du repo : place-toi dedans, vérifie que le dossier caché `.claude/` est bien présent, puis `git init` et un premier commit. `Makefile.template` sera renommé en `Makefile` lors de M0.
3. Lance Claude Code depuis `rempart/`, colle `MASTER_PROMPT.md` (version complète) ou `prompts/00-bootstrap.md` (version courte qui renvoie aux documents). Lis sa critique, ajuste.
4. `/milestone M0`, valide le découpage, puis `/task` pour chaque tâche. `/close-milestone M0` à la fin.
5. En parallèle de M0 à M2, mène la découverte marché (`docs/03-DISCOVERY.md`). Ses conclusions peuvent modifier le périmètre de M3 et au-delà.

## Limites honnêtes
- Les hooks relèvent fortement le niveau d'exigence mais ne sont pas un bac à sable : un agent déterminé qui dispose de Bash peut contourner certaines règles. Les filets de sécurité sont le journal dans `STATUS.md`, les subagents indépendants, la CI et ta revue.
- Les scripts fournis (hooks, vérificateur CIDR, normaliseur, chaîne de validation, exemples Rego) ont été testés ; le squelette Temporal et les schémas sont des points de départ à compiler et valider en M0 et M1.
- Les références réglementaires et les détails fournisseurs (VPN, permissions, clouds souverains) sont à vérifier à la source au moment de l'implémentation : les skills l'exigent explicitement.
- Le périmètre M0 à M8 représente plusieurs mois de travail pour une personne. M0 à M4 sur le scénario de référence est déjà un MVP démontrable pour des design partners.
