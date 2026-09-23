# Proposition 0001 : harnais portable, qui bloque en cas de doute, et compatible avec la phase tests

- Date : 2026-09-23
- Statut : proposé, **à appliquer par l'humain** (l'agent n'a pas le droit de modifier le harnais)
- Patch : `docs/proposals/0001-harnais-portable-et-tdd.patch`
- Constats d'origine : `docs/reviews/2026-09-23-critique-initiale.md`, section 1

## Appliquer

Depuis la racine du dépôt, dans ton terminal (pas via Claude) :

```bash
git apply docs/proposals/0001-harnais-portable-et-tdd.patch
bash .claude/hooks/test_hooks.sh
git add .claude && git commit -m "fix(harness): portable hooks, fail-closed guards, tests-phase compatible Stop hook"
```

Puis redémarre Claude Code pour que les nouveaux hooks soient chargés.

## Ce qui change

| Fichier | Changement |
|---|---|
| `.claude/hooks/py.sh` (nouveau) | Lanceur qui trouve un Python 3 qui fonctionne (`python3`, `python` ou `py`), force l'UTF-8. Sans Python : exit 2 pour les gardes (action bloquée), exit 1 sinon |
| `.claude/settings.json` | Tous les hooks passent par `py.sh` ; les gardes en `--fail-closed` |
| `_common.py` | Entrée lue en UTF-8 ; `read_input(fail_closed=True)` bloque sur une entrée illisible ; `rel()` renvoie toujours des `/`, casse normalisée sous Windows ; état lu et écrit en UTF-8 |
| `guard_edit.py` | Garde bloquante en cas de doute ; motifs de chemin insensibles à la casse ; baselines d'eval protégées dans toutes les phases ; `t.Skipf` aussi interdit en impl |
| `guard_bash.py` | Exemption `rempart-state` seulement pour un appel seul (sans `; & \| < > $` ni retour ligne) ; chemins Windows normalisés ; écriture dans le harnais détectée quel que soit l'ordre (`python -c open(...)`, `git checkout`, etc.) ; `--write-baseline`, `git push +ref`, `git commit -n` et `rm -rf .git` bloqués |
| `post_edit_check.py` | Erreur de syntaxe Go signalée ; en phase tests, `go vet` n'est pas lancé sur un `_test.go` (il peut appeler du code pas encore écrit) |
| `stop_verify.py` | En phase tests : exige seulement `go build ./...` (on peut s'arrêter pour faire relire des tests rouges) ; ailleurs `make verify-quick` ; `make` ou `go` absent compte comme un échec, pas comme un succès silencieux ; clés d'état séparées par type de vérification ; UTF-8 |
| `session_start.py` | UTF-8 (« RÉSOLU » enfin reconnu) |
| `.claude/bin/rempart-state` | `git status -uall` (tests des nouveaux packages visibles) ; refus des tests avec erreur de syntaxe (mauvaise raison d'échouer) ; UTF-8 |
| `.claude/hooks/test_hooks.sh` (nouveau) | 57 cas de non-régression, exécutés dans un projet temporaire |

## Résultats des tests (copie corrigée)

- Windows 11, Git Bash, Python 3.13, Go 1.16 : 57 réussis, 0 échoué.
- Ubuntu sous WSL2, Python 3.12, sans Go : 48 réussis, 0 échoué (cas Go sautés et signalés).

## Conséquences à connaître

- **Baselines d'eval** : l'agent ne peut plus les créer ni les modifier, dans aucune phase. La première baseline de M0 (critère 5) se génère donc par toi : `make update-baseline EVAL=...`.
- **Shell POSIX requis** pour lancer les hooks (`sh`) : Linux, macOS, WSL2 ou Git Bash sous Windows.
- `CLAUDE.md` et les commandes écrivent toujours `python3 .claude/bin/rempart-state` ; sous Windows sans `python3`, utiliser `python` (le garde Bash accepte les deux).
- Les filtres restent contournables par un agent déterminé (limite déjà écrite dans le README) : les filets restent le journal, les subagents indépendants, la CI et ta revue.
