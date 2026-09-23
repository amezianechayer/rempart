# Proposition 0002 : attribution des commits dans CLAUDE.md

- Date : 2026-09-23
- Statut : proposé, **à appliquer par l'humain** (`CLAUDE.md` fait partie du harnais)
- Patch : `docs/proposals/0002-claude-md-trailer-commits.patch`

## Pourquoi
Demande de l'humain : les commits ne portent pas la ligne `Co-Authored-By` de Claude, mais `Co-Authored-By: Ameziane Chayer <amezianechayer9@gmail.com>`. Une règle écrite dans `CLAUDE.md` l'emporte sur la consigne d'attribution par défaut de Claude Code, sur toutes les machines ; une mémoire locale ne vaut que pour un poste.

## Appliquer
```bash
git apply docs/proposals/0002-claude-md-trailer-commits.patch
git add CLAUDE.md && git commit -m "docs(claude): set commit co-author trailer"
```
Peut être appliqué en même temps que la proposition 0001.
