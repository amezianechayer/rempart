#!/bin/sh
# Lanceur portable des hooks Rempart : trouve un Python 3 qui fonctionne (python3, python ou py selon l'OS).
# Usage : py.sh [--fail-closed] <script.py> [args...]
# --fail-closed : sans Python, exit 2 (l'action est bloquée) au lieu de 1 (erreur non bloquante).
# Un hook de garde qui ne peut pas s'exécuter doit bloquer, jamais laisser passer en silence.
fail=1
if [ "$1" = "--fail-closed" ]; then
  fail=2
  shift
fi
export PYTHONUTF8=1 PYTHONIOENCODING=utf-8
for p in python3 python py; do
  # Vérifie que l'interpréteur fonctionne vraiment (l'alias python3 du Microsoft Store ne fait rien).
  if "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    exec "$p" "$@"
  fi
done
echo "Hook Rempart : aucun Python 3.8+ trouvé (python3, python, py). Installe Python 3." >&2
exit "$fail"
