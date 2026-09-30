"""Utilitaires partagés par les hooks Rempart."""
import json
import os
import sys
from pathlib import Path

PROJECT_DIR = Path(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd()))
STATE_DIR = PROJECT_DIR / ".claude" / "state"

# Sous Windows, la locale par défaut (cp1252) corrompt les accents : on force l'UTF-8.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):
        pass


def read_input(fail_closed: bool = False) -> dict:
    """Lit l'entrée JSON du hook en UTF-8, quelle que soit la locale.

    fail_closed=True (hooks de garde) : une entrée illisible bloque l'action au lieu d'être ignorée.
    """
    try:
        data = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("objet JSON attendu")
        return data
    except Exception as e:  # noqa: BLE001
        if fail_closed:
            block(f"BLOQUÉ : entrée du hook illisible ({e}). Par sécurité, l'action est refusée.")
        return {}


def state(name: str, default: str = "") -> str:
    p = STATE_DIR / name
    try:
        return p.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return default


def set_state(name: str, value: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    (STATE_DIR / name).write_text(value + "\n", encoding="utf-8")


def block(message: str) -> None:
    """Exit 2 : l'action est bloquée et le message est renvoyé à Claude."""
    print(message, file=sys.stderr)
    sys.exit(2)


def rel(path: str) -> str:
    """Chemin relatif au projet, toujours avec des « / ».

    Sous Windows, la casse est normalisée (minuscules) : les motifs de chemin s'évaluent sans tenir compte de la casse.
    Un chemin hors du projet est renvoyé tel quel (en « / »).
    """
    if not path:
        return ""
    p = Path(path)
    if not p.is_absolute():
        p = PROJECT_DIR / p
    target = os.path.normcase(str(p.resolve()))
    root = os.path.normcase(str(PROJECT_DIR.resolve())).rstrip("\\/")
    if target == root:
        return ""
    if target.startswith(root + os.sep):
        return target[len(root) + 1:].replace(os.sep, "/")
    return Path(path).as_posix()
