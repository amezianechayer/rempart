"""Utilitaires partagés par les hooks Rempart."""
import json
import os
import sys
from pathlib import Path

PROJECT_DIR = Path(os.environ.get("CLAUDE_PROJECT_DIR", os.getcwd()))
STATE_DIR = PROJECT_DIR / ".claude" / "state"


def read_input() -> dict:
    try:
        return json.load(sys.stdin)
    except Exception:
        return {}


def state(name: str, default: str = "") -> str:
    p = STATE_DIR / name
    try:
        return p.read_text().strip()
    except FileNotFoundError:
        return default


def set_state(name: str, value: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    (STATE_DIR / name).write_text(value + "\n")


def block(message: str) -> None:
    """Exit 2 : l'action est bloquée et le message est renvoyé à Claude."""
    print(message, file=sys.stderr)
    sys.exit(2)


def rel(path: str) -> str:
    try:
        return str(Path(path).resolve().relative_to(PROJECT_DIR.resolve()))
    except Exception:
        return path
