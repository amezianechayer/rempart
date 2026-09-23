#!/usr/bin/env python3
"""SessionStart : injecte l'état du projet dans le contexte (stdout est ajouté au contexte)."""
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import PROJECT_DIR, state  # noqa: E402


def main() -> None:
    lines = ["# Contexte Rempart (injecté au démarrage)",
             f"- Jalon courant : {state('milestone', 'non défini')}",
             f"- Phase TDD : {state('phase', 'free')}"]
    try:
        log = subprocess.run(["git", "log", "--oneline", "-8"], cwd=PROJECT_DIR,
                             capture_output=True, text=True, timeout=10).stdout.strip()
        if log:
            lines += ["- Derniers commits :", *["  " + l for l in log.splitlines()]]
    except Exception:  # noqa: BLE001
        pass
    status = PROJECT_DIR / "docs" / "STATUS.md"
    if status.exists():
        content = status.read_text().splitlines()
        lines += ["", "## Extrait de docs/STATUS.md", *content[:60]]
        blocked = [l for l in content if "BLOCAGE" in l and "RÉSOLU" not in l]
        if blocked:
            lines += ["", "ATTENTION, blocages non résolus :", *blocked[-3:]]
    lines += ["", "Protocole : lis les skills pertinents, suis /task pour toute tâche, rien n'est fini sans `make verify-quick` vert."]
    print("\n".join(lines))


if __name__ == "__main__":
    main()
