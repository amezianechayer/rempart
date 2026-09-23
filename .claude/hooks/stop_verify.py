#!/usr/bin/env python3
"""Stop : Claude ne peut pas terminer son tour avec un arbre de travail qui ne passe pas `make verify-quick`.

- Si rien n'a changé depuis la dernière vérification verte : on laisse passer.
- Sinon on lance `make verify-quick`. Rouge : exit 2, Claude reçoit les erreurs et doit continuer.
- Coupe-circuit anti-boucle : après MAX_ATTEMPTS échecs consécutifs, on laisse Claude s'arrêter
  mais on consigne un BLOCAGE dans docs/STATUS.md pour l'humain.
"""
import datetime as dt
import hashlib
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import PROJECT_DIR, block, read_input, set_state, state  # noqa: E402

MAX_ATTEMPTS = 3
TARGET = "verify-quick"


def sh(cmd, timeout=60):
    p = subprocess.run(cmd, cwd=PROJECT_DIR, capture_output=True, text=True, timeout=timeout)
    return p.returncode, p.stdout, p.stderr


def worktree_fingerprint() -> str:
    h = hashlib.sha256()
    _, diff, _ = sh(["git", "diff", "HEAD", "--", ".", ":(exclude).claude/state"])
    h.update(diff.encode())
    _, untracked, _ = sh(["git", "ls-files", "--others", "--exclude-standard"])
    for f in sorted(untracked.split()):
        if f.startswith(".claude/state"):
            continue
        h.update(f.encode())
        try:
            h.update((PROJECT_DIR / f).read_bytes())
        except OSError:
            pass
    return h.hexdigest()


def has_target() -> bool:
    mk = PROJECT_DIR / "Makefile"
    return mk.exists() and f"\n{TARGET}:" in "\n" + mk.read_text()


def log_blocked(summary: str) -> None:
    status = PROJECT_DIR / "docs" / "STATUS.md"
    status.parent.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    with status.open("a") as f:
        f.write(f"\n- {stamp} BLOCAGE : `make {TARGET}` rouge après {MAX_ATTEMPTS} tentatives. "
                f"Intervention humaine requise. Dernière erreur : {summary}\n")


def main() -> None:
    data = read_input()
    rc, _, _ = sh(["git", "rev-parse", "--is-inside-work-tree"])
    if rc != 0 or not has_target():
        sys.exit(0)

    fp = worktree_fingerprint()
    if fp == state("last_verified"):
        set_state("stop_attempts", "0")
        sys.exit(0)

    attempts = int(state("stop_attempts", "0") or 0)
    if data.get("stop_hook_active") and attempts >= MAX_ATTEMPTS:
        log_blocked("voir la sortie de la dernière exécution")
        set_state("stop_attempts", "0")
        sys.exit(0)

    try:
        rc, out, err = sh(["make", TARGET], timeout=840)
    except subprocess.TimeoutExpired:
        rc, out, err = 1, "", f"make {TARGET} a dépassé le délai."

    if rc == 0:
        set_state("last_verified", fp)
        set_state("stop_attempts", "0")
        sys.exit(0)

    set_state("stop_attempts", str(attempts + 1))
    tail = (out + "\n" + err).strip().splitlines()[-80:]
    block(
        f"Tu ne peux pas terminer : `make {TARGET}` échoue (tentative {attempts + 1}/{MAX_ATTEMPTS}).\n"
        "Diagnostique la cause racine avant de modifier quoi que ce soit. Ne désactive aucun test.\n"
        "--- fin de sortie ---\n" + "\n".join(tail)
    )


if __name__ == "__main__":
    main()
