#!/usr/bin/env python3
"""Stop : Claude ne peut pas terminer son tour avec un arbre de travail qui ne passe pas la vérification.

- Phase tests : les nouveaux tests échouent par construction ; on exige seulement que le code de
  production compile (`go build ./...`), pour pouvoir s'arrêter et faire relire les tests.
- Autres phases : `make verify-quick`.
- Si rien n'a changé depuis la dernière vérification verte du même type : on laisse passer.
- Rouge : exit 2, Claude reçoit les erreurs et doit continuer. Un outil absent (make, go) compte comme un échec.
- Coupe-circuit anti-boucle : après MAX_ATTEMPTS échecs consécutifs, on laisse Claude s'arrêter
  mais on consigne un BLOCAGE dans docs/STATUS.md pour l'humain.
"""
import datetime as dt
import hashlib
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import PROJECT_DIR, block, read_input, set_state, state  # noqa: E402

MAX_ATTEMPTS = 3
TARGET = "verify-quick"
# T32 : variables héritées qui remplacent la commande des sous-make, le fichier lu ou les options
# de make, ou qui injectent du code dans bash (SHELL := /bin/bash).
ENV_STRIP = ("MAKE", "MAKE_COMMAND", "MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKEFILES",
             "MAKELEVEL", "MAKEOVERRIDES", "BASH_ENV", "ENV")


def clean_env() -> dict:
    return {k: v for k, v in os.environ.items() if k not in ENV_STRIP and not k.startswith("BASH_FUNC_")}


def sh(cmd, timeout=60):
    try:
        p = subprocess.run(cmd, cwd=PROJECT_DIR, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout, env=clean_env())
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"commande introuvable : {cmd[0]}"


def worktree_fingerprint() -> str:
    h = hashlib.sha256()
    _, diff, _ = sh(["git", "diff", "HEAD", "--", ".", ":(exclude).claude/state"])
    h.update(diff.encode())
    _, untracked, _ = sh(["git", "ls-files", "--others", "--exclude-standard"])
    for f in sorted(untracked.splitlines()):
        if not f or f.startswith(".claude/state"):
            continue
        h.update(f.encode())
        try:
            h.update((PROJECT_DIR / f).read_bytes())
        except OSError:
            pass
    return h.hexdigest()


def has_target() -> bool:
    mk = PROJECT_DIR / "Makefile"
    return mk.exists() and f"\n{TARGET}:" in "\n" + mk.read_text(encoding="utf-8")


def check_plan():
    """Renvoie (commande, libellé, clé d'état) selon la phase, ou None s'il n'y a rien à vérifier."""
    if state("phase", "free") == "tests":
        if (PROJECT_DIR / "go.mod").exists():
            return ["go", "build", "./..."], "go build ./... (phase tests)", "last_compiled"
        return None
    if has_target():
        # T32 : -f Makefile, un GNUmakefile ou makefile ne remplace jamais le Makefile relu ; -r, aucune
        # règle implicite intégrée ne refait le Makefile à partir d'un fichier voisin (Makefile.sh, RCS).
        return ["make", "-r", "-f", "Makefile", TARGET], f"make -r -f Makefile {TARGET}", "last_verified"
    return None


def log_blocked(label: str, summary: str) -> None:
    status = PROJECT_DIR / "docs" / "STATUS.md"
    status.parent.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    with status.open("a", encoding="utf-8") as f:
        f.write(f"\n- {stamp} BLOCAGE : `{label}` rouge après {MAX_ATTEMPTS} tentatives. "
                f"Intervention humaine requise. Dernière erreur : {summary}\n")


def main() -> None:
    data = read_input()
    rc, _, _ = sh(["git", "rev-parse", "--is-inside-work-tree"])
    plan = check_plan()
    if rc != 0 or plan is None:
        sys.exit(0)
    cmd, label, key = plan

    fp = worktree_fingerprint()
    if fp == state(key):
        set_state("stop_attempts", "0")
        sys.exit(0)

    attempts = int(state("stop_attempts", "0") or 0)
    if data.get("stop_hook_active") and attempts >= MAX_ATTEMPTS:
        log_blocked(label, "voir la sortie de la dernière exécution")
        set_state("stop_attempts", "0")
        sys.exit(0)

    try:
        rc, out, err = sh(cmd, timeout=840)
    except subprocess.TimeoutExpired:
        rc, out, err = 1, "", f"{label} a dépassé le délai."

    if rc == 0:
        set_state(key, fp)
        set_state("stop_attempts", "0")
        sys.exit(0)

    set_state("stop_attempts", str(attempts + 1))
    tail = (out + "\n" + err).strip().splitlines()[-80:]
    block(
        f"Tu ne peux pas terminer : `{label}` échoue (tentative {attempts + 1}/{MAX_ATTEMPTS}).\n"
        "Diagnostique la cause racine avant de modifier quoi que ce soit. Ne désactive aucun test.\n"
        "--- fin de sortie ---\n" + "\n".join(tail)
    )


if __name__ == "__main__":
    main()
