#!/usr/bin/env python3
"""PostToolUse (Edit|Write|MultiEdit) : retour immédiat pendant que le contexte est frais.

Formate le fichier puis lance une vérification rapide propre au langage.
En cas d'erreur, exit 2 : le message est renvoyé à Claude pour correction immédiate.
Les outils absents sont ignorés (bootstrap).
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import PROJECT_DIR, block, read_input, rel  # noqa: E402


def run(cmd, timeout=90):
    try:
        p = subprocess.run(cmd, cwd=PROJECT_DIR, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return 0, ""  # une vérification lente ne doit pas bloquer l'édition ; le Stop hook rattrapera


def main() -> None:
    data = read_input()
    path = (data.get("tool_input") or {}).get("file_path", "")
    if not path or not Path(path).exists():
        sys.exit(0)
    r = rel(path)
    ext = Path(path).suffix

    if ext == ".go" and shutil.which("gofmt"):
        run(["gofmt", "-w", path])
        if shutil.which("go"):
            pkg = "./" + str(Path(r).parent)
            code, out = run(["go", "vet", pkg])
            if code != 0:
                block(f"go vet échoue après modification de {r} :\n{out[-3000:]}")

    elif ext == ".rego" and shutil.which("opa"):
        run(["opa", "fmt", "-w", path])
        code, out = run(["opa", "check", path])
        if code != 0:
            block(f"opa check échoue sur {r} :\n{out[-3000:]}")

    elif ext in (".tf", ".tfvars") and shutil.which("tofu"):
        run(["tofu", "fmt", path])

    elif ext == ".json" and (r.startswith("schemas/") or "/references/" in r):
        try:
            json.loads(Path(path).read_text())
        except Exception as e:  # noqa: BLE001
            block(f"JSON invalide dans {r} : {e}")

    sys.exit(0)


if __name__ == "__main__":
    main()
