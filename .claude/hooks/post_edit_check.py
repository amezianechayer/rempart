#!/usr/bin/env python3
"""PostToolUse (Edit|Write|MultiEdit) : retour immédiat pendant que le contexte est frais.

Formate le fichier puis lance une vérification rapide propre au langage.
En cas d'erreur, exit 2 : le message est renvoyé à Claude pour correction immédiate.
Les outils absents sont ignorés (bootstrap).
En phase tests, un test Go peut appeler du code pas encore écrit : on n'y vérifie que la syntaxe, pas `go vet`.
Un fichier hors du dépôt n'est ni formaté ni vérifié : `go vet ./<chemin absolu>` échouerait depuis le dépôt.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import PROJECT_DIR, block, read_input, rel, state  # noqa: E402


def run(cmd, timeout=90):
    try:
        p = subprocess.run(cmd, cwd=PROJECT_DIR, capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout)
        return p.returncode, (p.stdout + p.stderr).strip()
    except subprocess.TimeoutExpired:
        return 0, ""  # une vérification lente ne doit pas bloquer l'édition ; le Stop hook rattrapera


def main() -> None:
    data = read_input()
    path = (data.get("tool_input") or {}).get("file_path", "")
    if not path or not Path(path).exists():
        sys.exit(0)
    try:
        Path(path).resolve().relative_to(PROJECT_DIR.resolve())
    except ValueError:
        sys.exit(0)  # hors du dépôt (copie de vérification, scratchpad) : ni formatage ni vérification
    r = rel(path)
    ext = Path(path).suffix

    if ext == ".go" and shutil.which("gofmt"):
        code, out = run(["gofmt", "-e", "-w", path])
        if code != 0:
            block(f"Erreur de syntaxe Go dans {r} :\n{out[-3000:]}")
        test_in_tests_phase = r.endswith("_test.go") and state("phase", "free") == "tests"
        if shutil.which("go") and not test_in_tests_phase:
            pkg = "./" + Path(r).parent.as_posix()
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
            json.loads(Path(path).read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            block(f"JSON invalide dans {r} : {e}")

    sys.exit(0)


if __name__ == "__main__":
    main()
