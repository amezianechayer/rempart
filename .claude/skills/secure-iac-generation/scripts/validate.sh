#!/usr/bin/env bash
# Chaîne de validation IaC de référence Rempart.
# Usage : validate.sh <dossier_iac> <dossier_sortie> [dossier_policies]
# Produit : <sortie>/raw/*.json, <sortie>/findings.json, <sortie>/fingerprint.txt, <sortie>/score.txt
# Code retour : 0 si aucun finding >= medium, 1 sinon, 2 si erreur d'usage.
set -uo pipefail

IAC="${1:?dossier IaC requis}"
OUT="${2:?dossier de sortie requis}"
POL="${3:-policies/iac}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RAW="$OUT/raw"
mkdir -p "$RAW"
IAC_ABS="$(cd "$IAC" && pwd)"

have() { command -v "$1" >/dev/null 2>&1; }

# 0. Exceptions interdites dans le code généré
python3 - "$IAC_ABS" > "$RAW/exceptions.json" << 'PY'
import json, re, sys, pathlib
root = pathlib.Path(sys.argv[1])
pat = re.compile(r"(checkov:skip|trivy:ignore|tflint-ignore|tfsec:ignore)")
out = []
for p in root.rglob("*.tf"):
    for i, line in enumerate(p.read_text(errors="ignore").splitlines(), 1):
        if pat.search(line):
            out.append({"code": "FORBIDDEN_EXCEPTION", "source": "rempart", "severity": "critical",
                        "resource": "", "file": str(p.relative_to(root)), "line": i,
                        "message": "exception de politique interdite dans le code généré"})
print(json.dumps(out))
PY

if have tofu; then
  ( cd "$IAC_ABS" && tofu fmt -check -recursive >/dev/null ) || \
    echo '[{"code":"TOFU_FMT","source":"tofu","severity":"low","resource":"","file":"","line":0,"message":"fichiers non formatés (tofu fmt)"}]' > "$RAW/fmt.json"
  ( cd "$IAC_ABS" && tofu init -backend=false -input=false >/dev/null 2>&1; tofu validate -json ) > "$RAW/tofu-validate.json" 2>/dev/null
fi
have tflint  && ( cd "$IAC_ABS" && tflint --init >/dev/null 2>&1; tflint --format json ) > "$RAW/tflint.json" 2>/dev/null
have checkov && checkov -d "$IAC_ABS" -o json --quiet > "$RAW/checkov.json" 2>/dev/null
have trivy   && trivy config --format json --quiet "$IAC_ABS" > "$RAW/trivy.json" 2>/dev/null
if have tofu && have conftest && [ -d "$POL" ] && [ -n "${REMPART_PLAN:-}" ]; then
  # Le plan est fourni par l'appelant (sandbox) : REMPART_PLAN=chemin du plan binaire
  ( cd "$IAC_ABS" && tofu show -json "$REMPART_PLAN" ) > "$RAW/plan.json" 2>/dev/null
  conftest test --output json -p "$POL" "$RAW/plan.json" > "$RAW/conftest.json" 2>/dev/null
fi

python3 "$HERE/normalize_findings.py" "$RAW" > "$OUT/result.json"
python3 - "$OUT" << 'PY'
import json, sys, pathlib
out = pathlib.Path(sys.argv[1])
r = json.loads((out / "result.json").read_text())
fmt = out / "raw" / "fmt.json"
if fmt.exists():
    r["findings"] += json.loads(fmt.read_text())
(out / "findings.json").write_text(json.dumps(r["findings"], ensure_ascii=False, indent=2))
(out / "fingerprint.txt").write_text(r["fingerprint"] + "\n")
(out / "score.txt").write_text(str(r["score"]) + "\n")
print(f"findings={len(r['findings'])} score={r['score']} ok={r['ok']}")
sys.exit(0 if r["ok"] else 1)
PY
