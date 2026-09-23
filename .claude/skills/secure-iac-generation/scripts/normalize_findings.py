#!/usr/bin/env python3
"""Normalise les sorties JSON des outils de validation IaC vers le format Rempart.

Usage : normalize_findings.py <dossier_sorties_brutes>
Fichiers lus s'ils existent : tofu-validate.json, tflint.json, checkov.json, trivy.json, conftest.json,
exceptions.json (liste de findings produits par le détecteur d'exceptions).
Écrit sur stdout : {"findings": [...], "fingerprint": "...", "score": N, "ok": bool}
"""
import hashlib
import json
import sys
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SCORE = {"critical": 100, "high": 20, "medium": 5, "low": 1, "info": 0}


def f(code, source, severity, resource="", file="", line=0, message=""):
    sev = (severity or "medium").lower()
    if sev not in SEV_ORDER:
        sev = "medium"
    return {"code": str(code), "source": source, "severity": sev, "resource": resource or "",
            "file": file or "", "line": int(line or 0), "message": (message or "").strip()[:500]}


def load(path: Path):
    if not path.exists() or path.stat().st_size == 0:
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def from_tofu(d):
    out = []
    for diag in (d or {}).get("diagnostics", []):
        if diag.get("severity") != "error":
            continue
        rng = diag.get("range") or {}
        out.append(f("TOFU_VALIDATE", "tofu", "critical", "", rng.get("filename"),
                     (rng.get("start") or {}).get("line"), f"{diag.get('summary', '')}: {diag.get('detail', '')}"))
    return out


def from_tflint(d):
    sevmap = {"error": "high", "warning": "medium", "notice": "low", "info": "low"}
    out = []
    for i in (d or {}).get("issues", []):
        rng = i.get("range") or {}
        rule = i.get("rule") or {}
        out.append(f(rule.get("name", "TFLINT"), "tflint", sevmap.get((rule.get("severity") or "").lower(), "medium"),
                     "", rng.get("filename"), (rng.get("start") or {}).get("line"), i.get("message")))
    for e in (d or {}).get("errors", []):
        out.append(f("TFLINT_ERROR", "tflint", "high", message=e.get("message")))
    return out


def from_checkov(d):
    reports = d if isinstance(d, list) else [d] if d else []
    out = []
    for r in reports:
        for c in ((r or {}).get("results") or {}).get("failed_checks", []):
            lines = c.get("file_line_range") or [0]
            out.append(f(c.get("check_id"), "checkov", c.get("severity") or "medium", c.get("resource"),
                         c.get("file_path"), lines[0], c.get("check_name")))
    return out


def from_trivy(d):
    out = []
    for res in (d or {}).get("Results", []) or []:
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status") == "PASS":
                continue
            cm = m.get("CauseMetadata") or {}
            out.append(f(m.get("AVDID") or m.get("ID"), "trivy", m.get("Severity"), cm.get("Resource"),
                         res.get("Target"), cm.get("StartLine"), f"{m.get('Title', '')}: {m.get('Message', '')}"))
    return out


def from_conftest(d):
    out = []
    for file_res in d or []:
        for kind, default_sev in (("failures", "high"), ("warnings", "low")):
            for x in file_res.get(kind, []) or []:
                meta = x.get("metadata") or {}
                out.append(f(meta.get("control_id", "CONFTEST"), "conftest", meta.get("severity", default_sev),
                             meta.get("resource", ""), file_res.get("filename"), 0, x.get("msg")))
    return out


def normalize(raw_dir: Path) -> dict:
    findings = []
    findings += from_tofu(load(raw_dir / "tofu-validate.json"))
    findings += from_tflint(load(raw_dir / "tflint.json"))
    findings += from_checkov(load(raw_dir / "checkov.json"))
    findings += from_trivy(load(raw_dir / "trivy.json"))
    findings += from_conftest(load(raw_dir / "conftest.json"))
    findings += load(raw_dir / "exceptions.json") or []
    findings.sort(key=lambda x: (SEV_ORDER[x["severity"]], x["file"], x["line"], x["code"]))
    significant = sorted({f"{x['code']}|{x['resource'] or x['file']}" for x in findings
                          if SEV_ORDER[x["severity"]] <= SEV_ORDER["medium"]})
    fp = hashlib.sha256("\n".join(significant).encode()).hexdigest() if significant else ""
    score = sum(SCORE[x["severity"]] for x in findings)
    return {"findings": findings, "fingerprint": fp, "score": score, "ok": not significant}


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    print(json.dumps(normalize(Path(sys.argv[1])), ensure_ascii=False, indent=2))
