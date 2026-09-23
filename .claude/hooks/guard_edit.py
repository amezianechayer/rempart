#!/usr/bin/env python3
"""PreToolUse (Edit|Write|MultiEdit).

1. Protège le harnais (.claude/settings.json, hooks, bin, state) contre toute modification par l'agent.
2. Applique la discipline TDD selon la phase courante :
   - phase "tests" : seuls les tests, fixtures, evals et docs sont modifiables ;
   - phase "impl"  : les tests, cas d'eval et baselines sont gelés ;
   - phase "free"  : aucune restriction TDD (bootstrap, docs).
3. Bloque l'écriture de secrets en clair.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import block, read_input, rel, state  # noqa: E402

PROTECTED = re.compile(r"^(CLAUDE\.md$|\.claude/(settings\.json|settings\.local\.json|hooks/|bin/|state/|agents/|commands/))")
TEST_FILE = re.compile(
    r"(_test\.go$|_test\.rego$|/testdata/|^evals/.*/(cases|graders)/|^evals/.*/baseline\.json$|"
    r"^modules/.*/tests?/|\.tftest\.hcl$|^evals/security/lab/)"
)
DOC_FILE = re.compile(r"(^docs/|\.md$)")
SOURCE_FILE = re.compile(r"^(internal|cmd|pkg|policies|modules|web/src)/")

SECRET_PATTERNS = [
    (re.compile(r"AKIA[0-9A-Z]{16}"), "clé d'accès AWS"),
    (re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"), "clé privée"),
    (re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"), "secret AWS"),
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "jeton GitHub"),
    (re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"), "jeton GitLab"),
    (re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"), "clé API Anthropic"),
    (re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"), "jeton Slack"),
]
ALLOWED_FAKE = re.compile(r"(EXAMPLE|FAKE|DUMMY|PLACEHOLDER)")


def new_content(tool: str, ti: dict) -> str:
    if tool == "Write":
        return ti.get("content", "")
    if tool == "Edit":
        return ti.get("new_string", "")
    if tool == "MultiEdit":
        return "\n".join(e.get("new_string", "") for e in ti.get("edits", []))
    return ""


def main() -> None:
    data = read_input()
    tool = data.get("tool_name", "")
    ti = data.get("tool_input", {}) or {}
    path = rel(ti.get("file_path", ""))
    content = new_content(tool, ti)

    if PROTECTED.search(path):
        block(
            f"BLOQUÉ : {path} fait partie du harnais Rempart et ne peut pas être modifié par l'agent. "
            "Si un changement du harnais est nécessaire, explique pourquoi à l'humain et propose le diff."
        )

    for pattern, label in SECRET_PATTERNS:
        for m in pattern.finditer(content):
            window = content[max(0, m.start() - 40): m.end() + 40]
            if not ALLOWED_FAKE.search(window):
                block(
                    f"BLOQUÉ : {label} détecté dans {path}. Aucun secret en clair dans le repo. "
                    "Utilise une référence au gestionnaire de secrets, ou une valeur marquée EXAMPLE/FAKE dans testdata."
                )

    phase = state("phase", "free")
    is_test = bool(TEST_FILE.search(path))
    is_doc = bool(DOC_FILE.search(path))

    if phase == "impl":
        if is_test:
            block(
                f"BLOQUÉ (phase impl) : {path} est un test, un cas d'eval ou une baseline, gelés pendant l'implémentation. "
                "Si un test est faux, arrête-toi, explique pourquoi, et repasse en phase tests avec "
                "`python3 .claude/bin/rempart-state phase tests` (le changement sera tracé dans STATUS.md)."
            )
        if re.search(r"\bt\.Skip\(|\bt\.SkipNow\(", content):
            block("BLOQUÉ : ajout de t.Skip interdit en phase impl. Un test qui échoue se corrige, il ne se désactive pas.")
    elif phase == "tests":
        if SOURCE_FILE.search(path) and not is_test and not is_doc:
            block(
                f"BLOQUÉ (phase tests) : {path} est du code de production. En phase tests, écris uniquement "
                "les tests, fixtures et cas d'eval, puis vérifie qu'ils échouent pour la bonne raison. "
                "Passe ensuite en phase impl avec `python3 .claude/bin/rempart-state phase impl`."
            )

    sys.exit(0)


if __name__ == "__main__":
    main()
