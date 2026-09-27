#!/usr/bin/env python3
"""PreToolUse (Bash) : bloque les commandes dangereuses ou qui contournent le harnais.

Ce filtre relève le niveau d'exigence mais n'est pas un bac à sable : les filets restent le journal,
les subagents indépendants, la CI et la revue humaine.
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import block, read_input  # noqa: E402

# Seule exemption : un appel direct à rempart-state, sans enchaînement, redirection ni substitution.
STATE_CMD = re.compile(r"^\s*(python3?|py)\s+\.claude/bin/rempart-state(\s|$)")
SHELL_META = re.compile(r"[;&|<>`$\n\r]")

HARNESS_PATH = re.compile(r"(\.claude/(settings|hooks|bin|state|agents|commands)\b|\bclaude\.md\b)", re.I)
# T58, T63 : baselines, suites et cas d'eval ne s'écrivent jamais par commande ; l'outil d'édition reste gardé par phase.
EVAL_DATA_PATH = re.compile(r"evals/\S*(baseline|suite\.yaml|/cases/)", re.I)
HARMLESS_REDIRECT = re.compile(r"\d?>>?\s*/dev/null|\d>&\d")
WRITERS = re.compile(
    r"(>|\btee\b|\bsed\s+(-\S*\s+)*-\S*i|\bperl\s+-\S*i|\bcp\b|\bmv\b|\brm\b|\bln\b|\bchmod\b|\btruncate\b|"
    r"\binstall\b|\bdd\b|\brsync\b|\bgit\s+(checkout|restore|apply|stash|reset)\b|\bopen\(|\bwrite_text\(|"
    r"\bwriteFile|\bSet-Content\b|\bOut-File\b|\bNew-Item\b|\bRemove-Item\b)"
)

RULES = [
    (r"\b(tofu|terraform)\b[^|;&]*\b(apply|destroy)\b",
     "apply/destroy direct interdit. Utilise `make sandbox-apply` (approbation humaine requise)."),
    (r"\bgit\s+push\b[^|;&]*(--force|\s-f\b|\s\+\S)", "push forcé interdit (y compris la forme +refspec)."),
    (r"\bgit\s+(commit|push)\b[^|;&]*--no-verify", "contournement des hooks git interdit."),
    (r"\bgit\s+commit\b[^|;&]*\s-[a-zA-Z]*n[a-zA-Z]*(\s|$)", "contournement des hooks git interdit (git commit -n)."),
    (r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(/|~|\$HOME|\.\s*$|\./?\*|\./?\s*$|\.git\b)", "suppression récursive dangereuse."),
    (r"\baws\b[^|;&]*\b(delete-|terminate-|remove-|deregister-)", "commande AWS destructive interdite depuis l'agent."),
    (r"\baz\b[^|;&]*\bdelete\b", "commande Azure destructive interdite depuis l'agent."),
    (r"\b(scw|ovhcloud)\b[^|;&]*\b(delete|terminate)\b", "commande cloud souverain destructive interdite."),
    (r"\bgo\s+test\b[^|;&]*\s-skip\b", "exclusion de tests via -skip interdite dans le flux normal."),
    # T63 : le paquet flag de Go accepte un ou deux tirets.
    (r"\bg?make\b[^|;&]*\bupdate-baseline\b|(^|\s)-{1,2}write-baseline\b",
     "la mise à jour des baselines d'eval se fait par une PR humaine explicite."),
    # T28 : make développe $(...) et ${...} dans une variable passée en ligne de commande.
    (r"\bg?make\b[^|;&]*\$[({]",
     "argument de make contenant $( ou ${ : make le développerait avant toute garde (T28). "
     "Passe une valeur littérale, validée par la recette."),
    # T29 : seule la forme canonique, couverte par la permission « ask », atteint le bac à sable.
    (r"^(?!\s*make\s+sandbox-(apply|destroy)\s+SCENARIO=[a-z0-9][a-z0-9-]{0,62}\s*$)[\s\S]*"
     r"(\bg?make\b[^|;&]*\bsandbox-(apply|destroy)\b|\bsandbox\.sh\b[^|;&]*\b(apply|destroy)\b)",
     "bac à sable : seule la forme `make sandbox-apply SCENARIO=<nom>` (ou sandbox-destroy), seule sur la ligne, "
     "est permise ; elle demande l'approbation humaine (T29)."),
    # T31 et T32 : options et variables qui changent le fichier lu par make ou ignorent les échecs de recette.
    (r"\b(MAKEFLAGS|MAKEFILES|GNUMAKEFLAGS)\s*=|\bg?make\b[^|;&]*\s(-[a-zA-Z]*[if][a-zA-Z]*|--ignore-errors|--eval|--file|--makefile)\b",
     "make : -i, -f, --eval, MAKEFLAGS et MAKEFILES interdits ; ils ignorent les échecs de recette ou changent "
     "le fichier exécuté (T31, T32)."),
]


def touches_harness(cmd: str) -> bool:
    """Vrai si la commande mentionne un chemin du harnais ET contient une opération d'écriture, dans n'importe quel ordre."""
    if not HARNESS_PATH.search(cmd):
        return False
    return bool(WRITERS.search(HARMLESS_REDIRECT.sub(" ", cmd)))


def main() -> None:
    data = read_input(fail_closed=True)
    cmd = (data.get("tool_input") or {}).get("command", "")
    norm = re.sub(r"/+", "/", cmd.replace("\\", "/"))  # chemins Windows, antislashs doublés compris
    if STATE_CMD.match(norm) and not SHELL_META.search(norm):
        sys.exit(0)
    for pattern, reason in RULES:
        if re.search(pattern, norm):
            block(f"BLOQUÉ : {reason}\nCommande : {cmd}")
    if touches_harness(norm):
        block(
            "BLOQUÉ : modification du harnais interdite. Pour changer de phase : "
            f"`python3 .claude/bin/rempart-state phase <tests|impl|free>`.\nCommande : {cmd}"
        )
    if EVAL_DATA_PATH.search(norm) and WRITERS.search(HARMLESS_REDIRECT.sub(" ", norm)):
        block("BLOQUÉ : écriture par commande dans les baselines, suites ou cas d'eval interdite (T58, T63) ; "
              f"utilise l'outil d'édition, gardé par phase.\nCommande : {cmd}")
    sys.exit(0)


if __name__ == "__main__":
    main()
