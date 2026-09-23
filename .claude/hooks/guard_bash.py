#!/usr/bin/env python3
"""PreToolUse (Bash) : bloque les commandes dangereuses ou qui contournent le harnais."""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from _common import block, read_input  # noqa: E402

RULES = [
    (r"\b(tofu|terraform)\b[^|;&]*\b(apply|destroy)\b",
     "apply/destroy direct interdit. Utilise `make sandbox-apply` (approbation humaine requise)."),
    (r"\bgit\s+push\b[^|;&]*(--force|\s-f\b)", "push forcé interdit."),
    (r"\bgit\s+(commit|push)\b[^|;&]*--no-verify", "contournement des hooks git interdit."),
    (r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(/|~|\$HOME|\.\s*$|\*)", "suppression récursive dangereuse."),
    (r"\baws\b[^|;&]*\b(delete-|terminate-|remove-|deregister-)", "commande AWS destructive interdite depuis l'agent."),
    (r"\baz\b[^|;&]*\bdelete\b", "commande Azure destructive interdite depuis l'agent."),
    (r"\b(scw|ovhcloud)\b[^|;&]*\b(delete|terminate)\b", "commande cloud souverain destructive interdite."),
    (r"(>|>>|\btee\b|\bsed\s+-i|\bcp\b|\bmv\b|\brm\b|\bchmod\b|\btruncate\b)[^|;&]*(\.claude/(settings|hooks|bin|state|agents|commands)|CLAUDE\.md)",
     "modification du harnais interdite. Pour changer de phase : `python3 .claude/bin/rempart-state phase <tests|impl|free>`."),
    (r"\bgo\s+test\b[^|;&]*\s-skip\b", "exclusion de tests via -skip interdite dans le flux normal."),
    (r"\bmake\s+update-baseline\b", "la mise à jour des baselines d'eval se fait par une PR humaine explicite."),
]


def main() -> None:
    data = read_input()
    cmd = (data.get("tool_input") or {}).get("command", "")
    if re.match(r"^\s*python3\s+\.claude/bin/rempart-state\b", cmd):
        sys.exit(0)
    for pattern, reason in RULES:
        if re.search(pattern, cmd):
            block(f"BLOQUÉ : {reason}\nCommande : {cmd}")
    sys.exit(0)


if __name__ == "__main__":
    main()
