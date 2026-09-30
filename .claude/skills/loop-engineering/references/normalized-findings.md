# Format normalisé des findings

Tous les vérificateurs (tofu validate, tflint, Checkov, Trivy, Conftest, équivalence graphe/plan, Infracost, politiques de conception) produisent ce format. Implémentation de référence : `.claude/skills/secure-iac-generation/scripts/normalize_findings.py`.

```json
{
  "code": "CKV_AWS_20",
  "source": "checkov",
  "severity": "high",
  "resource": "aws_s3_bucket.logs",
  "file": "modules/storage/main.tf",
  "line": 12,
  "message": "S3 bucket autorise l'accès public en lecture"
}
```

- `severity` normalisée : `critical`, `high`, `medium`, `low`, `info`. Correspondances : tflint `error` vers high, `warning` vers medium, `notice` vers low ; Checkov sans gravité vers medium par défaut (à surcharger via la table de `policies/severity-overrides.yaml`) ; Trivy `CRITICAL/HIGH/MEDIUM/LOW` directement ; erreurs `tofu validate` vers critical (le code ne s'initialise pas).
- Implémentation Go de référence : `internal/loops/domain/findings.go` (M0-T13), tests dans `findings_test.go`.
- Gravité inconnue : poids 100, comme `critical` (échec prudent).
- Tri : ordre total (`domain.Sort`) : poids décroissant, puis gravité, fichier, ligne, code, ressource, source, message. `domain.Top(f, n)` rend les n premiers.
- Empreinte (`domain.Fingerprint`) : SHA-256 hexadécimal des couples (code, ressource) des findings de gravité supérieure ou égale à medium, triés, dédoublonnés, encodés chacun en deux netstrings (`<longueur>:<octets>,`) mis bout à bout. Liste vide : SHA-256 de la chaîne vide. Encodage figé : le modifier change toutes les empreintes et doit passer par `workflow.GetVersion` (M1).
- Score (`domain.Score`) : somme des poids, doublons compris : critical 100, high 20, medium 5, low 1, info 0.
