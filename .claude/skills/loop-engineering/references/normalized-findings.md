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
- Tri : gravité décroissante, puis fichier, puis ligne.
- Empreinte : SHA-256 de la liste triée des couples `code|resource`, calculée sur les findings de gravité supérieure ou égale à medium.
- Score : critical 100, high 20, medium 5, low 1, info 0.
