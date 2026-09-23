# Contrat d'un module interne

Tout module de `modules/` respecte ce contrat. Le subagent `security-reviewer` le vérifie.

## Structure
```
modules/<cloud>-<fonction>/
  main.tf  variables.tf  outputs.tf  versions.tf
  README.md            # objectif, entrées, sorties, garanties de sécurité, exemple
  examples/basic/      # exemple minimal déployable en sandbox
  tests/               # tofu test (*.tftest.hcl) ou Terratest
  SECURITY.md          # garanties, contrôles couverts (control_id), limites connues
```

## Garanties par défaut (non désactivables sans override humain tracé)
- Chiffrement au repos et en transit activé, clés gérées (KMS/Key Vault) quand le service le permet.
- Journalisation activée (flow logs, journaux d'accès, audit du plan de contrôle K8s).
- Aucune exposition publique : les variables d'exposition valent `false` par défaut.
- Tags/labels obligatoires : `rempart_tenant`, `rempart_env`, `rempart_owner`, `rempart_change_id`, `rempart_module`.
- IAM : aucune action `*` ni ressource `*` sauf exception documentée dans SECURITY.md.

## Variables
- Typées, avec blocs `validation` (formats, plages, énumérations).
- Pas de défaut dangereux. Les secrets arrivent par référence (chemin OpenBao, ARN de secret), jamais par valeur.

## Versions
- `required_version` et `required_providers` épinglés.
- Module versionné (tag sémantique) ; la génération référence une version exacte.

## Tests
- Au moins : un test de plan qui vérifie les garanties (chiffrement, pas d'IP publique, tags), un test d'échec de validation d'entrée.
- `scripts/validate.sh` sur `examples/basic` sans finding `medium` ou plus.
