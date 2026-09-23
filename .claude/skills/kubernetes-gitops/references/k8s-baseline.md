# Socle de durcissement Kubernetes

| Contrôle | Niveau | Politique (`policies/k8s/`) | Source d'inspiration à vérifier |
|---|---|---|---|
| API du cluster non publique ou restreinte | cluster | K8S-001 | CIS Kubernetes / CIS EKS / CIS AKS |
| Journal d'audit du plan de contrôle activé | cluster | K8S-002 | CIS |
| Chiffrement des Secrets au repos (KMS) | cluster | K8S-003 | CIS |
| Pas de conteneur privilégié | admission | K8S-010 | Pod Security Standards (restricted) |
| Pas de hostPath, hostNetwork, hostPID | admission | K8S-011 | Pod Security Standards |
| runAsNonRoot, pas d'élévation de privilèges | admission | K8S-012 | Pod Security Standards |
| Images depuis registres autorisés, signées | admission | K8S-013 | Supply chain (Sigstore) |
| Requests et limits définies | admission | K8S-014 | Bonnes pratiques |
| NetworkPolicy deny par défaut par namespace | namespace | K8S-020 | Bonnes pratiques |
| Aucun ClusterRoleBinding vers cluster-admin hors système | RBAC | K8S-030 | CIS |
| Pas de clé cloud dans les Secrets (identités de workload) | workload | K8S-040 | Rempart |
| ArgoCD : projets restreints, pas de dépôt source joker | GitOps | K8S-050 | Rempart |

Le mode `enforce` des politiques d'admission est activé après une période `audit` configurable, pour ne pas casser un cluster existant lors de l'onboarding.
