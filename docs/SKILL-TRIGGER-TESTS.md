# Tests de déclenchement des skills

Les skills ne servent que s'ils se déclenchent au bon moment. Après installation, vérifie dans Claude Code que chaque prompt « doit déclencher » charge bien le skill (visible dans la trace), et que les prompts « ne doit pas » ne le chargent pas. En cas d'écart, améliore la `description` du skill (le skill `skill-creator` d'Anthropic propose une boucle d'optimisation des descriptions via `claude -p`).

| Skill | Doit déclencher | Ne doit pas déclencher |
|---|---|---|
| loop-engineering | « Ajoute la détection de stagnation au workflow L3 » | « Renomme cette variable dans le handler HTTP » |
| intent-to-spec | « Le schéma d'intention doit accepter les bases managées » | « Écris la règle Rego sur les buckets publics » |
| multicloud-networking | « Ajoute un sous-réseau data dans le VPC de prod » | « Corrige le test du rédacteur de secrets » |
| secure-iac-generation | « Le module EKS doit activer le chiffrement des secrets » | « Rédige le guide d'entretien client » |
| policy-as-code | « Crée une règle qui interdit SSH depuis Internet » | « Ajoute un endpoint de santé à l'API » |
| security-graph-attack-paths | « Détecte les chemins pod vers rôle IAM administrateur » | « Formate le README » |
| safe-autonomy | « Un changement IAM en prod doit exiger deux approbateurs » | « Ajoute un tag au module réseau » |
| compliance-evidence | « Ajoute l'attestation du runner au dossier de preuves » | « Optimise la requête SQL d'inventaire » |
| go-platform-conventions | « Implémente le collecteur Azure » | « Mets à jour le guide de découverte marché » |
| agent-evals | « J'ai changé le prompt de L1, vérifie qu'on ne régresse pas » | « Corrige une faute dans un ADR » |
| llm-safety | « Le résumé des findings doit inclure les tags des ressources » | « Ajoute un index PostgreSQL » |
| kubernetes-gitops | « Déploie la stack d'observabilité via ArgoCD » | « Écris le module VPN Azure » |
| secrets-and-identity | « Écris le modèle d'onboarding AWS pour un nouveau client » | « Ajoute une métrique Prometheus de durée de boucle » |
| product-interface | « Ajoute le récapitulatif d'approbation sur l'écran de revue » | « Corrige le calcul des permissions effectives Azure » |
