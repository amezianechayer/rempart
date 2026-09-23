---
name: kubernetes-gitops
description: Sécurité Kubernetes et GitOps pour Rempart, comme cible gérée (EKS, AKS, Kapsule, OVHcloud MKS) et comme plateforme d'hébergement de Rempart (durcissement du cluster, RBAC, politiques d'admission, NetworkPolicy, identités de workload, ArgoCD, graphe K8s). À utiliser pour tout module ou politique touchant Kubernetes, ArgoCD, Helm, manifestes, ou le collecteur Kubernetes.
---

# Kubernetes et GitOps

## Référence
Socle de durcissement et correspondance avec les politiques : `references/k8s-baseline.md`

## Principes
- **Deux couches GitOps distinctes** : OpenTofu gère l'infrastructure (cluster, réseau, identités cloud) ; ArgoCD gère ce qui tourne dans le cluster (add-ons, observabilité, applications). Rempart génère les deux et ne mélange pas les responsabilités.
- ArgoCD en motif « app of apps » ou ApplicationSet, projets ArgoCD restreints par namespace et par dépôt source, synchronisation automatique uniquement pour les environnements non production par défaut.
- API du cluster privée par défaut ; si publique, restreinte à des plages explicites de l'IR.
- **Identités de workload** (IRSA ou EKS Pod Identity, Azure Workload Identity) : jamais de clé cloud dans un Secret Kubernetes.
- Politiques d'admission (Kyverno ou Gatekeeper, à trancher par ADR) appliquant le socle : pas de conteneur privilégié, pas de hostPath, pas de hostNetwork, utilisateur non root, images signées depuis des registres autorisés, limites de ressources.
- NetworkPolicy deny par défaut par namespace, ouvertures explicites dérivées du graphe.
- Secrets applicatifs via OpenBao (injecteur ou External Secrets Operator), jamais en clair dans Git.

## Dans le graphe de sécurité
Nœuds K8sCluster, K8sNamespace, K8sWorkload, service accounts ; arêtes RUNS_AS vers l'identité cloud liée. Chemins d'élévation à couvrir : pod compromis vers service account vers identité cloud privilégiée ; droits RBAC permettant de créer des pods privilégiés ; accès à des Secrets d'autres namespaces.
