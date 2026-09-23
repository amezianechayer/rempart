# Permissions effectives

> Résumé de conception. La logique officielle de chaque fournisseur fait foi : la relire dans la documentation AWS (« policy evaluation logic ») et Microsoft (Azure RBAC, deny assignments) avant d'implémenter, et construire le corpus de tests à partir de leurs exemples.

## AWS : ordre de raisonnement pour une requête (principal, action, ressource)
1. **Deny explicite** dans n'importe quelle politique applicable : refus.
2. Garde-fous d'organisation : **SCP** (sur le principal) et **RCP** (sur la ressource) doivent autoriser, sinon refus.
3. Politiques basées sur la ressource : peuvent accorder l'accès (avec des subtilités selon principal de même compte ou autre compte).
4. Politiques d'identité : doivent autoriser (en même compte, une autorisation par politique d'identité ou de ressource suffit généralement ; en inter-comptes, il faut les deux côtés).
5. **Permission boundary** : plafond des politiques d'identité.
6. **Session policy** (rôles assumés avec politique de session) : plafond supplémentaire.
7. Sinon : refus implicite.
Conditions : résoudre ce qui est statiquement déterminable (tags, `aws:SourceVpc`, etc.) ; ce qui ne l'est pas marque la permission `ambiguous`.

## Azure
1. Attributions de rôle aux portées groupe d'administration, abonnement, groupe de ressources, ressource ; **héritage** vers le bas.
2. Distinguer `actions` (plan de contrôle) et `dataActions` (plan de données), et leurs `notActions`/`notDataActions`.
3. **Deny assignments** : priment sur les attributions.
4. Conditions (ABAC) sur certaines attributions : évaluer si déterminable, sinon `ambiguous`.
5. Rôles Entra ID : à relier pour les chemins d'élévation (ex. administrateur d'application pouvant ajouter un secret à un service principal privilégié).

## Chemins d'élévation à couvrir en priorité
Passage de rôle (`iam:PassRole` + création de calcul), création de clés d'accès pour un autre utilisateur, modification de politiques attachées, ajout d'identifiants à un service principal, identité managée attachée à une VM accessible, service account Kubernetes lié à une identité cloud privilégiée.

## Corpus de tests
`internal/graph/permissions/testdata/` : un cas par règle ci-dessus et par chemin d'élévation, avec résultat attendu (`allow`, `deny`, `ambiguous`). 100 % des cas doivent passer (critère M5).
