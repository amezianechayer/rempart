# Motifs de rédaction (chaque ligne = au moins un cas de test)

- Clés d'accès AWS (`AKIA...`, `ASIA...`) et secrets associés
- Jetons de session AWS
- Secrets de service principal Azure, chaînes de connexion Azure Storage (`AccountKey=`), SAS tokens (`sig=`)
- Clés API Scaleway et identifiants OVHcloud (application key/secret, consumer key)
- Clés privées PEM (RSA, EC, OpenSSH), certificats avec clé
- Jetons GitHub (`ghp_`, `github_pat_`), GitLab (`glpat-`), Slack (`xox?-`)
- Clés API LLM (`sk-ant-`, `sk-`)
- Mots de passe dans des URL (`scheme://user:pass@host`)
- Chaînes de connexion de bases (`postgres://`, `mysql://`, `mongodb+srv://` avec identifiants)
- Kubeconfig (champs `client-key-data`, `token`)
- Valeurs de variables nommées `*password*`, `*secret*`, `*token*`, `*api_key*` dans des manifestes ou tfvars
- Clés pré-partagées IPsec
