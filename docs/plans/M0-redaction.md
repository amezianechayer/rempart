# M0-T07 `redaction` : rédacteur de secrets (critère 3, première moitié)

- Date : 2026-09-23
- Auteur : subagent `architect`
- Statut : proposé à l'agent principal
- Fiche d'origine : `docs/plans/M0-overview.md` section 7 (M0-T07). Ce plan ne l'élargit pas ; les précisions sont listées en section 2.3.
- Décision structurante : **pas d'ADR**. La grammaire de détection, l'ordre de priorité et les exemptions sont internes à un paquet sans consommateur à ce jour, sans format persisté autre que le texte `[REDACTED:<kind>]` déjà fixé par la fiche, et réversibles en une tâche. Elles deviennent coûteuses à changer quand T11 et T12 les utiliseront : c'est l'objet des contraintes de la section 5.9.
- Sources lues : `docs/plans/M0-overview.md` (sections 0, 2.2, 5.1, 5.2, fiches T07, T11, T12, tableaux 8.1, 10, 11) ; `prompts/M0.md` (critères 3 et 8) ; `docs/plans/M0-secret-value.md` et `docs/plans/M0-tenancy.md` (format, contraintes du harnais non patché) ; `docs/02-THREAT-MODEL.md` (T7, T10, T30, T36) ; skill `llm-safety` et `references/redaction-patterns.md` ; `.claude/hooks/{guard_edit.py,post_edit_check.py,_common.py}` ; `.claude/bin/rempart-state` ; `internal/archtest/rules.go` ; `.golangci.yml` ; `go.mod` ; `Makefile` ; `docs/STATUS.md`.
- État de départ : M0-T01, T02, T05 et T06 faites. `internal/llm/` ne contient que `doc.go` (suivi) ; `internal/llm/redact/` **n'existe pas**. Go 1.27.1, golangci-lint v2.13.2 (gosec actif, `nosec` neutralisé, aucun `nolint` dans le dépôt : critère 8 de M0-T01, menace T30), `pgregory.net/rapid v1.3.0` en dépendance directe. Harnais **non patché**.

---

## 0. Amendement V1 (vérification 7.8 par `test-author`, 2026-09-24, prime sur le reste du document)

Sur une copie contenant le code de référence des sections 5.1 et 5.2, les propriétés `rapid` (potage à 100 000 cas) et une exploration aléatoire de 3 millions d'entrées ont trouvé **454 contre-exemples** distincts, dont deux **fuites réelles** :
- S1 : `skip` ignorait une clé imbriquée même quand sa valeur sortait de la valeur externe (`password: a?api_key: FAKErealsecret` laissait la fin en clair) ;
- S2 : `FindAll` consommait l'espace après le séparateur, qui servait de préfixe à la clé suivante (`password: password: FAKEhunter2` laissait `FAKEhunter2` en clair) ;
- D1, D2 : non-idempotences (userinfo d'URL qui avale `[`, `:` et `]` d'un placeholder ; union qui se termine au milieu d'une valeur, relue en seconde passe) ;
- J : textes rédigés qui redevenaient positifs une fois encodés en JSON (guillemets simples ou échappés contenant une barre oblique inverse, tabulation échappée dans `Authorization`) ;
- gosec G101 sur `KindOVHCredential` et `KindLLMAPIKey` (repli prévu en section 5.2 : conversion `Kind("...")`).

Correctif retenu (validé sur copie : 4 fichiers de test identiques à ceux du dépôt, `golangci-lint` 0 issue, potage à 100 000 cas sur 7 graines dont les deux fautives, 3 millions d'entrées sans échec, `-race`, entrées adverses entre 0,23 et 0,47 s). Il **remplace** le code des sections 5.1 et 5.2 aux lignes indiquées :

```diff
--- r/internal/llm/redact/redact.go	2026-09-24 00:00:16.305652406 +0000
+++ amendC/internal/llm/redact/redact.go	2026-09-24 00:33:30.427932234 +0000
@@ -23,12 +23,12 @@
 	KindAWSSessionToken Kind = "aws_session_token"
 	KindAzureSecret     Kind = "azure_secret"
 	KindScalewayKey     Kind = "scaleway_key"
-	KindOVHCredential   Kind = "ovh_credential"
+	KindOVHCredential   Kind = Kind("ovh_credential")
 	KindPrivateKey      Kind = "private_key"
 	KindGitHubToken     Kind = "github_token"
 	KindGitLabToken     Kind = "gitlab_token"
 	KindSlackToken      Kind = "slack_token"
-	KindLLMAPIKey       Kind = "llm_api_key"
+	KindLLMAPIKey       Kind = Kind("llm_api_key")
 	KindURLCredentials  Kind = "url_credentials"
 	KindDBConnString    Kind = "db_connection_string"
 	KindKubeconfig      Kind = "kubeconfig_credential"
@@ -92,14 +92,14 @@
 	return b.String(), ms
 }
 
-// find evaluates every rule on s, drops candidates that lie inside existing
+// find evaluates every rule on s, drops candidates that start inside existing
 // placeholders, and merges the rest.
 func find(s string) []Match {
 	protected := placeholderRe.FindAllStringIndex(s, -1)
 	var cs []candidate
 	for prio, ru := range rules {
-		for _, c := range ru.candidates(s) {
-			if c.end <= c.start || covered(protected, c.start, c.end) {
+		for _, c := range ru.candidates(s, protected) {
+			if c.end <= c.start || inside(protected, c.start) {
 				continue
 			}
 			c.prio = prio
@@ -109,18 +109,15 @@
 	return merge(cs)
 }
 
-// covered reports whether [start, end) lies entirely inside the union of the
-// sorted, disjoint spans in protected.
-func covered(protected [][]int, start, end int) bool {
+// inside reports whether pos lies inside one of the sorted, disjoint spans in
+// protected. A candidate that starts in a placeholder is already redacted, or
+// is the re-reading of a redacted value: it is never redacted again.
+func inside(protected [][]int, pos int) bool {
 	for _, p := range protected {
-		if p[1] <= start {
-			continue
-		}
-		if p[0] > start {
+		if pos < p[0] {
 			return false
 		}
-		start = p[1]
-		if start >= end {
+		if pos < p[1] {
 			return true
 		}
 	}
--- r/internal/llm/redact/rules.go	2026-09-24 00:00:16.306220791 +0000
+++ amendC/internal/llm/redact/rules.go	2026-09-24 00:33:30.427787589 +0000
@@ -28,9 +28,9 @@
 	// keyPrefix: start of text, a delimiter, or an escaped newline or tab.
 	// ':' and ']' are deliberately absent.
 	keyPrefix = "(?:^|[\\s\"'`{}(\\[,;?&|>$]|\\\\[nrt])"
-	sepAny    = `[ \t]*(?::=|=>|[:=])[ \t]*`
-	sepBare   = `(?:[ \t]*(?::=|=>|=)[ \t]*|[ \t]*:[ \t]+)`
-	userinfo  = "[^\\s:@/?#\"'`<>\\\\]*:(?P<v>[^\\s@/?#\"'`<>\\\\]+)@"
+	sepAny    = `[ \t]*(?::=|=>|[:=])`
+	sepBare   = `[ \t]*(?::=|=>|=|(?P<c>:))`
+	userinfo  = "[^\\s:@/?#\"'`<>\\\\\\[\\]]*:(?P<v>[^\\s@/?#\"'`<>\\\\\\[\\]]+)@"
 	names     = `[A-Za-z0-9_.-]*(?:password|passwd|passphrase|pwd|secret|token|api[_.-]?key|apikey|access[_.-]?key|private[_.-]?key)[A-Za-z0-9_.-]*`
 	maxExempt = 256
 )
@@ -47,7 +47,7 @@
 		`|[?&](?i:sig)=(?P<v>[A-Za-z0-9%/+=]{16,})` +
 		`|[A-Za-z0-9_~.]{3}[0-9]Q~[A-Za-z0-9_~.-]{31,34}`
 	reScw     = `SCW[A-Z0-9]{17}`
-	rePSKLine = boundary + `(?i:PSK)[ \t]+(?:"(?P<v>[^"\\\r\n]+)"|'(?P<v>[^'\r\n]+)'|\\"(?P<v>[^"\\\r\n]+)\\"|(?P<v>[^\s"'\\]+))`
+	rePSKLine = boundary + `(?i:PSK)[ \t]+(?:"(?P<v>[^"\\\r\n]+)"|'(?P<v>[^'\\\r\n]+)'|\\"(?P<v>[^"\\\r\n]+)\\"|(?P<v>[^\s"'\\]+))`
 	reGitHub  = `gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}`
 	reGitLab  = `gl(?:pat|dt|ptt|rt|cbt|oas)-[A-Za-z0-9_-]{20,}`
 	reSlack   = `xox[abeoprs]-[A-Za-z0-9-]{10,}|https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_-]+`
@@ -55,8 +55,8 @@
 	reB64PEM  = `LS0tLS1CRUdJTi[A-Za-z0-9+/=]*`
 	reDB      = boundary + `(?i:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|sqlserver|mssql|clickhouse|cockroachdb|jdbc:[a-z0-9]+)://` + userinfo
 	reURL     = boundary + `[A-Za-z][A-Za-z0-9+.-]*://` + userinfo
-	reAuthz   = boundary + `(?i:(?:proxy-)?authorization)["']?[ \t]*[:=][ \t]*["']?` +
-		`(?i:(?:bearer|basic|token|digest|negotiate|ntlm|aws4-hmac-sha256)[ \t]+)?(?P<v>[^\r\n"'\\]*[^\s"'\\])`
+	reAuthz   = boundary + `(?i:(?:proxy-)?authorization)["']?(?:[ \t]|\\t)*[:=](?:[ \t]|\\t)*["']?` +
+		`(?i:(?:bearer|basic|token|digest|negotiate|ntlm|aws4-hmac-sha256)(?:[ \t]|\\t)+)?(?P<v>[^\r\n"'\\]*[^\s"'\\])`
 	reAuthScheme = boundary + `(?i:bearer)[ \t]+(?P<v>[A-Za-z0-9._~+/=-]{16,})`
 )
 
@@ -65,8 +65,8 @@
 // JSON-escaped), shell reference with braces, or a bare word.
 var valueRe = regexp.MustCompile(`^(?:` +
 	`"(?P<v>(?:[^"\\\r\n]|\\.)+)"` +
-	`|'(?P<v>[^'\r\n]+)'` +
-	`|\\"(?P<v>(?:[^"\\\r\n]|\\[^"\r\n])+)\\"` +
+	`|'(?P<v>[^'\\\r\n]+)'` +
+	`|\\"(?P<v>[^"\\\r\n]+)\\"` +
 	`|[|>][+-]?[0-9]?[ \t]*\r?\n[ \t]+(?P<v>[^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)` +
 	`|[|>][+-]?[0-9]?[ \t]*\\n[ \t]+(?P<v>(?:[^\\"\r\n]|\\[^n"\r\n])+(?:\\n[ \t]+(?:[^\\"\r\n]|\\[^n"\r\n])+)*)` +
 	`|(?P<v>\$\{[A-Za-z_][A-Za-z0-9_.]*\})` +
@@ -113,19 +113,23 @@
 	return rule{kind: k, re: regexp.MustCompile(expr), keyed: true, exempt: exempt}
 }
 
-func (ru rule) candidates(s string) []candidate {
+func (ru rule) candidates(s string, protected [][]int) []candidate {
 	var out []candidate
-	skip := 0 // keyed: end of the last non-exempt value; nested keys are redundant
+	skip := 0 // keyed: end of the last non-exempt value; values starting in it are redundant
+	colon := ru.re.SubexpIndex("c")
 	for _, loc := range ru.re.FindAllStringSubmatchIndex(s, -1) {
 		if !ru.keyed {
 			st, en := span(ru.re, loc, "v")
 			out = append(out, candidate{start: st, end: en})
 			continue
 		}
-		if loc[0] < skip {
+		vs := loc[1]
+		for vs < len(s) && (s[vs] == ' ' || s[vs] == '\t') {
+			vs++
+		}
+		if vs < skip || inside(protected, vs) || (colon > 0 && loc[2*colon] >= 0 && vs == loc[1]) {
 			continue
 		}
-		vs := loc[1]
 		vloc := valueRe.FindStringSubmatchIndex(s[vs:])
 		if vloc == nil {
 			continue
```

Limites nouvelles (à ajouter à la section 5.8) : une valeur qui commence par un placeholder déjà présent est tenue pour rédigée (`password=[REDACTED:github_token]FAKEtail` reste inchangé ; ne concerne que les entrées déjà rédigées) ; une valeur entre guillemets simples ou échappés qui contient une barre oblique inverse n'est plus reconnue par ces alternatives (L4) ; un userinfo contenant `[` ou `]` n'est plus reconnu (L5, conforme à la RFC 3986). Résidus déjà présents dans la référence : `password=${DB}FAKEhunter2` non masqué (L3 et E3) ; bloc YAML imbriqué dans une valeur nue ignoré par `skip`.

Corrections de la section 8.3 (mutations) : M16 a pour ancre unique `` `|\\"(?P<v>[^" `` ; M20 devient `skip = en` remplacé par `skip = 0` (échec attendu : `TestLargeInputAdversarial` dépasse son délai) ; M6 devient `inside(protected, c.start)` remplacé par `inside(protected[:0], c.start)` ; M10 devient `loc[2*colon] >= 0 && vs == loc[1])` remplacé par `loc[2*colon] >= 0 && false)`.

---

## 0 bis. Amendement V2 (revue `security-reviewer`, verdict BLOCK, 2026-09-24, prime sur le reste du document et sur V1)

Constats à corriger dans T07 (sondes et correctifs de la revue dans le scratchpad `sec07/`). Chaque constat devient d'abord un ou plusieurs cas de test rouges (retour journalisé en phase tests), puis est corrigé :

| # | Gravité | Constat | Comportement exigé |
|---|---|---|---|
| F1 | haute | `userinfo` exclut `@` : `postgres://admin:P@<pw>@h` laisse la fin du mot de passe ; `smtp://alerts@example.com:<pw>@h`, `postgresql://user@server:<pw>@x.postgres.database.azure.com` laissent tout le mot de passe | lecture jusqu'au **dernier** `@` avant la fin de l'autorité (`/`, `?`, `#`, blanc, guillemet) ; mot de passe entier masqué dans les 3 formes |
| F2 | haute | valeur en tableau JSON : `"Authorization":["Basic <b64>"]` (multiValueHeaders, `http.Header`) et `"api_keys": ["<k>"]` : seul `[` masqué | tableau sur une ligne lu comme valeur (`\[[^\]\r\n]*\]`) ; `reAuthz` accepte `[` avant le guillemet ; aucun élément du tableau ne reste en clair |
| F3 | haute | armure de clé PGP avec en-têtes `Version:`, `Comment:` : masque arrêté à l'en-tête, corps en clair | toute ligne d'en-tête d'armure `[A-Za-z-]+:[^\r\n\\]*` acceptée dans le corps ; corps entier masqué |
| F4 | haute | paires nom et valeur des manifestes : `- name: DB_PASSWORD` puis `value: <pw>` (env Kubernetes, YAML), `{"name":"DB_PASSWORD","value":"<pw>"}` (ECS, JSON), dans les deux ordres | la valeur d'un champ `value` est masquée (`KindSensitiveVar`) quand le champ `name` du même objet (même objet JSON sur une ligne, ou même élément de liste YAML, lignes consécutives) porte un nom sensible (`names`) ; ordre `value` puis `name` compris |
| F5 | moyenne | `inside` linéaire, appelé pour chaque candidat : 1 Mio de faux placeholders puis ` token=x` prend 13,2 s (T10) | recherche dichotomique (`slices.BinarySearchFunc`) ; cas ajouté à `TestLargeInputAdversarial`, borne de temps inchangée |
| F6 | moyenne | guillemet jamais fermé (journal tronqué, `{"password": "<pw>` en fin de ligne ou de texte) : rien masqué | sans guillemet fermant sur la ligne, la valeur court jusqu'à la fin de ligne (ou de texte) |
| F7 | moyenne | `json.Marshal` de Go écrit `&` en `\u0026` (et `<`, `>` en `\u003c`, `\u003e`) : `\u0026password=<pw>` et `\u0026sig=` passent | `\u0026`, `\u003c`, `\u003e` acceptés comme préfixe de clé (`keyPrefix`), comme frontière (`boundary`) et devant `sig` |
| F8 | moyenne | E2 cherche les mots de quantité par sous-chaîne : `admin_password: 48213957`, `SERVICE_ACCOUNT_PASSWORD=74120385`, `manager_password` exemptés (`min`, `count`, `age`) | mot de quantité reconnu seulement comme **segment entier** de la clé (séparateurs `_ . -` ou changement de casse) ; les trois exemples masqués, `max_tokens: 1024` toujours exempté |
| F9 | moyenne | `RABBITMQ_DEFAULT_PASS`, `SMTP_PASS`, clé `auth` de `~/.docker/config.json` non couverts | `pass` reconnu comme segment entier de clé ; clé exacte `auth` (insensible à la casse) couverte |

Constats bas : documentés en section 5.8 (limites) à la clôture, sans correctif dans T07 : `db/password: x` (préfixe `/`), octet UTF-8 invalide avant la clé, jetons STS `AgoJ...`, et les limites déjà listées (L1 netrc, L2 `<pre_shared_key>` XML de CustomerGatewayConfiguration, L3, L4, L5 `#` dans une URL). Contrat pour T12 (section 5.9) : décoder les chaînes JSON avant `ContainsSecret` sur un corps sortant (une tabulation encodée en `\t` dégrade la détection). Contrat pour T11 et M1 : rédiger **avant** toute troncature ou sérialisation.

Exigences transverses inchangées : idempotence, cohérence de `ContainsSecret`, sortie propre une fois encodée en JSON, aucun nouveau faux positif de `TestNoFalsePositive`, coût linéaire (entrées adverses sous la borne), aucun `.*` ni `(?s`, fixtures marquées.

---

Correction du 2026-09-24 : la fixture `l06_slack_webhook` utilise un chemin `fake-example/placeholder-path`. La forme précédente (segments `T...`, `B...` et 24 caractères) était prise pour un vrai webhook par la protection de push de GitHub, qui refusait le commit. La règle testée (`hooks.slack.com/services/...`) est inchangée.

## 0 ter. Amendement V3 (implémentation des correctifs V2, 2026-09-24, prime sur V1 et V2)

Les correctifs de F1 à F9 ont été validés par `test-author` sur copie, puis appliqués au dépôt en phase impl (diff de 527 lignes, identique à l'octet à la copie validée). Pour tenir l'idempotence et le contrat JSON face à une exploration plus hostile que celle de V1 (3 millions d'entrées hostiles puis 25 familles de fuite × 40 000, sans échec), l'implémentation va au-delà du tableau V2 :

- **Vue opaque** : les règles lisent le texte où chaque placeholder existant vaut une suite d'octets NUL, qu'aucune classe n'accepte ; aucun jeton, clé ou valeur ne commence dans un placeholder ni ne le traverse (idempotence structurelle). `inside` et `overlaps` en recherche dichotomique (F5).
- **Lecture stricte et lecture relâchée** pour `PSK` et `Authorization` : la valeur stricte s'arrête aux octets que JSON échappe ; une règle « bloquée » (toujours exemptée) lit la valeur entière et étend le masque strict quand elle le chevauche.
- **Frontière** : une `\` seule n'est plus une frontière (`\n`, `\r`, `\t` et les échappements JSON `\u0026`, `\u003c`, `\u003e` le sont).
- **Mot de schéma seul exempté** : `Authorization: Bearer` suivi d'un placeholder ne masque pas `Bearer`.
- **Blocs YAML** : le contenu ne commence ni par un blanc ni par un saut de ligne. **Tableaux** : sur une ligne, un niveau d'imbrication, sans traverser un `\n` échappé.
- **F2** : `Authorization` suivi d'un tableau masque le tableau entier. **F4** : objets sur plusieurs lignes acceptés (JSON indenté, HCL) ; exemptions E1 à E4 appliquées avec le nom comme clé. **F6** : couvre aussi le guillemet simple. **F7** : `<` et `>` bruts acceptés devant `sig`. **F8** : mots de quantité ajoutés `length`, `minimum`, `maximum`, `expiry`, `expire`, `expires`, `expiration`. **F9** : `smtpPass` (casse mixte) couvert.

Limites nouvelles (section 5.8) : tableaux sur plusieurs lignes ; F4 : objets à accolades imbriquées (y compris dans une chaîne) et paires `Key`/`Value` non couverts ; valeur coupée à un placeholder existant ; `\sk-...` non détecté ; plus les constats bas de V2.

Tests : 85 cas positifs, 31 négatifs, 17 quasi-exemptions, 22 fixtures d'idempotence, 18 entrées adverses. Mutations de la section 8.3 : les ancres M11, M13, M16, M17, M21 et M22 ne s'appliquent plus au code V3 ; l'acceptation les remplace par des mutations équivalentes (même propriété visée, même test attendu en échec), documentées dans son rapport. Écart de protocole consigné : la correction V3 a été écrite par `test-author` sur copie puis appliquée par l'agent principal ; l'indépendance est compensée par la contre-revue `security-reviewer` et l'acceptation.

---

## 1. Objectif

Fournir `internal/llm/redact`, le rédacteur déterministe que `llm.Client` (T11) appliquera à toute partie de requête avant l'appel au fournisseur, et que `TestNoSecretInOutgoingRequest` (T12) utilisera pour inspecter les corps sortants. Chaque motif de `.claude/skills/llm-safety/references/redaction-patterns.md` est masqué par `[REDACTED:<kind>]` ; `Match` localise chaque masque par ses octets dans l'entrée, jamais par sa valeur ; `Redact` est idempotent ; `ContainsSecret(s)` vaut exactement « `Redact(s)` masquerait quelque chose ». Aucune décision n'est prise par un LLM (règle 1 du skill) : tout est expression régulière RE2 et règle d'exemption codée.

---

## 2. Périmètre

### 2.1 Dans le périmètre
- `internal/llm/redact/redact.go` : commentaire de paquet, `Kind` et ses 16 constantes, `Match`, `Redactor`, `New`, `Placeholder`, `Kinds`, `ContainsSecret`, `Redact`, fusion des candidats.
- `internal/llm/redact/rules.go` : fragments d'expressions, lecteur de valeurs, table des 23 règles, exemptions, reconnaissance des placeholders.
- Tests : `cases_test.go`, `redact_test.go`, `reference_test.go`, `property_test.go` dans `internal/llm/redact/`.
- `docs/STATUS.md` à la clôture.

### 2.2 Hors périmètre
- Appel du rédacteur par `llm.Client`, compteur `Trace.Redactions`, borne de taille des requêtes : T11 (contraintes en section 5.9).
- Inspection des corps HTTP sortants : T12 (`TestNoSecretInOutgoingRequest`).
- Masquage des IP publiques, pseudonymisation, minimisation des sous-graphes : M1 et M5 (vue d'ensemble, section 3.2).
- Rédaction structurée de documents connus (valeurs `data:` d'un `Secret` Kubernetes sous des clés quelconques, attributs `sensitive` d'un état Terraform, en-têtes `Cookie`) : proposée pour M1 (section 5.8, ligne L5).
- Evals du taux de faux positifs sur des corpus réels : M1, avec la première boucle qui envoie des données client au modèle.
- Modification de `references/redaction-patterns.md` : lu, jamais écrit par cette tâche (critère 18).

### 2.3 Précisions par rapport à la fiche (sans élargissement)

| # | Point de la fiche | Précision retenue | Raison |
|---|---|---|---|
| P1 | `type Redactor struct{ /* règles compilées, immuables après New */ }` | Les règles sont compilées **une fois, à l'initialisation du paquet** ; `Redactor` est un type vide sans état. La valeur zéro et un `*Redactor` nil se comportent exactement comme `New()`. Sûr en concurrence. | Aucun `Redactor` mal construit ne peut masquer moins (pas d'échec ouvert) ; `regexp.Regexp` est sûr en concurrence. |
| P2 | `Placeholder(k) // "[REDACTED:<kind>]"` | Texte exact `"[REDACTED:" + string(k) + "]"`. Les placeholders des 16 `Kind` présents dans l'entrée sont **protégés** : un candidat entièrement couvert par des placeholders est ignoré. | Idempotence (section 5.6) ; un placeholder n'est jamais pris pour un secret, même après `password: `. |
| P3 | `Match{Kind; Start, End int} // positions dans l'entrée ; jamais la valeur` | `[Start, End)` en **octets** de l'entrée d'origine ; matches triés, disjoints, `0 <= Start < End <= len(s)`. Reconstruction exacte : la sortie est l'entrée où chaque `[Start, End)` est remplacé par `Placeholder(Kind)`. Octets UTF-8 invalides conservés tels quels. | Positions directement utilisables par T11 et par les preuves ; pas de runes (ambiguës sur une entrée invalide). |
| P4 | Ordre d'application | Toutes les règles sont évaluées sur l'entrée **d'origine**, indépendamment ; l'ordre de la table (section 5.3) ne sert qu'à choisir le `Kind` d'un masque. `Kinds()` rend l'ordre de déclaration de la fiche, distinct de l'ordre de priorité. | Aucune règle ne voit la sortie d'une autre : pas d'effet de bord d'ordre sur ce qui est masqué. |
| P5 | Chevauchements | Les candidats qui se **chevauchent strictement** sont fusionnés en un seul masque, leur **union** ; le `Kind` est celui de la règle de plus haute priorité parmi les candidats non exemptés du groupe. Deux candidats qui se touchent sans se chevaucher restent deux masques. | L'union garantit qu'aucun fragment ne survit ; la priorité rend l'étiquette la plus spécifique ; la sécurité ne dépend jamais de l'étiquette. |
| P6 | `KindSensitiveVar` : `*password*`, `*secret*`, `*token*`, `*api_key*` (HCL, tfvars, YAML, JSON, env) | Clé = identifiant contenant `password`, `passwd`, `passphrase`, `pwd`, `secret`, `token`, `api_key` (séparateur `_`, `.`, `-` ou aucun), `access_key`, `private_key`, casse ignorée (sous-chaîne, comme les jokers du skill). Quatre formes de clé : `"k"`, `'k'`, `\"k\"`, `k` nue. Séparateurs : `=`, `:=`, `=>` avec espaces libres ; `:` suivi d'**au moins une espace** pour une clé nue (règle de YAML), libre pour une clé entre guillemets (JSON). | `secretsmanager:GetSecretValue` (politique IAM) et `arn:...:secret:nom` ne sont pas des couples clé et valeur ; `password: x`, `"password":"x"`, `PASSWORD=x` le sont. |
| P7 | Formes de valeur | Sept formes, dans cet ordre : guillemets doubles (échappements JSON), guillemets simples, guillemets échappés `\"...\"`, bloc YAML `\|` ou `>` (brut), bloc YAML échappé JSON, référence `${NOM}`, mot nu. Le mot nu s'arrête à un blanc, un guillemet, un accent grave, `,`, `;`, `&`, `{`, `}`, `<`, `>`, une barre oblique inverse ; il ne commence ni par `\|` ni par `\`. Seule la valeur est masquée, la clé reste lisible. | Couvre tfvars, HCL, YAML, JSON, env, URL (`?password=x&`), chaînes de connexion (`Password=x;`), journaux JSON contenant du `clé = "valeur"`. Clé lisible : le modèle garde le contexte (« un mot de passe est présent »). |
| P8 | `max_tokens: 1024` (règle à préciser) | Quatre exemptions, **pour la seule règle générique** `KindSensitiveVar` par clé : E1 valeur mot-clé (`true`, `false`, `null`, `nil`, `none`, `yes`, `no`, `on`, `off`) ; E2 valeur de 1 à 9 chiffres **et** clé contenant un mot de quantité (`len`, `min`, `max`, `count`, `age`, `days`, `ttl`, `expir`, `reuse`, `size`, `limit`, `attempts`, `retries`, `timeout`, `rotation`, `version`, `port`, `tokens`) ; E3 valeur entièrement référence (`var.x`, `local.x`, `data.x`, `module.x`, `${...}`, `$NOM`, `{{ ... }}`, `${{ ... }}`) ; E4 clé finissant par `name`, `arn`, `ref`, `url`, `uri`, `endpoint`, `path`, `file`, `policy`, `version`, `type` (après `_`, `.`, `-` ou en camelCase). Une valeur de plus de 256 octets n'est jamais exemptée. **Contamination** : une valeur exemptée qui chevauche un autre candidat est masquée en entier. | `max_tokens` figure dans chaque requête Anthropic (T12) ; les politiques de mot de passe, drapeaux booléens, références HCL et ARN sont le quotidien de l'IaC que le modèle doit expliquer. `password: 123456` reste masqué (pas de mot de quantité). La contamination empêche qu'une exemption cache un jeton reconnaissable (`var.` suivi d'une clé d'accès AWS). |
| P9 | Idempotence `Redact(Redact(x)) == Redact(x)` | Garantie par construction (section 5.6) et prouvée par table et par propriété sur un « potage » de fragments hostiles ; la seconde passe rend **zéro** match. | Un texte déjà rédigé (trace, reprise de workflow) ne doit ni changer ni compter de nouveaux secrets. |
| P10 | Taille maximale | **Aucune borne dans `redact`** : pas de troncature (échec ouvert) ni de refus (l'API n'a pas d'erreur). Coût linéaire visé par construction (section 5.7), mesuré par `TestLargeInputAdversarial`. La borne de taille appartient à T11, qui **refuse** (sans tronquer) une requête de plus de 1 Mio de texte avant rédaction. | Une borne interne obligerait à choisir entre fuite (tronquer) et perte de données silencieuse ; T11 a déjà les budgets (T10). |
| P11 | `ContainsSecret` | Défini comme `len(find(s)) > 0`, même fonction que `Redact` : cohérence par construction, prouvée par `TestContainsSecretConsistent`. | T12 s'appuie sur `ContainsSecret` pour juger les corps sortants. |
| P12 | Marqueurs `EXAMPLE`, `FAKE` des fixtures | **Aucune exemption par marqueur** dans le code : les fixtures marquées sont masquées comme les autres. Les mots `EXAMPLE`, `FAKE`, `DUMMY`, `PLACEHOLDER` n'apparaissent pas dans le code de production (critère 11). | Sinon un vrai secret suivi de `EXAMPLE` passerait, et les tests ne prouveraient rien. |
| P13 | `internal/llm/redact/testdata/` (fixtures) | **Pas de dossier `testdata/`** : toutes les fixtures sont des champs de littéraux composites dans `cases_test.go`. Repli unique, si gosec G101 signale une fixture (section 7.8) : la fixture fautive passe dans `testdata/fixtures/<cas>.txt`, lu par `os.ReadFile`, et l'écart est consigné. | Tables lisibles et exactes ; `testdata/` est gelé en phase impl et attirerait les fichiers d'échec de `rapid`. |
| P14 | 6 tests nommés | 11 tests témoins ajoutés (section 7), 17 tests de premier niveau | Chaque décision P1 à P13 a sa preuve ; chaque ligne d'ancre a une mutation qui la fait échouer (section 8.3). |
| P15 | Implémentation | Bibliothèque standard seule : `cmp`, `regexp`, `slices`, `strings` | Paquet importé par T11 ; aucune dépendance nouvelle. |

---

## 3. Conditions d'entrée et contraintes du harnais non patché

### 3.1 Conditions d'entrée
- `python3 .claude/bin/rempart-state show` : `jalon=M0 phase=free`.
- `make verify-quick; echo rc=$?` : `rc=0` sur `HEAD`.
- `git status --porcelain | wc -l` : `0`.
- `test ! -e internal/llm/redact; echo rc=$?` : `rc=0`.
- `grep -c '^require pgregory.net/rapid v1.3.0$' go.mod` : `1` (aucun `go get`).
- `grep -c '^- ' .claude/skills/llm-safety/references/redaction-patterns.md` : `12`.

### 3.2 Contraintes (reprises de `docs/plans/M0-secret-value.md` section 3.2, appliquées à T07)
1. **Hook Stop** : `make verify-quick` doit être vert à chaque fin de tour. Les tests rouges rendent `internal/llm/redact` non compilable. **Tout le cycle, de `phase tests` au premier `make verify-quick` vert en phase impl, se fait dans un seul tour de l'agent principal**, délégation à `test-author` comprise, sans question à l'humain entre les phases. La validation humaine de ce plan se fait **avant** `phase tests`.
2. **`post_edit_check.py`** lance `go vet ./internal/llm/redact` après chaque écriture d'un `.go`. En phase tests, le dossier ne contient que des `_test.go`, tous en `package redact` (tests internes : un paquet `redact_test` échouerait sur l'import d'un paquet sans fichier non test, mauvaise raison). Le hook renvoie alors `undefined: New`, `undefined: Kind`, etc. : **attendu**, le fichier est écrit, le message est informatif. `no non-test Go files` est aussi informatif. Tout autre message (syntaxe, import introuvable) se corrige avant de continuer ; la preuve de rouge se fait par `go test -gcflags=-e` (section 7.7).
3. **Porte `phase impl`, dossier nouveau : `git add` obligatoire.** `internal/llm/` est suivi (`doc.go`) mais `internal/llm/redact/` est nouveau : `git status --porcelain` l'affiche groupé, `?? internal/llm/redact/`, chemin qui ne finit pas par `_test.go`, et la porte répondrait `Refusé : aucun test nouveau ou modifié`. En fin de phase tests : `git add internal/llm/redact/` (le dossier ne contient que les 4 `_test.go`) ; la porte lance ensuite `go test ./internal/llm/redact` sans tag : échec de compilation, passage accepté. `redact.go` et `rules.go` apparaîtront ensuite individuellement ; aucun autre `git add` avant le commit de clôture.
4. **`guard_edit`, phases** : `*_test.go` modifiables en phase tests, gelés en impl ; `redact.go` et `rules.go` interdits en phase tests.
5. **`guard_edit`, motifs de secrets** : toute écriture (tests, production, **ce plan**) contenant une clé d'accès AWS, un en-tête PEM de clé privée RSA, EC, OPENSSH, DSA ou générique, `aws_secret_access_key` suivi de 40 caractères, `ghp_` suivi de 36 caractères, `glpat-`, `sk-ant-` ou `xox?-` suivis de leur corps est bloquée si aucun de `EXAMPLE`, `FAKE`, `DUMMY`, `PLACEHOLDER` (majuscules) ne figure à moins de 40 caractères. Conséquences :
   - **Code de production** : aucune expression de `rules.go` ne déclenche la garde, parce que chaque préfixe littéral y est suivi d'une classe ou d'un groupe (`(?:AKIA|ASIA)[A-Z0-9]{16}`, `gh[pousr]_`, `gl(?:pat|...)-`, `xox[abeoprs]-`, `sk-ant-[A-Za-z0-9_-]`, `-----BEGIN[A-Z0-9 ]*PRIVATE KEY`) et non d'un corps de secret. Les commentaires de production ne citent **aucun exemple** (critère 11 : aucun mot marqueur en production).
   - **Fixtures** : chaque fixture qui ressemble à un secret contient un marqueur **dans la chaîne elle-même** quand le format le permet (section 7.1, règle F1), ou juste avant (`FAKE\n` devant un en-tête PEM suivi de lignes d'en-tête).
   - **Construction à l'exécution** : interdite pour reconstituer un secret fixe (`"gh" + "p_" + ...`, `strings.Repeat` ou `fmt.Sprintf` de morceaux fixes) ; permise seulement pour des **corps aléatoires** tirés par `rapid` dans `property_test.go` (section 7.1, règle F4). Critères 13 et 13 bis.
6. **Lint des tests et attentes gelées** : `golangci-lint` ne peut pas analyser un paquet qui ne compile pas, et plusieurs attentes dépendent du moteur `regexp` de Go 1.27.1 (sémantique « le plus à gauche, puis la première alternative », noms de groupe répétés). Parade : copie scratch avec le **code de référence de la section 5** (section 7.8), où `go vet`, `golangci-lint` (dont gosec G101), `go test` et le potage à 100 000 cas doivent être verts **avant** le gel.
7. **Fichiers d'échec de `rapid`** : toute exécution ciblée passe `-rapid.nofailfile` (le paquet importe `rapid`) ; critère 14 en fin de tâche.
8. **Lecture du skill par un test** : `TestEveryPatternLineMapped` lit `../../../.claude/skills/llm-safety/references/redaction-patterns.md` en lecture seule ; aucun hook ne s'y oppose.

---

## 4. Fichiers exacts

| Fichier | Phase | Contenu |
|---|---|---|
| `internal/llm/redact/cases_test.go` | tests | tables normatives de la section 7.2, aides `rebuild`, `kindsOf`, `allFixtures` |
| `internal/llm/redact/redact_test.go` | tests | tests 1, 3, 6, 7 à 12, 14 à 16 |
| `internal/llm/redact/reference_test.go` | tests | test 2 |
| `internal/llm/redact/property_test.go` | tests | tests 4, 5, 13, 17 (`rapid`), générateurs |
| `internal/llm/redact/redact.go` | impl | section 5.1 |
| `internal/llm/redact/rules.go` | impl | section 5.2 |
| `docs/STATUS.md` | clôture | section 13, F3 |

---

## 5. Interfaces et code de référence

Les lignes marquées « ancre » sont normatives au caractère près (mutations de la section 8.3) ; les commentaires `// ancre Mx` ne sont pas écrits dans le dépôt. Les commentaires de documentation sont libres, sans exemple de secret.

### 5.1 `redact.go`

```go
// Package redact masks secrets in text before it reaches a language model
// (skill llm-safety, rule 4; threat T7). Detection is deterministic: fixed
// RE2 regular expressions and fixed exemption rules, compiled once at package
// initialization. Each detected secret is replaced by Placeholder(kind); a
// Match gives its byte offsets in the input, never its value. Secrets are
// found by shape (token prefixes, PEM armor) or by context (a sensitive key
// followed by a value). Free-form secrets without such context are not found:
// see docs/plans/M0-redaction.md, section 5.8.
package redact

import (
	"cmp"
	"slices"
	"strings"
)

// Kind names a family of secrets. Its value appears in Placeholder.
type Kind string

const (
	KindAWSAccessKey    Kind = "aws_access_key"
	KindAWSSecretKey    Kind = "aws_secret_key"
	KindAWSSessionToken Kind = "aws_session_token"
	KindAzureSecret     Kind = "azure_secret"
	KindScalewayKey     Kind = "scaleway_key"
	KindOVHCredential   Kind = "ovh_credential"
	KindPrivateKey      Kind = "private_key"
	KindGitHubToken     Kind = "github_token"
	KindGitLabToken     Kind = "gitlab_token"
	KindSlackToken      Kind = "slack_token"
	KindLLMAPIKey       Kind = "llm_api_key"
	KindURLCredentials  Kind = "url_credentials"
	KindDBConnString    Kind = "db_connection_string"
	KindKubeconfig      Kind = "kubeconfig_credential"
	KindSensitiveVar    Kind = "sensitive_variable"
	KindIPsecPSK        Kind = "ipsec_psk"
)

// allKinds lists every Kind in declaration order.
var allKinds = []Kind{
	KindAWSAccessKey, KindAWSSecretKey, KindAWSSessionToken, KindAzureSecret,
	KindScalewayKey, KindOVHCredential, KindPrivateKey, KindGitHubToken,
	KindGitLabToken, KindSlackToken, KindLLMAPIKey, KindURLCredentials,
	KindDBConnString, KindKubeconfig, KindSensitiveVar, KindIPsecPSK,
}

// Match locates one redacted secret: bytes [Start, End) of the input.
type Match struct {
	Kind       Kind
	Start, End int
}

// Redactor masks secrets. It holds no state: the zero value and a nil
// *Redactor behave exactly like New(). It is safe for concurrent use.
type Redactor struct{}

// New returns a Redactor.
func New() *Redactor { return &Redactor{} }

// Placeholder returns the text that replaces a secret of kind k.
func Placeholder(k Kind) string {
	return "[REDACTED:" + string(k) + "]" // ancre M1
}

// Kinds returns every Kind, in declaration order, in a new slice.
func (r *Redactor) Kinds() []Kind {
	return slices.Clone(allKinds) // ancre M19
}

// ContainsSecret reports whether Redact(s) would redact anything.
func (r *Redactor) ContainsSecret(s string) bool {
	return len(find(s)) > 0 // ancre M18
}

// Redact returns s with every detected secret replaced by its Placeholder,
// and the matches, sorted and disjoint, as byte offsets in s. Placeholders
// already present in s are never redacted again: Redact is idempotent.
func (r *Redactor) Redact(s string) (string, []Match) {
	ms := find(s)
	if len(ms) == 0 {
		return s, nil
	}
	var b strings.Builder
	b.Grow(len(s))
	prev := 0
	for _, m := range ms {
		b.WriteString(s[prev:m.Start])
		b.WriteString(Placeholder(m.Kind))
		prev = m.End
	}
	b.WriteString(s[prev:])
	return b.String(), ms
}

// find evaluates every rule on s, drops candidates that lie inside existing
// placeholders, and merges the rest.
func find(s string) []Match {
	protected := placeholderRe.FindAllStringIndex(s, -1)
	var cs []candidate
	for prio, ru := range rules {
		for _, c := range ru.candidates(s) {
			if c.end <= c.start || covered(protected, c.start, c.end) { // ancre M6
				continue
			}
			c.prio = prio
			cs = append(cs, c)
		}
	}
	return merge(cs)
}

// covered reports whether [start, end) lies entirely inside the union of the
// sorted, disjoint spans in protected.
func covered(protected [][]int, start, end int) bool {
	for _, p := range protected {
		if p[1] <= start {
			continue
		}
		if p[0] > start {
			return false
		}
		start = p[1]
		if start >= end {
			return true
		}
	}
	return false
}

// merge unites strictly overlapping candidates. A group becomes a Match only
// if one of its candidates is not exempt; its Kind is that of the highest
// priority (lowest index) non-exempt candidate.
func merge(cs []candidate) []Match {
	slices.SortFunc(cs, func(a, b candidate) int {
		return cmp.Or(cmp.Compare(a.start, b.start), cmp.Compare(b.end, a.end), cmp.Compare(a.prio, b.prio))
	})
	var out []Match
	for i := 0; i < len(cs); {
		start, end := cs[i].start, cs[i].end
		best, active := len(rules), false
		j := i
		for ; j < len(cs) && cs[j].start < end; j++ { // ancre M2
			end = max(end, cs[j].end) // ancre M3
			if !cs[j].exempt {
				active = true
				best = min(best, cs[j].prio) // ancre M4
			}
		}
		if active {
			out = append(out, Match{Kind: rules[best].kind, Start: start, End: end})
		}
		i = j
	}
	return out
}
```

### 5.2 `rules.go`

```go
package redact

import (
	"regexp"
	"strings"
)

// rule finds candidates of one Kind. A shape rule matches the secret itself;
// its group "v", when present, narrows the span. A keyed rule matches a
// sensitive key and its separator; the value that follows is read by valueRe.
type rule struct {
	kind   Kind
	re     *regexp.Regexp
	keyed  bool
	exempt func(key, value string) bool // keyed rules only; nil: never exempt
}

type candidate struct {
	start, end, prio int
	exempt           bool
}

const (
	// boundary: start of text, or a byte that is neither a word byte nor ']'
	// (the last byte of a placeholder), so that masking a neighbour never
	// creates a new match.
	boundary = `(?:^|[^A-Za-z0-9_\]])`
	// keyPrefix: start of text, a delimiter, or an escaped newline or tab.
	// ':' and ']' are deliberately absent.
	keyPrefix = "(?:^|[\\s\"'`{}(\\[,;?&|>$]|\\\\[nrt])"
	sepAny    = `[ \t]*(?::=|=>|[:=])[ \t]*`
	sepBare   = `(?:[ \t]*(?::=|=>|=)[ \t]*|[ \t]*:[ \t]+)` // ancre M10
	userinfo  = "[^\\s:@/?#\"'`<>\\\\]*:(?P<v>[^\\s@/?#\"'`<>\\\\]+)@"
	names     = `[A-Za-z0-9_.-]*(?:password|passwd|passphrase|pwd|secret|token|api[_.-]?key|apikey|access[_.-]?key|private[_.-]?key)[A-Za-z0-9_.-]*`
	maxExempt = 256
)

// Shapes. Each literal prefix is followed by a class or a group, never by a
// secret body.
const (
	rePEM = `-----BEGIN[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----` +
		`(?:Proc-Type:[^\r\n\\]*|DEK-Info:[^\r\n\\]*|[A-Za-z0-9+/=\s\\])*` + // ancres M11, M12
		`(?:-----END[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----)?`
	reAWSKey     = `(?:AKIA|ASIA)[A-Z0-9]{16}` // ancre M15
	reAWSSession = `(?:FwoGZXIvYXdz|IQoJb3JpZ2lu)[A-Za-z0-9/+=]{50,}`
	reAzure      = `(?i:AccountKey|SharedAccessKey)=(?P<v>[A-Za-z0-9+/=]{20,})` +
		`|[?&](?i:sig)=(?P<v>[A-Za-z0-9%/+=]{16,})` +
		`|[A-Za-z0-9_~.]{3}[0-9]Q~[A-Za-z0-9_~.-]{31,34}`
	reScw     = `SCW[A-Z0-9]{17}`
	rePSKLine = boundary + `(?i:PSK)[ \t]+(?:"(?P<v>[^"\\\r\n]+)"|'(?P<v>[^'\r\n]+)'|\\"(?P<v>[^"\\\r\n]+)\\"|(?P<v>[^\s"'\\]+))`
	reGitHub  = `gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255}`
	reGitLab  = `gl(?:pat|dt|ptt|rt|cbt|oas)-[A-Za-z0-9_-]{20,}`
	reSlack   = `xox[abeoprs]-[A-Za-z0-9-]{10,}|https://hooks\.slack\.com/(?:services|workflows)/[A-Za-z0-9/_-]+`
	reLLM     = `sk-ant-[A-Za-z0-9_-]{20,}|` + boundary + `(?P<v>sk-[A-Za-z0-9_-]{20,})` // ancre M14
	reB64PEM  = `LS0tLS1CRUdJTi[A-Za-z0-9+/=]*`
	reDB      = boundary + `(?i:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|sqlserver|mssql|clickhouse|cockroachdb|jdbc:[a-z0-9]+)://` + userinfo
	reURL     = boundary + `[A-Za-z][A-Za-z0-9+.-]*://` + userinfo
	reAuthz   = boundary + `(?i:(?:proxy-)?authorization)["']?[ \t]*[:=][ \t]*["']?` +
		`(?i:(?:bearer|basic|token|digest|negotiate|ntlm|aws4-hmac-sha256)[ \t]+)?(?P<v>[^\r\n"'\\]*[^\s"'\\])`
	reAuthScheme = boundary + `(?i:bearer)[ \t]+(?P<v>[A-Za-z0-9._~+/=-]{16,})`
)

// valueRe reads a value at the start of its input: double quotes (JSON
// escapes), single quotes, escaped double quotes, YAML block scalar (raw or
// JSON-escaped), shell reference with braces, or a bare word.
var valueRe = regexp.MustCompile(`^(?:` +
	`"(?P<v>(?:[^"\\\r\n]|\\.)+)"` + // ancre M13
	`|'(?P<v>[^'\r\n]+)'` +
	`|\\"(?P<v>(?:[^"\\\r\n]|\\[^"\r\n])+)\\"` + // ancre M16 sur la sous-chaîne |\\"(?P<v>
	`|[|>][+-]?[0-9]?[ \t]*\r?\n[ \t]+(?P<v>[^\r\n]+(?:\r?\n[ \t]+[^\r\n]+)*)` + // ancre M17
	`|[|>][+-]?[0-9]?[ \t]*\\n[ \t]+(?P<v>(?:[^\\"\r\n]|\\[^n"\r\n])+(?:\\n[ \t]+(?:[^\\"\r\n]|\\[^n"\r\n])+)*)` +
	`|(?P<v>\$\{[A-Za-z_][A-Za-z0-9_.]*\})` +
	"|(?P<v>[^\\s\"'`,;&{}<>\\\\|][^\\s\"'`,;&{}<>\\\\]*)" +
	`)`)

// rules, by decreasing priority (section 5.3 of docs/plans/M0-redaction.md).
var rules = []rule{
	shape(KindPrivateKey, rePEM),
	keyed(KindKubeconfig, `client-key-data|token|id-token|refresh-token`, nil),
	keyed(KindAWSSecretKey, `(?:aws_)?secret_?access_?key|aws_secret_key`, nil),
	keyed(KindAWSSessionToken, `(?:aws_)?session_?token|aws_security_token|x-amz-security-token|x-amz-signature`, nil),
	shape(KindAWSSessionToken, reAWSSession),
	keyed(KindAzureSecret, `(?:arm_|azure_)?client_?secret|secret_?text`, nil),
	shape(KindAzureSecret, reAzure),
	keyed(KindScalewayKey, `scw_secret_key|scaleway_secret_key`, nil),
	shape(KindScalewayKey, reScw),
	keyed(KindOVHCredential, `(?:ovh_)?(?:application_?key|application_?secret|consumer_?key)`, nil),
	keyed(KindIPsecPSK, `psk|pre_?shared_?key|tunnel[0-9]_preshared_key|shared_?key|ike_psk`, nil),
	shape(KindIPsecPSK, rePSKLine),
	shape(KindAWSAccessKey, reAWSKey),
	shape(KindGitHubToken, reGitHub),
	shape(KindGitLabToken, reGitLab),
	shape(KindSlackToken, reSlack),
	shape(KindLLMAPIKey, reLLM),
	shape(KindPrivateKey, reB64PEM),
	shape(KindDBConnString, reDB),
	shape(KindURLCredentials, reURL),
	shape(KindSensitiveVar, reAuthz), // ancre M21
	shape(KindSensitiveVar, reAuthScheme),
	keyed(KindSensitiveVar, names, exemptGeneric),
}

func shape(k Kind, expr string) rule {
	return rule{kind: k, re: regexp.MustCompile(expr)}
}

// keyed builds a rule for keys named by keyNames (case-insensitive, whole
// key), quoted, single-quoted, escaped-quoted or bare.
func keyed(k Kind, keyNames string, exempt func(key, value string) bool) rule {
	n := `(?P<k>` + keyNames + `)`
	expr := `(?i)` + keyPrefix + `(?:"` + n + `"` + sepAny + `|'` + n + `'` + sepAny +
		`|\\"` + n + `\\"` + sepAny + `|` + n + sepBare + `)`
	return rule{kind: k, re: regexp.MustCompile(expr), keyed: true, exempt: exempt}
}

func (ru rule) candidates(s string) []candidate {
	var out []candidate
	skip := 0 // keyed: end of the last non-exempt value; nested keys are redundant
	for _, loc := range ru.re.FindAllStringSubmatchIndex(s, -1) {
		if !ru.keyed {
			st, en := span(ru.re, loc, "v")
			out = append(out, candidate{start: st, end: en})
			continue
		}
		if loc[0] < skip { // ancre M20
			continue
		}
		vs := loc[1]
		vloc := valueRe.FindStringSubmatchIndex(s[vs:])
		if vloc == nil {
			continue
		}
		st, en := span(valueRe, vloc, "v")
		st, en = vs+st, vs+en
		ks, ke := span(ru.re, loc, "k")
		exempt := ru.exempt != nil && ru.exempt(s[ks:ke], s[st:en])
		if !exempt {
			skip = en
		}
		out = append(out, candidate{start: st, end: en, exempt: exempt}) // ancre M5
	}
	return out
}

// span returns the bounds of the first participating group named name, or
// those of the whole match.
func span(re *regexp.Regexp, loc []int, name string) (int, int) {
	for i, n := range re.SubexpNames() {
		if n == name && loc[2*i] >= 0 {
			return loc[2*i], loc[2*i+1]
		}
	}
	return loc[0], loc[1]
}

var (
	reKeyword   = regexp.MustCompile(`(?i)^(?:true|false|null|nil|none|yes|no|on|off)$`)
	reSmallInt  = regexp.MustCompile(`^[0-9]{1,9}$`) // ancre M8
	reQuantity  = regexp.MustCompile(`(?i)len|min|max|count|age|days|ttl|expir|reuse|size|limit|attempts|retries|timeout|rotation|version|port|tokens`)
	reReference = regexp.MustCompile(`^(?:(?:var|local|data|module)\.[A-Za-z0-9_.\[\]*-]+|\$\{[^{}]+\}|\$[A-Za-z_][A-Za-z0-9_]*|\$?\{\{[^{}]*\}\})$`)
	reNameKey   = regexp.MustCompile(`(?i:(?:^|[_.-])(?:name|arn|ref|url|uri|endpoint|path|file|policy|version|type))$|(?:Name|Arn|Ref|Url|Uri|Endpoint|Path|File|Policy|Version|Type)$`) // ancre M9
)

// exemptGeneric reports whether the value of a generic sensitive key is not a
// secret (rules E1 to E4 of docs/plans/M0-redaction.md, section 5.4).
func exemptGeneric(key, value string) bool {
	if len(value) > maxExempt {
		return false
	}
	return reKeyword.MatchString(value) || // E1
		(reSmallInt.MatchString(value) && reQuantity.MatchString(key)) || // E2, ancre M7
		reReference.MatchString(value) || // E3
		reNameKey.MatchString(key) // E4
}

// placeholderRe matches the placeholders of the known kinds.
var placeholderRe = regexp.MustCompile(`\[REDACTED:(?:` + kindAlternatives() + `)\]`)

func kindAlternatives() string {
	quoted := make([]string, len(allKinds))
	for i, k := range allKinds {
		quoted[i] = regexp.QuoteMeta(string(k))
	}
	return strings.Join(quoted, "|")
}
```

Faits du moteur `regexp` de Go sur lesquels repose ce code, à confirmer sur la copie scratch (section 7.8) : noms de groupe répétés acceptés (`(?P<v>a)|(?P<v>b)`, documenté par `Regexp.SubexpIndex`) ; sémantique « le plus à gauche, puis la première alternative » (d'où l'ordre des alternatives de `rePEM` et de `valueRe`) ; bornes de répétition au plus 1000 ; `\s` = `[\t\n\f\r ]`.

Lint anticipé : noms de constantes et de variables choisis pour ne contenir ni `secret`, `token`, `pass`, `pw`, `cred`, `apikey`, `bearer` (motif de noms de gosec G101), hors les 16 constantes imposées par la fiche dont les valeurs sont des mots courts de faible entropie ; `errcheck` exclut par défaut `(*strings.Builder).WriteString` ; aucune directive `nolint`. Si G101 signale malgré tout une constante `Kind`, repli sans `nolint` : écrire la valeur sous forme de conversion `Kind("aws_secret_key")` (G101 n'examine que les littéraux), consigné dans `docs/STATUS.md`.

### 5.3 Table des règles, par priorité décroissante

La priorité ne décide que de l'étiquette d'un masque issu de candidats qui se chevauchent (P5). Principe : **le contexte le plus spécifique gagne** (armure PEM, clé nommée d'un fournisseur), puis les formes de jeton, puis les formes génériques.

| Prio | Kind | Type | Ce qui est reconnu | Portée masquée |
|---|---|---|---|---|
| 0 | `private_key` | forme | en-tête PEM de clé privée (RSA, EC, OPENSSH, DSA, ENCRYPTED, PKCS#8, PGP `BLOCK`), lignes `Proc-Type` et `DEK-Info`, corps base64 avec sauts de ligne réels ou échappés `\n`, pied facultatif (clé tronquée) | tout le bloc |
| 1 | `kubeconfig_credential` | clé exacte | `client-key-data`, `token`, `id-token`, `refresh-token` | valeur |
| 2 | `aws_secret_key` | clé exacte | `aws_secret_access_key`, `secret_access_key`, `SecretAccessKey`, `aws_secret_key` | valeur |
| 3 | `aws_session_token` | clé exacte | `aws_session_token`, `SessionToken`, `aws_security_token`, `X-Amz-Security-Token`, `X-Amz-Signature` (URL présignée) | valeur |
| 4 | `aws_session_token` | forme | préfixes STS `IQoJb3JpZ2lu`, `FwoGZXIvYXdz` suivis d'au moins 50 caractères base64 | jeton |
| 5 | `azure_secret` | clé exacte | `client_secret`, `clientSecret`, `ARM_CLIENT_SECRET`, `azure_client_secret`, `secretText` | valeur |
| 6 | `azure_secret` | forme | `AccountKey=` et `SharedAccessKey=` (chaîne de connexion), `?sig=` ou `&sig=` (SAS), secret Entra `xxx8Q~...` | valeur ou jeton |
| 7 | `scaleway_key` | clé exacte | `SCW_SECRET_KEY`, `scaleway_secret_key` | valeur |
| 8 | `scaleway_key` | forme | `SCW` suivi de 17 majuscules ou chiffres | jeton |
| 9 | `ovh_credential` | clé exacte | `application_key`, `application_secret`, `consumer_key`, avec ou sans `ovh_` | valeur |
| 10 | `ipsec_psk` | clé exacte | `psk`, `pre_shared_key`, `preshared_key`, `tunnelN_preshared_key`, `shared_key`, `ike_psk` | valeur |
| 11 | `ipsec_psk` | forme | ligne strongSwan `... : PSK "valeur"` | valeur |
| 12 | `aws_access_key` | forme | `AKIA` ou `ASIA` suivis de 16 majuscules ou chiffres | jeton |
| 13 | `github_token` | forme | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` et 36 à 255 alphanumériques ; `github_pat_` et 22 à 255 | jeton |
| 14 | `gitlab_token` | forme | `glpat-`, `gldt-`, `glptt-`, `glrt-`, `glcbt-`, `gloas-` et au moins 20 caractères | jeton |
| 15 | `slack_token` | forme | `xoxa-`, `xoxb-`, `xoxe-`, `xoxo-`, `xoxp-`, `xoxr-`, `xoxs-` et au moins 10 caractères ; URL de webhook `hooks.slack.com` | jeton |
| 16 | `llm_api_key` | forme | `sk-ant-` et au moins 20 caractères ; `sk-` précédé d'une frontière et suivi d'au moins 20 caractères | jeton |
| 17 | `private_key` | forme | base64 d'une armure PEM (`LS0tLS1CRUdJTi...`) | jeton |
| 18 | `db_connection_string` | forme | `postgres`, `postgresql`, `mysql`, `mariadb`, `mongodb`, `mongodb+srv`, `redis`, `rediss`, `amqp`, `amqps`, `sqlserver`, `mssql`, `clickhouse`, `cockroachdb`, `jdbc:<x>` suivis de `://user:mot@` | mot de passe |
| 19 | `url_credentials` | forme | tout schéma `://user:mot@` | mot de passe |
| 20 | `sensitive_variable` | forme | en-tête `Authorization` ou `Proxy-Authorization` (`:` ou `=`, clé entre guillemets admise), schéma facultatif (`Bearer`, `Basic`, `Token`, `Digest`, `Negotiate`, `NTLM`, `AWS4-HMAC-SHA256`) | reste de la valeur jusqu'au guillemet, à la barre oblique inverse ou à la fin de ligne |
| 21 | `sensitive_variable` | forme | `Bearer` suivi d'au moins 16 caractères de jeton | jeton |
| 22 | `sensitive_variable` | clé générique | P6, avec exemptions E1 à E4 | valeur |

Mise en correspondance avec les 12 lignes du fichier de référence (vérifiée par `TestEveryPatternLineMapped`) :

| Ligne | Début de la ligne à puce | Kinds exigés, chacun avec au moins un cas positif sur cette ligne |
|---|---|---|
| 1 | `Clés d'accès AWS` | `aws_access_key`, `aws_secret_key` |
| 2 | `Jetons de session AWS` | `aws_session_token` |
| 3 | `Secrets de service principal Azure` | `azure_secret` |
| 4 | `Clés API Scaleway` | `scaleway_key`, `ovh_credential` |
| 5 | `Clés privées PEM` | `private_key` |
| 6 | `Jetons GitHub` | `github_token`, `gitlab_token`, `slack_token` |
| 7 | `Clés API LLM` | `llm_api_key` |
| 8 | `Mots de passe dans des URL` | `url_credentials` |
| 9 | `Chaînes de connexion de bases` | `db_connection_string` |
| 10 | `Kubeconfig` | `kubeconfig_credential` |
| 11 | `Valeurs de variables nommées` | `sensitive_variable` |
| 12 | `Clés pré-partagées IPsec` | `ipsec_psk` |

Les 16 `Kind` sont couverts, chacun par au moins une ligne.

### 5.4 Clés, valeurs et exemptions (tranché)

- **Préfixe de clé** : début du texte, blanc, `"`, `'`, accent grave, `{`, `}`, `(`, `[`, `,`, `;`, `?`, `&`, `|`, `>`, `$`, ou séquence échappée `\n`, `\r`, `\t` (JSON). `:` et `]` sont **exclus** : ni l'intérieur d'un ARN ni celui d'un placeholder ne commencent une clé.
- **Clé nue suivie de `:`** : au moins une espace ou tabulation après `:` ; sinon ce n'est pas un couple clé et valeur (`password:hunter2` n'est pas masqué, ligne L2 de la section 5.8).
- **Valeur vide** (`password = ""`, `password:` en fin de ligne) : aucun masque.
- **Valeur nue** : s'arrête aux délimiteurs de P7 ; ce qui suit n'est pas masqué (ligne L3). Une valeur nue ne commence ni par `|` (indicateur de bloc YAML) ni par `\` (échappement JSON), ce qui évite les faux positifs dans du JSON sérialisé (section 5.6).
- **Bloc YAML** : lignes suivantes indentées, jusqu'à la première ligne non indentée ; la première indentation reste hors du masque. Continuation reconnue par la seule présence d'une indentation : une clé sœur plus indentée que la clé parente est absorbée (sur-masquage accepté, ligne L3).
- **Exemptions E1 à E4** (P8), seulement pour la règle générique ; jamais pour une clé de fournisseur (`token: 1024` exact reste masqué au titre de `kubeconfig_credential`). Contamination : un groupe qui contient un candidat exempté et un candidat non exempté est masqué en entier (union).
- **Table exacte de ce qui n'est pas masqué** : `negativeCases` (section 7.2), 22 cas ; table des quasi-exemptions masquées : `narrowCases`, 12 cas.

### 5.5 Positions, chevauchements, priorité : résumé

| Question | Réponse |
|---|---|
| Unité de `Start`, `End` | octets de l'entrée d'origine, `[Start, End)` |
| Ordre des `Match` | croissant, disjoints ; deux masques peuvent se toucher |
| Clé seule | jamais masquée ; la valeur l'est |
| Jeton dans une valeur sensible (`password: "ghp_..."`) | un masque, étiquette `github_token` (prio 13 avant 22) |
| URL de base dans une valeur sensible (`password=postgres://u:p@h/db`) | un masque sur toute la valeur (union), étiquette `db_connection_string` |
| Armure PEM qui commence dans une valeur et la dépasse | union : tout le bloc, étiquette `private_key` |
| Même portée trouvée par deux règles | un masque, étiquette de la plus prioritaire |
| Valeur exemptée seule | aucun masque |

### 5.6 Idempotence et JSON sérialisé : pourquoi c'est garanti

1. Un placeholder connu est protégé : tout candidat entièrement couvert par des placeholders est ignoré (`covered`).
2. Aucun caractère d'un placeholder (`[`, lettres, `_`, `:`, `]`) ne peut créer un nouveau candidat : `:` et `]` ne sont pas des préfixes de clé ; les formes à frontière (`boundary`) excluent `]` ; les classes des formes de jeton excluent `[`, `]`, `:` ; `REDACTED` n'est pas une clé sensible.
3. Une valeur exemptée qui contient un jeton reconnaissable est masquée en entier (contamination) : sa forme exemptée ne réapparaît jamais à moitié masquée.
4. Toute valeur non exemptée est masquée en entier, et les clés imbriquées dans une valeur déjà masquée sont redondantes.

Conséquence vérifiée par `TestIdempotent` : `Redact(Redact(x)) == Redact(x)` et la seconde passe rend zéro match, sur les 105 fixtures et sur le potage aléatoire (section 7.5).

JSON sérialisé : T12 inspecte des corps JSON qui contiennent du texte déjà rédigé. `json.Marshal` ajoute `\"`, `\n`, `\u003c` ; le rédacteur reconnaît les clés précédées de `\n` échappé, les clés et valeurs entre `\"`, les blocs YAML échappés, et une valeur nue s'arrête à toute barre oblique inverse. Donc `ContainsSecret(json(Redact(x)))` est faux, prouvé par `TestRedactedOutputStaysCleanWhenJSONEncoded` avec et sans échappement HTML. Un seul niveau d'échappement est garanti (ligne L4).

### 5.7 Coût et taille (tranché)

- `regexp` de Go (RE2) garantit un temps linéaire **par recherche** ; `FindAll` enchaîne des recherches à partir de la fin de la précédente. Aucune règle ne contient de `.*` ni de `(?s)` (critère 17) : chaque classe répétée s'arrête sur un délimiteur, ce qui borne le travail au-delà de la fin d'une correspondance.
- Règles par clé : les clés sont trouvées par `FindAll` sans consommer les valeurs ; chaque valeur est lue par une expression ancrée. Une clé qui commence dans une valeur non exemptée déjà lue est ignorée (`skip`), sans perte (le masque externe la couvre). Une valeur exemptée fait au plus 256 octets. Le travail total reste linéaire, à une constante près.
- Borne de taille : aucune dans `redact` (P10) ; T11 refuse une requête de plus de 1 Mio de texte (section 5.9).
- Preuve empirique : `TestLargeInputAdversarial`, 8 entrées de 160 à 320 Kio construites pour maximiser les reprises (en-têtes PEM sans pied, schémas sans `@`, identifiant géant, clés imbriquées), sous `-timeout 120s` ; durées consignées dans `docs/STATUS.md`. La mutation M20 (suppression de `skip`) doit faire dépasser ce délai.

### 5.8 Ce que le rédacteur ne garantit pas (à documenter dans `docs/STATUS.md` et à reporter à la menace proposée en section 12)

| # | Limite | Exemple de forme (sans valeur réelle) |
|---|---|---|
| L1 | Secret à forme libre sans clé nommée ni forme reconnaissable | prose « le mot de passe est ... », argument `--password x` ou `-p x` sans `=`, mot de passe collé à `-p` |
| L2 | Syntaxes clé et valeur non couvertes | clé nue suivie de `:` sans espace ; élément XML `<password>...</password>` ; heredoc HCL `<<EOT` (sauf clé PEM à l'intérieur) |
| L3 | Valeur nue coupée à un délimiteur (blanc, `,`, `;`, `&`, `{`, `}`, `<`, `>`, guillemet, barre oblique inverse) : le reste n'est pas masqué ; bloc YAML délimité par l'indentation seule | `password: abc;def` masque `abc` seulement |
| L4 | Encodages et transformations | base64, hexadécimal, encodage URL, JSON échappé deux fois (`\\\"`), `\u` Unicode, homoglyphes, caractères de largeur nulle dans un jeton, secret réparti sur plusieurs champs ou lignes |
| L5 | Secret sous une clé non parlante | valeurs `data:` d'un `Secret` Kubernetes sous `db-conn`, attributs `sensitive` d'un état Terraform, `Cookie` et `Set-Cookie`, JWT isolé, identifiant réduit à un nom d'utilisateur (`https://jeton@hôte`), mot de passe d'URL contenant `/`, `?` ou `#` non encodés, fichiers PuTTY, PKCS#12, JKS |
| L6 | `sk-` collé à un caractère de mot ou à `]` précédent | `xsk-...` |
| L7 | Étiquette heuristique : le `Kind` d'un masque dépend de la priorité, pas d'une analyse du document | `shared_key` d'un compte de stockage étiqueté `ipsec_psk` |
| L8 | Exemptions : un vrai secret passe s'il est un mot-clé, 1 à 9 chiffres sous une clé de quantité, une chaîne en forme de référence, ou la valeur d'une clé finissant par `name`, `arn`, `url`, etc. | `api_key_name: ...` |
| L9 | Guillemets croisés et valeurs imbriquées pathologiques dans une valeur déjà masquée | sans cas réaliste connu |
| L10 | IP publiques et identifiants de ressources : non masqués | M1 (minimisation, pseudonymisation) |

### 5.9 Contraintes pour les consommateurs (à reporter dans leurs plans)
- **T11 (`llm.Client`)** : `Redact` sur chaque `Part.Text` et `UntrustedBlock.Content` avant `RenderUntrusted` et avant tout appel ; `Trace.Redactions` = somme des `len(matches)` ; aucune journalisation du texte d'origine ni d'un extrait autour d'un `Match` ; `RequestHash` calculé sur la requête **rédigée** (un hachage de requête contenant un secret court permettrait de le confirmer par force brute) ; refus typé (`ErrRequestTooLarge`, à nommer par T11) de toute requête dont le texte dépasse 1 Mio avant rédaction, jamais de troncature. Les prompts système versionnés (T09) sont vérifiés par un test : `ContainsSecret(System)` faux pour chaque prompt embarqué.
- **T12** : `TestNoSecretInOutgoingRequest` applique `redact.New().ContainsSecret` au corps HTTP capturé ; la cohérence avec un niveau de sérialisation JSON est garantie par `TestRedactedOutputStaysCleanWhenJSONEncoded`. Les champs de l'enveloppe du SDK (`max_tokens`, schéma de sortie) ne déclenchent aucune règle : `max_tokens` relève d'E2, et un schéma JSON a des objets pour valeurs. Toute clé d'enveloppe nouvelle qui déclencherait une règle se traite dans T12, pas par une exemption ajoutée ici.
- **M1** : rédaction structurée des documents connus (L5), evals du taux de faux positifs, masquage des IP publiques ; toute nouvelle ligne de `redaction-patterns.md` impose une nouvelle entrée dans `referenceLines` et au moins un cas positif (le test échoue sinon).

---

## 6. Flux de données

```
texte (prompt partiel, donnée cloud non fiable, journal, manifeste)
  -> placeholderRe : placeholders déjà présents (protégés)
  -> 23 règles évaluées sur le texte d'origine
       formes : FindAll, portée = groupe v ou correspondance entière
       clés : FindAll des clés, puis valueRe ancrée ; exemptions E1 à E4 (règle générique)
  -> candidats couverts par des placeholders : ignorés
  -> fusion : union des chevauchements stricts, Kind de plus haute priorité non exemptée
  -> []Match (octets, triés, disjoints, sans valeur)
  -> Redact : reconstruction avec Placeholder(Kind) ; ContainsSecret : len(matches) > 0
  -> T11 : requête rédigée -> RenderUntrusted -> fournisseur ; Trace.Redactions
```

Aucun état global mutable, aucune entrée-sortie, aucun journal émis par le paquet.

---

## 7. Tests (phase tests, subagent `test-author`)

### 7.1 Règles communes
- `package redact`, **API exportée uniquement** (`New`, `Redact`, `ContainsSecret`, `Kinds`, `Placeholder`, `Match`, constantes `Kind`) : aucun accès à `rules`, `find`, `valueRe` (critère 9). Imports : bibliothèque standard ; `pgregory.net/rapid` dans `property_test.go` seulement.
- Sous-tests en `snake_case` minuscule, messages en anglais qui nomment le cas ; pas de `t.Skip` ; rien n'est sauté sous `-short` ; les tables vérifient l'unicité de leurs noms.
- Assertions de type avec `ok` ; erreurs d'encodage vérifiées ; goroutines par `sync.WaitGroup.Go`, `t.Errorf` seulement dans les goroutines.
- **Fixtures et garde** :
  - F1 : toute fixture qui ressemble à un secret contient `EXAMPLE` ou `FAKE` **dans la chaîne**, sauf si le format l'interdit (UUID hexadécimal de Scaleway : valeur manifestement factice `11111111-2222-4333-8444-555555555555`). Fixtures canoniques : `AKIAIOSFODNN7EXAMPLE` et `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` (exemples publiés par la documentation AWS), `ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000` (36 caractères, somme de contrôle invalide : jamais un jeton réel), `glpat-FAKEEXAMPLE000000000`, `sk-ant-api03-FAKEEXAMPLE0000000000000000`, `xoxb-FAKE-0000000000-EXAMPLE`, en-têtes PEM immédiatement suivis de `FAKE...` (ou précédés de `FAKE\n` quand des lignes `Proc-Type` suivent l'en-tête).
  - F2 : les fixtures ne sont **jamais** affectées à une variable ou à une constante (`x := "..."`), seulement écrites comme champs des littéraux composites des tables : gosec G101 n'examine que les affectations et déclarations.
  - F3 : le rédacteur n'exempte aucun marqueur (P12) : une fixture marquée doit être masquée.
  - F4 : génération à l'exécution **seulement** dans `property_test.go`, et seulement pour des corps aléatoires : `rapid.StringMatching` avec une expression dont le texte ne déclenche pas la garde (préfixe suivi d'une classe, par exemple `gh[pousr]_[A-Za-z0-9]{36}`, `(AKIA|ASIA)[A-Z0-9]{16}`), ou `fmt.Sprintf` d'un format sans corps (`"-----BEGIN %sPRIVATE KEY-----%s%s"`) appliqué à des corps tirés par `rapid`. C'est légitime : aucune valeur fixe n'existe dans le dépôt, la valeur n'existe qu'en mémoire pendant le test, et la garde protège le dépôt contre des secrets réels, pas contre des formes. Interdit partout : reconstituer un secret fixe par concaténation, `strings.Repeat` ou `fmt.Sprintf` de morceaux littéraux (critères 13 et 13 bis).
- Aides de `cases_test.go` : `rebuild(in string, ms []Match) string` (reconstruction par P3) ; `kindsOf(ms []Match) []Kind` ; `allFixtures() []string` (entrées de toutes les tables et `idempotentCases`, puis les sorties attendues).

### 7.2 `cases_test.go` : tables normatives

Les chaînes ci-dessous sont à reprendre à l'octet près. Guillemets obliques (accents graves) : chaînes brutes, dont les `\n` sont deux caractères (JSON échappé) ; guillemets droits : chaînes interprétées.

```go
type posCase struct {
	name  string // l<NN>_<snake_case>, NN = line of redaction-patterns.md
	line  int
	in    string
	want  string
	kinds []Kind
}

var positiveCases = []posCase{
	// Line 1: AWS access keys and associated secrets.
	{"l01_aws_access_key_bare", 1,
		"AKIAIOSFODNN7EXAMPLE",
		"[REDACTED:aws_access_key]",
		[]Kind{KindAWSAccessKey}},
	{"l01_aws_sts_key_id_json", 1,
		`{"AccessKeyId": "ASIAIOSFODNN7EXAMPLE"}`,
		`{"AccessKeyId": "[REDACTED:aws_access_key]"}`,
		[]Kind{KindAWSAccessKey}},
	{"l01_aws_credentials_ini", 1,
		"[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"[default]\naws_access_key_id = [REDACTED:aws_access_key]\naws_secret_access_key = [REDACTED:aws_secret_key]",
		[]Kind{KindAWSAccessKey, KindAWSSecretKey}},
	{"l01_aws_secret_key_env", 1,
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_SECRET_ACCESS_KEY=[REDACTED:aws_secret_key]",
		[]Kind{KindAWSSecretKey}},
	{"l01_aws_secret_key_json", 1,
		`{"SecretAccessKey":"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}`,
		`{"SecretAccessKey":"[REDACTED:aws_secret_key]"}`,
		[]Kind{KindAWSSecretKey}},
	{"l01_aws_secret_key_env_json_escaped", 1,
		`{"env":"DEBUG=1\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"}`,
		`{"env":"DEBUG=1\nAWS_SECRET_ACCESS_KEY=[REDACTED:aws_secret_key]\n"}`,
		[]Kind{KindAWSSecretKey}},
	{"l01_two_tokens_one_line", 1,
		"AKIAIOSFODNN7EXAMPLE,ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000",
		"[REDACTED:aws_access_key],[REDACTED:github_token]",
		[]Kind{KindAWSAccessKey, KindGitHubToken}},

	// Line 2: AWS session tokens.
	{"l02_aws_session_token_env", 2,
		"AWS_SESSION_TOKEN=IQoJb3JpZ2luX2VjEXAMPLE0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH",
		"AWS_SESSION_TOKEN=[REDACTED:aws_session_token]",
		[]Kind{KindAWSSessionToken}},
	{"l02_aws_session_token_shape", 2,
		"issued IQoJb3JpZ2luX2VjEXAMPLE0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH for 1h",
		"issued [REDACTED:aws_session_token] for 1h",
		[]Kind{KindAWSSessionToken}},
	{"l02_aws_presigned_url", 2,
		"https://fake-bucket.s3.amazonaws.com/o?X-Amz-Security-Token=FwoGZXIvYXdzEXAMPLE&X-Amz-Signature=FAKE0123456789abcdef",
		"https://fake-bucket.s3.amazonaws.com/o?X-Amz-Security-Token=[REDACTED:aws_session_token]&X-Amz-Signature=[REDACTED:aws_session_token]",
		[]Kind{KindAWSSessionToken, KindAWSSessionToken}},

	// Line 3: Azure.
	{"l03_azure_storage_connection_string", 3,
		"DefaultEndpointsProtocol=https;AccountName=fakeaccount;AccountKey=FAKEEXAMPLE0000000000000000000000000000000000==;EndpointSuffix=core.windows.net",
		"DefaultEndpointsProtocol=https;AccountName=fakeaccount;AccountKey=[REDACTED:azure_secret];EndpointSuffix=core.windows.net",
		[]Kind{KindAzureSecret}},
	{"l03_azure_sas_url", 3,
		"https://fakeaccount.blob.core.windows.net/c/b.txt?sv=2022-11-02&sp=r&se=2026-12-31T00:00:00Z&sig=FAKEEXAMPLE0000000000000000000000000000%3D",
		"https://fakeaccount.blob.core.windows.net/c/b.txt?sv=2022-11-02&sp=r&se=2026-12-31T00:00:00Z&sig=[REDACTED:azure_secret]",
		[]Kind{KindAzureSecret}},
	{"l03_azure_client_secret_tfvars", 3,
		`client_secret = "abc8Q~FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00"`,
		`client_secret = "[REDACTED:azure_secret]"`,
		[]Kind{KindAzureSecret}},
	{"l03_azure_client_secret_shape", 3,
		"rotated to abc8Q~FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE00 today",
		"rotated to [REDACTED:azure_secret] today",
		[]Kind{KindAzureSecret}},

	// Line 4: Scaleway and OVHcloud.
	{"l04_scaleway_access_key_shape", 4,
		"SCWFAKEEXAMPLE000000",
		"[REDACTED:scaleway_key]",
		[]Kind{KindScalewayKey}},
	{"l04_scaleway_secret_key_env", 4,
		"SCW_SECRET_KEY=11111111-2222-4333-8444-555555555555",
		"SCW_SECRET_KEY=[REDACTED:scaleway_key]",
		[]Kind{KindScalewayKey}},
	{"l04_scaleway_provider_hcl", 4,
		"provider \"scaleway\" {\n  access_key = \"SCWFAKEEXAMPLE000000\"\n  secret_key = \"11111111-2222-4333-8444-555555555555\"\n}",
		"provider \"scaleway\" {\n  access_key = \"[REDACTED:scaleway_key]\"\n  secret_key = \"[REDACTED:sensitive_variable]\"\n}",
		[]Kind{KindScalewayKey, KindSensitiveVar}},
	{"l04_ovh_env", 4,
		"OVH_APPLICATION_SECRET=FAKEovhEXAMPLEsecret0000",
		"OVH_APPLICATION_SECRET=[REDACTED:ovh_credential]",
		[]Kind{KindOVHCredential}},
	{"l04_ovh_provider_hcl", 4,
		"provider \"ovh\" {\n  endpoint           = \"ovh-eu\"\n  application_key    = \"FAKEovhappkey000\"\n  application_secret = \"FAKEovhappsecret0000000000000000\"\n  consumer_key       = \"FAKEovhconsumerkey00000000000000\"\n}",
		"provider \"ovh\" {\n  endpoint           = \"ovh-eu\"\n  application_key    = \"[REDACTED:ovh_credential]\"\n  application_secret = \"[REDACTED:ovh_credential]\"\n  consumer_key       = \"[REDACTED:ovh_credential]\"\n}",
		[]Kind{KindOVHCredential, KindOVHCredential, KindOVHCredential}},

	// Line 5: PEM private keys.
	{"l05_pem_rsa", 5,
		"-----BEGIN RSA PRIVATE KEY-----\nFAKEKEYEXAMPLEMIIEpAIBAAKCAQEA0000\n00000000000000000000000000000000\n-----END RSA PRIVATE KEY-----\ndone",
		"[REDACTED:private_key]\ndone",
		[]Kind{KindPrivateKey}},
	{"l05_pem_openssh", 5,
		"-----BEGIN OPENSSH PRIVATE KEY-----\nFAKEb3BlbnNzaC1rZXktdjEAAAAAEXAMPLE\n-----END OPENSSH PRIVATE KEY-----",
		"[REDACTED:private_key]",
		[]Kind{KindPrivateKey}},
	{"l05_pem_encrypted_headers", 5,
		"FAKE\n-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,FAKE0000000000000000000000000000\n\nFAKEEXAMPLEbase64body0000\n-----END RSA PRIVATE KEY-----",
		"FAKE\n[REDACTED:private_key]",
		[]Kind{KindPrivateKey}},
	{"l05_pem_json_escaped_no_key", 5,
		`{"log":"-----BEGIN RSA PRIVATE KEY-----\nFAKEEXAMPLEMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"}`,
		`{"log":"[REDACTED:private_key]\n"}`,
		[]Kind{KindPrivateKey}},
	{"l05_gcp_service_account_json", 5,
		`{"type": "service_account", "private_key_id": "FAKE0123456789abcdef", "private_key": "-----BEGIN PRIVATE KEY-----\nFAKEEXAMPLEMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----\n", "client_email": "fake@example.iam.gserviceaccount.com"}`,
		`{"type": "service_account", "private_key_id": "[REDACTED:sensitive_variable]", "private_key": "[REDACTED:private_key]", "client_email": "fake@example.iam.gserviceaccount.com"}`,
		[]Kind{KindSensitiveVar, KindPrivateKey}},
	{"l05_pem_truncated", 5,
		"-----BEGIN EC PRIVATE KEY-----\nFAKEEXAMPLEMHcCAQEEIA0000",
		"[REDACTED:private_key]",
		[]Kind{KindPrivateKey}},
	{"l05_pem_key_after_certificate", 5,
		"-----BEGIN CERTIFICATE-----\nFAKECERTMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nFAKEEXAMPLEMIIEvQIBADANBgkqhkiG\n-----END PRIVATE KEY-----",
		"-----BEGIN CERTIFICATE-----\nFAKECERTMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n[REDACTED:private_key]",
		[]Kind{KindPrivateKey}},
	{"l05_pem_base64_encoded", 5,
		"tls.key: LS0tLS1CRUdJTiBGQUtFIEVYQU1QTEUgS0VZLS0tLS0K",
		"tls.key: [REDACTED:private_key]",
		[]Kind{KindPrivateKey}},

	// Line 6: GitHub, GitLab, Slack tokens.
	{"l06_github_classic", 6,
		"ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000",
		"[REDACTED:github_token]",
		[]Kind{KindGitHubToken}},
	{"l06_github_fine_grained_git_url", 6,
		"https://x-access-token:github_pat_FAKE000000000000000000_EXAMPLE0000000000000000000000000000000000000000000000000000000000000@github.com/o/r.git",
		"https://x-access-token:[REDACTED:github_token]@github.com/o/r.git",
		[]Kind{KindGitHubToken}},
	{"l06_gitlab_header", 6,
		"PRIVATE-TOKEN: glpat-FAKEEXAMPLE000000000",
		"PRIVATE-TOKEN: [REDACTED:gitlab_token]",
		[]Kind{KindGitLabToken}},
	{"l06_slack_bot_token_yaml", 6,
		"slack:\n  bot_token: xoxb-FAKE-0000000000-EXAMPLE",
		"slack:\n  bot_token: [REDACTED:slack_token]",
		[]Kind{KindSlackToken}},
	{"l06_slack_webhook", 6,
		"webhook: https://hooks.slack.com/services/fake-example/placeholder-path",
		"webhook: [REDACTED:slack_token]",
		[]Kind{KindSlackToken}},
	{"l06_adjacent_tokens_no_separator", 6,
		"AKIAIOSFODNN7EXAMPLEghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000",
		"[REDACTED:aws_access_key][REDACTED:github_token]",
		[]Kind{KindAWSAccessKey, KindGitHubToken}},

	// Line 7: LLM API keys.
	{"l07_anthropic_key_env", 7,
		"ANTHROPIC_API_KEY=sk-ant-api03-FAKEEXAMPLE0000000000000000",
		"ANTHROPIC_API_KEY=[REDACTED:llm_api_key]",
		[]Kind{KindLLMAPIKey}},
	{"l07_openai_key_json", 7,
		`{"api_key":"sk-proj-FAKEEXAMPLE000000000000"}`,
		`{"api_key":"[REDACTED:llm_api_key]"}`,
		[]Kind{KindLLMAPIKey}},
	{"l07_llm_key_in_prose", 7,
		"use sk-FAKEEXAMPLE0000000000000 for tests",
		"use [REDACTED:llm_api_key] for tests",
		[]Kind{KindLLMAPIKey}},

	// Line 8: passwords in URLs.
	{"l08_url_basic_auth", 8,
		"https://admin:FAKEpassw0rd@registry.example.com/v2/",
		"https://admin:[REDACTED:url_credentials]@registry.example.com/v2/",
		[]Kind{KindURLCredentials}},
	{"l08_url_in_yaml", 8,
		`mirror: "ftp://mirror:FAKEftppass@ftp.example.org/pub"`,
		`mirror: "ftp://mirror:[REDACTED:url_credentials]@ftp.example.org/pub"`,
		[]Kind{KindURLCredentials}},

	// Line 9: database connection strings.
	{"l09_postgres_url_env", 9,
		"DATABASE_URL=postgres://app:FAKEdbpass@db.internal:5432/app?sslmode=require",
		"DATABASE_URL=postgres://app:[REDACTED:db_connection_string]@db.internal:5432/app?sslmode=require",
		[]Kind{KindDBConnString}},
	{"l09_mongodb_srv", 9,
		"mongodb+srv://root:FAKEmongoEXAMPLE@cluster0.example.mongodb.net/admin",
		"mongodb+srv://root:[REDACTED:db_connection_string]@cluster0.example.mongodb.net/admin",
		[]Kind{KindDBConnString}},
	{"l09_jdbc_query_password", 9,
		"jdbc:mysql://db.example.com:3306/app?user=app&password=FAKEjdbcpass",
		"jdbc:mysql://db.example.com:3306/app?user=app&password=[REDACTED:sensitive_variable]",
		[]Kind{KindSensitiveVar}},
	{"l09_ado_connection_string", 9,
		"Server=tcp:fake.database.windows.net,1433;User ID=app;Password=FAKEsqlpass;Encrypt=True",
		"Server=tcp:fake.database.windows.net,1433;User ID=app;Password=[REDACTED:sensitive_variable];Encrypt=True",
		[]Kind{KindSensitiveVar}},

	// Line 10: kubeconfig.
	{"l10_kubeconfig_token", 10,
		"users:\n- name: fake\n  user:\n    token: FAKEEXAMPLEeyJhbGciOiJSUzI1NiJ9.e30.FAKEsig",
		"users:\n- name: fake\n  user:\n    token: [REDACTED:kubeconfig_credential]",
		[]Kind{KindKubeconfig}},
	{"l10_kubeconfig_client_key_data", 10,
		"    client-key-data: LS0tLS1CRUdJTiBGQUtFIEVYQU1QTEUgS0VZLS0tLS0K",
		"    client-key-data: [REDACTED:kubeconfig_credential]",
		[]Kind{KindKubeconfig}},

	// Line 11: values of variables named *password*, *secret*, *token*, *api_key*.
	{"l11_tfvars_password", 11,
		`db_password = "FAKE-hunter2"`,
		`db_password = "[REDACTED:sensitive_variable]"`,
		[]Kind{KindSensitiveVar}},
	{"l11_k8s_secret_string_data", 11,
		"apiVersion: v1\nkind: Secret\nstringData:\n  api_key: FAKEapikey123\n  app_secret: 'FAKE s3cret with spaces'\n",
		"apiVersion: v1\nkind: Secret\nstringData:\n  api_key: [REDACTED:sensitive_variable]\n  app_secret: '[REDACTED:sensitive_variable]'\n",
		[]Kind{KindSensitiveVar, KindSensitiveVar}},
	{"l11_json_nested_camel_case", 11,
		`{"auth": {"refreshToken": "FAKErefreshEXAMPLE"}}`,
		`{"auth": {"refreshToken": "[REDACTED:sensitive_variable]"}}`,
		[]Kind{KindSensitiveVar}},
	{"l11_env_export", 11,
		"export GITHUB_TOKEN=FAKEnotAGitHubShape",
		"export GITHUB_TOKEN=[REDACTED:sensitive_variable]",
		[]Kind{KindSensitiveVar}},
	{"l11_authorization_bearer_curl", 11,
		`curl -H "Authorization: Bearer FAKEbearerEXAMPLE0000" https://api.example.com/v1`,
		`curl -H "Authorization: Bearer [REDACTED:sensitive_variable]" https://api.example.com/v1`,
		[]Kind{KindSensitiveVar}},
	{"l11_authorization_basic_json", 11,
		`{"headers": {"Authorization": "Basic RkFLRTpFWEFNUExF"}}`,
		`{"headers": {"Authorization": "Basic [REDACTED:sensitive_variable]"}}`,
		[]Kind{KindSensitiveVar}},
	{"l11_yaml_block_scalar", 11,
		"password: |\n  FAKE-line-one\n  FAKE-line-two\nuser: admin",
		"password: |\n  [REDACTED:sensitive_variable]\nuser: admin",
		[]Kind{KindSensitiveVar}},
	{"l11_yaml_block_scalar_json_escaped", 11,
		`{"file":"password: |\n  FAKE-line-one\n  FAKE-line-two\nuser: admin"}`,
		`{"file":"password: |\n  [REDACTED:sensitive_variable]\nuser: admin"}`,
		[]Kind{KindSensitiveVar}},
	{"l11_escaped_quotes_in_json_log", 11,
		`{"msg":"set password = \"FAKEhunter2\" on db"}`,
		`{"msg":"set password = \"[REDACTED:sensitive_variable]\" on db"}`,
		[]Kind{KindSensitiveVar}},
	{"l11_json_value_with_escaped_quote", 11,
		`{"password":"FAKE\"quoted\"pass"}`,
		`{"password":"[REDACTED:sensitive_variable]"}`,
		[]Kind{KindSensitiveVar}},

	// Line 12: IPsec pre-shared keys.
	{"l12_aws_vpn_tunnel_psk", 12,
		`tunnel1_preshared_key = "FAKEpskEXAMPLE0000"`,
		`tunnel1_preshared_key = "[REDACTED:ipsec_psk]"`,
		[]Kind{KindIPsecPSK}},
	{"l12_strongswan_ipsec_secrets", 12,
		`203.0.113.1 198.51.100.1 : PSK "FAKEpskEXAMPLE"`,
		`203.0.113.1 198.51.100.1 : PSK "[REDACTED:ipsec_psk]"`,
		[]Kind{KindIPsecPSK}},
	{"l12_azure_vpn_shared_key", 12,
		`shared_key = "FAKEsharedEXAMPLE"`,
		`shared_key = "[REDACTED:ipsec_psk]"`,
		[]Kind{KindIPsecPSK}},
}
```

Répartition : lignes 1 à 12 : 7, 3, 4, 5, 8, 6, 3, 2, 4, 2, 10, 3 cas ; **57 cas**.

```go
var negativeCases = []struct{ name, in string }{
	{"prose_password", "Rotate the database password every 90 days and never reuse a password."},
	{"prose_secret_and_token", "The secret of a good token bucket is its refill rate."},
	{"label_without_value", "password:\nusername: admin"},
	{"empty_quoted_value", `password = ""`},
	{"sha256_hex", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"docker_digest", "image: nginx@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
	{"git_sha1", "commit da39a3ee5e6b4b0d3255bfef95601890afd80709"},
	{"uuid", "resource_id: 123e4567-e89b-42d3-a456-426614174000"},
	{"max_tokens_yaml", "max_tokens: 1024"},
	{"token_usage_json", `{"max_tokens": 1024, "input_tokens": 12, "output_tokens": 345}`},
	{"password_policy_hcl", "minimum_password_length = 14\npassword_reuse_prevention = 24\nmax_password_age = 90"},
	{"boolean_and_null_values", "manage_master_user_password = true\nrequire_secret: false\nsecret_rotation = null"},
	{"hcl_references", "password = var.db_password\nsecret = data.aws_secretsmanager_secret_version.db.secret_string\napi_key = \"${var.api_key}\""},
	{"env_and_template_references", "DB_PASSWORD=$DB_PASSWORD_FROM_VAULT\nclient_token: \"{{ .Values.clientToken }}\"\napi_key: \"${{ secrets.API_KEY }}\""},
	{"secret_names_arns_urls", "secret_name: prod/db\nsecret_arn = \"arn:aws:secretsmanager:eu-west-3:123456789012:secret:prod/db-AbCdEf\"\ntoken_url: https://login.example.com/oauth2/token"},
	{"existing_placeholders", "password: [REDACTED:sensitive_variable]\nAuthorization: Bearer [REDACTED:sensitive_variable]\nurl: https://u:[REDACTED:url_credentials]@example.com"},
	{"sk_and_task_identifiers", "task-0123456789abcdefghijklmnop and sk-short"},
	{"urls_without_password", "https://user@example.com/path and http://example.com:8080/x"},
	{"public_pem_blocks", "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----\n-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----"},
	{"kubernetes_secret_key_ref", "valueFrom:\n  secretKeyRef:\n    name: db\n    key: password"},
	{"short_prefixes", "AKIA1234 ghp_short glpat-short xoxb-1 sk-ant-x"},
	{"iam_policy_json", `{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": "*"}`},
}

var narrowCases = []struct{ name, in, want string }{
	{"x01_numeric_password", "password: 123456", "password: [REDACTED:sensitive_variable]"},
	{"x02_ten_digit_token", "api_token: 1234567890", "api_token: [REDACTED:sensitive_variable]"},
	{"x03_quantity_key_eleven_digits", "token_count = 12345678901", "token_count = [REDACTED:sensitive_variable]"},
	{"x04_quantity_key_non_numeric", "max_tokens: 1024abc", "max_tokens: [REDACTED:sensitive_variable]"},
	{"x05_length_key_text_value", `password_length = "FAKEnotanumber"`, `password_length = "[REDACTED:sensitive_variable]"`},
	{"x06_id_suffix_not_exempt", `secret_id = "FAKEvaultsecretid"`, `secret_id = "[REDACTED:sensitive_variable]"`},
	{"x07_keyword_prefix", `password = "true-FAKE"`, `password = "[REDACTED:sensitive_variable]"`},
	{"x08_partial_interpolation", `password = "${var.x}FAKE"`, `password = "[REDACTED:sensitive_variable]"`},
	{"x09_suffix_not_at_end", "secret_name_FAKE: FAKEvalue", "secret_name_FAKE: [REDACTED:sensitive_variable]"},
	{"x10_reference_containing_token", "password = var.AKIAIOSFODNN7EXAMPLE", "password = [REDACTED:aws_access_key]"},
	{"x11_name_key_containing_token", "secret_name: ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000", "secret_name: [REDACTED:github_token]"},
	{"x12_exact_token_key_numeric", "token: 1024", "token: [REDACTED:kubeconfig_credential]"},
}

var overlapCases = []struct {
	name, in, want string
	kinds          []Kind
}{
	{"o1_token_inside_sensitive_value", `password: "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000"`, `password: "[REDACTED:github_token]"`, []Kind{KindGitHubToken}},
	{"o2_kubeconfig_beats_base64_pem", "client-key-data: LS0tLS1CRUdJTiBGQUtFIEVYQU1QTEUgS0VZLS0tLS0K", "client-key-data: [REDACTED:kubeconfig_credential]", []Kind{KindKubeconfig}},
	{"o3_db_url_inside_sensitive_value", "password=postgres://u:FAKEp@h/db", "password=[REDACTED:db_connection_string]", []Kind{KindDBConnString}},
	{"o4_llm_key_inside_sensitive_value", `api_key = "sk-ant-api03-FAKEEXAMPLE0000000000000000"`, `api_key = "[REDACTED:llm_api_key]"`, []Kind{KindLLMAPIKey}},
	{"o5_keyed_aws_secret_beats_shape", "aws_secret_access_key = AKIAIOSFODNN7EXAMPLE", "aws_secret_access_key = [REDACTED:aws_secret_key]", []Kind{KindAWSSecretKey}},
	{"o6_pem_inside_hcl_string", `private_key = "-----BEGIN RSA PRIVATE KEY-----\nFAKEEXAMPLE\n-----END RSA PRIVATE KEY-----"`, `private_key = "[REDACTED:private_key]"`, []Kind{KindPrivateKey}},
	{"o7_union_extends_past_value", "password=x-----BEGIN RSA PRIVATE KEY-----\nFAKEEXAMPLE0000\n-----END RSA PRIVATE KEY-----", "password=[REDACTED:private_key]", []Kind{KindPrivateKey}},
}

// idempotentCases are inputs whose first redaction must be stable.
var idempotentCases = []string{
	"AKIAIOSFODNN7EXAMPLEsk-FAKEEXAMPLE0000000000000",
	"password=[REDACTED:github_token]FAKEtail",
	"password: |\n  [REDACTED:sensitive_variable]\n  FAKEtail",
	"Authorization: Bearer [REDACTED:sensitive_variable] FAKEtail",
	"https://u:[REDACTED:url_credentials]FAKE@h",
	"secret_name: var.[REDACTED:aws_access_key]",
	"[REDACTED:private_key]-----BEGIN FAKE PRIVATE KEY-----",
}

// referenceLines maps each bullet of redaction-patterns.md, by prefix, to the
// kinds it requires (docs/plans/M0-redaction.md, section 5.3).
var referenceLines = []struct {
	prefix string
	kinds  []Kind
}{
	{"Clés d'accès AWS", []Kind{KindAWSAccessKey, KindAWSSecretKey}},
	{"Jetons de session AWS", []Kind{KindAWSSessionToken}},
	{"Secrets de service principal Azure", []Kind{KindAzureSecret}},
	{"Clés API Scaleway", []Kind{KindScalewayKey, KindOVHCredential}},
	{"Clés privées PEM", []Kind{KindPrivateKey}},
	{"Jetons GitHub", []Kind{KindGitHubToken, KindGitLabToken, KindSlackToken}},
	{"Clés API LLM", []Kind{KindLLMAPIKey}},
	{"Mots de passe dans des URL", []Kind{KindURLCredentials}},
	{"Chaînes de connexion de bases", []Kind{KindDBConnString}},
	{"Kubeconfig", []Kind{KindKubeconfig}},
	{"Valeurs de variables nommées", []Kind{KindSensitiveVar}},
	{"Clés pré-partagées IPsec", []Kind{KindIPsecPSK}},
}
```

Total des fixtures : 57 + 22 + 12 + 7 + 7 = **105**. Les préfixes de `referenceLines` sont copiés à l'octet près depuis le fichier du skill (apostrophe droite, NFC) ; si l'étape A4 révèle un écart d'octet, c'est le préfixe du test qui est corrigé, jamais le skill.

### 7.3 `redact_test.go`

**1. `TestRedactPatterns`** (fiche) : un sous-test par entrée de `positiveCases`, nommé par `name` (57). Pour chacun : `out == want` ; `kindsOf(matches) == kinds` ; `ContainsSecret(in)` vrai ; `ContainsSecret(out)` faux ; pour chaque match, `in[m.Start:m.End]` absent de `out` ; `rebuild(in, matches) == out`.

**3. `TestNoFalsePositive`** (fiche) : un sous-test par entrée de `negativeCases` (22) : `Redact(in)` rend `in` et `nil` ; `ContainsSecret(in)` faux.

**6. `TestMatchesCarryNoValue`** (fiche), 3 sous-tests :
- `shape` : `reflect.TypeFor[Match]()` a exactement 3 champs, `Kind` de type `Kind`, `Start` et `End` de type `int` ; `Match` et `*Match` n'ont aucune méthode (`NumMethod() == 0`).
- `no_secret_in_rendering` : pour chaque cas positif, aucune portée `in[m.Start:m.End]` n'apparaît dans `fmt.Sprintf("%v %+v %#v", ms, ms, ms)` ni dans `json.Marshal(ms)`.
- `kinds_are_known` : chaque `m.Kind` appartient à `Kinds()`.

**7. `TestKinds`**, 3 sous-tests : `exact_order` (les 16 chaînes de la section 5.1, dans l'ordre de déclaration, uniques, de forme `^[a-z][a-z_]*[a-z]$`) ; `fresh_copy` (modifier l'élément 0 du résultat ne change pas l'appel suivant) ; `zero_and_nil` (`(&Redactor{}).Kinds()` et `(*Redactor)(nil).Kinds()` égaux à `New().Kinds()`).

**8. `TestPlaceholder`**, sous-tests par `Kind` (16) : `Placeholder(k) == "[REDACTED:" + string(k) + "]"` ; `ContainsSecret(Placeholder(k))` faux ; `Redact` de la concaténation des 16 placeholders séparés par une espace rend l'entrée et `nil`.

**9. `TestOverlapPriority`**, un sous-test par entrée de `overlapCases` (7) : `out == want`, `kindsOf == kinds`.

**10. `TestMatchPositions`**, 4 sous-tests : `all_fixtures` (pour chaque cas positif, recouvrement et narrow : matches triés, disjoints, `0 <= Start < End <= len(in)`, `rebuild(in, ms) == out`) ; `ascii` : `"x AKIAIOSFODNN7EXAMPLE y"` donne `[{aws_access_key 2 22}]` ; `multibyte_prefix` : `"é password: FAKEpw12"` donne `[{sensitive_variable 13 21}]` ; `two_keys` : `"a=1 password=FAKEone token=FAKEtwo"` donne `[{sensitive_variable 13 20} {kubeconfig_credential 27 34}]`.

**11. `TestExemptionsAreNarrow`**, un sous-test par entrée de `narrowCases` (12) : `out == want`, au moins un match.

**12. `TestZeroAndNilRedactor`**, 2 sous-tests `zero_value`, `nil_pointer` : pour chaque entrée de `allFixtures()`, `Redact` et `ContainsSecret` égaux à ceux de `New()`, sans panique.

**14. `TestInvalidUTF8`** : `"\xff\xfe AKIAIOSFODNN7EXAMPLE \xff"` donne `"\xff\xfe [REDACTED:aws_access_key] \xff"` et `[{aws_access_key 3 23}]`.

**15. `TestConcurrentUse`** : un `Redactor` partagé, 8 goroutines lancées par `wg.Go`, 20 itérations chacune sur tous les cas positifs, sortie comparée à `want` (utile sous `-race`, critère 7).

**16. `TestLargeInputAdversarial`**, 8 sous-tests ; construction par `strings.Repeat` de fragments sans forme de secret de la garde :

| Sous-test | Entrée | Attendu |
|---|---|---|
| `many_keyed_values` | `strings.Repeat("password=FAKEvalue0\n", 1<<13)` | 8192 matches ; sortie `strings.Repeat("password=[REDACTED:sensitive_variable]\n", 1<<13)` |
| `pem_headers_without_end` | `strings.Repeat("-----BEGIN FAKE PRIVATE KEY-----", 1<<13)` | 8192 matches ; sortie `strings.Repeat(Placeholder(KindPrivateKey), 1<<13)` |
| `url_prefixes_without_at` | `strings.Repeat("https://u:", 1<<15)` | 0 match, sortie identique |
| `long_identifier` | `strings.Repeat("password", 1<<15)` | 0 match |
| `long_run_then_llm_key` | `strings.Repeat("a", 1<<18) + " sk-FAKEEXAMPLE0000000000000"` | 1 match `llm_api_key`, `Start == 1<<18 + 1`, `End == len(in)` |
| `quoted_keys_without_value` | `strings.Repeat("{\"password\":", 1<<14)` | 0 match |
| `block_indicators` | `strings.Repeat("password: |\n", 1<<14)` | 0 match |
| `nested_keys` | `strings.Repeat("password=(", 1<<15)` | 1 match `sensitive_variable` de 9 à `len(in)` ; sortie `"password=[REDACTED:sensitive_variable]"` |

### 7.4 `reference_test.go`

**2. `TestEveryPatternLineMapped`** (fiche) : lit le fichier du skill (chemin relatif de la section 3.2, point 8) ; garde les lignes commençant par `- `. Exige : chaque ligne commence par exactement un préfixe de `referenceLines` ; chaque entrée de `referenceLines` correspond à exactement une ligne ; l'union des `kinds` égale `Kinds()` ; pour la ligne `i` (numérotée à partir de 1) et chaque `k` de ses kinds, un cas de `positiveCases` a `line == i` et `k` dans `kinds` ; chaque cas positif a `1 <= line <= len(referenceLines)` et un nom qui commence par `l%02d_` de sa ligne. Sous-tests : `bullets_match_entries`, `kinds_cover_all`, `every_kind_has_positive_case`, `case_lines_valid`. Une ligne ajoutée au skill fait échouer ce test : c'est voulu (traçabilité skill vers test).

### 7.5 `property_test.go` (`pgregory.net/rapid`)

Générateurs communs :
- `soup()` : `rapid.SliceOfN(rapid.OneOf(rapid.SampledFrom(soupWords), rapid.StringMatching("[A-Za-z0-9]{1,24}")), 0, 40)` joint sans séparateur. `soupWords` (littéraux, garde respectée) : `password`, `db_password`, `token`, `max_tokens`, `secret_name`, `api_key`, `Authorization`, `Bearer `, `PSK `, `https://`, `postgres://`, `u`, `:`, `: `, `=`, ` = `, `"\n"`, `"\n  "`, `` `\n` ``, `` `\n  ` ``, `"`, `'`, `` `\"` ``, `|`, `>`, `(`, `[`, `]`, `{`, `}`, `$`, `${`, `{{`, `}}`, `&`, `?`, `;`, `,`, `@`, `var.`, `true`, `1024`, `12345678901`, les placeholders `sensitive_variable`, `github_token`, `private_key`, `url_credentials`, `AKIAIOSFODNN7EXAMPLE`, `ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE0000`, `sk-FAKEEXAMPLE0000000000000`, `-----BEGIN FAKE PRIVATE KEY-----`, `-----END FAKE PRIVATE KEY-----`, `LS0tLS1CRUdJTi`, `Proc-Type: 4,ENCRYPTED`, `FAKE`, `x`.
- `family(k Kind)` : rend un exemple `{input, body string; kind Kind}` ; `input = pre + "\n" + text + "\n" + post`, `pre` et `post` tirés par `rapid.String()`, filtré par `strings.Count(input, body) == 1`. Formats des familles à clé (tirés parmi) : `%s: %s`, `%s: "%s"`, `"%s": "%s"`, `%s = "%s"`, `%s=%s`, `%s: '%s'`, `\"%s\": \"%s\"`.

| Famille | Texte | Corps (secret) |
|---|---|---|
| `aws_access_key` | corps seul | `(AKIA\|ASIA)[A-Z0-9]{16}` |
| `aws_secret_key` | clé parmi `aws_secret_access_key`, `AWS_SECRET_ACCESS_KEY`, `SecretAccessKey` | `[A-Za-z0-9/+]{40}` |
| `aws_session_token` | clé parmi `aws_session_token`, `AWS_SESSION_TOKEN`, `SessionToken`, ou corps seul préfixé `IQoJb3JpZ2lu` par l'expression | `[A-Za-z0-9/+=]{100,300}` ; forme seule : `IQoJb3JpZ2lu[A-Za-z0-9/+=]{60,200}` |
| `azure_secret` | chaîne de connexion `...;AccountKey=%s;EndpointSuffix=...` ; URL SAS `...?sv=2022-11-02&sig=%s` ; forme seule ; clé `client_secret` | `[A-Za-z0-9+/]{86}==` ; `[A-Za-z0-9%]{43}` ; `[A-Za-z0-9]{3}[0-9]Q~[A-Za-z0-9_~.-]{34}` ; `[A-Za-z0-9_~.-]{34,40}` |
| `scaleway_key` | forme seule ; clé `SCW_SECRET_KEY` | `SCW[A-Z0-9]{17}` ; `[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}` |
| `ovh_credential` | clé parmi `application_secret`, `consumer_key`, `OVH_APPLICATION_KEY` | `[A-Za-z0-9]{16,32}` |
| `private_key` | `fmt.Sprintf` d'un en-tête de type tiré parmi `RSA `, `EC `, `OPENSSH `, `ENCRYPTED `, `DSA `, vide ; 1 à 5 lignes ; séparateur saut de ligne réel ou `\n` échappé ; pied présent ou absent | première ligne, `[A-Za-z0-9+/]{64}` |
| `github_token` | corps seul | `gh[pousr]_[A-Za-z0-9]{36}` ou `github_pat_[A-Za-z0-9_]{82}` |
| `gitlab_token` | corps seul | `gl(pat\|dt)-[A-Za-z0-9_-]{20,40}` |
| `slack_token` | corps seul | `xox[bpas]-[0-9]{10,13}-[A-Za-z0-9-]{10,40}` ou webhook `https://hooks\.slack\.com/services/T[A-Z0-9]{8}/B[A-Z0-9]{8}/[A-Za-z0-9]{24}` |
| `llm_api_key` | corps seul | `sk-ant-api03-[A-Za-z0-9_-]{40,95}` ou `sk-(proj-)?[A-Za-z0-9_-]{40}` |
| `url_credentials` | `%s://%s:%s@%s/p`, schéma parmi `https`, `ftp`, `sftp`, `git+https` | mot de passe `[A-Za-z0-9!$*+.~_-]{8,24}` |
| `db_connection_string` | idem, schéma parmi `postgres`, `postgresql`, `mysql`, `mongodb+srv`, `redis` | idem |
| `kubeconfig_credential` | clé parmi `token`, `client-key-data`, `id-token` | `[A-Za-z0-9._-]{20,200}` |
| `sensitive_variable` | clé parmi `password`, `db_password`, `apiKey`, `x-api-key`, `auth_token`, `SPRING_DATASOURCE_PASSWORD`, `passphrase` | `[A-Za-z][A-Za-z0-9!#%*+./?^_~-]{7,39}`, filtré : ne commence ni par `var.`, `local.`, `data.`, `module.` |
| `ipsec_psk` | clé parmi `tunnel1_preshared_key`, `psk`, `shared_key`, `pre_shared_key`, ou ligne `: PSK "%s"` | `[A-Za-z0-9!#%*+./?^_~-]{8,40}` |

**4. `TestIdempotent`** (fiche) : sous-tests `fixtures` (les 105 entrées et les sorties attendues) et `soup` (`rapid.Check`). Propriété : `out1, _ := Redact(x)` ; `out2, m2 := Redact(out1)` ; `out2 == out1`, `len(m2) == 0`, `ContainsSecret(out1)` faux.

**5. `TestPropertyNoSecretSurvives`** (fiche) : un sous-test par `Kind` (16), chacun `rapid.Check` sur `family(k)`. Propriété : le corps n'apparaît pas dans `out` ; `ContainsSecret(out)` faux ; `Redact(out)` rend `out` et `nil` ; un match couvre entièrement le corps, de `Kind == k`, sauf pour `url_credentials`, `db_connection_string` et `sensitive_variable` où un `Kind` de plus haute priorité est accepté (un corps aléatoire peut contenir par hasard une forme de jeton).

**13. `TestContainsSecretConsistent`** : sous-tests `fixtures` et `soup` : `ContainsSecret(x) == (len(matches) > 0)`, sur l'entrée et sur la sortie.

**17. `TestRedactedOutputStaysCleanWhenJSONEncoded`** : sous-tests `fixtures` et `soup` ; pour `out := Redact(x)` : `ContainsSecret(string(json.Marshal(out)))` faux, et de même avec un `json.Encoder` en `SetEscapeHTML(false)` (section 5.6).

Récapitulatif : **17 tests de premier niveau**, dont les 6 de la fiche (numéros 1 à 6). Nombre de cas `rapid` : 100 par défaut dans `make verify-quick` ; 10 000 au critère 6 ; 100 000 sur la copie scratch pour le potage (section 7.8).

### 7.6 Répartition des tests
Fiche : 1 `TestRedactPatterns`, 2 `TestEveryPatternLineMapped`, 3 `TestNoFalsePositive`, 4 `TestIdempotent`, 5 `TestPropertyNoSecretSurvives`, 6 `TestMatchesCarryNoValue`. Témoins : 7 à 17.

### 7.7 Preuve de rouge (fin de phase tests, avant `phase impl`)

| Commande | Résultat attendu |
|---|---|
| `test ! -e internal/llm/redact/redact.go && test ! -e internal/llm/redact/rules.go; echo rc=$?` | `rc=0` |
| `ls internal/llm/redact \| sort \| tr '\n' ' '` | `cases_test.go property_test.go redact_test.go reference_test.go ` |
| `go test -gcflags=-e ./internal/llm/redact 2>&1 \| grep -c 'undefined: '` | au moins `1` |
| `go test -gcflags=-e ./internal/llm/redact 2>&1 \| grep -E '\.go:[0-9]+:[0-9]+: ' \| grep -vc 'undefined: '` | `0` |
| Section 7.8 sur la copie | tout vert |
| `git status --porcelain \| grep -c '^?? internal/llm/redact/$'` | `1` |
| `git add internal/llm/redact/ && git status --porcelain \| grep -cE '^A  internal/llm/redact/[a-z_]+_test\.go$'` | `4` |
| `git status --porcelain \| grep -vcE '^A  internal/llm/redact/[a-z_]+_test\.go$'` | `0` |
| `python3 .claude/bin/rempart-state phase impl` | `Phase : tests -> impl` |

### 7.8 Copie scratch avec le code de référence (avant gel)

```bash
S=<scratchpad de session>/t07 && rm -rf "$S" && mkdir -p "$S" && cp -a . "$S/r" && cd "$S/r"
# redact.go et rules.go écrits dans la copie seulement : sections 5.1 et 5.2, sans les commentaires d'ancre
go vet ./internal/llm/redact; echo rc=$?                                               # rc=0
golangci-lint run ./internal/llm/redact/... ; echo rc=$?                               # rc=0, dont gosec G101
go test ./internal/llm/redact/ -count=1 -rapid.nofailfile; echo rc=$?                  # rc=0
go test ./internal/llm/redact/ -count=1 -rapid.nofailfile -rapid.checks=100000 \
  -run '^(TestIdempotent|TestContainsSecretConsistent|TestRedactedOutputStaysCleanWhenJSONEncoded)$'; echo rc=$?  # rc=0
go test ./internal/llm/redact/ -count=1 -run '^TestLargeInputAdversarial$' -v -timeout 120s   # durées notées
```

Règles de décision :
- Une attente fausse sur un détail du moteur (position, ordre de `kinds`) se corrige dans le test, en phase tests, avec le constat consigné.
- Un contre-exemple de fuite ou de non-idempotence trouvé par une propriété est un **défaut du code de référence** : arrêt, retour à l'architecte, amendement de ce plan (précédent : amendement V1 de M0-T06), jamais un rétrécissement silencieux du générateur.
- gosec G101 sur une fixture : repli P13 ; sur une constante `Kind` : repli de la section 5.2 ; jamais de `nolint`.
- La copie est supprimée ensuite ; aucun fichier de production n'est écrit dans le dépôt en phase tests.

---

## 8. Critères d'acceptation

Depuis la racine du dépôt, phase impl terminée ou phase free. `-count=1` partout. `P=./internal/llm/redact/`. `-rapid.nofailfile` seulement sur ce paquet.

### 8.1 Critères de la fiche, précisés

| # | Commande | Résultat attendu |
|---|---|---|
| 1 | `go test $P -count=1 -run '^TestRedactPatterns$' -v 2>&1 \| grep -cE -- '--- PASS: TestRedactPatterns/l[0-9]{2}_[a-z0-9_]+ '` | `57` (fiche : au moins 24 ; critère 3 de `prompts/M0.md` : au moins 10) |
| 1 bis | `go test $P -count=1 -run '^TestRedactPatterns$' -v 2>&1 \| grep -oE 'PASS: TestRedactPatterns/l[0-9]{2}' \| sort -u \| wc -l` | `12` (chaque ligne du skill a un cas) |
| 2 | `go test $P -count=1 -rapid.nofailfile -v -run '^(TestEveryPatternLineMapped\|TestNoFalsePositive\|TestIdempotent\|TestPropertyNoSecretSurvives\|TestMatchesCarryNoValue)$' 2>&1 \| grep -cE '^--- PASS: '` | `5` |
| 3 | `make verify-quick; echo rc=$?` | dernière ligne `rc=0` |

### 8.2 Critères complémentaires

| # | Commande | Résultat attendu |
|---|---|---|
| 4 | `go test $P -count=1 -rapid.nofailfile -v 2>&1 \| grep -cE '^--- PASS: Test'` puis `\| grep -cE -- '--- (FAIL\|SKIP)'` | `17` puis `0` |
| 5 | sur la même sortie : `grep -cE -- '--- PASS: TestNoFalsePositive/[a-z0-9_]+ '` ; `TestExemptionsAreNarrow/` ; `TestOverlapPriority/` ; `TestPropertyNoSecretSurvives/[a-z_]+ ` ; `TestPlaceholder/` ; `TestLargeInputAdversarial/` | `22` ; `12` ; `7` ; `16` ; `16` ; `8` |
| 6 | `go test $P -count=1 -rapid.nofailfile -rapid.checks=10000 -run '^(TestIdempotent\|TestPropertyNoSecretSurvives\|TestContainsSecretConsistent\|TestRedactedOutputStaysCleanWhenJSONEncoded)$'; echo rc=$?` | `rc=0` |
| 7 | `CGO_ENABLED=1 go test $P -race -count=1 -rapid.nofailfile -run '^(TestConcurrentUse\|TestZeroAndNilRedactor)$'; echo rc=$?` | `rc=0` ; sans compilateur C, « non applicable ici » consigné avec la sortie, repris par la CI (T04) |
| 8 | `go list -f '{{join .Imports " "}}' $P` | `cmp regexp slices strings` |
| 9 | `go list -f '{{join .TestImports "\n"}}' $P \| grep '\.'` ; `grep -nE '\b(rules\|find\|merge\|covered\|valueRe\|placeholderRe)\b' internal/llm/redact/*_test.go \| wc -l` | `pgregory.net/rapid` seul ; `0` |
| 10 | `grep -rnE '//[[:space:]]*(nolint\|#nosec)' --include='*.go' . \| wc -l` | `0` |
| 11 | `cat internal/llm/redact/redact.go internal/llm/redact/rules.go \| grep -cE 'EXAMPLE\|FAKE\|DUMMY\|PLACEHOLDER'` | `0` (aucune exemption par marqueur, aucun exemple en production) |
| 12 | script de la section 8.4 (motifs de `guard_edit` sur les 6 fichiers `.go` et sur ce plan) | `violations 0` |
| 13 | `grep -nE '"[[:space:]]*\+[[:space:]]*"\|`[[:space:]]*\+[[:space:]]*`' internal/llm/redact/cases_test.go internal/llm/redact/redact_test.go internal/llm/redact/reference_test.go \| wc -l` | `0` (aucune concaténation de littéraux dans les fichiers de fixtures) |
| 13 bis | `grep -l 'rapid\.' internal/llm/redact/*.go` | `internal/llm/redact/property_test.go` seul |
| 14 | `test ! -e internal/llm/redact/testdata; echo rc=$?` | `rc=0` (sauf repli P13 consigné) |
| 15 | `go test ./internal/archtest/ -count=1; echo rc=$?` | `rc=0` |
| 16 | `git diff --quiet HEAD -- go.mod go.sum internal/llm/doc.go; echo rc=$?` ; `go mod tidy -diff; echo rc=$?` | `rc=0` ; `rc=0` |
| 17 | `grep -nE '\.\*\|\(\?s' internal/llm/redact/rules.go \| wc -l` | `0` (aucune répétition non bornée par un délimiteur) |
| 18 | `grep -c '^- ' .claude/skills/llm-safety/references/redaction-patterns.md` ; `git diff --quiet HEAD -- .claude/skills/llm-safety/; echo rc=$?` | `12` ; `rc=0` |
| 19 | `go test $P -count=1 -run '^TestLargeInputAdversarial$' -v -timeout 120s 2>&1 \| grep -E -- '--- PASS: TestLargeInputAdversarial/'` | 8 lignes ; durées recopiées dans `docs/STATUS.md` |
| 20 | `grep -c '^func (r \*Redactor) ' internal/llm/redact/redact.go` ; `grep -c '^type Redactor struct{}$' internal/llm/redact/redact.go` | `3` ; `1` |

### 8.3 Preuves par mutation sur une copie (jamais dans le dépôt)

```bash
S=<scratchpad de session>/t07m && rm -rf "$S" && mkdir -p "$S" && cp -a . "$S/r" && cd "$S/r"
python3 - "$FILE" "$OLD" "$NEW" <<'EOF'
import pathlib, sys
p = pathlib.Path("internal/llm/redact") / sys.argv[1]
s = p.read_text()
old, new = sys.argv[2], sys.argv[3]
assert s.count(old) == 1, "anchor not found exactly once"
p.write_text(s.replace(old, new))
EOF
go test ./internal/llm/redact/ -count=1 -rapid.nofailfile -timeout 60s 2>&1 | grep -cE -- "--- FAIL: ($EXPECTED)|test timed out"
```

| # | `FILE` | `OLD` | `NEW` | `EXPECTED` : au moins `1` ligne |
|---|---|---|---|---|
| M1 | `redact.go` | `return "[REDACTED:" + string(k) + "]"` | `return "[REDACTED " + string(k) + "]"` | `TestPlaceholder\|TestRedactPatterns` |
| M2 | `redact.go` | `cs[j].start < end` | `cs[j].start <= end` | `TestRedactPatterns\|TestLargeInputAdversarial` |
| M3 | `redact.go` | `end = max(end, cs[j].end)` | `end = max(end, cs[i].end)` | `TestOverlapPriority` (`o7_union_extends_past_value`) |
| M4 | `redact.go` | `best = min(best, cs[j].prio)` | `best = cs[j].prio` | `TestOverlapPriority\|TestRedactPatterns` |
| M5 | `rules.go` | `out = append(out, candidate{start: st, end: en, exempt: exempt})` | `if !exempt { out = append(out, candidate{start: st, end: en}) }` | `TestExemptionsAreNarrow\|TestIdempotent` |
| M6 | `redact.go` | `covered(protected, c.start, c.end)` | `covered(protected[:0], c.start, c.end)` | `TestIdempotent\|TestNoFalsePositive` |
| M7 | `rules.go` | `(reSmallInt.MatchString(value) && reQuantity.MatchString(key)) \|\|` | `false \|\|` | `TestNoFalsePositive` |
| M8 | `rules.go` | `` `^[0-9]{1,9}$` `` | `` `^[0-9]+$` `` | `TestExemptionsAreNarrow` (`x03`) |
| M9 | `rules.go` | `(?:name\|arn\|ref\|` | `(?:id\|name\|arn\|ref\|` | `TestExemptionsAreNarrow` (`x06`) |
| M10 | `rules.go` | `[ \t]*:[ \t]+)` | `[ \t]*:[ \t]*)` | `TestNoFalsePositive` (`iam_policy_json`) |
| M11 | `rules.go` | `(?:Proc-Type:[^\r\n\\]*\|DEK-Info:[^\r\n\\]*\|[A-Za-z0-9+/=\s\\])*` | `(?:[A-Za-z0-9+/=\s\\]\|Proc-Type:[^\r\n\\]*\|DEK-Info:[^\r\n\\]*)*` | `TestRedactPatterns` (`l05_pem_encrypted_headers`) |
| M12 | `rules.go` | `[A-Za-z0-9+/=\s\\])*` | `[A-Za-z0-9+/=\s])*` | `TestRedactPatterns` (`l05_pem_json_escaped_no_key`) |
| M13 | `rules.go` | `"(?P<v>(?:[^"\\\r\n]\|\\.)+)"` | `"(?P<v>[^"\\\r\n]+)"` | `TestRedactPatterns` (`l11_json_value_with_escaped_quote`) |
| M14 | `rules.go` | ``|` + boundary + `(?P<v>sk-`` | ``|` + `(?P<v>sk-`` | `TestNoFalsePositive` (`sk_and_task_identifiers`) |
| M15 | `rules.go` | `(?:AKIA\|ASIA)[A-Z0-9]{16}` | `(?:AKIA\|ASIA)[A-Z0-9]{17}` | `TestRedactPatterns` |
| M16 | `rules.go` | `\|\\"(?P<v>` | `\|\\"(?P<x>` | `TestRedactPatterns` (`l11_escaped_quotes_in_json_log`) |
| M17 | `rules.go` | `\r?\n[ \t]+(?P<v>[^\r\n]+` | `\r?\n[ \t]+(?P<x>[^\r\n]+` | `TestRedactPatterns` (`l11_yaml_block_scalar`) |
| M18 | `redact.go` | `return len(find(s)) > 0` | `return len(find(s)) > 1` | `TestRedactPatterns\|TestContainsSecretConsistent` |
| M19 | `redact.go` | `return slices.Clone(allKinds)` | `return allKinds` | `TestKinds` (`fresh_copy`) |
| M20 | `rules.go` | `if loc[0] < skip {` | `if loc[0] < 0 {` | `TestLargeInputAdversarial` (`nested_keys`), par dépassement du délai de 60 s |
| M21 | `rules.go` | `shape(KindSensitiveVar, reAuthz),` | `` (vide) | `TestRedactPatterns` (`l11_authorization_basic_json`) |
| M22 | `rules.go` | ``boundary = `(?:^|[^A-Za-z0-9_\]])` `` | ``boundary = `(?:^|[^A-Za-z0-9_])` `` | `TestIdempotent` (`fixtures`, premier `idempotentCases`) |

Dans le tableau, `\|` est l'échappement Markdown de `|` ; les accents graves doubles délimitent un texte qui contient des accents graves. Toutes les mutations compilent (M5 réécrit un bloc complet ; M6 garde `protected` utilisé ; M21 laisse `reAuthz` en constante inutilisée, ce que le compilateur accepte). Après chaque mutation, la copie est supprimée.

### 8.4 Script de la garde (critère 12)

```bash
python3 - <<'EOF'
import pathlib, sys
sys.path.insert(0, ".claude/hooks")
import guard_edit as g
files = sorted(pathlib.Path("internal/llm/redact").glob("*.go")) + [pathlib.Path("docs/plans/M0-redaction.md")]
bad = 0
for p in files:
    c = p.read_text()
    for pat, label in g.SECRET_PATTERNS:
        for m in pat.finditer(c):
            if not g.ALLOWED_FAKE.search(c[max(0, m.start() - 40): m.end() + 40]):
                bad += 1
                print(p, label, m.start())
print("violations", bad)
EOF
```

L'import de `guard_edit` n'a pas d'effet de bord (`main` n'est appelé que sous `__main__`) ; le script lit les motifs du harnais au lieu de les recopier.

---

## 9. Revue sécurité (`security-reviewer`, diff de `internal/llm/redact/`)

Obligatoire : LLM, secrets, T7. Points à vérifier, chacun avec sa preuve :
1. Chaque ligne du skill a son `Kind` et un cas positif, et le lien est mécanique : test 2, critères 1 et 1 bis.
2. Aucune exemption par marqueur ; aucun exemple en production : P12, critère 11.
3. Exemptions E1 à E4 étroites, limitées à la règle générique, contaminées par tout jeton reconnu, bornées à 256 octets : tests 3 et 11, mutations M5, M7 à M9.
4. Union des chevauchements : aucun fragment de secret ne survit ; l'étiquette ne porte aucune garantie : tests 1, 9, M2 à M4.
5. Idempotence, y compris pour un texte qui contient déjà des placeholders ou des morceaux hostiles : tests 4 et 13, potage à 100 000 cas sur copie, M6, M22.
6. Cohérence de `ContainsSecret` avec `Redact`, y compris sous un niveau de sérialisation JSON (contrat avec T12) : tests 13 et 17, M18.
7. `Match` ne porte aucune valeur ; aucun journal, aucune erreur contenant un extrait : test 6, critère 8.
8. Coût : pas de `.*` ni de `(?s)`, `skip` des clés imbriquées, entrées adverses : critère 17, test 16, M20 ; pertinence du report de la borne de taille à T11 (section 5.9).
9. Honnêteté des limites (section 5.8) et contraintes pour T11, T12 et M1 (section 5.9).
10. Respect de la règle des fixtures (F1 à F4) : critères 12, 13, 13 bis ; revue de `property_test.go` : aucune valeur fixe reconstruite.

Verdict attendu : PASS. Un BLOCK qui exige de changer un test renvoie en phase tests (retour journalisé).

---

## 10. Spécification de boucle

Sans objet : T07 ne crée aucune boucle. `internal/llm/redact` n'est ni un `domain` (R1 ne s'applique pas) ni un adaptateur ; il sera importé par `internal/llm` (T11). Aucune règle de `internal/archtest/rules.go` n'est touchée (critère 15).

---

## 11. Risques

| # | Risque | Atténuation |
|---|---|---|
| K1 | Faux négatifs structurels (L1 à L6) : un secret sans contexte atteint le modèle | Limites documentées (section 5.8) et consignées ; menace proposée (section 12) ; rédaction structurée et minimisation en M1 ; le modèle ne prend aucune décision (règle 1 du skill), la fuite reste une fuite d'information, bornée par la résidence et la rétention (ADR 0002). |
| K2 | Faux positifs qui appauvrissent le contexte envoyé au modèle (valeurs d'IaC masquées à tort) | Clé toujours lisible ; exemptions E1 à E4 prouvées par la table de 22 cas ; evals du taux de faux positifs en M1. |
| K3 | Coût quadratique d'un `FindAll` dans un cas pathologique non couvert | Règles sans `.*`, `skip`, test 16 ; borne de 1 Mio par requête imposée à T11 ; toute lenteur constatée devient un cas de test. |
| K4 | Garde `guard_edit` qui bloque une écriture (fixture, expression, ce plan) | Règles F1 à F4 ; expressions vérifiées (section 3.2, point 5) ; critère 12 rejoue la garde. |
| K5 | gosec G101 sur une fixture ou une constante, alors que `nolint` est interdit (T30) | Fixtures en champs de littéraux composites (F2) ; replis P13 et section 5.2 ; vérification sur copie (section 7.8). |
| K6 | Le potage découvre une non-idempotence dans le code de référence | Section 7.8 : amendement du plan avant le gel, jamais un générateur rétréci. |
| K7 | Le skill `llm-safety` est enrichi (les skills restent modifiables) sans mise à jour des tests | `TestEveryPatternLineMapped` échoue : la nouvelle ligne exige une entrée de `referenceLines` et un cas positif, écrits en phase tests. |
| K8 | Étiquette trompeuse (`shared_key` de stockage étiquetée `ipsec_psk`) | L7 ; aucune garantie ni décision ne dépend du `Kind`. |
| K9 | Donnée cloud hostile qui provoque volontairement un masquage (préfixer un texte par `password: `) pour cacher une information au modèle, ou qui contient un faux placeholder | Effet limité au texte explicatif (aucune décision par le LLM) ; un faux placeholder n'est qu'un texte protégé. |
| K10 | Sémantique du moteur `regexp` supposée à tort (noms de groupe répétés, priorité des alternatives) | Vérifiée sur copie avant gel (section 7.8) ; toute divergence est un amendement du plan. |
| K11 | Valeur exemptée proche de 256 octets qui dépasse la borne une fois sérialisée en JSON (`\u003c`) : masquée dans le corps sortant seulement | Sur-masquage sans fuite ; noté, sans cas réaliste en M0. |
| K12 | Hook Stop : cycle en un seul tour, 3 échecs de `verify-quick` puis BLOCAGE | Incréments courts (section 13), `go test` ciblé après chacun, `make verify-quick` avant de rendre la main. |
| K13 | Porte `phase impl` aveugle au dossier nouveau | `git add internal/llm/redact/` (section 3.2, point 3 ; tableau 7.7). |

---

## 12. Impact sur le modèle de menace (`docs/02-THREAT-MODEL.md`)

- **T7 (fuite vers le fournisseur LLM)** : la vérification « Test de rédaction » devient `TestRedactPatterns` (57 cas, 12 lignes du skill), `TestEveryPatternLineMapped`, `TestPropertyNoSecretSurvives` (16 familles) et `TestRedactedOutputStaysCleanWhenJSONEncoded`, qui fonde `TestNoSecretInOutgoingRequest` (T12). La colonne « Atténuations » gagne, à la clôture (H4), les limites L1 à L10 et la borne de taille de T11 ; ce plan ne modifie pas le modèle.
- **T36 (contournement du masquage de `secret.Value`)** : un `Reveal()` qui atteindrait un prompt est rattrapé par le rédacteur **seulement** si le secret a une forme ou une clé reconnues ; le rédacteur est une seconde barrière, pas une atténuation suffisante de T36 (la liste blanche des appelants de `Reveal`, prévue en M1, reste nécessaire).
- **T10 (coût)** : la rédaction a un coût linéaire visé et mesuré ; la borne de taille relève de T11.
- **Menace nouvelle proposée à `security-reviewer` pour la clôture (H4)**, sans modification du modèle par ce plan : « T37 Contournement ou affaiblissement du rédacteur de secrets » (I) : secret à forme libre, encodé ou réparti (L1 à L6), abus des exemptions (L8), dérive entre le skill et les tests, entrée démesurée. Atténuations : table des limites, `TestEveryPatternLineMapped`, contamination des exemptions, borne de 1 Mio de T11, rédaction structurée et minimisation en M1, aucune décision par le LLM. Vérifications : tests de M0-T07 et mutations M1 à M22 ; à créer en M1 : evals de fuite sur corpus réels anonymisés.

---

## 13. Tâches ordonnées (un seul tour de l'agent principal, section 3.2)

Avant le tour : validation humaine de ce plan.

Phase tests :

| # | Tâche | Qui | Vérification immédiate |
|---|---|---|---|
| A0 | Conditions d'entrée (section 3.1) ; `python3 .claude/bin/rempart-state phase tests` | agent principal | `Phase : free -> tests` |
| A1 | `cases_test.go` : tables de la section 7.2 à l'octet près, aides `rebuild`, `kindsOf`, `allFixtures` | `test-author` | écriture acceptée par `guard_edit` ; message de `post_edit_check` limité à `undefined:` |
| A2 | `redact_test.go` : tests 1, 3, 6 à 12, 14 à 16 | `test-author` | idem |
| A3 | `reference_test.go` (test 2) et `property_test.go` (tests 4, 5, 13, 17, générateurs de la section 7.5) | `test-author` | idem ; aucun `no required module` |
| A4 | Copie scratch avec le code de référence (section 7.8) : vet, golangci-lint dont G101, go test, potage à 100 000 cas, entrées adverses ; attentes corrigées ou amendement demandé | `test-author` | tableau 7.8 vert |
| A5 | Preuve de rouge (section 7.7), `git add internal/llm/redact/`, `phase impl` | agent principal | tableau 7.7 ; `Phase : tests -> impl` |

Phase impl (même tour, `-rapid.nofailfile` sur chaque `go test` ciblé) :

| # | Incrément | Vérification immédiate |
|---|---|---|
| I1 | `rules.go` (section 5.2) puis `redact.go` (section 5.1), écrits à la suite : les tests exigent les deux | `go vet ./internal/llm/redact; echo rc=$?` : `rc=0` ; `go test ./internal/llm/redact/ -count=1 -rapid.nofailfile` : `ok` ; critères 1, 2, 4, 5 |
| I2 | `golangci-lint run ./...`, puis `make verify-quick` | critères 3, 8 à 18, 20 ; fin de tour possible |

Clôture :

| # | Étape | Vérification |
|---|---|---|
| F1 | Critères 1 à 20 (dont 7 selon l'environnement, 19 avec durées), puis mutations M1 à M22 sur copies | tableaux 8.1 à 8.4 |
| F2 | `security-reviewer` (section 9), puis `acceptance-verifier` (critères 1 à 20, M1 à M22) | verdicts PASS |
| F3 | `docs/STATUS.md` : précisions P1 à P15, limites L1 à L10, contraintes de la section 5.9 pour T11, T12 et M1, durées du critère 19, résultat du critère 7, menace proposée T37, replis éventuels (P13, G101) ; `python3 .claude/bin/rempart-state phase free --reason "tâche redaction terminée"` ; commit `feat(llm): deterministic secret redactor (M0-T07)` | `git status --porcelain \| wc -l` : `0` après commit ; `make verify-quick; echo rc=$?` : `rc=0` |
