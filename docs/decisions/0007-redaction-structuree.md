# 0007. Rédaction structurée : passe JSON et YAML, désarmement des placeholders, octets NUL

- Statut : proposé
- Date : 2026-10-13
- Jalon : M1 (M1-T08 `redact-structured`, D12 de `docs/plans/M1-overview.md`). À accepter par l'humain avant la phase tests de M1-T08 (H0-M1 point 4) ; bloque M1-T09 et tout appel à un modèle réel.
- Sources : garde « issue de M0-T07 » de `prompts/M1.md` ; constats ouverts de `docs/plans/M0-redaction.md` (section 0 quater) ; obligation (ad) de `docs/STATUS.md` ; skill `llm-safety` (règles 1 et 4) ; `internal/llm/redact/{redact.go,rules.go}`, `redactMessages` (`internal/llm/check.go`), `RenderUntrusted` (`internal/llm/domain/untrusted.go`).

## Contexte

Le rédacteur de M0-T07 lit tout texte par expressions régulières RE2. Deux revues `security-reviewer` successives ont rendu BLOCK sur la même classe de défauts : une expression régulière ne saute pas les chaînes d'un objet JSON (paire `name`/`value` perdue dès qu'une chaîne contient `{` ou `}` : `kubectl -o json`, `ecs:DescribeTaskDefinition`), ne lit pas un JSON doublement encodé (T69) et ne lie pas un nom de paramètre SSM (`/prod/db/password`) à sa valeur. S'y ajoutent les octets NUL réels confondus avec la vue opaque des placeholders (`/proc/<pid>/environ`, T39), les placeholders `[REDACTED:...]` forgés dans une donnée cloud qui rendent illisible ce qui les suit (T38) et les cas de l'obligation (ad). La règle « même échec deux fois : changer d'approche » s'applique ; la garde de `prompts/M1.md` interdit tout appel à un modèle réel avant la refonte.

Contraintes : signatures de `Redact` et `ContainsSecret` inchangées (appelants de `internal/llm` inchangés), aucune erreur rendue, idempotence, aucun LLM dans la détection (`llm-safety`, règle 1), coût borné jusqu'à 1 Mio (borne S6 du client), aucune dépendance nouvelle.

## Options envisagées

1. **(a) Passe structurée JSON et YAML, puis expressions régulières sur les feuilles décodées et le texte libre (retenue).** Pour : lit la structure comme le modèle (chaînes sautées, paires liées quelle que soit la mise en forme, double encodage) ; les règles existantes restent la seule source des formes de secrets ; bibliothèque standard et `go.yaml.in/yaml/v3` déjà présent. Contre : deux décodeurs exposés à des entrées adverses (coût, paniques, alias YAML) ; deux lectures à fusionner sans perdre l'idempotence ; sur-masquage des feuilles échappées.
2. **(b) Expressions régulières durcies seules.** Pour : coût linéaire garanti par RE2, aucun décodeur, continuité avec M0. Contre : deux BLOCK sur cette classe en M0-T07 ; RE2 ne compte pas les accolades et ne suit pas les chaînes imbriquées ; chaque correctif a ouvert de nouveaux cas. Refusée.
3. **(c) Liste blanche de champs par type de ressource.** Pour : précise ; un champ inconnu est masqué (échec fermé naturel). Contre : catalogue par cloud, service et version d'API à tenir pour cinq fournisseurs ; aveugle au texte libre (journaux, descriptions, tags), à rédiger de toute façon par expressions régulières, alors qu'un champ libre admis est justement celui qui porte un secret collé. Refusée comme mécanisme principal ; deux règles de type ciblées en sont reprises (D2, règle 5).

## Décision

Option (a). `find`, partagé par `Redact` et `ContainsSecret`, enchaîne : normalisation des NUL (D1), passe structurée (D2), expressions régulières (D4), fusion. **Aucune borne ne rend la passe structurée aux seules expressions régulières ni ne produit d'erreur : toute borne atteinte masque (échec fermé).**

### D1. Octets NUL (T39)

Chaque octet NUL réel devient `\n` avant toute détection, dans la vue **et dans la sortie** : même longueur, offsets des `Match` inchangés, et le modèle lit la forme contrôlée (T69). La reconstruction de M0 (`rebuild`) et l'identité sur un texte sans secret s'énoncent sur l'entrée normalisée. NUL reste réservé à la vue opaque des placeholders. Les feuilles décodées (`\u0000`) sont normalisées de même, et `\u0000` échappé devient frontière et préfixe de clé comme `\n`.

### D2. Passe structurée

- **JSON** (`encoding/json`, `Decoder.Token` avec `UseNumber`, offsets par `InputOffset`) : tentative à chaque `{` ou `[` hors d'une valeur déjà décodée avec succès (document entier ou fragment d'un journal). Chaque conteneur est évalué à sa fermeture ; à une erreur, les conteneurs encore ouverts le sont avec les membres déjà lus (JSON tronqué par la source).
- **YAML** (`go.yaml.in/yaml/v3` v3.0.5, dépendance directe déjà épinglée dans `go.mod`, utilisée par `internal/evals`) : seulement si le texte entier, qui n'est pas un document JSON entier, est un flux de documents dont chaque racine est un mapping ou une séquence, parcouru en `yaml.Node`. Alias jamais développés : un alias en position sensible masque l'alias et l'étendue de son ancre ; un alias de scalaire est résolu sur place là où un nom ou un élément est lu. L'étendue masquée d'un nœud couvre au moins tous ses octets bruts (au besoin jusqu'au nœud suivant), jamais moins.
- **Bornes, toutes à échec fermé** : `MaxStructuredDepth = 64` (sous-arbre plus profond masqué entier, jusqu'à sa fermeture ou à l'erreur) ; budget de travail partagé par toute la passe et sa récursion, `MaxStructuredWork = 32` (octets lus et nœuds visités au plus `32 × len(s) + 65536`) : épuisé, le texte est masqué d'un seul tenant de la première position non examinée à la fin ; panique d'un décodeur récupérée : texte entier masqué. Sans alias développé, les nœuds sont bornés par la taille du texte : un document valide de 1 Mio et de profondeur au plus 64 n'atteint aucune borne.
- **Règle 1, clé sensible** : union des noms de **toutes** les règles à clé de `rules.go`, avec leur `Kind` (`client-key-data`, `pre_shared_key`, `consumer_key`, et non la seule règle générique), plus `authorization`, `proxy-authorization`, `cookie`, `set-cookie`, casse ignorée. Valeur scalaire masquée entière, avec les exemptions de la règle correspondante (E1 à E4 pour la générique, schéma seul pour `authorization`, aucune sinon). Valeur conteneur : contexte sensible propagé, chaque feuille scalaire masquée, exemptions jugées avec la clé de la feuille (`variables.db_password.value` d'un plan OpenTofu). Une clé exemptée par E4 (`password_policy`) ne propage rien.
- **Règle 2, paires** : objet ou mapping qui a un membre `name` ou `key`, ou finissant par `Name` ou `Key` (`ParameterKey`, `OptionName`), et un membre `value` ou finissant par `Value`, casse ignorée ; nom sensible au sens de la règle 1, entier ou par son dernier segment de chemin (`/prod/db/password`, SSM). Clés en double : chaque occurrence compte. La valeur suit la règle 1.
- **Règle 3, feuilles** (valeurs et clés textuelles) : expressions régulières sur la forme décodée ; une feuille qui est elle-même du JSON ou du YAML au sens ci-dessus repasse par D2 (récursion, profondeur et budget partagés : double encodage, T69). Forme brute identique à la forme décodée : candidats reportés en place ; sinon (échappements, guillemets, scalaire replié), une feuille que touche un candidat quelconque, de la feuille ou du texte brut, est masquée entière. Dans une feuille décodée, un placeholder n'est protégé que s'il figure à l'identique dans la forme brute (`[REDACTED:` forgé, T38).
- **Règle 4, tableaux** : la concaténation des éléments chaînes passe par les expressions régulières ; un candidat qui chevauche deux éléments masque tous les éléments chaînes du tableau (secret coupé entre éléments d'`enum`, `Fn::Join`).
- **Règle 5, types** (repris de (c), ligne L5 de `M0-redaction.md`) : objet avec `kind: Secret` : feuilles de `data` et `stringData` masquées ; objet avec `sensitive: true` : membre `value` frère masqué (sorties et variables OpenTofu).
- **Fusion** : les masques structurés sont des candidats de `merge` comme les autres (exemptions, contamination, placeholders existants), avec le `Kind` de la règle à clé correspondante, sinon de la forme trouvée dans la feuille, sinon `sensitive_variable`. Le masque d'une chaîne JSON est posé entre ses guillemets (la sortie reste décodable). Idempotence : propriété `rapid` étendue à des fragments JSON et YAML hostiles.

### D3. Désarmement des placeholders (T38)

`DisarmPlaceholders(s string) string` réécrit chaque `[REDACTED:` en `(REDACTED:` et, si suivent des minuscules ou `_` puis `]`, ce `]` en `)` (même longueur). `)` rejoint les préfixes de clé (la frontière des formes l'accepte déjà) : une clé ou un jeton collé derrière un placeholder forgé est lu, et un champ frère forgé n'annule plus une paire. Réécrire le seul `[` ne suffit pas : `]` est exclu des préfixes de clé et de la frontière (`rules.go`). Appelée par `redactMessages` sur `Content` **et** `SourceID` de chaque `UntrustedBlock`, avant `Redact` ; jamais sur `Text` (texte de Rempart, rédactions antérieures protégées, idempotence).

### D4. Expressions régulières du texte libre

Clé `\"Authorization\"` échappée ; balise XML dont le nom est une clé sensible (`<pre_shared_key>` d'`ec2:DescribeVpnConnections`) ; clé d'accès AWS (`AKIA`, `ASIA`) coupée par un seul saut de ligne, réel ou échappé, en un point quelconque ; `:` admis devant une clé suivie de `=` (`:AWS_SECRET_ACCESS_KEY=...` ; une clé suivie de `:`, forme des ARN, reste exclue) ; clé nue, `:`, saut de ligne puis valeur indentée qui n'ouvre pas un mapping (obligation (ad)) ; deux URL à identifiants collées masquées en une passe (la recherche ne consomme pas la frontière du jeton suivant) ; lectures relâchées de PSK et `Authorization` gardées par des tests (mutations X3, X4). Tout motif modifié est reporté dans `redaction-patterns.md`, modification signalée dans `docs/STATUS.md`.

### D5. Rédaction avant troncature et sérialisation

Déjà vraie : `redactMessages` (S12) précède `RenderUntrusted`, la coupe de `sanitizeSourceID` à 128 octets et l'encodage par l'adaptateur ; S12b refuse sans tronquer. Figée par `TestRedactBeforeTruncation`.

### Écarts avec la fiche M1-T08 (à reporter dans le plan)

- `MaxStructuredNodes` (repli en texte libre) est remplacé par `MaxStructuredWork` à échec fermé ; la dépendance YAML n'est pas nouvelle (R13 devient : exposition d'un décodeur existant à des données non fiables à l'exécution).
- `DisarmPlaceholders` couvre `SourceID` et le `]` ; règles 1 à 5 précisées ; `TestStructuredDecodeBounded` vérifie aussi l'échec fermé de chaque borne ; test ajouté : `TestRedactTypedSecrets` (règle 5).

## Conséquences

- Positives : chaque constat ouvert de M0-T07 et chaque cas de (ad) est traité par construction ; les appelants ne changent pas ; aucune borne n'ouvre de repli exploitable ; aucune dépendance nouvelle.
- Négatives : sur-masquage (feuilles échappées entières, contexte sensible propagé, budget épuisé ou panique) qui appauvrit les explications ; coût d'un décodage JSON et YAML à chaque appel jusqu'à 1 Mio (mesuré par `TestStructuredDecodeBounded`) ; paquet plus complexe (deux lectures, fusion) ; `go.yaml.in/yaml/v3` lit désormais des données non fiables dans le worker, plus seulement des fichiers du dépôt.
- Difficile à changer : forme désarmée `(REDACTED:...)` (traces, evals), sémantique « borne atteinte, texte masqué », listes des clés et des paires (cas de test, evals de fuite).

## Risques résiduels

- Secret en texte libre sans clé ni forme (« le mot de passe est ... », `-p x`) : non détecté ; défense première : minimisation et quarantaine (T2, T7).
- YAML incrusté dans de la prose, ou document YAML rendu invalide par une seule ligne (qu'une donnée non fiable peut écrire) : lu par les seules expressions régulières (paires sur lignes consécutives, blocs) ; le JSON incrusté, lui, est lu par fragments.
- Secret réparti entre membres d'objets ou feuilles non sœurs ; nom porté par la structure (`title`, `description` frère) ; valeur encodée (base64) hors règle 5.
- Exemption E4 jugée avec la clé de la feuille dans un contexte sensible : `{"password": {"name": "..."}}` reste en clair.
- Sur-masquage accepté, y compris provoqué par un attaquant (budget, profondeur) : il dégrade l'explication, jamais une décision (`llm-safety`, règle 1).

## Impact sécurité

- **T7, T37** : refonte exigée par la garde ; une mutation au moins par constat ; `security-reviewer` PASS exigé (critère de `prompts/M1.md`) ; `TestNoSecretInOutgoingRequest` et l'idempotence conservés.
- **T38** : D3 (contenu et `SourceID`, `[` et `]`) ; placeholder d'une feuille décodée protégé seulement s'il figure dans la forme brute ; `TestForgedPlaceholderDisarmed`.
- **T39, T69** : NUL normalisé dans la vue et la sortie, `\u0000` frontière ; forme décodée contrôlée, récursion, feuille échappée masquée entière ; `TestRedactRealNUL`, `TestRedactDoubleEncodedJSON`.
- **T81 (étendue au rédacteur)** : alias non développés ; profondeur, budget de travail et panique à échec fermé ; `TestStructuredDecodeBounded` (entrées adverses de 1 Mio : temps et allocations bornés par un multiple fixé de la taille, chaque borne masque).
- **T98 (proposée)** : repli forcé de la rédaction : une donnée non fiable épuise une borne ou rend le texte non décodable pour ramener un secret voisin aux seules expressions régulières (I) ; parades : bornes à échec fermé, fragments JSON, D4 pour le YAML hors document ; résidu : YAML rendu invalide (ci-dessus).
- **T6** : aucune dépendance nouvelle ; `govulncheck` dans `make verify`.
