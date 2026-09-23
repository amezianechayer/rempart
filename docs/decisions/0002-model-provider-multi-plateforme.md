# 0002. `ModelProvider` multi-plateforme et résidence des données dans l'UE

- Statut : accepté le 2026-09-23 (décision humaine)
- Date : 2026-09-23
- Jalon : M0

## Contexte
A6 promet un « modèle LLM configurable, option UE » ; T7 exige « option modèle UE ou auto-hébergé ; rétention nulle quand disponible ». La vision prévoit « API Anthropic via SDK Go derrière `ModelProvider` ». La cible (ETI européennes régulées, NIS2, DORA, secteur public) demandera où sont traitées les données d'architecture envoyées au modèle. La critique initiale (§4) conclut qu'il faut un `ModelProvider` multi-plateforme dès M0 et une baseline d'evals par fournisseur.

Faits, **à revérifier à la source au moment de l'implémentation** :
- API Anthropic directe : le paramètre de géographie d'inférence `inference_geo` accepte `us` ou `global`, sans valeur UE.
- Résidence UE : Amazon Bedrock (régions UE, profils d'inférence limités à l'UE) ou Google Vertex AI (région multirégionale `eu` ou région UE précise).
- Le SDK Go officiel `github.com/anthropics/anthropic-sdk-go` fournit des clients Bedrock et Vertex sur la même API Messages.
- Sorties structurées : `output_config.format` (JSON Schema) pour la réponse, `strict: true` sur les outils. Leur disponibilité peut différer selon la plateforme et le modèle.
- Certains modèles du palier le plus haut exigent une rétention de 30 jours et ne sont pas disponibles en rétention nulle.
- Les identifiants de modèle diffèrent d'une plateforme à l'autre.

Contraintes Rempart : aucune décision de sécurité par le LLM ; toute sortie validée par schéma côté code, même si la plateforme garantit le format (`llm-safety`, règle 5) ; l'appel exposé à des données non fiables n'a aucun outil (règle 2) ; tout changement de modèle relance la suite complète d'evals (`agent-evals`). Un même modèle peut se comporter différemment selon la plateforme (versions, options disponibles).

## Options envisagées
1. **(a) Interface `ModelProvider` minimale, adaptateurs natifs.** Deux appels : structuré sans outils, avec outils. Adaptateurs : Anthropic direct, Bedrock, Vertex (via le SDK officiel), faux déterministe ; plus tard un modèle auto-hébergé ou un fournisseur européen par le même contrat. Rédaction, quarantaine, budget, résidence, validation de schéma et trace vivent dans un service commun au-dessus de l'interface. Avantages : aucun intermédiaire de plus ne voit les prompts ; la règle de résidence est du code Go testé ; les options propres à chaque plateforme restent accessibles ; tests sans réseau. Inconvénients : trois adaptateurs à maintenir et des écarts de fonctionnalités à suivre ; comptes AWS et GCP d'inférence à gérer par Rempart.
2. **(b) Passerelle LLM externe** (proxy multi-fournisseurs à API commune). Avantages : nombreux fournisseurs d'emblée, budgets et journaux centralisés. Inconvénients : un composant de plus sur la frontière plan de contrôle et fournisseur, qui voit tous les prompts en clair et les journalise souvent (nouvel actif, T7) ; dépendance supplémentaire (T6) ; API au plus petit dénominateur commun (perte de `strict` et des sorties structurées natives) ; routage par tenant dans une configuration hors des tests Go ; composant de plus à livrer en auto-hébergé.
3. **(c) Anthropic direct seulement au MVP.** Avantage : le plus simple. Inconvénients : aucune résidence UE, donc A6 non tenu et cible régulée bloquée ; le code se couple aux types du SDK et le passage multi-plateforme coûte ensuite plus cher.

## Décision
Option **(a)**.

Interface (esquisse, `internal/llm/ports`) :
```go
type Route struct {
	Platform Platform // anthropic, bedrock, vertex, selfhosted, fake
	Region   string   // vide pour anthropic ; "eu-west-3", "eu", ...
	Model    string   // identifiant exact épinglé, jamais un alias
}

type Request struct {
	PromptID, PromptHash string
	System               string
	Messages             []Message       // déjà rédigés ; les données non fiables sont des UntrustedBlock
	Schema               json.RawMessage // JSON Schema de la sortie attendue
	MaxTokens            int
}

type Response struct {
	Output    json.RawMessage // brut : la validation est faite par le service, jamais par l'adaptateur seul
	ToolCalls []ToolCall
	Usage     Usage
	Model     string // modèle déclaré par la réponse, comparé à Route.Model
	RequestID string
}

type ModelProvider interface {
	// Structured n'expose aucun outil ; seul appel autorisé à recevoir un UntrustedBlock.
	Structured(ctx context.Context, route Route, req Request) (Response, error)
	// WithTools refuse toute requête contenant un UntrustedBlock.
	WithTools(ctx context.Context, route Route, req Request, tools []ToolSpec) (Response, error)
	Capabilities(route Route) Capabilities // sortie structurée native, outils stricts, rétention exigée
}
```
Le service `internal/llm.Client` est le seul point d'entrée des domaines : tenant du contexte, route du tenant (`RouteResolver`), contrôles de résidence et de rétention, rédaction, budget, appel, validation de schéma avec correction bornée, trace (plateforme, région, modèle, hash du prompt, identifiant de requête) reprise dans le dossier de preuves. Si la plateforme ne propose pas la sortie structurée native, l'adaptateur passe par le prompt ; la validation côté code reste la seule garantie.

Route par tenant :
- Chaque tenant a une route explicite, réglée par son administrateur (écran E11) : plateforme, région, modèle, exigence de résidence (`eu` ou `none`), exigence de rétention (`zero` ou `standard`).
- Pas de route par défaut : un tenant sans route n'appelle aucun modèle (`ErrNoRoute`, échec sûr).
- Résidence `eu` : seules les paires (plateforme, région) d'une liste blanche codée dans `internal/llm/domain` sont acceptées ; Anthropic direct est refusé tant que `inference_geo` n'a pas de valeur UE. Contrôle à chaque appel, pas seulement à l'enregistrement de la configuration. Un tenant qui exige un seul pays n'accepte qu'une région unique ou l'auto-hébergé, jamais un profil multirégional.
- Rétention `zero` : un modèle qui exige une rétention est refusé d'après la table de capacités.
- À partir de M1 (première boucle LLM) : une route dont la paire (plateforme, modèle) n'a pas de baseline d'evals validée est refusée.

Evals : une baseline par paire (plateforme, modèle), sous `evals/<boucle>/baseline/<plateforme>/<modèle>.json` ; le rapport ajoute `platform` et `region`. Changement de paire : suite complète. Changement de région pour une même paire : suite de fumée. L'offre se limite à deux ou trois paires pour contenir le coût des evals.

Périmètre M0 : interface, service, résolveur de route, contrôles de résidence et de rétention, faux déterministe (réponses enregistrées indexées par `PromptID` et hash de requête ; réponse absente = erreur, jamais un défaut inventé), adaptateur Anthropic direct testé contre un serveur `httptest`. Aucun appel réel en CI de PR ; appels réels la nuit. Adaptateur Bedrock (régions UE) : avant le premier envoi au modèle de données d'un client réel, au plus tard en M5 (démonstrations aux design partners). Vertex, auto-hébergé, fournisseur européen : sur demande client, par le même contrat.

Vérifié dès M0 :

| Commande | Attendu |
|---|---|
| `go test ./internal/llm/...` | `TestFakeDeterministic` : même requête, même réponse à l'octet |
| idem | `TestOutOfSchemaRejected` : sortie hors schéma rejetée |
| idem | `TestProviderContract` sur le faux et sur l'adaptateur Anthropic face à `httptest` : schéma transmis dans `output_config.format`, `strict: true` sur chaque outil |
| idem | `TestResidencyEUBlocksAnthropicDirect` : erreur, zéro requête reçue par le serveur de test |
| idem | `TestNoRouteNoCall`, `TestRetentionZeroRejectsRetentionModel`, `TestUntrustedBlockRejectedWithTools`, `TestModelMismatchRejected` |
| idem | `TestNoSecretInOutgoingRequest` : aucun corps capturé par `httptest` ne contient un motif de `.claude/skills/llm-safety/references/redaction-patterns.md` |
| `go test ./internal/archtest/...` | seul `internal/llm/adapters/...` importe `github.com/anthropics/anthropic-sdk-go` ; aucun domaine n'importe `internal/llm/adapters` |

## Conséquences
- Positives : résidence UE possible sans refonte ; règle de résidence déterministe, testée et tracée dans les preuves ; tests de boucle indépendants du réseau grâce au faux ; un fournisseur européen ou auto-hébergé s'ajoute sans toucher aux domaines.
- Négatives : suivi des écarts de fonctionnalités entre plateformes ; coût des evals proportionnel au nombre de paires offertes ; comptes d'inférence AWS et GCP de Rempart à exploiter (identités de charge de travail, quotas, journalisation des invocations côté plateforme désactivée ou chiffrée en UE).
- Difficile à changer : forme de `Request` et `Response` (les prompts versionnés s'y adossent) ; arborescence des baselines.
- Après acceptation : amender `docs/00-VISION.md` §4 (« API Anthropic » devient « Claude via l'API Anthropic, Bedrock ou Vertex, derrière `ModelProvider` ») ; adapter le skill `agent-evals` (baseline par paire), modification à signaler dans `docs/STATUS.md`.

## Impact sécurité
- **T7** : résidence UE réelle, rétention nulle vérifiée par la table de capacités, route effective tracée ; la minimisation et la rédaction restent dans le service, communes à tous les adaptateurs.
- **T2** : la séparation `Structured` et `WithTools` rend la règle « pas d'outil au contact de données non fiables » vérifiable par le type et par un test.
- **T3** : route, budget et contexte par tenant ; aucun cache de prompt partagé entre tenants contenant des données de tenant.
- **T10** : budgets appliqués dans le service, quel que soit l'adaptateur.
- **T6** : SDK épinglé et couvert par `govulncheck` ; le modèle est une dépendance : identifiant exact épinglé, tout changement relance la suite complète.

Menaces nouvelles, à intégrer au modèle de menace par `security-reviewer` après acceptation :
- Erreur de routage qui envoie hors UE les données d'un tenant `eu` (I). Atténuation : contrôle déterministe à chaque appel, route effective tracée, test dédié.
- Compromission des comptes d'inférence de Rempart sur Bedrock ou Vertex (I, D) : lecture des journaux d'invocation, épuisement de coût. Atténuation : aucune clé longue durée (fédération d'identité), journalisation d'invocation désactivée, quotas et alertes de budget.
- Substitution silencieuse de modèle par un alias ou une redirection de plateforme (T). Atténuation : identifiants exacts, contrôle du modèle déclaré par la réponse.
