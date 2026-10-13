# 0008. Politique des fournisseurs de modèle : adaptateur compatible OpenAI, OpenRouter limité aux evals synthétiques

- Statut : proposé
- Date : 2026-10-13
- Jalon : M1 (M1-T09 `llm-providers`). **Amende l'ADR 0002.** À accepter par l'humain avant la phase tests de M1-T09 (H0-M1 point 5) ; tranche O1.
- Sources : fiche M1-T09, O1, D11, ligne 0008 de la section 8, T89 à T92 et R11 de `docs/plans/M1-overview.md` ; entrée « Fournisseur LLM réel » de `docs/STATUS.md` (2026-10-13) ; ADR 0002 ; `internal/llm/domain/policy.go` ; `transport` de `internal/llm/adapters/anthropic/provider.go` ; `BaselinePath` de `internal/evals/baseline.go` ; `internal/archtest/rules.go`.

## Contexte

Le plan M1 prévoyait des appels directs à OpenAI, DeepSeek, Qwen et à l'auto-hébergé par un adaptateur compatible OpenAI. Le 2026-10-13, l'humain a choisi **OpenRouter** comme seul fournisseur réel de M1 et a fourni une clé (hors dépôt, rotation refusée, risque accepté). OpenRouter est une passerelle multi-fournisseurs, type de composant écarté par l'ADR 0002 (son option (b)) : un tiers voit les prompts en clair, le fournisseur final échappe au code, les sorties structurées se perdent, le routage sort des tests Go. Ces objections visent une passerelle **dans le produit**, sur des données client ; elles se réexaminent pour un usage borné aux evals synthétiques (tenant d'evals D11, résidence `none`, `evals/intent/` seulement).

Défaut bloquant relevé dans le code : `BaselinePath` n'admet dans un nom de modèle que `[a-z0-9-_.:@]`, sans `/` ; or tout identifiant OpenRouter s'écrit `<éditeur>/<modèle>`. Aucune baseline OpenRouter ne serait enregistrable, donc aucune route OpenRouter exécutable (D8, `ErrRouteWithoutBaseline`). Corrigé en D4.

## Faits fournisseurs

Relevés le 2026-10-13 **sans accès réseau : tous non vérifiés**. Chacun est confirmé à la source (URL et date reportées dans ce tableau) avant la phase tests de M1-T09 ; un fait infirmé change la décision par amendement (R11).

| # | Fait supposé | Statut | Sert à |
|---|---|---|---|
| F1 | Point d'accès `https://openrouter.ai/api/v1/chat/completions`, format OpenAI, clé dans `Authorization: Bearer` | non vérifié | D1, D3 |
| F2 | OpenRouter (société américaine) relaie vers des fournisseurs finaux variables (équilibrage, replis) ; `provider.order`, `allow_fallbacks`, `require_parameters`, `data_collection`, `zdr` règlent ce choix | non vérifié | D2, D3 |
| F3 | `data_collection: "deny"` écarte les fournisseurs qui conservent ou entraînent sur les données ; ce n'est pas une rétention nulle | non vérifié | D3 |
| F4 | Journalisation des prompts par OpenRouter désactivée par défaut au niveau du compte ; métadonnées conservées | non vérifié | risques |
| F5 | `response_format` `json_schema` strict pris en charge selon le modèle et le fournisseur ; `require_parameters: true` écarte tout fournisseur qui ne déclare pas un paramètre envoyé | non vérifié | D3 |
| F6 | Transformation `middle-out` (compression du prompt) appliquée par défaut à certains modèles ; `transforms: []` la désactive | non vérifié | D3 |
| F7 | Identifiants sans date (`anthropic/claude-…`, `deepseek/deepseek-chat`, `qwen/…`) ; suffixes de variante (`:free`, `:nitro`, `:floor`, `:online`, `:thinking`) ; routeur `openrouter/auto` | non vérifié | D4 |
| F8 | La réponse porte `model`, `provider` (fournisseur final, nom peut-être distinct du slug de `order`) et parfois `system_fingerprint` | non vérifié | D4 |
| F9 | Plafond de crédit réglable par clé | non vérifié | D5 |
| F10 | Localisations des plateformes non câblées : `openai` `us` ; `deepseek` `cn` ; `qwen` `sg` (point d'accès international) ou `cn` | non vérifié | D2 |

## Options envisagées

1. **(a) Adaptateur unique compatible OpenAI en `net/http` (retenue)**, OpenRouter étant une plateforme parmi d'autres. Pour : aucune dépendance (T6) ; hôte, corps et préférences de routage écrits par du code Go testé contre `httptest` ; une plateforme directe s'ajoute par une ligne de table. Contre : hétérogénéité des serveurs « compatibles » (T91, R10) à absorber par la table de capacités.
2. **(b) SDK officiel par fournisseur.** Pour : couverture fonctionnelle. Contre : dépendances multipliées (T6) ; `openai-go` lit par défaut `OPENAI_API_KEY` et `OPENAI_BASE_URL` (T19, T22) ; aucun SDK officiel ne pose les préférences propres à OpenRouter. Refusée.
3. **(c) Passerelle multi-fournisseurs comme socle** (OpenRouter pour tout tenant, ou proxy auto-hébergé). Pour : tous les modèles avec une clé. Contre : objections de l'ADR 0002 intactes pour des données client (tiers américain, fournisseur final variable, résidence `eu` impossible). Refusée comme socle ; OpenRouter admis seulement comme plateforme confinée (D2, D7).

## Décision

Option (a). Les six points proposés par l'agent principal sont retenus ; les compléments sont marqués « ajout », les écarts « écart ».

- **D1. Plateformes.** `openrouter` (nouvelle), `openai`, `deepseek`, `qwen` ajoutées à `Route` ; adaptateur unique `internal/llm/adapters/openaicompat`, `net/http` et `encoding/json` seulement. Seule `openrouter` est câblée en M1 (choix de l'humain) : `openaicompat.New` rend `ErrPlatformNotWired` pour les autres (ajout, échec fermé : aucune table d'hôtes non vérifiée). `Region` vide exigée pour `openrouter`.
- **D2. Localisation et résidence.** `ProcessingLocation` : `openrouter` vaut `global`. Résidence `eu` acceptée seulement pour une localisation `eu` ou `in-process` : OpenRouter est réservé à la résidence `none`. Les entrées de F10 sont codées et commentées « non vérifié » ; aucune ne vaut `eu`, la règle reste juste même si elles sont fausses. Aucune donnée client vers OpenRouter sans amendement de cet ADR.
- **D3. Corps OpenRouter.** Toujours `provider: {order: [<fournisseur de l'entrée>], allow_fallbacks: false, require_parameters: true, data_collection: "deny"}`, plus `zdr: true` seulement si F2 est confirmé (aucun champ non vérifié n'est envoyé) ; `transforms: []` (ajout, F6 : le prompt système n'est jamais compressé) ; `response_format` `json_schema` strict ; `stream: false`. Jamais `tools`, `tool_choice`, `functions`, `plugins`, `models`, `route`, en-têtes `HTTP-Referer` ou `X-Title`, ni `n` (ajout, F5 : `require_parameters` pourrait écarter un fournisseur qui ne déclare pas `n` ; plusieurs `choices` restent refusés). Hôte codé `https://openrouter.ai/api/v1`, `BaseURL` de bouclage pour les tests seulement ; une tentative, délai obligatoire, corps de réponse borné à 1 Mio, aucune redirection, aucun proxy.
- **D4. Épinglage (O1, option (a)).** Liste fermée de chaînes exactes, codée pour `openrouter` (plus tard `deepseek`), sans expression régulière : aucun suffixe de variante, ni `openrouter/auto`, ni casse modifiée. Chaque entrée fixe un fournisseur final unique (ajout : `order` à un élément, contre la quantification et le comportement variables, T92) ; une entrée que `data_collection: "deny"` laisse sans fournisseur est retirée, jamais assouplie. Admise en résidence `none` seulement ; rapport `pinned: false`, baseline réputée fragile ; toute entrée nouvelle passe par un amendement. Le `model` de la réponse est comparé octet à octet à la route et le `provider` à celui de l'entrée : écart refusé (précise le point 4 proposé : `TestModelMismatchRejected` inchangé) ; `model`, `provider` et `system_fingerprint` consignés dans la trace et le rapport. `BaselinePath` admet un seul `/`, encodé `%2f` comme `:` et `@` (ajout, correction du défaut bloquant) ; un nom auto-hébergé reste sans `/` (D11).
- **D5. Clé.** Lue par la seule commande `rempart-evals`, dans `REMPART_LLM_KEY_OPENROUTER` (`credentials.EnvVar` de la fiche) et non `OPENROUTER_API_KEY` (écart : un nom conventionnel est lu par défaut par d'autres outils, motif du refus de (b)) ; variable retirée de l'environnement après lecture ; KV OpenBao `rempart/llm/openrouter` en alternative. Jamais journalisée, jamais en argument ni en CI ; seulement dans `Authorization`. Plafond de crédit sur la clé (F9), posé par l'humain.
- **D6. Transport durci commun** (`internal/llm/adapters/transport`, obligation (ay), adaptateur Anthropic migré). Transport neuf sans proxy. Transport injecté refusé s'il n'est pas un `*http.Transport` ou s'il porte `Proxy`, `Dial`, `DialContext`, `DialTLS`, `DialTLSContext`, `GetProxyConnectHeader`, `OnProxyConnectResponse`, `TLSNextProto` (ajout : reçoit la connexion TLS déchiffrée) ou un `TLSClientConfig` non nul (ajout, plus strict que la liste `InsecureSkipVerify`, `KeyLogWriter`, `VerifyPeerCertificate`, `VerifyConnection`, `RootCAs`, gardée en sous-tests ; couvre aussi `Time`, `ServerName`, `MinVersion`). Aucun test existant n'injecte de configuration TLS.
- **D7. Confinement.** Règle `llm-adapters-evals-cli-only` (remplace `anthropic-unwired-m0`) : `internal/llm/adapters/...` et `internal/llm/credentials` importables par `cmd/rempart-evals` et entre adaptateurs seulement. Mode réel : tenant d'evals D11 et `evals/intent/` seulement.

Amendements de l'ADR 0002 : plateformes ci-dessus ; « jamais un alias » devient « jamais un alias hors de la liste fermée de D4, en résidence `none` » ; passerelle admise seulement comme plateforme confinée. Après acceptation : `docs/00-VISION.md` §4 cite OpenRouter (evals synthétiques seulement, ADR 0008).

Écarts avec la fiche M1-T09 (à reporter dans son plan) : `TestSelfHostedEndpointRejectsInternalAddresses` et `CheckEndpoint` suivent le câblage de `selfhosted` (obligation datée ; T22 tenu en M1 par l'hôte codé) ; `n` absent du corps OpenRouter. Vérification ajoutée aux tests de la fiche :
`go test -race ./internal/llm/... ./internal/evals/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(OpenRouterRequestBody|OpenRouterClosedList|OpenRouterProviderMismatchRejected|BaselinePathEncodesSlash|PlatformNotWired) '` : `5` (corps capturé par `httptest` : préférences, `transforms` vide, clés interdites et `n` absents ; entrée listée admise en `none`, refusée en `eu`, variantes et `openrouter/auto` refusés ; un `/` encodé, deux refusés, chemins existants inchangés).

## Conséquences

- Positives : critère 1 mesurable sur un vrai modèle dès M1 avec une seule clé ; aucune dépendance ; règle `eu` inchangée et étendue ; plateformes directes ajoutables par amendement.
- Négatives : baselines fragiles (alias) ; un tiers de plus voit les prompts d'evals ; `BaselinePath` modifié (registre D8) ; liste fermée à tenir à jour.
- Opérationnel : l'environnement cloud refuse `openrouter.ai` et ne sort que par un proxy HTTPS qui intercepte TLS ; le transport de D6 (aucun proxy, racines du système) ne peut pas, par construction, y joindre OpenRouter. Les essais réels se font depuis le terminal de l'humain. Toute exception (proxy explicite, autorité ajoutée) exige un amendement : ce proxy verrait la clé et les prompts (T47).
- Difficile à changer : encodage `%2f` des baselines ; forme des préférences ; sémantique `pinned: false`.

## Risques résiduels

- Passerelle tierce : OpenRouter voit en clair prompts, réponses et clé ; F4 non vérifié. Acceptable seulement pour des données synthétiques.
- Fournisseur final : fixé par `order`, mais connu seulement par le `provider` que déclare OpenRouter (confiance dans la passerelle) ; localisation réelle inconnue, d'où `global`.
- Alias mobiles : les poids derrière un identifiant sans date peuvent changer sans que `model` change ; seule la dérive des evals le révèle (R14).
- Clé donnée dans la conversation de l'agent, rotation refusée : contraire à la parade de T90, risque accepté par l'humain ; le plafond de crédit borne l'épuisement.
- `data_collection: "deny"` n'est pas une rétention nulle ; la politique `{none, standard}` du tenant d'evals l'accepte.

## Impact sécurité

- **T19** : `openrouter` `global`, refusé en `eu` à chaque appel ; hôte codé, `Region` vide, aucune lecture de l'environnement ; ligne `openrouter` ajoutée à `TestResidencyEUOnlyEUOrSelfHosted` ; `TestEndpointFromRouteOnly`.
- **T20** : périmètre étendu à la clé OpenRouter ; D5 ; jamais en CI ; `TestAPIKeyNeverLogged`, `TestKeyFromEnvUnset`, `TestAPIKeyOnlyInAuthorizationHeader`.
- **T21** : liste fermée exacte, `model` et `provider` comparés, baseline par couple, `pinned: false` ; `TestOpenRouterClosedList`, `TestOpenRouterProviderMismatchRejected`.
- **T22** : hôte codé, `BaseURL` de bouclage seulement, aucune redirection, aucun proxy, transport D6 (`TestTransportInjectionRefused`) ; OpenRouter, tiers qui reçoit les prompts, est borné par D2 et D7.
- **T92** : alias en `none` seulement, fournisseur final fixé, `model`, `provider` et `system_fingerprint` consignés ; `TestModelPinnedPerPlatform`.
- Proposé à `security-reviewer` : T89 étendue au relais américain et au fournisseur final variable ; T47 et T91 couverts par D3 et D6.
