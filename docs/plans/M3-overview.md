# M3 : découpage du jalon « Génération et validation IaC (AWS + Azure) »

- Date : 2026-11-25 (M2 accepté le même jour, tag `m2-done` à poser par l'humain)
- Auteur : subagent `architect`
- Statut : **validé** par l'humain le 2026-11-25 (Q1 à Q13 selon les recommandations) ; ADR 0014 accepté le 2026-11-26. Écarts de l'ADR 0014 reportés ci-dessous (section 13), au début de T02.
- Sources : `prompts/M3.md` (objectif, livrables, critères C1 à C4) ; `docs/00-VISION.md` (sections 3, 4, mode runner) ; `docs/01-LOOPS.md` (L3) ; `docs/02-THREAT-MODEL.md` (T2, T6, T8, T30, T31, T115 à T117, section 4.2) ; `docs/STATUS.md` (« M2 ACCEPTÉ », « Reste à faire », obligations (fk), (fl), (fd), garde « Avant M3 (création de `scripts/sandbox.sh`) », lot CI de la section 8.2 du plan M2) ; `docs/plans/M2-overview.md` ; `docs/plans/M0-squelette.md` (section 0, contre-revue R1) ; `docs/loops/L2.md` ; ADR 0010 (D2, D6, D8), 0011 (D1 à D6, vérification 13), 0012 (D2, D5), 0013 (D0.5, question 2) ; skills `secure-iac-generation` (`references/module-contract.md`, `scripts/validate.sh`, `scripts/normalize_findings.py`), `multicloud-networking` (`references/aws-azure-vpn.md`), `secrets-and-identity`, `kubernetes-gitops`, `loop-engineering` (gabarit), `agent-evals`, `policy-as-code` ; code : `internal/loops/{spec.go,l2}`, `internal/design/{build.go,planof.go,cidr,verify,confirm,revise}`, `internal/graph/{domain,reach}`, `internal/policy/adapters/opa/engine.go`, `policies/embed.go`, `cmd/rempart-evals/{targets.go,design.go}`, `evals/design/`, `Makefile` (cibles `sandbox-*`), `internal/{iacgen,validate,plan}` (vides), `policies/iac/` (vide, `.gitkeep`), `modules/` (vide).
- Contraintes de conduite transmises pour M3 : mode allégé (plan court, tests essentiels, code d'une traite, phases TDD du harnais) ; `architect` seulement pour les ADR ; `security-reviewer` une passe sur les tâches sensibles, seuls critiques et hauts relancent un cycle, moyens et bas deviennent des obligations datées ; une seule acceptation à `/close-milestone M3` ; 6 à 9 tâches livrables chacune en une session ; aucun identifiant cloud détenu par l'agent.
- Environnement mesuré le 2026-11-25 (session cloud) : aucun outil IaC installé ; téléchargeables : actifs de releases GitHub, PyPI, `releases.hashicorp.com` ; bloqués : API GitHub, pages HTML de releases, `registry.opentofu.org`, `registry.terraform.io`, API de prix d'Infracost ; pas de démon Docker.

Convention des commandes (reprise de M2) : `go test -v` écrit `--- PASS: TestNom (0.00s)` ; les motifs se terminent par une espace après le nom. `rc=` est le code affiché par `echo rc=$?` ; `go run` rend 1 pour tout code non nul. « Pile » : suppose `make -f Makefile dev`. « Outils » : suppose `make -f Makefile iac-tools` (T02) ; les tests qui exécutent un outil portent l'étiquette `integration` et restent hors de `verify-quick`. « Humain » : commande lancée par l'humain sur son poste.

---

## 0. Synthèse

Neuf tâches, dans cet ordre :

| Ordre | N° | Titre | Taille | Dépend de | Critère servi | Revue sécurité |
|---|---|---|---|---|---|---|
| 1 | M3-T01 | `pre-m3` : obligations datées « avant M3 » | S | aucune | aucun (préalable) | oui |
| 2 | M3-T02 | `iac-toolchain` : ADR 0014, sonde du plan hors ligne, outils et miroir vérifiés, exécution confinée | M | T01, ADR 0014 | C1, C2 (socle) | oui |
| 2b | M3-T02b | `tool-isolation` : ADR 0015, assistant de re-exécution, espaces de noms, arbre fermé, échec fermé | M | T02, ADR 0015 | C1, C2 (socle) | oui |
| 3 | M3-T03 | `validate-chain` : `internal/validate`, garde statique, parité avec `validate.sh`, `rempart check`, pack `policies/iac` | L | T02, T02b | C1, C2 | oui |
| 4 | M3-T04 | `modules-network` : réseau AWS, réseau Azure, groupe de VM Azure, VPN AWS et Azure | L | T03 | C1 | oui (groupée avec T05, Q9) |
| 5 | M3-T05 | `modules-cluster` : EKS, AKS, amorçage ArgoCD, observabilité | L | T03 | C1 | oui (groupée) |
| 6 | M3-T06 | `iacgen` : compilateur graphe vers composition, traduction des permissions, rendu, bundle | L | T04, T05 | C2 | oui |
| 7 | M3-T07 | `equivalence-sandbox` : équivalence graphe et plan, `scripts/sandbox.sh`, `make sandbox-plan` | L | T06 | C2, C3 | oui |
| 8 | M3-T08 | `l3-loop` : fiche L3, réparateur, workflow, worker, `make l3-demo` | L | T07 | C3 (boucle), C4 (mécanique) | oui |
| 9 | M3-T09 | `evals-iac` : suite `evals/iac`, cible `iac`, stagnation | M | T08 | C4 | non (revue de clôture) |

L'ADR 0014 est rédigé par `architect` pendant T01 (deux branches selon la sonde), complété par le résultat de la sonde au début de T02, accepté par l'humain avant la phase tests de T02.

---

## 1. Objectif et critères

Boucle L3 : depuis le graphe convergé de L2 (sujet `ir` confirmé), une IaC OpenTofu composée de modules internes épinglés, qui passe toute la chaîne de validation sans finding `medium` ou plus et dont le plan ne contient rien hors du graphe ; sinon, escalade expliquée. Aucune décision de sécurité ni aucun appel de modèle dans L3 en M3 (Q1). Le plan de contrôle ne détient aucun identifiant cloud, même en lecture : il planifie hors ligne ; le plan réel est lancé par l'humain sur ses comptes de bac à sable.

| Critère (`prompts/M3.md`) | Tâches |
|---|---|
| C1 chaque module : `tofu test` vert, Checkov et Trivy sans finding non justifié | T04, T05 (outils T02, chaîne T03) |
| C2 scénario de référence : chaîne verte, `tofu plan` réel sur comptes sandbox par `make sandbox-plan` | T06 (bundle), T07 (`sandbox.sh`, équivalence), étape humaine H-sandbox-plan ; convergence de L3 sur la référence en T08 |
| C3 une ressource injectée dans le HCL hors graphe est détectée par l'équivalence et bloque | T07 (CLI et plan), T08 (la boucle ne converge pas), T09 (trappe d'evals) |
| C4 evals L3 : convergence en 8 itérations au plus sur 90 % des cas, stagnation testée | T09 (avec T08) |
| Livrable `modules/` (8 modules, tests, contrat) | T04, T05 |
| Livrable `internal/validate` (chaîne complète, erreurs normalisées, même sortie que `scripts/validate.sh`) | T02 (exécution), T03 |
| Livrable `internal/plan/equivalence` | T07 |
| Livrable `docs/loops/L3.md`, workflow L3 | T08 |
| Livrable evals L3 | T09 |
| Vérificateur de L3 (`docs/01-LOOPS.md`) : aucun finding `medium` ou plus, aucune exception de politique, équivalence, coût dans le budget | T03, T07, T08 ; coût : Q6 |

## 2. Périmètre

**Dans** : chaîne d'outils IaC épinglée et vérifiée (OpenTofu, providers par miroir fichier, tflint et ses rulesets, Checkov, Trivy) ; exécution confinée des commandes (`internal/validate/toolexec`) ; `internal/validate` (garde statique, étages, normalisation, parité avec `scripts/validate.sh`) et `rempart check <dossier>` (`docs/04-INTERFACE.md` section 8) ; `internal/plan` (décodage strict du plan JSON) ; pack `policies/iac/` évalué par le moteur OPA embarqué (Q5) ; 8 modules au contrat de `module-contract.md` ; `internal/iacgen` (composition typée, compilateur, allocations dérivées, traduction des permissions, rendu, bundle, modules embarqués) ; `internal/plan/equivalence` ; `internal/iacgen/repair` ; `internal/loops/l3`, worker `-l3-once`, `make l3-demo` ; `scripts/sandbox.sh` et `make sandbox-plan` ; suite `evals/iac` et cible `iac` ; obligations (fk), (fl), (fd), (cf), T31 ; alignement du skill `secure-iac-generation` (signalé dans `docs/STATUS.md`).

**Hors** : appel de modèle dans L3 et stratégie `modules_plus_freeform` par LLM (Q1) ; stratégie `decompose_by_cloud` (Q1) ; blocage par le coût (Q6, L4 en M4) ; `sandbox-apply` et `sandbox-destroy` effectifs (aucun critère de M3 ne les exige ; le script les refuse sans approbation, Q10) ; runner et plan signé (M4) ; backend distant par tenant (M4 avec le runner) ; dossier de preuves, PR et intégration Git (M4, T25) ; modules OVHcloud, Scaleway, stockage objet, base managée (M7 ; L3 escalade `module_missing`) ; `policies/k8s/` au niveau manifeste et choix Kyverno ou Gatekeeper (Q11, M5) ; Terratest et tout test qui exige un compte réel ; sujet `graph` dans L3 (T115, Q3) ; L7 et L8 (seule la forme d'entrée `initial` est posée).

---

## 3. Décisions proposées (réversibles, reprises dans l'ADR 0014)

| # | Décision |
|---|---|
| D1 (Q1) | **Proposeur déterministe.** `iacgen.Compile` traduit le graphe en composition typée de modules internes ; `repair.Repair` applique un catalogue fermé de corrections ; aucun LLM, aucun import de `internal/llm` sous `internal/iacgen`, `internal/validate`, `internal/plan`, `internal/loops/l3`. |
| D2 (Q1) | **Stratégies** `repair` puis `recompile`, seuils de stagnation 2 et 3. `repair` corrige la composition courante (`pin_version`, `remove_orphan`, `add_missing`, `set_from_graph`) ; `recompile` repart de `Compile(graph)` et abandonne tout ce que le compilateur ne produit pas. `modules_plus_freeform` (LLM derrière le même vérificateur, route et baseline à calibrer) et `decompose_by_cloud` (un état par cloud, VPN en racine d'interconnexion : plan en deux temps) sortent de M3 ; `docs/01-LOOPS.md` amendé par l'ADR. |
| D3 (Q3, T115) | **Entrée** `{ir, confirmation, graph, initial?}`, tenant du worker. `l3.Prepare` recalcule au lieu de croire : `ValidateIR`, `confirm.Check` sur `DigestOfIR`, `verify.Derives(Build(ir), graph)`, vérificateur de L2 rejoué sur `graph` (aucun critique ni haut, couverture des expositions), tenant égal à celui du worker. Échec : `InvalidL3Input`, non rejouable, avant toute activité de boucle. Aucun sujet `graph` tant qu'un ADR ne lève pas T115 (confirmation signée, M4 ; éditeur, M8). `initial` n'est jamais de confiance : c'est un point de départ que le vérificateur juge. |
| D4 (T147) | **Composition typée, HCL rendu par Go.** Aucun HCL libre accepté en M3. La composition liste des appels de module (catalogue fermé, version exacte, entrées typées : littéraux ou références aux sorties d'un autre appel) et des blocs `extra` typés (type de ressource en liste fermée par fournisseur, attributs littéraux), emplacement réservé au HCL libre de D2. Aucun texte libre du graphe ou de l'IR n'atteint l'HCL ; rendu par `hclwrite`, ordre total, `${` et `%{` échappés dans toute chaîne. Taille au plus `loops.MaxCandidateBytes`. |
| D5 (Q8) | **Bundle** : deux racines, `infra` (réseaux, calcul, clusters, VPN) et `cluster` (ArgoCD et applications), appliquées dans cet ordre ; modules vendorisés depuis le binaire (`modules/embed.go`, règle archtest `modules-confined` : seul `internal/iacgen` importe le paquet `modules`) avec manifeste SHA-256 par fichier ; verrou des providers commun (`.terraform.lock.hcl`, hachages `zh:` et `h1:`) ; aucun bloc `backend`, `cloud`, `encryption`, `provider` avec identifiant ; valeurs de l'exécutant en variables (`rempart_owner`, `rempart_change_id`, identifiants de compte, chiffrement de l'état par `TF_ENCRYPTION`). Empreinte du bundle = SHA-256 des netstrings (chemin, contenu) triés. |
| D6 | **Chaîne** (`internal/validate`), du moins cher au plus cher : garde statique (toujours en premier ; jamais d'outil sur un arbre refusé), `fmt`, `init` (miroir seul, `-lockfile=readonly`), `validate`, puis tflint, Checkov et Trivy en parallèle, puis plan hors ligne, pack `iac`, équivalence, coût (`not_evaluated`, Q6). Arrêt au premier étage bloquant, étages suivants `skipped`. Échec fermé : outil absent, somme fausse, code de sortie non documenté, sortie illisible ou au-delà de sa borne, sévérité inconnue donnent un finding critique (`TOOL_MISSING`, `TOOL_FAILED`, `TOOL_OUTPUT_INVALID`). Findings dans `loopsdomain.Finding`, empreinte et score de `loopsdomain` (netstrings) ; `scripts/validate.sh` et `normalize_findings.py` alignés (même sortie sur les mêmes sorties brutes). |
| D7 (T30, T142 à T144) | **Garde statique** sur l'arbre HCL analysé (`hclsyntax`, jamais par expression régulière seule) : annotations de scanners dans tout commentaire et toute casse (`checkov:skip`, `trivy:ignore`, `tflint-ignore`, `tfsec:ignore`, `#nosec`) ; fichiers de configuration de scanner (`.tflint.hcl` hors celui de la chaîne, `.checkov.y*ml`, `.trivyignore*`, `trivy.y*ml`) ; `provisioner`, `connection`, données `external` et `http`, ressources `local_file` et `local_sensitive_file`, `terraform_remote_state`, blocs `backend` et `cloud` ; fonctions qui lisent le système de fichiers (`file*`, `templatefile`, `pathexpand`, `abspath`) ; sources de module autres que `./modules/<nom>` du manifeste ; `required_providers` sans version exacte ou hors liste ; fichiers `*.tofu`, `*_override.tf`, `*.tf.json`, `.terraformrc`, `terraform.rc`, répertoire `.terraform/` ; liens symboliques, non UTF-8, fichiers au-delà de leur borne ; fichier vendorisé dont la somme diffère du manifeste (`MODULE_TAMPERED`). |
| D8 (Q2) | **Plan hors ligne** dans le plan de contrôle : `tofu plan -refresh=false -lock=false -out` sur un état vide éphémère, providers configurés sans aucun identifiant (AWS : `skip_credentials_validation`, `skip_requesting_account_id`, `skip_metadata_api_check`, clés factices ; azurerm et helm selon la sonde de T02), sans source de données qui appelle une API (zones de disponibilité et identifiant de compte en variables), réseau coupé pour le processus (`HTTPS_PROXY` vers une adresse injoignable, environnement construit). Jamais de faux point d'authentification. Plan réel : humain en M3 (`sandbox.sh`), runner en M4, qui rejoue l'équivalence. |
| D9 (Q5) | **Pack `policies/iac` embarqué** : `opa.NewIaC()` dans le seul adaptateur OPA (règle `opa-confined` inchangée), `//go:embed iac/*.rego`, paquets `rempart.iac.<nom>`, requête `data.rempart.iac[_].deny[_]`, même barrière AST, mêmes capacités, mêmes métadonnées ; entrée `IaCInput` de faits extraits du plan en Go (schéma strict `schemas/policy/iac-input-v1.json`), jamais le plan brut ; `control_id` repris de `policies/design` quand l'intention est la même ; `opa check` lancé par pack avec son schéma. Conftest n'est pas utilisé. Amende ADR 0011 D4 et D6, la vision (section 4) et le skill `policy-as-code`. |
| D10 (T146) | **Équivalence** à deux niveaux. Composition : chaque appel et chaque `extra` réalise des éléments existants du graphe, chaque élément du graphe est réalisé, entrées de sécurité égales à celles que dicte le graphe. Plan : chaque ressource du plan est rattachée par son adresse de module (jamais par nom ni étiquette) à un appel de la composition, et son type figure dans la table fermée du module pour cet élément, à la cardinalité attendue ; atteignabilité tirée des règles SG et NSG du plan incluse dans celle du graphe (`reach.SubsetOf`, une seule implémentation) ; actions IAM incluses dans la traduction ; adresses publiques seulement sur les éléments exposés du graphe ; complétude des attributs de sécurité (chiffrement, journaux, API privée). Codes `EQUIV-ORPHAN`, `EQUIV-MISSING`, `EQUIV-REACH`, `EQUIV-IAM`, `EQUIV-PUBLIC`, `EQUIV-ATTR`, `EQUIV-PLAN-INVALID`, tous critiques. |
| D11 (T117) | **Traduction des permissions** : table fermée par (cloud, type et sous-type de cible, action abstraite), versionnée, chaque ligne sourcée (domaine du fournisseur) et datée. Aucun joker (`*`, `?`), aucune action d'une autre catégorie (`read` sans verbe d'écriture ni d'administration), portée la ressource elle-même. Azure : rôles personnalisés aux `DataActions` exactes, jamais un rôle intégré (sa définition peut s'élargir sans nous). `admin` et `*` jamais traduits en M3. `dataset` hébergé par un `Compute` : ligne `host_local` (aucune permission cloud). Sans ligne : `L3-NO-TRANSLATION` critique. |
| D12 (Q7, T116) | **Allocations dérivées**, toutes par `internal/design/cidr` et contrôlées par `cidr.Check` sur l'union avec le plan du graphe : sous-réseaux par zone de disponibilité contenus dans le sous-réseau du graphe (EKS et LB exigent deux zones) ; `GatewaySubnet` /27 dans l'espace libre du VNet ; /30 APIPA dans la plage Azure ; ASN 64512 (AWS) et 65515 (Azure) explicites. Sources des règles réseau calculées depuis les `MEMBER_OF`, jamais depuis `path`. |
| D13 (Q7) | **Ressources de soutien** : par type d'élément du graphe, liste fermée, cardinalité exacte, attributs contraints (passerelle Internet d'un VPC à tier public, NAT selon Q7, tables de routage, journaux de flux, clés KMS et Key Vault, groupes de journaux, rôles de plate-forme EKS et AKS à politiques gérées épinglées). L'egress (NAT) est signalé à part dans le rapport d'équivalence. |
| D14 (Q6) | **Coût** : port `CostEstimator` ; en M3 l'étage rend `not_evaluated`, sans finding bloquant ; blocage en L4 sur le plan réel (M4) ; Infracost seulement dans `sandbox.sh` si l'humain a sa clé dans son environnement. |
| D15 (Q4, T6, T143) | **Outils et providers** : `scripts/iac-tools.sh` (`install`, `verify`, `mirror`) sur le verrou `scripts/iac-tools.lock.json` (nom, version exacte, URL, SHA-256, date de publication, empreinte de la clé de signature) ; cache hors dépôt ; providers dans un miroir fichier peuplé depuis `releases.hashicorp.com`, sommes vérifiées sur `SHA256SUMS` signé ; version la plus récente publiée depuis au moins 14 jours ; configuration CLI `provider_installation` en miroir seul ; Checkov dans un venv par `pip --require-hashes` ; rulesets tflint et charts Helm depuis les actifs de releases GitHub, sommes au verrou. |
| D16 (Q9, T30, T148) | **Exceptions de scanners** : aucune annotation, nulle part (modules compris) ; fichier central `modules/scanner-exceptions.json` sous CODEOWNERS, une entrée par (outil, check, module, adresse), justification, expiration à 180 jours au plus, approbateur humain ; entrée périmée ou sans finding correspondant : erreur. |
| D17 (Q10, T31, T149) | **Bac à sable** : `plan` seul exigé en M3, identité en lecture (AWS `ReadOnlyAccess`, Azure `Reader`) fournie par l'environnement de l'humain ; sans elle, code 2 avant tout appel d'outil ; `apply` et `destroy` seulement sur le fichier de plan enregistré dont l'empreinte a été affichée, après la permission « ask » et des identifiants d'écriture obtenus sous MFA par l'humain ; sortie résumée sans identifiant de compte ; `.sandbox/` ignoré par git ; état et plan chiffrés (chiffrement natif d'OpenTofu). |
| D18 | **Boucle** : 8 itérations, `max_tokens` 1 (aucun modèle), 30 minutes, `ActivityTimeout` 10 minutes ; escalade sans composition ni bundle (analogue de T98) ; `Finalize` rejoue la garde statique et l'équivalence de composition sur le final et lie le rapport à l'empreinte du bundle ; workflow `rempart.l3.v1`, file `rempart-l3`, worker de L3 qui vérifie la chaîne d'outils au démarrage (échec fermé). |
| D19 (Q11) | **Faits Kubernetes réalisés** : `admission_policy` par Pod Security Admission `restricted` sur les espaces de noms hors système ; `network_policy_default_deny` par moteur de politique réseau activé (VPC CNI, AKS) et NetworkPolicy deny par défaut par espace de noms ; `audit_log`, `secrets_encryption`, `workload_identity` par les entrées des modules EKS et AKS. |
| D20 | **Dépendance** `github.com/hashicorp/hcl/v2` (et `go-cty`) pour la garde statique et le rendu, mesurée dans l'ADR (modules, `govulncheck`), importée par `internal/validate` et `internal/iacgen` seulement. |

### 3.1 Interfaces principales (Go)

```go
package composition // internal/iacgen/composition : bibliothèque standard et internal/*/domain seulement
const SchemaVersion = "1"
type ModuleRef struct{ Name, Version string } // catalogue fermé, version exacte
type OutputRef struct{ Call, Output string }
type Value struct { // aucune expression, aucun texte libre
	Kind string // string, number, bool, list, map, ref
	Str  string
	Num  int64
	Bool bool
	List []Value
	Map  map[string]Value
	Ref  *OutputRef
}
type Call struct{ ID string; Module ModuleRef; Realizes []string; Inputs map[string]Value }
type Extra struct{ ID, Type string; Realizes []string; Attrs map[string]Value } // bloc libre typé (D4)
type Root struct{ Name string; Calls []Call; Extras []Extra }                   // "infra", "cluster"
type Composition struct{ SchemaVersion, TenantID, GraphRevision, CatalogDigest string; Roots []Root }
var ErrInvalid error
func Decode(raw []byte) (Composition, error) // strict, borné, grammaires fermées
func (c Composition) Digest() (string, error)

package iacgen // internal/iacgen : seul importeur du paquet modules
type Bundle struct{ Files map[string][]byte; SHA256 string }
const CodeModuleMissing, CodeNoTranslation = "L3-MODULE-MISSING", "L3-NO-TRANSLATION"
func Compile(g graphdomain.Graph) (composition.Composition, []loopsdomain.Finding, error)
func Render(c composition.Composition) (Bundle, error) // hclwrite, ordre total
func Catalog() []composition.ModuleRef

package iam // internal/iacgen/iam
type Mode string // inline_policy, custom_role, host_local
type Row struct{ Cloud, Target, Subtype, Action string; Mode Mode; Actions []string; Source, Verified string }
var ErrNoTranslation error
func Translate(cloud string, target graphdomain.FactNode, actions []string) ([]Row, error)

package repair // internal/iacgen/repair : composition et loopsdomain seulement
type Fix string // pin_version, remove_orphan, add_missing, set_from_graph
type Applied struct{ Code, Resource string; Fix Fix }
func Repair(cur, compiled composition.Composition, f []loopsdomain.Finding) (composition.Composition, []Applied, error)

package toolexec // internal/validate/toolexec : seul importeur d'os/exec hors cmd/rempart-evals et internal/archtest
type Tool struct{ Name, Version, Path, SHA256 string }
type Spec struct{ Tool Tool; Args []string; Dir string; Env []string; Timeout time.Duration; MaxStdout, MaxStderr int64 }
type Result struct{ ExitCode int; Stdout, Stderr []byte }
var ErrChecksum, ErrTimeout, ErrOutputTooLarge error
func Run(ctx context.Context, s Spec) (Result, error) // sans shell, somme revérifiée, environnement construit, HOME et TMPDIR éphémères

package domain // internal/validate/domain : types purs, lisibles par le paquet de workflow de L3
type Stage string       // static, fmt, init, validate, tflint, checkov, trivy, plan, policy, equivalence, cost
type StageStatus string // ok, findings, failed, skipped, not_evaluated
type StageResult struct{ Stage Stage; Status StageStatus; Tool, Version string }
type Report struct {
	Findings     []loopsdomain.Finding // 100 plus graves
	Omitted      int
	Fingerprint  string // loopsdomain.Fingerprint
	Score        int
	OK           bool
	Stages       []StageResult
	BundleSHA256 string
}

package validate // internal/validate
type Mode string // bundle, module
type Planner interface{ Plan(ctx context.Context, bundle fs.FS, root string) (plan.Plan, error) }
type PolicyEvaluator interface{ Evaluate(ctx context.Context, in policy.IaCInput) ([]loopsdomain.Finding, error) }
type EquivalenceChecker interface{ Check(p plan.Plan) ([]loopsdomain.Finding, error) }
type CostEstimator interface{ Estimate(ctx context.Context, p plan.Plan) (vdomain.StageStatus, []loopsdomain.Finding, error) }
type Ports struct{ Planner Planner; Policy PolicyEvaluator; Equivalence EquivalenceChecker; Cost CostEstimator }
type Options struct{ Timeout time.Duration; MaxOutputBytes int64; MaxFindings int }
type Toolchain struct{ /* outils du verrou, vérifiés */ }
func LoadToolchain(lock []byte, cacheDir string) (Toolchain, error)
func Static(fsys fs.FS, m Mode) []loopsdomain.Finding
func Normalize(raw map[string][]byte) (vdomain.Report, error) // pure ; parité avec normalize_findings.py
func Run(ctx context.Context, tc Toolchain, bundle fs.FS, p Ports, o Options) (vdomain.Report, error)

package plan // internal/plan
type Resource struct{ Address, Module, Type, Name, Mode string; Actions []string; After map[string]any }
type Plan struct{ FormatVersion string; Resources []Resource }
func Decode(raw []byte) (Plan, error) // strict, borné, format_version en liste blanche, doublons refusés

package equivalence // internal/plan/equivalence
func CheckComposition(g graphdomain.FactsGraph, c composition.Composition) []loopsdomain.Finding
func CheckPlan(g graphdomain.FactsGraph, c composition.Composition, p plan.Plan) ([]loopsdomain.Finding, error)

package policy // internal/policy
type IaCInput struct{ /* faits typés par ressource du plan, sans texte libre */ }
func NewIaCInput(p plan.Plan, g graphdomain.FactsGraph) (IaCInput, error)

package opa // internal/policy/adapters/opa
func NewIaC() (*IaCEngine, error) // pack policies/iac, même barrière, capacités, métadonnées

package l3 // internal/loops/l3 : n'importe ni internal/validate (hors domain), ni os/exec, ni internal/llm
const WorkflowName = "rempart.l3.v1"
const ErrTypeInvalidL3Input = "InvalidL3Input"
type Input struct {
	IR           *intentdomain.IR
	Confirmation confirm.Confirmation
	Graph        *graphdomain.Graph
	Initial      *composition.Composition // facultative, jamais de confiance
} // aucun tenant : celui du worker
type Explanation struct{ Code, FindingCode, Resource, Text string } // Text : gabarit codé
type Output struct {
	Status, Reason         string
	Composition            *composition.Composition // converged seulement
	BundleSHA256           string                   // converged seulement
	Report                 *vdomain.Report          // final, converged seulement
	Applied                []repair.Applied
	InitialFindings        []loopsdomain.Finding
	InitialFindingsOmitted int
	Explanation            []Explanation // escalated seulement
	Loop                   loops.LoopResult // Best vidé
}
func Spec() loops.LoopSpec // littéral constant
```

### 3.2 Flux de données

1. L1 produit l'IR ; l'humain la confirme ; L2 converge et rend `graph` (sujet `ir`).
2. Entrée de L3 : `{ir, confirmation, graph, initial?}`, au plus 256 Kio. `Prepare` décode strictement, recalcule (D3), borne, compile (`Compile(graph)`) et construit la charge : graphe (faits), composition compilée, clés confirmées.
3. `Propose` : itération 1 : `initial` si fournie, sinon la composition compilée ; ensuite `repair` ou `recompile` selon la stratégie. Le candidat est la composition (JSON, 64 Kio au plus), jamais l'HCL.
4. `Verify` : rendu déterministe dans un répertoire éphémère (`os.Root`), garde statique, outils par `toolexec` sans réseau ni identifiant, plan hors ligne, `IaCInput` puis pack `iac`, équivalence (composition puis plan), coût `not_evaluated`. Sortie : findings normalisés (code, ressource) ; aucun message d'outil n'est lu par une décision.
5. `RunLoop` : empreinte, stagnation, budget ; `Finalize` : rapport final, explication codée si escalade.
6. Sortie : composition et empreinte du bundle ; le bundle se reconstruit à l'identique par `rempart iac compile` (aucun gros objet dans l'historique Temporal).
7. Côté humain : `make sandbox-plan SCENARIO=reference` rend le bundle, initialise sur le miroir, planifie avec l'identité en lecture, rejoue chaîne et équivalence sur le plan réel, affiche un résumé JSON.

Rien ne quitte le plan de contrôle vers un tiers : ni modèle, ni API de prix, ni registre ; Checkov en `--skip-download`, Trivy sur règles embarquées (à vérifier en T02).

---

## 4. Fiche de la boucle L3 (recopiée dans `docs/loops/L3.md` au début de T08, avant le code)

```yaml
id: L3-iac
workflow: rempart.l3.v1
purpose: produire une composition OpenTofu de modules internes, verte sur toute la chaîne et équivalente au graphe convergé de L2, ou escalader en expliquant
trigger: démarrage explicite (make l3-demo, cible d'eval iac, tests) ; à terme, sortie convergée de L2 (M4)
inputs:
  - ir             # Intent IR v1, celle que L2 a confirmée
  - confirmation   # empreinte de l'IR et clés d'exposition (ADR 0012 D3)
  - graph          # graphe convergé de L2 ; L3 recalcule Build(ir), Derives, vérificateur de L2 (T115)
  - initial        # composition initiale facultative (evals ; L7 et L8 plus tard), jamais de confiance
  # tenant : celui du worker ; tenant de l'IR, du graphe ou de la composition différent : refus avant la boucle
strategies: [repair, recompile]
steps:
  prepare: activité l3.Prepare (formes, tenant, bornes, garde T115, compilation, refus InvalidL3Input non rejouable ou escalade sans boucle)
  propose: activité l3.Propose (itération 1 : initial ou composition compilée ; ensuite repair.Repair ou recompile)
  verify: activité l3.Verify (rendu, garde statique, fmt, init, validate, tflint, checkov, trivy, plan hors ligne, pack iac, équivalence, coût not_evaluated)
  diagnose: findings normalisés (code, ressource), 100 plus graves rendus, 20 premiers renvoyés au proposeur
  finalize: activité l3.Finalize (garde statique et équivalence de composition rejouées sur le final, rapport lié à l'empreinte du bundle, explication codée si escalade)
verifier:
  success_when:
    - aucun finding medium ou plus (garde statique, outils, pack iac, équivalence)
    - aucune exception de politique dans le bundle (annotations et fichiers de configuration de scanner refusés, T30)
    - équivalence graphe et plan : aucune ressource, permission, règle réseau ou exposition hors graphe ; chaque élément du graphe réalisé
    - coût : not_evaluated en M3 (Q6), bloquant en L4
budget: {max_iterations: 8, max_tokens: 1, max_wall_time: 30m, max_cost_eur: 0}   # aucun modèle en M3
stall_detection: {same_fingerprint_switch_strategy: 2, same_fingerprint_escalate: 3}
escalation:
  to: résultat du workflow (statut escalated), aucune composition, aucun bundle, aucun best
  payload: [initial_findings, explication codée, corrections appliquées, stratégies essayées, trace]
outputs: [status, reason, composition (converged), bundle_sha256 (converged), report (converged), applied, initial_findings, initial_findings_omitted, explanation (escalated), loop]
idempotency_keys: [tenant_id, workflow_id]
security_notes: aucun texte libre dans l'HCL ; aucun outil sur un arbre refusé par la garde statique ; outils sans shell, sans réseau, sans identifiant, environnement construit ; aucun modèle ; réparateur borné à la composition compilée ; historique chiffré (ADR 0001)
evals: evals/iac/
```

Codes d'escalade : `module_missing`, `no_translation`, `equivalence_violation`, `chain_failed`, `tool_unavailable`, `payload_too_large`, `evaluation_failed`, `manual_fix_required`. Gabarit français fixe par code, paramétré seulement par un code de finding et une ressource vérifiés par grammaire (identifiant du graphe, adresse OpenTofu `[a-z0-9_.\[\]"-]+`).

---

## 5. Tâches

### M3-T01 `pre-m3` : obligations datées « avant M3 »

- **Objectif** : solder ce qui précède tout code de M3 : confinement du moteur OPA avant le second pack, arbre `policies/` fermé, échec sûr des cibles de bac à sable avant la création du script (T31).
- **Dépend de** : aucune. En parallèle : rédaction de l'ADR 0014 par `architect` (H0-M3.2).
- **Livrables** : (fk) barrière AST de `internal/policy/adapters/opa` : toute référence `data` hors `data.rempart.<pack compilé>` refusée (`data` nu, `data[x]`, `data.rempart`, autre pack, paquet de test) ; (fl) `internal/archtest` : fichiers de `policies/` limités à `.rego`, `embed.go`, `.gitkeep` (vérification 13 de l'ADR 0011 devenue mécanique), tout répertoire qui contient un `.rego` couvert par une directive `//go:embed` lue par un constructeur de l'adaptateur, aucun sous-répertoire de second niveau ; (fd) `internal/intent/domain` lit `policydomain.Jurisdiction`, `regions.go` supprimé ; T31 : dans `sandbox-plan`, `sandbox-apply`, `sandbox-destroy`, validation de `SCENARIO`, confirmation lue sur `/dev/tty` (apply, destroy) et appel de `scripts/sandbox.sh` sur une seule ligne logique chaînée par `&&` ; refus par test du préfixe `-` sur toute ligne de recette, de `.IGNORE`, de `MAKEFLAGS` affecté ou lu (y compris `MAKEFLAGS=` en texte shell) ; (cf) `cmd/rempart-evals/git.go` : `-c core.hooksPath=/dev/null -c diff.external=` ; proposition `docs/proposals/0011-ci-avant-m3.md` pour (ce), (cg), (bq), (br) (`.github/` sous CODEOWNERS).
- **Tests clés (6)** : `TestEngineRefusesForeignDataRefs`, `TestPoliciesTreeClosed` (cas négatifs sur arbre de test : `.json`, `.yaml`, sous-répertoire non embarqué), `TestIntentZonesFromJurisdiction`, `TestSandboxRecipesChained`, `TestSandboxIgnoreErrorsNeverCalls` (copie temporaire avec faux `scripts/sandbox.sh` qui consigne ses appels ; `make -i`, `MAKEFLAGS=i` et `-k` ; processus détaché du terminal par `setsid` : faux script jamais appelé), `TestGitOptionsFrozen`.
- **Acceptation** :
  1. `go test ./internal/policy/... ./internal/archtest/ ./internal/intent/... ./cmd/rempart-evals/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(EngineRefusesForeignDataRefs|PoliciesTreeClosed|IntentZonesFromJurisdiction|SandboxRecipesChained|SandboxIgnoreErrorsNeverCalls|GitOptionsFrozen) '` : `6`.
  2. `find policies -type f ! -name '*.rego' ! -name embed.go ! -name .gitkeep | wc -l` : `0` ; `test -e internal/intent/domain/regions.go; echo rc=$?` : `rc=1`.
  3. `grep -cE '&& \./scripts/sandbox\.sh (plan|apply|destroy) "\$\$SCENARIO"$' Makefile` : `3`.
  4. `make -f Makefile opa-test; echo rc=$?` : `rc=0` (pack inchangé).
  5. `test -f docs/proposals/0011-ci-avant-m3.md && echo ok` : `ok`.
  6. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
- **Sécurité** : oui (T31, T108, T109, exécution de git).

### M3-T02 `iac-toolchain` : ADR 0014, sonde, outils et miroir vérifiés, exécution confinée

- **Objectif** : une chaîne d'outils reproductible, vérifiée par sommes, sans registre ni identifiant, et un seul point d'exécution de commandes (T8).
- **Dépend de** : T01 ; ADR 0014 accepté avant la phase tests (après la sonde).
- **Étape 0, sonde (avant toute phase, rien dans le dépôt)** : outils et providers téléchargés dans un cache hors dépôt ; `tofu init` sur miroir fichier ; `tofu plan` hors ligne (D8) sur trois racines jetables : AWS (VPC, EKS, IAM), azurerm (VNet, VM, passerelle VPN), helm (chart local) ; réseau coupé pour le processus. Résultat par provider (faisable, faisable avec réglage, impossible) consigné dans l'ADR 0014 et `docs/STATUS.md` ; il fixe la branche de Q2.
- **Livrables** : `scripts/iac-tools.lock.json`, `scripts/iac-tools.sh` (`install`, `verify`, `mirror`, `env`), `scripts/checkov-requirements.lock` (hachages) ; configuration CLI d'OpenTofu générée (miroir seul) ; `internal/validate/toolexec` ; `internal/validate/toolchain.go` (`LoadToolchain`, somme revérifiée avant chaque exécution) ; règle archtest `exec-confined` ; cible `make iac-tools` et `internal/archtest/makefile_test.go` ; `docs/SETUP.md` (section outils IaC) ; mesure de la dépendance `hcl/v2` (D20) dans l'ADR ; proposition harnais `docs/proposals/0013-garde-iac.md`.
- **Tests clés (8)** : `TestToolexecNoShell` (`;`, `$(...)`, guillemets passés tels quels), `TestToolexecEnvBuilt` (canari d'environnement invisible pour l'enfant ; aucun `AWS_*`, `ARM_*`, `TF_*` hérité, `HTTPS_PROXY` neutralisé), `TestToolexecChecksum` (binaire modifié après verrou : refus avant exécution), `TestToolexecBounds` (délai qui tue le groupe de processus, sortie au-delà de la borne : erreur, jamais une sortie tronquée lue), `TestExecConfined`, `TestIaCToolsLockPinned` (version exacte, URL `https` sur hôtes listés, SHA-256, publication antérieure de 14 jours au moins à la date du verrou), `TestTofuCLIConfigMirrorOnly` (aucun `direct`, `network_mirror` ni `credentials`), `TestMakefileIaCToolsTarget`.
- **Acceptation** :
  1. `go test ./internal/validate/... ./internal/archtest/ -v 2>&1 | grep -Ec -- '^--- PASS: Test(ToolexecNoShell|ToolexecEnvBuilt|ToolexecChecksum|ToolexecBounds|ExecConfined|IaCToolsLockPinned|TofuCLIConfigMirrorOnly|MakefileIaCToolsTarget) '` : `8`.
  2. `make -f Makefile iac-tools; echo rc=$?` : `rc=0` ; `bash scripts/iac-tools.sh verify; echo rc=$?` : `rc=0`.
  3. Outils : `go test -tags=integration ./internal/validate/... -run 'Test(OfflineInitFromMirror|OfflinePlanProbe)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(OfflineInitFromMirror|OfflinePlanProbe) '` : `2` (le second fige le résultat de la sonde inscrit dans l'ADR).
  4. `go list -f '{{.ImportPath}} {{join .Imports " "}}' ./internal/... ./cmd/rempart ./cmd/rempart-worker | grep -E ' os/exec( |$)' | cut -d' ' -f1 | grep -vE '/internal/(archtest|validate/toolexec)$' | wc -l` : `0`.
  5. `jq -e 'all(.tools[]; (.sha256 | test("^[0-9a-f]{64}$")) and (.url | startswith("https://")) and (.version | test("^[0-9]+[.][0-9]+[.][0-9]+$")))' scripts/iac-tools.lock.json` : `true`.
  6. `make -f Makefile verify-quick; echo rc=$?` : `rc=0` (sans outil IaC installé).
- **Sécurité** : oui (T6, T8, T143).

### M3-T02b `tool-isolation` : isolation des outils (ADR 0015)

- **Objectif** : aucun outil de la chaîne ne voit les processus, fichiers, sockets, réseau ou terminal de son lanceur, d'un autre outil ou d'un autre tenant ; échec fermé (obligation (hg), T157).
- **Dépend de** : T02 ; ADR 0015 accepté le 2026-11-26.
- **Livrables** :
  - `internal/validate/toolexec` : socle (lanceur non « dumpable » avec la bascule de F10, `Setsid`, `Pdeathsig` sur une goroutine verrouillée) ;
  - assistant de re-exécution (`MaybeHelper`, descripteurs 3 et 4, poignée de main), capacités ambiantes de F11 ;
  - espaces de noms de D3, arbre fermé de D5 par `pivot_root` (options verrouillées de F12), durcissement de D6, binaire scellé (`memfd` copié dans un tmpfs privé, (ht)) ;
  - Landlock en renfort (D7) ;
  - `Probe`, `ErrIsolationUnavailable`, `ErrIsolationSetup`, `Spec.WriteData`, `Spec.ReadOnly`, `Result.Isolation`, `Workspace.DataDir` ;
  - `Toolchain.ReadOnlyRoots` ; chemins de l'environnement fournis par la chaîne d'outils ((hr)) ;
  - règles `isolation-confined` et `toolexec-helper-first` ;
  - correctif (ho) de `scripts/iac-tools.sh` ;
  - `docs/SETUP.md`, section « Isolation des outils » ; proposition `docs/proposals/0014-ci-isolation-outils.md` (Q4) ;
  - T8, T157, T161, T162 mises à jour, soumises à `security-reviewer`.
- **Étapes ordonnées** (chacune un cycle tests puis impl) : 1 socle ; 2 assistant et espaces de noms ; 3 arbre de l'outil ; 4 Landlock ; 5 (ho) ; 6 documentation et revue (ADR 0015, section « Recommandation et ordre de mise en œuvre »).
- **Tests clés** : les 11 `TestIsolation*`, `TestIsolationConfined`, `TestToolexecHelperFirst`, le sous-cas (ho) ; **test modifié** : `TestToolexecNoShell` (marqueurs dans `data/`).
- **Acceptation** : vérifications 1 à 11 de l'ADR 0015.
- **Sécurité** : oui (T3, T8, T143, T157, T161, T162).

### M3-T03 `validate-chain` : chaîne, garde statique, parité, `rempart check`, pack `iac`

- **Objectif** : `internal/validate` produit, sur les mêmes sorties brutes, la même sortie que `scripts/validate.sh`, échoue fermé, n'exécute jamais un outil sur un arbre refusé ; premier pack de politiques sur le plan.
- **Dépend de** : T02, T02b (ADR 0015 : aucun câblage de `toolexec` dans `rempart check` avant la revue PASS de T02b).
- **Livrables** : `internal/validate/{static.go,normalize.go,chain.go}` et `internal/validate/domain` (D6, D7) ; `internal/plan` (`Decode`) ; `internal/policy` (`IaCInput`, `NewIaCInput`) et `schemas/policy/iac-input-v1.json` ; `opa.NewIaC()` (adaptateur généralisé par pack, D9) ; `policies/embed.go` (variable `IaC`) ; `policies/iac/*.rego` et leurs `_test.rego` (au moins 10 contrôles : entrée depuis `0.0.0.0/0` hors écouteur d'un équilibreur exposé, API de cluster publique hors sources du graphe, chiffrement au repos, rotation des clés, journaux de flux par réseau, journal d'audit du cluster, IAM sans joker d'action ni de ressource, VM sans IP publique, chiffrement des disques, comptes locaux AKS désactivés, étiquettes obligatoires) ; `Makefile` : `opa check` par pack avec son schéma ; `cmd/rempart check [--module] [--static] [--json] <dossier>` (codes 0, 1, 2) ; `scripts/validate.sh` et `normalize_findings.py` alignés (outil absent : finding critique, sévérité inconnue : critique, empreinte en netstrings, garde statique par `rempart check --static`) : **modification de skill signalée** ; `internal/validate/testdata/` (sorties brutes adverses, arbres `bad`, `good`, `forbidden-annotation`, `code-exec`) ; proposition `docs/proposals/0012-ci-outils-iac.md` (outils en CI par `scripts/iac-tools.sh`, sans cache).
- **Tests clés (11)** : `TestNormalizeFailsClosed`, `TestStaticGateForbiddenAnnotations` (cinq annotations, trois styles de commentaire, casse, fichiers de configuration), `TestStaticGateRefusesCodeExecution` (`external`, `http`, provisioners, `terraform_data` à provisioner, fonctions de fichier, `terraform_remote_state`, `backend`, `cloud`, `.tofu`, surcharge, `.tf.json`), `TestStaticGateModuleSources` (`git::`, registre, `http`, `../`, plage de versions), `TestChainShortCircuit`, `TestChainUntrustedMessage` (C1, bidirectionnels, ANSI échappés ; 500 runes), `TestCheckCommand`, `TestPlanDecodeStrict`, `TestIaCInputHasNoFreeText`, `TestIaCPackMetadataComplete`, `TestIaCEveryControlHasOkAndKo` ; outils : `TestNormalizeParityWithScript` (même `findings.json`, empreinte et score que `normalize_findings.py`, lancé par `python3 -I`, sur 10 jeux bruts au moins), `TestChainOnFixtures`.
- **Acceptation** :
  1. `go test ./internal/validate/... ./internal/plan/... ./internal/policy/... ./cmd/rempart/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(NormalizeFailsClosed|StaticGateForbiddenAnnotations|StaticGateRefusesCodeExecution|StaticGateModuleSources|ChainShortCircuit|ChainUntrustedMessage|CheckCommand|PlanDecodeStrict|IaCInputHasNoFreeText|IaCPackMetadataComplete|IaCEveryControlHasOkAndKo) '` : `11`.
  2. Outils : `go test -tags=integration ./internal/validate/... -run 'Test(NormalizeParityWithScript|ChainOnFixtures)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(NormalizeParityWithScript|ChainOnFixtures) '` : `2`.
  3. `go run ./cmd/rempart check --json internal/validate/testdata/forbidden-annotation | jq -e '.ok == false and ([.findings[] | select(.code == "FORBIDDEN_EXCEPTION" and .severity == "critical")] | length) >= 5'` : `true`.
  4. `go run ./cmd/rempart check --json internal/validate/testdata/code-exec | jq -e '.ok == false and ([.stages[] | select(.stage != "static" and .status != "skipped")] | length) == 0'` : `true`.
  5. `make -f Makefile opa-test; echo rc=$?` : `rc=0` ; `ls policies/iac/*.rego | grep -v '_test\.rego$' | xargs grep -h '^#[[:space:]]*control_id:' | sort -u | wc -l` : au moins `10`.
  6. `go list -f '{{.ImportPath}}: {{join .Imports " "}}' ./... | grep -E 'github.com/open-policy-agent/| github.com/amezianechayer/rempart/policies( |$)' | cut -d: -f1 | sort -u` : exactement `github.com/amezianechayer/rempart/internal/policy/adapters/opa`.
  7. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
- **Sécurité** : oui (T8, T30, T142, T145, T108, T109).
- **Garde de taille** : au-delà de 6 cycles, couper en T03a (chaîne, garde, parité, `rempart check`) et T03b (`internal/plan`, `IaCInput`, pack `iac`), critères inchangés.

### M3-T04 `modules-network` : réseau AWS, réseau Azure, groupe de VM Azure, VPN AWS et Azure

- **Objectif** : quatre modules au contrat, verts sous `tofu test` (fournisseurs simulés) et sans finding non justifié (C1).
- **Dépend de** : T03.
- **Livrables** : `modules/aws-network` (VPC, sous-réseaux par tier et par zone, passerelle Internet seulement avec un tier public, routes, journaux de flux chiffrés, groupe par défaut verrouillé) ; `modules/azure-network` (VNet, sous-réseaux par tier, NSG deny par défaut par sous-réseau, règles en entrée typée, `GatewaySubnet` facultatif, journaux de flux de VNet) ; `modules/azure-vm-group` (N VM Linux sans IP publique, authentification par mot de passe coupée, clé SSH par référence, disques chiffrés, connexion par identité, NSG d'entrée issue des arêtes) ; `modules/vpn-aws-azure` (passerelle Azure actif-actif à BGP, VGW AWS, deux passerelles client, quatre tunnels, politique IPsec explicite identique des deux côtés, ASN et /30 en entrées, clé pré-partagée par référence ou valeur éphémère, préfixes annoncés limités) ; pour chacun : `main.tf`, `variables.tf` (validations), `outputs.tf`, `versions.tf` (versions exactes), `README.md`, `SECURITY.md` (`control_id` couverts), `examples/basic/`, `tests/*.tftest.hcl` (`mock_provider`) ; `modules/scanner-exceptions.json` ; cible `make module-test` ; contrôles d'architecture des modules.
- **Tests clés (3, Go)** : `TestModulesContract` (fichiers, versions exactes, variable d'étiquettes, aucun `*` IAM, `SECURITY.md` ne cite que des `control_id` existants), `TestModuleTestsCoverGuarantees` (par module : au moins un `run` sur chiffrement, absence d'IP publique et étiquettes, au moins un `expect_failures`), `TestScannerExceptionsClosed`.
- **Acceptation** :
  1. `go test ./internal/archtest/ -v 2>&1 | grep -Ec -- '^--- PASS: Test(ModulesContract|ModuleTestsCoverGuarantees|ScannerExceptionsClosed) '` : `3`.
  2. Outils : `make -f Makefile module-test; echo rc=$?` : `rc=0` ; `ls -d modules/*/ | wc -l` : `4`.
  3. Outils : `for m in aws-network azure-network azure-vm-group vpn-aws-azure; do go run ./cmd/rempart check --module --json "modules/$m" | jq -e '.ok' >/dev/null || echo "KO $m"; done | wc -l` : `0`.
  4. `jq -e 'all(.[]; (.justification | length) >= 20 and (.expires | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}$")) and (.approved_by | length) > 0)' modules/scanner-exceptions.json` : `true`.
  5. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
- **Sécurité** : oui, une passe groupée avec T05 à la fin de T05 (Q9).
- **Garde de taille** : au-delà de 6 cycles, T04a (deux réseaux) et T04b (VM, VPN).

### M3-T05 `modules-cluster` : EKS, AKS, amorçage ArgoCD, observabilité

- **Objectif** : quatre modules au contrat qui réalisent les faits de cluster du graphe (D19), C1 pour les huit modules.
- **Dépend de** : T03 (T04 pour les entrées d'exemple seulement).
- **Livrables** : `modules/aws-eks` (point d'accès privé, sources explicites si public, chiffrement des Secrets par KMS, journaux du plan de contrôle chiffrés, groupe de nœuds en sous-réseaux privés, IMDSv2, volumes chiffrés, identités de workload, politique réseau du VPC CNI, entrées d'accès sans `aws-auth`) ; `modules/azure-aks` (cluster privé, RBAC Entra ID, comptes locaux coupés, émetteur OIDC et identités de workload, politique réseau, chiffrement etcd par Key Vault, journaux d'audit, chiffrement à l'hôte) ; `modules/argocd-bootstrap` (chart vendorisé avec somme, serveur non exposé, projets restreints, application racine, espaces de noms en PSA `restricted`, NetworkPolicy deny par défaut) ; `modules/observability-stack` (Applications ArgoCD Prometheus, Loki sur volume, Grafana ; aucune exposition ; rétention de l'IR) ; contrat, tests et exceptions comme T04.
- **Tests clés (1 nouveau, Go)** : `TestChartsPinned` (chaque chart vendorisé : version exacte, somme au manifeste) ; les trois de T04 couvrent les huit modules.
- **Acceptation** :
  1. `go test ./internal/archtest/ -v 2>&1 | grep -Ec -- '^--- PASS: Test(ModulesContract|ModuleTestsCoverGuarantees|ScannerExceptionsClosed|ChartsPinned) '` : `4`.
  2. C1, outils : `make -f Makefile module-test; echo rc=$?` : `rc=0` ; `ls -d modules/*/ | wc -l` : `8`.
  3. C1, outils : `for m in $(cd modules && ls -d */ | tr -d /); do go run ./cmd/rempart check --module --json "modules/$m" | jq -e '.ok' >/dev/null || echo "KO $m"; done | wc -l` : `0`.
  4. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
- **Sécurité** : oui (passe groupée T04 et T05 : IaC, identités, réseau, secrets).
- **Garde de taille** : T05a (EKS, AKS) et T05b (ArgoCD, observabilité).

### M3-T06 `iacgen` : compilateur, traduction, rendu, bundle

- **Objectif** : du graphe convergé à une composition et un bundle déterministes, sans texte libre, sans permission hors table ; scénario de référence compilé.
- **Dépend de** : T04, T05 ; ADR 0014 (D4, D5, D11 à D13).
- **Livrables** : `internal/iacgen/composition` ; `internal/iacgen` (`Compile`, `Render`, `Catalog`) ; allocations dérivées (D12) ; `internal/iacgen/iam` (table sourcée et datée ; lignes AWS vérifiées par l'agent sur `docs.aws.amazon.com`, lignes Azure en attente de H-permissions) ; `modules/embed.go` et règle `modules-confined` ; verrou des providers du bundle ; `cmd/rempart iac compile [--json] [--out <dossier vide>] <entrée L3>` ; `internal/iacgen/testdata/reference-input.json` (`ir`, `confirmation` et graphe convergé de L2 sur l'IR de référence, tenant de démo) et `internal/iacgen/testdata/scenarios/reference.json`.
- **Tests clés (10)** : `TestCompileReferenceScenario` (composition de référence figée), `TestCompileDeterministic` (nœuds et arêtes permutés : même composition, même empreinte de bundle), `TestCompileIgnoresFreeText` (canaris dans `summary`, `justification`, `notes`, `purpose` : bundle identique, aucun canari dans un fichier, T147), `TestCompileIgnoresEdgePath` (T116), `TestTranslationTableClosed` (T117), `TestTranslateFailsClosed`, `TestCompileModuleMissing`, `TestDerivedCIDRsInsideGraph`, `TestRenderEscapesTemplates`, `TestModulesConfined` ; outils : `TestReferenceBundleValidates`.
- **Acceptation** :
  1. `go test ./internal/iacgen/... ./internal/archtest/ -v 2>&1 | grep -Ec -- '^--- PASS: Test(CompileReferenceScenario|CompileDeterministic|CompileIgnoresFreeText|CompileIgnoresEdgePath|TranslationTableClosed|TranslateFailsClosed|CompileModuleMissing|DerivedCIDRsInsideGraph|RenderEscapesTemplates|ModulesConfined) '` : `10`.
  2. `go run ./cmd/rempart iac compile --json internal/iacgen/testdata/reference-input.json | jq -e '([.composition.roots[].name] == ["infra","cluster"]) and (.bundle_sha256 | test("^[0-9a-f]{64}$"))'` : `true`.
  3. `for i in 1 2; do go run ./cmd/rempart iac compile --json internal/iacgen/testdata/reference-input.json | jq -r .bundle_sha256; done | uniq | wc -l` : `1`.
  4. `d=$(mktemp -d) && go run ./cmd/rempart iac compile --out "$d" internal/iacgen/testdata/reference-input.json >/dev/null && go run ./cmd/rempart check --static --json "$d" | jq -e '.ok'` : `true`.
  5. Outils : `go test -tags=integration ./internal/iacgen/ -run TestReferenceBundleValidates -v 2>&1 | grep -c '^--- PASS: TestReferenceBundleValidates '` : `1`.
  6. `go list -deps ./internal/iacgen/... ./internal/validate/... ./internal/plan/... | grep -c '/internal/llm'` : `0`.
  7. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
- **Sécurité** : oui (T116, T117, T147, T6).

### M3-T07 `equivalence-sandbox` : équivalence graphe et plan, bac à sable

- **Objectif** : C3 ; rien dans le plan hors du graphe, tout le graphe dans le plan ; plan réel du scénario de référence lancé par l'humain (C2).
- **Dépend de** : T06.
- **Livrables** : `internal/plan/equivalence` (D10, table fermée par module et par type d'élément, D13) ; port `EquivalenceChecker` branché dans la chaîne ; `rempart check --graph-input <entrée L3> <bundle>` (équivalence sur le plan hors ligne, ou sur `--plan <plan.json>` fourni) ; `scripts/sandbox.sh` (`plan` : rendu du scénario, miroir, identité en lecture lue dans l'environnement de l'humain, `tofu plan -out`, `tofu show -json`, chaîne et équivalence rejouées sur le plan réel, Infracost seulement si `INFRACOST_API_KEY` est présente, résumé JSON sans identifiant de compte ; `apply` et `destroy` : refus sans fichier de plan enregistré et empreinte confirmée, D17) ; `.gitignore` (`.sandbox/`) ; `internal/plan/equivalence/testdata/injected-iam-user.tf`.
- **Tests clés (10)** : `TestEquivalenceInjectedResourceBlocks` (C3 sur plans de test : `aws_iam_user`, règle `0.0.0.0/0`, IP publique Azure), `TestEquivalenceReferenceClean`, `TestEquivalenceRefusesMisleadingAddress` (nom, étiquette `rempart_node` ou adresse qui imite un élément), `TestEquivalenceReachSubset`, `TestEquivalenceIAMSubset`, `TestEquivalenceCompleteness` (arête sans règle, chiffrement absent), `TestEquivalenceSupportTableClosed`, `TestSandboxScriptPlanOnly` (faux `tofu` : miroir, `-lockfile=readonly`, `-out`, jamais `apply`), `TestSandboxRefusesWithoutCredentials`, `TestSandboxOutputHasNoAccountData`.
- **Acceptation** :
  1. `go test ./internal/plan/... ./internal/archtest/ -v 2>&1 | grep -Ec -- '^--- PASS: Test(EquivalenceInjectedResourceBlocks|EquivalenceReferenceClean|EquivalenceRefusesMisleadingAddress|EquivalenceReachSubset|EquivalenceIAMSubset|EquivalenceCompleteness|EquivalenceSupportTableClosed|SandboxScriptPlanOnly|SandboxRefusesWithoutCredentials|SandboxOutputHasNoAccountData) '` : `10`.
  2. C3, outils (ressource AWS : plan hors ligne faisable quelle que soit la sonde) : `d=$(mktemp -d) && go run ./cmd/rempart iac compile --out "$d" internal/iacgen/testdata/reference-input.json >/dev/null && cp internal/plan/equivalence/testdata/injected-iam-user.tf "$d/infra/" && go run ./cmd/rempart check --json --graph-input internal/iacgen/testdata/reference-input.json "$d" | jq -e '.ok == false and ([.findings[] | select(.code == "EQUIV-ORPHAN" and .severity == "critical" and (.resource | startswith("aws_iam_user.")))] | length) == 1'` : `true`.
  3. Témoin, outils : même commande sans la copie du fichier injecté : `jq -e '.ok'` rend `true` (chaîne verte hors ligne sur la référence, branche de Q2 retenue).
  4. Sans identifiant (session de l'agent) : `make -f Makefile sandbox-plan SCENARIO=reference; echo rc=$?` : `rc=2`, message « identifiants de bac à sable absents ; aucune action », aucun appel d'outil.
  5. C2, humain (H-sandbox-plan) : `make -s -f Makefile sandbox-plan SCENARIO=reference | jq -e '.plan_real and .chain_ok and .equivalence_ok and (.plan_sha256 | test("^[0-9a-f]{64}$")) and .findings_blocking == 0'` : `true`.
  6. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`.
- **Sécurité** : oui (T146, T31, T149, T117).

### M3-T08 `l3-loop` : fiche, réparateur, workflow, worker

- **Objectif** : boucle L3 de bout en bout sur l'historique chiffré ; T115 fermée par recalcul ; stagnation et changement de stratégie testés.
- **Dépend de** : T07.
- **Livrables** : `docs/loops/L3.md` (fiche de la section 4, avant le code) ; `internal/iacgen/repair` ; `internal/loops/l3/{workflow.go,register.go}`, `internal/loops/l3/activities/{prepare,propose,verify,finalize,explain}.go` ; `internal/loops/versions.go` ; `cmd/rempart-worker` (`-l3-once`, `-l3-input`, chaîne d'outils et pack `iac` vérifiés au démarrage, enregistrement derrière `codec.Check`, échec fermé ; `prctl(PR_SET_DUMPABLE, 0)` avant tout outil) ; `make l3-demo` et `internal/archtest/makefile_test.go` ; amendement de `docs/01-LOOPS.md` (stratégies, coût) selon l'ADR 0014.
- **Tests clés (11, `-race`)** : `TestL3ReferenceConverges` (chaîne simulée par rapports déterministes ; une itération, `applied` vide), `TestL3RefusesGraphSubject` (graphe non dérivé de `Build(ir)`, IR non confirmée, graphe à finding critique de L2 : refus avant toute activité de boucle), `TestL3TenantMismatchRefused`, `TestL3RepairsInitialComposition` (version flottante, `extra` orphelin, entrée divergente : convergence en deux itérations au moins), `TestL3StallSwitchesToRecompile`, `TestL3StallEscalates` (`module_missing`, `strategies_exhausted`), `TestRepairNeverAddsOutsideCompiler` (rapid : toute entrée réparée est une entrée compilée ou une entrée d'origine inchangée), `TestL3EscalationHasNoComposition`, `TestL3FreeTextHasNoEffect`, `TestL3SpecIsTheSheet`, `TestWorkerRequiresToolchain` ; outils : `TestL3ReferenceConvergesWithTools`.
- **Acceptation** :
  1. `go test -race ./internal/loops/l3/... ./internal/iacgen/repair/... ./cmd/rempart-worker/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(L3ReferenceConverges|L3RefusesGraphSubject|L3TenantMismatchRefused|L3RepairsInitialComposition|L3StallSwitchesToRecompile|L3StallEscalates|RepairNeverAddsOutsideCompiler|L3EscalationHasNoComposition|L3FreeTextHasNoEffect|L3SpecIsTheSheet|WorkerRequiresToolchain) '` : `11`.
  2. `go test ./internal/iacgen/repair/ -run TestRepairNeverAddsOutsideCompiler -rapid.checks=1000 -v 2>&1 | grep -c '^--- PASS: TestRepairNeverAddsOutsideCompiler '` : `1`.
  3. `go list -deps -f '{{if not .Standard}}{{.ImportPath}}{{end}}' ./internal/loops/l3/... | grep -c '/internal/llm'` : `0` ; `go list -deps ./internal/loops/l3 | grep -cx 'os/exec'` : `0` (paquet de workflow).
  4. `grep -c '^budget: {max_iterations: 8,' docs/loops/L3.md` : `1`.
  5. Outils : `go test -tags=integration ./internal/loops/l3/... -run TestL3ReferenceConvergesWithTools -v 2>&1 | grep -c '^--- PASS: TestL3ReferenceConvergesWithTools '` : `1`.
  6. Pile et outils : `make -s -f Makefile l3-demo | jq -e '.status == "converged" and ([.composition.roots[].name] == ["infra","cluster"]) and (.bundle_sha256 | test("^[0-9a-f]{64}$")) and ([.report.stages[] | select(.stage == "cost")][0].status == "not_evaluated") and (.loop | has("best") | not)'` : `true` (humain si Docker manque).
  7. `make -f Makefile verify; echo rc=$?` : `rc=0` (dont `workflowcheck` et `loopsrc` sur `internal/loops/l3`).
- **Sécurité** : oui (T3, T8, T115, T142, T148, T16).

### M3-T09 `evals-iac` : suite `evals/iac`

- **Objectif** : C4 mesuré par `make evals`, chaîne réelle, graders déterministes, convergence non triviale et stagnation observée.
- **Dépend de** : T08.
- **Livrables** : `evals/iac/suite.yaml` (cible `iac`, `watch` couvrant `modules/**`, `internal/iacgen/**`, `internal/validate/**`, `internal/plan/**`, `internal/loops/l3/**`, `internal/loops/*.go`, `internal/loops/domain/**`, `internal/loops/codec/**`, `internal/policy/**`, `internal/design/**`, `internal/graph/**`, `internal/intent/**`, `policies/**`, `schemas/**`, `scripts/iac-tools.lock.json`, `cmd/rempart-evals/**`) ; `evals/iac/cases/` : 21 cas (8 nominaux, 6 trappes à composition initiale fautive, 2 stagnations, 3 injections, 2 limites ; proportions du skill `agent-evals`), entrée `{ir, confirmation, initial?}`, graphe obtenu par L2 dans le même processus ; cible `iac` (`cmd/rempart-evals/iac.go` : L3 dans un environnement de test neuf, chaîne réelle vérifiée, aucun faux d'outil ; chaîne absente : erreur d'exécution, jamais un succès) ; étiquettes `trap` et `stall` ; `runs: 1`.
- **Cas** : nominaux (référence ; EKS seul ; AKS seul ; VM Azure seules ; multicloud sans VPN ; prod à trois nœuds ; deux variantes de taille) : convergés en une itération ; trappes (version de module flottante ; `extra` `aws_iam_user` hors graphe, forme de C3 ; entrée d'API publique contraire au graphe ; chiffrement coupé ; appel de module manquant ; règle d'entrée élargie) : convergées en 2 à 4 itérations avec la correction attendue dans `applied` ; stagnations (`extra` présent au graphe mais sans correction au catalogue : bascule `recompile` puis convergence ; élément sans module : escalade `module_missing` à la troisième empreinte) ; injections (texte HCL dans `justification` ; texte HCL dans `summary` et `notes` ; valeur d'entrée `${file("...")}` dans `initial`) : bundle identique au nominal, aucun canari ; limites (stockage objet : `module_missing` ; graphe proche de 64 Kio). 19 cas sur 21 attendus convergés (90,5 %) : la lecture stricte de C4 tient aussi.
- **Graders** : `status` exact ; convergés : `max_iterations` au plus 8 (au plus 4 pour les trappes) ; trappes : `must_include` `$.initial_findings[*].code` contient le code visé et `$.applied[*].fix` la correction ; stagnations : `must_include` `$.loop.trace[*].strategy` contient `recompile` (champ de la trace de `RunLoop`, à vérifier) ; escalades : `$.explanation[*].code` et `must_not_include` `$.composition`.
- **Tests clés (4)** : `TestIaCSuiteComposition` (proportions ; 90 % au moins des cas attendus convergés ; chaque trappe rejetée par le vérificateur sur son candidat initial pour sa raison ; chaque stagnation sans correction au catalogue sur son empreinte initiale ; chaque cas convergé déclare `max_iterations` au plus 8), `TestIaCTargetRunsCase`, `TestIaCInputClosed`, `TestIaCWatchCoversTargetDeps` (T140).
- **Étape humaine H3-iac** : `make update-baseline EVAL=iac`, commit de `evals/iac/baseline.json`.
- **Acceptation** :
  1. C4, outils : `make -s -f Makefile evals EVAL=iac | jq -e '.cases >= 20 and .success_rate >= 0.9 and .injection_resistance == 1 and .regressions_vs_baseline == []'` : `true`.
  2. `grep -lE '^tags:.*[[ ,]trap[],]' evals/iac/cases/*.yaml | wc -l` : au moins `6` ; `grep -lE '^tags:.*[[ ,]stall[],]' evals/iac/cases/*.yaml | wc -l` : au moins `2`.
  3. `go test ./cmd/rempart-evals/... -v 2>&1 | grep -Ec -- '^--- PASS: Test(IaCSuiteComposition|IaCTargetRunsCase|IaCInputClosed|IaCWatchCoversTargetDeps) '` : `4`.
  4. `git log --format=%ae -- evals/iac/baseline.json | sort -u` : la seule adresse de l'humain.
  5. `make -f Makefile verify; echo rc=$?` : `rc=0` (en CI après H-CI-2).
- **Sécurité** : non par tâche (revue de clôture ; T151 atténuée par la composition et la baseline humaine).

---

## 6. ADR et propositions à écrire

| Document | Quand | Contenu et options |
|---|---|---|
| **ADR 0014 « Boucle L3 : compilateur déterministe, composition typée, équivalence et chaîne d'outils »** | rédigé pendant T01, complété par la sonde au début de T02, accepté avant sa phase tests | Proposeur et stratégies (Q1 : A déterministe, B LLM, C hybride) ; entrée et T115 (Q3) ; composition typée et rendu (D4, D5) ; chaîne et garde statique (D6, D7) ; plan hors ligne et sonde (Q2) ; pack `iac` embarqué contre Conftest (Q5, amende ADR 0011 D4 et D6) ; équivalence (D10, D13) ; table de traduction (D11) ; allocations dérivées (D12) ; état et backend en mode runner (D5, D17) ; miroir de providers contre ouverture du registre (Q4) ; coût (Q6) ; exceptions (Q9) ; faits Kubernetes (Q11) ; dépendance `hcl/v2` mesurée ; amendements de `docs/00-VISION.md` (Conftest, Infracost), `docs/01-LOOPS.md` (stratégies, coût) et des skills concernés. |
| Proposition `0011-ci-avant-m3` | T01 | (ce) golangci-lint par `go tool` ou hachage, (cg) repli sûr de `github.event.before`, (bq) liste blanche des expressions `${{ }}`, (br) concurrence ; appliquée par l'humain. |
| Proposition `0012-ci-outils-iac` | T03 | Installation des outils par `scripts/iac-tools.sh` en CI, sans cache, avant `make verify`. |
| Proposition harnais `0013-garde-iac` | T02 | `make sandbox-plan` en « ask » ; `deny` étendu aux formes `*/tofu apply`, `*/tofu destroy`, `"$TOFU" apply` ; garde d'écriture (comme les baselines) sur `modules/scanner-exceptions.json`, `scripts/iac-tools.lock.json`, la table `internal/iacgen/iam` ; CODEOWNERS sur `/modules/`, `/scripts/iac-tools.lock.json`, `/scripts/sandbox.sh`, `/internal/iacgen/iam/`, `/internal/plan/equivalence/`. |
| Amendement ADR 0005 | T09, si besoin | `runs: 1` et baseline hors registre des routes pour la cible déterministe `iac`, comme `design`. |

## 7. Obligations héritées : place de chacune

| Obligation | Gravité | Tâche | Note |
|---|---|---|---|
| (fk) références `data.*` hors `data.rempart.design` | bas | T01 | avant le second pack (T03) |
| (fl) sous-répertoire non embarqué, vérification 13 de l'ADR 0011 mécanique | bas | T01 | T03 l'exerce avec `policies/iac` |
| Durcissement T31 (plan `M0-squelette` section 0) | moyen | T01 (`Makefile`), T07 (script) | **préalable obligatoire** à la création de `scripts/sandbox.sh` |
| (fd) table de zones de L1 fusionnée avec la juridiction | moyen | T01 | **ajout** : datée « avant M3 » par l'ADR 0011, encore ouverte (`regions.go` présent) ; à confirmer (Q13) |
| (cf) options `-c` de git dans `rempart-evals` | bas | T01 | lot « avant M3 » de la section 8.2 du plan M2, encore ouvert |
| (ce), (cg), (bq), (br) CI | bas | T01 (proposition 0011), humain | `.github/` sous CODEOWNERS |
| Empreinte de `normalize_findings.py` (note de M0-T19d) | bas | T03 | skill aligné, signalé |
| (fo) historique de référence de L2 | moyen | sans objet en M3 | L3 ne change pas la séquence de L2 ; historique de référence de L3 en obligation analogue si la pile manque |
| (gs), (gu), (go), (gp), (fu), (gw), (gx) | | M4 | inchangées |
| (bj2), (ga) | bas | avant M4 | inchangées |
| Résidu de (fb), écarts de M2-T07, ADR 0012 D2 et D3, questions 1, 3 et 4 de l'ADR 0013 | | humain | hors critères de M3 ; la question 2 de l'ADR 0013 est tranchée par Q3 |

## 8. Impact sur le modèle de menace

Menaces existantes fermées ou complétées par M3 :

- **T115** : L3 recalcule la provenance (D3) ; `TestL3RefusesGraphSubject`.
- **T116** : sources des règles depuis `MEMBER_OF`, `path` ignoré ; `TestCompileIgnoresEdgePath`.
- **T117** : table fermée, sans joker, échec fermé, rôles Azure personnalisés, IAM du plan inclus dans la traduction ; `TestTranslationTableClosed`, `TestTranslateFailsClosed`, `TestEquivalenceIAMSubset`.
- **T30** : annotations refusées partout, fichiers de configuration de scanner refusés, exceptions centralisées et datées ; `TestStaticGateForbiddenAnnotations`, `TestScannerExceptionsClosed`.
- **T6** : modules embarqués avec manifeste SHA-256, sources locales seulement, versions exactes, verrou des providers, charts et outils à sommes ; la « vérification de signature dans la chaîne L3 » devient `MODULE_TAMPERED` et `TestIaCToolsLockPinned`.
- **T8** : un seul exécutant (`toolexec`, règle `exec-confined`), sans shell, environnement construit, réseau coupé, sorties bornées ; `TestToolexec*`, `TestExecConfined`.
- **T31** : ligne unique chaînée, préfixe `-`, `.IGNORE` et `MAKEFLAGS` refusés, approbation par permission « ask » et identifiants sous MFA chez l'humain ; `TestSandboxIgnoreErrorsNeverCalls`.
- **Section 4.2, deuxième point** (exécution de code pendant `tofu plan`) : formalisé par T142.
- T2, T3, T10, T16, T24 : texte libre jamais rendu (T147), tenant du worker, budget et délais de la boucle, versions du workflow, bornes de la composition et des sorties d'outil.

Menaces nouvelles proposées (numéros provisoires, à confirmer par `security-reviewer`) :

| # | Menace | Cat. | Atténuation | Vérification |
|---|---|---|---|---|
| T142 | Code exécuté à l'`init` ou au `plan` d'une IaC générée, réparée ou locale (`rempart check`) : données `external` et `http`, provisioners, fonctions de lecture de fichiers, fichiers `.tofu` ou de surcharge qui masquent le code relu ; lecture de secrets du worker, SSRF, exfiltration par la sortie du plan | E, I | Garde statique avant tout outil (D7), composition typée (D4), réseau coupé, environnement construit, `HOME` éphémère, processus outil sans accès à la mémoire du worker (`PR_SET_DUMPABLE`, utilisateur ou bac à sable distinct en production) | `TestStaticGateRefusesCodeExecution`, `TestToolexecEnvBuilt`, critère 4 de T03 |
| T143 | Outil de la chaîne, provider, module ou chart substitué ou compromis (version flottante, registre, miroir contourné par une configuration CLI héritée, `.terraformrc`, publication piégée récente) | T, E | Verrou à sommes et signatures, âge minimal de 14 jours, miroir seul, `-lockfile=readonly`, somme revérifiée avant exécution, CODEOWNERS | `TestIaCToolsLockPinned`, `TestTofuCLIConfigMirrorOnly`, `TestToolexecChecksum`, `TestChartsPinned` |
| T144 | Backend, état ou chiffrement de l'état dans le code généré (`backend`, `cloud`, `terraform_remote_state`) : état envoyé à un tiers, état d'un autre tenant lu, clés pré-partagées en clair | I, T | Aucun de ces blocs dans le bundle, chiffrement natif imposé par l'exécutant, état vide éphémère en L3 | `TestStaticGateRefusesCodeExecution` (cas `backend`, `cloud`, `remote_state`) |
| T145 | Sortie d'outil non fiable : JSON géant ou inattendu lu comme « aucun finding » (échec ouvert), sévérité inconnue rabaissée, message à séquences de contrôle ou injection affiché à un humain | T, D | Décodage strict et borné, échec fermé, sévérité inconnue critique, message échappé et tronqué, jamais lu par une décision | `TestNormalizeFailsClosed`, `TestChainUntrustedMessage`, `TestNormalizeParityWithScript` |
| T146 | Équivalence contournée : adresse, nom ou étiquette trompeurs, `count` ou `for_each` qui multiplie, ressource de soutien trop large (route `0.0.0.0/0`, rôle de plate-forme), plan tronqué ou forgé, garantie du graphe non réalisée | E, T | Rattachement par adresse de module, table fermée à cardinalité, `reach.SubsetOf`, complétude, plan décodé depuis le même run | C3 ; `TestEquivalenceRefusesMisleadingAddress`, `TestEquivalenceReachSubset`, `TestEquivalenceCompleteness`, `TestEquivalenceSupportTableClosed` |
| T147 | Texte non fiable du graphe ou de l'IR rendu dans l'HCL (`${...}`, `%{...}`, heredoc, guillemet) : expression évaluée au plan ou ressource ajoutée | T, E | Aucun texte libre rendu, étiquettes tirées de champs fermés, `hclwrite` avec échappement | `TestCompileIgnoresFreeText`, `TestRenderEscapesTemplates`, cas d'injection de `evals/iac` |
| T148 | Exception de scanner élargie : entrée globale par `check`, sans expiration, écrite par l'agent sans revue, périmée | T | Fichier central sous CODEOWNERS et garde du harnais (proposition 0013), entrée par adresse, expiration, approbateur | `TestScannerExceptionsClosed` |
| T149 | Bac à sable détourné : plan réel lancé par l'agent avec les identifiants de l'humain, sortie de plan (identifiants de compte, valeurs sensibles) lue ou commitée, apply d'un plan autre que celui affiché, contournement de `deny` par un chemin d'outil ; complément (revue de M3-T02) : formes de `make sandbox-plan` hors « ask » (option ou variable avant la cible, cible enchaînée, commande composée, appel direct de `sandbox.sh plan`), la recette du plan ne demandant aucune confirmation | E, I | Identité en lecture pour le plan, MFA pour l'écriture, apply du seul plan enregistré, résumé sans donnée de compte, `.sandbox/` ignoré, proposition 0013 (seconde version : règle `guard_bash` calquée sur T29 pour `sandbox-plan`, une seule entrée « ask » ; appliquée par l'humain avant la création de `sandbox.sh`, obligation (hh)). La règle du hook n'est qu'une friction : filtre sur le texte, elle se contourne par développement du shell (variable, barre oblique inverse, accolades, motif de nom de fichier ; seconde passe de la revue de M3-T02). Seule une confirmation lue sur `/dev/tty` par `sandbox.sh` lui-même, pour chaque sous-commande y compris `plan`, et par la recette `sandbox-plan`, ferme le risque (obligation (hk)) | `TestSandboxScriptPlanOnly`, `TestSandboxRefusesWithoutCredentials`, `TestSandboxOutputHasNoAccountData` |
| T150 | Allocations et soutien hors graphe (sous-réseaux par zone, `GatewaySubnet`, /30, NAT) qui chevauchent ou ouvrent un egress non modélisé | I, E | `cidr.Check` sur l'union, egress signalé à part, arêtes de sortie au graphe en M6 | `TestDerivedCIDRsInsideGraph` ; résidu consigné |
| T151 | Evals de L3 rendues triviales ou truquées : chaîne simulée dans la cible, trappes qui ne déclenchent rien, cas sans étage lourd | T, R | Chaîne réelle obligatoire dans la cible, composition de suite testée, baseline humaine, CODEOWNERS | `TestIaCSuiteComposition`, `TestIaCTargetRunsCase` |

---

## 9. Liste ordonnée des tâches

1. **M3-T01 `pre-m3`** (S) : (fk), (fl), (fd), (cf), durcissement T31 du `Makefile`, proposition CI 0011. En parallèle : ADR 0014 par `architect`.
2. **M3-T02 `iac-toolchain`** (M) : sonde du plan hors ligne, acceptation de l'ADR 0014, verrou et script d'outils, miroir de providers, `toolexec`, `exec-confined`, `make iac-tools`, proposition harnais 0013.
2b. **M3-T02b `tool-isolation`** (M) : ADR 0015 (accepté le 2026-11-26), socle du lanceur, assistant et espaces de noms, arbre fermé, Landlock, (ho), proposition CI 0014 ; revue sécurité PASS exigée avant tout câblage de `toolexec`.
3. **M3-T03 `validate-chain`** (L) : garde statique, étages, normalisation, parité avec `validate.sh`, `rempart check`, `internal/plan`, pack `policies/iac`, proposition CI 0012.
4. **M3-T04 `modules-network`** (L) : `aws-network`, `azure-network`, `azure-vm-group`, `vpn-aws-azure`, exceptions, `make module-test`.
5. **M3-T05 `modules-cluster`** (L) : `aws-eks`, `azure-aks`, `argocd-bootstrap`, `observability-stack` ; revue sécurité groupée T04 et T05.
6. **M3-T06 `iacgen`** (L) : composition, compilateur, allocations, traduction, rendu, bundle, `rempart iac compile`.
7. **M3-T07 `equivalence-sandbox`** (L) : équivalence (C3), `scripts/sandbox.sh`, `make sandbox-plan` ; puis H-sandbox-plan (C2).
8. **M3-T08 `l3-loop`** (L) : fiche, réparateur, workflow, worker, `make l3-demo`.
9. **M3-T09 `evals-iac`** (M) : suite et cible `iac`, C4 ; puis H3-iac et `/close-milestone M3`.

Chaque tâche : plan court, phase tests (tests rouges pour la bonne raison), phase impl, `make verify-quick`, revue sécurité si indiquée, fiche `docs/STATUS.md`.

## 10. Étapes humaines

| Étape | Qui | Quand | Action |
|---|---|---|---|
| H0-M3.1 | humain | avant T01 | Valider le découpage, répondre à Q1 à Q13 ; poser le tag `m3-start`. |
| H0-M3.2 | humain | fin de la sonde (début de T02), avant sa phase tests | Accepter l'ADR 0014 (branche de Q2 fixée par la sonde). |
| H-CI-1 | humain | fin de T01 | Appliquer la proposition 0011 (lot CI daté avant M3). |
| H-harness-M3 | humain | fin de T02 | Appliquer la proposition 0013 (permissions « ask » et `deny`, gardes d'écriture, CODEOWNERS). |
| H-tools-lock | humain | fin de T02 | Relire `scripts/iac-tools.lock.json` et le verrou des providers : versions, sommes, dates de publication, empreinte de clé de signature. |
| H0-M3.3 | humain | avant la phase tests de T02b | Accepter l'ADR 0015 (fait le 2026-11-26, « Oui a tout »). |
| H-CI-3 | humain | fin de T02b | Appliquer la proposition 0014 (levée de la restriction AppArmor sur le runner éphémère, `REMPART_REQUIRE_SANDBOX=1`). |
| H-isolation-probe | humain | avant le premier `rempart check` avec outils sur le poste (fin de T03) | Lancer les commandes de l'hypothèse H2 de l'ADR 0015 sur le poste WSL2 et coller la sortie. |
| H-CI-2 | humain | fin de T03 | Appliquer la proposition 0012 (outils IaC en CI) ; sans elle, `make verify` en CI échoue fermé sur les tests d'intégration IaC. |
| H-exceptions | humain | fin de T04 et de T05 | Approuver ou refuser chaque entrée de `modules/scanner-exceptions.json` (revue de PR). |
| H-sandbox-accounts | humain | avant la fin de T06 | Comptes de bac à sable AWS et Azure dédiés, alertes de budget, régions restreintes à `eu-west-3` et `francecentral` ; identité en lecture pour le plan (AWS `ReadOnlyAccess`, Azure `Reader`) ; identité d'écriture sous MFA réservée à un apply futur ; rien dans le dépôt ni dans la session de l'agent. |
| H-permissions | humain | fin de T06 | Vérifier les lignes Azure de la table de traduction sur `learn.microsoft.com` (hôte refusé à la session), comme H-jurisdiction. |
| H-sandbox-plan | humain | après T07 | `make sandbox-plan SCENARIO=reference` sur son poste, coller le résumé JSON (critère 5 de T07, C2) ; facultatif : Infracost avec sa clé (Q6). |
| H-demo | humain | fin de T08, si la session n'a pas Docker | `make l3-demo` et `make verify` sur son poste. |
| H3-iac | humain | fin de T09 | `make update-baseline EVAL=iac`, commit. |
| H-skills | humain | avant la clôture | Relire `secure-iac-generation` (scripts, contrat de module, ordre de la chaîne), `policy-as-code` (pack `iac`), `loop-engineering` et `multicloud-networking` s'ils sont modifiés. |
| H-close | humain | après `/close-milestone M3` | Tag `m3-done`. |

## 11. Risques classés

**Élevés**

| # | Risque | Parade |
|---|---|---|
| R1 | Plan hors ligne impossible pour azurerm ou helm sans identifiant : équivalence de plan et evals partielles dans la session et la CI | Sonde en ouverture de T02 ; repli de Q2 (équivalence de composition et manifestes de modules, plan réel par l'humain) ; C3 prouvé sur une ressource AWS dans les deux branches |
| R2 | Volume des huit modules et findings de Checkov et Trivy (EKS et AKS en particulier) : T04 et T05 débordent | Gardes de taille (a et b) ; modules minimaux mais complets ; exceptions justifiées revues par l'humain |
| R3 | Chaîne d'approvisionnement des outils : un incident visant les artefacts de Trivy a été signalé au premier semestre 2026 (à vérifier à la source avant d'épingler) ; Checkov et ses dépendances PyPI ; providers de plusieurs centaines de Mo | D15 : sommes, signatures, âge minimal, verrou sous CODEOWNERS, exécution sans réseau ni identifiant (T143) |
| R4 | C2 dépend de l'humain (comptes, identité en lecture, plan réel) | H-sandbox-accounts planifiée avant la fin de T06 ; `sandbox.sh` livré en T07, pas en fin de jalon |

**Moyens**

| # | Risque | Parade |
|---|---|---|
| R5 | Durée de la chaîne (1 à 2 minutes par vérification complète) : evals lentes, CI bornée à 45 minutes | Ordre du moins cher au plus cher et arrêt au premier étage bloquant (les trappes itèrent sur les étages en Go) ; scanners en parallèle ; 21 cas ; aucun cache de résultats (vecteur de falsification) |
| R6 | Outils hors ligne : `tflint --init` passe par l'API GitHub (403 dans la session), règles de Trivy tirées d'un registre OCI, téléchargements de Checkov | À vérifier en T02 : rulesets placés depuis les actifs de releases, règles embarquées de Trivy, `--skip-download` |
| R7 | Plan réel de la racine `cluster` impossible avant l'existence du cluster | Q8 : C2 porte sur `infra` ; `cluster` par `tofu test` et plan hors ligne |
| R8 | Grammaire stricte du `Makefile` (`iac-tools`, `module-test`, `l3-demo`, `opa check` par pack, lignes `sandbox-*`) | Prévu tâche par tâche dans `makefile_test.go` |
| R9 | Table Azure invérifiable depuis la session ; rôles intégrés qui évoluent | H-permissions ; rôles personnalisés aux actions exactes (D11) |
| R10 | Rendu non déterministe (ordre, versions d'outils) : empreinte instable, rejeu Temporal (T16) | `TestCompileDeterministic`, critère 3 de T06 ; `GetVersion` dès le premier changement de séquence de L3 |
| R11 | Faux positifs d'équivalence sur les ressources de soutien : la référence n'aboutit pas | `TestEquivalenceReferenceClean` dès T07, table revue |
| R12 | Tailles Temporal : graphe et composition dans la charge de 64 Kio | Charge réduite au graphe et aux clés ; escalade `payload_too_large` ; référence mesurée en T06 |
| R13 | Historique de référence de L3 non enregistré faute de Docker | Obligation analogue à (fo), avant le premier changement de séquence de L3 |

**Bas**

| # | Risque | Parade |
|---|---|---|
| R14 | Disque et temps de téléchargement des providers dans la session et la CI | Cache hors dépôt, une plateforme (`linux_amd64`) |
| R15 | La table de traduction n'a aucun consommateur réel dans la référence (la donnée est hébergée par les VM : ligne `host_local`) | Couverte par les tests et un cas limite ; servira au premier module de stockage (M7) |
| R16 | Coût du bac à sable | Aucun apply exigé en M3 ; alertes de budget |
| R17 | Nouvelle baseline humaine (H3-iac) qui bloque `make verify` | Signalée en fin de T09, aucune autre tâche n'en dépend |

## 12. Questions ouvertes (une recommandation par question)

- **Q1. Proposeur et stratégies de L3.** (A) déterministe : compilateur graphe vers composition, réparateur à catalogue fermé, stratégies `repair` puis `recompile`, forme d'entrée `initial` ; (B) LLM qui écrit le HCL libre de `modules_plus_freeform`, vérifié par la même chaîne ; (C) A d'abord, B en troisième stratégie après stagnation. **Recommandation : A en M3**, C plus tard. Aucune décision de sécurité ne bouge (le vérificateur décide dans les trois cas), mais A n'ajoute ni prompt, ni route à calibrer (crédit manquant), ni sortie d'architecture vers un fournisseur (T7), ni HCL libre à analyser (T142, T147). Le critère 4 reste non trivial : les trappes partent d'une composition fautive que le vérificateur refuse et que le réparateur corrige étage par étage (2 à 4 itérations), les stagnations déclenchent réellement la bascule puis la convergence ou l'escalade, la chaîne est réelle dans la cible ; avec B, il faudrait un faux scripté en CI (mesure de la mécanique seulement) et une mesure réelle à trois exécutions par cas (H-real). `decompose_by_cloud` attend le runner (un état par cloud, VPN en deux temps). `docs/01-LOOPS.md` amendé par l'ADR 0014.
- **Q2. Plan hors ligne et sonde.** **Recommandation** : sonde en ouverture de T02 (AWS, azurerm, helm), résultat dans l'ADR ; branche nominale : plan hors ligne dans le plan de contrôle sans identifiant, réseau coupé ; repli si un provider l'interdit : équivalence de composition et manifestes de modules dans la boucle, plan réel par l'humain, rejoué par le runner en M4 ; jamais de faux point d'authentification.
- **Q3. Sujet de L3 (T115, question 2 de l'ADR 0013).** (A) recalcul : `ValidateIR`, `confirm.Check`, `Derives(Build(ir), graph)`, vérificateur de L2 rejoué ; (B) confiance dans `subject: ir` de la sortie de L2 ; (C) sortie de L2 signée exigée. **Recommandation : A** (déterministe, peu coûteux, ferme T115 sans attendre M4) ; sujet `graph` refusé jusqu'à un ADR qui exige une confirmation signée (M4) ; C s'ajoute en M4 avec le dossier de preuves.
- **Q4. Providers.** (A) miroir fichier peuplé depuis `releases.hashicorp.com`, sommes et signature vérifiées, versions de 14 jours au moins ; (B) l'humain ouvre `registry.opentofu.org` dans l'environnement cloud. **Recommandation : A, traité comme une tâche (T02)** : c'est aussi la forme cible du runner (aucun registre au moment du plan), la CI et le poste de l'humain l'utilisent à l'identique ; l'humain ne relit que le verrou (H-tools-lock).
- **Q5. Pack de politiques IaC.** (A) moteur embarqué, second pack dans l'adaptateur confiné, faits extraits du plan en Go ; (B) binaire Conftest (OPA d'une autre version, `http.send` disponible, format de sortie différent, exécution de commande de plus). **Recommandation : A** (règle `opa-confined` inchangée, mêmes capacités et barrière, parité avec `go tool opa test`) ; amendements de l'ADR 0011, de la vision et du skill par l'ADR 0014.
- **Q6. Coût et Infracost.** (A) clé fournie par l'humain dans les secrets de l'environnement cloud et hôte de l'API de prix ouvert ; (B) table de prix codée, datée, sourcée ; (C) blocage reporté à L4 (M4) sur le plan réel, `not_evaluated` en M3, Infracost dans `sandbox.sh` si la clé est sur le poste de l'humain. **Recommandation : C** : aucune clé ni donnée d'architecture vers un tiers depuis la session ou la CI, Infracost est plus juste sur un plan réel, le coût n'est pas une décision de sécurité ; la lecture « chaîne verte » de C2 exclut le coût, écart à valider par l'humain.
- **Q7. Ressources de soutien, raffinements et egress.** (A) table fermée dans l'équivalence et allocations dérivées par `internal/design/cidr` ; (B) tout porter au graphe (sous-réseaux par zone, `GatewaySubnet`, NAT) par `Build` et le schéma. **Recommandation : A en M3** (aucun changement de L2 ni de baseline `design`) ; egress par NAT dans la table de soutien d'un cluster à nœuds privés, signalé à part dans le rapport et en T150 ; arêtes de sortie au graphe en M6 (menace d'exfiltration) ; points de terminaison privés à la place du NAT si l'humain préfère payer pour supprimer l'egress.
- **Q8. Lecture de « plan réel » pour la racine `cluster`.** **Recommandation** : deux racines ; C2 = plan réel de `infra` ; `cluster` vérifiée par `tofu test` et plan hors ligne ; plan réel de `cluster` après un `sandbox-apply` facultatif de `infra`, hors critères.
- **Q9. Exceptions de scanners.** (A) aucune annotation nulle part, fichier central revu, expirant ; (B) annotations admises dans les modules internes seulement. **Recommandation : A** (un seul mécanisme, auditable, conforme à T30) ; revue sécurité groupée de T04 et T05 en une passe à la fin de T05.
- **Q10. Approbation de `sandbox-apply` et `sandbox-destroy` (T31).** Un contrôle écrit dans `scripts/sandbox.sh` ne protège pas d'un agent qui peut modifier le script localement. **Recommandation** : canal hors de portée de l'agent = permission « ask » de Claude Code et identifiants d'écriture obtenus sous MFA par l'humain (l'agent n'a jamais d'identifiant) ; le script n'applique que le plan enregistré dont l'empreinte a été affichée ; aucun apply en M3 ; `make sandbox-plan` passe aussi en « ask » (proposition 0013) ; état local chiffré dans `.sandbox/`.
- **Q11. Admission Kubernetes et `policies/k8s/`.** **Recommandation** : `admission_policy` réalisé en M3 par Pod Security Admission `restricted` (intégré, aucun composant de plus) ; Kyverno ou Gatekeeper par ADR en M5 avec `policies/k8s/` et le collecteur Kubernetes.
- **Q12. Nom et place des evals.** **Recommandation** : `evals/iac`, cible `iac` (cohérent avec `evals/design`), `loop: L3-iac`, `runs: 1`, baseline `evals/iac/baseline.json` hors registre des routes, rejouée en CI après H-CI-2.
- **Q13. Obligations trouvées ouvertes hors de la liste transmise.** (fd) (moyen, ADR 0011) et le lot CI de la section 8.2 du plan M2 ((ce), (cg), (bq), (br), (cf)) sont datés « avant M3 » et encore ouverts. **Recommandation** : (fd) et (cf) dans T01 (code), le reste par la proposition 0011 appliquée par l'humain (H-CI-1).

## 13. Écarts de l'ADR 0014, reportés au début de M3-T02

L'ADR 0014 (accepté le 2026-11-26) précise ce plan. Ses décisions priment ; sauf mention, les comptes des critères d'acceptation ne changent pas.

1. **D6, étage `composition`** en tête de la chaîne de L3, en Go, avant le rendu ; `Stage` gagne `composition`, `StageResult` gagne `Root` (étages `plan`, `policy` et `equivalence` rendus racine par racine).
2. **D7, garde statique en liste blanche** (fichiers, blocs, attributs de provider, sources de données, fonctions) ; refus ajoutés : blocs `ephemeral`, `import`, `removed`, `check` ; `templatestring`, fonctions non déterministes et fonctions de provider ; attributs `endpoints` et d'identité des providers.
3. **D8, réglages hors ligne** portés par la variable `rempart_offline_plan` du bundle (défaut `false`), jamais par un fichier de surcharge.
4. **D2, catalogue de réparation** : codes fixés, `L3-MODULE-VERSION` ajouté.
5. **D3 et fiche L3** : `Prepare` n'escalade sans boucle que pour `payload_too_large` ; `module_missing` et `no_translation` passent par la stagnation.
6. **Branche de repli** (sonde : azurerm impossible hors ligne) : les critères 2 et 3 de M3-T07 portent sur `internal/iacgen/testdata/aws-only-input.json` (racine `infra` sans azurerm) ; la référence, qui mêle AWS et azurerm dans `infra`, n'a pas de plan hors ligne (étages `plan`, `policy`, `equivalence` à `not_evaluated` pour cette racine).
7. **D20, règle `hcl-confined`** ajoutée à `DefaultRules`, vérifiée par `TestRepositoryConforms` (T03, avec la dépendance `hcl/v2` v2.25.0).
8. **D6, `exec-confined`** complétée d'un contrôle de sources (`os.StartProcess`, `syscall.Exec`, `syscall.ForkExec`, `syscall.StartProcess`, `unix.Exec`), sous-cas de `TestExecConfined` (T02).
9. **D16** : périmètre des exceptions limité aux findings des scanners sur le code des modules ; `Report.Excepted`, `Options.Today`, `LoadExceptions` ; parité avec le script étendue aux exceptions.
10. **D10** : `EQUIV-EGRESS` (`low`).
11. **D9** : un `control_id` partagé garde la même sévérité ; un type sans extracteur échoue fermé.
12. **D4** : le compilateur de M3 ne produit aucun `extra`.

Obligations ajoutées par la revue de M3-T01 et datées dans ce plan : (hd), (he), (gz), (hb) avant M3-T03 ; (hc) avant M3-T06 ; (ha) avant M3-T07 ; (gy) avant M3-T09.
