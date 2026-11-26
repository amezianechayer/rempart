# 0015. Isolation des outils IaC : espaces de noms, arbre fermé monté par un assistant de re-exécution, Landlock en renfort

- Statut : **accepté** par l'humain le 2026-11-26 (« Oui a tout » : les six questions, avec la recommandation de l'agent, oui à chacune), prototype mesuré le même jour (section « Mesure du prototype »). Les constats F10 à F12, la variante retenue pour (ht) et la section D13 bis font partie de la décision acceptée. Rédigé le 2026-11-26 par `architect` pour solder l'obligation (hg) de `docs/STATUS.md` (menace T157). L'humain l'accepte avant la phase tests de M3-T02b, une fois la section « Mesure du prototype » complétée. Tant que M3-T02b n'est pas close avec une revue `security-reviewer` PASS, `internal/validate/toolexec` n'est câblé ni dans `rempart check` (M3-T03) ni dans `rempart-worker` (M3-T08).
- Date : 2026-11-26
- Jalon : M3. Mise en œuvre par tâche :
  - M3-T02b (nouvelle, insérée entre T02 et T03) : D1 à D8, D10 à D13 ;
  - M3-T03 : D9 pour la chaîne, `rempart check` et le script du skill ;
  - M3-T08 : D9 pour le worker ;
  - M4 : Q5 (conteneur du worker), bornes de ressources (D8), profil réseau du runner (D14).
- Base :
  - ADR 0014 accepté le 2026-11-26 ; M3-T02 close ;
  - lot d'obligations dues avant M3-T03 fait le 2026-11-26 ((hd), (gz), (he), (hb), (hf), (hi), (hj), (hl)), revue sécurité PASS ; obligations (hp) à (ht) nées de cette revue ;
  - (hg), (hn), (ho), (hq), (hr) et (ht) ouvertes ; T160 (cas de test Rego sur une entrée irréalisable) déjà prise, d'où les numéros provisoires T161 et T162 ci-dessous.
- Sources :
  - code : `internal/validate/toolexec/{toolexec.go,toolexec_test.go}`, `internal/validate/toolchain.go` (`LoadToolchain`, `PluginDir`, `MirrorDir`, copies privées en 0500 et 0400 dans un répertoire 0700), `internal/archtest/{rules.go,exec_confined_test.go}`, `scripts/iac-tools.sh` (`inside`, `put`, `download`), `.claude/skills/secure-iac-generation/scripts/validate.sh`, `.github/workflows/verify.yml` ;
  - documents : `docs/00-VISION.md` (mode runner), `docs/02-THREAT-MODEL.md` (T3, T8, T17, T22, T24, T142, T143, T157, T159, section 4.2), `docs/STATUS.md` (obligations (hg), (hn), (ho)), `docs/SETUP.md` (WSL2, groupe `docker`), `docs/plans/M3-overview.md` (sections 5, 9, 10) ;
  - ADR : 0014 (D6, D8, D15, D18, risques résiduels 1 et 2, amendement 4).

## Contexte

### Ce que fait `toolexec.Run` aujourd'hui (établi)
- L'outil est lancé sans shell, arguments en tableau.
- Il tourne dans un `Workspace` créé par Rempart :
  - `tree/`, écrit par `os.Root`, répertoire de travail de chaque exécution ;
  - `data/`, qui est `TF_DATA_DIR`, hors de l'arbre ;
  - `path/`, vide, seule entrée de `PATH`.
- L'environnement est construit en liste blanche, et les mandataires pointent vers `127.0.0.1:9`.
- `Setpgid` est posé ; un délai tue le groupe de processus ; les sorties sont bornées.
- Juste avant l'exécution, le binaire est vérifié par SHA-256. C'est une copie privée en lecture seule, qui appartient à l'utilisateur, dans un répertoire que nul autre n'écrit.

### T157 (établi, revue sécurité de M3-T02)
L'outil tourne sous le même uid que son lanceur, dans les mêmes espaces de noms. Points numérotés pour la suite :

| # | Ce que l'outil peut faire aujourd'hui |
|---|---|
| P1 | lire `/proc/<ppid>/environ`, car Yama ne restreint pas `PTRACE_MODE_READ` : secrets du worker, `AWS_*` de l'humain sous `rempart check` |
| P2 | lire les fichiers des autres tenants et `~/.aws` |
| P3 | sortir du groupe par `setsid()` et survivre à `Run` |
| P4 | joindre la boucle locale (OpenBao, PostgreSQL et Temporal de la pile de dev, API Kubernetes locale), que le mandataire ne couvre jamais |
| P5 | lier le port 9 dans un conteneur où `ip_unprivileged_port_start=0`, et devenir le relais des autres outils |
| P6 | modifier entre deux exécutions les copies privées des autres outils, dont les rulesets tflint (obligation (hn)) |

D6 lance tflint, Checkov et Trivy en parallèle. C'est le mode opératoire de l'incident Trivy de mars 2026 (T143).

### Compléments relevés en préparant cet ADR (à confirmer par `security-reviewer`, section « Menaces à compléter »)

| # | Complément | Pourquoi |
|---|---|---|
| P7 | lire l'environnement, et la mémoire si Yama est absent ou à 0, de **tout** processus du même uid, pas seulement du parent : shell et Claude Code de l'humain, `tofu plan` de `sandbox.sh` porteur de l'identité en lecture, `Runner.Worker` en CI | `PR_SET_DUMPABLE=0` ne protège que le processus qui le pose (F1) |
| P8 | joindre une socket Unix nommée : `/var/run/docker.sock`, l'humain étant dans le groupe `docker` selon `docs/SETUP.md`, ce qui donne root ; agent SSH ; bus D-Bus de session, d'où `systemd-run --user` lance une commande hors de tout confinement | une socket nommée est un objet du système de fichiers, pas du réseau (F9) |
| P9 | écrire hors de l'espace de travail, pour persister ou empoisonner : `~/.bashrc`, `.git/hooks` du dépôt, fichiers du harnais `.claude/` (les gardes du harnais visent les outils de l'agent, pas ses sous-processus), cache de compilation Go, cache IaC | même uid |
| P10 | WSL2 : lire `/mnt/c` (fichiers Windows de l'humain), lancer un `.exe` Windows, qui s'exécute hors de tout confinement Linux | interopérabilité WSL |
| P11 | modifier l'arbre partagé pendant l'étage parallèle, pour masquer un finding à l'outil voisin | `tree/` partagé et inscriptible |
| P12 | signaler tout processus du même uid (`kill(-1)`), donc tuer le worker ou la session de l'humain | même uid, même espace PID |
| P13 | injecter des frappes dans le terminal de l'humain (`TIOCSTI` sur `/dev/tty`) sous `rempart check` | `Setpgid` garde la session et le terminal de contrôle |

### Sondes faites dans la session (établi)
Conteneur cloud, uid 0, noyau 6.18.44, cgroup v1 avec hiérarchie nommée, securityfs non monté.
- `unshare -U -r -n -p -f --mount-proc true` réussit : espaces utilisateur, réseau, PID et montage disponibles.
- `max_user_namespaces` vaut 64271.
- `landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)` rend l'ABI 7.
- Ni `bwrap`, ni `firejail`, ni `nsjail` ne sont installés.

### Hypothèses non sondées (à vérifier, commande et moment donnés)

| # | Hypothèse | Ce qui en dépend | Vérification |
|---|---|---|---|
| H0 | La sonde a tourné en uid 0 : elle ne prouve pas le chemin non privilégié | toutes les options à espaces de noms | critère 4 de M3-T02b (`setpriv` vers l'uid 65534, dans la session) ; CI après Q4 |
| H1 | CI : `verify.yml` fixe `runs-on: ubuntu-24.04`, même famille que `ubuntu-latest`. Ubuntu 24.04 restreint par défaut les espaces de noms utilisateur non privilégiés par AppArmor (`kernel.apparmor_restrict_unprivileged_userns=1`), ce qui fait échouer la création d'un espace réseau dans un espace utilisateur. Landlock y est disponible (ABI 4 ou plus sur un noyau 6.8) | (a) à (d) en CI ; Q4 | étape de diagnostic de la proposition 0014 : `sysctl kernel.apparmor_restrict_unprivileged_userns` ; `unshare -U -r -n true; echo rc=$?` ; `tr , '\n' < /sys/kernel/security/lsm \| grep -cx landlock` |
| H2 | Poste de l'humain, WSL2 sous Ubuntu 24.04 (`docs/SETUP.md`) : support de Landlock et des espaces de noms à confirmer. Le réglage AppArmor ci-dessus vient d'un correctif des noyaux Ubuntu ; le noyau de WSL2 est fourni par Microsoft et pourrait ne pas le porter | (a) à (d) sur le poste ; Q2, Q3 | humain (H-isolation-probe) : `uname -r` ; `sysctl kernel.apparmor_restrict_unprivileged_userns` ; `unshare -U -r -n -p -f --mount-proc true; echo rc=$?` ; `cat /sys/kernel/security/lsm` ; puis `REMPART_REQUIRE_SANDBOX=1 go test ./internal/validate/toolexec/ -run '^TestIsolation' -v` |
| H3 | Production : `rempart-worker` tourne en conteneur (mode runner, `docs/00-VISION.md`). Les profils seccomp par défaut de Docker et `RuntimeDefault` de Kubernetes refusent la création d'espaces de noms sans `CAP_SYS_ADMIN`. L'admission des appels Landlock par ces profils et le LSM de l'hôte sont inconnus | Q5 | M4 : `TestWorkerRequiresIsolation` lancé dans l'image, avec le profil de l'ADR de déploiement |
| H4 | À l'ABI 7, Landlock ne restreint pas `connect()` sur une socket Unix nommée. Le droit `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (constante présente dans `golang.org/x/sys` v0.49.0) le fait sur un noyau plus récent, numéro d'ABI à vérifier | (b) ne ferme pas P8 | prototype : connexion à une socket nommée de test depuis un processus restreint |
| H5 | Ubuntu 24.04 : bwrap de la distribution, et profil AppArmor qui l'autoriserait à créer un espace utilisateur | (d) seulement | non mesuré, seulement si (d) était retenue |
| H6 | OpenTofu et tflint joignent providers et plugins par sockets Unix (go-plugin) sous Linux, donc une interface `lo` éteinte suffit | D5 | prototype |

### Faits techniques qui départagent les options
- **F1. `ptrace_may_access`** (lecture de `/proc/<pid>/environ` et `mem`). L'accès passe si les uid noyau sont égaux ; il est ensuite refusé si la cible n'est pas « dumpable » et que l'appelant n'a pas `CAP_SYS_PTRACE` dans l'espace utilisateur de la cible ; puis les LSM (Yama, Landlock) décident. Conséquences :
  - un espace utilisateur ne change pas l'uid noyau et ne ferme donc rien seul ;
  - `PR_SET_DUMPABLE=0` ferme la lecture du lanceur pour un outil sans capacité dans l'espace du lanceur, mais pas celle des autres processus (P7).
- **F2. Groupes supplémentaires.** Un espace utilisateur non privilégié les conserve (`setgroups` refusé, groupes gardés pour le contrôle d'accès) : le groupe `docker` reste actif dans l'espace.
- **F3. Espace PID.** Quand le PID 1 d'un espace PID meurt, le noyau tue tous les autres processus de l'espace. C'est la garantie que cherchait le « cgroup pour tuer les descendants échappés » de (hg).
- **F4. `Pdeathsig`** est envoyé à la mort du **fil** qui a créé l'enfant, pas du processus. En Go, il faut donc garder la goroutine verrouillée sur son fil de `Start` à `Wait`.
- **F5. `/proc` de l'hôte.** Un espace PID sans nouveau montage de `/proc` laisse voir les processus de l'hôte.
- **F6. `chroot` n'est pas une frontière.** Un outil qui crée un espace utilisateur imbriqué y obtient `CAP_SYS_CHROOT` et en sort. Seul `pivot_root` suivi du détachement de l'ancienne racine, dans un espace de montage, ne laisse rien à atteindre.
- **F7. Landlock.**
  - Le domaine s'applique au fil qui appelle `landlock_restrict_self`, et ses descendants en héritent. Il exige `PR_SET_NO_NEW_PRIVS` (par fil) ou `CAP_SYS_ADMIN`.
  - Un processus restreint ne peut viser par ptrace, donc par les fichiers de `/proc` protégés par F1, aucun processus hors de son domaine.
  - Un fil restreint ne peut ni monter ni changer de racine.
  - Selon l'ABI : 4 restreint `bind` et `connect` en TCP (pas UDP), 5 les ioctl de périphériques, 6 les signaux et les sockets abstraites hors du domaine.
- **F8. Go ne peut exécuter aucun code entre le fork et l'exec.** `syscall.SysProcAttr` (Go 1.27) offre `Cloneflags`, `UidMappings`, `GidMappings`, `Pdeathsig`, `UseCgroupFD` et `CgroupFD`. Un montage en lecture seule exige donc un assistant : re-exécution du binaire Rempart lui-même, à la manière de `nsexec` de runc, ou un outil externe comme bubblewrap. Le parent écrit `/proc/<pid>/uid_map` depuis le fil qui a appelé `Start`.
- **F9. Sockets.** Les sockets Unix abstraites sont propres à l'espace réseau ; les sockets nommées sont des fichiers, joignables depuis tout espace réseau.

### Contraintes du projet
- Isolation stricte par tenant, testée.
- Mode runner : aucun identifiant d'écriture dans le plan de contrôle.
- Toute dépendance nouvelle passe par un ADR avec mesure (précédent : `hcl/v2`, D20 de l'ADR 0014).
- Échec fermé : un mode dégradé n'est jamais le défaut.
- `make verify-quick` reste vert sans outil IaC installé.

### Socle commun S, supposé par toutes les options
Il est peu coûteux, ne dépend d'aucun mécanisme du noyau, et chaque option le suppose :
- `PR_SET_DUMPABLE=0` dans le processus qui lance les outils ;
- `Setsid` au lieu de `Setpgid` : nouvelle session, aucun terminal de contrôle (P13), groupe toujours tué par `-pid` ;
- `Pdeathsig: SIGKILL`, goroutine verrouillée sur son fil de `Start` à `Wait` (F4).

## Options envisagées

### Option (a) : espaces de noms natifs de Go, sans confinement du système de fichiers
- **Principe** : `Cloneflags` = utilisateur, réseau, PID, IPC, UTS, plus le socle S et un cgroup. L'outil voit le système de fichiers de l'hôte, `/proc` de l'hôte compris (F5).
- **Ferme** : P1 (S, et l'outil n'a aucune capacité dans l'espace du lanceur), P3 (F3), P4 et P5 (espace réseau sans interface), P12 (espace PID), P13 (S).
- **Laisse ouvert** : P2, P6, P7, P8 (F2), P9, P10, P11.
- **Portabilité** :
  - session : oui (sondé) ;
  - CI : non, sauf levée de la restriction AppArmor (H1) ;
  - WSL2 : à confirmer (H2) ;
  - conteneur du worker : non avec le profil seccomp par défaut (H3).
- **Cgroup** : `UseCgroupFD` exige cgroup v2 et un sous-arbre délégué inscriptible. La session est en v1 ; la délégation en CI et sous WSL2 est inconnue. Le cgroup n'y apporte rien que F3 n'apporte, hormis des bornes de ressources.
- **Mécanisme absent** : échec fermé (`ErrIsolationUnavailable`, aucun processus lancé). Aucun mode dégradé n'a de sens : sans espace utilisateur, (a) se réduit au socle S.
- **Coût** : de l'ordre de 50 lignes de Go et 250 lignes de tests ; aucune dépendance.
- **Tests** : `TestIsolationKillsEscapedDescendants`, `TestIsolationNoNetwork` (sauf le sous-cas `unix_pathname`), `TestIsolationLauncherNotDumpable`, `TestIsolationNoTerminal`. Ils sautent proprement si l'espace utilisateur manque, et échouent si `REMPART_REQUIRE_SANDBOX=1` (D12).

### Option (b) : (a), plus Landlock appliqué à un fil dédié avant le fork
- **Principe** :
  - une goroutine appelle `runtime.LockOSThread` sans jamais déverrouiller : le fil meurt avec elle ;
  - elle pose `PR_SET_NO_NEW_PRIVS`, construit et applique le domaine, puis appelle `Start` et `Wait` depuis ce fil ;
  - l'enfant hérite du domaine (F7).
- **Deux variantes du jeu de règles** :
  - (b1), lecture du texte de (hg) (« système de fichiers en lecture seule hors du répertoire de travail ») : lecture partout, écriture dans l'espace de travail seulement. Elle ne ferme pas P2 : `~/.aws` et les arbres des autres tenants restent lisibles ;
  - (b2) : lecture et exécution limitées à une liste fermée (répertoires système, copie privée, outil, espace de travail), écriture dans `data/`, `HOME` et `TMPDIR` de l'exécution seulement. C'est la variante comparée ci-dessous.
- **Ferme** (b2) : tout ce que ferme (a), plus P2, P6 et P9 (règles), P7 (domaine, F7), P10 (ni lecture ni exécution sous `/mnt`), P11 (si `tree/` est hors des droits d'écriture). Sans espace réseau, P4 et P5 ne seraient fermés que pour TCP, à l'ABI 4 ou plus.
- **Laisse ouvert** : P8 à l'ABI 7 (H4) : socket Docker, agent SSH, bus D-Bus de session. Sur le poste de l'humain, c'est une évasion complète.
- **Difficultés propres** :
  - le parent écrit `/proc/<pid>/uid_map` depuis le fil restreint (F8), et Landlock refuse cette écriture sauf à ouvrir `/proc` en écriture. (b) doit donc créer l'espace utilisateur sans correspondance d'uid : l'outil se voit `nobody`, à prouver par prototype ;
  - `Pdeathsig` lie la vie de l'outil à ce fil (F4).
- **Portabilité** :
  - session : oui (ABI 7) ;
  - CI : Landlock seul (ABI 4 ou plus) ; espaces de noms non, comme (a) ;
  - WSL2 : à confirmer ;
  - conteneur : Landlock à confirmer (H3) ; espaces de noms non.
- **Mécanisme absent** :
  - Landlock absent, espaces présents : (b) devient (a), ce qui rouvre P2, P6, P7, P9, P10 et P11 ; c'est donc un échec fermé ;
  - espaces absents, Landlock présent : « Landlock seul » laisse ouverts P3, P4 en UDP (exfiltration par DNS), P8, et P12 sous l'ABI 6. Ce serait un mode dégradé explicite, jamais le défaut, refusé au worker et à la CI, autorisé seulement par une variable posée par l'humain sur son poste (Q2).
- **Coût** : (a), plus 250 à 300 lignes (sonde d'ABI, jeu de règles, fil verrouillé) ; aucune dépendance si les appels passent par `syscall.Syscall` dans `toolexec`.
- **Tests** : ceux de (a), plus `TestIsolationFilesystemClosed`, `TestIsolationPrivateCopiesReadOnly` et `TestIsolationHidesProcesses` (l'environnement d'un processus témoin est refusé), et le sous-cas `unix_pathname` attendu **ouvert** à l'ABI 7. Les sous-tests Landlock sautent si l'ABI requise manque.

### Option (c) : assistant de re-exécution de Rempart, qui monte les espaces de noms et l'arbre, puis fait l'exec
- **Principe** :
  - `Run` lance `/proc/self/exe`, c'est-à-dire le binaire Rempart en cours, avec un `argv[0]` marqueur, les `Cloneflags` de (a), une correspondance d'uid et de gid, et une configuration passée sur un tube. Le parent n'est pas restreint, donc l'écriture de `uid_map` ne pose aucune difficulté (F8) ;
  - l'assistant démarre déjà dans les nouveaux espaces de noms, qu'ont créés les drapeaux de `clone`. Ses montages valent donc pour tout le processus, sans cgo, contrairement à `nsexec` de runc ;
  - il monte un arbre fermé sur un tmpfs, monte le `/proc` de son espace PID, fait `pivot_root`, détache l'ancienne racine (F6), durcit, applique Landlock s'il est présent, puis fait l'exec de l'outil, qui devient PID 1.
- **Ferme** : P1 à P13 (tableau de synthèse). P8 et P10 sont fermés parce que ni `/run`, ni `/var`, ni le `/tmp` de l'hôte, ni `/mnt` n'existent dans l'arbre de l'outil. P7 l'est parce que le `/proc` de l'outil est celui de son espace PID.
- **Leçon de CVE-2019-5736 (runc)** :
  - le binaire Rempart n'est jamais visible en écriture dans l'arbre de l'outil ;
  - aucun code non fiable ne tourne avant l'exec, qui remplace l'image ;
  - l'assistant ne lit que sa configuration ;
  - l'assistant n'accorde aucun droit que son appelant n'a pas déjà.
- **Portabilité** : celle de (a), plus l'espace de montage, sondé dans la session par `--mount-proc`. Donc oui dans la session ; non en CI sans levée de la restriction (H1) ; à confirmer sous WSL2 (H2) ; non dans le conteneur par défaut (H3).
- **Mécanisme absent** : échec fermé. Le mode « Landlock seul » de (b) resterait le seul mode dégradé concevable (Q2).
- **Coût** :
  - de l'ordre de 600 à 900 lignes de Go dans `toolexec` : assistant, table de montage, protocole, sonde, couche Landlock ;
  - 450 lignes de tests ;
  - aucune dépendance ;
  - c'est le code de sécurité propre le plus lourd à relire (T161).
- **Tests** : toute la suite comportementale de D12, sous-cas `unix_pathname` attendu fermé, plus `TestIsolationParallelRunsSeparated` et `TestIsolationLandlockLayer`.

### Option (d) : bubblewrap externe, épinglé
- **Principe** : `toolexec` lance `bwrap --unshare-all --die-with-parent --new-session --cap-drop ALL --clearenv`, avec les montages de (c) (`--ro-bind`, `--bind`, `--proc`, `--dev`, `--tmpfs`, `--chdir`), puis l'outil.
- **Ferme** : comme (c), si les montages sont les mêmes.
- **Chaîne d'approvisionnement** :
  - le projet amont ne publie que des archives de sources, pas de binaire. Le modèle de D15 (actif de release haché au verrou, revérifié avant chaque exécution) ne s'applique pas ;
  - il faudrait compiler du C dans `iac-tools.sh` (meson, en-têtes libcap) ou prendre le paquet de la distribution, dont la version et la somme diffèrent d'une distribution à l'autre ;
  - certaines distributions l'installent setuid root, une variante que Rempart devrait refuser ;
  - un programme C entre dans la base de confiance.
- **Portabilité** :
  - session : non installé ;
  - CI : `apt` possible, mais même restriction AppArmor, sauf profil (H5) ;
  - WSL2 : `apt` ;
  - conteneur : à installer dans l'image, même restriction seccomp.
- **Mécanisme absent** : bwrap absent donne un finding critique comme un outil absent (`TOOL_MISSING`) : échec fermé. Mais chaque test qui appelle `Run`, les `TestToolexec*` existants compris, exige alors bwrap. Ces tests sauteraient dans `make verify-quick` sans outil, et la couverture de l'exécutant serait perdue hors intégration.
- **Coût** : de l'ordre de 150 lignes de Go, plus l'installation et l'épinglage hors du modèle du verrou ; une dépendance externe.
- **Tests** : la même suite comportementale, plus `TestBwrapPinned` (somme, absence de bit setuid).

### Option (e) : isolation déléguée au conteneur du worker, résidu accepté pour `rempart check` sur le poste
- **Principe** : aucun mécanisme dans `toolexec`. Le conteneur du worker (utilisateur non root, système de fichiers racine en lecture seule, politique réseau de sortie) borne l'outil.
- **Ferme** :
  - outil et worker dans le même conteneur : seulement P1 par le socle S, et P13. P2 (espaces de travail des autres tenants dans le même conteneur), P3 à P12 restent ouverts : le réseau du conteneur est celui dont le worker a besoin (Temporal, OpenBao, PostgreSQL), donc P4 est ouvert ;
  - pod d'outils distinct : la plupart des points sont fermés, mais c'est une architecture de déploiement de M4 (protocole entre worker et pod, volume de l'espace de travail).
- **Portabilité** : sans objet en M3. Il n'y a pas de conteneur de worker en M3 : `make l3-demo` et `-l3-once` tournent sur l'hôte. Sur le poste, le résidu est total.
- **Mécanisme absent** : le résidu sur le poste serait le comportement **par défaut** de `rempart check`, contraire à la contrainte « jamais par défaut ».
- **Coût** : nul en M3 ; travail de déploiement en M4.
- **Tests** : aucun en M3. En M4 : test du contexte de sécurité du pod et de la politique de sortie.

### Synthèse : fermeture point par point (avec le socle S)

| Point | (a) | (b2) | (c) | (d) | (e), même conteneur |
|---|---|---|---|---|---|
| P1 environ du lanceur | fermé | fermé | fermé | fermé | fermé par S, si l'outil n'a pas `CAP_SYS_PTRACE` |
| P2 autres tenants, `~/.aws` | ouvert | fermé (ouvert en b1) | fermé | fermé | ouvert |
| P3 `setsid()`, survie | fermé (F3) | fermé | fermé | fermé | ouvert |
| P4 boucle locale | fermé | fermé | fermé | fermé | ouvert |
| P5 port 9 en relais | fermé | fermé | fermé | fermé | ouvert |
| P6 copies privées ((hn)) | ouvert | fermé | fermé | fermé | ouvert |
| P7 autres processus du même uid | ouvert (F5) | fermé (F7) | fermé | fermé | ouvert |
| P8 sockets Unix nommées | ouvert (F2) | **ouvert à l'ABI 7** (H4) | fermé | fermé | ouvert |
| P9 écriture persistante | ouvert | fermé | fermé | fermé | ouvert |
| P10 `/mnt/c`, interop WSL | ouvert | fermé | fermé | fermé | ouvert sur le poste |
| P11 arbre partagé | ouvert | fermé | fermé | fermé | ouvert |
| P12 `kill(-1)` | fermé | fermé | fermé | fermé | ouvert |
| P13 `TIOCSTI` | fermé (S) | fermé (S) | fermé (S, `/dev` minimal) | fermé (`--new-session`) | fermé (S) |

### Synthèse : portabilité

| Contexte | (a) | (b2) | (c) | (d) | (e) |
|---|---|---|---|---|---|
| Session cloud (sondé) | oui | oui (ABI 7) | oui | non installé | sans objet |
| CI `ubuntu-24.04` (H1) | non sans levée de la restriction | Landlock seul | non sans levée | non sans profil (H5) | sans objet |
| Poste WSL2 (H2) | à confirmer | à confirmer | à confirmer | à confirmer | résidu total |
| Conteneur du worker (H3, M4) | non par défaut | Landlock à confirmer | non par défaut | non par défaut | selon le déploiement |

Lecture :
- seules (c) et (d) ferment les treize points ;
- (d) sort du modèle de chaîne d'approvisionnement de D15 et ajoute un programme C ;
- les quatre options à espaces de noms partagent la même limite de portabilité, que la CI lève par configuration (Q4), et que le conteneur de production réglera en M4 (Q5).

## Décision (proposée)

### D1. Option (c), niveau unique « complet », exigé partout, échec fermé
- **Contenu du niveau complet** : socle S (D2), espaces de noms (D3), arbre fermé monté par l'assistant (D4 à D6). Landlock est un renfort (D7), pas une condition.
- **Contextes** : le niveau complet est exigé pour toute exécution d'outil, dans tous les contextes (session, CI, poste, worker).
- **Aucun mode dégradé en M3** (Q2) : sans isolation complète, aucun outil ne tourne ; `rempart check --static` reste disponible.
- **Pourquoi (c) plutôt que (b)** : seules (c) et (d) ferment P8, et entre elles (c) est seule à rester dans le modèle de D15 sans dépendance. (b) n'est pas abandonnée : Landlock devient la couche de renfort de (c) (D7), et la base d'un éventuel mode dégradé si l'humain le demande (Q2).

### D2. Socle du lanceur (S)
- **`PR_SET_DUMPABLE`** : `Run` pose `PR_SET_DUMPABLE=0` avant tout lancement. Le drapeau vaut pour tout le processus et l'appel est idempotent ; `Run` vérifie ensuite `PR_GET_DUMPABLE` à 0. `rempart check` en bénéficie comme le worker.
- **Lancement** : `Setsid` remplace `Setpgid`. `Pdeathsig: SIGKILL` est posé. `Start` et `Wait` se font sur une goroutine verrouillée sur son fil (F4).
- **Sonde** : `Probe` lance l'assistant une fois par processus en mode sonde (espaces, arbre, puis sortie sans exec), et met le résultat en cache.

### D3. Espaces de noms
- **Espaces exigés** :
  - utilisateur, avec un uid et un gid internes fixes et non nuls (1000), associés à l'uid et au gid effectifs du lanceur ; `setgroups` refusé ;
  - montage, réseau, PID, IPC, UTS, cgroup.
- **Absence** : l'absence de l'un d'eux à la sonde donne `ErrIsolationUnavailable`.
- **Capacités** : un uid interne non nul fait perdre ses capacités à l'outil à l'exec, y compris quand le lanceur est root, comme dans la session.

### D4. Assistant de re-exécution
- **Lancement** :
  - par `exec.Cmd` sur `/proc/self/exe`, `argv[0]` = `rempart-toolexec-helper`, environnement vide ;
  - configuration sur le descripteur 3 : JSON décodé strictement, 64 Kio au plus, chemins absolus et propres revérifiés par l'assistant ;
  - canal de compte rendu sur le descripteur 4, fermé à l'exec.
- **Poignée de main** : l'assistant écrit un jeton « prêt » avant tout montage. Le parent tue l'assistant et rend `ErrIsolationSetup` s'il ne le reçoit pas dans les 2 secondes, ou s'il reçoit un code d'erreur au lieu de la fin de fichier qui signe l'exec. Cela couvre un binaire qui aurait oublié `MaybeHelper` et lancerait son `main` normal.
- **`toolexec.MaybeHelper()`** est la première instruction de chaque `main` et de chaque `TestMain` dont le binaire lie `toolexec` (règle `toolexec-helper-first`, D11). Hors du mode assistant, elle rend la main tout de suite.
- **Discipline de l'assistant** : il ne lit rien d'autre que sa configuration, n'ouvre aucune connexion, et n'accorde aucun droit que son appelant n'a pas.

### D5. Arbre de l'outil : liste fermée, mêmes chemins absolus que sur l'hôte

| Entrée | Montage | Options |
|---|---|---|
| `/` | tmpfs, remonté en lecture seule après la préparation | `nosuid`, `nodev` |
| `/usr`, `/lib`, `/lib64`, `/bin`, `/sbin` (ou leurs liens, si `/usr` est fusionné) | lien en lecture seule | `nosuid`, `nodev` |
| `/etc` | fichiers synthétiques : `passwd` et `group` à l'uid interne, `hosts`, `resolv.conf` vide ; rien de l'hôte | lecture seule |
| `/dev` | tmpfs avec `null`, `zero`, `full`, `random`, `urandom` liés ; ni `tty` ni `pts` | `nosuid` |
| `/proc` | `proc` de l'espace PID, `subset=pid` si le noyau l'admet (mesure) | `nosuid`, `nodev`, `noexec` |
| répertoire de l'outil (`filepath.Dir(Tool.Path)`) et entrées de `Spec.ReadOnly` (copie privée : binaires, plugins, miroir) | lien en lecture seule | `nosuid`, `nodev` |
| `tree/` | lien en lecture seule, **pour tous les outils** (P11) | `nosuid`, `nodev`, `noexec` |
| `data/` | lien en écriture si `Spec.WriteData` (exécutions d'OpenTofu), absent sinon | `nosuid`, `nodev` |
| `HOME`, `TMPDIR` de l'exécution | lien en écriture | `nosuid`, `nodev`, `noexec` |

- **Tout le reste est absent** : `/home`, `/root`, `/run`, `/var`, `/tmp` de l'hôte, `/mnt`, `/sys`, `/opt`, les espaces de travail des autres tenants, le cache IaC, le dépôt, le binaire Rempart.
- **Réseau** : l'interface `lo` reste éteinte (H6). Si le prototype montre qu'un outil l'exige, elle est levée, sans autre interface. Le mandataire injoignable reste en seconde barrière.
- **Tenue de la liste** : elle est un littéral Go de `toolexec`, sous CODEOWNERS. Tout ajout, par exemple un besoin de Checkov mesuré en M3-T03, amende cet ADR avant le code.

### D6. Durcissement avant l'exec
L'assistant fait, dans cet ordre :
1. `pivot_root`, puis détachement et suppression de l'ancienne racine (F6) ;
2. `sethostname` ;
3. `user.max_user_namespaces=0` dans l'espace utilisateur de l'outil, si le prototype le confirme : l'outil ne peut plus créer d'espace imbriqué (T161) ;
4. `chdir` vers `tree/` ;
5. fermeture de tout descripteur au-delà de 2, hors le canal de compte rendu ;
6. verrouillage du fil, `PR_SET_NO_NEW_PRIVS`, ensemble limitant de capacités vidé, capacités ambiantes effacées ;
7. couche Landlock (D7) ;
8. `syscall.Exec` de l'outil.

Si l'exec échoue, l'assistant écrit un code fixe sur le descripteur 4 et sort avec le code 127.

### D7. Landlock en couche de renfort
- **Quand** : appliqué par l'assistant, juste avant l'exec, si l'ABI vaut 1 ou plus.
- **Règles** :
  - système de fichiers : exactement les entrées de D5, en lecture et exécution pour les liens en lecture seule (sans exécution sur `tree/`), en écriture pour `data/`, `HOME` et `TMPDIR` ;
  - ABI 4 ou plus : `bind` et `connect` TCP refusés ;
  - ABI 6 ou plus : signaux et sockets abstraites limités au domaine.
- **Échec fermé** : une ABI annoncée par la sonde mais qui échoue à l'application donne `ErrIsolationSetup`.
- **Absence** : une ABI 0 est consignée (`Isolation.LandlockABI`) mais ne bloque pas, car D3 et D5 ferment T157 seuls.
- **M4** : l'exigence est réexaminée avec le noyau des workers.

### D8. Fin d'exécution et descendants
- **Fin** : l'outil est le PID 1 de son espace. Le `SIGKILL` envoyé à `-pid` (délai, borne de sortie, fin de `Run`) le tue, et le noyau tue tout l'espace (F3). Aucun descendant ne survit à `Run`, `setsid()` compris.
- **Mort du lanceur** : `Pdeathsig` couvre la mort du lanceur.
- **Pas de cgroup en M3** : cgroup v1 dans la session, délégation inconnue ailleurs. C'est un écart justifié au texte de (hg).
- **Bornes de ressources** (mémoire, nombre de processus, disque de `data/`) : M4, par les limites du conteneur ou un cgroup délégué (T24).

### D9. Erreurs, findings, rapport, worker et script du skill
- **Erreurs de `toolexec`** (messages fixes, jamais une sortie de l'outil) :
  - `ErrIsolationUnavailable`, rendue avant tout processus ;
  - `ErrIsolationSetup`.
- **Chaîne** (M3-T03) : ces erreurs deviennent le finding critique `TOOL_ISOLATION_UNAVAILABLE`, et L3 escalade en `tool_unavailable` (code existant de D18). `Report` porte `Isolation` (niveau, ABI Landlock) pour le futur dossier de preuves.
- **`rempart check`** : code 1 avec ce finding dès qu'un étage outillé doit tourner ; `--static` est inchangé.
- **Worker** (M3-T08) : `Probe` est appelé au démarrage, avant toute connexion à Temporal, comme `LoadToolchain`. Sans niveau complet, le processus s'arrête sans enregistrement.
- **Script du skill** : `scripts/validate.sh` ne lance plus aucun outil lui-même, puisqu'il les lance aujourd'hui sans confinement, depuis le `PATH`. Il appelle `rempart check --json` et garde la seule normalisation en Python (écart E5).

### D10. Aucune dépendance nouvelle
- Les appels passent par `syscall` dans `toolexec` (`Mount`, `PivotRoot`, `Unmount`, `Sethostname`, et `Syscall` pour `prctl`, `ioctl` et Landlock).
- `golang.org/x/sys/unix`, déjà au graphe en v0.49.0 (indirect), n'est importé directement par `toolexec` que si la mesure montre qu'il est déjà lié dans `rempart` et `rempart-worker` (section « Mesure du prototype »). Dans ce cas, aucun module n'est ajouté.

### D11. Règles d'architecture
- **`isolation-confined`** : `syscall.Mount`, `Unmount`, `PivotRoot`, `Chroot`, `Unshare`, `Setns`, `Sethostname` et leurs équivalents de `golang.org/x/sys/unix` sont refusés hors de `internal/validate/toolexec`. C'est un contrôle de sources sur le modèle de `checkProcessSource`. `Syscall` y est déjà confiné par (hj).
- **`toolexec-helper-first`** : tout `main` et tout `TestMain` dont le binaire lie `toolexec` (`go list -deps -test`) commence par `toolexec.MaybeHelper()`.
- **Contrôle de `check(spec)`** : tout chemin que nomme l'environnement construit (`TF_CLI_CONFIG_FILE`, `TFLINT_PLUGIN_DIR`, configuration de tflint) doit être couvert par une entrée en lecture seule de D5, sinon `ErrSpec`. Une entrée de `Spec.ReadOnly` doit :
  - appartenir à l'uid effectif et n'être inscriptible par nul autre ;
  - n'être ni `/`, ni le répertoire temporaire lui-même, ni un ancêtre de l'espace de travail, de `HOME` ou d'une autre entrée.
- **L'assistant reste dans le paquet `toolexec`** : `exec-confined` n'a besoin d'aucune exemption nouvelle.

### D12. Tests : témoins, sans réseau, sauts contrôlés
- **Faux outil** : c'est le binaire de test lui-même, copié en lecture seule dans un répertoire privé et haché. Son `TestMain` reconnaît le premier argument `fake-tool` et exécute une action : lire, écrire, se connecter, lier, `setsid`, signaler. Aucun utilitaire du système n'est requis.
- **Témoin** : chaque test d'attaque lance la même action par `exec.Command` direct dans le test, et prouve qu'elle réussit hors isolation. Si le témoin échoue, l'environnement bloque déjà l'attaque : le test saute avec une raison fixe, jamais un succès vide.
- **Pas de réseau** : les cibles sont des écouteurs TCP et UDP sur `127.0.0.1:0`, une socket Unix nommée dans un répertoire temporaire, une socket abstraite et un processus victime, tous créés par le test.
- **`requireIsolation(t)`** :
  - saute avec une raison fixe si la sonde ne rend pas le niveau complet ;
  - échoue si `REMPART_REQUIRE_SANDBOX=1`. La CI pose cette variable (proposition 0014), et les critères de M3-T02b sont lancés avec elle ;
  - `TestIsolationFailsClosed` ne saute jamais : il remplace la sonde par la variable non exportée `probe`, dans le paquet seulement.
- **Tests existants** : les `TestToolexec*` passent par l'isolation. Les marqueurs de `TestToolexecNoShell` sont écrits dans `data/` (`WriteData`) et non plus dans `tree/`, désormais en lecture seule. Sans ce changement, le test deviendrait vide : c'est un test modifié, à déclarer.

### D13. Obligations (hn) et (ho)
- **(hn)** : couverte par D5. La copie privée (binaires, rulesets, miroir) est montée en lecture seule pour tout outil, ce qui est la seconde forme du correctif de (hn) ; aucun rehachage avant chaque `tflint` n'est requis. Preuve : `TestIsolationPrivateCopiesReadOnly`. Résidu : un processus du même uid hors isolation peut encore la modifier, mais il détient déjà tous les droits de cet uid.
- **(ho)** : la condition de l'attaque, un lien planté dans le cache par un outil du même uid, disparaît, puisque le cache est absent de l'arbre de l'outil. Le correctif du script est fait quand même dans M3-T02b, car il est peu coûteux et que `iac-tools.sh` tourne hors de l'isolation : `inside()` d'abord, puis création par `dir_fd` et `O_NOFOLLOW`. Preuve : sous-cas de `TestIaCToolsScriptRefusesTraversal`.

### D13 bis. Obligations nées de la revue du lot avant M3-T03 (ajout de l'agent, après la rédaction)
Cette revue (verdict PASS) est arrivée après la rédaction de cet ADR. Rattachement proposé, à confirmer à l'acceptation :
- **(hq)** (T159) :
  - la partie « arbre scellé pendant les exécutions » est couverte par D5 : `tree/` est monté en lecture seule pour tout outil, donc aucun outil n'y écrit ni n'y dépose `.trivyignore` pour le suivant ;
  - restent à faire dans M3-T03, hors de cet ADR : `WriteFile` limité à la liste fermée de D7 de l'ADR 0014 (ni `terraform.tfstate*` ni `*.tfvars`) et sorties des outils (plan) écrites dans `data/` ;
  - `path/` en 0500 : sans objet sous D5, où `PATH` ne nomme que des entrées du montage en lecture seule ; le mode est posé quand même par M3-T02b, pour un coût nul.
- **(hr)** : rejoint le contrôle de `check(spec)` de D11. Tout chemin que nomme l'environnement construit doit être couvert par une entrée en lecture seule fournie par `Toolchain` (`ReadOnlyRoots`, `PluginDir`, configuration CLI rendue), jamais un chemin libre ; la configuration CLI d'OpenTofu est imposée par la chaîne. À faire dans M3-T02b, étape 3.
- **(ht)** (T157) :
  - propriétaire et mode n'arrêtent pas un processus du même uid hors isolation, qui peut réécrire le binaire entre la vérification du parent et l'exec de l'assistant ;
  - proposé pour l'étape 2 de M3-T02b : le parent copie le binaire vérifié dans un `memfd` scellé (`F_SEAL_WRITE`, `F_SEAL_SHRINK`, `F_SEAL_GROW`, `F_SEAL_SEAL`), haché pendant la copie, et le passe à l'assistant sur un descripteur hérité ; l'assistant fait l'exec par `execveat(fd, "", AT_EMPTY_PATH)`. La fenêtre entre la vérification et l'exec disparaît, et le binaire n'a plus besoin d'être visible dans l'arbre de l'outil ;
  - à mesurer par le prototype : exec d'un `memfd` depuis l'espace de montage de l'assistant, surcoût de la copie pour les gros binaires (OpenTofu, Trivy) ;
  - le contrôle du `TMPDIR` employé (bit collant ou répertoire privé) est fait par `check`.
- **(hs)** (lancement de Checkov sous les contrôles de (hi)) : reste à M3-T03. L'arbre fermé de D5 devra y ajouter le venv de Checkov en lecture seule, ce qui amende la liste de D5 avant le code.

### D14. Hors périmètre
- Le plan réel de `scripts/sandbox.sh` : il exige le réseau et l'identité de lecture de l'humain. La chaîne qu'il rejoue (`rempart check --plan`) est, elle, isolée.
- Le profil réseau du runner (sortie filtrée vers les seules API du cloud), en M4.
- Un filtre seccomp, en M4.
- Les bornes de ressources (D8).
- Le git de `rempart-evals` (T152).

### Interfaces Go

```go
package toolexec // internal/validate/toolexec (linux)

// Level is the isolation level of a run (ADR 0015 D1): LevelFull, or empty
// when the kernel does not offer it.
type Level string

const LevelFull Level = "full"

// Isolation is what Probe measured once per process, by a real helper run.
type Isolation struct {
	Level       Level  // LevelFull, or "" when unavailable
	LandlockABI int    // 0 when Landlock is absent (D7)
	Reason      string // fixed text when Level is ""
}

// Probe runs the helper once in probe mode (namespaces and tree, no exec)
// and caches the result for the process.
func Probe(ctx context.Context) Isolation

var (
	ErrIsolationUnavailable = errors.New("toolexec: tool isolation unavailable") // before any process
	ErrIsolationSetup       = errors.New("toolexec: tool isolation setup failed") // helper failure, fixed code
)

// MaybeHelper must be the first statement of main and TestMain in every
// binary that links toolexec (rule toolexec-helper-first). In the helper
// process it builds the tree of the tool and executes it, never returning;
// elsewhere it returns at once.
func MaybeHelper()

// Spec gains two fields; the others are unchanged.
type Spec struct {
	// ...
	WriteData bool     // data/ writable: OpenTofu runs only; tree/ is always read-only (D5)
	ReadOnly  []string // extra read-only directories (private toolchain copy), rules of D11
}

// Result gains the isolation of the run.
type Result struct {
	ExitCode       int
	Stdout, Stderr []byte
	Isolation      Isolation
}

// DataDir is data/ of the workspace (TF_DATA_DIR, plan files).
func (w *Workspace) DataDir() string

package validate
// ReadOnlyRoots is the private copy (binaries, plugins, mirror), for Spec.ReadOnly.
func (tc *Toolchain) ReadOnlyRoots() []string

package domain // internal/validate/domain (M3-T03)
const CodeToolIsolationUnavailable = "TOOL_ISOLATION_UNAVAILABLE" // critical
// Report gains Isolation {Level, LandlockABI}.
```

### Flux d'une exécution
1. La chaîne appelle `Run(ctx, spec)`.
2. `check(spec)`, avec les contrôles de D11, puis `verify` du binaire (D15 de l'ADR 0014), puis `Probe` (en cache). Sans niveau complet : `ErrIsolationUnavailable`, aucun processus.
3. `PR_SET_DUMPABLE=0`, répertoires éphémères `HOME` et `TMPDIR`, tubes des descripteurs 3 et 4.
4. Sur une goroutine verrouillée : `exec.Cmd` vers `/proc/self/exe`, avec `Cloneflags`, les correspondances, `Setsid` et `Pdeathsig`. Puis `Start`, écriture de la configuration, attente du « prêt », puis de la fin de fichier (exec réussi) ou d'un code (échec).
5. L'assistant monte l'arbre, fait `pivot_root`, durcit, applique Landlock, puis l'exec de l'outil, qui devient PID 1.
6. Le parent lit des sorties bornées. Au délai ou à la borne, `SIGKILL` sur `-pid` tue l'espace. Puis `Wait`, et suppression des répertoires éphémères.
7. `Result{..., Isolation}` remonte à la chaîne, puis à `Report.Isolation`.

## Conséquences
- **Positives** :
  - T157 fermée point par point (P1 à P13) partout où l'isolation complète existe ;
  - l'espace réseau rend la coupure effective, ce qui ferme le risque résiduel 1 de l'ADR 0014 (mandataire seulement déclaratif) ;
  - isolation entre tenants au niveau de l'outil, testée ;
  - aucune dépendance ; un seul mécanisme, testé dans la session et en CI ;
  - (hn) soldée, (ho) réduite ;
  - base réutilisable pour le runner (M4).
- **Négatives** :
  - code de sécurité propre (l'assistant), à relire avec soin (T161) ;
  - la CI exige une levée de restriction sur le runner (Q4) ; le poste WSL2 reste à vérifier (Q3) ;
  - un conteneur de worker au profil seccomp par défaut ne démarre pas (Q5) ;
  - surcoût par exécution, à mesurer ;
  - chaque binaire qui lie `toolexec` doit appeler `MaybeHelper` ;
  - les tests d'isolation sautent là où le mécanisme manque, sauf avec la variable ;
  - un outil qui voudrait écrire dans `tree/` exigera un amendement.
- **Difficile à changer** :
  - le protocole de l'assistant (marqueur, descripteurs 3 et 4, poignée de main) ;
  - la liste fermée de D5 ;
  - la règle `toolexec-helper-first` ;
  - l'exigence d'espaces de noms utilisateur pour tout lanceur d'outils, qui devient une contrainte du déploiement de M4.

## Impact sécurité : rattachement

| Décision | Menaces |
|---|---|
| D1, D3 | T157 (P3 à P5, P12), T8, T22 |
| D2 | T157 (P1, P13), T17 |
| D4, D6 | T157, T161 |
| D5 | T157 (P2, P6 à P11), T3, T159, (hn) |
| D7 | T157 (renfort), T161 |
| D8 | T157 (P3), T143 (mode opératoire Trivy), T24 (résidu) |
| D9 | T8, T145, T162 |
| D11, D12 | T162, T8 |
| D13 | T157, T158 ((ho)) |

## Risques résiduels
1. **Surface noyau des espaces de noms utilisateur** : c'est un vecteur fréquent d'élévation locale, et la raison de la restriction d'Ubuntu. Parades : `max_user_namespaces=0` dans l'espace de l'outil (si le prototype le confirme), capacités perdues à l'exec, `no_new_privs`, Landlock, noyau à jour ; seccomp en M4 (T161).
2. **Ressources non bornées** jusqu'en M4 (mémoire, processus, disque de `data/`) (T24).
3. **Sortie de l'outil** : c'est le seul canal restant, borné, échappé et jamais lu par une décision (D6 de l'ADR 0014, T145). L'outil lit l'IaC du tenant, c'est son travail ; elle ne contient pas de secret (D5 de l'ADR 0014).
4. **Processus du même uid hors isolation** (shell, autres programmes) : hors périmètre, car l'attaquant est déjà présent.
5. **Plan réel de `sandbox.sh`** hors de l'isolation complète (D14).
6. **Landlock absent ou ABI faible** : la couche de renfort manque, ce que le rapport signale.
7. **Fenêtre entre `verify` et l'exec** : elle reste ouverte pour un processus du même uid hors isolation ((hi)), mais elle est fermée pour les outils, faute d'accès en écriture. L'exec du descripteur haché reste possible plus tard.

## Mesure du prototype (à compléter avant l'acceptation, étape 0 de M3-T02b)
Protocole :
- copie de travail jetable, rien dans le dépôt ;
- assistant minimal, dans la session, en uid 0 puis en uid 65534 par `setpriv` ;
- outils du verrou, réseau absent.

| Mesure | Attendu | Valeur |
|---|---|---|
| `tofu init` sur le miroir privé, `validate`, `plan` hors ligne d'une racine AWS, dans l'isolation complète | code 0 | **code 0** pour les trois. `init` en 5,8 s, `validate` en 2,1 s, `plan -out` en 2,5 s ; `show -json` rend les 8 ressources attendues, dont `aws_iam_user.injected`. Arbre en lecture seule, aucun `.terraform/` écrit dedans |
| `tflint` avec les rulesets de la copie privée | code 0 ou 2 (findings) | **code 2** : un finding `terraform_required_version`, identique à l'exécution directe ; le ruleset AWS est chargé |
| `trivy config` sur règles embarquées | code 0 | **code 0** (`--skip-check-update`, cache dans `TMPDIR`) |
| montages nécessaires au-delà de D5 | aucun | **aucun** pour les trois outils. Deux conséquences sur l'usage : `plan -out` vise `data/`, puisque l'arbre est en lecture seule ; la configuration de tflint est passée par `--config` depuis une entrée en lecture seule, jamais un `.tflint.hcl` de l'arbre (D7 de l'ADR 0014) |
| `lo` levé nécessaire (H6) | non | **non** : providers d'OpenTofu et plugins de tflint passent par des sockets Unix dans `TMPDIR` |
| `subset=pid` admis | oui (noyau 6.18) | **oui** : `/proc` ne montre que `1`, `self` et `thread-self` |
| `max_user_namespaces=0` posé dans l'espace de l'outil, puis `unshare -U` refusé dans l'outil | oui | **oui**, en uid 0 comme en uid 65534 : `unshare: No space left on device`. À poser avant le montage de `/proc` en `subset=pid`, qui masque `/proc/sys` |
| connexion à une socket Unix nommée depuis un processus restreint par Landlock seul (H4) | réussie à l'ABI 7 | **réussie** : sous un domaine qui refuse tous les droits du système de fichiers (création de fichier refusée), `connect()` aboutit. H4 est confirmée : (b) ne ferme pas P8 |
| exec par `execveat(AT_EMPTY_PATH)` d'un `memfd` scellé depuis l'espace de montage de l'assistant ((ht)), et surcoût de la copie d'OpenTofu | réussi, moins de 100 ms | **réussi pour OpenTofu et Trivy, échec pour tflint**, qui se relance lui-même par `os.Executable()` pour son ruleset intégré (`fork/exec /memfd:tool: no such file or directory`). Monter le `memfd` par `bind` est refusé par le noyau (`EINVAL`). **Variante retenue, réussie pour les trois outils** : l'assistant copie le `memfd` scellé dans un tmpfs de l'espace de montage de l'outil, monté sur le répertoire de l'outil puis remonté en lecture seule. Le chemin est stable et le contenu est celui qui a été vérifié. Copie en 23 ms (tflint, 53 Mio), 41 ms (OpenTofu, 108 Mio), 73 ms (Trivy, 167 Mio), plus la copie du parent dans le `memfd`. Mémoire : environ deux fois la taille du binaire pendant l'exécution |
| surcoût médian par exécution (assistant compris) | moins de 50 ms | **1,8 ms** (`/usr/bin/true`, médiane sur 25 exécutions : 2,3 ms en direct, 4,1 ms isolé), hors copie du binaire |
| `go version -m <binaire> \| grep -c 'golang.org/x/sys'` pour `rempart` et `rempart-worker` (D10) | à mesurer | **1** pour chacun : `x/sys` est déjà lié, donc son import direct par `toolexec` n'ajoute aucun module |

Conditions : prototype jetable de 300 lignes de Go, hors dépôt, dans la session ; outils du verrou ; réseau absent. La chaîne complète d'outils a tourné en uid 0 (cache sous `/root`). En uid 65534 par `setpriv`, ont été vérifiés : `id` (uid 1000), capacités effectives et ensemble limitant nuls, `tofu version` par la copie du `memfd`, `/proc` réduit aux processus de l'outil, `kill -9 -1` sans effet sur un processus de l'hôte du même uid, espace imbriqué refusé. La chaîne complète en uid non privilégié est le critère 4 de M3-T02b.

### Constats du prototype, qui amendent D2 à D4 (à l'acceptation)
- **F10. `PR_SET_DUMPABLE` contre la re-exécution.** En uid non privilégié, un lanceur dont `PR_SET_DUMPABLE` vaut 0 ne peut plus se relancer par `/proc/self/exe` : `fork/exec /proc/self/exe: permission denied`, mesuré en uid 65534 ; root n'est pas touché, d'où la nécessité du critère 4. Parade mesurée, qui amende D2 : le lanceur repasse à 1 sous un verrou le seul temps de `Start`, puis revient à 0 (vérifié : `PR_GET_DUMPABLE` vaut 0 juste après). Pendant cette fenêtre, aucun outil ne voit le lanceur, puisque l'espace PID et son `/proc` (D3, D5) ferment P1 à eux seuls ; `PR_SET_DUMPABLE=0` reste une défense en profondeur contre les autres processus.
- **F11. Capacités de l'assistant.** L'assistant tourne sous l'uid interne 1000. Il perdrait ses capacités à sa propre exec, et ne pourrait alors plus monter (`EPERM` mesuré). Amendement de D3 et D4 : le lanceur lui donne en capacités ambiantes (`SysProcAttr.AmbientCaps`) `CAP_SETPCAP`, `CAP_SYS_ADMIN` et `CAP_SYS_RESOURCE`. L'assistant efface ensuite, avant l'exec de l'outil, les capacités ambiantes, l'ensemble limitant **et l'ensemble héritable**. Le prototype laissait l'ensemble héritable non nul, sans effet mais à effacer. Mesuré dans l'outil : `CapEff`, `CapBnd`, `CapAmb` nuls.
- **F12. Remontage en lecture seule dans un espace utilisateur.** Il doit reprendre les options verrouillées de la source (`noexec`, options d'horodatage), lues par `statfs`, sinon il est refusé. Le prototype le fait ; la mise en œuvre le teste.
- **(ht)** : la variante retenue (copie du `memfd` scellé dans un tmpfs privé de l'outil) remplace, dans D4 et D5, le montage en lecture seule du répertoire de l'outil. Un outil qui se relance lui-même (tflint) garde un chemin valide, et une réécriture de la copie privée entre la vérification et l'exec n'a plus d'effet.

## Vérifications (critères de M3-T02b, puis compléments de M3-T03 et M3-T08)
Sauf mention, dans la session de l'agent.

1. `REMPART_REQUIRE_SANDBOX=1 go test ./internal/validate/toolexec/ -v 2>&1 | grep -Ec -- '^--- PASS: TestIsolation(Probe|FailsClosed|LauncherNotDumpable|KillsEscapedDescendants|NoNetwork|FilesystemClosed|PrivateCopiesReadOnly|HidesProcesses|ParallelRunsSeparated|NoTerminal|LandlockLayer) '` : `11`.
2. `REMPART_REQUIRE_SANDBOX=1 go test ./internal/validate/toolexec/ -v 2>&1 | grep -Ec -- '^[[:space:]]*--- SKIP'` : `0`.
3. `REMPART_REQUIRE_SANDBOX=1 go test ./internal/validate/toolexec/ -v 2>&1 | grep -Ec -- '^--- PASS: TestToolexec(NoShell|EnvBuilt|Workspace|Checksum|Bounds) '` : `5`.
4. Chemin non privilégié (H0), avec `setpriv` d'util-linux :
   `d=$(mktemp -d) && t=$(mktemp -d) && chmod 755 "$d" && chown 65534:65534 "$t" && go test -c -o "$d/toolexec.test" ./internal/validate/toolexec && setpriv --reuid=65534 --regid=65534 --clear-groups env -i TMPDIR="$t" REMPART_REQUIRE_SANDBOX=1 "$d/toolexec.test" -test.run '^TestIsolation' -test.v 2>&1 | grep -Ec -- '^--- PASS: TestIsolation'` : `11`.
   La même commande, terminée par `grep -Ec -- '^[[:space:]]*--- (FAIL|SKIP)'`, rend `0`.
5. Sans mécanisme, sur toute machine et sans variable : `go test ./internal/validate/toolexec/ -run TestIsolationFailsClosed -v 2>&1 | grep -c '^--- PASS: TestIsolationFailsClosed '` : `1`.
6. `go test ./internal/archtest/ -run 'Test(ExecConfined|IsolationConfined|ToolexecHelperFirst)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(ExecConfined|IsolationConfined|ToolexecHelperFirst) '` : `3`.
7. Avec les outils, OpenTofu dans l'isolation complète : `REMPART_REQUIRE_SANDBOX=1 go test -tags=integration ./internal/validate/... -run 'Test(OfflineInitFromMirror|OfflinePlanProbe|OfflineInitRefusesPlantedPackage)$' -v 2>&1 | grep -Ec -- '^--- PASS: Test(OfflineInitFromMirror|OfflinePlanProbe|OfflineInitRefusesPlantedPackage) '` : `3`.
8. (ho) : `go test ./internal/archtest/ -run TestIaCToolsScriptRefusesTraversal -v 2>&1 | grep -Ec -- '^[[:space:]]*--- PASS: TestIaCToolsScriptRefusesTraversal/planted_link_after_makedirs '` : `1`.
9. Aucun module ajouté (D10) : `go list -m all | wc -l` rend la valeur consignée dans `docs/STATUS.md` au début de la tâche.
10. `test -f docs/proposals/0014-ci-isolation-outils.md && grep -c 'REMPART_REQUIRE_SANDBOX' docs/SETUP.md` : au moins `1`.
11. `make -f Makefile verify-quick; echo rc=$?` : `rc=0`, sans outil IaC installé.
12. M3-T03 :
    - `go test ./cmd/rempart/... -run TestCheckRefusesWithoutIsolation -v 2>&1 | grep -c '^--- PASS: TestCheckRefusesWithoutIsolation '` : `1`. Le refus est prouvé par le port d'exécution de la chaîne, jamais par un commutateur global de `toolexec` ;
    - avec les outils : `go run ./cmd/rempart check --json internal/validate/testdata/good | jq -e '.isolation.level == "full"'` : `true`.
13. M3-T08 : `go test ./cmd/rempart-worker/... -run TestWorkerRequiresIsolation -v 2>&1 | grep -c '^--- PASS: TestWorkerRequiresIsolation '` : `1`.

## Recommandation et ordre de mise en œuvre

**Recommandation** :
- option (c), avec le socle S et Landlock en renfort ;
- niveau complet exigé partout, échec fermé, aucun mode dégradé en M3 ;
- portée par une tâche nouvelle, **M3-T02b `tool-isolation`** (taille M), insérée entre M3-T02 et M3-T03. M3-T03 en dépend, et la revue `security-reviewer` de M3-T02b (PASS) précède tout câblage.

Fiche à insérer dans `docs/plans/M3-overview.md` à l'acceptation :
- **Objectif** : aucun outil de la chaîne ne voit les processus, fichiers, sockets, réseau ou terminal de son lanceur, d'un autre outil ou d'un autre tenant ; échec fermé.
- **Dépend de** : T02 ; ADR 0015 accepté après la mesure du prototype.
- **Livrables** :
  - `internal/validate/toolexec` : socle, assistant, arbre, Landlock, `Probe`, `MaybeHelper`, `Spec.WriteData`, `Spec.ReadOnly`, `Result.Isolation`, `Workspace.DataDir` ;
  - `Toolchain.ReadOnlyRoots` ;
  - règles `isolation-confined` et `toolexec-helper-first` ;
  - correctif (ho) de `scripts/iac-tools.sh` ;
  - `docs/SETUP.md`, section « Isolation des outils » (prérequis, commandes de H2) ;
  - proposition `docs/proposals/0014-ci-isolation-outils.md` ;
  - T8 et T157 mises à jour, soumises à `security-reviewer`.
- **Tests clés** : les 11 `TestIsolation*`, `TestIsolationConfined`, `TestToolexecHelperFirst`, le sous-cas (ho).
- **Acceptation** : vérifications 1 à 11.
- **Sécurité** : oui (T8, T143, T157, T3, T161, T162).

Tâches ordonnées, chacune d'un cycle tests puis impl :
0. **Prototype et mesure** (hors dépôt, hors phase) : section « Mesure du prototype » ; acceptation de l'ADR par l'humain.
1. **Socle S** :
   - `PR_SET_DUMPABLE=0` dans `Run`, `Setsid`, goroutine verrouillée avec `Pdeathsig` ;
   - `TestIsolationLauncherNotDumpable`, `TestIsolationNoTerminal` (`tty_nr` nul) ;
   - `TestToolexec*` inchangés et verts.
2. **Assistant et espaces de noms**, sans montage :
   - `MaybeHelper`, descripteurs 3 et 4, poignée de main, `Cloneflags` et correspondances (D3), `Probe` par essai réel, `ErrIsolationUnavailable`, `ErrIsolationSetup` ;
   - `TestMain` de `toolexec`, règle `toolexec-helper-first` ;
   - `TestIsolationProbe`, `TestIsolationFailsClosed`, `TestIsolationKillsEscapedDescendants`, `TestIsolationNoNetwork` (TCP, UDP, socket abstraite, relais).
3. **Arbre de l'outil** :
   - D5 et D6, contrôles de D11 dans `check`, règle `isolation-confined`, `Toolchain.ReadOnlyRoots` ;
   - `TestIsolationFilesystemClosed`, `TestIsolationPrivateCopiesReadOnly`, `TestIsolationHidesProcesses`, `TestIsolationParallelRunsSeparated`, sous-cas `unix_pathname` ;
   - test modifié `TestToolexecNoShell` (marqueurs dans `data/`) ;
   - tests d'intégration sous isolation (vérification 7).
4. **Couche Landlock** : D7, `Isolation.LandlockABI` ; `TestIsolationLandlockLayer`. Le code d'erreur d'un `connect` TCP vaut `EACCES` sous Landlock, contre `ENETUNREACH` sans lui ; le test saute sous l'ABI 4.
5. **(ho)** : `iac-tools.sh` et le sous-cas de `TestIaCToolsScriptRefusesTraversal`.
6. **Documentation et revue** :
   - `docs/SETUP.md`, proposition 0014, `docs/STATUS.md` ((hg), (hn), (ho) soldées sous réserve) ;
   - T8, T157, T161, T162 proposées ;
   - revue `security-reviewer`, une passe, PASS exigé.

Puis :
- **M3-T03** : D9 pour la chaîne, `rempart check`, `Report.Isolation`, `validate.sh` qui délègue à `rempart check` ; vérification 12.
- **M3-T08** : D9 pour le worker ; vérification 13.
- **M4** : Q5, bornes de ressources, seccomp, profil réseau du runner.

## Questions à l'humain
1. **Option (c)**, assistant écrit dans Rempart, sans dépendance, plutôt que (d), bubblewrap hors du modèle du verrou ? Recommandation : **oui**.
2. **Aucun mode dégradé en M3** : sans isolation complète, les étages outillés échouent fermés et seul `rempart check --static` reste utilisable. Si la sonde WSL2 (question 3) montre que les espaces de noms manquent, active-les plutôt que d'admettre un mode « Landlock seul », dont le résidu inclut la socket Docker (root) et le bus D-Bus de session. Recommandation : **oui**.
3. **Sonde du poste WSL2 (H-isolation-probe)** : lancer les commandes de H2 et coller la sortie, avant le premier `rempart check` avec outils sur le poste (fin de M3-T03). Cette sonde ne bloque pas M3-T02b, qui se fait dans la session. Recommandation : **oui**.
4. **CI (proposition 0014, H-CI-3)** :
   - une étape lève la restriction AppArmor sur le runner éphémère (`sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0`) et affiche le diagnostic de H1 ;
   - le job pose `REMPART_REQUIRE_SANDBOX=1`.
   Un profil AppArmor par chemin est écarté : les binaires de test changent de chemin à chaque compilation. Sans cette proposition, la CI saute les tests d'isolation (visible, jamais vert vide). Recommandation : **oui**.
5. **Production** : le worker refuse de démarrer sans isolation complète. Le choix entre un profil seccomp qui admet les espaces de noms dans le conteneur du worker et un pod d'outils distinct revient à l'ADR de déploiement de M4. Recommandation : **oui**.
6. **`tree/` en lecture seule pour tous les outils**, `data/` inscriptible pour OpenTofu seulement. Un outil qui écrirait dans l'arbre amende cet ADR. Recommandation : **oui**.

## Écarts avec l'ADR 0014 (amendements appliqués après l'acceptation de cet ADR)
- **E1. D6, « Un seul exécutant »** : inchangé. Le processus que lance `Run` est l'assistant, le binaire Rempart lui-même, qui fait l'exec de l'outil. `exec-confined` est inchangée, et complétée par `isolation-confined` et `toolexec-helper-first`.
- **E2. D6, « Conditions d'exécution »** :
  - ajouter « isolation complète obligatoire (ADR 0015, D1 à D8) » ;
  - « un délai tue le groupe de processus » devient « un délai tue l'espace PID de l'outil (`SIGKILL` sur son PID 1) » ;
  - `Setsid` remplace `Setpgid` ;
  - « répertoire de travail éphémère ouvert par `os.Root` » est complété par « `tree/` en lecture seule pour tout outil, `data/` inscriptible pour OpenTofu seulement ».
- **E3. D6, « Échec fermé »** : la liste gagne `TOOL_ISOLATION_UNAVAILABLE` (critique), qui mène à l'escalade `tool_unavailable` ; les codes de D18 sont inchangés.
- **E4. D6, étage 6** : le parallélisme de tflint, Checkov et Trivy est inchangé. Chaque outil a son propre espace et son arbre en lecture seule (P11).
- **E5. D6, « Parité avec le script du skill »** : `scripts/validate.sh` ne lance plus d'outil et appelle `rempart check --json`. La parité porte sur la normalisation. L'amendement 4 de l'ADR 0014 est modifié en conséquence ; c'est une modification de skill, signalée dans `docs/STATUS.md`.
- **E6. D6, « Findings »** : `Report` gagne `Isolation` (niveau, ABI Landlock).
- **Hors D6, même ADR** :
  - **D8** : l'espace réseau arrive en M3 pour tous les contextes, plus seulement « en production (M4) ». Le mandataire reste en seconde barrière. Le risque résiduel 1 est fermé là où l'isolation complète existe ;
  - **D18** : `prctl(PR_SET_DUMPABLE, 0)` passe du worker dans `toolexec.Run`. Le worker appelle `Probe` au démarrage et s'arrête sans niveau complet ;
  - **risque résiduel 2** : « utilisateur distinct ou bac à sable en production » est livré en M3 comme bac à sable ; reste la configuration du conteneur (Q5).
- **Écart au texte de (hg)** : « cgroup » est remplacé par l'espace PID (F3, D8). « Système de fichiers en lecture seule hors du répertoire de travail » est remplacé par « invisible hors d'une liste fermée » (D5), car la lecture seule laissait P2 ouvert.
- **Écarts au plan M3** :
  - M3-T02b est insérée dans les sections 0, 5 et 9 ; M3-T03 dépend de M3-T02b ;
  - étapes humaines H-isolation-probe (question 3) et H-CI-3 (proposition 0014) ajoutées à la section 10 ;
  - `make module-test` (M3-T04) passe par `rempart`, pour que `tofu test` soit isolé.

## Menaces à compléter (insertion par M3-T02b, confirmée par `security-reviewer`)

### Menaces existantes
- **T157** :
  - texte complété par P7 à P13 ;
  - atténuations : socle S, espaces utilisateur, montage, réseau, PID, IPC, UTS et cgroup, arbre fermé par `pivot_root`, `/proc` de l'espace PID, `tree/` et copie privée en lecture seule, Landlock en renfort, échec fermé ;
  - vérification : les 11 `TestIsolation*`, `TestIsolationConfined`, `TestToolexecHelperFirst` ;
  - (hn) soldée par D5 ; (ho) réduite et corrigée.
- **T8** : le résidu « l'environnement construit ne sépare pas l'outil de son lanceur » est remplacé par un renvoi à l'ADR 0015 ; vérification complétée.
- **T143** : le mode opératoire de l'incident Trivy est contenu. Un outil compromis ne lit ni l'environnement ni la mémoire d'un autre processus, ne survit pas à son exécution, ne joint aucun réseau.
- **T142** : le code exécuté à l'`init` ou au `plan` reste dans l'isolation de l'outil.
- **T17** : la mémoire du worker est hors de portée des outils (lanceur non « dumpable », espace PID).
- **T3** : l'isolation par tenant est prouvée au niveau de l'outil (`TestIsolationParallelRunsSeparated`).
- **T22** : aucune requête des outils vers le réseau interne (espace réseau vide).
- **T24** : le résidu est écrit : mémoire, processus et disque de `data/` ne sont pas bornés avant M4.
- **T159** : chemins de l'environnement construit couverts par un montage en lecture seule (D11).
- **Section 4.2, second point** : la révision de T8 est formalisée par cet ADR.

### Menaces nouvelles proposées (numéros provisoires)

| # | Menace | Cat. | Atténuations | Vérification |
|---|---|---|---|---|
| T161 | Faille du mécanisme d'isolation lui-même : montage oublié ou trop large, descripteur hérité, ancienne racine non détachée, binaire Rempart visible en écriture (leçon de CVE-2019-5736), configuration de l'assistant détournée ; surface noyau offerte par les espaces de noms utilisateur, dont un espace imbriqué créé par l'outil | E | Liste fermée sous CODEOWNERS et amendée par ADR ; détachement vérifié ; descripteurs fermés ; `no_new_privs` ; ensemble limitant vidé ; uid interne non nul ; `max_user_namespaces=0` dans l'espace de l'outil ; Landlock en renfort ; seccomp en M4 ; revue sécurité de chaque changement de `toolexec` | `TestIsolationFilesystemClosed` (racine en liste fermée), `TestIsolationHidesProcesses`, `TestIsolationLandlockLayer`, critère 4 (uid non privilégié) |
| T162 | Isolation désactivée ou affaiblie en silence : tests d'isolation sautés en CI, sonde trompée, binaire sans `MaybeHelper` (la re-exécution lance alors son `main` normal), mode dégradé posé par une variable sous injection | T, E | Échec fermé, aucun mode dégradé ; `REMPART_REQUIRE_SANDBOX=1` en CI (proposition 0014) ; poignée de main de l'assistant ; règle `toolexec-helper-first` ; niveau porté par chaque rapport ; refus de démarrage du worker | `TestIsolationFailsClosed`, `TestToolexecHelperFirst`, vérification 2, `TestWorkerRequiresIsolation` |
