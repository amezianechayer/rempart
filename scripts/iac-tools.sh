#!/usr/bin/env bash
# Chaîne d'outils IaC de Rempart (ADR 0014 D15, menaces T6, T143, T156 et T158).
# Usage : bash scripts/iac-tools.sh install|verify|mirror|env
#   install : outils, rulesets tflint et providers du verrou, téléchargés et vérifiés dans le cache
#   mirror  : providers seulement (miroir fichier d'OpenTofu)
#   verify  : revérifie chaque binaire et chaque archive de provider du cache contre le verrou
#             (SHA-256 et h1), et refuse toute entrée du miroir que le verrou ne nomme pas
#   env     : affiche la variable REMPART_IAC_CACHE à exporter
# Le verrou est relu sous sa grammaire fermée (celle de validate.LoadToolchain) avant toute
# écriture : aucun de ses champs ne peut mener une écriture hors du cache.
# Cache : REMPART_IAC_CACHE, sinon ~/.cache/rempart/iac-tools ; jamais dans le dépôt.
# Plateforme : linux_amd64 seulement. Codes : 0 succès, 1 vérification échouée, 2 usage, verrou ou plateforme.
set -euo pipefail
umask 077

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
lock="$here/iac-tools.lock.json"
cmd="${1:-}"
case "$cmd" in
	install | verify | mirror | env) ;;
	*)
		echo "usage : bash scripts/iac-tools.sh install|verify|mirror|env" >&2
		exit 2
		;;
esac
if [ "$(uname -s)" != Linux ] || [ "$(uname -m)" != x86_64 ]; then
	echo "iac-tools : plateforme non prise en charge (linux_amd64 seulement) ; aucune action." >&2
	exit 2
fi
cache="${REMPART_IAC_CACHE:-$HOME/.cache/rempart/iac-tools}"
case "$cache" in
	/*) ;;
	*)
		echo "iac-tools : REMPART_IAC_CACHE doit être un chemin absolu ; aucune action." >&2
		exit 2
		;;
esac
# Comparaison sur les chemins résolus : ni lien symbolique ni « .. » ne placent le cache dans le dépôt.
repo="$(realpath -e -- "$here/..")"
cache_real="$(realpath -m -- "$cache")"
case "$cache_real/" in
	"$repo"/*)
		echo "iac-tools : le cache ne peut pas être dans le dépôt ; aucune action." >&2
		exit 2
		;;
esac
if [ "$cmd" = env ]; then
	printf 'export REMPART_IAC_CACHE=%q\n' "$cache"
	exit 0
fi
mkdir -p -- "$cache_real"

exec python3 -I - "$cmd" "$lock" "$cache_real" <<'PY'
import base64, hashlib, json, os, posixpath, re, subprocess, sys, tarfile, tempfile, urllib.parse, zipfile

cmd, lock_path, cache = sys.argv[1:4]
HOSTS = {"github.com", "releases.hashicorp.com"}
MAX_ARCHIVE = 512 << 20  # octets ; la plus grosse archive du verrou fait 176 Mo

def fail(msg, code=1):
    print("iac-tools : " + msg, file=sys.stderr)
    sys.exit(code)

# Grammaire fermée du verrou, la même que validate.parseLock (Go) et
# l'archtest TestIaCToolsLockPinned : vérifiée avant toute écriture (T158).
SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
SHA256 = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-z][a-z0-9-]{0,62}")
PLUGIN = re.compile(r"github\.com/terraform-linters/tflint-ruleset-[a-z0-9]+")
SOURCE = re.compile(r"registry\.opentofu\.org/hashicorp/([a-z0-9-]+)")
H1 = re.compile(r"h1:[A-Za-z0-9+/]{43}=")
FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
REPOS = {
    "tofu": "opentofu/opentofu",
    "tflint": "terraform-linters/tflint",
    "tflint-ruleset-aws": "terraform-linters/tflint-ruleset-aws",
    "tflint-ruleset-azurerm": "terraform-linters/tflint-ruleset-azurerm",
    "trivy": "aquasecurity/trivy",
}
LOCK_KEYS = {"date", "hosts", "lock_version", "min_age_days", "platform", "providers", "tools"}
TOOL_KEYS = {"archive", "binary", "binary_sha256", "kind", "name", "published", "sha256", "signature", "url", "version"}
PROVIDER_KEYS = {"h1", "published", "sha256", "signature", "source", "url", "version"}

def refuse(what):
    fail("verrou refusé (%s) ; aucune action." % what, 2)

def full(rx, v):
    return isinstance(v, str) and rx.fullmatch(v) is not None

def no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        refuse("clé répétée")
    return dict(pairs)

def url_ok(raw, hosts):
    if not isinstance(raw, str):
        return False
    u = urllib.parse.urlsplit(raw)
    return (u.scheme == "https" and u.netloc in hosts and u.username is None and not u.query
            and not u.fragment and full(FILE, posixpath.basename(u.path)))

def check_lock(lock):
    if not isinstance(lock, dict) or set(lock) != LOCK_KEYS:
        refuse("clés")
    if type(lock["lock_version"]) is not int or lock["lock_version"] != 1 or lock["platform"] != "linux_amd64":
        refuse("version ou plateforme")
    hosts = lock["hosts"]
    if not isinstance(hosts, list) or not all(isinstance(h, str) and h in HOSTS for h in hosts):
        refuse("hôtes")
    hosts = set(hosts)
    if not isinstance(lock["tools"], list) or not isinstance(lock["providers"], list):
        refuse("listes")
    seen = set()
    for t in lock["tools"]:
        if not isinstance(t, dict):
            refuse("outil")
        plugin = t.get("kind") == "tflint-plugin"
        if set(t) != (TOOL_KEYS | {"plugin_source"} if plugin else TOOL_KEYS):
            refuse("clés d'un outil")
        name, version = t["name"], t["version"]
        if not full(NAME, name) or name in seen or name not in REPOS:
            refuse("nom d'outil")
        seen.add(name)
        if t["kind"] not in ("tool", "tflint-plugin"):
            refuse("type d'outil")
        if plugin and (not full(PLUGIN, t["plugin_source"]) or not t["plugin_source"].endswith("/" + name)):
            refuse("plugin_source")
        if not full(SEMVER, version):
            refuse("version d'outil")
        if not url_ok(t["url"], hosts) or not t["url"].startswith("https://github.com/%s/releases/download/v%s/" % (REPOS[name], version)):
            refuse("URL d'outil")
        if not full(SHA256, t["sha256"]) or not full(SHA256, t["binary_sha256"]):
            refuse("somme d'outil")
        if t["archive"] not in ("zip", "tar.gz") or not full(NAME, t["binary"]):
            refuse("archive ou binaire d'outil")
        if not isinstance(t["signature"], dict):
            refuse("signature d'outil")
    seen = set()
    for p in lock["providers"]:
        if not isinstance(p, dict) or set(p) != PROVIDER_KEYS:
            refuse("clés d'un provider")
        m = SOURCE.fullmatch(p["source"]) if isinstance(p["source"], str) else None
        if m is None or p["source"] in seen:
            refuse("source de provider")
        seen.add(p["source"])
        if not full(SEMVER, p["version"]) or not full(SHA256, p["sha256"]) or not full(H1, p["h1"]):
            refuse("version ou somme de provider")
        want = "https://releases.hashicorp.com/terraform-provider-%s/%s/%s" % (m.group(1), p["version"], provider_zip(p))
        if p["url"] != want or not url_ok(p["url"], hosts):
            refuse("URL de provider")
        if not isinstance(p["signature"], dict):
            refuse("signature de provider")

def provider_zip(p):
    return "terraform-provider-%s_%s_linux_amd64.zip" % (p["source"].rsplit("/", 1)[1], p["version"])

try:
    with open(lock_path, encoding="utf-8") as f:
        lock = json.load(f, object_pairs_hook=no_duplicates)
except (OSError, ValueError):
    refuse("lecture")
check_lock(lock)

# Le cache appartient à l'utilisateur et n'est inscriptible que par lui.
os.makedirs(cache, mode=0o700, exist_ok=True)
st = os.stat(cache)
if st.st_uid != os.geteuid() or st.st_mode & 0o022:
    fail("le cache appartient à un autre compte ou est inscriptible par d'autres ; aucune action.", 2)

def inside(path):
    """Refuses a path whose directory, resolved, is not inside the cache."""
    d = os.path.realpath(os.path.dirname(path))
    if not (d + os.sep).startswith(cache + os.sep):
        fail("chemin hors du cache : refus", 2)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def hash1_zip(path):
    """dirhash Hash1 of the members of the zip: the h1 hash OpenTofu checks."""
    with zipfile.ZipFile(path) as z:
        names = [i.filename for i in z.infolist()]
        if len(names) != len(set(names)) or any("\n" in n for n in names):
            return None
        summary = hashlib.sha256()
        for n in sorted(names):
            h = hashlib.sha256()
            with z.open(n) as f:
                for chunk in iter(lambda: f.read(1 << 20), b""):
                    h.update(chunk)
            summary.update(("%s  %s\n" % (h.hexdigest(), n)).encode())
    return "h1:" + base64.b64encode(summary.digest()).decode()

def regular(path):
    return os.path.isfile(path) and not os.path.islink(path)

def scratch():
    """A new file, created exclusively, in cache/tmp (never in the mirror)."""
    d = os.path.join(cache, "tmp")
    os.makedirs(d, mode=0o700, exist_ok=True)
    inside(os.path.join(d, "x"))
    return tempfile.mkstemp(dir=d)

def put(dest, write, mode):
    """Writes dest through a scratch file renamed over it: no link followed."""
    os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
    inside(dest)
    fd, tmp = scratch()
    try:
        with os.fdopen(fd, "wb") as f:
            write(f)
            os.fchmod(f.fileno(), mode)
        os.replace(tmp, dest)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)

def download(url, want):
    """The archive of url in dl/<sha256>/, downloaded once, checked by its hash."""
    dest = os.path.join(cache, "dl", want, posixpath.basename(urllib.parse.urlsplit(url).path))
    if regular(dest) and sha256(dest) == want:
        return dest
    os.makedirs(os.path.dirname(dest), mode=0o700, exist_ok=True)
    inside(dest)
    fd, tmp = scratch()
    os.close(fd)
    try:
        r = subprocess.run(["curl", "-q", "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "-fsSL",
                            "--max-time", "900", "--max-filesize", str(MAX_ARCHIVE), "-o", tmp, url])
        if r.returncode != 0:
            fail("téléchargement échoué pour " + posixpath.basename(url))
        if sha256(tmp) != want:
            fail("somme fausse pour " + posixpath.basename(url) + " : refus")
        os.replace(tmp, dest)
    finally:
        if os.path.lexists(tmp):
            os.unlink(tmp)
    return dest

def extract(archive, kind, member):
    """The bytes of the exact member of the archive: nothing else is extracted."""
    if kind == "zip":
        with zipfile.ZipFile(archive) as z:
            return z.read(member)
    with tarfile.open(archive, "r:gz") as t:
        info = t.getmember(member)
        if not info.isfile():
            fail("membre " + member + " non régulier : refus")
        return t.extractfile(info).read()

def tool_path(t):
    if t["kind"] == "tflint-plugin":
        return os.path.join(cache, "tflint-plugins", *t["plugin_source"].split("/"), t["version"], t["binary"])
    return os.path.join(cache, "tools", t["name"], t["version"], t["binary"])

def provider_rel(p):
    return p["source"] + "/" + provider_zip(p)

def provider_path(p):
    return os.path.join(cache, "mirror", *provider_rel(p).split("/"))

def install_tool(t):
    dest = tool_path(t)
    if regular(dest) and sha256(dest) == t["binary_sha256"]:
        return
    data = extract(download(t["url"], t["sha256"]), t["archive"], t["binary"])
    if hashlib.sha256(data).hexdigest() != t["binary_sha256"]:
        fail("somme fausse pour le binaire " + t["name"] + " : refus")
    put(dest, lambda f: f.write(data), 0o500)
    print("iac-tools : %s %s installé" % (t["name"], t["version"]))

def install_provider(p):
    dest = provider_path(p)
    if regular(dest) and sha256(dest) == p["sha256"]:
        return
    src = download(p["url"], p["sha256"])
    def copy(f):
        h = hashlib.sha256()
        with open(src, "rb") as i:
            for chunk in iter(lambda: i.read(1 << 20), b""):
                h.update(chunk)
                f.write(chunk)
        if h.hexdigest() != p["sha256"]:
            fail("somme fausse pour " + p["source"] + " : refus")
    put(dest, copy, 0o400)
    print("iac-tools : provider %s %s dans le miroir" % (p["source"], p["version"]))

def mirror_extras():
    """Entries of the mirror the lock does not name (T156): OpenTofu would read them."""
    root = os.path.join(cache, "mirror")
    files = {provider_rel(p) for p in lock["providers"]}
    dirs = {posixpath.dirname(f) for f in files}
    for f in list(dirs):
        while f:
            dirs.add(f)
            f = posixpath.dirname(f)
    extras = []
    def walk(d, rel):
        for e in os.scandir(d):
            r = rel + e.name
            if e.is_dir(follow_symlinks=False) and r in dirs:
                walk(e.path, r + "/")
            elif not (e.is_file(follow_symlinks=False) and r in files):
                extras.append(r)
    if os.path.isdir(root) and not os.path.islink(root):
        walk(root, "")
    elif os.path.lexists(root):
        extras.append("mirror")
    return extras

if cmd == "install":
    for t in lock["tools"]:
        install_tool(t)
if cmd in ("install", "mirror"):
    for p in lock["providers"]:
        install_provider(p)
if cmd == "verify":
    bad = 0
    for t in lock["tools"]:
        path = tool_path(t)
        if not regular(path) or sha256(path) != t["binary_sha256"]:
            print("iac-tools : %s %s absent ou modifié" % (t["name"], t["version"]), file=sys.stderr)
            bad += 1
    for p in lock["providers"]:
        path = provider_path(p)
        if not regular(path) or sha256(path) != p["sha256"] or hash1_zip(path) != p["h1"]:
            print("iac-tools : provider %s %s absent ou modifié" % (p["source"], p["version"]), file=sys.stderr)
            bad += 1
    for e in mirror_extras():
        print("iac-tools : entrée du miroir que le verrou ne nomme pas : %r (supprimer le cache et relancer)" % e, file=sys.stderr)
        bad += 1
    if bad:
        fail("%d artefact(s) en échec ; lancer make -f Makefile iac-tools" % bad)
    print("iac-tools : %d outils et %d providers conformes au verrou" % (len(lock["tools"]), len(lock["providers"])))
PY
