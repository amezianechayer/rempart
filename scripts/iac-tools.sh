#!/usr/bin/env bash
# Chaîne d'outils IaC de Rempart (ADR 0014 D15, menaces T6 et T143).
# Usage : bash scripts/iac-tools.sh install|verify|mirror|env
#   install : outils, rulesets tflint et providers du verrou, téléchargés et vérifiés dans le cache
#   mirror  : providers seulement (miroir fichier d'OpenTofu)
#   verify  : revérifie chaque binaire et chaque archive de provider du cache contre le verrou
#   env     : affiche la variable REMPART_IAC_CACHE à exporter
# Cache : REMPART_IAC_CACHE, sinon ~/.cache/rempart/iac-tools ; jamais dans le dépôt.
# Plateforme : linux_amd64 seulement. Codes : 0 succès, 1 vérification échouée, 2 usage ou plateforme.
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
repo="$(cd "$here/.." && pwd)"
case "$cache/" in
	"$repo"/*)
		echo "iac-tools : le cache ne peut pas être dans le dépôt ; aucune action." >&2
		exit 2
		;;
esac
if [ "$cmd" = env ]; then
	printf 'export REMPART_IAC_CACHE=%q\n' "$cache"
	exit 0
fi
mkdir -p "$cache"

exec python3 -I - "$cmd" "$lock" "$cache" <<'PY'
import hashlib, json, os, subprocess, sys, tarfile, tempfile, urllib.parse, zipfile

cmd, lock_path, cache = sys.argv[1:4]
HOSTS = {"github.com", "releases.hashicorp.com"}

def fail(msg, code=1):
    print("iac-tools : " + msg, file=sys.stderr)
    sys.exit(code)

with open(lock_path, encoding="utf-8") as f:
    lock = json.load(f)
if lock.get("lock_version") != 1 or lock.get("platform") != "linux_amd64":
    fail("verrou de version ou de plateforme inattendue", 2)

def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def regular(path):
    return os.path.isfile(path) and not os.path.islink(path)

def download(url, want):
    """The archive of url in dl/<sha256>/, downloaded once, checked by its hash."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or u.netloc not in HOSTS or u.username or u.query or u.fragment:
        fail("URL hors des hôtes du verrou : refus", 2)
    dest = os.path.join(cache, "dl", want, os.path.basename(u.path))
    if regular(dest) and sha256(dest) == want:
        return dest
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dest))
    os.close(fd)
    try:
        subprocess.run(["curl", "--proto", "=https", "--tlsv1.2", "-fsSL", "--max-time", "900", "-o", tmp, url], check=True)
        got = sha256(tmp)
        if got != want:
            fail("somme fausse pour " + os.path.basename(u.path) + " : refus")
        os.replace(tmp, dest)
    finally:
        if os.path.exists(tmp):
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

def provider_path(p):
    typ = p["source"].rsplit("/", 1)[1]
    return os.path.join(cache, "mirror", *p["source"].split("/"), "terraform-provider-%s_%s_linux_amd64.zip" % (typ, p["version"]))

def install_tool(t):
    dest = tool_path(t)
    if regular(dest) and sha256(dest) == t["binary_sha256"]:
        return
    data = extract(download(t["url"], t["sha256"]), t["archive"], t["binary"])
    if hashlib.sha256(data).hexdigest() != t["binary_sha256"]:
        fail("somme fausse pour le binaire " + t["name"] + " : refus")
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.exists(dest):
        os.chmod(dest, 0o700)
        os.unlink(dest)
    with open(dest, "xb") as f:
        f.write(data)
    os.chmod(dest, 0o500)
    print("iac-tools : %s %s installé" % (t["name"], t["version"]))

def install_provider(p):
    dest = provider_path(p)
    if regular(dest) and sha256(dest) == p["sha256"]:
        return
    src = download(p["url"], p["sha256"])
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(src, "rb") as i, open(dest + ".part", "wb") as o:
        o.write(i.read())
    if sha256(dest + ".part") != p["sha256"]:
        os.unlink(dest + ".part")
        fail("somme fausse pour " + p["source"] + " : refus")
    os.replace(dest + ".part", dest)
    print("iac-tools : provider %s %s dans le miroir" % (p["source"], p["version"]))

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
        if not regular(path) or sha256(path) != p["sha256"]:
            print("iac-tools : provider %s %s absent ou modifié" % (p["source"], p["version"]), file=sys.stderr)
            bad += 1
    if bad:
        fail("%d artefact(s) en échec ; lancer make -f Makefile iac-tools" % bad)
    print("iac-tools : %d outils et %d providers conformes au verrou" % (len(lock["tools"]), len(lock["providers"])))
PY
