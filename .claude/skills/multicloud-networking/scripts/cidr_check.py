#!/usr/bin/env python3
"""Vérificateur CIDR de référence pour Rempart.

Entrée (JSON) :
{
  "superblock": "10.0.0.0/8",
  "networks": [
    {"name": "aws-euw3-prod", "cidr": "10.0.0.0/16"},
    {"name": "aws-euw3-prod-app-a", "cidr": "10.0.1.0/24", "parent": "aws-euw3-prod"}
  ],
  "external": [{"name": "onprem", "cidr": "192.168.0.0/16"}]
}

Sortie : findings au format normalisé (voir loop-engineering/references/normalized-findings.md).
Code retour : 0 si aucun finding, 1 sinon.

--selftest N : génère N plans aléatoires via un allocateur naïf correct et vérifie qu'aucun faux positif n'apparaît,
puis injecte des chevauchements et vérifie qu'ils sont tous détectés.
"""
import ipaddress
import json
import random
import sys


def finding(code, severity, resource, message):
    return {"code": code, "source": "cidr_check", "severity": severity, "resource": resource,
            "file": "", "line": 0, "message": message}


def check(plan: dict) -> list:
    out = []
    try:
        sb = ipaddress.ip_network(plan.get("superblock", "10.0.0.0/8"))
    except ValueError as e:
        return [finding("CIDR_INVALID", "critical", "superblock", str(e))]

    nets = {}
    for n in plan.get("networks", []):
        try:
            nets[n["name"]] = (ipaddress.ip_network(n["cidr"]), n.get("parent"))
        except (ValueError, KeyError) as e:
            out.append(finding("CIDR_INVALID", "critical", n.get("name", "?"), f"CIDR invalide : {e}"))
    ext = []
    for e in plan.get("external", []):
        try:
            ext.append((e["name"], ipaddress.ip_network(e["cidr"])))
        except (ValueError, KeyError) as err:
            out.append(finding("CIDR_INVALID", "critical", e.get("name", "?"), str(err)))

    for name, (net, parent) in nets.items():
        if not net.is_private:
            out.append(finding("CIDR_NOT_PRIVATE", "high", name, f"{net} n'est pas une plage privée"))
        if parent is None:
            if not net.subnet_of(sb):
                out.append(finding("CIDR_OUTSIDE_SUPERBLOCK", "high", name, f"{net} hors du superbloc {sb}"))
        else:
            if parent not in nets:
                out.append(finding("CIDR_UNKNOWN_PARENT", "critical", name, f"parent inconnu : {parent}"))
            elif not net.subnet_of(nets[parent][0]):
                out.append(finding("CIDR_OUTSIDE_PARENT", "critical", name, f"{net} hors de son parent {nets[parent][0]}"))

    # Chevauchements entre frères (même parent, y compris racine) et avec les plages externes.
    names = sorted(nets)
    for i, a in enumerate(names):
        na, pa = nets[a]
        for b in names[i + 1:]:
            nb, pb = nets[b]
            if pa == pb and na.overlaps(nb):
                out.append(finding("CIDR_OVERLAP", "critical", f"{a}|{b}", f"{na} chevauche {nb}"))
        if pa is None:
            for en, enet in ext:
                if na.overlaps(enet):
                    out.append(finding("CIDR_OVERLAP_EXTERNAL", "critical", f"{a}|{en}", f"{na} chevauche la plage externe {enet}"))
    return out


def naive_allocate(rng: random.Random) -> dict:
    """Allocateur correct par construction : découpe séquentielle."""
    sb = ipaddress.ip_network("10.0.0.0/8")
    vpcs = list(sb.subnets(new_prefix=16))
    rng.shuffle(vpcs)
    plan = {"superblock": str(sb), "networks": [], "external": [{"name": "onprem", "cidr": "192.168.0.0/16"}]}
    for v in range(rng.randint(1, 6)):
        vpc = vpcs[v]
        vname = f"vpc{v}"
        plan["networks"].append({"name": vname, "cidr": str(vpc)})
        subs = list(vpc.subnets(new_prefix=rng.choice([20, 22, 24])))
        for s in range(rng.randint(1, min(8, len(subs)))):
            plan["networks"].append({"name": f"{vname}-s{s}", "cidr": str(subs[s]), "parent": vname})
    return plan


def selftest(n: int) -> int:
    rng = random.Random(42)
    fp = fn = 0
    for _ in range(n):
        plan = naive_allocate(rng)
        if check(plan):
            fp += 1
        # Injection d'un chevauchement entre frères
        bad = json.loads(json.dumps(plan))
        subs = [x for x in bad["networks"] if x.get("parent") == "vpc0"]
        bad["networks"].append({"name": "intrus", "cidr": subs[0]["cidr"], "parent": "vpc0"})
        if not any(f["code"] == "CIDR_OVERLAP" for f in check(bad)):
            fn += 1
    print(json.dumps({"cases": n, "false_positives": fp, "false_negatives": fn}))
    return 0 if fp == 0 and fn == 0 else 1


def main() -> int:
    if len(sys.argv) == 3 and sys.argv[1] == "--selftest":
        return selftest(int(sys.argv[2]))
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    with open(sys.argv[1]) as f:
        findings = check(json.load(f))
    print(json.dumps(findings, ensure_ascii=False, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
