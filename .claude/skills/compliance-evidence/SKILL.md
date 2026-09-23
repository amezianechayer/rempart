---
name: compliance-evidence
description: Dossiers de preuves signés par changement, journal append-only chaîné, conformité continue (NIS2, DORA, SecNumCloud, ISO 27001:2022, CIS), catalogue de contrôles sourcé, rapports et exports d'audit pour Rempart (boucles L4, L9). À utiliser pour tout travail sur internal/evidence, internal/compliance, compliance/catalog, les rapports ou les exports.
---

# Preuves et conformité

## Références
- Schéma du dossier de preuves : `references/evidence-bundle.schema.json`
- Format d'une entrée de catalogue de contrôles : `references/catalog-entry-example.yaml`

## Dossier de preuves (par changement)
Contenu défini par le schéma : intention, IR, hypothèses, graphe avant/après et diff, delta de menace, résultats de validation et de politiques (avec exceptions humaines justifiées), plan et son hash, rayon d'impact, risque, delta de coût, approbations, attestation du runner, vérifications post-déploiement, identifiants de trace.
- Sérialisation **JSON canonique** (clés triées, sans espaces) avant hachage et signature.
- Signature par clé de tenant (KMS) ; vérification possible hors ligne par l'auditeur avec la clé publique.
- **Journal append-only chaîné** : chaque entrée contient le hash de la précédente ; ancrage périodique du dernier hash (horodatage externe).
- Lien vers le dossier dans la PR.

## Conformité continue
- Catalogue `compliance/catalog/<framework>.yaml` : contrôles, exigences techniques couvertes, politiques associées (`control_id`), type de preuve attendu, **source officielle, version, date de revue**.
- Distinguer contrôles **techniques** (couverts) et **organisationnels** (listés hors périmètre, jamais présentés comme couverts).
- Rapport par référentiel : statut par contrôle, preuves horodatées, ressources non conformes, historique. Export PDF lisible et archive JSON vérifiable.

## Exactitude réglementaire
Ne jamais inventer une référence. Textes de base à consulter à la source : directive NIS2 (UE) 2022/2555 et ses actes d'exécution, règlement DORA (UE) 2022/2554 et ses normes techniques, référentiel SecNumCloud de l'ANSSI (version en vigueur), ISO/IEC 27001:2022, CIS Benchmarks. En cas de doute : tâche de vérification humaine.
