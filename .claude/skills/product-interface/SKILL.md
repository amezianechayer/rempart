---
name: product-interface
description: Conception et implémentation des interfaces de Rempart (application web Next.js, écrans E1 à E11, composants de preuve, CLI rempart, serveur MCP, commentaires de PR, notifications Slack/Teams, sécurité de l'interface, accessibilité, i18n, tests Playwright). À utiliser dès qu'une tâche touche web/, cmd/rempart, cmd/rempart-mcp, le format des commentaires de PR, les notifications ou l'API publique, même pour un petit ajustement d'écran.
---

# Interfaces de Rempart

La spécification complète est dans `docs/04-INTERFACE.md`. Lis la section de l'écran ou de la surface concernée avant toute tâche.

## Les sept principes, à vérifier sur chaque écran
1. La preuve avant la confiance : chaque chiffre ou statut mène à sa preuve en deux clics au plus.
2. Les faits d'abord : les faits calculés dans des composants structurés ; le texte du LLM dans le bloc « Explication générée », jamais à la place d'un fait.
3. Aucune action irréversible sans récapitulatif lié au hash du plan.
4. Le chemin plutôt que la liste pour les findings.
5. Calme par défaut : on sait en 10 secondes s'il y a une action urgente.
6. Deux niveaux de lecture : Résumé et Technique, sur les mêmes données.
7. Tout est faisable hors de l'interface : aucune action web sans équivalent API.

## Règles non négociables
- Chaînes issues du cloud : **texte brut échappé**, jamais de rendu HTML ou Markdown, marquées « Donnée issue du cloud ».
- Droits vérifiés côté serveur ; l'interface reflète, elle ne décide pas.
- Aucun bouton de fermeture manuelle d'un finding : seul un re-scan ferme.
- Approbations : réauthentification pour risque élevé, deux approbateurs dont un sécurité pour critique, auteur exclu.
- MCP et Slack ne peuvent jamais approuver au-delà du risque moyen ; MCP ne peut jamais appliquer.
- Information jamais portée par la couleur seule ; WCAG 2.2 AA ; clés i18n dès le premier composant.

## Qualité
- Composants dans Storybook, tests unitaires, Playwright sur les parcours E1, E3, E4, E5, E6, tests visuels, audit axe.
- Test de parcours des liens de preuve (critère 3 de la section 14).
- Test d'injection sur tous les écrans qui affichent des données cloud.
