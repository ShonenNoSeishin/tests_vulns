# <CVE ou nom> — <titre court en langage clair>

> Une ligne de gravité (CVSS, exploitation active, KEV) et une phrase sur qui est touché.

## En 30 secondes

| | |
|---|---|
| **Suis-je concerné ?** | <critère simple, vérifiable en une commande> |
| **Comment tester ?** | `<commande du script, lecture seule>` |
| **Comment corriger ?** | `<commande de mise à jour>` ; contournement : <…> |

## Ce qui se passe
Explication courte et concrète (qu'est-ce qui est cassé, comment c'est exploité, pourquoi ça compte), sans payload.

## Versions
| Composant | Vulnérable | Corrigé |
|---|---|---|

## 1. Tester
Commande, lecture du résultat (`[VULNÉRABLE]` / `[À VÉRIFIER]` / `[CORRIGÉ]` / `[NON CONCERNÉ]`), ligne « Confiance », codes de sortie 0/1/2.

## 2. Corriger
Une commande par cas (paquet, Docker, Windows…), redémarrage nécessaire ou non, contournement si la mise à jour doit attendre,
puis « relancer le script : la ligne doit passer à `[CORRIGÉ]` ».

## Limites
Ce que le script ne voit pas.

## Références
Avis officiel, tracker de la distribution, KEV.
