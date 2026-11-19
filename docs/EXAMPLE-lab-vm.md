# EXEMPLE de `lab-vm.md`

> **Ceci est un modèle, pas le vrai fichier.** Le `lab-vm.md` réel décrit la machine précise sur
> laquelle tournent les sessions de `/deep-dive-vuln` et reste **toujours privé**. Ce fichier
> montre juste la forme attendue, pour reproduire le workflow avec votre propre machine de labo.
>
> Pour reproduire : copier vers `~/ir-context/lab-vm.md` (chemin à ajuster selon votre
> installation), puis décrire votre propre machine.

## Identité

- Hostname, OS/version.
- Utilisateur courant.
- Moteur de conteneurs présent (Docker/Podman) et **inventaire de ce qui y tourne déjà** : des
  services personnels/projets en cours ne doivent jamais être confondus avec une cible de test
  posée exprès pour une faille donnée.
- Quels composants du parc décrit dans `company-profile.md` sont *réellement* présents sur cette
  machine (souvent : aucun directement — c'est un poste de travail, pas un miroir du parc client).

## Règle pour les deep-dive

Avant toute tentative d'exploitation sur cette VM :

1. Vérifier qu'aucun service existant de la liste ci-dessus ne sera perturbé.
2. Monter l'environnement de test **dans un conteneur/VM jetable isolé**, jamais directement sur
   l'hôte, sauf si la faille elle-même ne peut être démontrée que sur l'hôte (ex. faille noyau) —
   dans ce cas, demander confirmation explicite avant d'agir.
3. Documenter le résultat dans le dossier privé de la faille — jamais dans le dépôt public.

À mettre à jour si la VM change de rôle ou si des services supplémentaires y sont montés
spécifiquement pour les tests de sécurité.
