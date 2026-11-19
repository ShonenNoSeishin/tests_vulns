# EXEMPLE de `company-profile.md`

> **Ceci est un modèle, pas le vrai fichier.** Le `company-profile.md` réel décrit un parc
> machines précis et reste **toujours privé** (jamais dans ce dépôt, voir `CLAUDE.md`). Ce fichier
> montre juste la forme attendue par les commandes `.claude/commands/veille-hebdo.md` et
> `.claude/commands/deep-dive-vuln.md`, pour que quelqu'un qui fork ce dépôt puisse reproduire le
> workflow avec son propre contexte.
>
> Pour reproduire : copier ce fichier vers `~/ir-context/company-profile.md` (ou l'emplacement
> adapté à votre installation — les commandes utilisent un chemin absolu, à ajuster selon votre
> système), puis le remplir avec votre propre parc.

## Activité

Décrivez votre activité en une phrase et la priorité générale de la veille (ex. : exploitabilité
à distance sans authentification, failles d'évasion/élévation sur un composant partagé entre
plusieurs clients...).

## Parc machines (exemple)

- **Produit A** (ex. PBX/VoIP, ERP...) — ce qu'il faut surveiller en particulier.
- **OS serveur** — versions en service, et tout mécanisme de rétroportage de sécurité à connaître
  (ex. Ubuntu LTS, Debian, Windows Server...).
- **Virtualisation / stockage partagé** — tout composant dont une faille impacterait plusieurs
  clients à la fois (hyperviseur, stockage distribué...) : à traiter en priorité absolue.
- **Équipements de périmètre** — pare-feux, VPN, équipements d'administration centralisée
  (souvent la porte d'entrée n°1 des attaques réelles).

## DNS / registrars / CDN — points d'intérêt (exemple)

Fournisseurs dont les plages IP publiques doivent être tenues à jour pour vos règles de
pare-feu (whitelists), stockées dans un fichier équivalent à `ir-context/veille/ip-ranges-dns.md`.

## Priorisation pour la veille hebdomadaire (exemple)

1. Composant partagé critique (hyperviseur/stockage)
2. Équipements de périmètre exposés sur Internet
3. Composant d'authentification central (ex. Active Directory)
4. Applications métier exposées
5. Reste du parc
6. Hors parc — seulement si CVSS ≥ 7 ou présence au catalogue KEV CISA

## Ne jamais mettre dans le repo public

Le nom de l'organisation, les hostnames/IP internes, les numéros de version précis par client, et
ce fichier lui-même (ou tout extrait de son contenu).
