# Format `vuln.yaml`

Chaque dossier de faille contient un `vuln.yaml` à côté de son `README.md` et de ses scripts. L'interface **IRM** le lit pour afficher la
faille (fil d'actualité, badge « nouveau », fiche guidée *Suis-je concerné ? → Tester → Corriger*, téléchargement des scripts). Les champs
sont volontairement simples ; seuls `id`, `title`, `severity`, `published` et `summary` sont obligatoires.

```yaml
id: nom-du-dossier                 # identique au nom du dossier
title: "Titre lisible"
cves: [CVE-2026-00000]
severity: critical                 # critical | high | medium | low
published: 2026-11-09              # date de divulgation / d'ajout ; sert au badge « Nouveau » (14 jours)
updated: 2026-11-12                # dernière mise à jour de l'article (badge « Mis à jour »)
exploited: true                    # exploitation active connue
kev: true                          # présente au catalogue CISA KEV
summary: >-
  Une ou deux phrases, en langage clair : ce qui est cassé, qui est touché, ce qu'il faut faire.
affects: ["Produit et versions", "Autre produit"]
tags: [ssh, alpine]
concerned: ["Cas où la machine est concernée"]
not_concerned: ["Cas où elle ne l'est pas"]
impact:                             # OBLIGATOIRE : statut sur CHAQUE solution du parc, voir ci-dessous
  - {product: "Proxmox VE", status: "impacted", note: "Composant touché directement"}
  - {product: "Veeam", status: "not_impacted"}
  - {product: "nginx", status: "to_check", note: "Dépend de la version installée, non vérifiée ici"}
tests:                             # scripts téléchargeables (fichiers du dossier uniquement)
  - os: linux                      # linux | windows | any
    label: "Linux (hôte + conteneurs)"
    file: test_x.sh
    run: "chmod +x test_x.sh && sudo ./test_x.sh --scan-images"
    note: "Texte facultatif"
results:                           # comment lire le résultat du script
  - {status: "VULNÉRABLE", meaning: "…", action: "…"}
fix:                               # corrections par cas, avec la commande à copier
  - {for: "Debian / Ubuntu", command: "apt update && apt upgrade"}
fixed_versions: "Texte libre"
docs: [README.md]                  # fichiers Markdown affichés dans l'article
references:
  - {title: "Avis éditeur", url: "https://…"}
```

Règles de contenu (dépôt public) : voir `CLAUDE.md` — pas de nom de société, d'hôte ou d'IP internes, pas de méthode d'exploitation, pas de secret.

## Champ `impact:` — matrice d'impact sur le parc (obligatoire depuis le 19/11/2026)

**Demande explicite de l'utilisateur** : chaque fiche doit déclarer explicitement l'impact sur
**toutes** les solutions suivies (liste tenue à jour dans la section correspondante du contexte
privé de veille — Proxmox, Docker, LXC, Veeam, Nakivo, 3CX, Elastix, Andrisoft WANGuard, Datalust
Seq, LibreNMS, Observium, Debian, Ubuntu, Windows 2012/2016/2019/2022/2025, SMB/SFTP sur Debian,
Cisco, Ubiquiti, HP/Aruba, FortiGate, FortiAnalyzer, FortiManager, Sophos, nginx, Certbot, Odoo,
Nextcloud, JumpCloud, Python, Django, React, PHP, et MikroTik/Ceph/QEMU-KVM déjà suivis par
ailleurs). **Jamais un sous-ensemble** : une entrée par solution, même quand le statut est
trivialement "non impacté".

```yaml
impact:
  - {product: "Nom exact de la solution", status: "impacted", note: "Pourquoi (facultatif)"}
```

- `status` : exactement `impacted` / `not_impacted` / `to_check` (jamais une variante). `to_check`
  quand l'information manque pour trancher avec certitude — ne jamais mettre `not_impacted` par
  défaut faute de vérification.
- `note` : facultatif, utile surtout pour `to_check` (expliquer ce qui manque) ou pour une
  dépendance indirecte (ex. "Odoo embarque nginx" → impact transitif à documenter).
- Cette information est **publique sans problème** (dire "nginx : impacted" pour une CVE nginx est
  une donnée de sécurité générique, pas une donnée interne) — ce qui reste interdit, c'est de
  copier le contenu brut du fichier privé qui sert de source à cette liste.
- Le README du dossier doit aussi présenter cette matrice sous forme de tableau Markdown lisible
  (colonnes Solution / Statut / Remarque), pas seulement dans le YAML.

## Règle sur `fix:` — ne jamais présenter un correctif qui peut ne rien faire comme suffisant

**Incident réel (nginx2root, 19/11/2026)** : un technicien a lu la fiche, lancé la commande de
correction listée en premier (`apt install --only-upgrade nginx`), obtenu
`nginx is already the newest version`, et en a conclu — à raison, compte tenu de ce qui était
écrit — que la faille était corrigée. En réalité Debian n'avait tout simplement **pas encore
publié de correctif** pour cette CVE précise : « déjà la plus récente » ne veut dire que « c'est
la version la plus récente **disponible dans les dépôts configurés** », jamais « c'est corrigé ».
L'app IRM affiche le champ `fix:` directement, sans forcément montrer tout le README — la
nuance doit donc vivre **dans le YAML lui-même**, pas seulement en prose dans le README.

**Préférence utilisateur explicite (2026-11-19)** : commencer par la commande standard du
gestionnaire de paquets reste tout à fait acceptable — ce n'est pas elle le problème, c'est
l'absence d'étape de vérification et de bascule claire après coup. Structurer `fix:` en **séquence
numérotée** quand aucun rétroportage distro n'est confirmé :

1. `{for: "Étape 1 -- <distro>, tenter la mise à jour standard", command: "<commande standard>"}`
   — présentée normalement, pas comme un piège.
2. `{for: "Étape 2 -- OBLIGATOIRE, vérifier que l'étape 1 a réellement corrigé", command: "Relancer <script>. Si encore [VULNÉRABLE], l'étape 1 n'a rien corrigé -- passer à l'étape 3. Un message '<distro> already the newest version' ne prouve PAS que c'est corrigé."}`
3. `{for: "Étape 3 -- SI toujours vulnérable après l'étape 2 : <nom du vrai correctif>", command: "<commandes shell complètes et directement copiables -- JAMAIS un lien seul ni un 'voir le README'>"}`
4. `{for: "Étape finale -- toujours", command: "Relancer le script une dernière fois et confirmer [CORRIGÉ] avant de considérer la faille traitée."}`

Si un rétroportage distro **est** confirmé dès la recherche initiale, cette séquence numérotée
n'est pas nécessaire — un `fix:` classique (une entrée par cas) suffit, comme dans
`php2shell/vuln.yaml`.

Dans tous les cas : **vérifier le statut du rétroportage avant d'écrire `fix:`** (tracker de
sécurité officiel de la distro, pas une supposition), et le revérifier à chaque mise à jour de la
fiche — ce statut change avec le temps.
