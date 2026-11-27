# CVE-2026-99362 — "nfs2root" : heap overflow pré-authentifié dans le serveur NFS du noyau Linux

> Faille **critique** (CVSS 3.1 : **9.8**, vecteur `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) dans le
> code **nfsd** (serveur NFS) du noyau Linux. **Aucune authentification requise** : un client
> NFSv4.1 malveillant suffit. Proxmox, qui a publié le premier avis constatant cette faille sur
> son propre noyau (PSA-2026-00103-1, 26/11/2026), la qualifie explicitement de **"pre-auth root
> RCE"**. Surnommée **"nfs2root"** par analogie avec les dossiers `nginx2root`/`apache2root` de ce
> dépôt.

## En 30 secondes

| | |
|---|---|
| **Suis-je concerné ?** | Toute machine **Linux** faisant tourner un **serveur NFS** (`nfsd`/`nfs-kernel-server`) exposé sur le réseau — typiquement un hôte Proxmox ou un serveur Ubuntu/Debian configuré en partage de fichiers NFS. Une machine qui ne fait que **monter** un partage NFS (client) n'est pas exposée par ce vecteur précis, mais son noyau reste à corriger par principe de précaution. |
| **Comment tester ?** | `./test_nfs2root.sh` sur l'hôte **et dans chaque VM Linux** (Windows : `Test-Nfs2Root.ps1`, WSL2 seulement). |
| **Comment corriger ?** | Proxmox/Debian : mise à jour standard **+ redémarrage**. **Ubuntu : aucun correctif disponible à ce jour**, voir section dédiée. |

## Explication courte

Le protocole NFSv4.1 permet à un client de négocier la taille du cache de réponses pour chaque
"slot" de sa session — un mécanisme de fiabilité du protocole, pas une fonctionnalité exotique.
Un client peut négocier cette taille à **zéro**, laissant un tampon de taille nulle côté serveur.
En envoyant ensuite une requête `COMPOUND` bien construite, le code serveur (`nfsd4_sequence()`
dans `fs/nfsd/nfs4state.c`) écrit dans ce tampon de taille zéro — une écriture **hors limites**
(heap overflow) dans la mémoire du noyau, confirmée par un rapport KASAN (écriture de 80 octets
hors zone allouée). L'enregistrement CVE officiel ne confirme que la corruption mémoire ; c'est
**l'avis Proxmox lui-même** qui qualifie l'impact de **"pre-auth root RCE"** — un attaquant ayant
simplement accès réseau au port NFS (2049/tcp) peut en théorie obtenir l'exécution de code avec
les privilèges du noyau (root), sans aucune authentification.

**Pourquoi c'est particulièrement important ici** : cette faille touche directement le code
noyau utilisé par **Proxmox VE**, la priorité n°1 d'infrastructure de cet hébergeur (hyperviseur
partagé entre plusieurs clients). Contrairement à `cve-2026-98432/` (qui affectait tout trafic
TCP), celle-ci n'est exploitable à distance **que si un serveur NFS est effectivement actif et
accessible** — ce qui réduit l'exposition réseau immédiate sur un cluster Proxmox classique
(généralement client NFS d'un NAS externe, pas serveur), mais ne change rien au fait que le
paquet noyau doit être corrigé partout, car la configuration peut changer et le correctif ne
coûte rien.

## Portée de ce dossier — même logique que `cve-2026-98432/`

Cette faille est dans le **noyau**, pas dans une application : **un conteneur Docker/Podman/LXC
partage le noyau de son hôte, il n'y a donc rien à sonder "par conteneur" ou "par image"** ici.
En revanche, **une VM (QEMU/KVM) a son propre noyau indépendant** : il faut lancer le script
**séparément à l'intérieur de chaque VM Linux**, en plus de l'hôte Proxmox lui-même.

**NFS-Ganesha** (serveur NFS en espace utilisateur, parfois utilisé pour exporter CephFS) n'est
**pas concerné** : il réimplémente le protocole NFS indépendamment du code noyau `fs/nfsd/` visé
par ce CVE. C'est une déduction technique (aucun avis Ceph/Ganesha contraire trouvé à ce jour),
pas une déclaration officielle explicite de l'équipe Ceph — à reconfirmer si un avis paraît.

## Versions affectées et corrigées — statut au 27/11/2026

| Système | Versions affectées | Version corrigée | Statut au 27/11/2026 |
|---|---|---|---|
| Noyau Linux upstream | Introduit par le commit `47ee529...` | Corrigé par le commit `35ff1a7a7e3835c3e974bc5c45d335897564ceae` (landé en v7.4-rc1) ; rétroportages stables : 5.10.275 / 5.15.226 / 6.1.193 / 6.6.163 / 6.12.117 / 6.18.61 / 7.3.2 | Corrigé en amont |
| **Proxmox VE, branche par défaut** (`proxmox-kernel-7.0`) | < 7.0.14-30-pve | **7.0.14-30-pve** | ✅ Corrigé, disponible (PSA-2026-00103-1, 26/11/2026) |
| **Proxmox VE, branche opt-in** (`proxmox-kernel-7.3`) | < 7.3.3-1-pve | **7.3.3-1-pve** | ✅ Corrigé, disponible (PSA-2026-00103-1) |
| **Debian 12 (bookworm), noyau principal** | `linux` < 6.1.192-3 | **6.1.192-3** (DLA-4942-1) | ✅ Corrigé, disponible |
| **Debian 12 (bookworm), noyau de secours** (`linux-6.12`, bookworm-backports) | < 6.12.117-1~deb12u1 | **6.12.117-1~deb12u1** (DLA-4927-1) | ✅ Corrigé, disponible |
| **Debian 13 (trixie)** | `linux` < 6.12.117-1 | **6.12.117-1** (une révision ultérieure 6.12.118-1 existe aussi) | ✅ Corrigé, disponible |
| **Ubuntu (toutes branches, 18.04 à 26.10)** | Toutes | — | ❌ **Aucun correctif stable disponible** à ce jour. 26.04/26.10 listées "work in progress" sur `ubuntu.com/security/CVE-2026-99362` ; les autres branches restent "Vulnerable". **Ne pas déduire "corrigé" d'un `apt install --only-upgrade` qui répond "already the newest version"** : il n'existe simplement rien à installer pour l'instant. |
| **Windows Server** (AD/TS/SQL) | — | — | **Non concerné** (noyau NT, pas Linux ; le rôle natif "Server for NFS" est une implémentation indépendante). Seule exception : WSL2, voir script PowerShell. |

> ⚠️ **Point d'attention Ubuntu, identique à l'avertissement déjà documenté dans
> `cve-2026-98432/` pour Debian à l'époque** : tant qu'aucun correctif n'existe dans les dépôts
> Ubuntu, une mise à jour standard ne corrigera rien. Si le service NFS est exposé sur une machine
> Ubuntu du parc, traiter en mitigation réseau (voir section correction ci-dessous) en attendant
> un correctif Canonical — revérifier le security tracker Ubuntu avant de considérer ce point
> clos.

Sources vérifiées le 27/11/2026 : [forum Proxmox — PSA-2026-00103-1](https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/), [ubuntu.com/security/CVE-2026-99362](https://ubuntu.com/security/CVE-2026-99362), [security-tracker.debian.org/tracker/CVE-2026-99362](https://security-tracker.debian.org/tracker/CVE-2026-99362), enregistrement CVE officiel via l'API NVD.

## Comment vérifier

```bash
chmod +x test_nfs2root.sh
./test_nfs2root.sh
```

```powershell
.\Test-Nfs2Root.ps1
```

**Important** : relancer le script bash **à l'intérieur de chaque VM Linux**, pas seulement sur
l'hôte Proxmox — chaque VM a son propre noyau indépendant. Le script indique aussi, en plus du
verdict sur la version du noyau, si un service NFS semble **réellement actif et exposé** sur la
machine (information d'urgence, pas un critère d'exclusion — le noyau est à corriger dans tous
les cas).

## Comment corriger

- **Proxmox VE / Debian — `[VULNÉRABLE]` avec correctif disponible** → **action L1** : mise à
  jour standard, puis **redémarrage du nœud/VM requis** (le correctif ne s'applique qu'au
  reboot). Sur un cluster Proxmox, migrer les VM avant de redémarrer un nœud, un nœud à la fois.
  ```bash
  apt update && apt upgrade
  reboot   # obligatoire pour charger le nouveau noyau
  ```

- **Ubuntu — aucun correctif disponible à ce jour** → séquence à suivre :
  1. **Étape 1** : tenter la mise à jour standard (sans garantie, car aucun correctif n'existe
     encore dans les dépôts au 27/11/2026) :
     ```bash
     apt update && apt upgrade
     ```
  2. **Étape 2, OBLIGATOIRE** : relancer `./test_nfs2root.sh`. Si le résultat reste
     `[VULNÉRABLE]`, l'étape 1 n'a rien corrigé — un message `linux-image... is already the
     newest version` ne prouve **pas** que c'est corrigé, seulement qu'il n'y a rien de plus
     récent dans les dépôts configurés.
  3. **Étape 3 — mitigation en attendant un correctif Canonical** : si le serveur NFS n'est pas
     strictement nécessaire sur cette machine, le désactiver complètement :
     ```bash
     systemctl stop nfs-kernel-server
     systemctl disable nfs-kernel-server
     ```
     S'il est nécessaire, restreindre l'accès réseau au port 2049/tcp aux seuls clients NFS de
     confiance (pare-feu `nftables`/`iptables`/Proxmox Firewall), par exemple :
     ```bash
     nft add rule inet filter input tcp dport 2049 ip saddr != { <IP_clients_NFS_de_confiance> } drop
     ```
  4. **Étape finale, toujours** : relancer `./test_nfs2root.sh` une dernière fois pour confirmer
     l'état réel (le noyau restera `[VULNÉRABLE]` jusqu'à un correctif Canonical, mais la
     mitigation réseau réduit l'exposition réelle en attendant — c'est le point important à
     documenter dans un ticket de suivi, pas quelque chose que ce script peut détecter
     automatiquement).

- **Mitigation générale, quelle que soit la distribution, si le service NFS n'est pas nécessaire**
  → **action L1 immédiate et sans risque** : couper le service.
  ```bash
  systemctl stop nfs-kernel-server
  systemctl disable nfs-kernel-server
  ```

## Limites connues

- Ce script est un inventaire de version + un relevé d'exposition, pas un test d'intrusion : il
  ne prouve pas l'absence de compromission passée.
- Pour les distributions RHEL/CentOS/Rocky/Alma/SUSE/Fedora, ce script ne connaît pas de version
  corrigée de référence fiable et renvoie systématiquement `[À VÉRIFIER]` plutôt qu'un verdict —
  consulter l'erratum du fournisseur.
- Debian 11 (bullseye) et plus ancien, ou tout Debian dont le `VERSION_CODENAME`/`VERSION_ID` ne
  correspond ni à bookworm/12 ni à trixie/13 : renvoie `[À VÉRIFIER]` par prudence.
- La détection d'exposition nfsd (service actif, module chargé, port 2049, `/etc/exports`,
  `rpcinfo`) est un ensemble d'indices lecture-seule, pas une preuve d'exploitabilité réelle —
  l'absence de tout signal réduit le risque immédiat sans l'exclure formellement (configuration
  qui peut changer).
- Le lien entre NFS-Ganesha/CephFS et ce CVE est une déduction technique (code distinct), pas une
  confirmation officielle Ceph — à reconfirmer si un avis Ceph paraît.

## Impact sur nos solutions

| Solution | Statut | Remarque |
|---|---|---|
| Proxmox VE | Impacté | Noyau directement concerné (PSA-2026-00103-1) ; exposition réseau réelle dépend d'un service NFS actif — voir script |
| Docker | À vérifier | Partage le noyau de l'hôte ; `nfsd` tourne presque toujours sur l'hôte, pas dans un conteneur, sauf conteneur privilégié configuré explicitement en serveur NFS (atypique) |
| LXC | À vérifier | Même raison que Docker |
| Veeam | Non impacté | Application, pas de rôle serveur NFS documenté |
| Nakivo | Non impacté | Application, pas de rôle serveur NFS documenté |
| 3CX | Non impacté | Application PBX, pas de rôle serveur NFS |
| Elastix | Non impacté | Application PBX, pas de rôle serveur NFS |
| Andrisoft WANGuard | Non impacté | Application de supervision, pas de rôle serveur NFS |
| Datalust Seq | Non impacté | Application de supervision, pas de rôle serveur NFS |
| LibreNMS | Non impacté | Application de supervision, pas de rôle serveur NFS |
| Observium | Non impacté | Application de supervision, pas de rôle serveur NFS |
| Debian | Impacté | Noyau directement concerné (bookworm et trixie, voir tableau) |
| Ubuntu | Impacté | Noyau directement concerné, **aucun correctif disponible à ce jour** — voir section correction |
| Windows Server (2012/2016/2019/2022/2025) | Non impacté | Noyau NT, pas Linux ; le rôle natif "Server for NFS" est une implémentation indépendante, non concernée. Seule exception WSL2, couverte par le script PowerShell dédié |
| SMB (Samba, Debian) | Non impacté | Protocole et code noyau différents (SMB ≠ nfsd) ; voir l'entrée Debian pour le statut du noyau sous-jacent |
| SFTP (Debian) | Non impacté | Protocole et code différents (SFTP ≠ nfsd) ; voir l'entrée Debian pour le statut du noyau sous-jacent |
| Cisco | Non impacté | Équipement réseau, pas de rôle serveur NFS |
| Ubiquiti | Non impacté | Équipement réseau, pas de rôle serveur NFS |
| HP/Aruba | Non impacté | Équipement réseau (switches), pas de rôle serveur NFS |
| FortiGate | Non impacté | Pas de rôle serveur NFS documenté sur ce produit |
| FortiAnalyzer | À vérifier | Peut monter des partages NFS en tant que **client** (stockage externe de logs) — rôle client, pas serveur, donc non exposé par ce vecteur précis ; à confirmer selon la configuration exacte |
| FortiManager | Non impacté | Pas de rôle serveur NFS documenté sur ce produit |
| Sophos | Non impacté | Pas de rôle serveur NFS documenté sur ces produits |
| nginx | Non impacté | Application, pas de rôle serveur NFS |
| Certbot | Non impacté | Application, pas de rôle serveur NFS |
| Odoo (self-hosted) | Non impacté | Application, pas de rôle serveur NFS documenté |
| Nextcloud | À vérifier | Peut être configuré avec un stockage externe NFS, mais en tant que **client** — à confirmer selon le déploiement si un serveur NFS est hébergé à proximité |
| JumpCloud | Non impacté | Service SaaS externe, pas hébergé par nous |
| Python | Non impacté | Langage, pas de rôle serveur NFS |
| Django | Non impacté | Framework, pas de rôle serveur NFS |
| React | Non impacté | Framework frontend, pas de rôle serveur NFS |
| PHP | Non impacté | Langage, pas de rôle serveur NFS |
| MikroTik | Non impacté | RouterOS, pas de rôle serveur NFS documenté |
| Ceph | Non impacté | Protocoles OSD/MON internes distincts ; si CephFS est exporté via NFS-Ganesha (serveur NFS en espace utilisateur), ce composant est indépendant du code noyau `nfsd` visé par ce CVE — voir note technique ci-dessus |
| QEMU-KVM | Non impacté | Code de virtualisation indépendant du code serveur NFS ; le noyau hôte sous-jacent est couvert par l'entrée Proxmox VE/Debian/Ubuntu |

## Références

- [Proxmox VE — avis de sécurité PSA-2026-00103-1](https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/)
- [Ubuntu Security — CVE-2026-99362](https://ubuntu.com/security/CVE-2026-99362)
- [Debian Security Tracker — CVE-2026-99362](https://security-tracker.debian.org/tracker/CVE-2026-99362)
- [NVD — CVE-2026-99362](https://nvd.nist.gov/vuln/detail/CVE-2026-99362)
