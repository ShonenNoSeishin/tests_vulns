# Proxmox VE — lot d'avis de sécurité du 10-12 novembre 2026

> Proxmox a publié plusieurs avis de sécurité (PSA) entre le **10 et le 12 novembre 2026**.
> **Aucun CVE n'a été attribué** à ce jour (numérotation PSA interne Proxmox uniquement). Deux
> avis mènent à une **exécution de commande en root** (PSA-00088, PSA-00100) ; les cinq autres sont
> plus limités (serveur HTTP interne, ACL de l'API SDN, injection de configuration réseau,
> échappement de répertoire à l'extraction d'images OCI, contrôle de privilège conteneur).
> **Aucun n'est une RCE pré-authentification depuis l'extérieur** : tous nécessitent déjà un accès
> ou un vecteur spécifique (stockage iSCSI, upload d'image, API réseau...).

## En 30 secondes

| | |
|---|---|
| **Suis-je concerné ?** | Vous administrez un **nœud Proxmox VE**, sur une version de paquets `pve-*`/`libpve-*` antérieure à celles du tableau ci-dessous. |
| **Comment tester ?** | `./test_proxmox-novembre-2026.sh` **sur le nœud Proxmox lui-même** (pas dans un invité). Lecture seule, interroge seulement `dpkg`. |
| **Comment corriger ?** | `apt update && apt full-upgrade` suffit à tout corriger en une seule opération de maintenance. |

## Les sept avis

| Avis | Paquet(s) concerné(s) | Impact | Corrigé dans |
|---|---|---|---|
| **PSA-2026-00088-1** | `libpve-storage-perl`, `libpve-guest-common-perl`, `qemu-server` | Injection de commande shell via un nom de volume (stockage ZFS-over-iSCSI, ou migration vers un stockage de type répertoire) — **exécution en root sur la cible iSCSI ou le nœud de destination** | `libpve-storage-perl` ≥ 9.1.15, `libpve-guest-common-perl` ≥ 6.0.7, `qemu-server` ≥ 9.2.15 |
| **PSA-2026-00100-1** | `libpve-storage-perl` | Citation shell manquante dans la gestion d'erreur d'un upload (image ISO/template) — **exécution de commande en root sur le nœud** | `libpve-storage-perl` ≥ 9.1.15 (même paquet/version que PSA-00088) |
| **PSA-2026-00089-1** | `libpve-http-server-perl` | Plusieurs problèmes dans le serveur HTTP Perl interne (injection/entrelacement de logs, en-têtes dupliqués non rejetés) | `libpve-http-server-perl` ≥ 6.0.6 |
| **PSA-2026-00092-1** | `libpve-network-api-perl` | Contrôles ACL manquants ou incomplets dans l'API SDN (IPAM, subnets, VNet) | `libpve-network-api-perl` ≥ 1.6.8 |
| **PSA-2026-00093-1** | `libpve-network-perl`, `libpve-rs-perl` | Injection de configuration FRR via les route maps | `libpve-network-perl` ≥ 1.6.8, `libpve-rs-perl` ≥ 0.15.4 |
| **PSA-2026-00094-1** | `librust-proxmox-oci-dev`, `libpve-rs-perl` | Échappement de répertoire à l'extraction d'images OCI (fichiers supprimés hors du rootfs via des « whiteouts ») | `librust-proxmox-oci-dev` ≥ 0.2.2, `libpve-rs-perl` ≥ 0.15.4 |
| **PSA-2026-00095-1** | `pve-container` | Contrôles de privilège cassés à la modification des cartes réseau de conteneurs | `pve-container` ≥ 6.1.17 |

Aucun de ces avis n'a de CVE à ce jour : pas de suivi possible via un scanner générique basé CVE,
se fier au changelog des paquets (`apt changelog <paquet>`).

## Comment faire la vérification

Un seul fichier, aucune dépendance, **à lancer sur le nœud Proxmox VE lui-même** :

```bash
chmod +x test_proxmox-novembre-2026.sh
./test_proxmox-novembre-2026.sh
```

Le script interroge uniquement `dpkg-query` (lecture seule, aucune modification) et affiche une
ligne par avis : `[VULNÉRABLE]` (au moins un paquet concerné est trop ancien), `[CORRIGÉ]` (tous
les paquets concernés sont à jour), ou `[À VÉRIFIER]` (un paquet attendu est absent — souvent le
signe que ce n'est pas un nœud Proxmox VE standard, voir la ligne `pveversion` en haut de la
sortie).

## Comment corriger

Une seule opération de maintenance couvre les sept avis :

```bash
apt update && apt full-upgrade
```

Tous les correctifs sont dans les dépôts Proxmox standards. Un redémarrage des services concernés
(ou du nœud, selon votre politique de maintenance habituelle) peut être nécessaire pour que les
démons rechargent les bibliothèques Perl/Rust mises à jour. **Action L1** : mise à jour de paquets
standard, aucun contournement manuel requis.

## Limites connues

- Ce script vérifie des **numéros de version de paquets**, pas l'exploitabilité réelle : un
  paquet vulnérable sur un nœud où le vecteur précis (ex. stockage ZFS-over-iSCSI) n'est pas
  utilisé reste à mettre à jour, mais n'est pas forcément exploitable aujourd'hui.
- **Pas de script PowerShell pour ce dossier** : Proxmox VE est une distribution Linux (basée
  Debian), il n'existe pas de variante Windows à auditer (contrairement au noyau Linux de
  `cve-2026-98432/`, où un hôte WSL2 sous Windows reste un cas réel — voir ce dossier pour un
  exemple de script PowerShell limité à WSL2).
- Le script est conçu pour tourner **sur le nœud Proxmox lui-même** : lancé dans un LXC ou une VM
  invité, il affichera `[À VÉRIFIER]` sur tous les avis (paquets absents), ce qui est normal — ces
  avis concernent le plan de gestion de l'**hôte**, pas les invités.
- Aucun CVE n'étant attribué, un futur avis Proxmox pourrait réutiliser un numéro de paquet déjà
  couvert ici avec un seuil différent : toujours recroiser avec le
  [fil officiel des avis](https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/)
  en cas de doute.

## Impact sur nos solutions

| Solution | Statut | Remarque |
|---|---|---|
| Proxmox VE | Impacté | Lot d'avis touchant le plan de gestion de l'hôte (pve-manager, qemu-server, pve-container, libpve-*) |
| Docker | Non impacté | Ces avis concernent le plan de gestion de l'hôte Proxmox, pas les conteneurs/invités |
| LXC | Non impacté | Ces avis concernent le plan de gestion de l'hôte Proxmox, pas les LXC invités |
| Veeam | Non impacté |  |
| Nakivo | Non impacté |  |
| 3CX | Non impacté |  |
| Elastix | Non impacté |  |
| Andrisoft WANGuard | Non impacté |  |
| Datalust Seq | Non impacté |  |
| LibreNMS | Non impacté |  |
| Observium | Non impacté |  |
| Debian | Non impacté |  |
| Ubuntu | Non impacté |  |
| Windows Server (2012/2016/2019/2022/2025) | Non impacté |  |
| SMB (Samba, Debian) | Non impacté |  |
| SFTP (Debian) | Non impacté |  |
| Cisco | Non impacté |  |
| Ubiquiti | Non impacté |  |
| HP/Aruba | Non impacté |  |
| FortiGate | Non impacté |  |
| FortiAnalyzer | Non impacté |  |
| FortiManager | Non impacté |  |
| Sophos | Non impacté |  |
| nginx | Non impacté |  |
| Certbot | Non impacté |  |
| Odoo (self-hosted) | Non impacté |  |
| Nextcloud | Non impacté |  |
| JumpCloud | Non impacté |  |
| Python | Non impacté |  |
| Django | Non impacté |  |
| React | Non impacté |  |
| PHP | Non impacté |  |
| MikroTik | Non impacté |  |
| Ceph | Non impacté | Avis Proxmox VE (pve-manager/libpve-*), pas Ceph lui-même |
| QEMU-KVM | Non impacté | Avis Proxmox VE (pve-manager/libpve-*), pas QEMU/KVM lui-même |

## Références

- [Fil officiel des avis de sécurité Proxmox VE](https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/)
