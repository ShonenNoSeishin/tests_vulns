# CVE-2026-119618 — « Apache2Root »

> Une faille critique dans **mod_http2** d'Apache HTTP Server, corrigée le **11/11/2026**. Race condition (CWE-362) dans la fonction `assign_headers()` pouvant mener à une **exécution de code à distance SANS authentification**. CVSS 3.1 : **8.1 (High)**, `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` — « AC:H » car c'est une condition de concurrence, pas un bug trivial à déclencher à chaque tentative. Pas d'exploitation active connue à ce jour (SSVC CISA : `exploitation: none`). Affecte aussi, séparément, le module standalone du projet GitHub **icing/mod_h2** (même code source, packagé à part).

## En 30 secondes

| | |
|---|---|
| **Suis-je concerné ?** | Un serveur fait tourner **Apache httpd** (`apache2`/`httpd`) avec le **module `mod_http2` chargé**, en version **2.4.55 à 2.4.70**. Si `mod_http2` n'est pas chargé, vous n'êtes pas concerné par cette CVE précise (mais patchez quand même dès que possible). |
| **Comment tester ?** | `sudo ./test_apache2root.sh --scan-images` (Linux) · `.\Test-Apache2Root.ps1 -ScanImages` (Windows). Lecture seule, aucune requête envoyée à un serveur distant. |
| **Comment corriger ?** | `apt install --only-upgrade apache2` (Debian/Ubuntu, correctif déjà rétroporté depuis le 11/11/2026 pour les versions supportées) puis **revérifier avec le script**. Sous Windows (XAMPP/WAMP/Apache Lounge) : pas de rétroportage, réinstallation manuelle en 2.4.71+ (voir ci-dessous). |

## Explication courte

Le 11 novembre 2026, la fondation Apache a publié Apache HTTP Server **2.4.71**, corrigeant CVE-2026-119618 : une condition de concurrence dans `assign_headers()` (module `mod_http2`) qui peut, dans certains enchaînements de requêtes HTTP/2, mener à une **exécution de code à distance sans authentification**. La faille a été signalée par Anthropic (26/10/2026) et par le Google Cloud VRP (03/11/2026).

Point important pour l'évaluation du risque : **`mod_http2` n'est pas chargé par défaut** sur une installation Debian/Ubuntu standard (`apt install apache2`) — il faut l'avoir activé explicitement (`a2enmod http2`, ou équivalent sur une autre distribution/un autre OS) pour utiliser HTTP/2. Si ce module n'est pas chargé, cette CVE précise ne s'applique pas (mais une mise à jour reste recommandée par hygiène générale).

Le même défaut existe, séparément, dans le **module standalone du projet GitHub [icing/mod_h2](https://github.com/icing/mod_h2)** (versions 2.0.8 à 2.0.42) — un fork/miroir du code qui peut être compilé et installé indépendamment du paquet système Apache, avec sa propre numérotation de version. Un `apache2 -v` ne révèle alors pas la version du module standalone.

### Versions concernées / corrigées

| Produit | Versions vulnérables | Corrigé |
|---|---|---|
| Apache HTTP Server (mod_http2 intégré) | 2.4.55 → 2.4.70 | **2.4.71** (11/11/2026) |
| Module standalone `icing/mod_h2` (GitHub) | 2.0.8 → 2.0.42 | **2.0.43** |

> ⚠️ **Piège de version — Debian ET Ubuntu rétroportent sans changer le numéro amont, même piège
> que `nginx2root/` et `php-novembre-2026/` :**
>
> | Distribution (codename) | Paquet apache2 corrigé | Avis | Remarque |
> |---|---|---|---|
> | Debian 13 (trixie) | `2.4.71-1~deb13u1` | DSA-6620-1 | |
> | Debian 12 (bookworm) | `2.4.71-1~deb12u1` | DLA-4902-1 | LTS |
> | Ubuntu 26.10 (stonking) | `2.4.68-1ubuntu6.2` | USN-9090-1 | |
> | Ubuntu 26.04 LTS (resolute) | `2.4.66-2ubuntu2.8` | USN-9090-1 | |
> | Ubuntu 24.04 LTS (noble) | `2.4.58-1ubuntu8.19` | USN-9090-1 | |
> | Ubuntu 22.04 LTS (jammy) | `2.4.52-1ubuntu4.27` | USN-9090-1 | |
> | Ubuntu 20.04 LTS (focal) | `2.4.41-4ubuntu3.23+esm11` | USN-9090-1 | **Ubuntu Pro/ESM requis** |
> | Ubuntu 18.04 LTS (bionic) | — | — | Non affecté (version native < 2.4.55) |
> | Ubuntu 16.04 LTS (xenial) | — | — | Non affecté (version native < 2.4.55) |
>
> Validé en conditions réelles le 24/11/2026 : un Debian 12 et un Ubuntu 24.04 fraîchement installés
> via `apt` recevaient déjà le paquet corrigé par défaut (le correctif a deux semaines d'ancienneté
> à cette date) — mais **toute machine qui n'a pas reçu ses mises à jour depuis le 11/11/2026 reste
> potentiellement vulnérable**. Le script compare le **paquet dpkg** à la table ci-dessus, jamais
> `apache2 -v` seul, pour les deux distributions. **"Non affecté" pour bionic/xenial n'est pas un
> raccourci** : le script revérifie quand même la version réellement détectée (même piège que
> "trusty" rencontré sur `nginx2root/` le 19/11/2026) avant de conclure.
>
> **Module `mod_h2` standalone (icing/mod_h2)** : si le script détecte que `mod_http2` est chargé
> depuis un chemin **hors des dossiers standards** du paquet système (ex. `/usr/local/...` au lieu
> de `/usr/lib/apache2/modules/...`), il remonte `[À VÉRIFIER]` plutôt que de comparer à tort la
> version du module à la version du cœur Apache — comparer manuellement à la version 2.0.43+ du
> projet GitHub.
>
> **Windows (XAMPP / WAMP / Apache Lounge)** : la fondation Apache ne fournit pas de binaires
> Windows officiels ; ces distributions n'ont pas de rétroportage distro. Seule une réinstallation
> en 2.4.71+ corrige la faille (voir « Comment corriger » ci-dessous).

## Démonstration : comment vérifier qu'une cible est vulnérable

**Méthode recommandée, sans risque : l'inventaire de version + modules chargés.** C'est ce que fait le script de ce dossier : il identifie chaque binaire Apache (hôte, conteneurs, images Docker/Podman), vérifie si `mod_http2` est réellement chargé, et compare la version au seuil ci-dessus. Aucune requête HTTP/2 n'est envoyée à un serveur — sûr à lancer en production.

**Méthode active (test d'intrusion) — réservée à un labo isolé, jamais en production sans autorisation écrite :** le mécanisme publié déclenche la condition de concurrence via un enchaînement précis de trames HTTP/2 concurrentes dans `assign_headers()`. Ce dépôt ne fournit pas de preuve de concept exécutable : dans l'immense majorité des cas, l'inventaire de version + modules suffit à savoir si vous êtes concerné.

## Comment faire la vérification

Un seul fichier par plateforme, aucune dépendance :

```bash
chmod +x test_apache2root.sh
./test_apache2root.sh                # mode lecture seule (par défaut)
./test_apache2root.sh --scan-images  # + sonde les images Docker/Podman locales
```

```powershell
.\Test-Apache2Root.ps1
.\Test-Apache2Root.ps1 -ScanImages
```

## Comment corriger

**Action L1 — Debian/Ubuntu, le correctif est déjà rétroporté depuis le 11/11/2026 :**
```bash
apt update && apt install --only-upgrade apache2
systemctl restart apache2
```
Puis **toujours revérifier avec le script** (`./test_apache2root.sh`) : doit afficher `[CORRIGÉ]` ou `[NON CONCERNÉ]` (si `mod_http2` n'est pas chargé). Un message « apache2 is already the newest version » ne prouve pas que c'est corrigé si le dépôt de sécurité lui-même n'est pas à jour — relancer le script est la seule vérification fiable.

**Image Docker officielle `httpd` :**
```bash
docker pull httpd:2.4   # le tag "2.4" suit désormais 2.4.71 (mis à jour le 13/11/2026)
docker compose up -d --force-recreate
```
Un `docker-compose.yml` qui épingle un tag précis (`httpd:2.4.70`, `httpd:2.4.69`...) reste vulnérable tant que ce tag n'est pas changé manuellement — vérifier la version exacte pinnée.

**Windows (XAMPP / WAMP / Apache Lounge) — pas de rétroportage, réinstallation obligatoire :**
1. Télécharger Apache httpd **≥ 2.4.71** depuis <https://www.apachelounge.com/download/> (build Windows non officiel mais de référence), ou attendre la prochaine version de XAMPP/WAMP qui embarque ce correctif.
2. Remplacer les binaires existants en conservant la configuration (`conf\httpd.conf`), redémarrer le service.
3. Revérifier avec `Test-Apache2Root.ps1`.

**Mitigation temporaire, si la mise à jour doit attendre (réduit l'exposition à cette CVE uniquement) :**
```bash
a2dismod http2 && systemctl restart apache2
```
(ou commenter la ligne `LoadModule http2_module ...` dans la configuration, et retirer toute directive `Protocols h2 ...` sur les vhosts concernés.) Documenter cette mitigation comme temporaire : les clients ne pourront plus négocier HTTP/2 jusqu'à la vraie mise à jour.

**Module standalone `mod_h2` (projet GitHub icing/mod_h2), indépendant du paquet système :**
Mettre à jour vers la version **2.0.43 ou supérieure** depuis <https://github.com/icing/mod_h2/releases>, recompiler/réinstaller selon la procédure habituelle de ce module.

Dans tous les cas : **relancer `test_apache2root.sh`/`Test-Apache2Root.ps1` une dernière fois** et confirmer `[CORRIGÉ]` (ou `[NON CONCERNÉ]` si `mod_http2` reste désactivé) avant de considérer la faille traitée.

## Limites connues

- Ce script est un inventaire de versions + modules chargés, pas un test d'intrusion : il ne prouve pas l'absence de compromission passée.
- La détection du statut de `mod_http2` (chargé ou non) dépend de `apache2ctl -M`/`httpd -M`, qui nécessite une configuration lisible et valide. Si cette commande échoue (droits insuffisants, config cassée), le script remonte `[À VÉRIFIER]` plutôt qu'un `[NON CONCERNÉ]` non garanti.
- Le module standalone `mod_h2` (projet GitHub icing/mod_h2) n'est **jamais comparé automatiquement** quand son chemin de chargement sort des dossiers standards du paquet système : toujours `[À VÉRIFIER]` dans ce cas, par sécurité.
- La détection du paquet système (dpkg) **décide du verdict sur Debian et Ubuntu** (tables de rétroportage ci-dessus) ; sur toute autre distribution (Alpine, RHEL...), seule la version rendue par le binaire réellement utilisé compte (comparaison générique contre la plage 2.4.55-2.4.70).
- `Test-Apache2Root.ps1` (Windows) ne vérifie pas de paquet système (pas de rétroportage sous Windows) ; le statut `mod_http2` y est déduit d'une lecture **statique** du fichier `conf\httpd.conf` voisin du binaire trouvé — best-effort, peut échouer sur une disposition de fichiers non standard (remonte alors `[À VÉRIFIER]`, jamais un faux `[NON CONCERNÉ]`). Les conteneurs Windows natifs (non-WSL2) ne sont pas sondés.
- `Test-Apache2Root.ps1` : par sécurité, **seul le `httpd.exe` résolu depuis le PATH de l'opérateur est exécuté** (pour lister les modules via `-M`). Un binaire trouvé par recherche sur disque ou appartenant à un processus/service déjà en cours est lu uniquement via ses métadonnées de version et la configuration voisine (jamais exécuté).

## Impact sur nos solutions

| Solution | Statut | Remarque |
|---|---|---|
| Proxmox VE | Non impacté | L'interface de gestion Proxmox (pveproxy) n'utilise ni Apache ni nginx |
| Docker | À vérifier | Dépend si un conteneur fait tourner Apache httpd avec mod_http2 chargé en version vulnérable |
| LXC | À vérifier | Dépend si le conteneur fait tourner Apache httpd avec mod_http2 chargé en version vulnérable |
| Veeam | Non impacté |  |
| Nakivo | Non impacté |  |
| 3CX | Non impacté | 3CX embarque son propre nginx, pas Apache httpd (voir `nginx2root/`) |
| Elastix | À vérifier | FreePBX/Elastix utilise traditionnellement Apache httpd pour son interface d'administration -- vérifier la version et si mod_http2 est chargé |
| Andrisoft WANGuard | À vérifier | Console web PHP, serveur web sous-jacent non documenté publiquement -- vérifier selon le déploiement |
| Datalust Seq | Non impacté | Seq est une application .NET avec son propre serveur web intégré (Kestrel), pas Apache |
| LibreNMS | À vérifier | Application PHP -- la documentation communautaire couvre à la fois Apache et nginx selon le déploiement |
| Observium | À vérifier | Aucune information fiable trouvée sur le serveur web par défaut -- à vérifier selon le déploiement |
| Debian | Non impacté | L'OS lui-même n'est pas en cause -- vérifier le paquet apache2 installé dessus séparément |
| Ubuntu | Non impacté | L'OS lui-même n'est pas en cause -- vérifier le paquet apache2 installé dessus séparément |
| Windows Server (2012/2016/2019/2022/2025) | À vérifier | Apache httpd est rare sous Windows mais possible (XAMPP, WAMP, Apache Lounge) pour des applications spécifiques |
| SMB (Samba, Debian) | Non impacté |  |
| SFTP (Debian) | Non impacté |  |
| Cisco | Non impacté |  |
| Ubiquiti | Non impacté |  |
| HP/Aruba | Non impacté |  |
| FortiGate | Non impacté |  |
| FortiAnalyzer | Non impacté |  |
| FortiManager | Non impacté |  |
| Sophos | Non impacté |  |
| nginx | Non impacté | nginx n'est pas Apache httpd ; si les deux coexistent (reverse-proxy devant Apache), vérifier Apache séparément |
| Certbot | Non impacté | Certbot lui-même n'est pas Apache ; son plugin Apache ne fait qu'éditer la configuration TLS |
| Odoo (self-hosted) | À vérifier | Odoo tourne en général derrière nginx, mais un déploiement pourrait utiliser Apache comme reverse-proxy frontal -- à vérifier selon le déploiement |
| Nextcloud | À vérifier | La documentation officielle Nextcloud présente Apache comme méthode d'installation principale (nginx aussi supporté séparément) -- à vérifier selon le déploiement |
| JumpCloud | Non impacté |  |
| Python | Non impacté | Le moteur Python lui-même n'est pas en cause, même si une application Python tourne derrière un Apache vulnérable (mod_wsgi) -- vérifier Apache séparément |
| Django | Non impacté | Même remarque que Python : vérifier Apache séparément s'il sert de frontal |
| React | Non impacté |  |
| PHP | Non impacté | Le moteur PHP lui-même n'est pas en cause, même via mod_php dans un Apache vulnérable -- vérifier Apache séparément ; voir `php2shell/`/`php-novembre-2026/` pour les failles propres à PHP |
| MikroTik | Non impacté |  |
| Ceph | Non impacté |  |
| QEMU-KVM | Non impacté |  |

## Références

- [Avis officiel Apache HTTP Server 2.4](https://httpd.apache.org/security/vulnerabilities_24.html)
- [NVD — CVE-2026-119618](https://nvd.nist.gov/vuln/detail/CVE-2026-119618)
- [DSA-6620-1 — Debian 13 (trixie)](https://www.debian.org/security/2026/dsa-6620)
- [DLA-4902-1 — Debian 12 (bookworm, LTS)](https://www.debian.org/lts/security/2026/dla-4902)
- [USN-9090-1 — Ubuntu](https://ubuntu.com/security/notices/USN-9090-1)
- [Module standalone icing/mod_h2 (GitHub)](https://github.com/icing/mod_h2)
- Debian Security Tracker : <https://security-tracker.debian.org/tracker/CVE-2026-119618>
- Ubuntu Security Notices : <https://ubuntu.com/security/CVE-2026-119618>
