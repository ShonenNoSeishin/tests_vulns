# CVE-2026-132165 — « Drupal2Root »

> Une faille **« Highly critical » (20/25)** dans **Drupal Core**, corrigée le **18/11/2026** (avis officiel SA-CORE-2026-017). Sous conditions spécifiques, le fichier `install.php` peut être utilisé pour relancer l'installeur sur un site **déjà installé**, menant à une **prise de contrôle du site ou une exécution de code à distance, SANS authentification**. **Exploitation active signalée par l'équipe sécurité Drupal elle-même dès le 19/11/2026** sur des sites en production, et ajoutée au catalogue **KEV CISA le 24/11/2026**.

## En 30 secondes

| | |
|---|---|
| **Suis-je concerné ?** | Tout site **Drupal 10 ou 11** en version **< 10.6.22**, ou **≥ 11.0.0 < 11.3.22**, ou **≥ 11.4.0 < 11.4.13**. Drupal 8/9 et les branches 10.5.x/11.2.x et antérieures sont en **fin de vie** : elles restent affectées mais ne recevront jamais de correctif direct. |
| **Comment tester ?** | `sudo ./test_drupal2root.sh --scan-images` (Linux) · `.\Test-Drupal2Root.ps1 -ScanImages` (Windows, surtout utile pour Docker Desktop). Lecture seule, aucune requête envoyée à un serveur distant. |
| **Comment corriger ?** | Mettre à jour Drupal Core vers **10.6.22**, **11.3.22** ou **11.4.13** selon la branche (`composer require drupal/core:^10.6.22` ou équivalent selon la branche), puis **revérifier avec le script**. |

## Explication courte

Le 18 novembre 2026, l'équipe sécurité de Drupal a publié l'avis **SA-CORE-2026-017** : Drupal Core embarque un fichier `install.php` destiné à l'installation initiale du site. Sous certaines conditions, un attaquant peut l'utiliser pour **relancer l'installeur sur un site déjà en production**, ce qui peut mener à une prise de contrôle complète du site ou à une exécution de code à distance — sans avoir besoin d'un compte. L'avis précise qu'**un des chemins d'exploitation est mitigé si le serveur web ne peut pas écrire ou changer les permissions du fichier `settings.php`**, mais que ce n'est pas vrai de tous les chemins d'exploitation possibles.

**Fait important, confirmé par l'avis officiel lui-même** : l'équipe sécurité Drupal a reçu un signalement d'exploitation active sur des sites en production dès le **19 novembre 2026, 19h00 UTC** — moins de 24h après la publication du correctif. Ce n'est pas une faille théorique : elle est activement utilisée.

**Différence importante avec `apache2root/`, `nginx2root/`, `php2shell/`** : Drupal n'est **pas** distribué via un paquet système (`apt`/`dnf`/`apk`) — c'est une application PHP déployée en code (Composer, tarball) dans un dossier web. Il n'existe donc **aucune table de rétroportage distro** à vérifier ici : la version qui compte est directement celle du code source Drupal présent sur le disque (fichier `core/lib/Drupal.php`, constante `VERSION`), pas un numéro de paquet `dpkg -l`.

### Versions concernées / corrigées

| Branche | Versions vulnérables | Corrigé |
|---|---|---|
| Drupal 10.6.x (seule branche 10.x maintenue) | < 10.6.22 | **10.6.22** |
| Drupal 11.3.x | < 11.3.22 | **11.3.22** |
| Drupal 11.4.x | < 11.4.13 | **11.4.13** |
| Drupal 10.5.x et antérieur | toutes | **Fin de vie — aucun correctif direct, migrer vers 10.6.x puis 10.6.22+** |
| Drupal 11.0.x à 11.2.x | toutes | **Fin de vie — aucun correctif direct, migrer vers 11.3.x/11.4.x puis le correctif** |
| Drupal 8.x | toutes | **Fin de vie depuis le 02/11/2021 — aucun correctif, migration majeure obligatoire** |
| Drupal 9.x | toutes | **Fin de vie depuis le 01/11/2023 — aucun correctif, migration majeure obligatoire** |

> ⚠️ **Piège de version — différent du piège « rétroportage distro » habituel de ce dépôt :**
> ici il n'y a **aucun rétroportage** possible : Drupal 8/9 et les branches 10.5.x/11.2.x et
> antérieures sont en fin de vie et ne recevront **jamais** de correctif pour cette CVE,
> contrairement à un paquet Debian/Ubuntu qui reçoit un patch de sécurité sans changer de version
> majeure. La seule remédiation pour ces branches est une **migration complète** vers une branche
> supportée, puis l'application du correctif — pas une simple commande de mise à jour.
>
> **Drupal 7 et antérieur ne sont PAS couverts par cette fiche** : leur architecture ne possède
> pas le fichier `core/lib/Drupal.php` que ce script recherche (Drupal 7 date d'avant la
> réécriture Symfony de Drupal 8). Drupal 7 est lui-même en fin de vie depuis longtemps — s'il en
> existe encore dans le parc, c'est un risque à part, hors du périmètre de cette CVE précise.

## Démonstration : comment vérifier qu'une cible est vulnérable

**Méthode recommandée, sans risque : l'inventaire de version du code source.** C'est ce que fait le script de ce dossier : il cherche chaque installation Drupal (hôte, conteneurs, images Docker/Podman) via le fichier `core/lib/Drupal.php`, lit la constante `VERSION`, et la compare au seuil corrigé de sa branche. Aucune requête HTTP n'est envoyée à un serveur — sûr à lancer en production.

**Méthode active (test d'intrusion) — réservée à un labo isolé, jamais en production sans autorisation écrite :** l'avis officiel ne détaille pas publiquement la séquence exacte permettant de relancer `install.php` sur une installation existante. Ce dépôt ne fournit pas de preuve de concept exécutable : l'inventaire de version suffit dans l'immense majorité des cas à savoir si vous êtes concerné.

## Comment faire la vérification

Un seul fichier par plateforme, aucune dépendance :

```bash
chmod +x test_drupal2root.sh
./test_drupal2root.sh                # mode lecture seule (par défaut)
./test_drupal2root.sh --scan-images  # + sonde les images Docker/Podman locales
```

```powershell
.\Test-Drupal2Root.ps1
.\Test-Drupal2Root.ps1 -ScanImages
```

## Comment corriger

**Action L1 — si vous êtes sur une branche encore maintenue (10.6.x, 11.3.x ou 11.4.x) :**
```bash
# Avec Composer (déploiement standard Drupal 10/11)
composer require 'drupal/core:^10.6.22' 'drupal/core-recommended:^10.6.22' --update-with-dependencies
# (remplacer 10.6.22 par 11.3.22 ou 11.4.13 selon la branche installée)
drush updatedb -y   # si drush est disponible, pour exécuter les mises à jour de base de données
```
Puis **toujours revérifier avec le script** (`./test_drupal2root.sh`) : doit afficher `[CORRIGÉ]`.

**Image Docker officielle `drupal` :**
```bash
docker pull drupal:10.6-php8.3-apache   # ou le tag de branche correspondant (11.3-, 11.4-)
docker compose up -d --force-recreate
```
Un `docker-compose.yml` qui épingle un tag de version précis (`drupal:10.6.21-php8.3-apache`...) reste vulnérable tant que ce tag n'est pas changé manuellement — vérifier le tag exact utilisé.

**Si vous êtes sur une branche EN FIN DE VIE (Drupal 7/8/9, ou 10.0-10.5.x, ou 11.0-11.2.x) — pas de correctif direct, à escalader équipe sécu/infra :**
Il n'existe **aucun correctif de sécurité** pour ces branches. La seule remédiation est une **migration de branche majeure** (ex. Drupal 9 → 10.6.x, ou Drupal 11.1.x → 11.4.x), un projet à part entière (compatibilité des modules contrib/thèmes, tests), pas une action L1. En attendant la migration, voir la mitigation temporaire ci-dessous.

**Mitigation temporaire, si la mise à jour/migration doit attendre (réduit l'exposition à cette CVE uniquement) :** objectif, empêcher tout accès réseau à `install.php` une fois le site installé. Trois options officielles (« Securing the installer », lien en référence), à documenter comme temporaires, pas comme un correctif :
1. **Nginx (recommandé si Drupal est servi derrière nginx)** : bloquer l'accès dans la configuration du vhost :
   ```nginx
   location = /core/install.php { deny all; return 404; }
   ```
2. **Apache** : équivalent dans la configuration du vhost, ou via un `.htaccess` placé dans le dossier `core/` :
   ```apache
   <Files install.php>
     Require all denied
   </Files>
   ```
3. **Retirer le fichier du déploiement** après l'installation initiale (`rm core/install.php`) — à réappliquer après chaque mise à jour/déploiement qui le restaurerait (ex. `composer install` recrée l'arborescence `core/`).

Dans tous les cas : **relancer `test_drupal2root.sh`/`Test-Drupal2Root.ps1` une dernière fois** et confirmer `[CORRIGÉ]` avant de considérer la faille traitée.

## Limites connues

- Ce script est un inventaire de version du code source, pas un test d'intrusion : il ne prouve pas l'absence de compromission passée (une exploitation a été signalée en production dès le 19/11/2026 — si une installation vulnérable est trouvée, envisager une vérification d'intégrité, pas seulement une mise à jour).
- **Recherche bornée aux emplacements usuels et au système de fichiers local (`-xdev` côté Linux)** : un docroot Drupal situé sur un volume/montage séparé, ou dans un emplacement non standard, ne sera pas trouvé automatiquement — à vérifier manuellement si un tel déploiement existe.
- Drupal 7 et antérieur ne sont pas détectés par ce script (architecture différente, voir plus haut) — hors périmètre de cette CVE précise de toute façon.
- La permission du fichier `settings.php` est remontée à titre indicatif (`Test-Drupal2Root.ps1` ne la vérifie pas, `test_drupal2root.sh` oui) : elle ne change jamais le verdict `[VULNÉRABLE]`/`[CORRIGÉ]`, une permission restrictive ne mitige qu'une partie des chemins d'exploitation selon l'avis officiel lui-même.
- Ce script ne vérifie pas si la mitigation « accès bloqué à install.php » a été appliquée côté configuration du serveur web — seule la version du code compte pour le verdict, par prudence (zéro faux négatif accepté silencieusement).
- `Test-Drupal2Root.ps1` (Windows) : Drupal sous Windows natif est rare (pas de build officiel) — la recherche se limite à quelques emplacements usuels (IIS, XAMPP, WAMP, Laragon) ; le cas le plus probable sous Windows reste un conteneur Docker Desktop (WSL2), couvert par ce script.

## Impact sur nos solutions

| Solution | Statut | Remarque |
|---|---|---|
| Proxmox VE | Non impacté | L'interface de gestion Proxmox (pveproxy) n'utilise pas Drupal |
| Docker | À vérifier | Dépend si un conteneur fait tourner Drupal Core en version vulnérable |
| LXC | À vérifier | Dépend si le conteneur fait tourner Drupal Core en version vulnérable |
| Veeam | Non impacté | |
| Nakivo | Non impacté | |
| 3CX | Non impacté | 3CX embarque son propre nginx, pas Drupal |
| Elastix | Non impacté | FreePBX/Elastix utilise son propre framework d'administration (pas Drupal) |
| Andrisoft WANGuard | Non impacté | Console web PHP, aucune indication d'une dépendance Drupal |
| Datalust Seq | Non impacté | Application .NET avec serveur web intégré (Kestrel), pas Drupal |
| LibreNMS | Non impacté | Application PHP indépendante, pas basée sur Drupal |
| Observium | Non impacté | Application PHP indépendante, pas basée sur Drupal |
| Debian | Non impacté | L'OS lui-même n'est pas en cause -- Drupal n'est pas un paquet système, voir dossier applicatif concerné |
| Ubuntu | Non impacté | Idem Debian |
| Windows Server (2012/2016/2019/2022/2025) | À vérifier | Drupal sous Windows est rare (pas de build officiel) mais possible via IIS+PHP ou Docker Desktop |
| SMB (Samba, Debian) | Non impacté | |
| SFTP (Debian) | Non impacté | |
| Cisco | Non impacté | |
| Ubiquiti | Non impacté | |
| HP/Aruba | Non impacté | |
| FortiGate | Non impacté | |
| FortiAnalyzer | Non impacté | |
| FortiManager | Non impacté | |
| Sophos | Non impacté | |
| nginx | Non impacté | nginx n'est pas Drupal ; s'il sert de reverse-proxy devant un site Drupal, vérifier Drupal séparément (voir `nginx2root/`) |
| Certbot | Non impacté | Certbot ne fait qu'éditer la configuration TLS, aucun lien avec Drupal |
| Odoo (self-hosted) | Non impacté | Odoo est un framework Python/Flask, aucune dépendance Drupal |
| Nextcloud | Non impacté | Nextcloud est une application PHP indépendante (Symfony-based elle aussi, mais pas Drupal) |
| JumpCloud | Non impacté | |
| Python | Non impacté | |
| Django | Non impacté | |
| React | Non impacté | |
| PHP | À vérifier | Le moteur PHP lui-même n'est pas en cause, mais Drupal nécessite une version PHP minimale (8.1+ pour Drupal 10, selon la version) -- un correctif Drupal peut imposer une mise à jour PHP associée, voir `php2shell/`/`php-novembre-2026/` pour les failles propres à PHP |
| MikroTik | Non impacté | |
| Ceph | Non impacté | |
| QEMU-KVM | Non impacté | |

## Références

- [Avis officiel SA-CORE-2026-017](https://www.drupal.org/sa-core-2026-017)
- [NVD — CVE-2026-132165](https://nvd.nist.gov/vuln/detail/CVE-2026-132165)
- [CISA KEV — Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Drupal 8 — fin de vie (PSA 2021-06-29)](https://www.drupal.org/psa-2021-06-29)
- [Drupal 9 — fin de vie (PSA 2023-11-01)](https://www.drupal.org/psa-2023-11-01)
- [Securing the installer (install.php)](https://www.drupal.org/docs/administering-a-drupal-site/security-in-drupal/securing-the-installer-installphp)
- [Image Docker officielle `drupal`](https://hub.docker.com/_/drupal)
