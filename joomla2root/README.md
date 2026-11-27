# CVE-2026-123214 — « Joomla2Root »

> Un défaut d'**authentification manquante dans l'installeur web** de **Joomla CMS**, avis officiel **[20261111] - Core - Missing authentication in web installer**. Tant que le dossier `/installation` existe encore sur un site Joomla **déjà installé**, un attaquant **sans authentification** peut relancer l'installeur et **réécrire `configuration.php`** (identifiants d'accès, base de données) → **prise de contrôle complète du site**. CVSS 4.0 **9.2 Critical** (attribué le 24/11/2026), mais l'avis Joomla lui-même qualifie la **probabilité** d'exploitation de **modérée**, pas critique — nuance importante détaillée ci-dessous. Corrigé le 24/11/2026 en **5.4.11** / **6.2.1**.

## En 30 secondes

| | |
|---|---|
| **Suis-je concerné ?** | Tout site **Joomla** en version **4.0.0 à 5.4.10**, ou **6.0.0 à 6.2.0** — **ET** le dossier `/installation` encore présent sur le serveur (précondition réelle de l'exploitation, voir ci-dessous). |
| **Comment tester ?** | `sudo ./test_joomla2root.sh --scan-images` (Linux) · `.\Test-Joomla2Root.ps1 -ScanImages` (Windows, surtout utile pour Docker Desktop). Lecture seule, aucune requête envoyée à un serveur distant. |
| **Comment corriger ?** | Mettre à jour Joomla vers **5.4.11** ou **6.2.1** selon la branche, **et** supprimer le dossier `/installation` par bonne pratique (recommandé même après la mise à jour), puis **revérifier avec le script**. |

## Explication courte

Joomla installe un dossier `/installation` à la racine du site pour l'assistant d'installation initial. Une fois le site installé, ce dossier est censé être supprimé ou devenir inopérant — mais l'avis officiel Joomla révèle que **l'installeur reste utilisable sur un site déjà installé** tant que ce dossier n'est pas supprimé manuellement, sans authentification requise. Un attaquant peut alors relancer l'assistant d'installation et **réécrire `configuration.php`** (identifiants de connexion à la base de données, clé secrète, informations d'accès admin) → prise de contrôle complète du site.

**Nuance importante sur la sévérité, à bien comprendre avant de prioriser** : le vecteur CVSS 4.0 officiel est `CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` — score de base **9.2 (Critical)**. Le segment `AT:P` (« Attack Requirements: Present ») signifie qu'**une condition d'exploitation supplémentaire est nécessaire** : concrètement, le dossier `/installation` doit être encore présent. L'avis Joomla lui-même affiche cette faille avec **Impact : Critical**, mais **Probabilité : Low**, et un score composite **« Moderate »** dans sa propre grille de risque — Joomla considère que la plupart des hébergements suivent déjà la bonne pratique de supprimer ce dossier après l'installation initiale. **Ce n'est cependant pas une raison de la négliger** : c'est une négligence plausible et fréquente (beaucoup de déploiements automatisés, de migrations, ou de simples oublis laissent ce dossier en place), et un redéploiement futur (`composer install`, ré-extraction d'une archive de mise à jour) peut **recréer** le dossier même s'il avait été supprimé auparavant.

**Différence importante avec `nginx2root/`/`apache2root/`/`php2shell/`** : Joomla n'est **pas** distribué via un paquet système (`apt`/`dnf`/`apk`) — c'est une application PHP déployée en code (archive officielle, Composer dans certains cas) dans un dossier web, exactement comme Drupal (voir `drupal2root/`). Il n'existe donc **aucune table de rétroportage distro** à vérifier ici : la version qui compte est directement celle du code source Joomla présent sur le disque (fichier `libraries/src/Version.php`, constantes `MAJOR_VERSION`/`MINOR_VERSION`/`PATCH_VERSION`), pas un numéro de paquet `dpkg -l`.

### Versions concernées / corrigées

| Branche | Versions vulnérables | Corrigé |
|---|---|---|
| Joomla 4.x / 5.x (branche continue, numérotation séquentielle) | **4.0.0 à 5.4.10** | **5.4.11** |
| Joomla 6.x | **6.0.0 à 6.2.0** | **6.2.1** |
| Joomla 3.x et antérieur | Architecture différente (fichier `libraries/cms/version/version.php`, pas celui visé par ce CVE) — **non couvert par cette fiche**, voir Limites connues | — |

> ⚠️ **Piège de version — à bien comprendre** : la correction n'est **pas** un simple patch de sécurité appliqué à une ancienne version mineure. Joomla ne publie de correctif de sécurité que sur la **dernière version mineure de la branche active** (`5.4.11`, `6.2.1`) : si votre site est resté sur une version intermédiaire plus ancienne (ex. `5.2.0`), il n'existe **aucun correctif dédié** pour cette version précise — la seule voie est de mettre à jour **jusqu'à** `5.4.11` (ou `6.2.1`), ce qui peut inclure plusieurs mises à jour mineures successives. Ce n'est pas comparable à un rétroportage distro (qui patche une version figée sans la faire avancer) : c'est une mise à jour d'application classique, mais potentiellement en plusieurs étapes selon l'ancienneté de départ — **tester la compatibilité des extensions/templates tiers avant une mise à jour qui saute plusieurs versions mineures**, surtout en production.

## Démonstration : comment vérifier qu'une cible est vulnérable

**Méthode recommandée, sans risque : l'inventaire de version du code source + la présence du dossier `/installation`.** C'est ce que fait le script de ce dossier : il cherche chaque installation Joomla (hôte, conteneurs, images Docker/Podman) via le fichier `libraries/src/Version.php`, lit les constantes de version, les compare au seuil corrigé de sa branche, **et** vérifie séparément si `/installation` existe encore — à titre d'information sur l'urgence réelle, jamais comme critère d'exclusion (une version vulnérable sans `/installation` reste `[VULNÉRABLE]`, car ce dossier peut être recréé). Aucune requête HTTP n'est envoyée à un serveur — sûr à lancer en production.

**Méthode active (test d'intrusion) — réservée à un labo isolé, jamais en production sans autorisation écrite :** l'avis officiel ne détaille pas publiquement la séquence HTTP exacte permettant de relancer l'installeur. Ce dépôt ne fournit pas de preuve de concept exécutable : l'inventaire de version + la vérification du dossier `/installation` suffisent dans l'immense majorité des cas à savoir si vous êtes concerné.

## Comment faire la vérification

Un seul fichier par plateforme, aucune dépendance :

```bash
chmod +x test_joomla2root.sh
./test_joomla2root.sh                # mode lecture seule (par défaut)
./test_joomla2root.sh --scan-images  # + sonde les images Docker/Podman locales
```

```powershell
.\Test-Joomla2Root.ps1
.\Test-Joomla2Root.ps1 -ScanImages
```

## Comment corriger

**Action L1 — mise à jour standard via le gestionnaire de mises à jour Joomla (interface d'administration) :**
1. Dans l'administration Joomla : *Système → Maintenance → Mises à jour* (ou `com_joomlaupdate`), appliquer la mise à jour jusqu'à la dernière version de la branche (**5.4.11** si vous êtes sur la branche 4.x/5.x, **6.2.1** si vous êtes sur la branche 6.x). Si votre version de départ est ancienne, plusieurs mises à jour successives peuvent être nécessaires — **sauvegarder le site avant** (base de données + fichiers).
2. **Toujours, quelle que soit la version** : **supprimer le dossier `/installation`** à la racine du site (`rm -rf installation/` ou via le gestionnaire de fichiers de l'hébergement). C'est la mitigation directe de cette CVE précise — recommandée même sur une version déjà corrigée, par bonne pratique de durcissement, et à **réappliquer après chaque mise à jour/redéploiement** qui recréerait ce dossier.
3. **Revérifier avec le script** (`./test_joomla2root.sh`) : doit afficher `[CORRIGÉ]` sans mention du dossier `/installation`.

**Si une mise à jour en une seule fois n'est pas possible (version très ancienne, incompatibilités d'extensions à tester) — à escalader équipe sécu/infra :** planifier une migration par étapes (mise à jour progressive de version mineure en version mineure jusqu'au seuil corrigé), pas une action L1 immédiate. En attendant, appliquer la mitigation ci-dessous.

**Mitigation immédiate, si la mise à jour doit attendre (réduit l'exposition à cette CVE précise sans toucher au code Joomla) :**
```bash
rm -rf /chemin/vers/le/site/installation
```
C'est la mitigation **la plus efficace et la plus simple** pour cette faille précise : sans ce dossier, le vecteur d'exploitation documenté par l'avis officiel n'est plus accessible, même sur une version non encore mise à jour. Elle ne corrige pas la version du code (toujours vulnérable en théorie si le dossier est un jour recréé), mais elle neutralise l'exposition réelle immédiatement.

**Image Docker officielle `joomla` :**
```bash
docker pull joomla:5.4.11   # ou joomla:6.2.1 selon la branche
docker compose up -d --force-recreate
```
Un `docker-compose.yml` qui épingle un tag de version précis (`joomla:5.4.10`...) reste vulnérable tant que ce tag n'est pas changé manuellement — vérifier le tag réellement utilisé. **Au moment de la rédaction de cette fiche (27/11/2026), les tags `5.4.11`/`6.2.1` n'étaient pas encore publiés sur Docker Hub** — vérifier leur disponibilité avant de lancer cette commande ; en attendant, appliquer la mitigation `/installation` ci-dessus même en conteneur.

Dans tous les cas : **relancer `test_joomla2root.sh`/`Test-Joomla2Root.ps1` une dernière fois** et confirmer `[CORRIGÉ]` (sans mention du dossier `/installation` encore présent) avant de considérer la faille traitée.

## Limites connues

- **Joomla 3.x et antérieur ne sont PAS couverts par cette fiche** : leur fichier de version (`libraries/cms/version/version.php`, constantes différentes) n'est pas celui recherché par ce script, qui vise la structure introduite avec Joomla 4. Joomla 3.x est lui-même en fin de vie depuis longtemps — s'il en existe encore dans le parc, c'est un risque à part, hors du périmètre de cette CVE précise (l'avis officiel ne couvre que les versions 4.0.0 et ultérieures).
- Recherche limitée au système de fichiers racine (`-xdev`) : un docroot Joomla vivant sur un volume/montage séparé (bash) ou un disque/lettre dédié (PowerShell, hors des emplacements usuels listés) ne sera pas trouvé par défaut.
- La détection du dossier `/installation` est un simple test de présence (`-d`) — elle ne vérifie pas si le dossier a été vidé de son contenu exécutable tout en gardant son nom (cas atypique, mais possible). En cas de doute, vérifier manuellement la présence du fichier `installation/index.php`.
- Comme pour `drupal2root/`, aucune preuve de concept HTTP n'est fournie ou testée ici : seule la version du code et la présence du dossier `/installation` sont vérifiées.

## Impact sur nos solutions

| Solution | Statut | Remarque |
|---|---|---|
| Proxmox VE | Non impacté | L'interface de gestion Proxmox (pveproxy) n'utilise pas Joomla |
| Docker | À vérifier | Dépend si un conteneur fait tourner Joomla en version vulnérable avec `/installation` présent |
| LXC | À vérifier | Dépend si le conteneur fait tourner Joomla en version vulnérable avec `/installation` présent |
| Veeam | Non impacté | — |
| Nakivo | Non impacté | — |
| 3CX | Non impacté | 3CX embarque son propre nginx, pas Joomla |
| Elastix | Non impacté | FreePBX/Elastix utilise son propre framework d'administration, pas Joomla |
| Andrisoft WANGuard | Non impacté | Console web PHP, aucune indication d'une dépendance Joomla |
| Datalust Seq | Non impacté | Application .NET avec serveur web intégré (Kestrel), pas Joomla |
| LibreNMS | Non impacté | Application PHP indépendante, pas basée sur Joomla |
| Observium | Non impacté | Application PHP indépendante, pas basée sur Joomla |
| Debian | Non impacté | L'OS lui-même n'est pas en cause — Joomla n'est pas un paquet système |
| Ubuntu | Non impacté | L'OS lui-même n'est pas en cause — Joomla n'est pas un paquet système |
| Windows Server (2012/2016/2019/2022/2025) | À vérifier | Joomla sous Windows est rare (pas de build officiel) mais possible via IIS+PHP ou Docker Desktop |
| SMB (Samba, Debian) | Non impacté | — |
| SFTP (Debian) | Non impacté | — |
| Cisco | Non impacté | — |
| Ubiquiti | Non impacté | — |
| HP/Aruba | Non impacté | — |
| FortiGate | Non impacté | — |
| FortiAnalyzer | Non impacté | — |
| FortiManager | Non impacté | — |
| Sophos | Non impacté | — |
| nginx | Non impacté | nginx n'est pas Joomla ; s'il sert de reverse-proxy devant un site Joomla, vérifier Joomla séparément |
| Certbot | Non impacté | Certbot ne fait qu'éditer la configuration TLS, aucun lien avec Joomla |
| Odoo (self-hosted) | Non impacté | Odoo est un framework Python/Flask, aucune dépendance Joomla |
| Nextcloud | Non impacté | Nextcloud est une application PHP indépendante, pas basée sur Joomla |
| JumpCloud | Non impacté | — |
| Python | Non impacté | — |
| Django | Non impacté | — |
| React | Non impacté | — |
| PHP | À vérifier | Le moteur PHP lui-même n'est pas en cause, mais Joomla impose une version PHP minimale selon la branche — une mise à jour Joomla peut nécessiter une mise à jour PHP associée |
| MikroTik | Non impacté | — |
| Ceph | Non impacté | — |
| QEMU-KVM | Non impacté | — |

## Références

- [Avis officiel Joomla — [20261111] Core - Missing authentication in web installer](https://developer.joomla.org/security-centre/1109-20261111-core-missing-authentication-in-web-installer.html)
- [NVD — CVE-2026-123214](https://nvd.nist.gov/vuln/detail/CVE-2026-123214)
- [Image Docker officielle joomla](https://hub.docker.com/_/joomla)
