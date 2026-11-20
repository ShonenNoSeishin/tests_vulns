# Lot de correctifs de sécurité PHP du 19/11/2026 (18 CVE)

> PHP a publié le **19/11/2026** une mise à jour corrigeant **18 CVE distinctes** dans **PHP 8.2.36, 8.3.37, 8.4.28, 8.5.13** (et sorti PHP 8.6.0 en version stable). Les deux plus graves confirmées (CVSS 9.2, **CVSS v4.0**) permettent une **exécution de code à distance**, mais nécessitent des conditions précises (voir ci-dessous) — ce n'est **pas** une RCE triviale en configuration par défaut comme NGINX2Root ou PHP2Shell.
>
> ⚠️ **Ce lot est SÉPARÉ de PHP2Shell** (`php2shell/`, CVE-2026-109618/109619, publié le 21/10/2026) : **aucune CVE en commun**. Les deux dossiers coexistent, ne pas les confondre.

## En 30 secondes

| | |
|---|---|
| **Suis-je concerné ?** | Un serveur exécute PHP (Apache, nginx + PHP-FPM, IIS, XAMPP/WAMP, conteneur Docker PHP…), en version antérieure à **8.2.36 / 8.3.37 / 8.4.28 / 8.5.13** selon la branche installée. |
| **Comment tester ?** | `sudo ./test_php-novembre-2026.sh --scan-images` (Linux) · `.\Test-PhpNovembre2026.ps1 -ScanImages` (Windows). Lecture seule. |
| **Comment corriger ?** | `apt install --only-upgrade 'php*'` puis redémarrer php-fpm/Apache ; reconstruire les images Docker. **Debian a déjà le correctif en dépôt (vérifié 20/11/2026) ; Ubuntu n'a pas encore publié d'USN pour ce lot précis** — revérifier avec le script après toute mise à jour. |

## Explication courte

Le 19/11/2026, PHP a publié une mise à jour de sécurité corrigeant 18 CVE réparties sur plusieurs composants du moteur (Core, CGI, Date, DOM, FPM, Session, SOAP, URI, Standard, Phar). La plupart nécessitent une configuration ou un enchaînement précis pour être exploitées (voir le détail des deux plus graves ci-dessous) — l'annonce officielle de PHP précise elle-même que les scénarios notés **CRITICAL** demandent une configuration non standard ou un montage peu commun. Ce n'est donc pas une RCE "point-and-shoot" en configuration par défaut, mais plusieurs de ces failles restent exploitables en conditions réalistes sur des configurations courantes (PHP-FPM derrière nginx/Apache, applications utilisant les sessions ou SOAP).

### Les deux CVE confirmées les plus graves (CVSS 9.2, CVSS v4.0 — vérifié directement sur les avis GHSA officiels)

| CVE | Composant | Branches affectées | Condition d'exploitation démontrée |
|---|---|---|---|
| **CVE-2026-129474** | Core — use-after-free dans les backtraces de méthode magique (`__call`/`__callStatic`) | **PHP 8.5.x uniquement** (< 8.5.13) | Nécessite `fatal_error_backtraces=1` (activé par défaut sur 8.5) **et** `zend.exception_ignore_args=0`. `php.ini-production` met cette dernière à `1` et bloque ce chemin d'attaque précis — `php.ini-development` la met à `0`. |
| **CVE-2026-129496** | Date — use-after-free du cache de fuseau horaire | **Toutes les branches** (8.2, 8.3, 8.4, 8.5) | Le déclencheur exact dépend du mode (PHP-FPM : `auto_globals_jit=0` + cookies dans `request_order` ; Apache `mod_php` : requête POST dépassant la limite mémoire configurée + en-tête `Authorization` large). L'éditeur précise que ce sont des conditions de la démonstration, pas des prérequis généraux de la faille mémoire sous-jacente — ne pas supposer "pas concerné" juste parce que ces réglages précis sont absents.

### Les 16 autres CVE du lot (sévérité individuelle non confirmée par avis officiel distinct à ce jour)

| CVE | Composant | Résumé |
|---|---|---|
| CVE-2026-129182 | Core | Use-after-free via repopulation de `last_fatal_error_backtrace` après l'arrêt du moteur |
| CVE-2026-129538 | CGI | Lecture/écriture hors limites dans `php-cgi` pendant la correction de `PATH_INFO` |
| CVE-2026-129501 | DOM | Double free pendant la sérialisation XML DOM |
| CVE-2026-129291 | FPM | Use-after-free epoll dans PHP-FPM — **élévation de privilège locale**, pas une RCE distante |
| CVE-2026-129289 | FPM | Contrebande de requête (request smuggling) via un corps de requête HTTP non lu |
| CVE-2026-129292 | FPM | XSS sur l'endpoint de statut PHP-FPM (`/status`) |
| CVE-2026-129481 | Session | Use-after-free après un arrêt de session interrompu |
| CVE-2026-126714 | Session | Fichiers de session partiellement écrasés — peut mener à une RCE selon le contexte applicatif |
| CVE-2026-115560 | Session | Incohérence du sérialiseur de session — peut mener à une RCE selon le contexte applicatif |
| CVE-2026-15353 | SOAP | Divulgation d'information via des dimensions de tableau malformées |
| CVE-2026-129506 | SOAP | Use-after-free lors du traitement des références d'entité DTD |
| CVE-2026-48841 | URI | Mise à niveau de la bibliothèque `uriparser` vers 1.0.3 (corrige des failles amont de cette lib) |
| CVE-2026-129438 | URI | Sérialisation URI RFC 3986 incorrecte pour une entrée surdimensionnée |
| CVE-2026-128064 | Standard | URLs HTTPS/FTPS en casse mixte pouvant exposer des données en clair |
| CVE-2026-127960 | Standard | Déni de service via des en-têtes HTTP repliés (folded headers) |
| CVE-2026-128090 | Phar | Contournement de signature OpenSSL PHAR via déclassement d'algorithme |

**Aucun exploit public ni PoC connu à ce jour (20/11/2026)** — le lot a été publié la veille. Pas encore d'entrée au catalogue KEV CISA.

### Versions corrigées par branche

| Branche | Version corrigée minimale |
|---|---|
| 8.5 | **8.5.13** |
| 8.4 | **8.4.28** |
| 8.3 | **8.3.37** |
| 8.2 | **8.2.36** |
| 8.6 | Sorti directement en version stable (8.6.0), intègre déjà tous ces correctifs |
| ≤ 8.1 (7.x, 5.x…) | Fin de vie : **pas de correctif officiel pour ce lot**. À migrer ou isoler. |

Une version >= au seuil de sa branche corrige **toutes** les CVE de ce lot applicables à cette branche (certaines, comme CVE-2026-129474, ne touchent qu'une seule branche — le seuil par branche reste le bon critère, pas besoin de vérifier CVE par CVE).

> ⚠️ **Piège Debian** : le correctif y est **rétroporté dans le paquet** sans changer le numéro `PHP_VERSION` rendu par le binaire — même mécanisme que pour PHP2Shell (voir `php2shell/README.md`). **Vérifié par fetch direct de `security-tracker.debian.org` le 20/11/2026 : Debian a DÉJÀ le correctif en dépôt**, confirmé aussi en conditions réelles (conteneur Debian 12 et 13 à jour, voir plus bas) :
>
> | Distribution | Branche PHP | Paquet corrigé | Avis |
> |---|---|---|---|
> | Debian 12 (bookworm) | 8.2 | `php8.2-*` **8.2.36-1~deb12u1** | DLA-4916-1 |
> | Debian 13 (trixie) | 8.4 | `php8.4-*` **8.4.28-1~deb13u1** | DSA-6641-1 |
>
> Debian ne propose pas de paquet officiel `php8.3-*` ni `php8.5-*` (comme pour PHP2Shell) — seules les branches 8.2 (bookworm) et 8.4 (trixie) existent en paquet système Debian.
>
> ⚠️ **Piège Ubuntu, dans l'autre sens** : **aucune USN (Ubuntu Security Notice) retrouvée pour ce lot précis au 20/11/2026** (lot publié il y a seulement un jour — Canonical n'a pas encore backporté, ou pas encore publié l'avis). Le script le gère **sans deviner** : tout paquet PHP Ubuntu officiel ressort `[À VÉRIFIER]`, jamais `[CORRIGÉ]` ni `[VULNÉRABLE]` par déduction, tant qu'aucune table de correctif fiable n'existe pour cette combinaison — **à revérifier régulièrement** sur <https://ubuntu.com/security/notices/> et à mettre à jour dans ce script dès qu'une USN sort.

## Mitigation en attendant un correctif (branche 8.5 uniquement, CVE-2026-129474)

Si la mise à jour vers 8.5.13 n'est pas immédiatement possible sur une branche 8.5 : vérifier que `zend.exception_ignore_args` vaut **1** dans le `php.ini` actif (c'est la valeur par défaut de `php.ini-production`, mais `php.ini-development` la met à `0`). Cela bloque le chemin d'attaque précisément démontré par l'avis officiel, sans garantir l'absence d'un autre vecteur — **la mise à jour reste la seule correction complète**. Aucune mitigation de configuration connue pour les 17 autres CVE du lot.

## Comment faire la vérification

Un seul fichier par plateforme, aucune dépendance :

```bash
chmod +x test_php-novembre-2026.sh
./test_php-novembre-2026.sh                # mode lecture seule (par défaut)
./test_php-novembre-2026.sh --scan-images  # + sonde les images Docker/Podman locales
```

```powershell
.\Test-PhpNovembre2026.ps1
.\Test-PhpNovembre2026.ps1 -ScanImages
```

Mêmes modes, mêmes lignes de verdict (`[VULNÉRABLE]` / `[À VÉRIFIER]` / `[CORRIGÉ]` / `[NON CONCERNÉ]`) et ligne finale « Confiance » que les autres scripts de ce dépôt (voir `php2shell/README.md` section « Comment être sûr du résultat » pour le détail complet — logique identique ici).

## Comment corriger

**Action L1** pour Debian (correctif déjà disponible) :
```bash
apt update && apt install --only-upgrade 'php*'
systemctl restart 'php*-fpm' apache2 nginx 2>/dev/null
```
Relancer le script : doit afficher `[CORRIGÉ]`.

**Pour Ubuntu** : tant qu'aucune USN n'est publiée pour ce lot, `apt install --only-upgrade 'php*'` ne corrigera rien de spécifique à ce lot (le script le signalera en `[À VÉRIFIER]`, pas en `[CORRIGÉ]`, précisément pour éviter la fausse réassurance). Surveiller <https://ubuntu.com/security/notices/> et relancer le script régulièrement jusqu'à ce qu'une USN couvrant ce lot sorte.

**Image Docker officielle PHP** :
```bash
docker pull php:<tag-reconstruit-après-le-19/11/2026>
docker compose up -d --force-recreate
```

**PHP ≤ 8.1 (fin de vie)** : migrer vers 8.2+ ou isoler le service — pas de correctif officiel pour ce lot.

## Limites connues

- Ce script est un inventaire de versions, pas un test d'intrusion : il ne prouve pas l'absence de compromission passée.
- La vérification par paquet distro (bash uniquement) ne couvre que Debian 12/13 pour ce lot précis. Ubuntu ressort systématiquement `[À VÉRIFIER]` tant qu'aucune USN n'est référencée (voir avertissement ci-dessus) — ce n'est pas un défaut du script, c'est le résultat honnête de l'absence d'information officielle à ce jour.
- `Test-PhpNovembre2026.ps1` (Windows) ne fait pas de vérification par paquet : pas d'équivalent `dpkg`/APT sous Windows pour XAMPP/WAMP/IIS.
- La plupart des 18 CVE nécessitent des conditions précises (voir tableaux ci-dessus) : un résultat `[VULNÉRABLE]` signale une version non corrigée, pas une confirmation d'exploitabilité immédiate dans votre configuration exacte — mais mettre à jour reste la seule action sûre.
- `kubectl`/`lxc`/`nerdctl`/`crictl` sont seulement signalés comme présents, pas sondés automatiquement.

## Validation (VM de Lab, 20/11/2026)

Aucune installation PHP trouvée sur la VM de Lab elle-même (hôte ni conteneurs actifs — voir `ir-context/deep-dive/php-novembre-2026/lab-results.md`, privé). La logique de détection a été validée avec des conteneurs Debian/Ubuntu jetables :
- Conteneur Debian 13 (trixie) à jour : paquet réel `php8.4-cli 8.4.28-1~deb13u1` → `[CORRIGÉ]` (confirmé en conditions réelles, le dépôt Debian a déjà le correctif).
- Conteneur Debian 12 (bookworm) à jour : paquet réel `php8.2-cli 8.2.36-1~deb12u1` → `[CORRIGÉ]`.
- Conteneur Ubuntu 24.04 à jour : paquet réel `php8.3-cli 8.3.6-0ubuntu0.24.04.14` → `[À VÉRIFIER]` (confirmé : aucune USN pour ce lot, le script ne devine pas).
- Comparaisons de version `dpkg --compare-versions` validées directement pour les deux sens (vulnérable avant patch, corrigé après).

## Impact sur nos solutions

| Solution | Statut | Remarque |
|---|---|---|
| Proxmox VE | Non impacté |  |
| Docker | À vérifier | Dépend si un conteneur embarque une version PHP vulnérable |
| LXC | À vérifier | Dépend si le conteneur embarque une version PHP vulnérable |
| Veeam | Non impacté |  |
| Nakivo | Non impacté |  |
| 3CX | Non impacté |  |
| Elastix | À vérifier | Distributions PBX type FreePBX embarquent souvent une interface d'administration PHP -- vérifier la version |
| Andrisoft WANGuard | À vérifier | La console WANGuard a une interface web PHP -- vérifier la version |
| Datalust Seq | Non impacté |  |
| LibreNMS | À vérifier | Application PHP -- impact dépend de la version PHP utilisée par l'hôte |
| Observium | À vérifier | Application PHP -- impact dépend de la version PHP utilisée par l'hôte |
| Debian | Non impacté | L'OS lui-même n'est pas en cause -- paquet PHP déjà corrigé en dépôt (voir ci-dessus) |
| Ubuntu | Non impacté | L'OS lui-même n'est pas en cause -- mais aucune USN pour ce lot à ce jour, voir avertissement ci-dessus |
| Windows Server (2012/2016/2019/2022/2025) | À vérifier | Impacté seulement si IIS+PHP via FastCGI est configuré -- voir Test-PhpNovembre2026.ps1 |
| SMB (Samba, Debian) | Non impacté |  |
| SFTP (Debian) | Non impacté |  |
| Cisco | Non impacté |  |
| Ubiquiti | Non impacté |  |
| HP/Aruba | Non impacté |  |
| FortiGate | Non impacté |  |
| FortiAnalyzer | Non impacté |  |
| FortiManager | Non impacté |  |
| Sophos | Non impacté |  |
| nginx | Non impacté | nginx lui-même n'est pas écrit en PHP ; vérifier le PHP-FPM derrière, pas nginx |
| Certbot | Non impacté |  |
| Odoo (self-hosted) | Non impacté | Odoo est écrit en Python, pas en PHP |
| Nextcloud | À vérifier | Application PHP -- impact dépend de la version PHP utilisée |
| JumpCloud | Non impacté |  |
| Python | Non impacté |  |
| Django | Non impacté |  |
| React | Non impacté |  |
| PHP | Impacté | Moteur directement concerné |
| MikroTik | Non impacté |  |
| Ceph | Non impacté |  |
| QEMU-KVM | Non impacté |  |

## Références

- [php.net — archive des annonces 2026](https://www.php.net/archive/2026.php)
- [php.net — ChangeLog PHP 8](https://www.php.net/ChangeLog-8.php)
- GHSA-8mjj-2r7p-4hg2 (CVE-2026-129474) : <https://github.com/php/php-src/security/advisories/GHSA-8mjj-2r7p-4hg2>
- GHSA-gr4f-wgx5-jpfv (CVE-2026-129496) : <https://github.com/php/php-src/security/advisories/GHSA-gr4f-wgx5-jpfv>
- Debian Security Tracker : <https://security-tracker.debian.org/>
- Ubuntu Security Notices : <https://ubuntu.com/security/notices/>
