# CVE-2026-123007 / CVE-2026-123633 — « NGINX2Root »

> Deux failles critiques (CVSS 4.0 : 9.2) dans **nginx**, corrigées le **18/11/2026** avec un lot de 10 CVE au total. Les deux permettent une **exécution de code à distance SANS authentification**, via le protocole **HTTP/2**. CVE-2026-123007 est présente dans le code source depuis **2015** (nginx 1.9.5) : plus de 10 ans d'exposition potentielle. Un **PoC public** existe pour CVE-2026-123007.

## En 30 secondes

| | |
|---|---|
| **Suis-je concerné ?** | Un serveur fait tourner nginx (reverse-proxy, serveur web, ingress, panneau d'admin…), en version open source **antérieure à 1.30.7 (stable) ou 1.31.9 (mainline)**. |
| **Comment tester ?** | `sudo ./test_nginx2root.sh --scan-images` (Linux) · `.\Test-Nginx2Root.ps1 -ScanImages` (Windows). Lecture seule, aucune requête envoyée à un serveur distant. |
| **Comment corriger ?** | `apt update && apt install --only-upgrade nginx`, **puis revérifier avec le script** : Debian (DLA-4918-1/DSA-6642-1, 19/11/2026) et Ubuntu (USN-9159-1, 19/11/2026) ont désormais tous les deux un correctif — si malgré ça le script affiche encore `[VULNÉRABLE]`, basculer sur le dépôt officiel `nginx.org` (procédure ci-dessous). |

## Explication courte

Le 18 novembre 2026, l'éditeur de nginx (F5) a publié un correctif hors cycle pour **10 CVE** d'un coup. Les deux plus graves ne nécessitent **aucune authentification** et mènent à une **exécution de code à distance** :

- **CVE-2026-123007** : sous-dépassement d'entier (`send_window`) dans le contrôle de flux HTTP/2. Exploitable en configuration par défaut, HTTP/2 activé, sans backend applicatif particulier — démontré par des chercheurs sur un simple serveur de fichiers statiques en HTTPS.
- **CVE-2026-123633** : use-after-free dans la gestion des connexions HTTP/2, plus susceptible d'être déclenché quand nginx sert de reverse-proxy et que les connexions disponibles se raréfient.

Les deux ne s'appliquent que si **HTTP/2 est activé** sur le bloc serveur concerné. Les 8 autres CVE du même lot (résolveur DNS, HTTP/3, proxy mail, TLS 1.3, protocole PROXY v2, `alias`/`try_files`, SNI, `ssl_preread`) ont des conditions différentes et **ne dépendent pas de HTTP/2** — c'est pour cela que ce script recommande de mettre à jour même si HTTP/2 est désactivé.

Un instantané public (Shodan, 10/11/2026, avant correctif) indiquait que **98,9 % des instances nginx identifiables par version** tournaient dans la plage vulnérable.

### Versions concernées / corrigées

| Produit | CVE | Versions vulnérables | Corrigé |
|---|---|---|---|
| nginx open source | CVE-2026-123007 | 1.9.5 → 1.31.8 | **1.30.7** (branche stable) ou **1.31.9** (branche mainline) |
| nginx open source | CVE-2026-123633 | 1.19.7 → 1.31.8 | 1.30.7 ou 1.31.9 |
| nginx Plus | CVE-2026-123007 | R33, 37.0.0 → 37.2.x | 37.0.8.1 / 37.3.0.1 |
| nginx Plus | CVE-2026-123633 | R33, 37.0.0 → 37.2.x | 37.0.7.1 / 37.2.0.1 |

> ⚠️ **Piège de version — Debian ET Ubuntu rétroportent sans changer le numéro amont (mise à
> jour du 20/11/2026 : c'est maintenant vrai des deux côtés)** :
>
> - **Debian** : **aucun correctif jusqu'au 19/11/2026** (confirmé la veille sur
>   `security-tracker.debian.org`, `trixie`/`bookworm` encore « vulnerable »). Depuis le
>   **19/11/2026**, Debian a publié **DLA-4918-1** (bookworm, LTS) et **DSA-6642-1** (trixie,
>   Debian 13), qui corrigent les deux CVE **sans changer le numéro de version amont** — un
>   `nginx -v` sur un `trixie` corrigé affiche toujours `nginx/1.26.3`. Le script compare donc
>   désormais le **paquet dpkg** à la table ci-dessous pour Debian aussi, jamais `nginx -v` seul.
> - **Ubuntu** : Canonical a publié **USN-9159-1 le 19/11/2026**, même piège (ex. Ubuntu 22.04
>   "corrigé" reste `nginx/1.18.0` côté `nginx -v`, seul le suffixe de paquet dpkg change,
>   `1.18.0-6ubuntu14.23`).
>
> | Distribution (codename) | Paquet nginx corrigé | Avis | Remarque |
> |---|---|---|---|
> | Debian 13 (trixie) | `1.26.3-3+deb13u11` | DSA-6642-1 | |
> | Debian 12 (bookworm) | `1.22.1-9+deb12u11` | DLA-4918-1 | LTS |
> | Ubuntu 26.10 (stonking) | `1.30.4-7ubuntu1.2` | USN-9159-1 | |
> | Ubuntu 26.04 LTS (resolute) | `1.28.3-2ubuntu1.13` | USN-9159-1 | |
> | Ubuntu 24.04 LTS (noble) | `1.24.0-2ubuntu7.20` | USN-9159-1 | |
> | Ubuntu 22.04 LTS (jammy) | `1.18.0-6ubuntu14.23` | USN-9159-1 | |
> | Ubuntu 20.04 LTS (focal) | `1.18.0-0ubuntu1.7+esm5` | USN-9159-1 | **Ubuntu Pro/ESM requis** |
> | Ubuntu 18.04 LTS (bionic) | `1.14.0-0ubuntu1.11+esm6` | USN-9159-1 | **Ubuntu Pro/ESM requis** |
> | Ubuntu 16.04 LTS (xenial) | `1.10.3-0ubuntu0.16.04.5+esm11` | USN-9159-1 | **Ubuntu Pro (Legacy Support) requis** |
> | Ubuntu 14.04 LTS (trusty) | — | — | Non affecté selon Canonical |
>
> Validé en conditions réelles le 19/11/2026 (avant le correctif Debian) : Ubuntu 22.04 ressortait
> déjà `[CORRIGÉ]` (paquet `1.18.0-6ubuntu14.23`) malgré `nginx -v` affichant `1.18.0` ; un Debian
> 13 ressortait alors `[VULNÉRABLE]` (paquet `1.26.3-3+deb13u10`, antérieur au DSA). **Si vous avez
> suivi la bascule vers le dépôt `nginx.org` avant le 19-20/11/2026 parce que Debian n'avait pas
> encore de correctif** (voir historique de ce dossier) : ce n'est plus nécessaire pour cette
> faille précise, mais ça ne pose aucun problème de le garder — revenir au paquet Debian n'est pas
> une action prioritaire.
>
> **nginx Plus** n'est pas comparé automatiquement : sa numérotation (ex. `37.0.8.1`) ne se compare pas directement aux versions open source. Le script le signale en `[À VÉRIFIER]` plutôt que de risquer un faux résultat — comparer manuellement sur le portail support F5.

## Démonstration : comment vérifier qu'une cible est vulnérable

**Méthode recommandée, sans risque : l'inventaire de version.** C'est ce que fait le script de ce dossier : il identifie chaque binaire nginx (hôte, conteneurs, images Docker/Podman) et compare sa version aux seuils ci-dessus. Aucune requête HTTP/2 n'est envoyée à un serveur — sûr à lancer en production.

**Méthode active (test d'intrusion) — réservée à un labo isolé, jamais en production sans autorisation écrite :** le mécanisme publié consiste à envoyer une séquence de trames HTTP/2 spécialement construite (notamment de nombreuses trames `WINDOW_UPDATE` pour CVE-2026-123007) et à observer la réaction du worker nginx (plantage, redémarrage, ou preuve d'exécution de code dans un labo contrôlé).

Ce dépôt ne fournit pas de preuve de concept exécutable : un PoC publié sans vérification serait soit inopérant, soit un vrai risque entre de mauvaises mains. Dans l'immense majorité des cas, l'inventaire de version suffit à savoir si vous êtes concerné.

## Comment faire la vérification

Un seul fichier par plateforme, aucune dépendance :

```bash
chmod +x test_nginx2root.sh
./test_nginx2root.sh                # mode lecture seule (par défaut)
./test_nginx2root.sh --scan-images  # + sonde les images Docker/Podman locales
```

```powershell
.\Test-Nginx2Root.ps1
.\Test-Nginx2Root.ps1 -ScanImages
```

## Procédure de correction — Debian/Ubuntu (reverse-proxy, serveur web)

**Depuis le 19/11/2026, l'étape 1 suffit pour Debian ET Ubuntu** — Debian (DLA-4918-1 bookworm,
DSA-6642-1 trixie) et Ubuntu (USN-9159-1) ont tous les deux publié un correctif rétroporté. Le
script compare le **paquet dpkg**, pas `nginx -v`, donc il confirmera `[CORRIGÉ]` correctement
même si `nginx -v` continue d'afficher un numéro qui a l'air ancien. La bascule `nginx.org`
(étape 3) ne reste utile que si l'étape 2 montre encore `[VULNÉRABLE]` après la mise à jour — par
exemple un miroir pas encore synchronisé, un dépôt de sécurité non activé dans `/etc/apt/sources.list`,
ou un système sur une version de Debian/Ubuntu antérieure non couverte par les tables ci-dessus.

**Action L1, en 4 étapes — ne pas s'arrêter avant l'étape 4 :**

**Étape 1 — tenter la mise à jour standard du paquet distro** (rapide, sans risque) :
```bash
apt update && apt install --only-upgrade nginx
```

**Étape 2 — vérifier, obligatoire.** Relancer le script :
```bash
./test_nginx2root.sh
```
Si le résultat affiche encore `[VULNÉRABLE]` : **l'étape 1 n'a rien corrigé** (dépôt de sécurité
non à jour, miroir en retard, ou distribution non couverte par les tables ci-dessus), passer à
l'étape 3. Un message `nginx is already the newest version` **ne prouve pas** que c'est corrigé —
il veut dire « c'est la version la plus récente disponible dans vos dépôts actuels », qui peuvent
eux-mêmes être en retard sur l'avis officiel.

**Étape 3 — si toujours vulnérable après l'étape 2 : basculer sur le dépôt officiel `nginx.org`** (fonctionne dès aujourd'hui) :
```bash
sudo apt install -y curl gnupg2 ca-certificates lsb-release debian-archive-keyring
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
# Vérification de la clé (doit afficher l'empreinte 573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62) :
gpg --dry-run --quiet --no-keyring --import --import-options import-show /usr/share/keyrings/nginx-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/debian $(lsb_release -cs) nginx" \
    | sudo tee /etc/apt/sources.list.d/nginx.list
printf "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" \
    | sudo tee /etc/apt/preferences.d/99nginx

sudo apt update
sudo apt install nginx
sudo systemctl restart nginx
```
`lsb_release -cs` doit renvoyer `trixie` (Debian 13) ou `bookworm` (Debian 12) — les deux sont supportés par le dépôt officiel. Ceci remplace le paquet Debian par celui de nginx.org : les futures mises à jour de sécurité de ce paquet viendront de ce dépôt, plus de Debian. Vérifier `nginx -t` après coup (la config `/etc/nginx/` est conservée).

**Étape 4 — vérifier à nouveau, toujours :**
```bash
./test_nginx2root.sh
```
Doit maintenant afficher `[CORRIGÉ]` avec une version ≥ 1.30.7. Ne considérer la faille traitée qu'à ce moment-là.

**Branches alternatives** (pas Debian/Ubuntu) :

| Méthode d'installation | Commande |
|---|---|
| Alpine (`apk`) | `apk update && apk upgrade nginx` |
| Image Docker officielle `nginx` | `docker pull nginx:<tag>` avec un tag reconstruit après le 18/11/2026, puis `docker compose up -d --force-recreate` — **ne jamais patcher dans un conteneur en cours d'exécution** |
| nginx Plus | Suivre la procédure de mise à jour F5/nginx Plus habituelle (portail support), viser 37.0.8.1 ou 37.3.0.1 |
| Windows (installeur officiel) | Télécharger la version corrigée sur <https://nginx.org/en/download.html>, remplacer le binaire, redémarrer le service |

Pour ces branches aussi : **toujours relancer le script après coup** et confirmer `[CORRIGÉ]` plutôt que de se fier au seul outil de mise à jour.

### Contournement temporaire (nginx ≥ 1.25.1), si la mise à jour doit attendre

Désactiver HTTP/2 réduit l'exposition aux **deux** RCE (pas aux 8 autres CVE du lot) :
- Retirer le paramètre `http2` des directives `listen`, ou ajouter `http2 off;` dans les blocs serveur concernés.
- Tester la compatibilité applicative (certains clients négocient HTTP/2 par défaut), recharger nginx, vérifier que les anciens workers se sont bien terminés.
- Réactiver HTTP/2 après la mise à jour réelle — ce n'est qu'une mitigation, pas un correctif.

## Limites connues

- Ce script est un inventaire de versions, pas un test d'intrusion : il ne prouve pas l'absence de compromission passée.
- La détection du paquet système (dpkg) **décide désormais du verdict sur Debian et Ubuntu** (tables de rétroportage ci-dessus) ; sur toute autre distribution, seule la version rendue par le binaire `nginx -v` réellement utilisé compte.
- La lecture de la configuration (HTTP/2 activé ou non, via `nginx -T`) est **best-effort** : incomplète si le script ne tourne pas en root, ou si la configuration est répartie dans des fichiers non standard. Ne jamais se fier à "HTTP/2 non détecté" pour ignorer un correctif : les 8 autres CVE du lot ne dépendent pas de HTTP/2.
- `nginx Plus` n'est jamais comparé automatiquement (toujours `[À VÉRIFIER]`) : sa numérotation de build diffère trop de l'open source pour une comparaison fiable sans risque de faux résultat.
- `Test-Nginx2Root.ps1` (Windows) ne vérifie pas de paquet système (pas d'équivalent `dpkg`/`apk` sous Windows) ; les conteneurs Windows natifs (non-WSL2) ne sont pas sondés.
- `Test-Nginx2Root.ps1` : par sécurité (éviter qu'un utilisateur non administrateur dépose un faux `nginx.exe` que le script, souvent lancé en administrateur, exécuterait), **seul le `nginx.exe` résolu depuis le PATH de l'opérateur est exécuté**. Un binaire trouvé par recherche sur disque ou appartenant à un processus/service déjà en cours est lu uniquement via ses métadonnées de version (jamais exécuté) — ce qui veut dire que **nginx Plus n'est pas détectable dans ces deux cas** (seule l'exécution via `-V` révèle "Plus" ; un résultat "À VÉRIFIER : version illisible" sur un de ces chemins doit être complété à la main).
- Les ingress controllers Kubernetes basés sur nginx (`ingress-nginx`, etc.) ne sont pas spécifiquement couverts : le script détecte le binaire nginx si le conteneur est inspectable via `docker`/`podman`, mais un cluster Kubernetes managé nécessite une vérification dédiée (image de l'ingress controller).

## Impact sur nos solutions

| Solution | Statut | Remarque |
|---|---|---|
| Proxmox VE | Non impacté | L'interface de gestion Proxmox (pveproxy) n'utilise pas nginx |
| Docker | À vérifier | Dépend si un conteneur fait tourner nginx en version vulnérable |
| LXC | À vérifier | Dépend si le conteneur fait tourner nginx en version vulnérable |
| Veeam | Non impacté |  |
| Nakivo | Non impacté |  |
| 3CX | **Impacté** | 3CX (Linux, Debian) utilise nginx comme serveur web / reverse-proxy de la console et des clients web : lancer le script sur le serveur 3CX ; correctif via les mises à jour 3CX/Debian dès leur publication, HTTP/2 off en attendant |
| Elastix | Non impacté |  |
| Andrisoft WANGuard | Non impacté |  |
| Datalust Seq | Non impacté |  |
| LibreNMS | Non impacté |  |
| Observium | Non impacté |  |
| Debian | Non impacté |  |
| Ubuntu | Non impacté |  |
| Windows Server (2012/2016/2019/2022/2025) | À vérifier | nginx pour Windows existe, plus rare mais possible |
| SMB (Samba, Debian) | Non impacté |  |
| SFTP (Debian) | Non impacté |  |
| Cisco | Non impacté |  |
| Ubiquiti | Non impacté |  |
| HP/Aruba | Non impacté |  |
| FortiGate | Non impacté |  |
| FortiAnalyzer | Non impacté |  |
| FortiManager | Non impacté |  |
| Sophos | Non impacté |  |
| nginx | Impacté | Composant directement concerné |
| Certbot | Non impacté | Certbot lui-même n'est pas nginx, seul son plugin nginx interagit avec -- la faille est dans nginx, pas dans Certbot |
| Odoo (self-hosted) | À vérifier | Odoo utilise souvent nginx comme reverse-proxy frontal -- à vérifier selon le déploiement |
| Nextcloud | À vérifier | nginx souvent utilisé comme serveur web devant Nextcloud -- à vérifier selon le déploiement |
| JumpCloud | Non impacté |  |
| Python | Non impacté |  |
| Django | Non impacté |  |
| React | Non impacté |  |
| PHP | Non impacté |  |
| MikroTik | Non impacté |  |
| Ceph | Non impacté |  |
| QEMU-KVM | Non impacté |  |

## Références

- [Avis officiel nginx](https://nginx.org/en/security_advisories.html)
- [Wiz — analyse technique](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities)
- [The Hacker News](https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html)
- [Qualys — NGINX2Root, FAQ et détection](https://blog.qualys.com/product-tech/patch-management/2026/11/18/nginx2root-five-nginx-flaws-led-by-cve-2026-123007-how-to-find-mitigate-and-patch-now)
- Debian Security Tracker : <https://security-tracker.debian.org/>
- Ubuntu Security Notices : <https://ubuntu.com/security/notices/>
