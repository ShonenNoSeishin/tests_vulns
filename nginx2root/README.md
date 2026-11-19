# CVE-2026-123007 / CVE-2026-123633 — « NGINX2Root »

> Deux failles critiques (CVSS 4.0 : 9.2) dans **nginx**, corrigées le **18/11/2026** avec un lot de 10 CVE au total. Les deux permettent une **exécution de code à distance SANS authentification**, via le protocole **HTTP/2**. CVE-2026-123007 est présente dans le code source depuis **2015** (nginx 1.9.5) : plus de 10 ans d'exposition potentielle. Un **PoC public** existe pour CVE-2026-123007.

## En 30 secondes

| | |
|---|---|
| **Suis-je concerné ?** | Un serveur fait tourner nginx (reverse-proxy, serveur web, ingress, panneau d'admin…), en version open source **antérieure à 1.30.7 (stable) ou 1.31.9 (mainline)**. |
| **Comment tester ?** | `sudo ./test_nginx2root.sh --scan-images` (Linux) · `.\Test-Nginx2Root.ps1 -ScanImages` (Windows). Lecture seule, aucune requête envoyée à un serveur distant. |
| **Comment corriger ?** | Mettre à jour vers **1.30.7** ou **1.31.9** (ou l'équivalent nginx Plus), redémarrer/recharger nginx. Si le paquet distro n'est pas encore disponible : passer par le dépôt officiel `nginx.org`. |

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

> ⚠️ **Piège de version — à l'inverse de PHP2Shell** : il n'existe **aucun rétroportage distro connu à ce jour** (vérifié sur `security-tracker.debian.org` et `ubuntu.com/security/notices` le 19/11/2026 — rien ne référence encore ces CVE). Le numéro de version brut rendu par `nginx -v` est donc fiable **pour l'instant** : une version < 1.30.7/1.31.9 est réellement vulnérable, pas "peut-être déjà patchée en silence" comme pour PHP. **Si un USN/DSA sort plus tard avec un rétroportage**, ce script devra être mis à jour avec une table de correspondance (sur le modèle de celle de `php2shell/README.md`) — repasser le script après chaque mise à jour de sécurité en attendant.
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

## Procédure de correction par méthode d'installation

**Action L1 — mise à jour standard, simple et sûre :**

| Méthode d'installation | Commande |
|---|---|
| Paquet système (Debian/Ubuntu, `apt`) | `apt update && apt install --only-upgrade nginx` **si** un paquet ≥ 1.30.7/1.31.9 est déjà disponible — sinon voir ci-dessous |
| Paquet système (RHEL/CentOS/Fedora, `yum`/`dnf`) | `dnf update nginx` |
| Alpine (`apk`) | `apk update && apk upgrade nginx` |
| Dépôt officiel nginx.org (recommandé si le paquet distro n'est pas encore sorti) | Suivre <https://nginx.org/en/linux_packages.html> pour pointer vers le dépôt officiel, puis mettre à jour normalement |
| Image Docker officielle `nginx` | `docker pull nginx:<tag>` avec un tag reconstruit après le 18/11/2026, puis `docker compose up -d --force-recreate` — **ne jamais patcher dans un conteneur en cours d'exécution** |
| nginx Plus | Suivre la procédure de mise à jour F5/nginx Plus habituelle (portail support), viser 37.0.8.1 ou 37.3.0.1 |
| Windows (installeur officiel) | Télécharger la version corrigée sur <https://nginx.org/en/download.html>, remplacer le binaire, redémarrer le service |

Après mise à jour : `nginx -s reload` ou redémarrage complet selon la politique de maintenance, puis relancer le script pour confirmer `[CORRIGÉ]`.

### Contournement temporaire (nginx ≥ 1.25.1), si la mise à jour doit attendre

Désactiver HTTP/2 réduit l'exposition aux **deux** RCE (pas aux 8 autres CVE du lot) :
- Retirer le paramètre `http2` des directives `listen`, ou ajouter `http2 off;` dans les blocs serveur concernés.
- Tester la compatibilité applicative (certains clients négocient HTTP/2 par défaut), recharger nginx, vérifier que les anciens workers se sont bien terminés.
- Réactiver HTTP/2 après la mise à jour réelle — ce n'est qu'une mitigation, pas un correctif.

## Limites connues

- Ce script est un inventaire de versions, pas un test d'intrusion : il ne prouve pas l'absence de compromission passée.
- La détection du paquet système (bash) complète l'information mais **ne sert pas à décider du verdict** — seule la version rendue par le binaire `nginx -v` réellement utilisé compte, car aucune table de rétroportage distro n'existe à ce jour pour ces CVE (voir avertissement ci-dessus).
- La lecture de la configuration (HTTP/2 activé ou non, via `nginx -T`) est **best-effort** : incomplète si le script ne tourne pas en root, ou si la configuration est répartie dans des fichiers non standard. Ne jamais se fier à "HTTP/2 non détecté" pour ignorer un correctif : les 8 autres CVE du lot ne dépendent pas de HTTP/2.
- `nginx Plus` n'est jamais comparé automatiquement (toujours `[À VÉRIFIER]`) : sa numérotation de build diffère trop de l'open source pour une comparaison fiable sans risque de faux résultat.
- `Test-Nginx2Root.ps1` (Windows) ne vérifie pas de paquet système (pas d'équivalent `dpkg`/`apk` sous Windows) ; les conteneurs Windows natifs (non-WSL2) ne sont pas sondés.
- Les ingress controllers Kubernetes basés sur nginx (`ingress-nginx`, etc.) ne sont pas spécifiquement couverts : le script détecte le binaire nginx si le conteneur est inspectable via `docker`/`podman`, mais un cluster Kubernetes managé nécessite une vérification dédiée (image de l'ingress controller).

## Références

- [Avis officiel nginx](https://nginx.org/en/security_advisories.html)
- [Wiz — analyse technique](https://www.wiz.io/blog/nginx-http2-rce-vulnerabilities)
- [The Hacker News](https://thehackernews.com/2026/11/10-year-old-nginx-http2-flaw-lets.html)
- [Qualys — NGINX2Root, FAQ et détection](https://blog.qualys.com/product-tech/patch-management/2026/11/18/nginx2root-five-nginx-flaws-led-by-cve-2026-123007-how-to-find-mitigate-and-patch-now)
- Debian Security Tracker : <https://security-tracker.debian.org/>
- Ubuntu Security Notices : <https://ubuntu.com/security/notices/>
