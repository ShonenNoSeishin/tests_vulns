# CVE-2026-109618 / CVE-2026-109619 — PHP2Shell

> Deux failles PHP critiques (CVSS 9.2 à 9.8) permettant une **exécution de code à distance via HTTP, sans authentification** (RCE). Correctifs publiés le 21/10/2026.
> Le niveau de privilège obtenu dépend de l'utilisateur qui fait tourner PHP (souvent `www-data`/`apache`, parfois root sur les vieux appliances).

## Explication courte

Les deux failles touchent le traitement de certaines requêtes HTTP par le moteur PHP lui-même (pas une application PHP particulière) : PHP-FPM, Apache `mod_php`, `php-cgi`, FrankenPHP et LiteSpeed sont concernés. Un attaquant peut déclencher l'exécution de code à distance sans aucun accès préalable, simplement en contactant le service web qui sert du PHP.

CVE-2026-109619 est liée au traitement de `session.upload_progress` : une mitigation temporaire existe (désactiver ce réglage), mais seule la mise à jour corrige réellement les deux failles.

### Versions corrigées

| Branche | Version corrigée minimale |
|---|---|
| 8.5 | **8.5.12** |
| 8.4 | **8.4.27** |
| 8.3 | **8.3.36** |
| 8.2 | **8.2.35** |
| ≤ 8.1 (7.x, 5.x…) | Fin de vie : **pas de correctif officiel** (seulement des backports source minimaux pour 7.4 → 8.1). À migrer ou isoler. |

> ⚠️ **Piège Debian/Ubuntu** : les correctifs y sont **rétroportés dans le paquet** sans changer le numéro `PHP_VERSION` rendu par le binaire. Exemple réel : Ubuntu 22.04 reste en PHP **8.1.2** (branche amont EOL) après le correctif — seul le paquet `php8.1-*` change de version (`8.1.2-1ubuntu2.28`). Comparer uniquement le numéro PHP donnerait un **faux positif** sur un système déjà patché.
>
> Le script (bash) gère ça automatiquement pour les combinaisons distribution/version/branche déjà vérifiées (voir tableau ci-dessous) : il interroge le paquet système réel (`dpkg -l`) et compare sa version à celle corrigée par Debian/Ubuntu, pas au numéro amont. Pour toute combinaison **non** dans ce tableau (autre version d'Ubuntu/Debian, ou RHEL/CentOS/Fedora), il reste prudent et renvoie `[À VÉRIFIER]` plutôt que d'affirmer "vulnérable" sur la seule foi du numéro amont — à confirmer manuellement sur le tracker de sécurité de la distribution.

| Distribution | Branche PHP | Paquet corrigé | Remarque |
|---|---|---|---|
| Debian 12 (bookworm) | 8.2 | `php8.2-*` **8.2.35-1~deb12u1** | |
| Debian 13 (trixie) | 8.4 | `php8.4-*` **8.4.27-1~deb13u1** | |
| Ubuntu 22.04 LTS | 8.1 | `php8.1-*` **8.1.2-1ubuntu2.28** | |
| Ubuntu 24.04 LTS | 8.3 | `php8.3-*` **8.3.6-0ubuntu0.24.04.13** | |
| Ubuntu 26.04 LTS | 8.5 | `php8.5-*` **8.5.4-0ubuntu1.5** | |
| Ubuntu 26.10 | 8.5 | `php8.5-*` **8.5.9-0ubuntu2.1** | |
| Ubuntu 20.04 LTS | 7.4 | `php7.4-*` **7.4.3-4ubuntu2.29+esm5** | **Ubuntu Pro/ESM requis** pour recevoir ce paquet |
| Ubuntu 18.04 LTS | 7.2 | `php7.2-*` **7.2.24-0ubuntu0.18.04.17+esm14** | **Ubuntu Pro/ESM requis** |
| Ubuntu 16.04 LTS | 7.0 | `php7.0-*` **7.0.33-0ubuntu0.16.04.16+esm22** | **Ubuntu Pro (Legacy Support) requis** |
| Ubuntu 14.04 LTS | 5.5 | `php5-*` **5.5.9+dfsg-1ubuntu4.29+esm18** | **Ubuntu Pro (Legacy Support) requis** |

Sources : [security-tracker.debian.org/tracker/CVE-2026-109618](https://security-tracker.debian.org/tracker/CVE-2026-109618), [USN-8948-1](https://ubuntu.com/security/notices/USN-8948-1), [USN-8948-2](https://ubuntu.com/security/notices/USN-8948-2) — vérifiées le 30/10/2026.

**Mitigation temporaire** (CVE-2026-109619) : `session.upload_progress.enabled = 0` dans le `php.ini`, puis **redémarrer tous les workers** (php-fpm / apache / IIS). Seule la mise à jour protège complètement.

## Démonstration : comment vérifier qu'une cible est vulnérable

**Méthode recommandée, sans risque : l'inventaire de version.** C'est ce que fait le script de ce dossier : il identifie chaque binaire PHP (hôte, conteneurs, IIS FastCGI) et compare sa version aux tables ci-dessus. Aucune requête n'est envoyée à l'application cible — sûr à lancer sur un système de production.

**Méthode active (test d'intrusion) — réservée à un labo isolé, jamais en production sans autorisation écrite :**
Le principe publié par les chercheurs consiste à envoyer une requête HTTP spécialement construite (impliquant le traitement de session et d'upload côté serveur) à l'application cible et à observer la réaction du processus PHP (plantage, comportement anormal, ou preuve d'exécution de code dans un labo contrôlé).

Ce dépôt ne fournit pas de preuve de concept exécutable : un PoC publié sans vérification serait soit inopérant, soit un vrai risque entre de mauvaises mains. Si un test actif est nécessaire (ex. valider un correctif en labo) :
- Monter une cible jetable (VM ou conteneur, jamais un système réel) avec la version vulnérable connue.
- Partir des avis officiels (voir Références) et des bulletins des éditeurs de sécurité qui ont documenté la faille, en lisant tout code tiers avant de l'exécuter et en l'isolant du réseau.
- Détruire l'environnement de test après usage.

Dans l'immense majorité des cas, l'inventaire de version suffit à savoir si vous êtes concerné.

## Comment faire la vérification

Un seul fichier par plateforme, aucune dépendance :

```bash
chmod +x test_php2shell.sh
./test_php2shell.sh                # mode lecture seule (par défaut)
./test_php2shell.sh --scan-images  # + sonde les images Docker/Podman locales
```

```powershell
.\Test-Php2Shell.ps1
.\Test-Php2Shell.ps1 -ScanImages
```

## Comment être sûr du résultat

Le script a **deux modes**, et c'est volontaire :

- **Lecture seule (par défaut)** : il inspecte l'hôte (PATH, paquets système, processus, services, IIS/FastCGI sous Windows) et lit dans les conteneurs déjà en cours d'exécution (`docker exec`). Il ne crée, ne démarre et ne modifie rien.
- **`--scan-images` / `-ScanImages`** : en plus, il lance un conteneur **éphémère et isolé** (`--network none`, détruit juste après) pour chaque image Docker/Podman locale, afin d'y chercher un PHP vulnérable. **C'est le seul moyen de détecter une image vulnérable qui n'est pas démarrée actuellement** — une image dormante (ex. une image de build jamais lancée en production) n'apparaît jamais dans un `docker ps`, donc jamais en mode lecture seule.

Le script l'affiche lui-même en toutes lettres à la fin, sous forme d'une ligne **« Confiance »** :

| Situation | Ligne affichée |
|---|---|
| Un élément vulnérable trouvé | `Confiance : élément vulnérable CONFIRMÉ` — pas d'ambiguïté possible |
| Rien de vulnérable, mais au moins un élément « à vérifier » (version illisible, backport possible, etc.) | `Confiance : INCOMPLÈTE` — il reste une vérification manuelle à faire avant de pouvoir conclure |
| Rien trouvé, mode lecture seule | `Confiance : PARTIELLE` — les images locales non démarrées n'ont pas été inspectées |
| Rien trouvé, mode `--scan-images` | `Confiance : COMPLÈTE` dans la limite du script — hôte, conteneurs actifs et images ont tous été sondés |

**Pour être réellement sûr qu'une machine n'est pas vulnérable**, il faut donc avoir lancé le script avec `--scan-images`/`-ScanImages` **et** obtenu la ligne « Confiance : COMPLÈTE ». Un « NON CONCERNÉ » obtenu en mode lecture seule seul ne suffit pas à l'affirmer : relancer avec `--scan-images` pour confirmer.

Le code de sortie du script suit la même logique : `0` = rien à signaler, `1` = à vérifier manuellement, `2` = vulnérable confirmé — réutilisable dans un cron / une tâche planifiée / une supervision.

## Limites connues

- Ce script est un inventaire de versions, pas un test d'intrusion : il ne prouve pas l'absence de compromission passée.
- La vérification par paquet distro (bash uniquement) ne couvre que les combinaisons Debian/Ubuntu listées dans le tableau ci-dessus. Pour toute autre version (Debian 11, Ubuntu non listé) ou pour RHEL/CentOS/Fedora, le script reste prudent et renvoie `[À VÉRIFIER]` plutôt que d'affirmer un verdict sur la seule foi du numéro amont — à vérifier manuellement sur le tracker de sécurité de la distribution.
- `Test-Php2Shell.ps1` (Windows) ne fait pas cette vérification par paquet : il n'existe pas d'équivalent `dpkg`/APT sous Windows pour XAMPP/WAMP/IIS.
- Snap est couvert (binaires PHP et applications web connues repérés dans `/snap` et `/var/snap`), mais un paquet Snap n'est pas concerné par le mécanisme de backport Debian/Ubuntu ci-dessus : son numéro de version est celui publié par l'éditeur du snap, comparé directement aux versions amont.
- `kubectl`/`lxc`/`nerdctl`/`crictl` sont seulement signalés comme présents, pas sondés automatiquement.
- Sous Windows : la recherche sur disque est bornée aux chemins fournis en paramètre (par défaut XAMPP/WAMP/PHP officiel/IIS) — une installation ailleurs reste invisible ; les conteneurs Windows natifs (non-WSL2) ne sont pas sondés.

## Références

- [php.net](https://www.php.net/)
- Debian Security Tracker : <https://security-tracker.debian.org/>
- Ubuntu Security Notices : <https://ubuntu.com/security/notices/>
- Tenable — FAQ PHP2Shell : <https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote>
- The Hacker News : <https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html>
- watchTowr — FAQ : <https://watchtowr.com/intelligence/php-cve-2026-109618-faq/>
