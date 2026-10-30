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

> ⚠️ **Piège Debian/Ubuntu/RHEL** : les correctifs y sont souvent **rétroportés** : un numéro de version inférieur à celui ci-dessus peut déjà être patché par la distribution. Le script compare d'abord la version PHP elle-même (fiable pour un PHP installé via les sources officielles ou une image Docker upstream) ; pour un PHP fourni par le paquet système d'une distribution, vérifier aussi le tracker de sécurité de cette distribution (<https://security-tracker.debian.org/>, <https://ubuntu.com/security/notices/>).

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
- Paquets Debian/Ubuntu/RHEL : un numéro de version inférieur au correctif amont peut déjà être patché par la distribution (backport) — à vérifier sur le tracker de sécurité de la distribution en cas de doute.
- `kubectl`/`lxc`/`nerdctl`/`crictl` sont seulement signalés comme présents, pas sondés automatiquement.
- Sous Windows : la recherche sur disque est bornée aux chemins fournis en paramètre (par défaut XAMPP/WAMP/PHP officiel/IIS) — une installation ailleurs reste invisible ; les conteneurs Windows natifs (non-WSL2) ne sont pas sondés.

## Références

- [php.net](https://www.php.net/)
- Debian Security Tracker : <https://security-tracker.debian.org/>
- Ubuntu Security Notices : <https://ubuntu.com/security/notices/>
- Tenable — FAQ PHP2Shell : <https://www.tenable.com/blog/php2shell-cve-2026-109618-cve-2026-109619-frequently-asked-questions-about-critical-php-remote>
- The Hacker News : <https://thehackernews.com/2026/10/php-issues-emergency-patches-for-two.html>
- watchTowr — FAQ : <https://watchtowr.com/intelligence/php-cve-2026-109618-faq/>
