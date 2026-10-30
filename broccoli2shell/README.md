# CVE-2026-111497 — Broccoli2Shell / Node2Shell / HTTP2Shell

> Faille critique (CVSS 9.2) dans le **décodeur Brotli** (bibliothèque de compression de Google). Toute application qui décompresse du Brotli non vérifié — reçu dans une requête (`Content-Encoding: br`) ou dans une réponse d'un serveur distant — peut être affectée : écriture hors limites dans le décodeur, pouvant aller jusqu'à l'exécution de code.
> Ajoutée au catalogue **CISA KEV** le 27/10/2026 (exploitée activement). Alias : Node2Shell (nom d'origine), HTTP2Shell, Broccoli2Shell.

## Explication courte

Le décodeur C de Brotli (versions **1.0.3 à 1.2.0**) contient un défaut qui permet, en lui donnant un flux Brotli spécialement construit, de corrompre la mémoire du processus qui le décompresse. Le code a été introduit en février 2026 et corrigé sans bruit en octobre — personne ne l'avait signalé comme un problème de sécurité avant.

Ce décodeur n'est pas seulement "une bibliothèque Linux" : il est **copié ou lié** dans énormément de piles logicielles différentes, qui doivent donc chacune être corrigées séparément :

| Composant | Ce qui est concerné | Mise à jour système suffit ? |
|---|---|---|
| **Node.js** | Le décodeur Brotli interne du module `zlib` (bundlé dans Node lui-même) | Non — il faut mettre à jour **Node.js**, pas une dépendance npm |
| **Python** | Les paquets PyPI `Brotli` et `brotlicffi` ; chargés automatiquement par `urllib3`/`requests`, `aiohttp`, `httpx[brotli]` | Non — paquet Python à mettre à jour (`pip`), indépendant du système |
| **.NET** | `System.IO.Compression` (Brotli), donc `HttpClient` et la décompression de requêtes ASP.NET Core — .NET embarque sa **propre copie native** du code Brotli | Non — mise à jour du **runtime .NET** (ou republier une appli self-contained) |
| **Distributions Linux** | Paquet système `libbrotli`/`brotli-libs` (Debian, Ubuntu, Alpine, RHEL…) | Oui, si le correctif existe pour cette distribution/version — **le numéro de version est renuméroté par chaque distribution**, ne jamais comparer un numéro brut à la version amont (voir tableau plus bas) |
| **Copies embarquées** | DuckDB, Apache Arrow (build embarqué), 7-Zip-zstd/p7zip, EDK II, woff2 | **Non, jamais** — ces logiciels embarquent leur propre copie du code Brotli ; seule une nouvelle version de l'éditeur corrige |
| **IIS (Windows)** | Module de compression dynamique `brotli.dll` | C'est une implémentation Microsoft séparée — se corrige via Windows Update / l'avis IIS, pas via le décodeur Google |

### Versions corrigées

| Composant | Corrigé en | Branches EOL sans correctif |
|---|---|---|
| Brotli (amont) | 1.0.10 / 1.1.1 / 1.2.1 | — |
| Node.js | **22.23.4**, **24.22.1**, **26.12.1** (21/10/2026) | 20.x et antérieures, 21.x, 23.x, 25.x |
| Python `Brotli` | **1.2.1** | — |
| Python `brotlicffi` | **1.2.1.0** | — |
| .NET | **8.0.33**, **9.0.22**, **10.0.14**, 11 RC3+ (25/10/2026, hors cycle) | — |
| Debian 12 (bookworm) | libbrotli1 **1.0.9-2+deb12u1** | — |
| Debian 13 (trixie) | libbrotli1 **1.1.0-2+deb13u1** | — |
| Ubuntu 22.04 | libbrotli1 **1.0.9-2ubuntu0.1** | — |
| Ubuntu 24.04 | libbrotli1 **1.1.0-2ubuntu0.1** | — |
| Ubuntu 26.04 / 26.10 | libbrotli1 **1.2.0-3ubuntu0.1** / **1.2.0-4ubuntu0.1** | — |
| Alpine 3.21 | brotli-libs **1.1.1-r0** | — |
| Alpine 3.23 / 3.24 | brotli-libs **1.2.1-r0** | Alpine 3.20/3.22 : pas de branche de correctif confirmée au 30/10/2026 — vérifier `security.alpinelinux.org` |
| RHEL/CentOS/Fedora | Avis en cours de publication, NVR variables par version | À vérifier au cas par cas sur `access.redhat.com` |

> ⚠️ **Piège Ubuntu/Debian** : le paquet corrigé d'Ubuntu 22.04 est `1.0.9-2ubuntu0.1`, alors que la version amont corrigée est `1.2.1`. Si vous comparez juste "le numéro est inférieur à 1.2.1" vous allez classer vulnérable tout un parc Ubuntu/Debian **déjà patché**. Les scripts ci-dessous comparent contre la bonne table, par distribution ET par version — jamais contre le numéro amont brut.

## Démonstration : comment vérifier qu'une cible est vulnérable

**Méthode recommandée, sans risque : l'inventaire de version.** C'est ce que font les scripts de ce dossier : ils identifient Node.js/Python/.NET/le paquet système/les conteneurs installés et comparent leur version aux tables ci-dessus. Aucune requête n'est envoyée à l'application cible — c'est totalement sûr à lancer sur un système de production.

**Méthode active (test d'intrusion) — réservée à un labo isolé, jamais en production sans autorisation écrite :**
Le principe publié par les chercheurs est d'envoyer à l'application cible un corps de requête HTTP avec l'en-tête `Content-Encoding: br` contenant un flux Brotli spécialement construit, puis d'observer si le processus plante ou se comporte anormalement (c'est la preuve qu'il décompresse sans contrôle). L'inverse existe aussi côté client : un serveur malveillant peut renvoyer un flux Brotli piégé à un client qui a demandé `Accept-Encoding: br`.

Ce dépôt ne fournit pas les octets du flux Brotli qui déclenchent le bug — un flux publié sans vérification serait soit inopérant, soit un vrai risque s'il tombe dans les mauvaises mains. Si un test actif est nécessaire (ex. valider un correctif en labo) :
- Monter une cible jetable (VM ou conteneur, jamais un système réel) avec la version vulnérable connue.
- Utiliser l'avis officiel GitHub **GHSA-9v8h-qqgm-4m35** et les dépôts de preuve de concept publics référencés depuis **broccoli2shell.com** comme point de départ, en lisant le code avant de l'exécuter (même réserve que pour tout PoC tiers : isoler, lire, ne jamais lancer contre une cible non autorisée).
- Détruire l'environnement de test après usage.

Dans l'immense majorité des cas, l'inventaire de version suffit à savoir si vous êtes concerné — gardez le test actif pour les cas où la version seule ne suffit pas à trancher (ex. copie embarquée dont le numéro n'est pas documenté).

## Comment faire la vérification

Un seul fichier par plateforme, aucune dépendance :

```bash
chmod +x test_broccoli2shell.sh
./test_broccoli2shell.sh                # mode lecture seule (par défaut)
./test_broccoli2shell.sh --scan-images  # + sonde les images Docker/Podman locales
```

```powershell
.\Test-Broccoli2Shell.ps1
.\Test-Broccoli2Shell.ps1 -ScanImages
```

## Comment être sûr du résultat

Le script a **deux modes**, et c'est volontaire :

- **Lecture seule (par défaut)** : il inspecte l'hôte et lit dans les conteneurs déjà en cours d'exécution (`docker exec`). Il ne crée, ne démarre et ne modifie rien. C'est le mode à utiliser pour un premier passage rapide ou sur un système sensible.
- **`--scan-images` / `-ScanImages`** : en plus, il lance un conteneur **éphémère et isolé** (`--network none`, détruit juste après) pour chaque image Docker/Podman locale, afin d'y chercher une version vulnérable. **C'est le seul moyen de détecter une image vulnérable qui n'est pas démarrée actuellement** — une image dormante n'apparaît jamais dans un `docker ps`, donc jamais en mode lecture seule.

Le script l'affiche lui-même en toutes lettres à la fin, sous forme d'une ligne **« Confiance »** :

| Situation | Ligne affichée |
|---|---|
| Un élément vulnérable trouvé | `Confiance : élément vulnérable CONFIRMÉ` — pas d'ambiguïté possible |
| Rien de vulnérable, mais au moins un élément « à vérifier » (distribution non référencée, copie embarquée, etc.) | `Confiance : INCOMPLÈTE` — il reste une vérification manuelle à faire avant de pouvoir conclure |
| Rien trouvé, mode lecture seule | `Confiance : PARTIELLE` — les images locales non démarrées n'ont pas été inspectées |
| Rien trouvé, mode `--scan-images` | `Confiance : COMPLÈTE` dans la limite du script — hôte, conteneurs actifs et images ont tous été sondés |

**Pour être réellement sûr qu'une machine n'est pas vulnérable**, il faut donc avoir lancé le script avec `--scan-images`/`-ScanImages` **et** obtenu la ligne « Confiance : COMPLÈTE ». Un « NON CONCERNÉ » obtenu en mode lecture seule seul ne suffit pas à l'affirmer : relancer avec `--scan-images` pour confirmer.

Le code de sortie du script suit la même logique : `0` = rien à signaler, `1` = à vérifier manuellement, `2` = vulnérable confirmé — réutilisable dans un cron / une tâche planifiée / une supervision.

## Mitigation en attendant un correctif

- **Node.js** : aucun contournement connu — seule la mise à jour corrige.
- **Python** : si la mise à jour de `Brotli`/`brotlicffi` est impossible, les désinstaller fait retomber les clients HTTP sur gzip/deflate.
- **.NET** : la décompression automatique n'est pas activée par défaut (ASP.NET Core / `HttpClient`) — vérifier qu'elle n'a pas été activée explicitement si la mise à jour n'est pas encore faite.
- **Entrées HTTP** : rejeter au reverse-proxy/WAF les corps de requête avec `Content-Encoding: br`.
- **Sorties** : aucune protection fiable — retirer `br` de `Accept-Encoding` n'empêche pas un serveur malveillant d'envoyer du Brotli quand même.
- Dans tous les cas : **redémarrer tous les processus** après correctif — ils gardent l'ancien décodeur en mémoire jusqu'au redémarrage. Pour une image Docker : reconstruire et redéployer.

## Limites connues

- Ce script est un inventaire de versions, pas un test d'intrusion : il ne prouve pas l'absence de compromission passée.
- RHEL/CentOS/Fedora : pas de table de versions fiable à ce jour (avis éditeur en cours de publication) — toujours classé « à vérifier ».
- Les copies embarquées (DuckDB, Apache Arrow, 7-Zip-zstd/p7zip, EDK II, woff2) sont repérées par nom de binaire, pas par version — toujours classées « à vérifier », à confirmer auprès de l'éditeur.
- Les applications .NET autonomes (« self-contained ») sont repérées par leurs fichiers `*.runtimeconfig.json` sous les chemins fournis en paramètre — une installation ailleurs sur le disque reste invisible.

## Références

- Avis GitHub : [GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35)
- IT-Connect : [faille Brotli Broccoli2Shell](https://www.it-connect.fr/faille-brotli-broccoli2shell-python-dotnet-linux/)
- Suivi multi-écosystèmes : [broccoli2shell.com](https://broccoli2shell.com/)
- Debian Security Tracker : [CVE-2026-111497](https://security-tracker.debian.org/tracker/CVE-2026-111497)
- Ubuntu : [USN-8956-1](https://ubuntu.com/security/notices/USN-8956-1)
- Alpine : [security.alpinelinux.org/vuln/CVE-2026-111497](https://security.alpinelinux.org/vuln/CVE-2026-111497)
- Microsoft .NET : [mises à jour hors cycle d'octobre 2026](https://devblogs.microsoft.com/dotnet/dotnet-october-2026-oob-security-updates/)
- Node.js : [nodejs.org/en/blog/vulnerability](https://nodejs.org/en/blog/vulnerability)
