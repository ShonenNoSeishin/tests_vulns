# tests_vulns

Boîte à outils de détection — un dossier par faille, chacun avec :

- un script de détection **autonome** (un seul fichier, aucune dépendance à un autre script) pour Linux/macOS (bash) et pour Windows (PowerShell) ;
- un `README.md` qui explique la faille, donne les versions corrigées et explique comment vérifier qu'une machine est concernée.

Les scripts de `php2shell/` et `broccoli2shell/` sont en **lecture seule par défaut** : ils n'exploitent rien, ne modifient rien, et n'envoient aucune requête à une application cible — ils inventorient les versions installées (binaires, paquets système, runtimes, conteneurs) localement, sur la machine où ils tournent. [`public-scan/`](public-scan/) est différent : c'est une **reconnaissance réseau active** (via nmap) pour le cas où vous n'avez qu'un nom de domaine ou une IP publique, sans accès shell — voir l'avertissement dans son `README.md` avant de l'utiliser.

## Dernières failles

| Date | Faille (CVE) | Gravité | Exploitée ? | Dossier |
|---|---|---|---|---|
| 19/11/2026 | **PHP** — lot de correctifs (18 CVE, use-after-free/RCE conditionnelles) · CVE-2026-129474, CVE-2026-129496, +16 autres | 🔴 Critique | non connue | [`php-novembre-2026/`](php-novembre-2026/) |
| 18/11/2026 (maj 20/11) | **NGINX2Root** — RCE non authentifiée via HTTP/2 · CVE-2026-123007, CVE-2026-123633 | 🔴 Critique | PoC public | [`nginx2root/`](nginx2root/) |
| 18/11/2026 (dossier ajouté 25/11) | **Drupal2Root** — RCE/prise de contrôle non authentifiée via install.php · CVE-2026-132165 | 🔴 Critique | ✅ KEV | [`drupal2root/`](drupal2root/) |
| 12/11/2026 | **sshole** — contournement de mot de passe OpenSSH (Alpine/musl) · CVE-2026-123158 | 🟠 Haute | ✅ KEV | [`sshole-cve-2026-123158/`](sshole-cve-2026-123158/) |
| 11/11/2026 (dossier ajouté 24/11, maj 25/11) | **Apache2Root** — RCE non authentifiée via mod_http2 · CVE-2026-119618 | 🔴 Critique | signalée (pas KEV) | [`apache2root/`](apache2root/) |
| 10/11/2026 (maj 19/11) | **Fortinet** — lot de novembre (FGFM, API JRPC, OSPF) · CVE-2026-126261, CVE-2026-126170, CVE-2026-126253 | 🔴 Critique | non connue | [`fortinet-novembre-2026/`](fortinet-novembre-2026/) |
| 10-12/11/2026 | **Proxmox VE** — lot d'avis (injection shell volume/upload → root, 5 avis mineurs) · pas de CVE | 🔴 Critique | non connue | [`proxmox-novembre-2026/`](proxmox-novembre-2026/) |
| 05/11/2026 | **APT** — contournement de signature → root · CVE-2026-109518 | 🟠 Haute | non connue | [`cve-2026-109518/`](cve-2026-109518/) |
| 05/11/2026 | **Noyau Linux** — use-after-free TCP/IPv4 · CVE-2026-98432 | 🔴 Critique | non connue | [`cve-2026-98432/`](cve-2026-98432/) |
| 27/10/2026 | **Broccoli2Shell** — décodeur Brotli (Node, Python, .NET, IIS) · CVE-2026-111497 | 🔴 Critique | ✅ KEV | [`broccoli2shell/`](broccoli2shell/) |
| 21/10/2026 (maj 20/11) | **PHP2Shell** — RCE PHP sans authentification · CVE-2026-109618/109619 | 🔴 Critique | ✅ exploitée (campagne PAN-OS, hors KEV) | [`php2shell/`](php2shell/) |

## Technicien : êtes-vous touché ? En 3 étapes

1. **Repérer** votre cas dans le tableau ci-dessus (ou chercher votre produit/CVE dans l'interface IRM).
2. **Tester** : télécharger le script du dossier et le lancer (lecture seule par défaut). Chaque article commence par un encadré
   « **En 30 secondes** » : *Suis-je concerné ? Comment tester ? Comment corriger ?*
3. **Corriger** puis **relancer le même script** : la ligne doit passer à `[CORRIGÉ]` avec `Confiance : COMPLÈTE`.

Chaque dossier contient aussi un fichier **`vuln.yaml`** (métadonnées lues par l'interface IRM : gravité, dates, commandes de test et de correction),
voir [`docs/FORMAT.md`](docs/FORMAT.md).

## Quelle action effectuer une fois une faille détectée ?

[`REMEDIATION.md`](REMEDIATION.md) donne un **arbre de décision** : type de machine
(VM/LXC/bare-metal/conteneur) → OS (Windows/Linux) → distribution/version → mode
d'installation (gestionnaire de paquets, Docker, Snap) → faille concernée → doc précise
à lire et commande type à lancer. Il ne répète pas les tableaux de versions corrigées
(déjà dans le `README.md` de chaque dossier) : il sert uniquement à retrouver vite "je
suis dans ce cas précis, quelle commande je lance ?".

## Scan public (sans accès à la machine)

[`public-scan/`](public-scan/) explique comment installer nmap et scanner un site web ou une IP
publique **de l'extérieur**, pour les deux failles ci-dessus — utile pour un premier passage sur
tout votre périmètre public avant d'aller auditer chaque machine trouvée avec les scripts locaux.
**Lisez l'avertissement légal du dossier avant de l'utiliser** : contrairement aux deux autres
dossiers, il contacte réellement la cible, et ses résultats sont par nature une indication, jamais
une certitude (un scan externe ne peut pas voir une version masquée, ni la version d'un décodeur
Brotli).

## Démarrage rapide

```bash
cd php2shell && chmod +x test_php2shell.sh && ./test_php2shell.sh
cd ../broccoli2shell && chmod +x test_broccoli2shell.sh && ./test_broccoli2shell.sh
```

```powershell
cd php2shell;        .\Test-Php2Shell.ps1
cd ..\broccoli2shell; .\Test-Broccoli2Shell.ps1
```

Chaque script commence par une section **« 0. Prérequis »** qui vérifie les commandes disponibles (gestionnaire de paquets, Docker/Podman, timeout, etc.) avant de lancer quoi que ce soit. Une commande absente fait ignorer proprement la section correspondante — jamais une erreur brute de shell.

## Les deux modes, et comment être sûr du résultat

Chaque script fonctionne selon **deux modes**, communs à toutes les failles de ce dépôt :

1. **Lecture seule (par défaut)** — inspecte l'hôte et lit dans les conteneurs Docker/Podman **déjà en cours d'exécution** (`exec`). Ne crée, ne démarre, ne modifie et ne supprime rien.
2. **`--scan-images` (bash) / `-ScanImages` (PowerShell)** — en plus du mode lecture seule, lance un conteneur **éphémère et isolé** (`--network none`, détruit immédiatement après) pour chaque image locale, afin d'y chercher une version vulnérable. C'est le seul moyen de repérer une image dormante (jamais démarrée) qui serait invisible en mode lecture seule.

**Chaque script affiche lui-même, en toutes lettres à la fin, une ligne « Confiance »** qui dit explicitement si vous pouvez être sûr du résultat :

- `Confiance : élément vulnérable CONFIRMÉ` → pas d'ambiguïté, agir.
- `Confiance : INCOMPLÈTE` → au moins un élément nécessite une vérification manuelle (branche de distribution non référencée, copie embarquée, etc.).
- `Confiance : PARTIELLE` → rien trouvé, mais en mode lecture seule : des images locales non démarrées n'ont pas été inspectées.
- `Confiance : COMPLÈTE` → rien trouvé, **et** le script a été lancé avec `--scan-images`/`-ScanImages` : hôte, conteneurs actifs et images locales ont tous été sondés.

**Pour affirmer qu'une machine n'est pas vulnérable, il faut avoir obtenu "Confiance : COMPLÈTE"** — c'est-à-dire avoir lancé le script en mode `--scan-images`/`-ScanImages` et n'avoir rien trouvé. Un résultat obtenu uniquement en lecture seule est une première indication, pas une certitude.

Le code de sortie suit la même logique (`0` = rien à signaler, `1` = à vérifier, `2` = vulnérable confirmé) et peut être branché sur un cron, une tâche planifiée ou une supervision.

## Portée et limites

- Ces scripts sont des outils d'**inventaire de versions**, pas des tests d'intrusion : un résultat "non concerné" ne prouve pas l'absence de compromission passée, seulement l'absence de version vulnérable détectable aujourd'hui.
- Chaque `README.md` de dossier liste les limites spécifiques à sa faille (distributions non couvertes, copies embarquées non versionnées, etc.).
- Aucun de ces scripts ne doit être pointé contre une machine qui n'est pas la vôtre ou que vous n'êtes pas autorisé à auditer.

## Reproduire le workflow (Claude Code)

Ce dépôt est maintenu avec deux commandes [Claude Code](https://claude.com/claude-code), versionnées dans [`.claude/commands/`](.claude/commands/) :

- **`/veille-hebdo`** — veille hebdomadaire des failles importantes, classées par priorité pour votre parc.
- **`/deep-dive-vuln <CVE>`** — analyse une faille en détail, crée le dossier public de détection de ce dépôt (scripts + README + `vuln.yaml`) et, dans un dossier privé séparé, la méthode d'exploitation et les résultats de test.

Les deux lisent un contexte privé (parc machines, priorités, machine de labo) qui n'est **jamais** dans ce dépôt — voir les modèles [`docs/EXAMPLE-company-profile.md`](docs/EXAMPLE-company-profile.md) et [`docs/EXAMPLE-lab-vm.md`](docs/EXAMPLE-lab-vm.md) pour reproduire avec votre propre contexte. Les chemins absolus dans les commandes sont ceux de l'installation d'origine : à adapter à la vôtre.

## Ajouter une nouvelle faille

Modèle prêt à copier : [`docs/TEMPLATE.md`](docs/TEMPLATE.md) (article) et [`docs/FORMAT.md`](docs/FORMAT.md) (`vuln.yaml`).

1. Créer un dossier `<nom-de-la-faille>/`.
2. Y écrire un script bash `test_<nom>.sh` et/ou un script PowerShell `Test-<Nom>.ps1`, sur le modèle d'un dossier existant :
   - section « 0. Prérequis » en premier ;
   - mode lecture seule par défaut, `--scan-images`/`-ScanImages` en opt-in pour les conteneurs éphémères ;
   - chaque élément détecté sur sa propre ligne (`[VULNÉRABLE]`, `[À VÉRIFIER]`, `[CORRIGÉ]`/`[OK]`, ou `[NON CONCERNÉ]` si rien trouvé) ;
   - une ligne finale « Confiance » explicite (COMPLÈTE / PARTIELLE / INCOMPLÈTE / confirmé vulnérable) ;
   - code de sortie `0`/`1`/`2`.
3. Écrire le `README.md` du dossier : explication courte, tableau des composants concernés et versions corrigées, démonstration (inventaire + mention de la méthode active sans fournir de payload), procédure, mitigation, limites, références.
4. Écrire le `vuln.yaml` du dossier (gravité, dates, commandes), puis ajouter une ligne en tête du tableau « Dernières failles » ci-dessus.
