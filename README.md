# tests_vulns

Boîte à outils de détection — un dossier par faille, chacun avec :

- un script de détection **autonome** (un seul fichier, aucune dépendance à un autre script) pour Linux/macOS (bash) et pour Windows (PowerShell) ;
- un `README.md` qui explique la faille, donne les versions corrigées et explique comment vérifier qu'une machine est concernée.

Les scripts de `php2shell/` et `broccoli2shell/` sont en **lecture seule par défaut** : ils n'exploitent rien, ne modifient rien, et n'envoient aucune requête à une application cible — ils inventorient les versions installées (binaires, paquets système, runtimes, conteneurs) localement, sur la machine où ils tournent. [`public-scan/`](public-scan/) est différent : c'est une **reconnaissance réseau active** (via nmap) pour le cas où vous n'avez qu'un nom de domaine ou une IP publique, sans accès shell — voir l'avertissement dans son `README.md` avant de l'utiliser.

## Failles couvertes

| Dossier | Faille | CVE |
|---|---|---|
| [`php2shell/`](php2shell/) | PHP2Shell — RCE PHP non authentifiée via HTTP | CVE-2026-109618, CVE-2026-109619 |
| [`broccoli2shell/`](broccoli2shell/) | Broccoli2Shell / Node2Shell / HTTP2Shell — décodeur Brotli (Node.js, Python, .NET, Linux, IIS) | CVE-2026-111497 |

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

## Ajouter une nouvelle faille

1. Créer un dossier `<nom-de-la-faille>/`.
2. Y écrire un script bash `test_<nom>.sh` et/ou un script PowerShell `Test-<Nom>.ps1`, sur le modèle d'un dossier existant :
   - section « 0. Prérequis » en premier ;
   - mode lecture seule par défaut, `--scan-images`/`-ScanImages` en opt-in pour les conteneurs éphémères ;
   - chaque élément détecté sur sa propre ligne (`[VULNÉRABLE]`, `[À VÉRIFIER]`, `[CORRIGÉ]`/`[OK]`, ou `[NON CONCERNÉ]` si rien trouvé) ;
   - une ligne finale « Confiance » explicite (COMPLÈTE / PARTIELLE / INCOMPLÈTE / confirmé vulnérable) ;
   - code de sortie `0`/`1`/`2`.
3. Écrire le `README.md` du dossier : explication courte, tableau des composants concernés et versions corrigées, démonstration (inventaire + mention de la méthode active sans fournir de payload), procédure, mitigation, limites, références.
4. Ajouter une ligne dans le tableau « Failles couvertes » ci-dessus.
