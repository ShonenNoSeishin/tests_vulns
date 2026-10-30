# Arbre de décision — quelle action de remédiation effectuer ?

Ce document ne répète pas les tableaux de versions corrigées (ils sont déjà dans
[`php2shell/README.md`](php2shell/README.md) et [`broccoli2shell/README.md`](broccoli2shell/README.md)).
Il sert à répondre à une seule question, une fois qu'un script a affiché `[VULNÉRABLE]` ou
`[À VÉRIFIER]` : **concrètement, quelle commande lancer, ou quelle doc aller lire ?**

Suivre l'arbre dans l'ordre : type de machine → OS → distribution/version → mode
d'installation (gestionnaire de paquets / Docker / Snap) → faille concernée → action.

## Vue d'ensemble

```
Type de machine
 ├─ VM / bare-metal ─────┐
 ├─ LXC ──────────────────┤  → même procédure que VM/bare-metal (voir note kernel ci-dessous)
 └─ Image/conteneur Docker/Podman lui-même → jamais patché en place, voir §5
                          │
                          ▼
                    Windows / Linux
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
        Distribution Linux      Variante Windows
        (Debian/Ubuntu/Alpine/   (XAMPP/WAMP, IIS,
         autre)                   installeur officiel,
              │                    Docker Desktop)
              ▼                       │
      Gestionnaire de paquets   Mode d'installation
      (apt/apk/snap/pip/nvm/    (installeur/IIS/
       binaire manuel)           winget/choco/Docker)
              │                       │
              └───────────┬───────────┘
                          ▼
                 Quelle faille, quel composant ?
                 (PHP2Shell / Broccoli2Shell)
                          │
                          ▼
                 Doc / commande de remédiation (§6)
```

## 1. Type de machine

### VM ou bare-metal
Rien de particulier — aller directement à la section 2 (OS).

### LXC (conteneur système, ex. Proxmox)
Un LXC **partage le kernel de son hôte** (contrairement à une VM), mais cela ne change
**rien** à la procédure de remédiation : les versions de PHP, Node.js, libbrotli, .NET
installées *dans* le LXC sont des paquets/binaires userspace, totalement indépendants du
kernel de l'hôte Proxmox. Un kernel Proxmox récent fait tourner n'importe quelle version
de ces logiciels sans contrainte. → Traiter exactement comme "VM/bare-metal", en
continuant à la section 2 avec la distribution installée **dans le LXC** (pas celle du
host Proxmox).

### Image ou conteneur Docker/Podman (c'est lui l'objet vulnérable, pas l'hôte)
Ne jamais corriger *dans* un conteneur en cours d'exécution (`exec` + `apt upgrade`
dans le conteneur) : il sera recréé avec l'ancienne image au prochain déploiement/reboot,
et la correction disparaît. Toujours :
1. `docker pull` une image upstream déjà corrigée, ou
2. reconstruire l'image (`docker build`) avec une base (`FROM ...`) mise à jour,

puis redéployer. Avant de conclure qu'aucune image locale n'est concernée, relancer le
script avec `--scan-images`/`-ScanImages` (sinon une image jamais démarrée reste invisible
— voir "Confiance : PARTIELLE" dans le [`README.md`](README.md) racine).

## 2. Système d'exploitation

- **Linux** → section 3, puis 4a.
- **Windows** → section 4b directement (pas de notion de distribution/gestionnaire de paquets système équivalente).

## 3. Linux — distribution et version

| Distribution détectée | Remarque |
|---|---|
| Debian 12 / 13 | Rétroportage de sécurité suivi — voir tableau Debian dans `php2shell/README.md` / `broccoli2shell/README.md` |
| Ubuntu 22.04 / 24.04 / 26.04 / 26.10 | Idem, rétroportage suivi dans le dépôt principal |
| Ubuntu 16.04 / 18.04 / 20.04 | Rétroportage uniquement si **Ubuntu Pro/ESM** est actif — sinon EOL réel, pas de correctif possible sans migration |
| Alpine | Suivi via `apk` — versions souvent alignées sur upstream, vérifier le tableau Alpine |
| Autre (RHEL/CentOS, Arch, compilé maison) | **Non couvert par les tableaux distro** — se fier uniquement à la version upstream réelle du binaire (`php -v`, `node -v`, etc.) |

## 4. Mode d'installation

### 4a. Linux

| Gestionnaire / mode | Action type |
|---|---|
| `apt`/`dpkg` (paquet trouvé via `dpkg -S`) | `sudo apt update && sudo apt install --only-upgrade <paquet>` — nom exact donné par le script (ligne `PKG`) |
| `apk` (Alpine) | `sudo apk update && sudo apk add --upgrade <paquet>` |
| `snap` | `sudo snap refresh <nom-du-snap>` (ex. `sudo snap refresh node`, `sudo snap refresh php8`) |
| `pip` (Python Brotli/brotlicffi) | `pip install --upgrade brotli brotlicffi` — dans le **même venv/interpréteur** que celui signalé par le script |
| NodeSource (dépôt officiel Node.js) | `sudo apt update && sudo apt install --only-upgrade nodejs` |
| `nvm` | `nvm install --lts && nvm alias default lts/*` |
| Binaire manuel / compilé maison (aucun paquet trouvé) | Pas de commande système : télécharger/recompiler la version corrigée vous-même, puis remplacer le binaire |
| Node/PHP installé par défaut via **apt Debian/Ubuntu** (pas NodeSource/Sury) et EOL depuis longtemps | ⚠️ Piège fréquent : le dépôt distro par défaut fige souvent une vieille version sans suivi de sécurité actif pour Node.js (contrairement à PHP, qui lui bénéficie d'un vrai rétroportage distro — voir §3). Dans ce cas, changer de source (NodeSource) plutôt qu'attendre un correctif distro qui ne viendra pas. |

### 4b. Windows

| Mode d'installation | Action type |
|---|---|
| XAMPP / WAMP (trouvé par recherche récursive, PHP) | Réinstaller le paquet XAMPP/WAMP packageant une version PHP ≥ corrigée — **Windows Update ne les met pas à jour** |
| IIS + FastCGI (`applicationHost.config`) | Télécharger un `php-cgi.exe` corrigé sur <https://windows.php.net/download/>, remplacer le binaire au chemin trouvé, redémarrer le pool d'applications IIS |
| Node.js installeur officiel / PATH | Réinstaller depuis <https://nodejs.org> (choisir la ligne LTS active), ou `winget upgrade OpenJS.NodeJS.LTS` |
| .NET runtime | `winget upgrade Microsoft.DotNet.Runtime.8` (adapter la version concernée : 8/9/10) |
| .NET self-contained (appli publiée avec son propre runtime) | Un upgrade système ne suffit pas — republier l'application avec le SDK à jour |
| Docker Desktop (conteneurs/images) | Même règle que §1 "Image Docker" : `docker pull`/rebuild, jamais de correctif en place |

## 5. Docker/Podman ou Snap présents sur l'hôte, quelle que soit la distribution

- **Docker/Podman installé** → toujours relancer le script correspondant avec
  `--scan-images`/`-ScanImages` avant d'affirmer que la machine n'est pas vulnérable (une
  image locale jamais démarrée est invisible sinon — c'est la différence entre
  "Confiance : PARTIELLE" et "Confiance : COMPLÈTE", voir [`README.md`](README.md)).
- **Snap installé** → vérifier aussi les paquets snap (`snap list`) pour `php*`/`node*` en
  plus du gestionnaire de paquets système : un snap suit son propre cycle de mise à jour,
  indépendant de `apt`/`apk`.

## 6. Quelle faille, quelle doc lire pour corriger

| Faille | Composant trouvé vulnérable | Doc à lire en détail | Commande type (voir §4 pour le mode exact) |
|---|---|---|---|
| PHP2Shell | PHP via paquet système | [`php2shell/README.md`](php2shell/README.md) — tableau "Paquets Debian/Ubuntu" | `apt install --only-upgrade php8.x-*` |
| PHP2Shell | Branche EOL sans rétroportage trouvé | [`php2shell/README.md`](php2shell/README.md) — section "Procédure" | Migrer vers 8.2/8.3/8.4/8.5 |
| PHP2Shell | XAMPP/WAMP/IIS (Windows) | [`php2shell/README.md`](php2shell/README.md) | Voir §4b ci-dessus |
| PHP2Shell | Conteneur Docker/Podman | [`php2shell/README.md`](php2shell/README.md) — "Mitigation" | Voir §1 "Image Docker" ci-dessus |
| Broccoli2Shell | `libbrotli` système | [`broccoli2shell/README.md`](broccoli2shell/README.md) — tableau "Paquets" | `apt/apk install --only-upgrade libbrotli1` |
| Broccoli2Shell | Node.js | [`broccoli2shell/README.md`](broccoli2shell/README.md) — tableau Node | Voir §4a/4b "Node" ci-dessus |
| Broccoli2Shell | Python `brotli`/`brotlicffi` | [`broccoli2shell/README.md`](broccoli2shell/README.md) — section Python | `pip install --upgrade brotli brotlicffi` |
| Broccoli2Shell | .NET (partagé ou self-contained) | [`broccoli2shell/README.md`](broccoli2shell/README.md) — section .NET | Voir §4a/4b ".NET" ci-dessus |
| Broccoli2Shell | Copie embarquée (Pillow, 7-Zip, DuckDB, woff2…) | [`broccoli2shell/README.md`](broccoli2shell/README.md) — "Copies embarquées" | Mettre à jour le paquet applicatif qui l'embarque (ex. `pip install --upgrade Pillow`), pas de commande système directe |
| Broccoli2Shell | Conteneur Docker/Podman | [`broccoli2shell/README.md`](broccoli2shell/README.md) — "Mitigation" | Voir §1 "Image Docker" ci-dessus |

Dans tous les cas : après toute action, **relancer le script correspondant**
(`test_php2shell.sh`/`Test-Php2Shell.ps1` ou `test_broccoli2shell.sh`/`Test-Broccoli2Shell.ps1`,
avec `--scan-images`/`-ScanImages` si Docker/Podman est présent) pour confirmer que la ligne
passe de `[VULNÉRABLE]`/`[À VÉRIFIER]` à `[CORRIGÉ]`/`[OK]`, et que la ligne finale affiche
`Confiance : COMPLÈTE`.
