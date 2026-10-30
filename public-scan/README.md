# Scan public (nmap) — PHP2Shell et Broccoli2Shell vus depuis l'extérieur

Les dossiers [`php2shell/`](../php2shell/) et [`broccoli2shell/`](../broccoli2shell/) nécessitent
un accès à la machine (shell local, SSH). Ce dossier couvre le cas où vous n'avez **que** le nom
de domaine ou l'IP publique d'une cible — typiquement pour un premier passage sur tout votre
périmètre public, avant d'aller vérifier en détail chaque machine trouvée.

> ⚠️ **Avertissement légal/éthique.** Contrairement aux scripts des deux autres dossiers (qui
> n'envoient aucune requête à qui que ce soit), **ce scan contacte réellement la cible par le
> réseau**. Ne l'utilisez QUE sur un domaine, une IP ou un périmètre que **vous possédez** ou que
> vous êtes **explicitement autorisé par écrit** à tester. Scanner une infrastructure tierce sans
> autorisation peut être illégal selon votre juridiction, même avec un simple `nmap -sV`. En cas de
> doute, ne scannez pas.

## Ce que ce scan peut et ne peut PAS vous dire

**C'est important, lisez ceci avant de lancer quoi que ce soit.**

| Faille | Ce que nmap peut détecter | Ce qu'il ne peut PAS détecter |
|---|---|---|
| **PHP2Shell** | La version de PHP, **si le serveur l'expose** (en-tête `X-Powered-By`, comportement caractéristique testé par le script `http-php-version`) | Rien si l'administrateur a durci la configuration (`expose_php = Off`, reverse-proxy qui retire l'en-tête) — **l'absence de version visible NE PROUVE PAS que le serveur est à jour**, ça prouve seulement que le scan est non concluant |
| **Broccoli2Shell** | Si le serveur **négocie** la compression Brotli (en-tête `Content-Encoding: br` en réponse) | La **version** du décodeur Brotli utilisé n'est jamais visible depuis le réseau — ce point n'a **aucun moyen fiable d'être tranché** par un scan externe, quel que soit l'outil |

Pour Broccoli2Shell en particulier, ce scan est donc **"si applicable" au sens strict** : il peut
au mieux vous dire "ce serveur utilise Brotli, creusez en interne", jamais "il est corrigé" ou
"il est vulnérable". **Seuls les scripts de `php2shell/` et `broccoli2shell/`, exécutés directement
sur la machine, peuvent donner un verdict fiable.** Ce scan public sert à prioriser quoi auditer
en interne, pas à remplacer cet audit.

## 1. Installer nmap

**Linux :**
```bash
sudo apt install nmap          # Debian / Ubuntu
sudo dnf install nmap          # Fedora / RHEL / CentOS
sudo apk add nmap              # Alpine
```

**macOS :**
```bash
brew install nmap
```

**Windows :**
- Installeur officiel : <https://nmap.org/download.html#windows> (inclut Npcap, nécessaire pour les scans avancés), ou
- `winget install Insecure.Nmap`, ou
- `choco install nmap`

Vérifier l'installation :
```bash
nmap --version
```

## 2. Scanner une cible

Remplacer `cible.exemple.com` par le domaine ou l'IP à auditer (le vôtre, voir l'avertissement
ci-dessus).

**Services et versions sur les ports web courants :**
```bash
nmap -sV -p 80,443,8080,8443 cible.exemple.com
```

**Tenter de repérer la version PHP exposée** (script `http-php-version`, fourni avec nmap — teste
plusieurs comportements caractéristiques de PHP, pas seulement l'en-tête `Server`) :
```bash
nmap -p 80,443 --script=http-server-header,http-php-version cible.exemple.com
```
Si une version apparaît, la comparer au tableau de `../php2shell/README.md`. **Attention au piège
Debian/Ubuntu déjà documenté là-bas** : un serveur peut afficher une vieille version PHP en
apparence EOL alors qu'elle est en réalité patchée par la distribution — un scan externe ne peut
pas faire la différence, seul `test_php2shell.sh` exécuté sur la machine le peut.

**Voir si la cible utilise Brotli :**
```bash
nmap -p 80,443 --script=http-headers cible.exemple.com
```
Chercher une ligne `Content-Encoding: br` dans la sortie. (nmap n'est pas l'outil le plus direct
pour ce point précis — une simple requête `curl -sI -H 'Accept-Encoding: br' https://cible.exemple.com`
donne la même information plus clairement — mais `http-headers` fonctionne aussi et reste dans
l'esprit "tout avec nmap" de cette section.)

**Scanner une liste d'IP publiques en une fois** (reprend l'usage "scanner tout notre périmètre
public" qui a motivé ce dossier) :
```bash
# ips.txt : une IP ou un domaine par ligne
nmap -sV -p 80,443,8080,8443 --script=http-server-header,http-php-version -iL ips.txt -oN resultats.txt
```

## 3. Script tout-en-un

```bash
chmod +x scan_public.sh
./scan_public.sh cible.exemple.com
./scan_public.sh cible.exemple.com 80,443,8080
```

Il enchaîne les trois commandes ci-dessus et termine par un rappel explicite des limites — il
**n'affiche jamais** de ligne "Confiance : COMPLÈTE" comme les scripts des deux autres dossiers :
un scan réseau externe ne peut structurellement pas l'atteindre.

> Testé contre `scanme.nmap.org` (la cible publique d'essai officielle de nmap, explicitement
> ouverte à cet usage) : les trois sections s'exécutent correctement, sans version PHP ni Brotli
> détectés sur cette cible (attendu, elle ne sert ni l'un ni l'autre). Pour un test inoffensif
> avant de l'utiliser sur votre propre périmètre : `./scan_public.sh scanme.nmap.org`.

## Références

- nmap : <https://nmap.org/>
- Script `http-php-version` : <https://nmap.org/nsedoc/scripts/http-php-version.html>
- Script `http-server-header` : <https://nmap.org/nsedoc/scripts/http-server-header.html>
- Script `http-headers` : <https://nmap.org/nsedoc/scripts/http-headers.html>
- Cible de test publique officielle de nmap : <https://nmap.org/book/testing.html> (`scanme.nmap.org`)
