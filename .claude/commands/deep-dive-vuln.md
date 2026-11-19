---
description: Analyse profonde d'une faille/CVE — crée les scripts de détection publics (tests_vulns) et le dossier privé d'exploitation/tests (ir-context), teste sur la VM de Lab
argument-hint: <CVE-ou-nom-de-la-faille> [composant/produit si pas évident]
---

Faille à analyser : $ARGUMENTS

Lis d'abord `/home/thib/ir-context/company-profile.md` (priorités/parc) et
`/home/thib/ir-context/lab-vm.md` (ce qui tourne déjà sur la VM de Lab, pour ne rien casser).

## 1. Recherche

Rassemble, de sources officielles en priorité (avis vendeur, NVD, GHSA, security tracker de la
distro concernée, CISA KEV) :

- Description technique précise du mécanisme (pas juste "RCE", le *comment*).
- **Toutes** les versions/variantes affectées, et les subtilités de packaging :
  - **Backporting** : la distro (Debian/Ubuntu/RHEL...) a-t-elle backporté le correctif dans une
    version de paquet qui semble "ancienne" en upstream ? Vérifier via le security tracker officiel
    et `changelog`, pas seulement le numéro de version affiché par le binaire. **Noter
    explicitement le résultat des deux cas, pas seulement "backport existe"** : si tu confirmes
    qu'AUCUN correctif n'est encore disponible dans les dépôts d'une distro (cas réel : nginx2root,
    Debian trixie, 19/11/2026 — toujours marqué "vulnerable" sur security-tracker.debian.org pour
    `1.26.3-3+deb13u10`), ce fait doit être écrit noir sur blanc dans le README **et** dans
    `vuln.yaml` → `fix:` (voir section 2) : c'est l'information qui évite qu'un technicien lance
    `apt install --only-upgrade <paquet>`, lise "already the newest version", et conclue à tort
    que c'est corrigé.
  - **Snap / Flatpak / AppImage** : le paquet confiné embarque-t-il sa propre copie de la
    dépendance vulnérable (souvent non alignée sur la version système) ?
  - **Docker/Podman** : images officielles vs images tierces, images locales non démarrées
    (invisibles en lecture seule), copies de la lib vulnérable dans le conteneur indépendamment
    de l'hôte.
  - Pour Windows : build number exact (pas juste "Windows Server 2019"), KB qui corrige, rôle
    concerné (AD/TS/SQL) si pertinent pour le parc.
- Existence d'un exploit public, PoC, module Metasploit.
- Workaround officiel si pas encore de patch, ou si la version est en fin de support (ex. Windows
  Server 2012 sans ESU).

Si une information clé manque après recherche (ex. CVE ambigu, plusieurs failles portent un nom
proche), pose la question à l'utilisateur plutôt que de deviner.

## 2. Volet public — `/home/thib/Incident_Response_Project/<slug>/`

Crée (ou mets à jour si le dossier existe déjà) un dossier suivant **exactement** les conventions
du repo (relire un dossier existant, ex. `php2shell/`, avant d'écrire) :

- `test_<slug>.sh` (bash) et `Test-<Slug>.ps1` (PowerShell), **autonomes** (aucune dépendance à un
  autre fichier du repo), avec :
  - section « 0. Prérequis » en premier (vérifie les commandes dispo, ignore proprement ce qui
    manque) ;
  - mode **lecture seule par défaut** ; `--scan-images`/`-ScanImages` en opt-in pour les conteneurs
    éphémères (`--network none`, détruit juste après) ;
  - couverture explicite de **tous** les vecteurs identifiés à l'étape 1 (paquet système, snap,
    docker conteneurs actifs + images locales, copie embarquée, build Windows) — objectif : **zéro
    faux négatif accepté silencieusement**. Tout vecteur non couvert doit forcer un résultat
    `[À VÉRIFIER]`, jamais `[OK]` par défaut ;
  - comparaison contre la **version réellement patchée par le fournisseur/distro** (pas l'upstream
    brut) pour éviter les **faux positifs** sur une version backportée ;
  - une ligne par élément détecté (`[VULNÉRABLE]` / `[À VÉRIFIER]` / `[CORRIGÉ]`/`[OK]` /
    `[NON CONCERNÉ]`) ;
  - ligne finale « Confiance » (COMPLÈTE / PARTIELLE / INCOMPLÈTE / vulnérable confirmé) ;
  - code de sortie 0/1/2.
- `README.md` du dossier : explication courte et **concise, destinée à une équipe IT L1**
  (vocabulaire simple, pas de jargon inutile) + tableau versions vulnérables/corrigées + procédure
  de vérification + **procédure de patch par méthode d'installation** (paquet/Docker/Snap/KB
  Windows) + limites connues + références (liens officiels seulement).
  - Si un patch est **simple et sûr** (mise à jour de paquet standard, KB Windows, redémarrage
    service) → le dire explicitement comme "action L1".
  - Si c'est complexe/risqué (migration, changement de config impactant, pas de patch dispo,
    serveur en fin de vie) → marquer clairement "à escalader équipe sécu/infra", sans détailler de
    procédure dangereuse pour du L1.
  - **Aucune méthode d'exploitation ici.** Mention possible : "méthode active de vérification
    disponible dans `public-scan/`" si pertinent, sans payload.
  - Si aucun rétroportage distro n'est confirmé (voir étape 1) : le dire en encadré bien visible
    (pas noyé en fin de tableau), mettre le vrai correctif disponible (dépôt amont, backport
    manuel, contournement) en premier dans la procédure, et terminer la section correction par un
    rappel explicite de relancer le script pour confirmer — ne jamais laisser la commande standard
    du gestionnaire de paquets comme seule option présentée.
- Ajoute une ligne dans le tableau « Failles couvertes » de `README.md` racine.
- Mets à jour `REMEDIATION.md` (arbre de décision) avec le nouveau cas.
- **Crée ou mets à jour `<slug>/vuln.yaml` — OBLIGATOIRE, pas optionnel.** C'est ce fichier que lit
  l'app IRM (Incident_Response_Management) pour afficher la faille (fil d'actualité, badge
  « Nouveau »/« Mis à jour », fiche guidée, téléchargement des scripts) : **un dossier sans
  `vuln.yaml` valide est ignoré silencieusement par IRM**, même si le README et les scripts sont
  parfaits. Suivre exactement `docs/FORMAT.md` :
  - `id` = nom du dossier (identique au nom du répertoire) ;
  - `published` = date de divulgation/d'ajout (format AAAA-MM-JJ) ; **si le dossier existe déjà et
    que tu modifies son contenu, mets `updated:` à la date du jour** (c'est `updated`, pas la date
    du commit git, qui déclenche le badge « Mis à jour » dans IRM) ;
  - `tests:` doit référencer exactement les scripts créés dans ce même dossier (`file:` = nom de
    fichier présent à côté du `vuln.yaml`, pas un chemin d'un autre dossier) ;
  - `results`, `fix`, `references` : uniquement des liens `https://` officiels, jamais de méthode
    d'exploitation (même règle que le README).
  - **`fix:` — règle anti-faux-sentiment-de-sécurité (voir `docs/FORMAT.md` pour le détail
    complet), à appliquer systématiquement, pas seulement quand le cas se présente de façon
    évidente** : l'app IRM affiche ce champ directement, sans forcément montrer le README complet,
    donc la nuance doit vivre dans le YAML lui-même.
    1. Le **premier** élément de `fix:` doit être celui qui corrige réellement la faille
       **aujourd'hui**, d'après ce que tu as vérifié à l'étape 1 — jamais une commande standard de
       gestionnaire de paquets si aucun rétroportage distro n'est confirmé.
    2. Si une commande de gestionnaire de paquets est quand même listée alors qu'aucun
       rétroportage n'existe, son `command:` doit porter l'avertissement **dans la chaîne
       elle-même** (pas seulement dans `for:`) — ex. `"NE CORRIGE RIEN tant qu'aucun correctif
       distro n'est sorti pour cette CVE précise -- voir le dépôt amont ci-dessus"`.
    3. **Toujours** terminer `fix:` par un élément du type
       `{for: "Après toute action", command: "Relancer le script de détection et vérifier le numéro de version affiché -- ne jamais se fier au seul message du gestionnaire de paquets"}`.

## 3. Volet privé — `/home/thib/ir-context/deep-dive/<slug>/`

- `exploitation.md` : méthode(s) d'exploitation détaillées, pas à pas, **pour test autorisé
  uniquement sur nos propres machines** (rappelle-le en en-tête). Inclut les commandes/payloads
  nécessaires pour reproduire concrètement l'impact (ex. preuve de RCE via commande inoffensive
  type `id`/`whoami`, pas de charge destructrice).
- `lab-results.md` : résultats du test réel (étape 4).

## 4. Test sur la VM de Lab (spontané, sans attendre une demande)

Tu es déjà sur la VM de Lab. Applique les règles de `lab-vm.md` :

1. Lance ton propre script de détection (`test_<slug>.sh`) en mode lecture seule puis
   `--scan-images` sur cette VM, consigne le résultat.
2. Si une démonstration d'exploitation est possible sans danger pour les services déjà en place
   (cf. `lab-vm.md`) : monte un environnement **jetable et isolé** (conteneur `--network none`
   sauf si la faille a besoin de réseau pour être démontrée, dans ce cas réseau isolé dédié),
   reproduis l'impact avec une charge inoffensive, détruis l'environnement ensuite.
3. Si ce n'est pas raisonnablement possible sur cette VM (faille Windows AD, matériel spécifique,
   risque pour les services existants...), dis-le clairement dans `lab-results.md` et explique ce
   qu'il faudrait pour tester ailleurs (ex. "nécessite une VM Windows Server 2019 AD dédiée").
4. Consigne tout dans `ir-context/deep-dive/<slug>/lab-results.md` — jamais dans le repo public.

## 5. Avant de committer/pousser le volet public

Relis `/home/thib/Incident_Response_Project/CLAUDE.md` et vérifie en particulier :

- aucun contenu de `ir-context/` copié dans le repo public ;
- aucun nom de société, hostname/IP interne, méthode d'exploitation, résultat de test réel ;
- pas de ligne de co-autorat IA dans le message de commit.

**Valide chaque `vuln.yaml` créé ou modifié avant de committer** (un YAML syntaxiquement correct
mais avec un champ manquant/incohérent est aussi silencieusement ignoré par IRM qu'un fichier
absent) :
```
python3 -c "import yaml,sys,datetime as d; x=yaml.safe_load(open(sys.argv[1])); assert x['title'] and x['summary'] and x['severity'] in ('critical','high','medium','low') and x['id']==sys.argv[1].split('/')[-2]; d.date.fromisoformat(str(x['published']))" <slug>/vuln.yaml
```
Vérifier aussi que chaque `file:` listé sous `tests:` existe bien dans le dossier (`ls <slug>/`).

Propose le commit (message clair, sans attribution IA) mais **demande confirmation avant de
pousser** — action qui publie immédiatement et est difficile à annuler complètement une fois
indexée. **Une fois confirmé, pousse vers les deux remotes** (ce repo a `origin` = GitHub public
et `forgejo` = miroir interne) :
```
git push origin main && git push forgejo main
```
Vérifie ensuite que les deux sont bien synchronisés (`git log origin/main..main` et
`git log forgejo/main..main` doivent être vides) avant de conclure. Termine en rappelant à
l'utilisateur de **faire Pull sur la source dans IRM** pour que la nouvelle fiche apparaisse.

## 6. Fin

Termine par un résumé court : ce qui a été créé (public/privé), le résultat du test sur la VM de
Lab, et si quelque chose reste bloqué en attente d'une décision humaine (ex. escalade équipe
sécu, accès à une VM Windows AD de test).
