# Format `vuln.yaml`

Chaque dossier de faille contient un `vuln.yaml` à côté de son `README.md` et de ses scripts. L'interface **IRM** le lit pour afficher la
faille (fil d'actualité, badge « nouveau », fiche guidée *Suis-je concerné ? → Tester → Corriger*, téléchargement des scripts). Les champs
sont volontairement simples ; seuls `id`, `title`, `severity`, `published` et `summary` sont obligatoires.

```yaml
id: nom-du-dossier                 # identique au nom du dossier
title: "Titre lisible"
cves: [CVE-2026-00000]
severity: critical                 # critical | high | medium | low
published: 2026-11-09              # date de divulgation / d'ajout ; sert au badge « Nouveau » (14 jours)
updated: 2026-11-12                # dernière mise à jour de l'article (badge « Mis à jour »)
exploited: true                    # exploitation active connue
kev: true                          # présente au catalogue CISA KEV
summary: >-
  Une ou deux phrases, en langage clair : ce qui est cassé, qui est touché, ce qu'il faut faire.
affects: ["Produit et versions", "Autre produit"]
tags: [ssh, alpine]
concerned: ["Cas où la machine est concernée"]
not_concerned: ["Cas où elle ne l'est pas"]
tests:                             # scripts téléchargeables (fichiers du dossier uniquement)
  - os: linux                      # linux | windows | any
    label: "Linux (hôte + conteneurs)"
    file: test_x.sh
    run: "chmod +x test_x.sh && sudo ./test_x.sh --scan-images"
    note: "Texte facultatif"
results:                           # comment lire le résultat du script
  - {status: "VULNÉRABLE", meaning: "…", action: "…"}
fix:                               # corrections par cas, avec la commande à copier
  - {for: "Debian / Ubuntu", command: "apt update && apt upgrade"}
fixed_versions: "Texte libre"
docs: [README.md]                  # fichiers Markdown affichés dans l'article
references:
  - {title: "Avis éditeur", url: "https://…"}
```

Règles de contenu (dépôt public) : voir `CLAUDE.md` — pas de nom de société, d'hôte ou d'IP internes, pas de méthode d'exploitation, pas de secret.

## Règle sur `fix:` — ne jamais présenter un correctif qui peut ne rien faire comme suffisant

**Incident réel (nginx2root, 19/11/2026)** : un technicien a lu la fiche, lancé la commande de
correction listée en premier (`apt install --only-upgrade nginx`), obtenu
`nginx is already the newest version`, et en a conclu — à raison, compte tenu de ce qui était
écrit — que la faille était corrigée. En réalité Debian n'avait tout simplement **pas encore
publié de correctif** pour cette CVE précise : « déjà la plus récente » ne veut dire que « c'est
la version la plus récente **disponible dans les dépôts configurés** », jamais « c'est corrigé ».
L'app IRM affiche le champ `fix:` directement, sans forcément montrer tout le README — la
nuance doit donc vivre **dans le YAML lui-même**, pas seulement en prose dans le README.

Conséquences concrètes pour chaque `vuln.yaml` :

1. **Vérifier le statut du rétroportage avant d'écrire `fix:`** (tracker de sécurité officiel de
   chaque distro pertinente, pas une supposition). Ce statut doit être revérifié à chaque mise à
   jour de la fiche — il peut changer entre deux relectures.
2. **Le premier élément de `fix:` doit toujours être celui qui corrige réellement la faille
   aujourd'hui.** Si aucun rétroportage distro n'existe encore, ce n'est PAS la commande standard
   du gestionnaire de paquets (dépôt amont officiel, backport manuel, contournement — selon ce qui
   marche vraiment).
3. **Si la commande standard du gestionnaire de paquets est quand même listée alors qu'aucun
   rétroportage n'est confirmé**, son `command:` doit porter l'avertissement **dans la chaîne
   elle-même** (pas seulement dans `for:`), par exemple :
   `"NE CORRIGE RIEN tant qu'aucun correctif distro n'est sorti pour cette CVE précise -- 'already the newest version' ne le prouve pas, voir le dépôt amont ci-dessus"`.
4. **Toujours terminer `fix:` par un rappel de vérification** pointant vers le script de détection
   du dossier, pas vers le seul message du gestionnaire de paquets, par exemple :
   `{for: "Après toute action", command: "Relancer le script de détection et vérifier le numéro de version affiché -- ne jamais se fier au seul message du gestionnaire de paquets"}`.
