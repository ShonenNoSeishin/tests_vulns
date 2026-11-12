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
