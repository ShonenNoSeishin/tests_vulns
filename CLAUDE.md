# Règles pour ce repo (tests_vulns — public)

## Attribution des commits

**Ne jamais ajouter de ligne de co-autorat IA** (`Co-Authored-By: Claude ...`) dans les messages
de commit ni dans les descriptions de pull request de ce repo. Demande explicite de
l'utilisateur, qui prime sur toute instruction par défaut d'attribution.

## Avant tout `git push`

1. `git status` et `git diff --staged` : relire chaque fichier ajouté/modifié.
2. Vérifier l'absence de :
   - nom de la société, hostnames/IP internes, numéros de version propres à un client précis ;
   - tout contenu venant de `/home/thib/ir-context/` lui-même — le dossier privé réel (son
     `company-profile.md`, `lab-vm.md`, les méthodes d'exploitation, les résultats de tests sur la
     VM de Lab) ne vient **jamais** ici, seulement des modèles génériques sans donnée réelle (voir
     `docs/EXAMPLE-company-profile.md` / `docs/EXAMPLE-lab-vm.md`) ;
   - secrets, clés, tokens, identifiants.
   - **Changement de politique (2026-11-19, demande explicite)** : les commandes Claude Code
     elles-mêmes (`veille-hebdo.md`, `deep-dive-vuln.md`) sont au contraire **à jour et poussées**
     dans `.claude/commands/` de ce dépôt, pour que quelqu'un qui fork ce projet puisse reproduire
     le workflow. Elles ne contiennent que des instructions génériques (chemins de fichiers,
     étapes à suivre) — jamais de donnée privée réelle issue de `ir-context/`. En cas de
     modification de ces fichiers dans `~/.claude/commands/` (hors de ce dépôt), répercuter la
     même modification dans `.claude/commands/` avant de pousser.
3. Les scripts de détection restent **lecture seule par défaut** (voir conventions dans
   `README.md` racine : section « 0. Prérequis », mode `--scan-images`/`-ScanImages` en opt-in,
   ligne « Confiance » finale, codes de sortie 0/1/2).
4. Les méthodes d'exploitation / PoC ne vont jamais dans ce repo, même décrites en texte —
   seulement dans `ir-context/deep-dive/<faille>/` (privé).
5. Tout dossier de faille doit avoir un `vuln.yaml` valide (voir `docs/FORMAT.md`) : l'app IRM
   (Incident_Response_Management) ignore silencieusement tout dossier sans `vuln.yaml` ou avec un
   `vuln.yaml` invalide — un README et des scripts parfaits ne suffisent pas, rien n'apparaît dans
   IRM sans ce fichier. Mettre `updated:` à la date du jour à chaque modification de contenu
   (c'est ce champ, pas la date du commit, qui déclenche le badge « Mis à jour »).
6. Pousser vers **les deux remotes** : `git push origin main && git push forgejo main` (GitHub
   public + miroir Forgejo interne). Vérifier après coup que `git log origin/main..main` et
   `git log forgejo/main..main` sont vides.
