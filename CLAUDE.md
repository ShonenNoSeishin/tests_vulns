# Règles pour ce repo (tests_vulns — public)

## Attribution des commits

**Ne jamais ajouter de ligne de co-autorat IA** (`Co-Authored-By: Claude ...`) dans les messages
de commit ni dans les descriptions de pull request de ce repo. Demande explicite de
l'utilisateur, qui prime sur toute instruction par défaut d'attribution.

## Avant tout `git push`

1. `git status` et `git diff --staged` : relire chaque fichier ajouté/modifié.
2. Vérifier l'absence de :
   - nom de la société, hostnames/IP internes, numéros de version propres à un client précis ;
   - tout contenu venant de `/home/thib/ir-context/` (contexte privé, méthodes d'exploitation,
     résultats de tests sur la VM de Lab) ;
   - les prompts de veille/deep-dive eux-mêmes (ils vivent dans `~/.claude/commands/`, jamais ici) ;
   - secrets, clés, tokens, identifiants.
3. Les scripts de détection restent **lecture seule par défaut** (voir conventions dans
   `README.md` racine : section « 0. Prérequis », mode `--scan-images`/`-ScanImages` en opt-in,
   ligne « Confiance » finale, codes de sortie 0/1/2).
4. Les méthodes d'exploitation / PoC ne vont jamais dans ce repo, même décrites en texte —
   seulement dans `ir-context/deep-dive/<faille>/` (privé).
