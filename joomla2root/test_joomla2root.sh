#!/usr/bin/env bash
# test_joomla2root.sh -- script UNIQUE et autonome qui cherche la faille dite « Joomla2Root »
# (CVE-2026-123214, avis officiel Joomla [20261111] « Core - Missing authentication in web
# installer ») : l'installeur web de Joomla reste utilisable sur un site DÉJÀ installé tant que
# le dossier /installation existe, ce qui permet à un attaquant SANS AUTHENTIFICATION de
# réécrire configuration.php -> prise de contrôle complète du site (identifiants admin, base de
# données). Voir README.md.
#
# Nuance CVSS importante (vecteur CVSS:4.0/.../AT:P/...) : l'exploitation nécessite que le
# dossier /installation existe ENCORE sur le site (une bonne pratique de durcissement Joomla,
# documentée depuis longtemps, est de le supprimer après l'installation initiale). Ce script
# vérifie donc DEUX choses séparément : (1) la version du code Joomla, pour savoir si le correctif
# y est présent, et (2) la présence du dossier /installation, à titre d'URGENCE uniquement --
# jamais comme critère d'exclusion. Une version vulnérable reste [VULNÉRABLE] même si
# /installation est absent au moment du test (le dossier peut être recréé par un déploiement
# futur, ex. "composer install"/ré-extraction d'une archive).
#
# DIFFÉRENCE IMPORTANTE avec nginx2root/apache2root/php2shell : Joomla n'est PAS distribué via un
# paquet système apt/dnf/apk -- c'est une application PHP déployée en code (archive/Composer)
# dans un dossier web, comme Drupal (voir drupal2root/). Ce script ne compare donc AUCUNE version
# de paquet dpkg/rpm : il cherche directement le fichier libraries/src/Version.php (constantes
# MAJOR_VERSION/MINOR_VERSION/PATCH_VERSION), structure introduite avec Joomla 4. Joomla 3.x et
# antérieur utilisent un fichier et des constantes différents (libraries/cms/version/version.php) :
# non couverts par ce script, voir README, Limites connues.
#
# Déploiement : copier CE SEUL FICHIER sur la machine :
#   chmod +x test_joomla2root.sh
#   ./test_joomla2root.sh                # mode lecture seule (par défaut)
#   ./test_joomla2root.sh --scan-images  # + sonde les images Docker/Podman locales (conteneur éphémère --network none)
#
# LECTURE SEULE par défaut : rien n'est créé, modifié ni supprimé. Les conteneurs EN COURS
# D'EXÉCUTION sont sondés par `exec` (commandes de lecture). --scan-images lance un conteneur
# éphémère isolé par image, détruit immédiatement après.
# Codes de sortie : 0 = rien à signaler, 1 = à vérifier, 2 = vulnérable confirmé.
set -u
export LC_ALL=C

SCAN_IMAGES=0
for a in "$@"; do
  case "$a" in
    --scan-images) SCAN_IMAGES=1 ;;
    -h|--help)
      echo "Usage: $0 [--scan-images]"
      echo "  (sans option)  : mode lecture seule (hôte + conteneurs actifs, aucune création)"
      echo "  --scan-images  : + conteneurs éphémères --network none pour sonder les images locales"
      exit 0
      ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n===== %s =====\n' "$1"; }

HAVE_TIMEOUT=0; have timeout && HAVE_TIMEOUT=1
run_t() { local t="$1"; shift; if [ "$HAVE_TIMEOUT" -eq 1 ]; then timeout "$t" "$@" 2>/dev/null; else "$@" 2>/dev/null; fi; }

VULN=0; UNK=0; OK=0; NC=0
FINDINGS=()

# Statut d'une version Joomla "MAJ.MIN.PAT" -> vuln / ok / unk
# Plages affectées (avis officiel Joomla [20261111], fetch direct le 27/11/2026) :
#   4.0.0 -- 5.4.10  (branche continue 4.x/5.x, numérotation séquentielle Joomla)  -> corrigé 5.4.11
#   6.0.0 -- 6.2.0   (branche 6.x)                                                -> corrigé 6.2.1
# Joomla 3.x et antérieur : fichier/constantes différents, non trouvés par la sonde de ce script
# (voir README, Limites connues) -- pas besoin de les traiter ici explicitement.
joomla_status() {
  local maj="$1" min="$2" pat="$3" num
  case "$maj" in ''|*[!0-9]*) echo unk; return ;; esac
  case "$min" in ''|*[!0-9]*) echo unk; return ;; esac
  case "$pat" in ''|*[!0-9]*) echo unk; return ;; esac

  if [ "$maj" -lt 4 ]; then echo unk; return; fi

  num=$((maj * 10000 + min * 100 + pat))

  if [ "$maj" -le 5 ]; then
    if [ "$num" -le 50410 ]; then echo vuln; else echo ok; fi
    return
  fi

  if [ "$maj" -eq 6 ]; then
    if [ "$num" -le 60200 ]; then echo vuln; else echo ok; fi
    return
  fi

  echo unk
}

# Script d'analyse exécuté DANS la cible (hôte, conteneur ou image) : n'écrit rien, ne fait que
# lire. -xdev limite la recherche au système de fichiers racine (même convention que
# drupal2root/test_drupal2root.sh) -- ne traverse pas les volumes montés séparément : si un docroot
# Joomla vit sur un volume/montage dédié, il ne sera pas trouvé par défaut (voir README, Limites
# connues). Chaque installation trouvée est une ligne
# "FOUND|<racine>|<maj>|<min>|<pat>|<installation présente 0/1>|<configuration.php présente 0/1>".
PROBE='
find / -xdev -type f -path "*/libraries/src/Version.php" 2>/dev/null | while IFS= read -r f; do
  root="${f%/libraries/src/Version.php}"
  maj=$(grep -oE "MAJOR_VERSION[^0-9]*[0-9]+" "$f" 2>/dev/null | grep -oE "[0-9]+" | head -n1)
  min=$(grep -oE "MINOR_VERSION[^0-9]*[0-9]+" "$f" 2>/dev/null | grep -oE "[0-9]+" | head -n1)
  pat=$(grep -oE "PATCH_VERSION[^0-9]*[0-9]+" "$f" 2>/dev/null | grep -oE "[0-9]+" | head -n1)
  inst=0; [ -d "$root/installation" ] && inst=1
  cfg=0; [ -f "$root/configuration.php" ] && cfg=1
  printf "FOUND|%s|%s|%s|%s|%s|%s\n" "$root" "${maj:-}" "${min:-}" "${pat:-}" "$inst" "$cfg"
done
'

analyse_one() { # $1 ctx, $2 root, $3 maj, $4 min, $5 pat, $6 inst, $7 cfg
  local ctx="$1" root="$2" maj="$3" min="$4" pat="$5" inst="$6" cfg="$7" status note=""
  if [ -z "$maj" ] || [ -z "$min" ] || [ -z "$pat" ]; then
    UNK=$((UNK+1)); FINDINGS+=("$ctx:$root")
    printf '  [À VÉRIFIER] %s : installation Joomla trouvée en %s mais version illisible (constantes\n' "$ctx" "$root"
    printf '      MAJOR_VERSION/MINOR_VERSION/PATCH_VERSION introuvables dans libraries/src/Version.php)\n'
    return
  fi
  if [ "$cfg" -eq 0 ]; then
    note=" (configuration.php absent -- site probablement pas encore installé, à vérifier manuellement)"
  fi
  status=$(joomla_status "$maj" "$min" "$pat")
  case "$status" in
    vuln)
      VULN=$((VULN+1)); FINDINGS+=("$ctx:$root")
      if [ "$inst" -eq 1 ]; then
        printf '  [VULNÉRABLE] %s : Joomla %s.%s.%s en %s (CVE-2026-123214) -- dossier /installation\n' "$ctx" "$maj" "$min" "$pat" "$root"
        printf '      PRÉSENT : précondition d'"'"'exploitation réunie (CVSS AT:P), urgence immédiate%s\n' "$note"
      else
        printf '  [VULNÉRABLE] %s : Joomla %s.%s.%s en %s (CVE-2026-123214) -- dossier /installation\n' "$ctx" "$maj" "$min" "$pat" "$root"
        printf '      absent : précondition actuelle non réunie pour ce vecteur précis, mais le code reste\n'
        printf '      vulnérable (le dossier peut être recréé par un déploiement futur) -- à corriger quand même%s\n' "$note"
      fi
      ;;
    ok)
      OK=$((OK+1))
      if [ "$inst" -eq 1 ]; then
        printf '  [CORRIGÉ] %s : Joomla %s.%s.%s en %s (>= seuil corrigé) -- mais dossier /installation\n' "$ctx" "$maj" "$min" "$pat" "$root"
        printf '      encore présent : à supprimer par bonne pratique de durcissement (non lié à cette CVE précise)%s\n' "$note"
      else
        printf '  [CORRIGÉ] %s : Joomla %s.%s.%s en %s (>= seuil corrigé de sa branche)%s\n' "$ctx" "$maj" "$min" "$pat" "$root" "$note"
      fi
      ;;
    unk)
      UNK=$((UNK+1)); FINDINGS+=("$ctx:$root")
      printf '  [À VÉRIFIER] %s : Joomla %s.%s.%s en %s -- numéro de version non reconnu par ce script\n' "$ctx" "$maj" "$min" "$pat" "$root"
      printf '      (majeur < 4, ou branche future non encore qualifiée)%s\n' "$note"
      ;;
  esac
}

analyse() { # $1 ctx, $2 sortie du PROBE
  local ctx="$1" out="$2" any=0
  while IFS='|' read -r tag root maj min pat inst cfg; do
    [ "$tag" = "FOUND" ] || continue
    any=1
    analyse_one "$ctx" "$root" "$maj" "$min" "$pat" "$inst" "$cfg"
  done <<EOF
$out
EOF
  if [ "$any" -eq 0 ]; then
    NC=$((NC+1))
    printf "  [NON CONCERNÉ] %s : aucune installation Joomla 4/5/6 trouvée (libraries/src/Version.php\n" "$ctx"
    printf '      absent des emplacements scannés -- voir README, Limites connues, notamment pour Joomla 3.x)\n'
  fi
}

# ---------------------------------------------------------------- 0. Prérequis
section "0. Prérequis"
printf '  utilisateur : %s\n' "$(id -un)"
[ "$(id -u)" -eq 0 ] || printf '  [ATTENTION] pas root : certains dossiers web peuvent être illisibles -> faux "non concerné" possible, relancer en root pour une couverture complète\n'
have find || printf '  [ERREUR] commande "find" absente -- ce script ne peut rien détecter sans elle\n'
have docker && RT=docker || { have podman && RT=podman || RT=""; }
[ -n "$RT" ] && printf '  moteur de conteneurs : %s\n' "$RT" || printf '  aucun moteur de conteneurs détecté : hôte seul\n'

# ---------------------------------------------------------------- 1. Hôte
section "1. Hôte"
analyse "hôte $(hostname)" "$(run_t 180 sh -c "$PROBE")"

# ---------------------------------------------------------------- 2. Conteneurs actifs
if [ -n "$RT" ]; then
  section "2. Conteneurs en cours d'exécution (lecture seule)"
  ids=$($RT ps -q 2>/dev/null)
  if [ -z "$ids" ]; then echo "  aucun conteneur actif"; fi
  for id in $ids; do
    name=$($RT inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
    out=$(run_t 90 "$RT" exec "$id" sh -c "$PROBE") || { UNK=$((UNK+1)); echo "  [À VÉRIFIER] conteneur $name : exec impossible ou délai dépassé"; continue; }
    analyse "conteneur $name" "$out"
  done

  section "3. Images locales"
  if [ "$SCAN_IMAGES" -eq 1 ]; then
    for img in $($RT images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | sort -u); do
      out=$(run_t 90 "$RT" run --rm --network none --entrypoint sh "$img" -c "$PROBE") || { echo "  [IGNORÉ] image $img : pas de shell ou délai dépassé (image minimale probable)"; continue; }
      analyse "image $img" "$out"
    done
    NC_IMAGES_DONE=1
  else
    echo "  non sondées (relancer avec --scan-images pour inspecter aussi les images dormantes)"
  fi
fi

# ---------------------------------------------------------------- Bilan
section "Bilan"
printf '  vulnérables : %d | à vérifier : %d | corrigés : %d | non concernés : %d\n' "$VULN" "$UNK" "$OK" "$NC"
[ "${#FINDINGS[@]}" -gt 0 ] && printf '  à traiter : %s\n' "${FINDINGS[*]}"
if [ "$VULN" -gt 0 ]; then echo "Confiance : élément vulnérable CONFIRMÉ"; exit 2; fi
if [ "$UNK" -gt 0 ]; then echo "Confiance : INCOMPLÈTE (au moins un élément à vérifier à la main)"; exit 1; fi
if [ -z "$RT" ]; then echo "Confiance : COMPLÈTE (dans la limite des emplacements scannés, voir README)"; exit 0; fi
if [ "${NC_IMAGES_DONE:-0}" -eq 1 ]; then echo "Confiance : COMPLÈTE (dans la limite des emplacements scannés, voir README)"; exit 0; fi
echo "Confiance : PARTIELLE (images locales non sondées : relancer avec --scan-images)"; exit 0
