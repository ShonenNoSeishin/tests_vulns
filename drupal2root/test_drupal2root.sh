#!/usr/bin/env bash
# test_drupal2root.sh — script UNIQUE et autonome qui cherche la faille dite « Drupal2Root »
# (CVE-2026-132165, « Highly critical » 20/25 selon l'avis officiel Drupal SA-CORE-2026-017) :
# install.php peut, sous conditions spécifiques, être utilisé pour relancer l'installeur sur un
# site Drupal déjà installé -> prise de contrôle du site ou exécution de code à distance SANS
# authentification. Exploitation active signalée par l'équipe sécurité Drupal elle-même dès le
# 19/11/2026 (sites en production), et ajoutée au catalogue KEV CISA le 24/11/2026. Voir README.md.
#
# DIFFÉRENCE IMPORTANTE avec nginx2root/apache2root/php2shell : Drupal (10/11) n'est PAS distribué
# via un paquet système apt/dnf/apk -- il est presque toujours déployé en code applicatif PHP
# (Composer/tarball) dans un dossier web. Ce script ne compare donc AUCUNE version de paquet
# dpkg/rpm : il cherche directement le fichier core/lib/Drupal.php (constante VERSION) sur le
# système de fichiers, dans les conteneurs actifs, et (en option) dans les images locales.
#
# Déploiement : copier CE SEUL FICHIER sur la machine :
#   chmod +x test_drupal2root.sh
#   ./test_drupal2root.sh                # mode lecture seule (par défaut)
#   ./test_drupal2root.sh --scan-images  # + sonde les images Docker/Podman locales (conteneur éphémère --network none)
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

# Statut d'une version Drupal "X.Y.Z" -> vuln / eol / ok / unk
# Plages affectées (avis officiel SA-CORE-2026-017, fetch direct le 25/11/2026) :
#   <10.6.22  ||  >=11.0.0 <11.3.22  ||  >=11.4.0 <11.4.13
# Drupal 11.2.x et antérieur, et 10.5.x et antérieur, sont EN FIN DE VIE (pas de correctif direct
# dans la même branche -- il faut migrer vers 10.6.x ou 11.3.x/11.4.x PUIS appliquer le correctif).
# Drupal 8 et 9 (maj < 10) sont eux-mêmes totalement en fin de vie depuis 2021/2023.
drupal_status() {
  local v="$1" maj min pat
  maj=$(printf '%s' "$v" | cut -d. -f1)
  min=$(printf '%s' "$v" | cut -d. -f2)
  pat=$(printf '%s' "$v" | cut -d. -f3)
  case "$maj" in ''|*[!0-9]*) echo unk; return ;; esac
  case "$min" in ''|*[!0-9]*) echo unk; return ;; esac
  case "$pat" in ''|*[!0-9]*) pat=0 ;; esac

  if [ "$maj" -lt 10 ]; then echo eol; return; fi

  if [ "$maj" -eq 10 ]; then
    if [ "$min" -lt 6 ]; then echo eol; return; fi
    if [ "$min" -eq 6 ]; then
      if [ "$pat" -lt 22 ]; then echo vuln; else echo ok; fi
      return
    fi
    echo unk; return
  fi

  if [ "$maj" -eq 11 ]; then
    if [ "$min" -le 2 ]; then echo eol; return; fi
    if [ "$min" -eq 3 ]; then
      if [ "$pat" -lt 22 ]; then echo vuln; else echo ok; fi
      return
    fi
    if [ "$min" -eq 4 ]; then
      if [ "$pat" -lt 13 ]; then echo vuln; else echo ok; fi
      return
    fi
    echo unk; return
  fi

  echo unk
}

# Script d'analyse exécuté DANS la cible (hôte, conteneur ou image) : n'écrit rien, ne fait que
# lire. -xdev limite la recherche au système de fichiers racine (même convention que
# php2shell/test_php2shell.sh) -- ne traverse pas les volumes montés séparément : si un docroot
# Drupal vit sur un volume/montage dédié, il ne sera pas trouvé par défaut (voir README, Limites
# connues). Chaque installation trouvée est une ligne "FOUND|<racine>|<version>|<perm settings.php>".
PROBE='
find / -xdev -type f -path "*/core/lib/Drupal.php" 2>/dev/null | while IFS= read -r f; do
  root="${f%/core/lib/Drupal.php}"
  ver=$(grep "const VERSION" "$f" 2>/dev/null | head -n1 | sed "s/[^0-9.]//g")
  sp="$root/sites/default/settings.php"
  spperm=""
  if [ -f "$sp" ]; then
    spperm=$(stat -c "%a" "$sp" 2>/dev/null)
    [ -z "$spperm" ] && spperm=$(stat -f "%Lp" "$sp" 2>/dev/null)
  fi
  printf "FOUND|%s|%s|%s\n" "$root" "${ver:-}" "${spperm:-}"
done
'

analyse_one() { # $1 = label contexte, $2 = root, $3 = version, $4 = perm settings.php
  local ctx="$1" root="$2" ver="$3" spperm="$4" status note="" p3 g o
  if [ -n "$spperm" ]; then
    p3="${spperm: -3}"
    g="${p3:1:1}"; o="${p3:2:1}"
    case "$g$o" in
      *[2367]*) note=" (settings.php permissions $spperm -- possiblement modifiable au-delà du propriétaire, vérifier si le serveur web a ce droit)" ;;
      *) note=" (settings.php permissions $spperm, non modifiable au-delà du propriétaire -- un des chemins d'exploitation est probablement mitigé, voir README)" ;;
    esac
  fi
  if [ -z "$ver" ]; then
    UNK=$((UNK+1)); FINDINGS+=("$ctx:$root")
    printf '  [À VÉRIFIER] %s : installation Drupal trouvée en %s mais version illisible (constante\n' "$ctx" "$root"
    printf '      VERSION introuvable dans core/lib/Drupal.php -- fichier modifié/tronqué ?)\n'
    return
  fi
  status=$(drupal_status "$ver")
  case "$status" in
    vuln)
      VULN=$((VULN+1)); FINDINGS+=("$ctx:$root")
      printf '  [VULNÉRABLE] %s : Drupal %s en %s (CVE-2026-132165, install.php -> prise de contrôle\n' "$ctx" "$ver" "$root"
      printf '      du site / RCE sans authentification, exploité activement selon le avis officiel)%s\n' "$note"
      ;;
    eol)
      VULN=$((VULN+1)); FINDINGS+=("$ctx:$root")
      printf '  [VULNÉRABLE] %s : Drupal %s en %s -- branche EN FIN DE VIE, ne recevra JAMAIS de\n' "$ctx" "$ver" "$root"
      printf '      correctif direct (CVE-2026-132165) : migration complète vers 10.6.22+/11.3.22+/\n'
      printf '      11.4.13+ nécessaire, pas un simple composer update dans la même branche%s\n' "$note"
      ;;
    ok)
      OK=$((OK+1))
      printf '  [CORRIGÉ] %s : Drupal %s en %s (>= seuil corrigé de sa branche)%s\n' "$ctx" "$ver" "$root" "$note"
      ;;
    unk)
      UNK=$((UNK+1)); FINDINGS+=("$ctx:$root")
      printf '  [À VÉRIFIER] %s : Drupal %s en %s -- numéro de version non reconnu par ce script\n' "$ctx" "$ver" "$root"
      ;;
  esac
}

analyse() { # $1 = libellé contexte, $2 = sortie du PROBE (plusieurs lignes FOUND|...)
  local ctx="$1" out="$2" any=0
  while IFS='|' read -r tag root ver spperm; do
    [ "$tag" = "FOUND" ] || continue
    any=1
    analyse_one "$ctx" "$root" "$ver" "$spperm"
  done <<EOF
$out
EOF
  if [ "$any" -eq 0 ]; then
    NC=$((NC+1))
    printf "  [NON CONCERNÉ] %s : aucune installation Drupal trouvée (core/lib/Drupal.php absent des\n" "$ctx"
    printf '      emplacements scannés -- voir README, Limites connues, pour la portée exacte)\n'
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
