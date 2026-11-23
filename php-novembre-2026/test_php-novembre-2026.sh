#!/usr/bin/env bash
# test_php-novembre-2026.sh — script UNIQUE et autonome (n'appelle aucun autre fichier) qui
# audite une machine Linux/macOS pour le lot de correctifs de sécurité PHP du 19/11/2026
# (18 CVE distinctes, dont deux RCE non authentifiées notées CVSS 9.2 (CVSS v4.0) : voir
# README.md). Ce lot est SÉPARÉ de PHP2Shell (CVE-2026-109618/109619, dossier php2shell/,
# publié le 21/10/2026) : aucune CVE en commun, ne pas confondre les deux dossiers.
#
# Déploiement : copier CE SEUL FICHIER sur la machine à auditer, puis :
#   chmod +x test_php-novembre-2026.sh
#   ./test_php-novembre-2026.sh                # mode lecture seule (par défaut, voir ci-dessous)
#   ./test_php-novembre-2026.sh --scan-images   # + sonde les images Docker/Podman locales
#
# -------------------------------------------------------------------------------------------
# DEUX MODES :
#   - Lecture seule (PAR DÉFAUT) : inspecte l'hôte et exécute une commande de lecture dans
#     les conteneurs Docker/Podman DÉJÀ EN COURS D'EXÉCUTION (docker exec). Ne crée, ne
#     démarre, ne modifie et ne supprime RIEN.
#   - --scan-images : en plus du mode lecture seule, lance un conteneur ÉPHÉMÈRE et ISOLÉ
#     (docker/podman run --rm --network none) pour chaque image locale, le temps d'y chercher
#     un PHP vulnérable, puis le détruit immédiatement. C'est le seul mode qui peut révéler
#     une image vulnérable qui n'est PAS actuellement démarrée (donc invisible en lecture
#     seule) — nécessaire pour être réellement certain que la machine n'est pas concernée.
# -------------------------------------------------------------------------------------------
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

section() { printf '\n===== %s =====\n' "$1"; }

printf 'PHP — lot de correctifs du 19/11/2026 (18 CVE) — inventaire local\nMode : %s\nDate : %s\nHôte : %s\n' \
  "$([[ $SCAN_IMAGES -eq 1 ]] && echo 'complet (hôte + conteneurs actifs + images, conteneurs éphémères --network none)' || echo 'lecture seule (hôte + conteneurs actifs uniquement, aucune création)')" \
  "$(date -Is 2>/dev/null || date)" "$(hostname -f 2>/dev/null || hostname)"
if [[ -r /etc/os-release ]]; then . /etc/os-release; printf 'OS : %s %s\n' "${PRETTY_NAME:-unknown}" "${VERSION_ID:-}"; else echo "OS : unknown"; fi

# ============================================================
section "0. Prérequis"
# ============================================================
BASH_OK=1
if (( BASH_VERSINFO[0] < 4 )); then
  BASH_OK=0
  echo "[ERREUR] bash >= 4.0 requis (tableaux associatifs). Version détectée : $BASH_VERSION."
  echo "         macOS : le bash système est en 3.2 -> installer un bash récent (brew install bash)"
  echo "         puis relancer avec lui, ex. : /usr/local/bin/bash test_php-novembre-2026.sh"
fi

have() { command -v "$1" >/dev/null 2>&1; }

HAVE_TIMEOUT=0;    have timeout    && HAVE_TIMEOUT=1
HAVE_FIND=0;       have find       && HAVE_FIND=1
HAVE_GREP=0;       have grep       && HAVE_GREP=1
HAVE_PS=0;         have ps         && HAVE_PS=1
HAVE_DPKGQ=0;      have dpkg-query && HAVE_DPKGQ=1
HAVE_DPKG_CMD=0;   have dpkg       && HAVE_DPKG_CMD=1
HAVE_RPM=0;        have rpm        && HAVE_RPM=1
HAVE_APK=0;        have apk        && HAVE_APK=1
HAVE_SYSTEMCTL=0;  have systemctl  && HAVE_SYSTEMCTL=1
HAVE_SNAP=0;       have snap       && HAVE_SNAP=1
HAVE_DOCKER=0;     have docker     && HAVE_DOCKER=1
HAVE_PODMAN=0;     have podman     && HAVE_PODMAN=1

report() { printf '  %-14s %s\n' "$1" "$2"; }
report "bash"       "$([[ $BASH_OK -eq 1 ]] && echo "$BASH_VERSION (ok)" || echo 'ko (voir ERREUR ci-dessus)')"
report "timeout"    "$([[ $HAVE_TIMEOUT -eq 1 ]] && echo disponible || echo 'absent -> commandes longues non bornées en durée')"
report "find"       "$([[ $HAVE_FIND -eq 1 ]] && echo disponible || echo 'absent -> recherche des binaires PHP hors PATH ignorée')"
report "dpkg-query" "$([[ $HAVE_DPKGQ -eq 1 ]] && echo disponible || echo absent)"
report "dpkg"       "$([[ $HAVE_DPKG_CMD -eq 1 ]] && echo disponible || echo 'absent -> comparaison de version de paquet Debian/Ubuntu ignorée')"
report "rpm"        "$([[ $HAVE_RPM -eq 1 ]] && echo disponible || echo absent)"
report "apk"        "$([[ $HAVE_APK -eq 1 ]] && echo disponible || echo absent)"
report "systemctl"  "$([[ $HAVE_SYSTEMCTL -eq 1 ]] && echo disponible || echo 'absent -> section services ignorée')"
report "snap"       "$([[ $HAVE_SNAP -eq 1 ]] && echo disponible || echo 'absent -> section Snap ignorée')"
report "docker"     "$([[ $HAVE_DOCKER -eq 1 ]] && echo disponible || echo absent)"
report "podman"     "$([[ $HAVE_PODMAN -eq 1 ]] && echo disponible || echo absent)"
[[ "$HAVE_DOCKER" -eq 0 && "$HAVE_PODMAN" -eq 0 ]] && echo "  (ni docker ni podman : conteneurs/images non sondés -- seul l'hôte sera inspecté)"

if [[ "$BASH_OK" -eq 0 ]]; then
  echo
  echo "[ERREUR] Prérequis non satisfaits, arrêt avant toute vérification."
  exit 1
fi

run()       { if [[ "$HAVE_TIMEOUT" -eq 1 ]]; then timeout 8 "$@" 2>&1 || true; else "$@" 2>&1 || true; fi; }
run_t()     { local t="$1"; shift; if [[ "$HAVE_TIMEOUT" -eq 1 ]]; then timeout "$t" "$@" 2>/dev/null; else "$@" 2>/dev/null; fi; }
run_probe() { local t="$1"; shift; if [[ "$HAVE_TIMEOUT" -eq 1 ]]; then timeout "$t" "$@" 2>/dev/null; else "$@" 2>/dev/null; fi; }

# Lot du 19/11/2026 (18 CVE, voir README.md) — versions amont corrigées par branche. Une version
# >= ce seuil corrige TOUTES les CVE applicables à cette branche (certaines des 18 CVE ne
# s'appliquent qu'à une partie des branches, ex. CVE-2026-129474 : PHP 8.5 uniquement -- le seuil
# par branche reste le bon critère, pas la peine de distinguer CVE par CVE pour la détection).
declare -A FIXED=( [8.2]=36 [8.3]=37 [8.4]=28 [8.5]=13 )

# Debian REBACKPORTE ce correctif dans son propre paquet SANS changer le numéro PHP_VERSION rendu
# par le binaire : comparer le numéro amont seul donnerait un FAUX POSITIF sur un système déjà
# patché. Table vérifiée via fetch direct de security-tracker.debian.org le 20/11/2026
# (DLA-4916-1 pour bookworm/php8.2, DSA-6641-1 pour trixie/php8.4). Debian ne propose pas de
# paquet php8.3 officiel (comme pour PHP2Shell, voir php2shell/).
declare -A DEB_PHP_FIXED=(
  ["12:8.2"]="8.2.36-1~deb12u1"
  ["13:8.4"]="8.4.28-1~deb13u1"
)
# Ubuntu : aucune USN dédiée retrouvée pour ce lot, mais le security tracker officiel Ubuntu
# (ubuntu.com/security/CVE-xxxx, équivalent du security-tracker Debian) confirme un paquet corrigé
# pour deux combinaisons, vérifié par fetch direct le 23/11/2026 sur CVE-2026-129289 (FPM, request
# smuggling, CVSS 9.2) ET CVE-2026-129496 (Date, CVSS 9.2, toutes branches) ET CVE-2026-129291
# (FPM, EoP) simultanément -- même version de paquet pour les trois, donc considérée comme le
# seuil de correctif du lot pour ces deux combinaisons précises. Les autres combinaisons Ubuntu
# (26.04/26.10 php8.5, ou toute branche non listée ci-dessous) restent volontairement ABSENTES de
# cette table -- pas de preuve rassemblée pour elles à ce jour, donc [À VÉRIFIER] plutôt que deviner.
declare -A UBU_PHP_FIXED=(
  ["24.04:8.3"]="8.3.6-0ubuntu0.24.04.14"
  ["22.04:8.1"]="8.1.2-1ubuntu2.29"
)

VULN_COUNT=0; OK_COUNT=0; UNK_COUNT=0
FINDINGS=()

# php_pkg_fixed_version <distro_id> <distro_ver> <branche> : écrit la version de paquet corrigée
# connue pour cette distribution+version+branche PHP, ou rien si non référencée ici.
php_pkg_fixed_version() {
  local id="$1" ver="$2" br="$3"
  case "$id" in
    debian) printf '%s' "${DEB_PHP_FIXED["$ver:$br"]:-}" ;;
    ubuntu) printf '%s' "${UBU_PHP_FIXED["$ver:$br"]:-}" ;;
  esac
}

# looks_like_distro_build <distro_id> <version installée> : la table DEB_PHP_FIXED/UBU_PHP_FIXED
# ne doit s'appliquer qu'à un VRAI paquet officiel de la distribution. Un dépôt tiers (Sury/PPA,
# très répandu pour avoir plusieurs versions de PHP sur une LTS) nomme ses paquets EXACTEMENT
# comme les paquets officiels (php8.1-cli, etc.) mais suit son propre calendrier de correctifs :
# comparer sa version à la table officielle serait trompeur dans les deux sens.
looks_like_distro_build() {
  local id="$1" v_lower
  v_lower=$(printf '%s' "$2" | tr 'A-Z' 'a-z')
  case "$v_lower" in *sury*|*ppa*) return 1 ;; esac
  case "$id" in
    debian) [[ "$2" == *"~deb"* ]] ;;
    ubuntu) [[ "$2" == *ubuntu* ]] ;;
    *) return 1 ;;
  esac
}

# php_find_owning_pkg <binaire...> : sur l'HÔTE uniquement, retrouve via "dpkg -S" le paquet qui
# possède RÉELLEMENT le premier binaire trouvé dans cette liste (en suivant les liens), et écrit
# "nom version" sur stdout. Ne jamais déduire ce paquet du nom de la branche détectée : avec
# plusieurs versions de PHP installées côte à côte, ça comparerait le binaire actif à la version
# d'un AUTRE paquet.
php_find_owning_pkg() {
  local cand cbin realbin ownerline pkgname pkgver
  for cand in "$@"; do
    cbin=$(command -v "$cand" 2>/dev/null) || continue
    realbin=$(readlink -f "$cbin" 2>/dev/null || printf '%s' "$cbin")
    ownerline=$(dpkg -S "$realbin" 2>/dev/null | head -1) || continue
    [[ -z "$ownerline" ]] && continue
    pkgname="${ownerline%%:*}"
    pkgver=$(dpkg-query -W -f='${Version}' "$pkgname" 2>/dev/null)
    [[ -n "$pkgver" ]] && { printf '%s %s' "$pkgname" "$pkgver"; return 0; }
  done
  return 1
}

# php_distro_verdict <contexte> <nom paquet> <version installée> <version corrigée> : compare un
# paquet PHP système déjà localisé (hôte ou conteneur) et alimente le résumé. Toute sortie de
# "dpkg --compare-versions" autre que 0 (vrai) / 1 (faux) signale une chaîne de version mal
# formée : traité en "à vérifier", jamais compté comme corrigé par défaut.
php_distro_verdict() {
  local ctx="$1" pkgname="$2" instver="$3" fixedver="$4" rc
  dpkg --compare-versions "$instver" lt "$fixedver" 2>/dev/null; rc=$?
  case "$rc" in
    0) VULN_COUNT=$((VULN_COUNT+1)); FINDINGS+=("[VULNÉRABLE]  $ctx : paquet $pkgname $instver < $fixedver (correctif disponible)") ;;
    1) OK_COUNT=$((OK_COUNT+1)); FINDINGS+=("[CORRIGÉ]     $ctx : paquet $pkgname $instver >= $fixedver") ;;
    *) UNK_COUNT=$((UNK_COUNT+1)); FINDINGS+=("[À VÉRIFIER]  $ctx : paquet $pkgname $instver — comparaison de version impossible (dpkg --compare-versions code $rc) contre $fixedver attendu, vérifier manuellement.") ;;
  esac
}

# verdict_version <version> <contexte> [distro_id] [distro_ver] [paquet connu] [version paquet connue]
# Sans distro_id/distro_ver (cas de l'hôte), ils sont pris sur /etc/os-release de l'hôte, et le
# paquet propriétaire du binaire est recherché via dpkg -S. Avec distro_id/distro_ver fournis (cas
# d'un conteneur), AUCUNE recherche dpkg locale n'est faite : seul le paquet déjà repéré DANS le
# conteneur par la sonde (5e/6e argument, lui aussi via dpkg -S exécuté dans le conteneur) est
# utilisé — interroger le dpkg de l'hôte donnerait une comparaison fausse.
verdict_version() {
  local v="${1%%[-+~]*}" ctx="$2" d_id="${3-}" d_ver="${4-}" pkgname="${5-}" pkgver="${6-}"
  local br patch fx fixedpkg is_host=0 pkginfo

  if [[ -z "${3+x}" && -z "${4+x}" ]]; then d_id="${ID:-}"; d_ver="${VERSION_ID:-}"; is_host=1; fi

  if [[ ! "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    UNK_COUNT=$((UNK_COUNT+1)); FINDINGS+=("[À VÉRIFIER]  $ctx : version illisible ($1)"); return
  fi
  br="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"; patch="${BASH_REMATCH[3]}"

  if [[ -z "$pkgname" && "$is_host" -eq 1 && "$HAVE_DPKG_CMD" -eq 1 && "$HAVE_DPKGQ" -eq 1 ]]; then
    if pkginfo=$(php_find_owning_pkg php php-cgi php-fpm); then
      read -r pkgname pkgver <<< "$pkginfo"
    fi
  fi

  if [[ "$d_id" == debian || "$d_id" == ubuntu ]] && [[ "$HAVE_DPKG_CMD" -eq 1 ]] && [[ -n "$pkgname" && -n "$pkgver" ]]; then
    fixedpkg=$(php_pkg_fixed_version "$d_id" "$d_ver" "$br")
    if [[ -n "$fixedpkg" ]] && looks_like_distro_build "$d_id" "$pkgver"; then
      php_distro_verdict "$ctx" "$pkgname" "$pkgver" "$fixedpkg"
      return
    fi
    # Un paquet système possède bel et bien ce binaire (preuve d'une installation gérée par la
    # distribution), mais soit aucune table de correctif connue pour cette branche/version (cas
    # attendu pour Ubuntu, voir UBU_PHP_FIXED ci-dessus), soit la chaîne de version ne ressemble
    # pas à un build officiel (dépôt tiers type Sury/PPA) : ne jamais déduire "vulnérable" du seul
    # numéro amont ici, mais ne pas non plus affirmer "corrigé" sans preuve.
    UNK_COUNT=$((UNK_COUNT+1)); FINDINGS+=("[À VÉRIFIER]  $ctx : PHP $v, paquet $pkgname $pkgver — pas de référence de correctif fiable pour cette combinaison distribution/version/dépôt pour ce lot du 19/11/2026 (dépôt tiers possible, ou USN/DSA pas encore référencée ici) ; vérifier manuellement contre security-tracker.debian.org / ubuntu.com/security/notices")
    return
  fi

  # Aucun paquet système ne possède ce binaire (compilé/placé manuellement, ex. /usr/local/bin) :
  # rien ne permet de supposer un backport Debian/Ubuntu, on juge sur le seul numéro amont.
  if [[ -n "${FIXED[$br]:-}" ]]; then
    fx="${FIXED[$br]}"
    if (( patch < fx )); then
      VULN_COUNT=$((VULN_COUNT+1)); FINDINGS+=("[VULNÉRABLE]  $ctx : PHP $v < $br.$fx")
    else
      OK_COUNT=$((OK_COUNT+1)); FINDINGS+=("[CORRIGÉ]     $ctx : PHP $v >= $br.$fx")
    fi
  elif (( BASH_REMATCH[1] < 8 || (BASH_REMATCH[1] == 8 && BASH_REMATCH[2] < 2) )); then
    VULN_COUNT=$((VULN_COUNT+1)); FINDINGS+=("[VULNÉRABLE]  $ctx : PHP $v (branche EOL, pas de correctif amont pour ce lot — migration recommandée)")
  else
    UNK_COUNT=$((UNK_COUNT+1)); FINDINGS+=("[À VÉRIFIER]  $ctx : PHP $v (branche non référencée, vérifier l'avis officiel)")
  fi
}

# Script shell exécuté DANS un conteneur/une image : cherche les binaires PHP et affiche leur version
PROBE='if [ -r /etc/os-release ]; then . /etc/os-release; echo "OSREL ${ID:-} ${VERSION_ID:-}"; fi
for b in php php-cgi php-fpm php-fpm8 frankenphp; do p=$(command -v $b 2>/dev/null) && echo "BIN $p"; done
for p in /usr/local/bin/php /usr/local/sbin/php-fpm /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/frankenphp; do [ -x "$p" ] && echo "BIN $p"; done
v=$( (php -r "echo PHP_VERSION;" || php-cgi -v | sed -n "1p" | cut -d" " -f2) 2>/dev/null) && [ -n "$v" ] && echo "VER $v"
for cand in php php-cgi php-fpm; do
  cbin=$(command -v $cand 2>/dev/null)
  [ -z "$cbin" ] && continue
  realbin=$(readlink -f "$cbin" 2>/dev/null || echo "$cbin")
  owner=$(dpkg -S "$realbin" 2>/dev/null | head -1)
  [ -z "$owner" ] && continue
  pkgname=${owner%%:*}
  pkgver=$(dpkg-query -W -f="\${Version}" "$pkgname" 2>/dev/null)
  if [ -n "$pkgver" ]; then echo "PKG $pkgname $pkgver"; break; fi
done
true'

# probe_target <runtime> <exec|run> <cible> <libellé> : sonde un conteneur (exec, toujours) ou
# une image (run jetable --network none, UNIQUEMENT si --scan-images a été passé par l'appelant)
probe_target() {
  local rt="$1" mode="$2" tgt="$3" label="$4" out ver bins rc c_id c_ver pkg_line pkgname pkgver
  if [[ "$mode" == exec ]]; then
    out=$(run_probe 20 "$rt" exec "$tgt" sh -c "$PROBE"); rc=$?
  else
    out=$(run_probe 40 "$rt" run --rm --network none --entrypoint sh "$tgt" -c "$PROBE"); rc=$?
  fi
  bins=$(printf '%s\n' "$out" | awk '$1=="BIN"{print $2}' | sort -u | tr '\n' ' ')
  ver=$(printf '%s\n' "$out" | awk '$1=="VER"{print $2; exit}')
  if [[ -z "$bins" && -z "$ver" ]]; then
    if [[ "$rc" -ne 0 ]]; then
      UNK_COUNT=$((UNK_COUNT+1)); FINDINGS+=("[À VÉRIFIER]  $label : sonde impossible (exec/run a échoué ou expiré, code retour $rc — pas de shell, conteneur arrêté, ou délai dépassé) — vérifier manuellement.")
    fi
    return 0
  fi
  echo "  $label : binaires=[${bins% }] version=${ver:-?}"
  c_id=$(awk '$1=="OSREL"{print $2}' <<< "$out")
  c_ver=$(awk '$1=="OSREL"{print $3}' <<< "$out")
  pkg_line=$(awk '$1=="PKG"{print $2,$3; exit}' <<< "$out")
  pkgname=""; pkgver=""
  [[ -n "$pkg_line" ]] && { read -r pkgname pkgver <<< "$pkg_line"; }
  if [[ -n "$ver" ]]; then verdict_version "$ver" "$label" "$c_id" "$c_ver" "$pkgname" "$pkgver"
  else UNK_COUNT=$((UNK_COUNT+1)); FINDINGS+=("[À VÉRIFIER]  $label : PHP présent, version indéterminée"); fi
}

section "1. PHP accessible dans le PATH"
if have php; then
  command -v php
  php -v 2>&1 | head -n 3
  verdict_version "$(php -r 'echo PHP_VERSION;' 2>/dev/null)" "hôte (php du PATH)"
else
  echo "Aucune commande php dans le PATH."
fi

section "2. Paquets système PHP"
if [[ "$HAVE_DPKGQ" -eq 1 ]]; then
  dpkg-query -W -f='${db:Status-Abbrev} ${binary:Package} ${Version}\n' 2>/dev/null |
    awk '$1 ~ /^ii/ && tolower($0) ~ /(^|[[:space:]])(php|libapache2-mod-php|php[0-9]|libphp)/ {print}' |
    sort -u
elif [[ "$HAVE_RPM" -eq 1 ]]; then
  rpm -qa 2>/dev/null | grep -Ei '(^|-)php([0-9.-]|$)|libphp' || true
elif [[ "$HAVE_APK" -eq 1 ]]; then
  apk info -vv 2>/dev/null | grep -Ei 'php' || true
else
  echo "Gestionnaire de paquets non reconnu (dpkg-query/rpm/apk absents) : section ignorée."
fi

section "2b. Binaires PHP hors PATH et mitigation php.ini (CVE-2026-129474, PHP 8.5 uniquement)"
if [[ "$HAVE_FIND" -eq 1 ]]; then
  run_t 60 find / -xdev \( -type f \( -name 'php' -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' -o -name 'frankenphp*' -o -name 'libphp*.so' -o -name 'libphp*.so.*' \) \) \
    -not -path '/proc/*' -not -path '/var/lib/docker/*' -not -path '/var/lib/containerd/*' -not -path '*/node_modules/*' -not -path '*/.vscode-server/*' \
    -not -path '*/site-packages/*' -not -path '/usr/share/*' -not -path '/etc/*' \( -perm /111 -o -name '*.so*' \) -print | head -n 50
else
  echo "find absent : recherche des binaires PHP hors PATH ignorée."
fi
echo "-- zend.exception_ignore_args (mitigation CVE-2026-129474, PHP 8.5 uniquement : doit valoir 1/On pour bloquer le chemin d'attaque démontré) --"
if [[ "$HAVE_GREP" -eq 1 ]]; then
  grep -RInE '^[[:space:]]*zend\.exception_ignore_args' /etc/php /usr/local/etc/php /etc/php.ini /etc/php.d 2>/dev/null || echo "Aucun php.ini hôte trouvé (php.ini-production met cette directive à 1 par défaut ; php.ini-development la met à 0 -- vérifier laquelle est active)."
fi

section "3. Services et processus PHP / serveurs web"
if [[ "$HAVE_SYSTEMCTL" -eq 1 ]]; then
  systemctl list-units --type=service --all --no-pager 2>/dev/null |
    grep -Ei 'php.*(fpm|cgi)|apache2|httpd|nginx|frankenphp|litespeed|lsws' || true
else
  echo "systemctl absent : liste des services ignorée."
fi
if [[ "$HAVE_PS" -eq 1 ]]; then
  ps -eo user,pid,ppid,lstart,args 2>/dev/null |
    grep -Ei '[p]hp(-fpm|[0-9.]*-fpm|[0-9.]*-cgi|[0-9.]* |$)|[a]pache2|[h]ttpd|[n]ginx|[f]rankenphp|[l]shttpd|[o]penlitespeed' || true
else
  echo "ps absent : liste des processus ignorée."
fi

section "4. Snap"
if [[ "$HAVE_SNAP" -eq 1 ]]; then
  snap list 2>/dev/null | grep -Ei 'php|nextcloud|wordpress|owncloud|[^[:space:]]' || true
  if [[ "$HAVE_FIND" -eq 1 ]]; then
    echo "-- Exécutables PHP repérés dans les répertoires Snap (si accessibles) --"
    run_t 30 find /snap /var/snap -type f \( -name php -o -name 'php-fpm*' -o -name 'php-cgi*' \) -perm /111 | head -n 100
  fi
else
  echo "Snap non installé ou commande absente : section ignorée."
fi

section "5. Docker / Podman"
if [[ "$HAVE_DOCKER" -eq 0 && "$HAVE_PODMAN" -eq 0 ]]; then
  echo "Docker/Podman non détecté dans le PATH : section ignorée."
else
  for runtime in docker podman; do
    have "$runtime" || continue
    echo "-- $runtime : conteneurs en cours (image, commande, ports) --"
    run "$runtime" ps --no-trunc --format 'table {{.Names}}\t{{.Image}}\t{{.Command}}\t{{.Ports}}'
    echo "-- $runtime : images locales dont le nom peut indiquer PHP/web --"
    run "$runtime" images --format '{{.Repository}}:{{.Tag}}' | grep -Ei 'php|wordpress|drupal|joomla|nextcloud|owncloud|laravel|apache|nginx|frankenphp|librenms|observium|web' || true

    echo "-- $runtime : sonde PHP dans les conteneurs EN COURS (exec, lecture seule) --"
    while IFS= read -r c; do
      [[ -n "$c" ]] && probe_target "$runtime" exec "$c" "conteneur $c"
    done < <("$runtime" ps --format '{{.Names}}' 2>/dev/null)

    if [[ "$SCAN_IMAGES" -eq 1 ]]; then
      echo "-- $runtime : sonde PHP dans les IMAGES locales (conteneur ÉPHÉMÈRE, --network none, détruit après usage) --"
      while IFS= read -r img; do
        [[ -n "$img" && "$img" != *"<none>"* ]] && probe_target "$runtime" run "$img" "image $img"
      done < <("$runtime" images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | sort -u)
    else
      echo "(mode lecture seule : images locales non sondées — relancer avec --scan-images pour les inclure)"
    fi
  done
fi

section "6. Conclusion"
php_seen=0
have php && php_seen=1
[[ "$HAVE_PS" -eq 1 ]] && ps -eo args 2>/dev/null | grep -Eiq '[p]hp(-fpm|[0-9.]*-fpm|[0-9.]*-cgi|[0-9.]* )' && php_seen=1
printf '%s\n' "${FINDINGS[@]:-}" | sed '/^$/d'
echo
if [[ "$VULN_COUNT" -gt 0 ]]; then
  VERDICT="VULNÉRABLE"
  echo "[VULNÉRABLE] $VULN_COUNT installation(s) PHP < version corrigée pour le lot du 19/11/2026. Si elles servent des requêtes web : mettre à jour/reconstruire, redémarrer tous les workers. Pour la branche 8.5 spécifiquement (CVE-2026-129474) : vérifier zend.exception_ignore_args=1 en mitigation immédiate (voir section 2b)."
elif [[ "$UNK_COUNT" -gt 0 ]]; then
  VERDICT="À VÉRIFIER"
  echo "[À VÉRIFIER]  PHP détecté mais version non classable pour ce lot (souvent : paquet Ubuntu sans USN encore référencée pour ce lot précis, voir README) — vérifier manuellement."
elif [[ "$OK_COUNT" -gt 0 ]]; then
  VERDICT="OK"
  echo "[OK] PHP détecté, toutes les versions sont >= versions corrigées de ce lot (8.2.36 / 8.3.37 / 8.4.28 / 8.5.13)."
elif [[ "$php_seen" -eq 1 ]]; then
  VERDICT="À VÉRIFIER"
  echo "[À VÉRIFIER]  PHP détecté sur l'hôte (paquet exact et correctif fournisseur Debian/Ubuntu à vérifier : backports possibles)."
else
  VERDICT="NON CONCERNÉ"
  echo "[NON CONCERNÉ] Aucun PHP trouvé sur l'hôte ni dans les conteneurs actifs sondés."
fi

echo
if [[ "$VERDICT" == "VULNÉRABLE" ]]; then
  echo "Confiance : élément vulnérable CONFIRMÉ — pas d'ambiguïté, agir immédiatement (cf. ci-dessus)."
elif [[ "$VERDICT" == "À VÉRIFIER" ]]; then
  echo "Confiance : INCOMPLÈTE — au moins un élément nécessite une vérification manuelle avant de pouvoir conclure."
elif [[ "$SCAN_IMAGES" -eq 1 ]]; then
  echo "Confiance : COMPLÈTE dans la limite de ce script — hôte, conteneurs actifs ET images locales ont tous été sondés, aucune trace de PHP vulnérable."
else
  echo "Confiance : PARTIELLE — mode lecture seule : seuls l'hôte et les conteneurs ACTIFS ont été inspectés. Une image Docker/Podman locale non démarrée peut contenir un PHP vulnérable sans apparaître ici. Relancer avec --scan-images pour être certain."
fi
echo "[LIMITE] Ce script n'exploite pas la faille et ne prouve pas l'absence de compromission. Ubuntu : correctif confirmé via le security tracker officiel (pas de USN dédiée) seulement pour noble/php8.3 et jammy/php8.1 (voir README) -- toute autre combinaison Ubuntu ressort [À VÉRIFIER], jamais [CORRIGÉ] par déduction. Images tierces et kubectl/lxc non sondés en profondeur."
echo "Références : https://www.php.net/  |  https://security-tracker.debian.org/  |  https://ubuntu.com/security/notices/"

case "$VERDICT" in
  VULNÉRABLE) exit 2 ;;
  "À VÉRIFIER") exit 1 ;;
  *) exit 0 ;;
esac
