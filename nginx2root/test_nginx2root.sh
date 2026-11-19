#!/usr/bin/env bash
# test_nginx2root.sh — script UNIQUE et autonome qui cherche les failles nginx dites « NGINX2Root »
# (CVE-2026-123007 et CVE-2026-123633, les deux plus graves d'un lot de 10 CVE corrigées par
# nginx/F5 le 18/11/2026) : corruption mémoire / use-after-free dans le contrôle de flux HTTP/2,
# menant à une **exécution de code à distance SANS authentification**. Voir README.md.
#
# Déploiement : copier CE SEUL FICHIER sur la machine :
#   chmod +x test_nginx2root.sh
#   ./test_nginx2root.sh                 # mode lecture seule (par défaut)
#   ./test_nginx2root.sh --scan-images   # + sonde les images Docker/Podman locales (conteneur éphémère --network none)
#
# LECTURE SEULE par défaut : rien n'est créé, modifié ni supprimé. Les conteneurs EN COURS D'EXÉCUTION
# sont sondés par `exec` (commandes de lecture). --scan-images lance un conteneur éphémère isolé par image.
# Codes de sortie : 0 = rien à signaler, 1 = à vérifier, 2 = vulnérable confirmé.
set -u
export LC_ALL=C

SCAN_IMAGES=0
for a in "$@"; do
  case "$a" in
    --scan-images) SCAN_IMAGES=1 ;;
    -h|--help) echo "Usage: $0 [--scan-images]"; exit 0 ;;
  esac
done

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n===== %s =====\n' "$1"; }
get() { printf '%s\n' "$1" | sed -n "s/^$2=//p" | head -n1; }

VULN=0; UNK=0; OK=0; NC=0
FINDINGS=()

# Version de paquet nginx corrigée par CODENAME Ubuntu (USN-9159-1, publié le 19/11/2026).
# IMPORTANT : Ubuntu rétroporte sans changer le numéro de version amont (ex. 22.04 "corrigé"
# reste nginx/1.18.0 côté `nginx -v`, seul le suffixe de paquet change) -- comparer le NUMÉRO DE
# PAQUET dpkg à cette table, jamais le numéro de version amont brut, sous peine de FAUX POSITIF
# sur un Ubuntu déjà corrigé. $1 = codename (ex. jammy) -> version de paquet corrigée, vide si
# codename non reconnu par ce script (ne pas confondre avec "non affecté", voir trusty ci-dessous).
ubuntu_fixed() {
  case "$1" in
    stonking) echo "1.30.4-7ubuntu1.2" ;;             # 26.10
    resolute) echo "1.28.3-2ubuntu1.13" ;;             # 26.04 LTS
    noble)    echo "1.24.0-2ubuntu7.20" ;;             # 24.04 LTS
    jammy)    echo "1.18.0-6ubuntu14.23" ;;            # 22.04 LTS
    focal)    echo "1.18.0-0ubuntu1.7+esm5" ;;         # 20.04 LTS -- nécessite Ubuntu Pro/ESM
    bionic)   echo "1.14.0-0ubuntu1.11+esm6" ;;        # 18.04 LTS -- nécessite Ubuntu Pro/ESM
    xenial)   echo "1.10.3-0ubuntu0.16.04.5+esm11" ;;  # 16.04 LTS -- nécessite Ubuntu Pro (Legacy Support)
    *) echo "" ;;
  esac
}

# Branche 1.30 (stable) corrigée à partir de .7 ; branche 1.31 (mainline) corrigée à partir de .9.
# Toute branche < 1.30 (1.9.5 -> 1.29.x) est dans la plage affectée des deux CVE et n'a plus de
# correctif amont dédié (branches non maintenues) : traitée comme vulnérable. Toute branche > 1.31
# est postérieure à cet avis et supposée saine (à confirmer si un nouvel avis sort depuis).
# UTILISÉE UNIQUEMENT quand aucune table de rétroportage distro ne s'applique (voir ubuntu_fixed
# ci-dessus) -- reste correcte pour Debian, qui n'a aucun rétroportage à ce jour (voir README).
# $1 = version "X.Y.Z" -> "vuln" / "ok" / "unk"
ver_fixed_branch() {
  local v="$1" maj min pat
  maj=$(printf '%s' "$v" | cut -d. -f1)
  min=$(printf '%s' "$v" | cut -d. -f2)
  pat=$(printf '%s' "$v" | cut -d. -f3)
  case "$maj" in ''|*[!0-9]*) echo unk; return ;; esac
  case "$min" in ''|*[!0-9]*) echo unk; return ;; esac
  case "$pat" in ''|*[!0-9]*) pat=0 ;; esac
  if [ "$maj" -ne 1 ]; then echo unk; return; fi
  if [ "$min" -lt 30 ]; then echo vuln; return; fi
  if [ "$min" -eq 30 ]; then [ "$pat" -ge 7 ] && echo ok || echo vuln; return; fi
  if [ "$min" -eq 31 ]; then [ "$pat" -ge 9 ] && echo ok || echo vuln; return; fi
  echo ok
}

# Script d'analyse exécuté DANS la cible (hôte, conteneur ou image) : n'écrit rien, n'affiche que des clés=valeurs.
PROBE='
nginx_bin=$(command -v nginx 2>/dev/null)
if [ -z "$nginx_bin" ]; then
  for p in /usr/sbin/nginx /usr/local/nginx/sbin/nginx /usr/local/sbin/nginx /opt/nginx/sbin/nginx; do
    [ -x "$p" ] && nginx_bin="$p" && break
  done
fi
if [ -z "$nginx_bin" ]; then echo "nginx=absent"; exit 0; fi
echo "nginx=present"
vline=$("$nginx_bin" -v 2>&1)
Vline=$("$nginx_bin" -V 2>&1)
ver=$(printf "%s" "$vline" | sed -n "s#.*nginx/\([0-9][0-9.]*\).*#\1#p" | head -n1)
echo "ver=$ver"
plus=no
printf "%s" "$Vline" | grep -qi "plus" && plus=yes
echo "plus=$plus"
http2mod=non
printf "%s" "$Vline" | grep -qi "http_v2_module" && http2mod=oui
echo "http2mod=$http2mod"
http2cfg=inconnu
if cfgdump=$("$nginx_bin" -T 2>/dev/null); then
  if printf "%s" "$cfgdump" | grep -v "^[[:space:]]*#" | grep -qiE "http2[[:space:]]+on|listen[^;]*\bhttp2\b"; then
    http2cfg=oui
  else
    http2cfg=non
  fi
fi
echo "http2cfg=$http2cfg"
osid=""; oscodename=""
if [ -r /etc/os-release ]; then
  osid=$(sed -n "s/^ID=//p" /etc/os-release | tr -d "\"" | head -n1)
  oscodename=$(sed -n "s/^VERSION_CODENAME=//p" /etc/os-release | tr -d "\"" | head -n1)
fi
echo "osid=$osid"
echo "oscodename=$oscodename"
pkgver=""
if command -v dpkg-query >/dev/null 2>&1; then
  pkgver=$(dpkg-query -W -f="\${Version}\n" nginx nginx-core nginx-light nginx-full nginx-extras 2>/dev/null | grep -v "^$" | head -n1)
elif command -v rpm >/dev/null 2>&1; then
  pkgver=$(rpm -q --qf "%{VERSION}-%{RELEASE}\n" nginx 2>/dev/null | grep -v "not installed" | head -n1)
elif command -v apk >/dev/null 2>&1; then
  pkgver=$(apk list -I nginx 2>/dev/null | awk "NR==1{print \$1}" | sed "s/^nginx-//")
elif command -v pacman >/dev/null 2>&1; then
  pkgver=$(pacman -Q nginx 2>/dev/null | awk "{print \$2}")
fi
echo "pkgver=${pkgver:-}"
'

analyse() { # $1 = libellé, $2 = sortie du PROBE
  local label="$1" out="$2" present ver plus http2mod http2cfg pkgver osid oscodename status ubfixed
  present=$(get "$out" nginx)
  if [ "$present" != "present" ]; then printf '  [NON CONCERNÉ] %s : pas de nginx\n' "$label"; NC=$((NC+1)); return; fi
  ver=$(get "$out" ver); plus=$(get "$out" plus); http2mod=$(get "$out" http2mod)
  http2cfg=$(get "$out" http2cfg); pkgver=$(get "$out" pkgver)
  osid=$(get "$out" osid); oscodename=$(get "$out" oscodename)

  if [ "$plus" = "yes" ]; then
    UNK=$((UNK+1)); FINDINGS+=("$label")
    printf '  [À VÉRIFIER] %s : nginx Plus détecté (version affichée %s) — la numérotation Plus\n' "$label" "${ver:-?}"
    printf '      ne se compare pas directement aux versions open source : vérifier manuellement sur le\n'
    printf '      portail support F5 que le build est >= 37.0.8.1/37.3.0.1 (CVE-2026-123007) et\n'
    printf '      >= 37.0.7.1/37.2.0.1 (CVE-2026-123633)\n'
    return
  fi

  # Ubuntu : rétroportage sans changer le numéro de version amont -- comparer le paquet dpkg à la
  # table USN-9159-1, jamais `nginx -v`, sous peine de faux positif sur un système déjà corrigé.
  if [ "$osid" = "ubuntu" ]; then
    if [ "$oscodename" = "trusty" ]; then
      OK=$((OK+1)); printf '  [NON CONCERNÉ] %s : Ubuntu 14.04 (trusty), non affecté par cet avis selon Canonical\n' "$label"
      return
    fi
    ubfixed=$(ubuntu_fixed "$oscodename")
    if [ -z "$ubfixed" ]; then
      UNK=$((UNK+1)); FINDINGS+=("$label")
      printf '  [À VÉRIFIER] %s : Ubuntu "%s" non reconnu par ce script -- comparer manuellement à https://ubuntu.com/security/notices/USN-9159-1\n' "$label" "${oscodename:-codename illisible}"
      return
    fi
    if [ -z "$pkgver" ]; then
      UNK=$((UNK+1)); FINDINGS+=("$label")
      printf '  [À VÉRIFIER] %s : Ubuntu %s mais paquet nginx introuvable via dpkg-query (installation non standard ?)\n' "$label" "$oscodename"
      return
    fi
    if have dpkg; then
      if dpkg --compare-versions "$pkgver" lt "$ubfixed"; then
        VULN=$((VULN+1)); FINDINGS+=("$label")
        printf '  [VULNÉRABLE] %s : Ubuntu %s, paquet nginx %s (< %s selon USN-9159-1)\n' "$label" "$oscodename" "$pkgver" "$ubfixed"
        case "$oscodename" in focal|bionic|xenial) printf '      branche en ESM : ce correctif nécessite un abonnement Ubuntu Pro actif pour être reçu\n' ;; esac
      else
        OK=$((OK+1))
        printf '  [CORRIGÉ] %s : Ubuntu %s, paquet nginx %s (>= %s selon USN-9159-1)\n' "$label" "$oscodename" "$pkgver" "$ubfixed"
      fi
      return
    fi
    UNK=$((UNK+1)); FINDINGS+=("$label")
    printf '  [À VÉRIFIER] %s : Ubuntu %s, mais la commande "dpkg" (comparaison de version) est absente sur CETTE machine -- impossible de comparer %s à %s de façon fiable\n' "$label" "$oscodename" "$pkgver" "$ubfixed"
    return
  fi

  if [ -z "$ver" ]; then
    UNK=$((UNK+1)); FINDINGS+=("$label")
    printf '  [À VÉRIFIER] %s : nginx présent mais version illisible (relancer en root ?)\n' "$label"
    return
  fi

  status=$(ver_fixed_branch "$ver")
  case "$status" in
    vuln)
      VULN=$((VULN+1)); FINDINGS+=("$label")
      printf '  [VULNÉRABLE] %s : nginx %s (< 1.30.7 / < 1.31.9) — CVE-2026-123007/123633 (RCE non authentifiée)\n' "$label" "$ver"
      printf '      + 8 autres CVE du lot du 18/11/2026, dont certaines sans rapport avec HTTP/2 : patcher quand même\n'
      printf '      module HTTP/2 compilé : %s ; activé dans la config lue (best-effort) : %s\n' "$http2mod" "$http2cfg"
      [ -n "$pkgver" ] && printf '      paquet système détecté : %s (aucun rétroportage Debian connu à ce jour, voir README)\n' "$pkgver"
      ;;
    ok)
      OK=$((OK+1))
      printf '  [CORRIGÉ] %s : nginx %s (>= 1.30.7 ou >= 1.31.9)\n' "$label" "$ver"
      ;;
    unk)
      UNK=$((UNK+1)); FINDINGS+=("$label")
      printf '  [À VÉRIFIER] %s : nginx %s, numéro de version non reconnu par ce script\n' "$label" "$ver"
      ;;
  esac
}

# ---------------------------------------------------------------- 0. Prérequis
section "0. Prérequis"
printf '  utilisateur : %s\n' "$(id -un)"
[ "$(id -u)" -eq 0 ] || printf '  [ATTENTION] pas root : la lecture de config via "nginx -T" peut être incomplète (http2cfg = inconnu possible)\n'
have docker && RT=docker || { have podman && RT=podman || RT=""; }
[ -n "$RT" ] && printf '  moteur de conteneurs : %s\n' "$RT" || printf '  aucun moteur de conteneurs détecté : hôte seul\n'

# ---------------------------------------------------------------- 1. Hôte
section "1. Hôte"
analyse "hôte $(hostname)" "$(sh -c "$PROBE" 2>/dev/null)"

# ---------------------------------------------------------------- 2. Conteneurs actifs
if [ -n "$RT" ]; then
  section "2. Conteneurs en cours d'exécution (lecture seule)"
  ids=$($RT ps -q 2>/dev/null)
  if [ -z "$ids" ]; then echo "  aucun conteneur actif"; fi
  for id in $ids; do
    name=$($RT inspect -f '{{.Name}}' "$id" 2>/dev/null | sed 's#^/##')
    out=$($RT exec "$id" sh -c "$PROBE" 2>/dev/null) || { UNK=$((UNK+1)); echo "  [À VÉRIFIER] conteneur $name : exec impossible"; continue; }
    analyse "conteneur $name" "$out"
  done

  section "3. Images locales"
  if [ "$SCAN_IMAGES" -eq 1 ]; then
    for img in $($RT images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | sort -u); do
      out=$($RT run --rm --network none --entrypoint sh "$img" -c "$PROBE" 2>/dev/null) || { echo "  [IGNORÉ] image $img : pas de shell (image minimale, probable base scratch/distroless)"; continue; }
      analyse "image $img" "$out"
    done
    NC_IMAGES_DONE=1
  else
    echo "  non sondées (relancer avec --scan-images pour inspecter aussi les images dormantes)"
  fi
fi

# ---------------------------------------------------------------- Bilan
section "Bilan"
printf '  vulnérables : %d | à vérifier : %d | corrigés / non concernés : %d\n' "$VULN" "$UNK" "$OK"
[ "${#FINDINGS[@]}" -gt 0 ] && printf '  à traiter : %s\n' "${FINDINGS[*]}"
if [ "$VULN" -gt 0 ]; then echo "Confiance : élément vulnérable CONFIRMÉ"; exit 2; fi
if [ "$UNK" -gt 0 ]; then echo "Confiance : INCOMPLÈTE (au moins un élément à vérifier à la main)"; exit 1; fi
if [ -z "$RT" ]; then echo "Confiance : COMPLÈTE"; exit 0; fi
if [ "${NC_IMAGES_DONE:-0}" -eq 1 ]; then echo "Confiance : COMPLÈTE"; exit 0; fi
echo "Confiance : PARTIELLE (images locales non sondées : relancer avec --scan-images)"; exit 0
