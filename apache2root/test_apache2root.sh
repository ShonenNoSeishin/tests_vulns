#!/usr/bin/env bash
# test_apache2root.sh — script UNIQUE et autonome qui cherche la faille dite « Apache2Root »
# (CVE-2026-119618, race condition dans mod_http2 -- fonction assign_headers() -- pouvant mener à
# une **exécution de code à distance SANS authentification** quand le module HTTP/2 est chargé).
# Affecte aussi, séparément, le module standalone du projet GitHub icing/mod_h2 (versions 2.0.8 à
# 2.0.42 -- même code source que mod_http2, mais packagé/compilé à part). Voir README.md.
#
# Déploiement : copier CE SEUL FICHIER sur la machine :
#   chmod +x test_apache2root.sh
#   ./test_apache2root.sh                 # mode lecture seule (par défaut)
#   ./test_apache2root.sh --scan-images   # + sonde les images Docker/Podman locales (conteneur éphémère --network none)
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

# Version de paquet apache2 corrigée par CODENAME Ubuntu (USN-9090-1). Rétroportage classique :
# comparer le NUMÉRO DE PAQUET dpkg à cette table, jamais `apache2 -v` seul. bionic/xenial : leur
# version native d'apache2 est antérieure à 2.4.55 (plage affectée) -- "noaffected" n'est PAS un
# raccourci basé sur le codename seul, le script revérifie quand même la version réelle détectée
# juste après (même piège que "trusty" rencontré sur nginx2root le 19/11/2026).
ubuntu_fixed() {
  case "$1" in
    stonking) echo "2.4.68-1ubuntu6.2" ;;             # 26.10
    resolute) echo "2.4.66-2ubuntu2.8" ;;              # 26.04 LTS
    noble)    echo "2.4.58-1ubuntu8.19" ;;             # 24.04 LTS
    jammy)    echo "2.4.52-1ubuntu4.27" ;;             # 22.04 LTS
    focal)    echo "2.4.41-4ubuntu3.23+esm11" ;;       # 20.04 LTS -- nécessite Ubuntu Pro/ESM
    bionic)   echo "noaffected" ;;                     # 18.04 -- version native < 2.4.55
    xenial)   echo "noaffected" ;;                     # 16.04 -- version native < 2.4.55
    *) echo "" ;;
  esac
}

# Même logique côté Debian : DLA-4902-1 (bookworm) et DSA-6620-1 (trixie), publiées le 11/11/2026.
debian_fixed() {
  case "$1" in
    trixie)   echo "2.4.71-1~deb13u1" ;;  # Debian 13 -- DSA-6620-1
    bookworm) echo "2.4.71-1~deb12u1" ;;  # Debian 12 -- DLA-4902-1 (LTS)
    *) echo "" ;;
  esac
}

# Plage amont affectée : 2.4.55 à 2.4.70 inclus ; corrigé à partir de 2.4.71. UTILISÉE quand aucune
# table de rétroportage distro ne s'applique (ubuntu_fixed/debian_fixed ci-dessus), OU pour
# recroiser un codename "noaffected" avec la version réellement détectée (jamais conclure sur le
# seul nom de la distro, voir commentaire ubuntu_fixed).
# $1 = version "X.Y.Z" -> "vuln" / "ok" / "unk"
ver_fixed_branch() {
  local v="$1" maj min pat
  maj=$(printf '%s' "$v" | cut -d. -f1)
  min=$(printf '%s' "$v" | cut -d. -f2)
  pat=$(printf '%s' "$v" | cut -d. -f3)
  case "$maj" in ''|*[!0-9]*) echo unk; return ;; esac
  case "$min" in ''|*[!0-9]*) echo unk; return ;; esac
  case "$pat" in ''|*[!0-9]*) pat=0 ;; esac
  if [ "$maj" -ne 2 ] || [ "$min" -ne 4 ]; then echo unk; return; fi
  if [ "$pat" -lt 55 ]; then echo ok; return; fi
  if [ "$pat" -le 70 ]; then echo vuln; return; fi
  echo ok
}

# Script d'analyse exécuté DANS la cible (hôte, conteneur ou image) : n'écrit rien, n'affiche que des clés=valeurs.
PROBE='
bin=$(command -v apache2 2>/dev/null)
[ -z "$bin" ] && bin=$(command -v httpd 2>/dev/null)
if [ -z "$bin" ]; then
  for p in /usr/sbin/apache2 /usr/sbin/httpd /usr/local/apache2/bin/httpd /opt/apache2/bin/httpd; do
    [ -x "$p" ] && bin="$p" && break
  done
fi
if [ -z "$bin" ]; then echo "apache=absent"; exit 0; fi
vline=$("$bin" -v 2>&1)
# Un binaire nommé "httpd" ou "apache2" ne garantit pas que c est Apache HTTP Server -- BusyBox
# fournit par exemple son propre applet "httpd" (mini serveur de fichiers), totalement sans
# rapport, qui répond à "-v" sans jamais mentionner "Apache". Sans ce filtre, ces faux positifs
# ressortent en [À VÉRIFIER] avec un message trompeur ("modules illisibles") au lieu de
# [NON CONCERNÉ] -- vérifié sur des images BusyBox le 24/11/2026.
if ! printf "%s" "$vline" | grep -qi "Apache"; then echo "apache=absent"; exit 0; fi
echo "apache=present"
ver=$(printf "%s" "$vline" | sed -n "s#.*Apache/\([0-9][0-9.]*\).*#\1#p" | head -n1)
echo "ver=$ver"
mods=""
if command -v apache2ctl >/dev/null 2>&1; then mods=$(apache2ctl -M 2>/dev/null)
elif command -v apachectl >/dev/null 2>&1; then mods=$(apachectl -M 2>/dev/null)
else mods=$("$bin" -M 2>/dev/null); fi
http2mod=inconnu
if [ -n "$mods" ]; then
  if printf "%s" "$mods" | grep -qi "http2_module"; then http2mod=oui; else http2mod=non; fi
fi
echo "http2mod=$http2mod"
# Chemin du LoadModule http2_module dans la config (best-effort). Un chemin HORS des dossiers
# standards du paquet système indique un module mod_h2 (projet GitHub icing/mod_h2) compilé à
# part : sa version ne se déduit PAS de "$bin -v" (qui ne donne que la version du coeur Apache).
modpath=""
for d in /etc/apache2 /etc/httpd /usr/local/apache2/conf; do
  [ -d "$d" ] || continue
  f=$(grep -rniE "^[[:space:]]*LoadModule[[:space:]]+http2_module" "$d" 2>/dev/null | head -n1)
  [ -n "$f" ] && modpath=$(printf "%s" "$f" | awk "{print \$NF}" | tr -d "\"" | tr -d "\r") && break
done
echo "modpath=${modpath:-}"
osid=""; oscodename=""
if [ -r /etc/os-release ]; then
  osid=$(sed -n "s/^ID=//p" /etc/os-release | tr -d "\"" | head -n1)
  oscodename=$(sed -n "s/^VERSION_CODENAME=//p" /etc/os-release | tr -d "\"" | head -n1)
fi
echo "osid=$osid"
echo "oscodename=$oscodename"
pkgver=""
if command -v dpkg-query >/dev/null 2>&1; then
  pkgver=$(dpkg-query -W -f="\${Version}\n" apache2-bin apache2 httpd 2>/dev/null | grep -v "^$" | head -n1)
elif command -v rpm >/dev/null 2>&1; then
  pkgver=$(rpm -q --qf "%{VERSION}-%{RELEASE}\n" httpd 2>/dev/null | grep -v "not installed" | head -n1)
elif command -v apk >/dev/null 2>&1; then
  pkgver=$(apk list -I apache2 2>/dev/null | awk "NR==1{print \$1}" | sed "s/^apache2-//")
fi
echo "pkgver=${pkgver:-}"
# Le paquet dpkg trouvé ci-dessus correspond-il VRAIMENT au binaire $bin repéré plus haut ?
pkgowns=no
if [ -n "$pkgver" ] && command -v dpkg >/dev/null 2>&1; then
  ownpkg=$(dpkg -S "$bin" 2>/dev/null | sed -n "s/^\([^:]*\):.*/\1/p" | head -n1)
  case "$ownpkg" in apache2|apache2-bin|httpd) pkgowns=yes ;; esac
fi
echo "pkgowns=$pkgowns"
'

analyse() { # $1 = libellé, $2 = sortie du PROBE
  local label="$1" out="$2" present ver http2mod modpath pkgver pkgowns osid oscodename
  local status ubfixed dbfixed is_ubuntu_build is_debian_build is_standard_modpath rangestatus
  present=$(get "$out" apache)
  if [ "$present" != "present" ]; then printf '  [NON CONCERNÉ] %s : pas d'"'"'Apache httpd\n' "$label"; NC=$((NC+1)); return; fi
  ver=$(get "$out" ver); http2mod=$(get "$out" http2mod); modpath=$(get "$out" modpath)
  pkgver=$(get "$out" pkgver); pkgowns=$(get "$out" pkgowns)
  osid=$(get "$out" osid); oscodename=$(get "$out" oscodename)

  if [ "$http2mod" = "non" ]; then
    NC=$((NC+1))
    printf '  [NON CONCERNÉ] %s : Apache %s présent mais module mod_http2 non chargé — CVE-2026-119618 ne\n' "$label" "${ver:-?}"
    printf '      s'"'"'applique pas tant que ce module reste désactivé (a2dismod http2 reste une mitigation valable)\n'
    return
  fi
  if [ "$http2mod" = "inconnu" ]; then
    UNK=$((UNK+1)); FINDINGS+=("$label")
    printf '  [À VÉRIFIER] %s : impossible de lister les modules chargés (apache2ctl/httpd -M indisponible\n' "$label"
    printf '      ou droits insuffisants) — relancer en root pour trancher si mod_http2 est actif\n'
    return
  fi

  # mod_http2 chargé : vérifier que le chemin du module est bien celui du paquet système, pas un
  # build mod_h2 (GitHub icing/mod_h2) séparé dont la version ne se lit pas via "$bin -v".
  is_standard_modpath=inconnu
  case "$modpath" in
    "") is_standard_modpath=inconnu ;;
    /usr/lib/apache2/modules/*|/usr/lib64/httpd/modules/*|/usr/libexec/httpd/modules/*) is_standard_modpath=oui ;;
    *) is_standard_modpath=non ;;
  esac
  if [ "$is_standard_modpath" = "non" ]; then
    UNK=$((UNK+1)); FINDINGS+=("$label")
    printf '  [À VÉRIFIER] %s : module http2 chargé depuis un chemin non standard (%s) — probablement\n' "$label" "$modpath"
    printf '      un build mod_h2 (projet GitHub icing/mod_h2) séparé du paquet système : sa version ne se\n'
    printf '      déduit pas de la version Apache (%s). Comparer manuellement à mod_h2 >= 2.0.43 (README)\n' "${ver:-?}"
    return
  fi

  is_ubuntu_build=no
  if [ "$osid" = "ubuntu" ] && [ "$pkgowns" = "yes" ]; then
    case "$pkgver" in *ubuntu*|*+esm*) is_ubuntu_build=yes ;; esac
  fi
  is_debian_build=no
  if [ "$osid" = "debian" ] && [ "$pkgowns" = "yes" ]; then
    case "$pkgver" in *+deb*|*~deb*) is_debian_build=yes ;; esac
  fi

  if [ "$is_ubuntu_build" = "yes" ]; then
    ubfixed=$(ubuntu_fixed "$oscodename")
    if [ "$ubfixed" = "noaffected" ]; then
      # Ne pas conclure sur le seul codename : recroiser avec la version réelle détectée.
      rangestatus=$(ver_fixed_branch "${ver:-0.0.0}")
      case "$rangestatus" in
        vuln)
          VULN=$((VULN+1)); FINDINGS+=("$label")
          printf '  [VULNÉRABLE] %s : Ubuntu %s normalement non affecté (version native ancienne), mais\n' "$label" "$oscodename"
          printf '      la version Apache réellement détectée (%s) est dans la plage affectée 2.4.55-2.4.70 —\n' "$ver"
          printf '      build non standard probable, traiter comme vulnérable\n'
          ;;
        ok)
          NC=$((NC+1))
          printf '  [NON CONCERNÉ] %s : Ubuntu %s, version Apache %s hors de la plage affectée (2.4.55-2.4.70)\n' "$label" "$oscodename" "${ver:-?}"
          ;;
        *)
          UNK=$((UNK+1)); FINDINGS+=("$label")
          printf '  [À VÉRIFIER] %s : Ubuntu %s, version Apache illisible (%s) — vérifier manuellement\n' "$label" "$oscodename" "${ver:-?}"
          ;;
      esac
      return
    fi
    if [ -z "$ubfixed" ]; then
      UNK=$((UNK+1)); FINDINGS+=("$label")
      printf '  [À VÉRIFIER] %s : Ubuntu "%s" non reconnu par ce script — comparer manuellement à https://ubuntu.com/security/notices/USN-9090-1\n' "$label" "${oscodename:-codename illisible}"
      return
    fi
    if have dpkg; then
      if dpkg --compare-versions "$pkgver" lt "$ubfixed"; then
        VULN=$((VULN+1)); FINDINGS+=("$label")
        printf '  [VULNÉRABLE] %s : Ubuntu %s, paquet apache2 %s (< %s selon USN-9090-1)\n' "$label" "$oscodename" "$pkgver" "$ubfixed"
        [ "$oscodename" = "focal" ] && printf '      branche en ESM : ce correctif nécessite un abonnement Ubuntu Pro actif pour être reçu\n'
      else
        OK=$((OK+1))
        printf '  [CORRIGÉ] %s : Ubuntu %s, paquet apache2 %s (>= %s selon USN-9090-1)\n' "$label" "$oscodename" "$pkgver" "$ubfixed"
      fi
      return
    fi
    UNK=$((UNK+1)); FINDINGS+=("$label")
    printf '  [À VÉRIFIER] %s : Ubuntu %s, mais "dpkg" (comparaison de version) absent sur CETTE machine\n' "$label" "$oscodename"
    return
  fi

  if [ "$is_debian_build" = "yes" ]; then
    dbfixed=$(debian_fixed "$oscodename")
    if [ -z "$dbfixed" ]; then
      UNK=$((UNK+1)); FINDINGS+=("$label")
      printf '  [À VÉRIFIER] %s : Debian "%s" non reconnu par ce script — comparer manuellement à https://security-tracker.debian.org/tracker/CVE-2026-119618\n' "$label" "${oscodename:-codename illisible}"
      return
    fi
    if have dpkg; then
      if dpkg --compare-versions "$pkgver" lt "$dbfixed"; then
        VULN=$((VULN+1)); FINDINGS+=("$label")
        printf '  [VULNÉRABLE] %s : Debian %s, paquet apache2 %s (< %s selon DLA-4902-1/DSA-6620-1)\n' "$label" "$oscodename" "$pkgver" "$dbfixed"
      else
        OK=$((OK+1))
        printf '  [CORRIGÉ] %s : Debian %s, paquet apache2 %s (>= %s selon DLA-4902-1/DSA-6620-1)\n' "$label" "$oscodename" "$pkgver" "$dbfixed"
      fi
      return
    fi
    UNK=$((UNK+1)); FINDINGS+=("$label")
    printf '  [À VÉRIFIER] %s : Debian %s, mais "dpkg" (comparaison de version) absent sur CETTE machine\n' "$label" "$oscodename"
    return
  fi

  if [ -z "$ver" ]; then
    UNK=$((UNK+1)); FINDINGS+=("$label")
    printf '  [À VÉRIFIER] %s : Apache présent, module mod_http2 actif, mais version illisible (relancer en root ?)\n' "$label"
    return
  fi

  status=$(ver_fixed_branch "$ver")
  case "$status" in
    vuln)
      VULN=$((VULN+1)); FINDINGS+=("$label")
      printf '  [VULNÉRABLE] %s : Apache %s (2.4.55-2.4.70), module mod_http2 actif — CVE-2026-119618\n' "$label" "$ver"
      printf '      (RCE non authentifiée, race condition dans assign_headers())\n'
      [ -n "$pkgver" ] && printf '      paquet système détecté : %s (aucun rétroportage distro confirmé pour ce binaire, voir README)\n' "$pkgver"
      ;;
    ok)
      OK=$((OK+1))
      printf '  [CORRIGÉ] %s : Apache %s (>= 2.4.71, ou < 2.4.55 donc hors plage affectée)\n' "$label" "$ver"
      ;;
    unk)
      UNK=$((UNK+1)); FINDINGS+=("$label")
      printf '  [À VÉRIFIER] %s : Apache %s, numéro de version non reconnu par ce script\n' "$label" "$ver"
      ;;
  esac
}

# ---------------------------------------------------------------- 0. Prérequis
section "0. Prérequis"
printf '  utilisateur : %s\n' "$(id -un)"
[ "$(id -u)" -eq 0 ] || printf '  [ATTENTION] pas root : la lecture des modules chargés (-M) et de la config peut être incomplète\n'
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
printf '  vulnérables : %d | à vérifier : %d | corrigés : %d | non concernés : %d\n' "$VULN" "$UNK" "$OK" "$NC"
[ "${#FINDINGS[@]}" -gt 0 ] && printf '  à traiter : %s\n' "${FINDINGS[*]}"
if [ "$VULN" -gt 0 ]; then echo "Confiance : élément vulnérable CONFIRMÉ"; exit 2; fi
if [ "$UNK" -gt 0 ]; then echo "Confiance : INCOMPLÈTE (au moins un élément à vérifier à la main)"; exit 1; fi
if [ -z "$RT" ]; then echo "Confiance : COMPLÈTE"; exit 0; fi
if [ "${NC_IMAGES_DONE:-0}" -eq 1 ]; then echo "Confiance : COMPLÈTE"; exit 0; fi
echo "Confiance : PARTIELLE (images locales non sondées : relancer avec --scan-images)"; exit 0
