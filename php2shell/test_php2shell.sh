#!/usr/bin/env bash
# test_php2shell.sh — script UNIQUE et autonome (n'appelle aucun autre fichier) qui audite
# une machine Linux/macOS pour PHP2Shell (CVE-2026-109618 / CVE-2026-109619), deux failles
# PHP critiques (RCE non authentifiée via HTTP). Voir README.md pour l'explication complète.
#
# Déploiement : copier CE SEUL FICHIER sur la machine à auditer, puis :
#   chmod +x test_php2shell.sh
#   ./test_php2shell.sh                # mode lecture seule (par défaut, voir ci-dessous)
#   ./test_php2shell.sh --scan-images  # + sonde les images Docker/Podman locales (voir ci-dessous)
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
#
# Avant toute vérification, la section « 0. Prérequis » contrôle les commandes disponibles
# et adapte ce qui peut être testé en conséquence : une commande absente produit une ligne
# "absent" et la section correspondante est signalée comme ignorée — jamais une erreur
# brute de shell.
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

printf 'PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — inventaire local\nMode : %s\nDate : %s\nHôte : %s\n' \
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
  echo "         puis relancer avec lui, ex. : /usr/local/bin/bash test_php2shell.sh"
fi

have() { command -v "$1" >/dev/null 2>&1; }

HAVE_TIMEOUT=0;    have timeout    && HAVE_TIMEOUT=1
HAVE_FIND=0;       have find       && HAVE_FIND=1
HAVE_GREP=0;       have grep       && HAVE_GREP=1
HAVE_PS=0;         have ps         && HAVE_PS=1
HAVE_DPKGQ=0;      have dpkg-query && HAVE_DPKGQ=1
HAVE_RPM=0;        have rpm        && HAVE_RPM=1
HAVE_APK=0;        have apk        && HAVE_APK=1
HAVE_SYSTEMCTL=0;  have systemctl  && HAVE_SYSTEMCTL=1
HAVE_SNAP=0;       have snap       && HAVE_SNAP=1
HAVE_DOCKER=0;     have docker     && HAVE_DOCKER=1
HAVE_PODMAN=0;     have podman     && HAVE_PODMAN=1
HAVE_SS=0;         have ss         && HAVE_SS=1
HAVE_NETSTAT=0;    have netstat    && HAVE_NETSTAT=1

report() { printf '  %-14s %s\n' "$1" "$2"; }
report "bash"       "$([[ $BASH_OK -eq 1 ]] && echo "$BASH_VERSION (ok)" || echo 'ko (voir ERREUR ci-dessus)')"
report "timeout"    "$([[ $HAVE_TIMEOUT -eq 1 ]] && echo disponible || echo 'absent -> commandes longues non bornées en durée')"
report "find"       "$([[ $HAVE_FIND -eq 1 ]] && echo disponible || echo 'absent -> recherche des binaires PHP hors PATH ignorée')"
report "dpkg-query" "$([[ $HAVE_DPKGQ -eq 1 ]] && echo disponible || echo absent)"
report "rpm"        "$([[ $HAVE_RPM -eq 1 ]] && echo disponible || echo absent)"
report "apk"        "$([[ $HAVE_APK -eq 1 ]] && echo disponible || echo absent)"
report "systemctl"  "$([[ $HAVE_SYSTEMCTL -eq 1 ]] && echo disponible || echo 'absent -> section services ignorée')"
report "snap"       "$([[ $HAVE_SNAP -eq 1 ]] && echo disponible || echo 'absent -> section Snap ignorée')"
report "docker"     "$([[ $HAVE_DOCKER -eq 1 ]] && echo disponible || echo absent)"
report "podman"     "$([[ $HAVE_PODMAN -eq 1 ]] && echo disponible || echo absent)"
report "ss/netstat" "$([[ $HAVE_SS -eq 1 || $HAVE_NETSTAT -eq 1 ]] && echo disponible || echo 'absent -> section sockets ignorée')"
[[ "$HAVE_DOCKER" -eq 0 && "$HAVE_PODMAN" -eq 0 ]] && echo "  (ni docker ni podman : conteneurs/images non sondés -- seul l'hôte sera inspecté)"

if [[ "$BASH_OK" -eq 0 ]]; then
  echo
  echo "[ERREUR] Prérequis non satisfaits, arrêt avant toute vérification."
  exit 1
fi

run()       { if [[ "$HAVE_TIMEOUT" -eq 1 ]]; then timeout 8 "$@" 2>&1 || true; else "$@" 2>&1 || true; fi; }
run_t()     { local t="$1"; shift; if [[ "$HAVE_TIMEOUT" -eq 1 ]]; then timeout "$t" "$@" 2>/dev/null; else "$@" 2>/dev/null; fi; }
run_probe() { local t="$1"; shift; if [[ "$HAVE_TIMEOUT" -eq 1 ]]; then timeout "$t" "$@" 2>/dev/null; else "$@" 2>/dev/null; fi; }

# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — versions corrigées par branche (21/10/2026)
declare -A FIXED=( [8.2]=35 [8.3]=36 [8.4]=27 [8.5]=12 )
VULN_COUNT=0; OK_COUNT=0; UNK_COUNT=0
FINDINGS=()

# verdict_version <version> <contexte> : classe une version PHP et alimente le résumé
verdict_version() {
  local v="${1%%[-+~]*}" ctx="$2" br patch fx
  if [[ ! "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    UNK_COUNT=$((UNK_COUNT+1)); FINDINGS+=("[À VÉRIFIER]  $ctx : version illisible ($1)"); return
  fi
  br="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"; patch="${BASH_REMATCH[3]}"
  if [[ -n "${FIXED[$br]:-}" ]]; then
    fx="${FIXED[$br]}"
    if (( patch < fx )); then
      VULN_COUNT=$((VULN_COUNT+1)); FINDINGS+=("[VULNÉRABLE]  $ctx : PHP $v < $br.$fx")
    else
      OK_COUNT=$((OK_COUNT+1)); FINDINGS+=("[CORRIGÉ]     $ctx : PHP $v >= $br.$fx")
    fi
  elif (( BASH_REMATCH[1] < 8 || (BASH_REMATCH[1] == 8 && BASH_REMATCH[2] < 2) )); then
    VULN_COUNT=$((VULN_COUNT+1)); FINDINGS+=("[VULNÉRABLE]  $ctx : PHP $v (branche EOL, pas de correctif amont — backport source ou migration)")
  else
    UNK_COUNT=$((UNK_COUNT+1)); FINDINGS+=("[À VÉRIFIER]  $ctx : PHP $v (branche non référencée, vérifier l'avis officiel)")
  fi
}

# Script shell exécuté DANS un conteneur/une image : cherche les binaires PHP et affiche leur version
PROBE='for b in php php-cgi php-fpm php-fpm8 frankenphp; do p=$(command -v $b 2>/dev/null) && echo "BIN $p"; done
for p in /usr/local/bin/php /usr/local/sbin/php-fpm /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/frankenphp; do [ -x "$p" ] && echo "BIN $p"; done
v=$( (php -r "echo PHP_VERSION;" || php-cgi -v | sed -n "1p" | cut -d" " -f2) 2>/dev/null) && [ -n "$v" ] && echo "VER $v"
true'

# probe_target <runtime> <exec|run> <cible> <libellé> : sonde un conteneur (exec, toujours) ou
# une image (run jetable --network none, UNIQUEMENT si --scan-images a été passé par l'appelant)
probe_target() {
  local rt="$1" mode="$2" tgt="$3" label="$4" out ver bins
  if [[ "$mode" == exec ]]; then
    out=$(run_probe 20 "$rt" exec "$tgt" sh -c "$PROBE")
  else
    out=$(run_probe 40 "$rt" run --rm --network none --entrypoint sh "$tgt" -c "$PROBE")
  fi
  bins=$(printf '%s\n' "$out" | awk '$1=="BIN"{print $2}' | sort -u | tr '\n' ' ')
  ver=$(printf '%s\n' "$out" | awk '$1=="VER"{print $2; exit}')
  [[ -z "$bins" && -z "$ver" ]] && return 0
  echo "  $label : binaires=[${bins% }] version=${ver:-?}"
  if [[ -n "$ver" ]]; then verdict_version "$ver" "$label"
  else UNK_COUNT=$((UNK_COUNT+1)); FINDINGS+=("[À VÉRIFIER]  $label : PHP présent, version indéterminée"); fi
}

section "1. PHP accessible dans le PATH"
if have php; then
  command -v php
  php -v 2>&1 | head -n 3
  php --ini 2>&1 | head -n 12
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

section "2b. Binaires/modules PHP hors PATH et mitigation php.ini"
if [[ "$HAVE_FIND" -eq 1 ]]; then
  run_t 60 find / -xdev \( -type f \( -name 'php' -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' -o -name 'frankenphp*' -o -name 'libphp*.so' -o -name 'libphp*.so.*' \) \) \
    -not -path '/proc/*' -not -path '/var/lib/docker/*' -not -path '/var/lib/containerd/*' -not -path '*/node_modules/*' -not -path '*/.vscode-server/*' \
    -not -path '*/site-packages/*' -not -path '/usr/share/*' -not -path '/etc/*' \( -perm /111 -o -name '*.so*' \) -print | head -n 50
else
  echo "find absent : recherche des binaires PHP hors PATH ignorée."
fi
echo "-- session.upload_progress.enabled (mitigation CVE-2026-109619 : doit valoir 0/Off) --"
if [[ "$HAVE_GREP" -eq 1 ]]; then
  grep -RInE '^[[:space:]]*session\.upload_progress\.enabled' /etc/php /usr/local/etc/php /etc/php.ini /etc/php.d 2>/dev/null || echo "Aucun php.ini hôte trouvé (valeur par défaut PHP = On)."
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
  echo "-- Services Snap liés à PHP / applications web --"
  snap services 2>/dev/null | grep -Ei 'php|nextcloud|wordpress|owncloud|apache|nginx|web' || true
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
    echo "-- $runtime : tous les conteneurs connus (y compris arrêtés) --"
    run "$runtime" ps -a --no-trunc --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
    echo "-- $runtime : images locales dont le nom peut indiquer PHP/web --"
    run "$runtime" images --format '{{.Repository}}:{{.Tag}}' | grep -Ei 'php|wordpress|drupal|joomla|nextcloud|owncloud|laravel|apache|nginx|frankenphp|web' || true

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

section "6. Autres environnements / runtimes"
for cmd in nerdctl crictl ctr lxc; do
  have "$cmd" && echo "-- $cmd détecté : $("$cmd" --version 2>/dev/null | head -n 1) — non sondé automatiquement, à vérifier manuellement"
done
if have kubectl; then
  echo "-- Kubernetes : pods visibles dans le contexte courant (si autorisé) --"
  run kubectl get pods -A -o wide
fi

section "7. Sockets TCP/UDP en écoute"
if [[ "$HAVE_SS" -eq 1 ]]; then
  ss -lntup 2>&1 || ss -lntu 2>&1 || true
  echo "-- Ports web/PHP souvent pertinents (liste indicative) --"
  ss -lntup 2>/dev/null | awk 'NR==1 || /:80[[:space:]]|:443[[:space:]]|:8000[[:space:]]|:8080[[:space:]]|:8443[[:space:]]|:9000[[:space:]]|:9001[[:space:]]|:907[0-9][[:space:]]|:951[0-9][[:space:]]|:3000[[:space:]]|:5000[[:space:]]/'
elif [[ "$HAVE_NETSTAT" -eq 1 ]]; then
  netstat -lntup 2>&1 || netstat -lntu 2>&1 || true
else
  echo "ss/netstat indisponible : section ignorée."
fi

section "8. Configuration web susceptible de pointer vers PHP"
if [[ "$HAVE_GREP" -eq 1 ]]; then
  for dir in /etc/apache2 /etc/httpd /etc/nginx /etc/php /etc/caddy /etc/lsws; do
    if [[ -d "$dir" ]]; then
      echo "-- $dir --"
      grep -RInE 'proxy_pass|fastcgi_pass|SetHandler.*php|application/x-httpd-php|php-fpm|php-cgi|frankenphp' "$dir" 2>/dev/null | head -n 80 || true
    fi
  done
fi

section "9. Conclusion"
php_seen=0
have php && php_seen=1
[[ "$HAVE_PS" -eq 1 ]] && ps -eo args 2>/dev/null | grep -Eiq '[p]hp(-fpm|[0-9.]*-fpm|[0-9.]*-cgi|[0-9.]* )' && php_seen=1
printf '%s\n' "${FINDINGS[@]:-}" | sed '/^$/d'
echo
if [[ "$VULN_COUNT" -gt 0 ]]; then
  VERDICT="VULNÉRABLE"
  echo "[VULNÉRABLE] $VULN_COUNT installation(s) PHP < version corrigée. Si elles servent des requêtes web : mettre à jour/reconstruire en urgence, redémarrer tous les workers, appliquer session.upload_progress.enabled=0 en attendant. Si inactives (images non lancées) : supprimer ou reconstruire."
elif [[ "$UNK_COUNT" -gt 0 ]]; then
  VERDICT="À VÉRIFIER"
  echo "[À VÉRIFIER]  PHP détecté mais version non classable — vérifier manuellement."
elif [[ "$OK_COUNT" -gt 0 ]]; then
  VERDICT="OK"
  echo "[OK] PHP détecté, toutes les versions sont >= versions corrigées."
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
echo "[LIMITE] Ce script n'exploite pas la faille et ne prouve pas l'absence de compromission. Paquets Debian/Ubuntu : un numéro < corrigé peut être patché (backport) — voir le tracker de sécurité. Images tierces et kubectl/lxc non sondés en profondeur."
echo "Références : https://www.php.net/  |  https://security-tracker.debian.org/  |  https://ubuntu.com/security/notices/"

case "$VERDICT" in
  VULNÉRABLE) exit 2 ;;
  "À VÉRIFIER") exit 1 ;;
  *) exit 0 ;;
esac
