#!/usr/bin/env bash
# test_broccoli2shell.sh — script UNIQUE et autonome (n'appelle aucun autre fichier) qui
# audite une machine Linux/macOS pour Broccoli2Shell / Node2Shell / HTTP2Shell
# (CVE-2026-111497, décodeur Brotli). Voir README.md pour l'explication complète.
#
# Déploiement : copier CE SEUL FICHIER sur la machine à auditer, puis :
#   chmod +x test_broccoli2shell.sh
#   ./test_broccoli2shell.sh                # mode lecture seule (par défaut, voir ci-dessous)
#   ./test_broccoli2shell.sh --scan-images  # + sonde les images Docker/Podman locales
#
# -------------------------------------------------------------------------------------------
# DEUX MODES :
#   - Lecture seule (PAR DÉFAUT) : inspecte l'hôte et exécute une commande de lecture dans
#     les conteneurs Docker/Podman DÉJÀ EN COURS D'EXÉCUTION (docker exec). Ne crée, ne
#     démarre, ne modifie et ne supprime RIEN.
#   - --scan-images : en plus du mode lecture seule, lance un conteneur ÉPHÉMÈRE et ISOLÉ
#     (docker/podman run --rm --network none) pour chaque image locale, le temps d'y chercher
#     une bibliothèque Brotli vulnérable, puis le détruit immédiatement. C'est le seul mode
#     qui peut révéler une image vulnérable qui n'est PAS actuellement démarrée (donc
#     invisible en lecture seule) — nécessaire pour être réellement certain que la machine
#     n'est pas concernée.
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

printf 'Broccoli2Shell (CVE-2026-111497) — inventaire local\nMode : %s\nDate : %s\nHôte : %s\n' \
  "$([[ $SCAN_IMAGES -eq 1 ]] && echo 'complet (hôte + conteneurs actifs + images, conteneurs éphémères --network none)' || echo 'lecture seule (hôte + conteneurs actifs uniquement, aucune création)')" \
  "$(date -Is 2>/dev/null || date)" "$(hostname -f 2>/dev/null || hostname)"
OS_ID=""; OS_VER=""
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  printf 'OS : %s %s\n' "${PRETTY_NAME:-unknown}" "${VERSION_ID:-}"
  OS_ID="${ID:-}"; OS_VER="${VERSION_ID:-}"
else
  echo "OS : unknown"
fi

# ============================================================
section "0. Prérequis"
# ============================================================
BASH_OK=1
if (( BASH_VERSINFO[0] < 4 )); then
  BASH_OK=0
  echo "[ERREUR] bash >= 4.0 requis (tableaux associatifs). Version détectée : $BASH_VERSION."
  echo "         macOS : le bash système est en 3.2 -> installer un bash récent (brew install bash)"
  echo "         puis relancer avec lui, ex. : /usr/local/bin/bash test_broccoli2shell.sh"
fi

have() { command -v "$1" >/dev/null 2>&1; }

HAVE_TIMEOUT=0;    have timeout    && HAVE_TIMEOUT=1
HAVE_FIND=0;       have find       && HAVE_FIND=1
HAVE_DPKGQ=0;      have dpkg-query && HAVE_DPKGQ=1
HAVE_DPKG_CMD=0;   have dpkg       && HAVE_DPKG_CMD=1
HAVE_RPM=0;        have rpm        && HAVE_RPM=1
HAVE_APK=0;        have apk        && HAVE_APK=1
HAVE_SNAP=0;       have snap       && HAVE_SNAP=1
HAVE_DOCKER=0;     have docker     && HAVE_DOCKER=1
HAVE_PODMAN=0;     have podman     && HAVE_PODMAN=1
HAVE_DOTNET=0;     have dotnet     && HAVE_DOTNET=1
HAVE_NODE=0;       have node       && HAVE_NODE=1
HAVE_KUBECTL=0;    have kubectl    && HAVE_KUBECTL=1

report() { printf '  %-14s %s\n' "$1" "$2"; }
report "bash"       "$([[ $BASH_OK -eq 1 ]] && echo "$BASH_VERSION (ok)" || echo 'ko (voir ERREUR ci-dessus)')"
report "timeout"    "$([[ $HAVE_TIMEOUT -eq 1 ]] && echo disponible || echo 'absent -> commandes longues non bornées en durée')"
report "find"       "$([[ $HAVE_FIND -eq 1 ]] && echo disponible || echo 'absent -> sections hors-PATH / copies embarquées ignorées')"
report "dpkg-query" "$([[ $HAVE_DPKGQ -eq 1 ]] && echo disponible || echo absent)"
report "dpkg"       "$([[ $HAVE_DPKG_CMD -eq 1 ]] && echo disponible || echo absent)"
report "rpm"        "$([[ $HAVE_RPM -eq 1 ]] && echo disponible || echo absent)"
report "apk"        "$([[ $HAVE_APK -eq 1 ]] && echo disponible || echo absent)"
report "snap"       "$([[ $HAVE_SNAP -eq 1 ]] && echo disponible || echo 'absent -> section Snap ignorée')"
report "docker"     "$([[ $HAVE_DOCKER -eq 1 ]] && echo disponible || echo absent)"
report "podman"     "$([[ $HAVE_PODMAN -eq 1 ]] && echo disponible || echo absent)"
report "dotnet"     "$([[ $HAVE_DOTNET -eq 1 ]] && echo disponible || echo absent)"
report "node"       "$([[ $HAVE_NODE -eq 1 ]] && echo disponible || echo absent)"
report "kubectl"    "$([[ $HAVE_KUBECTL -eq 1 ]] && echo disponible || echo absent)"
[[ "$HAVE_DOCKER" -eq 0 && "$HAVE_PODMAN" -eq 0 ]] && echo "  (ni docker ni podman : conteneurs/images non sondés -- seul l'hôte sera inspecté)"

if [[ "$BASH_OK" -eq 0 ]]; then
  echo
  echo "[ERREUR] Prérequis non satisfaits, arrêt avant toute vérification."
  exit 1
fi

run()       { if [[ "$HAVE_TIMEOUT" -eq 1 ]]; then timeout 8 "$@" 2>&1 || true; else "$@" 2>&1 || true; fi; }
run_t()     { local t="$1"; shift; if [[ "$HAVE_TIMEOUT" -eq 1 ]]; then timeout "$t" "$@" 2>/dev/null; else "$@" 2>/dev/null; fi; }
run_probe() { local t="$1"; shift; if [[ "$HAVE_TIMEOUT" -eq 1 ]]; then timeout "$t" "$@" 2>/dev/null; else "$@" 2>/dev/null; fi; }

VULN_COUNT=0; OK_COUNT=0; UNK_COUNT=0
FINDINGS=()
add_finding() { # <verdict: VULNERABLE|OK|UNKNOWN> <ligne texte>
  case "$1" in
    VULNERABLE) VULN_COUNT=$((VULN_COUNT+1)); FINDINGS+=("[VULNÉRABLE]  $2") ;;
    OK)         OK_COUNT=$((OK_COUNT+1));     FINDINGS+=("[CORRIGÉ]     $2") ;;
    *)          UNK_COUNT=$((UNK_COUNT+1));   FINDINGS+=("[À VÉRIFIER]  $2") ;;
  esac
}

# ---- Tables de versions corrigées (sources : security-tracker.debian.org, ubuntu.com/security/notices,
#      security.alpinelinux.org — vérifiées au 30/10/2026 ; à recontrôler si la date a changé) ----
declare -A DEB_FIXED=( [12]="1.0.9-2+deb12u1" [13]="1.1.0-2+deb13u1" )
declare -A UBU_FIXED=( [22.04]="1.0.9-2ubuntu0.1" [24.04]="1.1.0-2ubuntu0.1" [26.04]="1.2.0-3ubuntu0.1" [26.10]="1.2.0-4ubuntu0.1" )
declare -A APK_FIXED=( [3.21]="1.1.1-r0" [3.23]="1.2.1-r0" [3.24]="1.2.1-r0" )
PY_BROTLI_FIXED="1.2.1"
PY_BROTLICFFI_FIXED="1.2.1.0"
NODE_FIXED_LINES="22.23.4 24.22.1 26.12.1"   # lignes EOL (20.x et antérieures, 21.x, 23.x, 25.x) : pas de correctif, migration nécessaire
DOTNET_FIXED_8="8.0.33"; DOTNET_FIXED_9="9.0.22"; DOTNET_FIXED_10="10.0.14"

verdict_pkg_version() { # <id> <installed> <fixed> <label>
  local id="$1" inst="$2" fx="$3" label="$4"
  if [[ -z "$fx" ]]; then
    add_finding UNKNOWN "$label : version $inst, pas de référence de correctif connue pour cette distribution/version — vérifier le tracker de sécurité officiel."
    return
  fi
  if [[ "$id" == deb ]]; then
    if [[ "$HAVE_DPKG_CMD" -eq 1 ]]; then
      if dpkg --compare-versions "$inst" lt "$fx"; then
        add_finding VULNERABLE "$label : $inst < $fx (correctif disponible)"
      else
        add_finding OK "$label : $inst >= $fx"
      fi
    else
      if [[ "$inst" != "$fx" && "$(printf '%s\n%s\n' "$inst" "$fx" | sort -V | head -1)" == "$inst" ]]; then
        add_finding VULNERABLE "$label : $inst < $fx (sort -V, dpkg --compare-versions indisponible — à confirmer)"
      else
        add_finding OK "$label : $inst >= $fx (sort -V, dpkg --compare-versions indisponible — à confirmer)"
      fi
    fi
  elif [[ "$id" == apk ]]; then
    if [[ "$HAVE_APK" -eq 1 ]]; then
      if apk version -t "$inst" "$fx" 2>/dev/null | grep -q '<'; then
        add_finding VULNERABLE "$label : $inst < $fx (correctif disponible)"
      else
        add_finding OK "$label : $inst >= $fx"
      fi
    else
      if [[ "$inst" != "$fx" && "$(printf '%s\n%s\n' "$inst" "$fx" | sort -V | head -1)" == "$inst" ]]; then
        add_finding VULNERABLE "$label : $inst < $fx (sort -V, apk natif indisponible pour comparer — à confirmer)"
      else
        add_finding OK "$label : $inst >= $fx (sort -V, apk natif indisponible pour comparer — à confirmer)"
      fi
    fi
  else
    add_finding UNKNOWN "$label : $inst (comparaison non fiable, vérifier manuellement contre $fx)"
  fi
}

section "1. Paquet système libbrotli / brotli-libs (hôte)"
if [[ "$HAVE_DPKGQ" -eq 1 ]]; then
  pkg_line=$(dpkg-query -W -f='${binary:Package} ${Version}\n' 2>/dev/null | grep -Ei '^(libbrotli|brotli)' | sort -u)
  if [[ -n "$pkg_line" ]]; then
    echo "$pkg_line"
    while read -r pkg ver; do
      [[ -z "$pkg" ]] && continue
      fixed=""
      case "$OS_ID" in
        debian) fixed="${DEB_FIXED[$OS_VER]:-}" ;;
        ubuntu) fixed="${UBU_FIXED[$OS_VER]:-}" ;;
      esac
      verdict_pkg_version deb "$ver" "$fixed" "hôte, paquet $pkg ($OS_ID $OS_VER)"
    done <<< "$pkg_line"
  else
    echo "Aucun paquet libbrotli/brotli trouvé via dpkg."
  fi
elif [[ "$HAVE_RPM" -eq 1 ]]; then
  pkg_line=$(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 2>/dev/null | grep -Ei '^(lib)?brotli')
  if [[ -n "$pkg_line" ]]; then
    echo "$pkg_line"
    while read -r pkg ver; do
      [[ -z "$pkg" ]] && continue
      add_finding UNKNOWN "hôte, paquet $pkg : $ver — RHEL/CentOS/Fedora : comparer manuellement à l'avis Red Hat/Fedora (RHSB-2026-015 ou équivalent), les NVR secondaires ne sont pas fiables ici."
    done <<< "$pkg_line"
  else
    echo "Aucun paquet brotli trouvé via rpm."
  fi
elif [[ "$HAVE_APK" -eq 1 ]]; then
  pkg_line=$(apk info -vv 2>/dev/null | grep -Ei '^brotli-libs')
  if [[ -n "$pkg_line" ]]; then
    echo "$pkg_line"
    ver=$(printf '%s\n' "$pkg_line" | sed -n 's/^brotli-libs-\([0-9][^ ]*\).*/\1/p' | head -1)
    fixed="${APK_FIXED[$OS_VER]:-}"
    verdict_pkg_version apk "$ver" "$fixed" "hôte, brotli-libs ($OS_ID $OS_VER)"
  else
    echo "Aucun paquet brotli-libs trouvé via apk."
  fi
else
  echo "Gestionnaire de paquets non reconnu (dpkg-query/rpm/apk absents) : section ignorée."
fi
echo "Note : sur Debian/Ubuntu/Alpine, le numéro de version est RE-NUMÉROTÉ par le mainteneur (ex. Ubuntu 22.04 corrige en 1.0.9-2ubuntu0.1, pas en 1.2.1). Ne jamais comparer le numéro brut à la version amont sans passer par la table de la distribution."

section "2. Python — paquets Brotli / brotlicffi (hôte)"
if [[ "$HAVE_FIND" -eq 1 ]]; then
  found_py=0
  while IFS= read -r di; do
    found_py=1
    name=$(basename "$di" | sed -E 's/-[0-9].*//')
    ver=$(grep -m1 '^Version:' "$di/METADATA" 2>/dev/null | awk '{print $2}')
    [[ -z "$ver" ]] && ver=$(basename "$di" | sed -E 's/^[^-]+-//; s/\.dist-info$//')
    echo "  $di -> $name $ver"
    case "$(echo "$name" | tr 'A-Z' 'a-z')" in
      brotli) [[ "$(printf '%s\n%s\n' "$ver" "$PY_BROTLI_FIXED" | sort -V | head -1)" == "$ver" && "$ver" != "$PY_BROTLI_FIXED" ]] \
          && add_finding VULNERABLE "Python Brotli $ver (< $PY_BROTLI_FIXED) dans $di" \
          || add_finding OK "Python Brotli $ver dans $di" ;;
      brotlicffi) [[ "$(printf '%s\n%s\n' "$ver" "$PY_BROTLICFFI_FIXED" | sort -V | head -1)" == "$ver" && "$ver" != "$PY_BROTLICFFI_FIXED" ]] \
          && add_finding VULNERABLE "Python brotlicffi $ver (< $PY_BROTLICFFI_FIXED) dans $di" \
          || add_finding OK "Python brotlicffi $ver dans $di" ;;
    esac
  done < <(run_t 30 find / -xdev -iname '*.dist-info' -ipath '*brotli*' -not -path '/proc/*')
  [[ "$found_py" -eq 0 ]] && echo "Aucun paquet Python Brotli/brotlicffi trouvé sur l'hôte (hors conteneurs)."
else
  echo "find absent : recherche des paquets Python Brotli/brotlicffi ignorée."
fi
echo "Rappel : si la mise à jour est impossible, désinstaller Brotli/brotlicffi fait retomber les clients HTTP (urllib3/requests/aiohttp/httpx) sur gzip/deflate."

section "3. Node.js (hôte)"
if [[ "$HAVE_NODE" -eq 1 || "$HAVE_FIND" -eq 1 ]]; then
  while IFS= read -r nodebin; do
    v=$("$nodebin" -v 2>/dev/null | sed 's/^v//')
    [[ -z "$v" ]] && continue
    echo "  $nodebin -> v$v"
    ok=0
    for f in $NODE_FIXED_LINES; do [[ "$v" == "$f" || "$(printf '%s\n%s\n' "$v" "$f" | sort -V | tail -1)" == "$v" ]] && { [[ "${v%%.*}" == "${f%%.*}" ]] && ok=1; }; done
    if [[ "$ok" -eq 1 ]]; then add_finding OK "Node.js $v ($nodebin)"
    else add_finding VULNERABLE "Node.js $v ($nodebin) — comparer à la ligne majeure correspondante (corrigé : $NODE_FIXED_LINES) ; lignes EOL (20.x et antérieures, 21.x, 23.x, 25.x) sans correctif, migration nécessaire"; fi
  done < <({ [[ "$HAVE_NODE" -eq 1 ]] && command -v node; [[ "$HAVE_FIND" -eq 1 ]] && run_t 30 find / -xdev -maxdepth 6 -type f -iname node -perm /111; } | sort -u)
else
  echo "node absent du PATH et find indisponible : section ignorée."
fi

section "4. .NET (hôte)"
if [[ "$HAVE_DOTNET" -eq 1 ]]; then
  run dotnet --list-runtimes
  while read -r name ver _; do
    [[ -z "$ver" ]] && continue
    case "$name" in
      Microsoft.NETCore.App|Microsoft.AspNetCore.App)
        major="${ver%%.*}"
        case "$major" in
          8) fx="$DOTNET_FIXED_8" ;; 9) fx="$DOTNET_FIXED_9" ;; 10) fx="$DOTNET_FIXED_10" ;; *) fx="" ;;
        esac
        if [[ -n "$fx" ]]; then
          if [[ "$(printf '%s\n%s\n' "$ver" "$fx" | sort -V | head -1)" == "$ver" && "$ver" != "$fx" ]]; then
            add_finding VULNERABLE ".NET $name $ver (< $fx)"
          else
            add_finding OK ".NET $name $ver (>= $fx)"
          fi
        else
          add_finding UNKNOWN ".NET $name $ver — branche .NET 11+ ou EOL, vérifier l'avis Microsoft directement."
        fi
        ;;
    esac
  done < <(dotnet --list-runtimes 2>/dev/null)
else
  echo "dotnet non trouvé dans le PATH."
fi
echo "-- Déploiements .NET autonomes (self-contained) : embarquent leur propre runtime, invisibles ci-dessus --"
if [[ "$HAVE_FIND" -eq 1 ]]; then
  run_t 30 find / -xdev -iname '*.runtimeconfig.json' -not -path '/proc/*' | head -n 30
  echo "Pour chaque fichier listé : vérifier le champ \"version\" sous runtimeOptions.framework et comparer à la table ci-dessus."
else
  echo "find absent : recherche des déploiements self-contained ignorée."
fi

section "5. Copies embarquées de Brotli (hôte)"
if [[ "$HAVE_FIND" -eq 1 ]]; then
  echo "-- Bibliothèques libbrotli* trouvées hors gestion de paquets --"
  run_t 30 find / -xdev \( -iname 'libbrotli*.so*' \) -not -path '/proc/*' -not -path '/var/lib/docker/*' -not -path '/var/lib/containerd/*' | sort -u | head -n 50
  echo "-- Logiciels connus pour embarquer leur propre Brotli (DuckDB, Apache Arrow, 7-Zip-zstd/p7zip, EDK II, woff2) --"
  run_t 30 find / -xdev -type f \( -iname 'duckdb' -o -iname '7z' -o -iname '7za' -o -iname '7zr' -o -iname '7zz*' -o -iname 'p7zip*' -o -iname 'woff2*' \) -perm /111 -not -path '/proc/*' | sort -u | head -n 50
  echo "Ces copies ne sont PAS corrigées par la mise à jour du paquet système libbrotli. Chaque binaire listé ci-dessus est à vérifier auprès de l'éditeur."
else
  echo "find absent : recherche des copies embarquées de Brotli ignorée."
fi

section "6. Snap"
if [[ "$HAVE_SNAP" -eq 1 ]]; then
  snap list 2>/dev/null
  if [[ "$HAVE_FIND" -eq 1 ]]; then
    echo "-- Bibliothèques/exécutables liés à Brotli repérés dans les répertoires Snap --"
    run_t 30 find /snap /var/snap -iname '*brotli*' | head -n 50
  fi
else
  echo "Snap non installé ou commande absente : section ignorée."
fi

# ---- Sonde conteneurs/images : paquet distro, Python, Node, .NET, copies embarquées ----
PROBE='
if [ -r /etc/os-release ]; then . /etc/os-release; echo "OSREL ${ID:-} ${VERSION_ID:-}"; fi
dpkg -l 2>/dev/null | awk "tolower(\$0) ~ /brotli/ {print \"PKGDPKG\",\$2,\$3}"
rpm -qa --qf "PKGRPM %{NAME} %{VERSION}-%{RELEASE}\n" 2>/dev/null | grep -i brotli
apk info -vv 2>/dev/null | awk "\$1 ~ /^brotli-libs-/ {n=\$1; sub(/^brotli-libs-/,\"\",n); print \"PKGAPK brotli-libs\",n}"
for di in $(find / -xdev -iname "*.dist-info" -ipath "*brotli*" -not -path "/proc/*" 2>/dev/null); do
  v=$(grep -m1 "^Version:" "$di/METADATA" 2>/dev/null | awk "{print \$2}")
  echo "PYPKG $di $v"
done
command -v node >/dev/null 2>&1 && echo "NODE $(node -v 2>/dev/null)"
command -v dotnet >/dev/null 2>&1 && dotnet --list-runtimes 2>/dev/null | sed "s/^/DOTNET /"
for b in duckdb 7z 7za 7zr p7zip woff2; do command -v $b >/dev/null 2>&1 && echo "EMBED $b"; done
true'

probe_container() { # <runtime> <exec|run> <cible> <libellé>
  local rt="$1" mode="$2" tgt="$3" label="$4" out c_id c_ver kind a b fixed
  if [[ "$mode" == exec ]]; then out=$(run_probe 25 "$rt" exec "$tgt" sh -c "$PROBE")
  else out=$(run_probe 45 "$rt" run --rm --network none --entrypoint sh "$tgt" -c "$PROBE"); fi
  [[ -z "$out" ]] && return 0
  echo "  -- $label --"
  printf '%s\n' "$out" | sed 's/^/    /'
  grep -qE '^(PKGDPKG|PKGAPK|PKGRPM|PYPKG|NODE|DOTNET|EMBED) ' <<< "$out" || return 0
  c_id=$(awk '$1=="OSREL"{print $2}' <<< "$out")
  c_ver=$(awk '$1=="OSREL"{print $3}' <<< "$out")
  while read -r kind a b; do
    case "$kind" in
      PKGDPKG)
        fixed=""
        case "$c_id" in debian) fixed="${DEB_FIXED[$c_ver]:-}" ;; ubuntu) fixed="${UBU_FIXED[$c_ver]:-}" ;; esac
        verdict_pkg_version deb "$b" "$fixed" "$label, paquet $a ($c_id ${c_ver:-?})"
        ;;
      PKGAPK)
        fixed="${APK_FIXED[$c_ver]:-}"
        verdict_pkg_version apk "$b" "$fixed" "$label, $a ($c_id ${c_ver:-?})"
        ;;
      PKGRPM)
        add_finding UNKNOWN "$label : paquet $a $b (rpm) — vérifier l'avis Red Hat/Fedora/distribution manuellement"
        ;;
      PYPKG)
        [[ -n "$b" ]] && add_finding UNKNOWN "$label : Python $(basename "$a") $b — comparer à Brotli>=$PY_BROTLI_FIXED / brotlicffi>=$PY_BROTLICFFI_FIXED"
        ;;
      NODE)
        add_finding UNKNOWN "$label : Node.js $a — comparer à $NODE_FIXED_LINES"
        ;;
      DOTNET)
        add_finding UNKNOWN "$label : .NET $a $b — comparer à 8.0.33/9.0.22/10.0.14/11 RC3+"
        ;;
      EMBED)
        add_finding UNKNOWN "$label : binaire embarquant potentiellement sa propre copie de Brotli ($a) — vérifier l'éditeur"
        ;;
    esac
  done <<< "$out"
}

section "7. Docker / Podman"
if [[ "$HAVE_DOCKER" -eq 0 && "$HAVE_PODMAN" -eq 0 ]]; then
  echo "Docker/Podman non détecté dans le PATH : section ignorée."
else
  for runtime in docker podman; do
    have "$runtime" || continue
    echo "-- $runtime : sonde dans les conteneurs EN COURS (exec, lecture seule) --"
    while IFS= read -r c; do [[ -n "$c" ]] && probe_container "$runtime" exec "$c" "conteneur $c"; done \
      < <("$runtime" ps --format '{{.Names}}' 2>/dev/null)
    if [[ "$SCAN_IMAGES" -eq 1 ]]; then
      echo "-- $runtime : sonde dans les IMAGES locales (conteneur ÉPHÉMÈRE, --network none, détruit après usage) --"
      while IFS= read -r img; do [[ -n "$img" && "$img" != *'<none>'* ]] && probe_container "$runtime" run "$img" "image $img"; done \
        < <("$runtime" images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | sort -u)
    else
      echo "(mode lecture seule : images locales non sondées — relancer avec --scan-images pour les inclure)"
    fi
  done
fi

section "8. Autres environnements de conteneurs/VM"
for cmd in nerdctl crictl ctr lxc; do
  have "$cmd" && echo "-- $cmd détecté : $("$cmd" --version 2>/dev/null | head -n 1) — à sonder manuellement (non couvert par ce script)"
done
if [[ "$HAVE_KUBECTL" -eq 1 ]]; then
  echo "-- Kubernetes détecté — pods non sondés automatiquement ; vérifier chaque image/pod manuellement --"
  run kubectl get pods -A -o wide
fi

section "9. Conclusion"
printf '%s\n' "${FINDINGS[@]:-}" | sed '/^$/d'
echo
if [[ "$VULN_COUNT" -gt 0 ]]; then
  VERDICT="VULNÉRABLE"
  echo "[VULNÉRABLE] $VULN_COUNT élément(s) confirmé(s) sous la version corrigée. Mettre à jour le paquet/runtime concerné, PUIS redémarrer tous les processus qui l'avaient chargé (ils gardent le décodeur vulnérable en mémoire jusqu'au redémarrage). Pour une image Docker : reconstruire et redéployer."
elif [[ "$UNK_COUNT" -gt 0 ]]; then
  VERDICT="À VÉRIFIER"
  echo "[À VÉRIFIER] $UNK_COUNT élément(s) détecté(s) sans verdict automatique fiable (distribution non référencée, conteneur à vérifier manuellement, copie embarquée, etc.). Compléter à la main."
elif [[ "$OK_COUNT" -gt 0 ]]; then
  VERDICT="OK"
  echo "[OK] Tous les éléments détectés sont à jour."
else
  VERDICT="NON CONCERNÉ"
  echo "[NON CONCERNÉ] Aucune trace de Brotli (libbrotli, Python Brotli/brotlicffi, Node.js, .NET) trouvée sur l'hôte ni dans les conteneurs actifs sondés."
fi

echo
if [[ "$VERDICT" == "VULNÉRABLE" ]]; then
  echo "Confiance : élément vulnérable CONFIRMÉ — pas d'ambiguïté, agir immédiatement (cf. ci-dessus)."
elif [[ "$VERDICT" == "À VÉRIFIER" ]]; then
  echo "Confiance : INCOMPLÈTE — au moins un élément nécessite une vérification manuelle avant de pouvoir conclure."
elif [[ "$SCAN_IMAGES" -eq 1 ]]; then
  echo "Confiance : COMPLÈTE dans la limite de ce script — hôte, conteneurs actifs ET images locales ont tous été sondés, aucune trace de Brotli vulnérable."
else
  echo "Confiance : PARTIELLE — mode lecture seule : seuls l'hôte et les conteneurs ACTIFS ont été inspectés. Une image Docker/Podman locale non démarrée peut contenir un Brotli vulnérable sans apparaître ici. Relancer avec --scan-images pour être certain."
fi
echo "[LIMITE] Ce script n'exploite pas la faille et ne prouve pas l'absence de compromission. Il ne sait pas évaluer RHEL/CentOS/Fedora de façon fiable (vérifier l'avis éditeur), ni les copies embarquées (DuckDB, Arrow, 7-Zip, woff2…), ni les applications .NET autonomes (self-contained) au-delà du repérage des fichiers *.runtimeconfig.json."
echo "Références : CVE-2026-111497 | GHSA-9v8h-qqgm-4m35 | https://security-tracker.debian.org/ | https://ubuntu.com/security/notices/ | https://security.alpinelinux.org/"

case "$VERDICT" in
  VULNÉRABLE) exit 2 ;;
  "À VÉRIFIER") exit 1 ;;
  *) exit 0 ;;
esac
