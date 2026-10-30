#!/usr/bin/env bash
# scan_public.sh — reconnaissance RÉSEAU (active) d'une ou plusieurs cibles publiques via nmap,
# pour une INDICATION (jamais une certitude) sur PHP2Shell (CVE-2026-109618/109619) et
# Broccoli2Shell (CVE-2026-111497). Voir README.md pour les limites détaillées et
# l'avertissement légal.
#
# ⚠️ Contrairement aux scripts de php2shell/ et broccoli2shell/, celui-ci envoie de VRAIES
# requêtes réseau à la ou aux cible(s). Ne l'utiliser QUE sur des domaines/IP que vous possédez
# ou que vous êtes explicitement autorisé à tester. Un scan réseau non autorisé peut être illégal.
#
# Usage : scan_public.sh <hôte-ou-IP | fichier.txt> [ports, défaut 80,443,8080,8443]
#   fichier.txt : une URL, IP ou nom d'hôte par ligne (une cible par ligne, comme nmap -iL).
#   Le schéma http(s)://, un chemin et un port en fin de ligne sont retirés automatiquement :
#   nmap veut un hôte/IP nu, pas une URL complète. Les lignes vides et commentaires (#) sont ignorés.
set -u
export LC_ALL=C

INPUT="${1:-}"
PORTS="${2:-80,443,8080,8443}"

if [[ -z "$INPUT" || "$INPUT" == "-h" || "$INPUT" == "--help" ]]; then
  echo "Usage: $0 <hôte-ou-IP | fichier.txt> [ports, défaut 80,443,8080,8443]"
  echo "  fichier.txt : une URL/IP/nom d'hôte par ligne (comme nmap -iL)."
  echo "Exemple inoffensif (cible de test officielle de nmap) : $0 scanme.nmap.org"
  exit 2
fi

if ! command -v nmap >/dev/null 2>&1; then
  echo "[ERREUR] nmap n'est pas installé. Voir README.md pour l'installer (apt/dnf/apk/brew/winget)."
  exit 1
fi

section() { printf '\n===== %s =====\n' "$1"; }

TMP_LIST=""
cleanup() { [[ -n "$TMP_LIST" && -f "$TMP_LIST" ]] && rm -f "$TMP_LIST"; }
trap cleanup EXIT

NMAP_TARGETS=()
TARGET_DESC=""
REPORT_FILE=""

if [[ -f "$INPUT" ]]; then
  # Fichier de cibles : on retire le schéma http(s)://, le chemin/la query et un éventuel port
  # en fin de ligne pour ne garder qu'un hôte/IP nu -- c'est ce que nmap -iL attend, pas une URL
  # complète (ex. "https://exemple.com:8443/admin" -> "exemple.com").
  TMP_LIST=$(mktemp)
  sed -E 's/#.*$//; s#^[a-zA-Z][a-zA-Z0-9+.-]*://##; s#[/?].*$##; s/:[0-9]+$//' "$INPUT" \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
    | grep -v '^$' > "$TMP_LIST"
  n=$(wc -l < "$TMP_LIST" | tr -d ' ')
  if [[ "$n" -eq 0 ]]; then
    echo "[ERREUR] Aucune cible valide trouvée dans $INPUT."
    exit 2
  fi
  NMAP_TARGETS=(-iL "$TMP_LIST")
  TARGET_DESC="$n cible(s) listée(s) dans $INPUT"
  REPORT_FILE="scan_public_$(date +%Y%m%d_%H%M%S).log"
else
  NMAP_TARGETS=("$INPUT")
  TARGET_DESC="$INPUT"
fi

run_report() {
  section "0. Prérequis"
  echo "nmap : $(nmap --version 2>/dev/null | head -1)"
  echo "Cible(s) : $TARGET_DESC"
  echo "Ports : $PORTS"
  if [[ -n "$TMP_LIST" ]]; then
    echo "-- Liste assainie transmise à nmap --"
    cat "$TMP_LIST"
  fi
  echo
  echo "⚠️  Ce scan envoie des requêtes réseau à CHAQUE cible listée ci-dessus. Interrompre"
  echo "   maintenant (Ctrl+C) si vous n'êtes pas certain d'être autorisé à toutes les tester."

  section "1. Services et bannières (nmap -sV)"
  nmap -sV -p "$PORTS" "${NMAP_TARGETS[@]}" 2>&1

  section "2. Version PHP exposée (si non masquée par la configuration serveur)"
  nmap -p "$PORTS" --script=http-server-header,http-php-version "${NMAP_TARGETS[@]}" 2>&1

  section "3. En-têtes de réponse HTTP (recherche de Content-Encoding: br)"
  nmap -p "$PORTS" --script=http-headers "${NMAP_TARGETS[@]}" 2>&1

  echo
  section "Conclusion"
  echo "Ce script n'affiche volontairement aucun verdict [VULNÉRABLE]/[CORRIGÉ]/[NON CONCERNÉ] :"
  echo "un scan réseau externe ne peut pas distinguer de façon fiable une version masquée d'une"
  echo "version absente, ni voir la version d'un décodeur Brotli depuis l'extérieur. Lire la"
  echo "sortie ci-dessus à la main, PAR CIBLE si plusieurs ont été scannées :"
  echo "  - Si une version PHP apparaît en section 2, la comparer au tableau de"
  echo "    ../php2shell/README.md (attention au piège Debian/Ubuntu documenté là-bas)."
  echo "  - Si 'Content-Encoding: br' apparaît en section 3, Brotli est en jeu : auditer la"
  echo "    machine avec ../broccoli2shell/test_broccoli2shell.sh pour un verdict réel."
  echo "[LIMITE] Aucune version visible ne prouve qu'un serveur est à jour (expose_php=Off est une"
  echo "pratique de durcissement courante, pas un signe de vulnérabilité). Pour une certitude"
  echo "réelle sur l'une ou l'autre faille, utiliser le script correspondant directement SUR la"
  echo "machine, avec un accès shell -- ce scan public ne sert qu'à prioriser quoi auditer."
}

if [[ -n "$REPORT_FILE" ]]; then
  run_report | tee "$REPORT_FILE"
  echo
  echo "Résultat complet également enregistré dans : $REPORT_FILE"
else
  run_report
fi
