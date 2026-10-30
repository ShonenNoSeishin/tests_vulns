#!/usr/bin/env bash
# scan_public.sh — reconnaissance RÉSEAU (active) d'une cible publique via nmap, pour une
# INDICATION (jamais une certitude) sur PHP2Shell (CVE-2026-109618/109619) et Broccoli2Shell
# (CVE-2026-111497). Voir README.md pour les limites détaillées et l'avertissement légal.
#
# ⚠️ Contrairement aux scripts de php2shell/ et broccoli2shell/, celui-ci envoie de VRAIES
# requêtes réseau à la cible. Ne l'utiliser QUE sur un domaine/IP que vous possédez ou que vous
# êtes explicitement autorisé à tester. Un scan réseau non autorisé peut être illégal.
#
# Usage : scan_public.sh <hôte-ou-IP> [ports, défaut 80,443,8080,8443]
set -u
export LC_ALL=C

TARGET="${1:-}"
PORTS="${2:-80,443,8080,8443}"

if [[ -z "$TARGET" || "$TARGET" == "-h" || "$TARGET" == "--help" ]]; then
  echo "Usage: $0 <hôte-ou-IP> [ports, défaut 80,443,8080,8443]"
  echo "Exemple inoffensif (cible de test officielle de nmap) : $0 scanme.nmap.org"
  exit 2
fi

section() { printf '\n===== %s =====\n' "$1"; }

section "0. Prérequis"
if ! command -v nmap >/dev/null 2>&1; then
  echo "[ERREUR] nmap n'est pas installé. Voir README.md pour l'installer (apt/dnf/apk/brew/winget)."
  exit 1
fi
echo "nmap : $(nmap --version 2>/dev/null | head -1)"
echo "Cible : $TARGET"
echo "Ports : $PORTS"
echo
echo "⚠️  Ce scan envoie des requêtes réseau à $TARGET. Interrompre maintenant (Ctrl+C) si vous"
echo "   n'êtes pas certain d'être autorisé à tester cette cible."

section "1. Services et bannières (nmap -sV)"
nmap -sV -p "$PORTS" "$TARGET" 2>&1

section "2. Version PHP exposée (si non masquée par la configuration serveur)"
nmap -p "$PORTS" --script=http-server-header,http-php-version "$TARGET" 2>&1

section "3. En-têtes de réponse HTTP (recherche de Content-Encoding: br)"
nmap -p "$PORTS" --script=http-headers "$TARGET" 2>&1

echo
section "Conclusion"
echo "Ce script n'affiche volontairement aucun verdict [VULNÉRABLE]/[CORRIGÉ]/[NON CONCERNÉ] :"
echo "un scan réseau externe ne peut pas distinguer de façon fiable une version masquée d'une"
echo "version absente, ni voir la version d'un décodeur Brotli depuis l'extérieur. Lire la"
echo "sortie ci-dessus à la main :"
echo "  - Si une version PHP apparaît en section 2, la comparer au tableau de"
echo "    ../php2shell/README.md (attention au piège Debian/Ubuntu documenté là-bas)."
echo "  - Si 'Content-Encoding: br' apparaît en section 3, Brotli est en jeu : auditer la"
echo "    machine avec ../broccoli2shell/test_broccoli2shell.sh pour un verdict réel."
echo "[LIMITE] Aucune version visible ne prouve qu'un serveur est à jour (expose_php=Off est une"
echo "pratique de durcissement courante, pas un signe de vulnérabilité). Pour une certitude"
echo "réelle sur l'une ou l'autre faille, utiliser le script correspondant directement SUR la"
echo "machine, avec un accès shell -- ce scan public ne sert qu'à prioriser quoi auditer."
