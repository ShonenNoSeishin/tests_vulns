#!/usr/bin/env bash
# check_fortinet_version.sh — compare la version d'un FortiManager/FortiAnalyzer, d'une FortiAnalyzer-BigData
# ou d'un FortiOS aux versions corrigées des avis Fortinet du lot de novembre 2026 :
#   FG-IR-26-275 (FortiManager/FortiAnalyzer, FGFM, exécution de code sans authentification)
#   FG-IR-26-219 (FortiManager/FortiAnalyzer/FortiAnalyzer-BigData, injection JSON API JRPC, CVE-2026-126170)
#   FG-IR-26-267 (FortiOS, OSPF, contournement d'authentification)
# AUCUNE connexion réseau, rien n'est modifié : le script ne fait que comparer des numéros de version
# (ceux que VOUS lui donnez, lus dans l'interface ou collés depuis `get system status`).
#
# Usage :
#   ./check_fortinet_version.sh fortimanager 7.4.5
#   ./check_fortinet_version.sh fortianalyzer-bigdata 7.6.2
#   ./check_fortinet_version.sh fortios 7.6.7
#   ssh admin@pare-feu 'get system status' | ./check_fortinet_version.sh        # produit et version lus dans la sortie
#   ./check_fortinet_version.sh --file get_system_status.txt
# Codes de sortie : 0 = corrigé pour tous les avis applicables à cette branche,
#                   1 = au moins un avis "à vérifier" (branche non listée / version illisible),
#                   2 = vulnérable à au moins un avis applicable.
set -u
export LC_ALL=C

product="${1:-}"; version="${2:-}"
if [ "${1:-}" = "--file" ]; then text="$(cat "${2:?fichier manquant}")"; product=""; version=""
elif [ -z "$product" ] && [ ! -t 0 ]; then text="$(cat)"; fi
if [ -n "${text:-}" ]; then
  echo "$text" | grep -qi "fortimanager" && product="fortimanager"
  echo "$text" | grep -qi "fortianalyzer" && product="${product:-fortimanager}"
  { echo "$text" | grep -qi "fortigate\|fortiwifi\|fortios"; } && product="${product:-fortios}"
  version="$(echo "$text" | sed -n 's/.*[vV]\([0-9]\+\.[0-9]\+\.[0-9]\+\).*/\1/p' | head -n1)"
fi
case "$product" in
  fortimanager|fortianalyzer) product=fortimanager ;;
  fortianalyzer-bigdata) product=fortianalyzer-bigdata ;;
  fortios|fortigate) product=fortios ;;
  *) echo "Usage : $0 {fortios|fortimanager|fortianalyzer-bigdata} <version>   (ex. $0 fortios 7.4.12)"; exit 1 ;;
esac
case "$version" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "[À VÉRIFIER] version illisible : '$version'"; exit 1 ;; esac

branch="${version%.*}"
WORST=0  # 0 = corrigé partout, 1 = au moins un "à vérifier", 2 = vulnérable à au moins un avis

# vlt A B : vrai (0) si la version A est strictement plus ancienne que B (tri de versions numérique).
vlt() { [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]; }

# check_one adv desc fixed note : affiche le verdict pour UN avis, met à jour $WORST.
#   fixed="" -> branche non listée dans cet avis : [À VÉRIFIER]
#   fixed="na" -> branche non concernée par CET avis précis : [NON CONCERNÉ] (pas de pénalité)
check_one() {
  local adv="$1" desc="$2" fixed="$3" note="${4:-}"
  if [ "$fixed" = "na" ]; then
    printf '  [NON CONCERNÉ] %s (%s) : branche %s non affectée par cet avis\n' "$adv" "$desc" "$branch"
    return
  fi
  if [ -z "$fixed" ]; then
    printf '  [À VÉRIFIER] %s (%s) : branche %s non listée — consulter https://www.fortiguard.com/psirt/%s\n' "$adv" "$desc" "$branch" "$adv"
    [ "$WORST" -lt 1 ] && WORST=1
    return
  fi
  if vlt "$version" "$fixed"; then
    printf '  [VULNÉRABLE] %s (%s) : %s < %s%s\n' "$adv" "$desc" "$version" "$fixed" "$note"
    WORST=2
  else
    printf '  [CORRIGÉ] %s (%s) : %s >= %s pour cet avis\n' "$adv" "$desc" "$version" "$fixed"
  fi
}

echo "Produit : $product   Version : $version"
case "$product" in
  fortimanager)
    case "$branch" in 8.0) f=8.0.1 ;; 7.6) f=7.6.8 ;; 7.4) f=7.4.6 ;; 7.2) f=7.2.9 ;; *) f="" ;; esac
    check_one "FG-IR-26-275" "FGFM, exécution de code sans authentification" "$f"
    case "$branch" in
      8.0) check_one "FG-IR-26-219" "injection JSON API JRPC, CVE-2026-126170" "8.0.3" \
             " (correctif annoncé mais PAS ENCORE PUBLIÉ au 19/11/2026 pour la branche 8.0 -- vérifier sa disponibilité, appliquer le contournement \"rpc-permit none\" en attendant, voir README)" ;;
      7.6) check_one "FG-IR-26-219" "injection JSON API JRPC, CVE-2026-126170" "7.6.8" ;;
      7.4|7.2) check_one "FG-IR-26-219" "injection JSON API JRPC, CVE-2026-126170" na ;;
      *) check_one "FG-IR-26-219" "injection JSON API JRPC, CVE-2026-126170" "" ;;
    esac
    ;;
  fortianalyzer-bigdata)
    case "$branch" in
      7.6) check_one "FG-IR-26-219" "injection JSON API JRPC, CVE-2026-126170 (BigData)" "7.6.3" ;;
      7.4|7.2) check_one "FG-IR-26-219" "injection JSON API JRPC, CVE-2026-126170 (BigData)" na ;;
      *) check_one "FG-IR-26-219" "injection JSON API JRPC, CVE-2026-126170 (BigData)" "" ;;
    esac
    ;;
  fortios)
    if [ "$branch" = "7.0" ]; then
      printf '  [VULNÉRABLE] FG-IR-26-267 (OSPF, contournement d'\''authentification) : branche 7.0, aucun correctif, migrer vers une branche corrigée (7.2.14 / 7.4.13 / 7.6.8 / 8.0.2)\n'
      WORST=2
    else
      case "$branch" in 8.0) f=8.0.2 ;; 7.6) f=7.6.8 ;; 7.4) f=7.4.13 ;; 7.2) f=7.2.14 ;; *) f="" ;; esac
      check_one "FG-IR-26-267" "OSPF, contournement d'authentification" "$f"
    fi
    ;;
esac

case "$WORST" in
  2) echo "Bilan : VULNÉRABLE à au moins un avis applicable — mettre à jour en priorité (voir README)."; exit 2 ;;
  1) echo "Bilan : au moins un avis À VÉRIFIER manuellement."; exit 1 ;;
  *) echo "Bilan : CORRIGÉ pour tous les avis applicables à cette branche (viser la dernière version de la branche : le lot de novembre en compte d'autres)."; exit 0 ;;
esac
