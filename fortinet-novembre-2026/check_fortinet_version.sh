#!/usr/bin/env bash
# check_fortinet_version.sh — compare la version d'un FortiManager/FortiAnalyzer ou d'un FortiOS aux versions
# corrigées de l'avis Fortinet de novembre 2026 (FG-IR-26-275 FortiManager/FGFM, FG-IR-26-267 FortiOS/OSPF).
# AUCUNE connexion réseau, rien n'est modifié : le script ne fait que comparer des numéros de version.
#
# Usage :
#   ./check_fortinet_version.sh fortimanager 7.4.5
#   ./check_fortinet_version.sh fortios 7.6.7
#   ssh admin@pare-feu 'get system status' | ./check_fortinet_version.sh        # produit et version lus dans la sortie
#   ./check_fortinet_version.sh --file get_system_status.txt
# Codes de sortie : 0 = version corrigée, 1 = à vérifier (branche non listée / version illisible), 2 = vulnérable.
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
case "$product" in fortimanager|fortianalyzer) product=fortimanager ;; fortios|fortigate) product=fortios ;;
  *) echo "Usage : $0 {fortios|fortimanager} <version>   (ex. $0 fortios 7.4.12)"; exit 1 ;; esac
case "$version" in [0-9]*.[0-9]*.[0-9]*) ;; *) echo "[À VÉRIFIER] version illisible : '$version'"; exit 1 ;; esac

branch="${version%.*}"
# Versions minimales corrigées par branche (avis FortiGuard, publiés le 10/11/2026).
if [ "$product" = fortimanager ]; then
  adv="FG-IR-26-275 (FortiManager/FortiAnalyzer, FGFM, exécution de code sans authentification)"
  case "$branch" in 8.0) fixed=8.0.1 ;; 7.6) fixed=7.6.8 ;; 7.4) fixed=7.4.6 ;; 7.2) fixed=7.2.9 ;; *) fixed="" ;; esac
else
  adv="FG-IR-26-267 (FortiOS, OSPF, contournement d'authentification, réseau adjacent)"
  case "$branch" in 8.0) fixed=8.0.2 ;; 7.6) fixed=7.6.8 ;; 7.4) fixed=7.4.13 ;; 7.2) fixed=7.2.14 ;; *) fixed="" ;; esac
fi

echo "Produit : $product   Version : $version   Avis : $adv"
if [ -z "$fixed" ]; then
  if [ "$product" = fortios ] && [ "$branch" = "7.0" ]; then echo "[VULNÉRABLE] branche 7.0 : aucun correctif, migrer vers une branche corrigée (7.2.14 / 7.4.13 / 7.6.8 / 8.0.2)"; exit 2; fi
  echo "[À VÉRIFIER] branche $branch non listée dans l'avis : consulter https://www.fortiguard.com/psirt"; exit 1
fi
if [ "$version" != "$fixed" ] && [ "$(printf '%s\n%s\n' "$version" "$fixed" | sort -V | head -n1)" = "$version" ]; then
  echo "[VULNÉRABLE] $version < $fixed : mettre à jour vers $fixed ou plus récent"; exit 2
fi
echo "[CORRIGÉ] $version >= $fixed pour cet avis (le lot de novembre en compte d'autres : viser la dernière version de la branche)"; exit 0
