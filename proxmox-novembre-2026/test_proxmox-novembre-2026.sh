#!/usr/bin/env bash
# test_proxmox-novembre-2026.sh — compare les paquets Perl/Rust de Proxmox VE réellement installés
# aux versions corrigées du lot d'avis de sécurité publiés les 10 et 12 novembre 2026 :
#   PSA-2026-00088-1  injection shell via le nom de volume (iSCSI/ZFS-over-iSCSI, migration)
#   PSA-2026-00100-1  citation shell manquante en gestion d'erreur d'upload (RCE root sur le nœud)
#   PSA-2026-00089-1  plusieurs problèmes dans le serveur HTTP Perl interne
#   PSA-2026-00092-1  contrôles ACL manquants/incomplets dans l'API SDN
#   PSA-2026-00093-1  injection de configuration FRR via les route maps
#   PSA-2026-00094-1  échappement de répertoire à l'extraction d'images OCI
#   PSA-2026-00095-1  contrôles de privilège cassés à la modification des cartes réseau de conteneurs
# Aucun CVE n'a été attribué à ce lot à ce jour (numérotation PSA interne Proxmox).
#
# À LANCER SUR LE NŒUD PROXMOX VE LUI-MÊME (pas dans un LXC/VM invité : ces paquets sont ceux du
# plan de gestion de l'hôte, pas des invités). LECTURE SEULE : interroge seulement dpkg, ne modifie
# et n'installe rien.
#
# Déploiement : copier CE SEUL FICHIER sur le nœud :
#   chmod +x test_proxmox-novembre-2026.sh
#   ./test_proxmox-novembre-2026.sh
# Codes de sortie : 0 = corrigé partout (ou hôte non-Proxmox, non concerné), 1 = à vérifier, 2 = vulnérable.
set -u
export LC_ALL=C

have() { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n===== %s =====\n' "$1"; }

# ---------------------------------------------------------------- 0. Prérequis
section "0. Prérequis"
printf '  utilisateur : %s\n' "$(id -un)"
if ! have dpkg-query; then
  echo "  [NON CONCERNÉ] dpkg-query absent : ceci n'est pas un système Debian/Proxmox. Rien à vérifier."
  echo "Confiance : COMPLÈTE"
  exit 0
fi
if have pveversion; then
  printf '  pveversion : %s\n' "$(pveversion 2>/dev/null | head -n1)"
else
  echo "  [ATTENTION] commande pveversion absente : ceci n'est probablement pas un nœud Proxmox VE (lancer plutôt sur l'hôte, pas dans un invité)."
fi

VULN=0; UNK=0; OK=0
FINDINGS=()

# pkg_version PAQUET -> version installée (vide si absent)
pkg_version() { dpkg-query -W -f='${Version}\n' "$1" 2>/dev/null; }

# pkg_status PAQUET MIN -> "ok" / "vuln" / "absent" SUR STDOUT (seul canal capturé par l'appelant via
# $(...)) ; le détail lisible par un humain part sur stderr pour ne jamais polluer la valeur de retour.
pkg_status() {
  local pkg="$1" min="$2" v
  v=$(pkg_version "$pkg")
  if [ -z "$v" ]; then
    printf '      %s : absent\n' "$pkg" >&2
    echo "absent"
    return
  fi
  if dpkg --compare-versions "$v" lt "$min"; then
    printf '      %s : %s (< %s)\n' "$pkg" "$v" "$min" >&2
    echo "vuln"
  else
    printf '      %s : %s (>= %s)\n' "$pkg" "$v" "$min" >&2
    echo "ok"
  fi
}

# check_psa ADV DESC PKG1 MIN1 [PKG2 MIN2 ...] -- affiche le verdict agrégé pour un avis.
check_psa() {
  local adv="$1" desc="$2"; shift 2
  local worst=ok s
  printf '  %s (%s) :\n' "$adv" "$desc"
  while [ "$#" -ge 2 ]; do
    s=$(pkg_status "$1" "$2")
    case "$s" in
      vuln) worst=vuln ;;
      absent) [ "$worst" = ok ] && worst=absent ;;
    esac
    shift 2
  done
  case "$worst" in
    vuln) printf '  [VULNÉRABLE] %s\n' "$adv"; VULN=$((VULN+1)); FINDINGS+=("$adv") ;;
    absent) printf '  [À VÉRIFIER] %s : au moins un paquet attendu est absent (installation non standard ?)\n' "$adv"; UNK=$((UNK+1)); FINDINGS+=("$adv") ;;
    ok) printf '  [CORRIGÉ] %s\n' "$adv"; OK=$((OK+1)) ;;
  esac
}

section "1. Lot d'avis Proxmox VE du 10-12/11/2026"
check_psa "PSA-2026-00088-1" "injection shell via le nom de volume" \
  libpve-storage-perl 9.1.15 libpve-guest-common-perl 6.0.7 qemu-server 9.2.15
check_psa "PSA-2026-00100-1" "citation shell manquante, upload (RCE root)" \
  libpve-storage-perl 9.1.15
check_psa "PSA-2026-00089-1" "serveur HTTP Perl interne, plusieurs problèmes" \
  libpve-http-server-perl 6.0.6
check_psa "PSA-2026-00092-1" "ACL manquants/incomplets dans l'API SDN" \
  libpve-network-api-perl 1.6.8
check_psa "PSA-2026-00093-1" "injection de configuration FRR" \
  libpve-network-perl 1.6.8 libpve-rs-perl 0.15.4
check_psa "PSA-2026-00094-1" "échappement de répertoire, extraction OCI" \
  librust-proxmox-oci-dev 0.2.2 libpve-rs-perl 0.15.4
check_psa "PSA-2026-00095-1" "contrôles de privilège cassés, cartes réseau conteneur" \
  pve-container 6.1.17

# ---------------------------------------------------------------- Bilan
section "Bilan"
printf '  vulnérables : %d | à vérifier : %d | corrigés : %d\n' "$VULN" "$UNK" "$OK"
[ "${#FINDINGS[@]}" -gt 0 ] && printf '  à traiter : %s\n' "${FINDINGS[*]}"
if [ "$VULN" -gt 0 ]; then echo "Confiance : élément vulnérable CONFIRMÉ"; exit 2; fi
if [ "$UNK" -gt 0 ]; then echo "Confiance : INCOMPLÈTE (au moins un paquet absent à vérifier à la main)"; exit 1; fi
echo "Confiance : COMPLÈTE"; exit 0
