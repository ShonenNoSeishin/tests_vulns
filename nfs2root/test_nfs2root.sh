#!/usr/bin/env bash
# test_nfs2root.sh — script UNIQUE et autonome (n'appelle aucun autre fichier) qui audite UNE
# machine Linux pour CVE-2026-99362 ("nfs2root") : heap overflow dans le code nfsd (serveur NFS)
# du noyau Linux, déclenchable SANS authentification par un client NFSv4.1 malveillant contre un
# serveur NFS exposé. Voir README.md pour l'explication complète.
#
# Déploiement : copier CE SEUL FICHIER sur la machine à auditer, puis :
#   chmod +x test_nfs2root.sh
#   ./test_nfs2root.sh          # vérifie le noyau de CETTE machine (hôte OU VM OU conteneur LXC)
#
# -------------------------------------------------------------------------------------------
# IMPORTANT — portée de ce script, même logique que cve-2026-98432 :
#   Cette faille est dans le NOYAU, pas dans une application. Un conteneur Docker/Podman/LXC
#   PARTAGE le noyau de son hôte : il n'a PAS sa propre version de noyau. Une VM (QEMU/KVM, donc
#   une VM Proxmox) a en revanche SON PROPRE noyau indépendant : il faut lancer ce script
#   SÉPARÉMENT à l'intérieur de chaque VM Linux, en plus de l'hôte Proxmox lui-même.
#   -> Ce script ne regarde donc QUE le noyau de la machine sur laquelle il tourne.
#
#   DIFFÉRENCE avec cve-2026-98432 : cette faille n'est exploitable À DISTANCE que si le code
#   nfsd (serveur NFS) est RÉELLEMENT actif et accessible sur le réseau (port 2049 par défaut).
#   Le paquet noyau peut être vulnérable sans que la machine serve activement du NFS — ce script
#   vérifie donc LES DEUX : la version du noyau (toujours à corriger, par principe de précaution
#   et car la mise à jour est gratuite) ET l'exposition réelle de nfsd (qui détermine l'URGENCE).
#   Une machine qui ne fait que MONTER un partage NFS (client) n'est PAS exposée par ce vecteur.
# -------------------------------------------------------------------------------------------
set -u
export LC_ALL=C

for a in "$@"; do
  case "$a" in
    -h|--help)
      echo "Usage: $0"
      echo "  Vérifie le noyau ET l'exposition nfsd de LA machine sur laquelle ce script tourne."
      exit 0
      ;;
  esac
done

section() { printf '\n===== %s =====\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }
report() { printf '  %-30s %s\n' "$1" "$2"; }

FINDINGS=()
VULN_COUNT=0
UNK_COUNT=0
OK_COUNT=0

add_finding() { FINDINGS+=("$1"); }

printf 'CVE-2026-99362 ("nfs2root", noyau Linux, nfsd, heap overflow) — inventaire local\nDate : %s\nHôte : %s\n' \
  "$(date -Is 2>/dev/null || date)" "$(hostname -f 2>/dev/null || hostname)"

# ============================================================
section "0. Prérequis"
# ============================================================
HAVE_DPKGQ=0;   have dpkg-query    && HAVE_DPKGQ=1
HAVE_DPKG=0;    have dpkg          && HAVE_DPKG=1
HAVE_RPM=0;     have rpm           && HAVE_RPM=1
HAVE_SYSTEMCTL=0; have systemctl   && HAVE_SYSTEMCTL=1
HAVE_SS=0;      have ss            && HAVE_SS=1
HAVE_LSMOD=0;   have lsmod         && HAVE_LSMOD=1
HAVE_RPCINFO=0; have rpcinfo       && HAVE_RPCINFO=1

report "dpkg/dpkg-query" "$([[ $HAVE_DPKGQ -eq 1 ]] && echo disponible || echo 'absent -> pas de comparaison de paquet Debian/Ubuntu/Proxmox possible')"
report "rpm"             "$([[ $HAVE_RPM -eq 1 ]] && echo disponible || echo 'absent -> pas de comparaison de paquet RHEL/SUSE possible')"
report "systemctl"       "$([[ $HAVE_SYSTEMCTL -eq 1 ]] && echo disponible || echo 'absent -> statut du service nfs-kernel-server non vérifiable par ce biais')"
report "ss"              "$([[ $HAVE_SS -eq 1 ]] && echo disponible || echo 'absent -> port 2049 non vérifiable par ce biais')"
report "lsmod"           "$([[ $HAVE_LSMOD -eq 1 ]] && echo disponible || echo 'absent -> module noyau nfsd non vérifiable par ce biais')"
report "rpcinfo"         "$([[ $HAVE_RPCINFO -eq 1 ]] && echo disponible || echo 'absent -> registre portmapper non vérifiable par ce biais')"

if [[ "$(uname -s 2>/dev/null)" != "Linux" ]]; then
  echo
  echo "[NON CONCERNÉ] Ce script tourne sur un système non-Linux ($(uname -s 2>/dev/null)) : CVE-2026-99362"
  echo "               est une faille du code nfsd du noyau LINUX, elle ne concerne pas macOS (XNU)"
  echo "               ni Windows (NT) nativement — Windows a sa propre implémentation \"Server for"
  echo "               NFS\", totalement indépendante, non couverte par ce CVE. Si cette machine"
  echo "               Windows exécute WSL2, utilisez Test-Nfs2Root.ps1 pour vérifier WSL2 séparément."
  echo
  echo "Confiance : COMPLÈTE — ce script couvre uniquement le noyau Linux, non applicable ici."
  exit 0
fi

# ============================================================
section "1. Identification OS / distribution"
# ============================================================
DISTRO_ID=""
DISTRO_VERSION=""
DISTRO_CODENAME=""
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
  DISTRO_ID="${ID:-}"
  DISTRO_VERSION="${VERSION_ID:-}"
  DISTRO_CODENAME="${VERSION_CODENAME:-}"
  report "PRETTY_NAME" "${PRETTY_NAME:-inconnu}"
else
  echo "[À VÉRIFIER] /etc/os-release absent : distribution non identifiable automatiquement."
fi

IS_PROXMOX=0
if have pveversion || { [[ $HAVE_DPKGQ -eq 1 ]] && dpkg-query -W -f='${Status}' pve-manager 2>/dev/null | grep -q '^install ok'; }; then
  IS_PROXMOX=1
  report "Proxmox VE" "détecté ($(pveversion 2>/dev/null | head -n1))"
fi

RUNNING_KERNEL="$(uname -r 2>/dev/null)"
report "Noyau en cours d'exécution (uname -r)" "$RUNNING_KERNEL"

# ============================================================
section "2. Paquet noyau réellement installé pour ce noyau"
# ============================================================
KERNEL_PKG=""
KERNEL_PKG_VERSION=""
if [[ "$HAVE_DPKGQ" -eq 1 ]]; then
  if [[ -e "/boot/vmlinuz-$RUNNING_KERNEL" ]]; then
    KERNEL_PKG="$(dpkg-query -S "/boot/vmlinuz-$RUNNING_KERNEL" 2>/dev/null | head -n1 | cut -d: -f1)"
  fi
  if [[ -z "$KERNEL_PKG" ]]; then
    KERNEL_PKG="$(dpkg-query -W -f='${Package}\n' 'linux-image-*' 'proxmox-kernel-*' 2>/dev/null | grep -F "$RUNNING_KERNEL" | head -n1)"
  fi
  if [[ -n "$KERNEL_PKG" ]]; then
    KERNEL_PKG_VERSION="$(dpkg-query -W -f='${Version}' "$KERNEL_PKG" 2>/dev/null)"
    report "Paquet noyau" "$KERNEL_PKG = $KERNEL_PKG_VERSION"
  else
    echo "[À VÉRIFIER] Impossible d'identifier le paquet dpkg correspondant au noyau en cours d'exécution."
  fi
elif [[ "$HAVE_RPM" -eq 1 ]]; then
  KERNEL_PKG="kernel"
  KERNEL_PKG_VERSION="$(rpm -q --qf '%{VERSION}-%{RELEASE}' kernel 2>/dev/null || true)"
  report "Paquet noyau (rpm)" "$KERNEL_PKG_VERSION"
fi

# ============================================================
section "3. Exposition réelle du service nfsd (information sur l'URGENCE, PAS un critère d'exclusion)"
# ============================================================
echo "[INFO] Cette faille n'est exploitable À DISTANCE que si un serveur NFS (nfsd) tourne et est"
echo "       accessible sur le réseau (port 2049 par défaut). Une machine qui ne fait que MONTER"
echo "       un partage NFS (client) n'est pas exposée par ce vecteur précis. Le paquet noyau reste"
echo "       néanmoins à corriger dans tous les cas (le correctif est gratuit et sans risque)."

NFSD_ACTIVE_SVC=""
if [[ "$HAVE_SYSTEMCTL" -eq 1 ]]; then
  for svc in nfs-kernel-server nfs-server; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      NFSD_ACTIVE_SVC="$svc"
      break
    fi
  done
fi
report "Service nfs-kernel-server/nfs-server" "$([[ -n "$NFSD_ACTIVE_SVC" ]] && echo "ACTIF ($NFSD_ACTIVE_SVC)" || echo "inactif ou absent")"

MODULE_LOADED=0
if [[ "$HAVE_LSMOD" -eq 1 ]] && lsmod 2>/dev/null | grep -qw '^nfsd'; then
  MODULE_LOADED=1
fi
report "Module noyau nfsd chargé" "$([[ "$MODULE_LOADED" -eq 1 ]] && echo oui || echo non)"

PORT_LISTEN=0
if [[ "$HAVE_SS" -eq 1 ]]; then
  if ss -tln 2>/dev/null | grep -Eq ':2049[[:space:]]'; then
    PORT_LISTEN=1
  fi
fi
report "Port 2049/tcp en écoute" "$([[ "$PORT_LISTEN" -eq 1 ]] && echo oui || echo non)"

EXPORTS_CONFIGURED=0
EXPORTS_CONTENT=""
if [[ -r /etc/exports ]]; then
  EXPORTS_CONTENT="$(grep -Ev '^\s*#|^\s*$' /etc/exports 2>/dev/null || true)"
  [[ -n "$EXPORTS_CONTENT" ]] && EXPORTS_CONFIGURED=1
fi
report "/etc/exports non vide" "$([[ "$EXPORTS_CONFIGURED" -eq 1 ]] && echo oui || echo 'non (ou absent)')"

RPC_NFS=0
if [[ "$HAVE_RPCINFO" -eq 1 ]] && rpcinfo -p 2>/dev/null | grep -qw nfs; then
  RPC_NFS=1
fi
report "nfsd enregistré au portmapper (rpcinfo)" "$([[ "$RPC_NFS" -eq 1 ]] && echo oui || echo 'non (ou rpcinfo indisponible/sans réponse)')"

NFSD_EXPOSED=0
if [[ -n "$NFSD_ACTIVE_SVC" || "$MODULE_LOADED" -eq 1 || "$PORT_LISTEN" -eq 1 || "$EXPORTS_CONFIGURED" -eq 1 || "$RPC_NFS" -eq 1 ]]; then
  NFSD_EXPOSED=1
fi

if [[ "$NFSD_EXPOSED" -eq 1 ]]; then
  echo "[URGENT] Au moins un signe de serveur NFS actif/configuré détecté sur cette machine — si le"
  echo "         noyau n'est pas corrigé (voir section 4), traiter en priorité haute : service"
  echo "         directement exposé au réseau sans authentification."
else
  echo "[INFO] Aucun signe de serveur NFS actif détecté (service inactif, pas de module chargé, pas"
  echo "       de port 2049 en écoute, /etc/exports vide ou absent). Risque d'exploitation À"
  echo "       DISTANCE réduit sur cette machine précise, mais le noyau reste à corriger (principe"
  echo "       de précaution — ne jamais compter sur une configuration qui pourrait changer)."
fi

# ============================================================
section "4. Comparaison à la version corrigée"
# ============================================================
# Table des versions CORRIGÉES CONFIRMÉES — vérifiée par fetch direct le 27/11/2026.
#  - Proxmox VE : PSA-2026-00103-1 (forum officiel), deux branches noyau distinctes.
#  - Debian : security-tracker.debian.org/tracker/CVE-2026-99362. Bookworm a DEUX noyaux possibles
#    (le noyau principal 6.1.x, et le noyau de secours "linux-6.12" disponible via
#    bookworm-backports) — chacun son propre seuil de correctif.
#  - Ubuntu : AUCUN correctif stable publié à ce jour (27/11/2026) sur AUCUNE branche, y compris
#    26.04/26.10 ("work in progress" selon ubuntu.com/security/CVE-2026-99362) — ne jamais
#    inventer un seuil ici, le script doit renvoyer [VULNÉRABLE] inconditionnellement pour Ubuntu
#    tant que ce statut n'a pas changé (revérifier la source avant de modifier cette table).

declare -A PROXMOX_FIXED=(
  [7.0]="7.0.14-30-pve"   # branche par défaut
  [7.3]="7.3.3-1-pve"     # branche opt-in
)
DEBIAN_BOOKWORM_MAIN_FIXED="6.1.192-3"            # bookworm, noyau principal (paquet linux-image-6.1.*)
DEBIAN_BOOKWORM_BACKPORTS_FIXED="6.12.117-1~deb12u1"  # bookworm, noyau de secours linux-6.12 (bookworm-backports)
DEBIAN_TRIXIE_FIXED="6.12.117-1"                  # trixie — une révision ultérieure 6.12.118-1 existe aussi, >= au seuil

verdict_pkg_ge() {
  [[ "$HAVE_DPKG" -eq 1 ]] || return 2
  dpkg --compare-versions "$1" ge "$2"
}

if [[ "$IS_PROXMOX" -eq 1 ]]; then
  echo "-- Hôte Proxmox VE détecté : comparaison au paquet proxmox-kernel --"
  if [[ -n "$KERNEL_PKG_VERSION" ]]; then
    BRANCH="$(printf '%s' "$KERNEL_PKG_VERSION" | grep -oE '^[0-9]+\.[0-9]+' || true)"
    FIXED="${PROXMOX_FIXED[$BRANCH]:-}"
    if [[ -z "$FIXED" ]]; then
      UNK_COUNT=$((UNK_COUNT+1))
      add_finding "[À VÉRIFIER] Branche de noyau Proxmox '$BRANCH' (paquet $KERNEL_PKG_VERSION) non référencée dans ce script (seules 7.0 et 7.3 sont connues au 27/11/2026) — vérifier manuellement https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/"
    elif verdict_pkg_ge "$KERNEL_PKG_VERSION" "$FIXED"; then
      OK_COUNT=$((OK_COUNT+1))
      add_finding "[OK] proxmox-kernel en cours d'exécution ($KERNEL_PKG_VERSION, branche $BRANCH) >= $FIXED (corrigé, PSA-2026-00103-1)."
    else
      VULN_COUNT=$((VULN_COUNT+1))
      add_finding "[VULNÉRABLE] proxmox-kernel en cours d'exécution ($KERNEL_PKG_VERSION, branche $BRANCH) < $FIXED (corrigé, PSA-2026-00103-1). Mettre à jour puis redémarrer le nœud."
    fi
    LATEST_PVE_KERNEL="$(dpkg-query -W -f='${Package} ${Version}\n' 'proxmox-kernel-*' 2>/dev/null | sort -k2 -V | tail -n1)"
    LATEST_PVE_VER="${LATEST_PVE_KERNEL##* }"
    LATEST_BRANCH="$(printf '%s' "$LATEST_PVE_VER" | grep -oE '^[0-9]+\.[0-9]+' || true)"
    LATEST_FIXED="${PROXMOX_FIXED[$LATEST_BRANCH]:-}"
    if [[ -n "$LATEST_PVE_VER" && -n "$LATEST_FIXED" ]] && verdict_pkg_ge "$LATEST_PVE_VER" "$LATEST_FIXED" && ! verdict_pkg_ge "$KERNEL_PKG_VERSION" "${FIXED:-99999}"; then
      UNK_COUNT=$((UNK_COUNT+1))
      add_finding "[À VÉRIFIER] Un paquet proxmox-kernel corrigé ($LATEST_PVE_VER) est installé mais le noyau EN COURS D'EXÉCUTION est encore l'ancien ($KERNEL_PKG_VERSION) -> redémarrage du nœud requis pour appliquer le correctif."
    fi
  else
    UNK_COUNT=$((UNK_COUNT+1))
    add_finding "[À VÉRIFIER] Proxmox détecté mais version de paquet noyau non lisible — vérifier manuellement : dpkg -l 'proxmox-kernel-*'"
  fi

elif [[ "$DISTRO_ID" == "debian" ]]; then
  echo "-- Debian $DISTRO_VERSION ($DISTRO_CODENAME) détecté --"
  if [[ -z "$KERNEL_PKG_VERSION" ]]; then
    UNK_COUNT=$((UNK_COUNT+1))
    add_finding "[À VÉRIFIER] Debian $DISTRO_VERSION détecté mais version de paquet noyau non lisible."
  elif [[ "$DISTRO_CODENAME" == "trixie" || "$DISTRO_VERSION" == "13" ]]; then
    FIXED="$DEBIAN_TRIXIE_FIXED"
    if verdict_pkg_ge "$KERNEL_PKG_VERSION" "$FIXED"; then
      OK_COUNT=$((OK_COUNT+1))
      add_finding "[OK] Noyau Debian 13 (trixie) en cours d'exécution ($KERNEL_PKG_VERSION) >= $FIXED (corrigé)."
    else
      VULN_COUNT=$((VULN_COUNT+1))
      add_finding "[VULNÉRABLE] Noyau Debian 13 (trixie) en cours d'exécution ($KERNEL_PKG_VERSION) < $FIXED (corrigé). apt update && apt upgrade puis redémarrer."
    fi
  elif [[ "$DISTRO_CODENAME" == "bookworm" || "$DISTRO_VERSION" == "12" ]]; then
    # Bookworm a deux noyaux possibles : le principal (6.1.x) et le noyau de secours
    # "linux-6.12" (bookworm-backports) -- seuils différents, à ne pas confondre.
    case "$KERNEL_PKG_VERSION" in
      6.12.*)
        FIXED="$DEBIAN_BOOKWORM_BACKPORTS_FIXED"
        KERNEL_LABEL="bookworm, noyau de secours linux-6.12 (backports)"
        ;;
      *)
        FIXED="$DEBIAN_BOOKWORM_MAIN_FIXED"
        KERNEL_LABEL="bookworm, noyau principal"
        ;;
    esac
    if verdict_pkg_ge "$KERNEL_PKG_VERSION" "$FIXED"; then
      OK_COUNT=$((OK_COUNT+1))
      add_finding "[OK] Noyau Debian 12 ($KERNEL_LABEL) en cours d'exécution ($KERNEL_PKG_VERSION) >= $FIXED (corrigé)."
    else
      VULN_COUNT=$((VULN_COUNT+1))
      add_finding "[VULNÉRABLE] Noyau Debian 12 ($KERNEL_LABEL) en cours d'exécution ($KERNEL_PKG_VERSION) < $FIXED (corrigé). apt update && apt upgrade puis redémarrer."
    fi
  else
    UNK_COUNT=$((UNK_COUNT+1))
    add_finding "[À VÉRIFIER] Debian $DISTRO_VERSION ($DISTRO_CODENAME) non référencé avec certitude dans ce script (seuls bookworm/12 et trixie/13 sont connus) — vérifier https://security-tracker.debian.org/tracker/CVE-2026-99362"
  fi

elif [[ "$DISTRO_ID" == "ubuntu" ]]; then
  echo "-- Ubuntu $DISTRO_VERSION détecté --"
  echo "[IMPORTANT] Aucun correctif stable n'est publié par Canonical à ce jour (vérifié par fetch"
  echo "            direct de ubuntu.com/security/CVE-2026-99362 le 27/11/2026) — TOUTES les"
  echo "            branches sont listées 'Vulnerable', y compris 26.04/26.10 ('work in progress')."
  echo "            Un 'apt update && apt upgrade' qui répond 'already the newest version' ne"
  echo "            prouve PAS que c'est corrigé ici : il n'existe simplement rien à installer."
  VULN_COUNT=$((VULN_COUNT+1))
  add_finding "[VULNÉRABLE] Ubuntu $DISTRO_VERSION : aucun correctif stable disponible à ce jour pour CVE-2026-99362 (toutes branches). Paquet noyau actuel : ${KERNEL_PKG_VERSION:-inconnu}. En attendant un correctif : si nfsd n'est pas nécessaire, le désactiver/désinstaller, ou restreindre l'accès réseau au port 2049 (pare-feu) aux seuls clients NFS de confiance."
  report "Paquet noyau installé (référence)" "${KERNEL_PKG_VERSION:-inconnu}"

elif [[ "$HAVE_RPM" -eq 1 ]]; then
  echo "-- Distribution RPM (RHEL/CentOS/Rocky/Alma/SUSE/Fedora) détectée --"
  UNK_COUNT=$((UNK_COUNT+1))
  add_finding "[À VÉRIFIER] Distribution RPM : ce script ne connaît pas de version corrigée fiable pour cette famille — vérifier l'erratum du fournisseur (Red Hat/SUSE/etc.) pour CVE-2026-99362. Paquet noyau actuel : ${KERNEL_PKG_VERSION:-inconnu}"

else
  UNK_COUNT=$((UNK_COUNT+1))
  add_finding "[À VÉRIFIER] Distribution Linux non reconnue par ce script (ni Debian/Ubuntu/Proxmox/RPM) — vérifier manuellement la version du noyau ($RUNNING_KERNEL) auprès du fournisseur."
fi

# ============================================================
section "5. Conclusion"
# ============================================================
printf '%s\n' "${FINDINGS[@]:-}" | sed '/^$/d'
echo
echo "[RAPPEL] Un conteneur Docker/Podman/LXC partage le noyau de son hôte : il n'y a rien à"
echo "         sonder par conteneur pour cette faille. Une VM a son propre noyau : relancer ce"
echo "         script À L'INTÉRIEUR de chaque VM Linux séparément."
echo "[RAPPEL] NFS-Ganesha (serveur NFS en espace utilisateur, parfois utilisé pour exporter"
echo "         CephFS) réimplémente le protocole NFS indépendamment du code noyau nfsd visé par"
echo "         ce CVE précis — non concerné par cette faille (déduction technique, aucun avis Ceph"
echo "         contraire trouvé à ce jour, à reconfirmer si un avis officiel paraît)."

if [[ "$VULN_COUNT" -gt 0 ]]; then
  VERDICT="VULNÉRABLE"
elif [[ "$UNK_COUNT" -gt 0 ]]; then
  VERDICT="À VÉRIFIER"
elif [[ "$OK_COUNT" -gt 0 ]]; then
  VERDICT="OK"
else
  VERDICT="NON CONCERNÉ"
fi

echo
case "$VERDICT" in
  VULNÉRABLE)
    if [[ "$NFSD_EXPOSED" -eq 1 ]]; then
      echo "Confiance : élément vulnérable CONFIRMÉ, ET un service NFS semble actif sur cette machine -- URGENT."
    else
      echo "Confiance : élément vulnérable CONFIRMÉ (nfsd non détecté comme actif actuellement, mais à corriger quand même)."
    fi
    ;;
  "À VÉRIFIER")
    echo "Confiance : INCOMPLÈTE — au moins un élément nécessite une vérification manuelle avant de pouvoir conclure." ;;
  OK)
    echo "Confiance : COMPLÈTE pour CE noyau — mais relancer séparément dans chaque VM Linux du parc." ;;
  *)
    echo "Confiance : COMPLÈTE — rien à signaler pour cette machine." ;;
esac
echo "Références : https://forum.proxmox.com/threads/proxmox-virtual-environment-security-advisories.149331/ | https://ubuntu.com/security/CVE-2026-99362 | https://security-tracker.debian.org/tracker/CVE-2026-99362"

case "$VERDICT" in
  VULNÉRABLE) exit 2 ;;
  "À VÉRIFIER") exit 1 ;;
  *) exit 0 ;;
esac
