<#
.SYNOPSIS
  Test-Nfs2Root.ps1 — script UNIQUE et autonome qui vérifie si CETTE machine Windows est
  concernée par CVE-2026-99362 ("nfs2root", heap overflow dans le code nfsd du NOYAU LINUX).

.DESCRIPTION
  CVE-2026-99362 est une faille du noyau LINUX (code nfsd, serveur NFS). Windows (NT) n'est PAS
  affecté nativement : le rôle Windows natif "Server for NFS" (File and Storage Services) est
  une implémentation totalement indépendante, écrite par Microsoft, qui ne partage AUCUN code
  avec le nfsd du noyau Linux visé par ce CVE — ce rôle n'est donc PAS concerné non plus.

  Le seul cas où une machine Windows peut être concernée est **WSL2** (Windows Subsystem for
  Linux v2), qui exécute un véritable noyau Linux, maintenu séparément par Microsoft (canal
  `wsl --update`, indépendant de Windows Update classique) — ET seulement si ce WSL2 fait
  tourner un serveur NFS (`nfs-kernel-server`) exposé, ce qui est rare en pratique.

  Ce script :
    1. Vérifie si WSL2 est installé/activé.
    2. Si oui, relève la version du noyau WSL2 et indique comment la comparer au correctif
       Microsoft (pas de numéro figé ici : Microsoft publie ses propres builds WSL2, à vérifier
       au moment de l'exécution — voir README.md).
    3. Sinon, conclut "NON CONCERNÉ".

  Déploiement : copier CE SEUL FICHIER sur la machine, puis :
    .\Test-Nfs2Root.ps1
#>

[CmdletBinding()]
param()

function Write-Section([string]$Title) {
  Write-Host ""
  Write-Host "===== $Title =====" -ForegroundColor Cyan
}

function Write-Report([string]$Label, [string]$Value) {
  Write-Host ("  {0,-30} {1}" -f $Label, $Value)
}

Write-Host "CVE-2026-99362 (`"nfs2root`", noyau Linux, nfsd, heap overflow) — inventaire local (Windows)"
Write-Host "Date : $(Get-Date -Format o)"
Write-Host "Hôte : $($env:COMPUTERNAME)"

Write-Section "0. Prérequis"
$HAVE_WSL = $null -ne (Get-Command wsl.exe -ErrorAction SilentlyContinue)
Write-Report "wsl.exe" ($(if ($HAVE_WSL) { "disponible" } else { "absent -> pas de WSL2 installé sur cette machine" }))

Write-Section "1. Rôle Windows Server concerné (information)"
Write-Host "[INFO] Cette faille ne touche pas le noyau Windows (NT) : AD, SQL Server, RDS/TS ne"
Write-Host "       sont PAS exposés par ce CVE sur une install Windows Server standard."
Write-Host "[INFO] Le rôle Windows natif `"Server for NFS`" (File and Storage Services), s'il est"
Write-Host "       installé, N'EST PAS concerné non plus : c'est une implémentation Microsoft"
Write-Host "       indépendante, sans rapport avec le code nfsd du noyau Linux visé par ce CVE."

$Verdict = "NON_CONCERNE"
$Findings = @()

Write-Section "2. WSL2 (Windows Subsystem for Linux v2)"
if ($HAVE_WSL) {
  try {
    $wslVersionOutput = & wsl.exe --version 2>&1 | Out-String
  } catch {
    $wslVersionOutput = ""
  }
  $kernelLine = ($wslVersionOutput -split "`n") | Where-Object { $_ -match "(?i)noyau|kernel" } | Select-Object -First 1
  if ($kernelLine) {
    Write-Report "Version noyau WSL2" ($kernelLine.Trim())
  } else {
    Write-Host "[À VÉRIFIER] WSL2 détecté mais version du noyau non lisible dans la sortie de 'wsl --version'."
  }

  Write-Host ""
  Write-Host "[INFO] Cette faille n'est exploitable À DISTANCE que si un serveur NFS (nfsd) tourne"
  Write-Host "       dans cette distribution WSL2 ET est accessible sur le réseau (port 2049)."
  Write-Host "       Vérifier manuellement dans le shell WSL2 (lecture seule) :"
  Write-Host "         systemctl is-active nfs-kernel-server   # ou : service nfs-kernel-server status"
  Write-Host "         ss -tln | grep ':2049'"
  Write-Host "       Si ni l'un ni l'autre ne montre un service actif, WSL2 n'agit pas comme serveur"
  Write-Host "       NFS et n'est pas exposé par ce vecteur précis (mais le noyau reste à corriger)."

  $Findings += "[À VÉRIFIER] WSL2 actif, noyau : $(if ($kernelLine) { $kernelLine.Trim() } else { 'version non lisible automatiquement' }). Comparer manuellement à la dernière version publiée par Microsoft (https://github.com/microsoft/WSL2-Linux-Kernel/releases) pour CVE-2026-99362, puis lancer 'wsl --update' si besoin. Vérifier aussi si un serveur NFS tourne réellement dans cette distribution (voir ci-dessus) avant de prioriser."
  $Verdict = "A_VERIFIER"

  Write-Host ""
  Write-Host "Action recommandée :"
  Write-Host "    wsl --update"
  Write-Host "    wsl --shutdown   # puis relancer WSL2 pour charger le nouveau noyau"
} else {
  Write-Host "[NON CONCERNÉ] WSL2 non installé/non activé sur cette machine."
}

Write-Section "3. Conclusion"
if ($Findings.Count -gt 0) { $Findings | ForEach-Object { Write-Host $_ } }
Write-Host ""

switch ($Verdict) {
  "A_VERIFIER" {
    Write-Host "Confiance : INCOMPLÈTE — WSL2 est présent, son noyau Linux et l'usage NFS éventuel doivent être vérifiés manuellement (voir ci-dessus)."
    exit 1
  }
  default {
    Write-Host "Confiance : COMPLÈTE — machine Windows sans WSL2 actif, non concernée par cette faille du noyau Linux (le rôle natif `"Server for NFS`" n'est pas non plus concerné, voir section 1)."
    exit 0
  }
}
