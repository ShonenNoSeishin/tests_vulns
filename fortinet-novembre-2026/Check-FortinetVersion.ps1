<#
 Check-FortinetVersion.ps1 — compare la version d'un FortiManager/FortiAnalyzer, d'une FortiAnalyzer-BigData
 ou d'un FortiOS aux versions corrigées des avis Fortinet du lot de novembre 2026 :
   FG-IR-26-275 (FortiManager/FortiAnalyzer, FGFM, exécution de code sans authentification)
   FG-IR-26-219 (FortiManager/FortiAnalyzer/FortiAnalyzer-BigData, injection JSON API JRPC, CVE-2026-126170)
   FG-IR-26-267 (FortiOS, OSPF, contournement d'authentification)
 Aucune connexion réseau, rien n'est modifié : simple comparaison de numéros de version (ceux que
 VOUS donnez, lus dans l'interface ou `get system status`).
 Usage : .\Check-FortinetVersion.ps1 -Product fortimanager -Version 7.4.5
         .\Check-FortinetVersion.ps1 -Product fortianalyzer-bigdata -Version 7.6.2
         .\Check-FortinetVersion.ps1 -Product fortios -Version 7.6.7
 Codes de sortie : 0 corrigé pour tous les avis applicables, 1 au moins un à vérifier, 2 vulnérable à au moins un avis.
#>
param(
  [Parameter(Mandatory)][ValidateSet('fortios', 'fortimanager', 'fortianalyzer-bigdata')][string]$Product,
  [Parameter(Mandatory)][string]$Version
)
if ($Version -notmatch '^\d+\.\d+\.\d+$') { Write-Host "[À VÉRIFIER] version illisible : '$Version'"; exit 1 }
$branch = ($Version -split '\.')[0..1] -join '.'
$Worst = 0  # 0 = corrigé partout, 1 = au moins un à vérifier, 2 = vulnérable à au moins un avis

function Test-OneAdvisory {
  # $Fixed : version corrigée, ou $null (branche non listée -> à vérifier), ou 'na' (branche non concernée par cet avis).
  param([string]$Adv, [string]$Desc, [string]$Fixed, [string]$Note = '')
  if ($Fixed -eq 'na') {
    Write-Host "  [NON CONCERNÉ] $Adv ($Desc) : branche $branch non affectée par cet avis"
    return
  }
  if (-not $Fixed) {
    Write-Host "  [À VÉRIFIER] $Adv ($Desc) : branche $branch non listée — https://www.fortiguard.com/psirt/$Adv"
    if ($script:Worst -lt 1) { $script:Worst = 1 }
    return
  }
  if ([version]$Version -lt [version]$Fixed) {
    Write-Host "  [VULNÉRABLE] $Adv ($Desc) : $Version < $Fixed$Note"
    $script:Worst = 2
  } else {
    Write-Host "  [CORRIGÉ] $Adv ($Desc) : $Version >= $Fixed pour cet avis"
  }
}

Write-Host "Produit : $Product   Version : $Version"
switch ($Product) {
  'fortimanager' {
    $table275 = @{ '8.0' = '8.0.1'; '7.6' = '7.6.8'; '7.4' = '7.4.6'; '7.2' = '7.2.9' }
    Test-OneAdvisory 'FG-IR-26-275' 'FGFM, exécution de code sans authentification' $table275[$branch]
    switch ($branch) {
      '8.0' { Test-OneAdvisory 'FG-IR-26-219' 'injection JSON API JRPC, CVE-2026-126170' '8.0.3' ' (correctif annoncé mais PAS ENCORE PUBLIÉ au 19/11/2026 pour la branche 8.0 -- vérifier sa disponibilité, appliquer "rpc-permit none" en attendant, voir README)' }
      '7.6' { Test-OneAdvisory 'FG-IR-26-219' 'injection JSON API JRPC, CVE-2026-126170' '7.6.8' }
      { $_ -in '7.4', '7.2' } { Test-OneAdvisory 'FG-IR-26-219' 'injection JSON API JRPC, CVE-2026-126170' 'na' }
      default { Test-OneAdvisory 'FG-IR-26-219' 'injection JSON API JRPC, CVE-2026-126170' $null }
    }
  }
  'fortianalyzer-bigdata' {
    switch ($branch) {
      '7.6' { Test-OneAdvisory 'FG-IR-26-219' 'injection JSON API JRPC, CVE-2026-126170 (BigData)' '7.6.3' }
      { $_ -in '7.4', '7.2' } { Test-OneAdvisory 'FG-IR-26-219' 'injection JSON API JRPC, CVE-2026-126170 (BigData)' 'na' }
      default { Test-OneAdvisory 'FG-IR-26-219' 'injection JSON API JRPC, CVE-2026-126170 (BigData)' $null }
    }
  }
  'fortios' {
    if ($branch -eq '7.0') {
      Write-Host "  [VULNÉRABLE] FG-IR-26-267 (OSPF, contournement d'authentification) : branche 7.0, aucun correctif, migrer vers une branche corrigée (7.2.14 / 7.4.13 / 7.6.8 / 8.0.2)"
      $Worst = 2
    } else {
      $table267 = @{ '8.0' = '8.0.2'; '7.6' = '7.6.8'; '7.4' = '7.4.13'; '7.2' = '7.2.14' }
      Test-OneAdvisory 'FG-IR-26-267' "OSPF, contournement d'authentification" $table267[$branch]
    }
  }
}

switch ($Worst) {
  2 { Write-Host 'Bilan : VULNÉRABLE à au moins un avis applicable — mettre à jour en priorité (voir README).'; exit 2 }
  1 { Write-Host 'Bilan : au moins un avis À VÉRIFIER manuellement.'; exit 1 }
  default { Write-Host "Bilan : CORRIGÉ pour tous les avis applicables à cette branche (viser la dernière version de la branche : le lot de novembre en compte d'autres)."; exit 0 }
}
