<#
 Check-FortinetVersion.ps1 — compare la version d'un FortiManager/FortiAnalyzer ou d'un FortiOS aux versions corrigées
 de l'avis Fortinet de novembre 2026 (FG-IR-26-275 FortiManager/FGFM, FG-IR-26-267 FortiOS/OSPF).
 Aucune connexion réseau, rien n'est modifié : simple comparaison de numéros de version.
 Usage : .\Check-FortinetVersion.ps1 -Product fortimanager -Version 7.4.5
         .\Check-FortinetVersion.ps1 -Product fortios -Version 7.6.7
 Codes de sortie : 0 corrigé, 1 à vérifier, 2 vulnérable.
#>
param([Parameter(Mandatory)][ValidateSet('fortios','fortimanager')][string]$Product, [Parameter(Mandatory)][string]$Version)
if ($Version -notmatch '^\d+\.\d+\.\d+$') { Write-Host "[À VÉRIFIER] version illisible : '$Version'"; exit 1 }
$branch = ($Version -split '\.')[0..1] -join '.'
$table = if ($Product -eq 'fortimanager') { @{ '8.0'='8.0.1'; '7.6'='7.6.8'; '7.4'='7.4.6'; '7.2'='7.2.9' } }
         else { @{ '8.0'='8.0.2'; '7.6'='7.6.8'; '7.4'='7.4.13'; '7.2'='7.2.14' } }
$adv = if ($Product -eq 'fortimanager') { 'FG-IR-26-275 (FortiManager/FortiAnalyzer, FGFM)' } else { 'FG-IR-26-267 (FortiOS, OSPF)' }
Write-Host "Produit : $Product   Version : $Version   Avis : $adv"
if (-not $table.ContainsKey($branch)) {
  if ($Product -eq 'fortios' -and $branch -eq '7.0') { Write-Host '[VULNÉRABLE] branche 7.0 : aucun correctif, migrer (7.2.14 / 7.4.13 / 7.6.8 / 8.0.2)'; exit 2 }
  Write-Host "[À VÉRIFIER] branche $branch non listée : https://www.fortiguard.com/psirt"; exit 1
}
$fixed = $table[$branch]
if ([version]$Version -lt [version]$fixed) { Write-Host "[VULNÉRABLE] $Version < $fixed : mettre à jour vers $fixed ou plus récent"; exit 2 }
Write-Host "[CORRIGÉ] $Version >= $fixed pour cet avis (viser la dernière version de la branche : le lot de novembre en compte d'autres)"; exit 0
