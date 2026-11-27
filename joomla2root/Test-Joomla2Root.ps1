<#
.SYNOPSIS
  Test-Joomla2Root.ps1 -- script UNIQUE et autonome qui cherche la faille dite "Joomla2Root"
  (CVE-2026-123214, avis officiel Joomla [20261111] "Core - Missing authentication in web
  installer") : l'installeur web de Joomla reste utilisable sur un site DEJA installe tant que
  le dossier /installation existe, ce qui permet a un attaquant SANS AUTHENTIFICATION de
  reecrire configuration.php -> prise de controle complete du site. Voir README.md.

  Nuance CVSS importante (vecteur CVSS:4.0/.../AT:P/...) : l'exploitation necessite que le
  dossier /installation existe ENCORE sur le site. Ce script verifie DEUX choses separement :
  (1) la version du code Joomla, et (2) la presence du dossier /installation, a titre
  d'URGENCE uniquement -- jamais comme critere d'exclusion. Une version vulnerable reste
  [VULNERABLE] meme si /installation est absent au moment du test.

  DIFFERENCE IMPORTANTE : comme Drupal (voir drupal2root/), Joomla sous Windows natif est rare
  (pas de paquet systeme, pas de build officiel Windows) -- generalement IIS+PHP ou, plus
  souvent, un conteneur Docker Desktop (WSL2). Ce script ne verifie AUCUN binaire executable :
  Joomla est du code PHP applicatif. Toute l'analyse se fait par LECTURE de fichiers
  (libraries/src/Version.php), jamais par execution. Joomla 3.x et antérieur (fichier/
  constantes différents) ne sont pas couverts -- voir README, Limites connues.

.USAGE
  .\Test-Joomla2Root.ps1
  .\Test-Joomla2Root.ps1 -ScanImages    # + sonde aussi les images Docker Desktop locales (WSL2)

  LECTURE SEULE : rien n'est cree, modifie ni supprime sur la machine Windows elle-meme. Les
  conteneurs Docker Desktop actifs sont sondes par "docker exec" (commandes de lecture).
  -ScanImages lance un conteneur ephemere isole par image (--network none), detruit juste apres.
#>
[CmdletBinding()]
param(
  [switch]$ScanImages
)

$ErrorActionPreference = 'Continue'
$Vuln = 0; $Unk = 0; $Ok = 0; $Nc = 0
$Findings = @()

function Section($t) { Write-Host "`n===== $t =====" }

# Statut d'une version Joomla "MAJ.MIN.PAT" -> vuln / ok / unk
# Plages affectees (avis officiel Joomla [20261111], fetch direct le 27/11/2026) :
#   4.0.0 -- 5.4.10 (branche continue 4.x/5.x)  -> corrige 5.4.11
#   6.0.0 -- 6.2.0  (branche 6.x)                -> corrige 6.2.1
# Joomla 3.x et antérieur : fichier/constantes différents, non trouvés par la sonde de ce script.
function Get-JoomlaStatus([int]$Maj, [int]$Min, [int]$Pat) {
  if ($Maj -lt 4) { return 'unk' }
  $num = $Maj * 10000 + $Min * 100 + $Pat
  if ($Maj -le 5) { if ($num -le 50410) { return 'vuln' } else { return 'ok' } }
  if ($Maj -eq 6) { if ($num -le 60200) { return 'vuln' } else { return 'ok' } }
  return 'unk'
}

function Write-JoomlaVerdict([string]$Ctx, [string]$Root, [Nullable[int]]$Maj, [Nullable[int]]$Min, [Nullable[int]]$Pat, [bool]$InstPresent, [bool]$CfgPresent) {
  if ($null -eq $Maj -or $null -eq $Min -or $null -eq $Pat) {
    $script:Unk++; $script:Findings += "$Ctx : $Root"
    Write-Host "  [A VERIFIER] $Ctx : installation Joomla trouvee en $Root mais version illisible"
    Write-Host "      (constantes MAJOR_VERSION/MINOR_VERSION/PATCH_VERSION introuvables)"
    return
  }
  $note = ''
  if (-not $CfgPresent) { $note = ' (configuration.php absent -- site probablement pas encore installe, a verifier manuellement)' }
  $status = Get-JoomlaStatus $Maj $Min $Pat
  switch ($status) {
    'vuln' {
      $script:Vuln++; $script:Findings += "$Ctx : $Root"
      if ($InstPresent) {
        Write-Host "  [VULNERABLE] $Ctx : Joomla $Maj.$Min.$Pat en $Root (CVE-2026-123214) -- dossier"
        Write-Host "      /installation PRESENT : precondition d'exploitation reunie (CVSS AT:P), urgence immediate$note"
      } else {
        Write-Host "  [VULNERABLE] $Ctx : Joomla $Maj.$Min.$Pat en $Root (CVE-2026-123214) -- dossier"
        Write-Host "      /installation absent : precondition actuelle non reunie pour ce vecteur precis, mais le"
        Write-Host "      code reste vulnerable (le dossier peut etre recree par un deploiement futur)$note"
      }
    }
    'ok' {
      $script:Ok++
      if ($InstPresent) {
        Write-Host "  [CORRIGE] $Ctx : Joomla $Maj.$Min.$Pat en $Root (>= seuil corrige) -- mais dossier"
        Write-Host "      /installation encore present : a supprimer par bonne pratique de durcissement$note"
      } else {
        Write-Host "  [CORRIGE] $Ctx : Joomla $Maj.$Min.$Pat en $Root (>= seuil corrige de sa branche)$note"
      }
    }
    default {
      $script:Unk++; $script:Findings += "$Ctx : $Root"
      Write-Host "  [A VERIFIER] $Ctx : Joomla $Maj.$Min.$Pat en $Root -- numero de version non reconnu$note"
    }
  }
}

# ---------------------------------------------------------------- 0. Prerequis
Section "0. Prerequis"
Write-Host "  PowerShell : $($PSVersionTable.PSVersion)"
$HaveDocker = $false
try { docker version --format '{{.Server.Version}}' *> $null; if ($LASTEXITCODE -eq 0) { $HaveDocker = $true } } catch {}
if ($HaveDocker) { Write-Host "  Docker Desktop detecte" } else { Write-Host "  Docker Desktop non detecte (ou non demarre) : conteneurs non sondes" }

# ---------------------------------------------------------------- 1. Recherche sur disque (emplacements usuels)
Section "1. Recherche sur disque (emplacements usuels)"
# Joomla sous Windows natif est rare -- recherche bornee aux emplacements web usuels, PAS un
# scan complet de tous les disques (cout/duree). Voir README, Limites connues.
$SearchRoots = @(
  'C:\inetpub\wwwroot',
  'C:\xampp\htdocs',
  'C:\wamp64\www',
  'C:\wamp\www',
  'C:\laragon\www'
) | Where-Object { Test-Path $_ }

$FoundAny = $false
foreach ($root in $SearchRoots) {
  $hits = Get-ChildItem -Path $root -Recurse -Filter 'Version.php' -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '[\\/]libraries[\\/]src[\\/]Version\.php$' }
  foreach ($m in $hits) {
    $FoundAny = $true
    $jRoot = $m.FullName -replace '[\\/]libraries[\\/]src[\\/]Version\.php$', ''
    $content = Get-Content -LiteralPath $m.FullName -ErrorAction SilentlyContinue -Raw
    $maj = $null; $min = $null; $pat = $null
    if ($content -match 'MAJOR_VERSION\s*=\s*(\d+)') { $maj = [int]$Matches[1] }
    if ($content -match 'MINOR_VERSION\s*=\s*(\d+)') { $min = [int]$Matches[1] }
    if ($content -match 'PATCH_VERSION\s*=\s*(\d+)') { $pat = [int]$Matches[1] }
    $instPresent = Test-Path (Join-Path $jRoot 'installation')
    $cfgPresent = Test-Path (Join-Path $jRoot 'configuration.php')
    Write-JoomlaVerdict "hote ($root)" $jRoot $maj $min $pat $instPresent $cfgPresent
  }
}
if (-not $FoundAny) {
  $Nc++
  Write-Host "  [NON CONCERNE] hote : aucune installation Joomla 4/5/6 trouvee dans les emplacements usuels"
  Write-Host "      scannes ($($SearchRoots -join ', ')) -- voir README, Limites connues"
}

# ---------------------------------------------------------------- 2. Conteneurs Docker Desktop (WSL2)
if ($HaveDocker) {
  Section "2. Conteneurs Docker Desktop en cours d'execution (lecture seule)"
  $Probe = 'find / -xdev -type f -path "*/libraries/src/Version.php" 2>/dev/null | while IFS= read -r f; do root="${f%/libraries/src/Version.php}"; maj=$(grep -oE "MAJOR_VERSION[^0-9]*[0-9]+" "$f" 2>/dev/null | grep -oE "[0-9]+" | head -n1); min=$(grep -oE "MINOR_VERSION[^0-9]*[0-9]+" "$f" 2>/dev/null | grep -oE "[0-9]+" | head -n1); pat=$(grep -oE "PATCH_VERSION[^0-9]*[0-9]+" "$f" 2>/dev/null | grep -oE "[0-9]+" | head -n1); inst=0; [ -d "$root/installation" ] && inst=1; cfg=0; [ -f "$root/configuration.php" ] && cfg=1; printf "FOUND|%s|%s|%s|%s|%s|%s\n" "$root" "${maj:-}" "${min:-}" "${pat:-}" "$inst" "$cfg"; done'

  $ids = @(docker ps -q 2>$null) | Where-Object { $_ }
  if (-not $ids) { Write-Host "  aucun conteneur actif" }
  foreach ($id in $ids) {
    $name = (docker inspect -f '{{.Name}}' $id 2>$null) -replace '^/', ''
    $out = @(docker exec $id sh -c $Probe 2>$null) | Where-Object { $_ }
    $hit = $false
    foreach ($line in $out) {
      if ($line -match '^FOUND\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$') {
        $hit = $true
        $m = $Matches
        $maj = if ($m[2]) { [int]$m[2] } else { $null }
        $min = if ($m[3]) { [int]$m[3] } else { $null }
        $pat = if ($m[4]) { [int]$m[4] } else { $null }
        Write-JoomlaVerdict "conteneur $name" $m[1] $maj $min $pat ($m[5] -eq '1') ($m[6] -eq '1')
      }
    }
    if (-not $hit) {
      $Nc++
      Write-Host "  [NON CONCERNE] conteneur $name : aucune installation Joomla 4/5/6 trouvee"
    }
  }

  Section "3. Images locales (Docker Desktop)"
  if ($ScanImages) {
    $images = @(docker images --format '{{.Repository}}:{{.Tag}}' 2>$null) | Where-Object { $_ -and $_ -notmatch '<none>' } | Sort-Object -Unique
    foreach ($img in $images) {
      $out = @(docker run --rm --network none --entrypoint sh $img -c $Probe 2>$null) | Where-Object { $_ }
      if ($LASTEXITCODE -ne 0 -or -not $out) {
        Write-Host "  [IGNORE] image $img : pas de shell (image minimale probable)"
        continue
      }
      $hit = $false
      foreach ($line in $out) {
        if ($line -match '^FOUND\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$') {
          $hit = $true
          $m = $Matches
          $maj = if ($m[2]) { [int]$m[2] } else { $null }
          $min = if ($m[3]) { [int]$m[3] } else { $null }
          $pat = if ($m[4]) { [int]$m[4] } else { $null }
          Write-JoomlaVerdict "image $img" $m[1] $maj $min $pat ($m[5] -eq '1') ($m[6] -eq '1')
        }
      }
      if (-not $hit) {
        $Nc++
        Write-Host "  [NON CONCERNE] image $img : aucune installation Joomla 4/5/6 trouvee"
      }
    }
    $ImagesScanned = $true
  } else {
    Write-Host "  non sondees (relancer avec -ScanImages pour inspecter aussi les images dormantes)"
  }
}

# ---------------------------------------------------------------- Bilan
Section "Bilan"
Write-Host "  vulnerables : $Vuln | a verifier : $Unk | corriges : $Ok | non concernes : $Nc"
if ($Findings.Count -gt 0) { Write-Host "  a traiter : $($Findings -join '; ')" }

if ($Vuln -gt 0) { Write-Host "Confiance : element vulnerable CONFIRME"; exit 2 }
if ($Unk -gt 0) { Write-Host "Confiance : INCOMPLETE (au moins un element a verifier a la main)"; exit 1 }
if (-not $HaveDocker) { Write-Host "Confiance : COMPLETE (dans la limite des emplacements scannes, voir README)"; exit 0 }
if ($ImagesScanned) { Write-Host "Confiance : COMPLETE (dans la limite des emplacements scannes, voir README)"; exit 0 }
Write-Host "Confiance : PARTIELLE (images locales non sondees : relancer avec -ScanImages)"; exit 0
