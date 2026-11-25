<#
.SYNOPSIS
  Test-Drupal2Root.ps1 -- script UNIQUE et autonome qui cherche la faille dite "Drupal2Root"
  (CVE-2026-132165, "Highly critical" 20/25 selon l'avis officiel Drupal SA-CORE-2026-017) :
  install.php peut, sous conditions specifiques, etre utilise pour relancer l'installeur sur un
  site Drupal deja installe -> prise de controle du site ou execution de code a distance SANS
  authentification. Exploitation active signalee par l'equipe securite Drupal elle-meme des le
  19/11/2026, et ajoutee au catalogue KEV CISA le 24/11/2026. Voir README.md.

  DIFFERENCE IMPORTANTE : Drupal sous Windows est tres rare (pas de paquet systeme, pas de build
  officiel Windows comme Apache/XAMPP) -- generalement un deploiement IIS+PHP ou, plus souvent,
  un conteneur Docker Desktop (WSL2). Ce script ne verifie AUCUN binaire executable : Drupal est
  du code PHP applicatif, pas un programme a lancer. Toute l'analyse se fait par LECTURE de
  fichiers (core/lib/Drupal.php), jamais par execution.

.USAGE
  .\Test-Drupal2Root.ps1
  .\Test-Drupal2Root.ps1 -ScanImages    # + sonde aussi les images Docker Desktop locales (WSL2)

  LECTURE SEULE : rien n'est cree, modifie ni supprime sur la machine Windows elle-meme. Les
  conteneurs Docker Desktop actifs sont sondes par "docker exec" (commandes de lecture). -ScanImages
  lance un conteneur ephemere isole par image (--network none), detruit immediatement apres.
#>
[CmdletBinding()]
param(
  [switch]$ScanImages
)

$ErrorActionPreference = 'Continue'
$Vuln = 0; $Unk = 0; $Ok = 0; $Nc = 0
$Findings = @()

function Section($t) { Write-Host "`n===== $t =====" }

# Statut d'une version Drupal "X.Y.Z" -> vuln / eol / ok / unk
# Plages affectees (avis officiel SA-CORE-2026-017, fetch direct le 25/11/2026) :
#   <10.6.22  ||  >=11.0.0 <11.3.22  ||  >=11.4.0 <11.4.13
# Drupal 11.2.x et antérieur, et 10.5.x et antérieur, sont EN FIN DE VIE (migration de branche
# necessaire, pas un simple correctif dans la meme branche). Drupal 8/9 (maj < 10) EOL depuis
# 2021/2023.
function Get-DrupalStatus([string]$v) {
  if ($v -notmatch '^(\d+)\.(\d+)\.(\d+)') { return 'unk' }
  $maj = [int]$Matches[1]; $min = [int]$Matches[2]; $pat = [int]$Matches[3]

  if ($maj -lt 10) { return 'eol' }

  if ($maj -eq 10) {
    if ($min -lt 6) { return 'eol' }
    if ($min -eq 6) { if ($pat -lt 22) { return 'vuln' } else { return 'ok' } }
    return 'unk'
  }

  if ($maj -eq 11) {
    if ($min -le 2) { return 'eol' }
    if ($min -eq 3) { if ($pat -lt 22) { return 'vuln' } else { return 'ok' } }
    if ($min -eq 4) { if ($pat -lt 13) { return 'vuln' } else { return 'ok' } }
    return 'unk'
  }

  return 'unk'
}

function Write-DrupalVerdict([string]$Ctx, [string]$Root, [string]$Ver, [string]$Note) {
  if (-not $Ver) {
    $script:Unk++; $script:Findings += "$Ctx : $Root"
    Write-Host "  [A VERIFIER] $Ctx : installation Drupal trouvee en $Root mais version illisible"
    Write-Host "      (constante VERSION introuvable dans core/lib/Drupal.php)"
    return
  }
  $status = Get-DrupalStatus $Ver
  switch ($status) {
    'vuln' {
      $script:Vuln++; $script:Findings += "$Ctx : $Root"
      Write-Host "  [VULNERABLE] $Ctx : Drupal $Ver en $Root (CVE-2026-132165, install.php ->"
      Write-Host "      prise de controle du site / RCE sans authentification, exploite activement"
      Write-Host "      selon l'avis officiel)$Note"
    }
    'eol' {
      $script:Vuln++; $script:Findings += "$Ctx : $Root"
      Write-Host "  [VULNERABLE] $Ctx : Drupal $Ver en $Root -- branche EN FIN DE VIE, ne recevra"
      Write-Host "      JAMAIS de correctif direct (CVE-2026-132165) : migration complete vers"
      Write-Host "      10.6.22+/11.3.22+/11.4.13+ necessaire$Note"
    }
    'ok' {
      $script:Ok++
      Write-Host "  [CORRIGE] $Ctx : Drupal $Ver en $Root (>= seuil corrige de sa branche)$Note"
    }
    default {
      $script:Unk++; $script:Findings += "$Ctx : $Root"
      Write-Host "  [A VERIFIER] $Ctx : Drupal $Ver en $Root -- numero de version non reconnu par ce script"
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
# Drupal sous Windows est rare (pas de build officiel, pas de paquet systeme) -- recherche
# bornee aux emplacements web usuels, PAS un scan complet de tous les disques (cout/duree).
# Si un docroot vit ailleurs (lettre de lecteur dediee, chemin applicatif maison), il ne sera
# pas trouve par defaut -- voir README, Limites connues.
$SearchRoots = @(
  'C:\inetpub\wwwroot',
  'C:\xampp\htdocs',
  'C:\wamp64\www',
  'C:\wamp\www',
  'C:\laragon\www'
) | Where-Object { Test-Path $_ }

$FoundAny = $false
foreach ($root in $SearchRoots) {
  $hits = Get-ChildItem -Path $root -Recurse -Filter 'Drupal.php' -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '[\\/]core[\\/]lib[\\/]Drupal\.php$' }
  foreach ($m in $hits) {
    $FoundAny = $true
    $drupalRoot = $m.FullName -replace '[\\/]core[\\/]lib[\\/]Drupal\.php$', ''
    $content = Get-Content -LiteralPath $m.FullName -ErrorAction SilentlyContinue -Raw
    $ver = $null
    if ($content -and ($content -match "const\s+VERSION\s*=\s*['""]([\d.]+)['""]")) { $ver = $Matches[1] }
    Write-DrupalVerdict "hote ($root)" $drupalRoot $ver ''
  }
}
if (-not $FoundAny) {
  $Nc++
  Write-Host "  [NON CONCERNE] hote : aucune installation Drupal trouvee dans les emplacements usuels"
  Write-Host "      scannes ($($SearchRoots -join ', ')) -- voir README, Limites connues"
}

# ---------------------------------------------------------------- 2. Conteneurs Docker Desktop (WSL2)
if ($HaveDocker) {
  Section "2. Conteneurs Docker Desktop en cours d'execution (lecture seule)"
  # Meme sonde POSIX que la version bash, executee via "docker exec" (le conteneur lui-meme
  # tourne sous Linux dans la VM WSL2 de Docker Desktop, meme si l'hote est Windows).
  $Probe = 'find / -xdev -type f -path "*/core/lib/Drupal.php" 2>/dev/null | while IFS= read -r f; do root="${f%/core/lib/Drupal.php}"; ver=$(grep "const VERSION" "$f" 2>/dev/null | head -n1 | sed "s/[^0-9.]//g"); printf "FOUND|%s|%s\n" "$root" "${ver:-}"; done'

  $ids = @(docker ps -q 2>$null) | Where-Object { $_ }
  if (-not $ids) { Write-Host "  aucun conteneur actif" }
  foreach ($id in $ids) {
    $name = (docker inspect -f '{{.Name}}' $id 2>$null) -replace '^/', ''
    $out = @(docker exec $id sh -c $Probe 2>$null) | Where-Object { $_ }
    $hit = $false
    foreach ($line in $out) {
      if ($line -match '^FOUND\|([^|]*)\|(.*)$') {
        $hit = $true
        Write-DrupalVerdict "conteneur $name" $Matches[1] $Matches[2] ''
      }
    }
    if (-not $hit) {
      $Nc++
      Write-Host "  [NON CONCERNE] conteneur $name : aucune installation Drupal trouvee"
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
        if ($line -match '^FOUND\|([^|]*)\|(.*)$') {
          $hit = $true
          Write-DrupalVerdict "image $img" $Matches[1] $Matches[2] ''
        }
      }
      if (-not $hit) {
        $Nc++
        Write-Host "  [NON CONCERNE] image $img : aucune installation Drupal trouvee"
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
