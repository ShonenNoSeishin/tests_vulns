<#
.SYNOPSIS
  Script UNIQUE et autonome (n'appelle aucun autre fichier), en LECTURE SEULE par défaut,
  pour Windows. Audite la machine locale pour PHP2Shell (CVE-2026-109618 / CVE-2026-109619),
  deux failles PHP critiques (RCE non authentifiée via HTTP). Voir README.md.

.DESCRIPTION
  Recherche PHP sous Windows : php.exe/php-cgi.exe dans le PATH et dans les emplacements
  courants (XAMPP, WAMP, installeur officiel PHP, IIS), la configuration FastCGI d'IIS
  (applicationHost.config), les processus/services actifs, et les conteneurs Docker
  Desktop (WSL2/Linux, même sonde que la version bash/Linux).

  DEUX MODES :
    - Lecture seule (PAR DÉFAUT) : inspecte l'hôte et exécute une commande de lecture dans
      les conteneurs Docker Desktop DÉJÀ EN COURS D'EXÉCUTION (docker exec). Ne crée, ne
      démarre, ne modifie et ne supprime RIEN.
    - -ScanImages : en plus du mode lecture seule, lance un conteneur ÉPHÉMÈRE et ISOLÉ
      (docker run --rm --network none) pour chaque image locale, le temps d'y chercher un
      PHP vulnérable, puis le détruit immédiatement. C'est le seul mode qui peut révéler une
      image vulnérable qui n'est PAS actuellement démarrée (donc invisible en lecture
      seule) — nécessaire pour être réellement certain que la machine n'est pas concernée.

  N'exploite rien. Ne modifie rien.

.PARAMETER Path
  Répertoires où chercher php.exe/php-cgi.exe. Par défaut : emplacements XAMPP/WAMP/PHP
  officiel/IIS les plus courants.

.PARAMETER Fast
  Ignore la recherche récursive sur le système de fichiers (rapide, mais ne détecte que le
  PHP déjà dans le PATH et la config FastCGI IIS).

.PARAMETER ScanImages
  Sonde aussi les images Docker Desktop locales via un conteneur éphémère
  (--network none, détruit après usage). Sans cette option : lecture seule.

.EXAMPLE
  .\Test-Php2Shell.ps1
.EXAMPLE
  .\Test-Php2Shell.ps1 -ScanImages -Path 'D:\sites'
#>

[CmdletBinding()]
param(
  [string[]]$Path = @('C:\xampp', 'C:\wamp', 'C:\wamp64', 'C:\PHP', 'C:\Program Files\PHP', 'C:\Program Files (x86)\PHP', 'C:\inetpub'),
  [switch]$Fast,
  [switch]$ScanImages
)

$ErrorActionPreference = 'SilentlyContinue'

function Write-Section($title) { Write-Host "`n===== $title =====" -ForegroundColor Cyan }

Write-Host "PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — inventaire local"
Write-Host "Mode : $(if ($ScanImages) { 'complet (hôte + conteneurs actifs + images, conteneurs éphémères --network none)' } else { 'lecture seule (hôte + conteneurs actifs uniquement, aucune création)' })"
Write-Host "Date : $(Get-Date -Format 'yyyy-MM-ddTHH:mm:sszzz')"
Write-Host "Hôte : $($env:COMPUTERNAME)"
try {
  $os = Get-CimInstance Win32_OperatingSystem
  Write-Host "OS : $($os.Caption) (build $($os.BuildNumber))"
} catch { Write-Host "OS : inconnu" }

# ============================================================
Write-Section "0. Prérequis"
# ============================================================
$PsOk = $PSVersionTable.PSVersion.Major -ge 5
if (-not $PsOk) {
  Write-Host "[ERREUR] PowerShell 5.1+ requis. Version détectée : $($PSVersionTable.PSVersion)." -ForegroundColor Red
}
$dockerExe = Get-Command docker.exe -ErrorAction SilentlyContinue
$iisConfig = "$env:SystemRoot\System32\inetsrv\config\applicationHost.config"
$hasIisConfig = Test-Path $iisConfig

function Write-Req($name, $ok, $koText) {
  Write-Host ("  {0,-12} {1}" -f $name, $(if ($ok) { 'disponible' } else { $koText }))
}
Write-Req 'PowerShell'  $PsOk 'ko (voir ERREUR ci-dessus)'
Write-Req 'docker.exe'  ([bool]$dockerExe) 'absent -> conteneurs/images Docker Desktop non sondés'
Write-Req 'IIS config'  $hasIisConfig 'absent -> IIS non installé ou inaccessible, section FastCGI ignorée'
if ($Fast) { Write-Host "  (-Fast : recherche récursive sur le système de fichiers ignorée)" }

if (-not $PsOk) {
  Write-Host ""
  Write-Host "[ERREUR] Prérequis non satisfaits, arrêt avant toute vérification." -ForegroundColor Red
  exit 1
}

# PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — versions corrigées par branche (21/10/2026)
$PhpFixed = @{ '8.2' = 35; '8.3' = 36; '8.4' = 27; '8.5' = 12 }

$Findings = New-Object System.Collections.Generic.List[string]
$Counts = @{ VULNERABLE = 0; OK = 0; UNKNOWN = 0 }

function Add-Finding {
  param([ValidateSet('VULNERABLE','OK','UNKNOWN')][string]$Verdict, [string]$Text)
  $Counts[$Verdict]++
  $tag = switch ($Verdict) { 'VULNERABLE' { '[VULNÉRABLE] ' } 'OK' { '[CORRIGÉ]    ' } default { '[À VÉRIFIER] ' } }
  $Findings.Add("$tag $Text")
}

function Add-PhpVersionFinding {
  # <version "X.Y.Z..."> <contexte>
  param([string]$RawVersion, [string]$Context)
  if ($RawVersion -notmatch '^(\d+)\.(\d+)\.(\d+)') {
    Add-Finding UNKNOWN "$Context : version illisible ($RawVersion)"
    return
  }
  $branch = "$($Matches[1]).$($Matches[2])"
  $patch = [int]$Matches[3]
  $major = [int]$Matches[1]; $minor = [int]$Matches[2]
  if ($PhpFixed.ContainsKey($branch)) {
    $fixedPatch = $PhpFixed[$branch]
    if ($patch -lt $fixedPatch) {
      Add-Finding VULNERABLE "$Context : PHP $RawVersion < $branch.$fixedPatch"
    } else {
      Add-Finding OK "$Context : PHP $RawVersion >= $branch.$fixedPatch"
    }
  } elseif ($major -lt 8 -or ($major -eq 8 -and $minor -lt 2)) {
    Add-Finding VULNERABLE "$Context : PHP $RawVersion (branche EOL, pas de correctif amont — backport source ou migration)"
  } else {
    Add-Finding UNKNOWN "$Context : PHP $RawVersion (branche non référencée, vérifier l'avis officiel)"
  }
}

function Get-PhpVersionStatic {
  # Lecture de version SANS exécution (certains builds PHP embarquent un numéro de version
  # Win32 lisible via VersionInfo). C'est la SEULE méthode utilisée pour un binaire trouvé par
  # une recherche sur disque (hors PATH) : un utilisateur local sans droits pourrait sinon
  # déposer un faux php.exe que ce script (souvent lancé en administrateur) exécuterait pour
  # lui. Une vérification de propriétaire/ACL avant exécution avait été envisagée puis écartée :
  # elle compare des noms de principals localisés (ne fonctionne pas sur un Windows non anglais)
  # et une liste de refus reste par nature incomplète -- plus sûr de ne jamais exécuter.
  param([string]$ExePath)
  try {
    $fv = (Get-Item -LiteralPath $ExePath -ErrorAction Stop).VersionInfo
    if ($fv.ProductVersion -and $fv.ProductVersion -match '^\d+\.\d+\.\d+') { return $fv.ProductVersion.Trim() }
    if ($fv.FileVersion -and $fv.FileVersion -match '^\d+\.\d+\.\d+') { return $fv.FileVersion.Trim() }
  } catch {}
  return $null
}

function Get-PhpVersionFromExe {
  # Lecture statique, puis EXÉCUTION en dernier recours -- réservé au php.exe résolu depuis le
  # PATH de l'opérateur (même frontière de confiance que docker.exe/node.exe/dotnet.exe ailleurs
  # dans ce script). Ne JAMAIS appeler cette fonction sur un binaire trouvé par une recherche
  # sur disque : utiliser Get-PhpVersionStatic à la place (voir sections 2 et 3 ci-dessous).
  param([string]$ExePath)
  $static = Get-PhpVersionStatic $ExePath
  if ($static) { return $static }
  try {
    $v = & $ExePath -r "echo PHP_VERSION;" 2>$null
    if ($v -match '^\d+\.\d+\.\d+') { return $v.Trim() }
  } catch {}
  try {
    $line = (& $ExePath -v 2>$null | Select-Object -First 1)
    if ($line -match 'PHP\s+(\d+\.\d+\.\d+)') { return $Matches[1] }
  } catch {}
  return $null
}

# ============================================================
Write-Section "1. PHP dans le PATH"
# ============================================================
$phpInPath = Get-Command php.exe -ErrorAction SilentlyContinue
if ($phpInPath) {
  Write-Host "  $($phpInPath.Source)"
  $v = Get-PhpVersionFromExe $phpInPath.Source
  if ($v) { Add-PhpVersionFinding $v "hôte (php.exe du PATH)" }
  else { Add-Finding UNKNOWN "hôte (php.exe du PATH) : version indéterminée" }
} else {
  Write-Host "  Aucun php.exe dans le PATH."
}

# ============================================================
Write-Section "2. Installations PHP connues (XAMPP / WAMP / installeur officiel)"
# ============================================================
if (-not $Fast) {
  $phpBins = foreach ($p in $Path) {
    if (Test-Path $p) { Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue -Include 'php.exe','php-cgi.exe' }
  }
  $phpBins = $phpBins | Sort-Object FullName -Unique
  if ($phpBins) {
    foreach ($b in $phpBins) {
      Write-Host "  $($b.FullName)"
      $v = Get-PhpVersionStatic $b.FullName
      if ($v) { Add-PhpVersionFinding $v $b.FullName }
      else { Add-Finding UNKNOWN "$($b.FullName) : version illisible statiquement (le binaire n'embarque pas de ressource de version Win32 exploitable) ; non exécuté par sécurité — vérifier manuellement, par ex. en exécutant '& `"$($b.FullName)`" -v' depuis une session de confiance." }
    }
  } else {
    Write-Host "  Aucun php.exe/php-cgi.exe trouvé sous : $($Path -join ', ')"
  }
} else {
  Write-Host "  (-Fast : recherche récursive ignorée)"
}

# ============================================================
Write-Section "3. IIS — configuration FastCGI (php-cgi.exe)"
# ============================================================
if ($hasIisConfig) {
  try {
    [xml]$cfg = Get-Content $iisConfig -Raw
    $apps = $cfg.configuration.'system.webServer'.fastCgi.application
    if ($apps) {
      foreach ($app in $apps) {
        $fp = $app.fullPath
        if ($fp -match 'php-cgi\.exe$|php\.exe$') {
          Write-Host "  FastCGI -> $fp (arguments : $($app.arguments))"
          if (Test-Path $fp) {
            $v = Get-PhpVersionStatic $fp
            if ($v) { Add-PhpVersionFinding $v "IIS FastCGI : $fp" }
            else { Add-Finding UNKNOWN "IIS FastCGI : $fp — version illisible statiquement ; non exécuté par sécurité — vérifier manuellement." }
          } else {
            Add-Finding UNKNOWN "IIS FastCGI référence $fp mais ce fichier n'existe pas (configuration obsolète ?)"
          }
        }
      }
    } else {
      Write-Host "  Aucune application FastCGI PHP configurée dans applicationHost.config."
    }
  } catch {
    Write-Host "  applicationHost.config illisible depuis ce contexte (droits administrateur requis en général)."
  }
} else {
  Write-Host "  IIS non installé ou applicationHost.config inaccessible : section ignorée."
}

# ============================================================
Write-Section "4. Services et processus PHP / serveurs web"
# ============================================================
$procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '^(php|php-cgi|httpd|apache|nginx|w3wp)$' }
if ($procs) {
  $procs | Select-Object Id, ProcessName, Path | Format-Table -AutoSize | Out-String | Write-Host
} else {
  Write-Host "  Aucun processus php/php-cgi/httpd/apache/nginx/w3wp trouvé."
}
$svcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'w3svc|wampapache|iisexpress' -or $_.DisplayName -match 'IIS|Apache|PHP' }
if ($svcs) { $svcs | Select-Object Name, Status, DisplayName | Format-Table -AutoSize | Out-String | Write-Host }

# ============================================================
Write-Section "5. Docker Desktop (conteneurs Linux via WSL2)"
# ============================================================
# Même sonde POSIX que la version bash/Linux, exécutée via docker exec / docker run.
$probe = @'
for b in php php-cgi php-fpm php-fpm8 frankenphp; do p=$(command -v $b 2>/dev/null) && echo "BIN $p"; done
for p in /usr/local/bin/php /usr/local/sbin/php-fpm /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/frankenphp; do [ -x "$p" ] && echo "BIN $p"; done
v=$( (php -r "echo PHP_VERSION;" || php-cgi -v | sed -n "1p" | cut -d" " -f2) 2>/dev/null) && [ -n "$v" ] && echo "VER $v"
true
'@

if ($dockerExe) {
  $containers = & $dockerExe.Source ps --format '{{.Names}}' 2>$null
  Write-Host "-- conteneurs EN COURS (exec, lecture seule) --"
  foreach ($c in $containers) {
    $out = & $dockerExe.Source exec $c sh -c $probe 2>$null
    $rc = $LASTEXITCODE
    if (-not $out) {
      # Sortie vide ET code retour non nul = la sonde n'a pas pu s'exécuter (pas de shell dans
      # l'image, conteneur arrêté entre-temps...) : pas une preuve d'absence de PHP.
      if ($rc -ne 0) { Add-Finding UNKNOWN "conteneur $c : sonde impossible (docker exec a échoué, code retour $rc — pas de shell ou conteneur arrêté) — vérifier manuellement." }
      continue
    }
    $bins = ($out | Where-Object { $_ -match '^BIN ' } | ForEach-Object { ($_ -split ' ', 2)[1] }) -join ' '
    $ver  = ($out | Where-Object { $_ -match '^VER ' } | Select-Object -First 1 | ForEach-Object { ($_ -split ' ', 2)[1] })
    if (-not $bins -and -not $ver) { continue }
    Write-Host "  conteneur $c : binaires=[$bins] version=$(if ($ver) { $ver } else { '?' })"
    if ($ver) { Add-PhpVersionFinding $ver "conteneur $c" }
    else { Add-Finding UNKNOWN "conteneur $c : PHP présent, version indéterminée" }
  }
  if ($ScanImages) {
    Write-Host "-- images locales (conteneur ÉPHÉMÈRE --network none, détruit après usage) --"
    $images = & $dockerExe.Source images --format '{{.Repository}}:{{.Tag}}' 2>$null | Where-Object { $_ -notmatch '<none>' } | Sort-Object -Unique
    foreach ($img in $images) {
      $out = & $dockerExe.Source run --rm --network none --entrypoint sh $img -c $probe 2>$null
      $rc = $LASTEXITCODE
      if (-not $out) {
        if ($rc -ne 0) { Add-Finding UNKNOWN "image $img : sonde impossible (docker run a échoué ou expiré, code retour $rc — pas de shell dans l'image) — vérifier manuellement." }
        continue
      }
      $bins = ($out | Where-Object { $_ -match '^BIN ' } | ForEach-Object { ($_ -split ' ', 2)[1] }) -join ' '
      $ver  = ($out | Where-Object { $_ -match '^VER ' } | Select-Object -First 1 | ForEach-Object { ($_ -split ' ', 2)[1] })
      if (-not $bins -and -not $ver) { continue }
      Write-Host "  image $img : binaires=[$bins] version=$(if ($ver) { $ver } else { '?' })"
      if ($ver) { Add-PhpVersionFinding $ver "image $img" }
      else { Add-Finding UNKNOWN "image $img : PHP présent, version indéterminée" }
    }
  } else {
    Write-Host "  (mode lecture seule : images locales non sondées — relancer avec -ScanImages pour les inclure)"
  }
} else {
  Write-Host "  docker.exe non trouvé (Docker Desktop absent ou non démarré) : section ignorée."
}

# ============================================================
Write-Section "6. Conclusion"
# ============================================================
$Findings | ForEach-Object { Write-Host $_ }
Write-Host ""
$Verdict = 'NON CONCERNÉ'
if ($Counts.VULNERABLE -gt 0) {
  $Verdict = 'VULNÉRABLE'
  Write-Host "[VULNÉRABLE] $($Counts.VULNERABLE) installation(s) PHP < version corrigée. Si elles servent des requêtes web : mettre à jour/reconstruire en urgence, redémarrer IIS/le pool d'applications ou le service concerné, appliquer session.upload_progress.enabled=0 en attendant. Si inactives (images non lancées) : supprimer ou reconstruire." -ForegroundColor Red
} elseif ($Counts.UNKNOWN -gt 0) {
  $Verdict = 'À VÉRIFIER'
  Write-Host "[À VÉRIFIER] $($Counts.UNKNOWN) élément(s) sans verdict automatique fiable (version non lisible, config FastCGI pointant vers un fichier absent, etc.). Compléter à la main." -ForegroundColor Yellow
} elseif ($Counts.OK -gt 0) {
  $Verdict = 'OK'
  Write-Host "[OK] PHP détecté, toutes les versions sont >= versions corrigées." -ForegroundColor Green
} else {
  Write-Host "[NON CONCERNÉ] Aucun PHP trouvé dans le périmètre scanné (PATH, emplacements connus, IIS FastCGI, conteneurs actifs)." -ForegroundColor Green
}

Write-Host ""
if ($Verdict -eq 'VULNÉRABLE') {
  Write-Host "Confiance : élément vulnérable CONFIRMÉ — pas d'ambiguïté, agir immédiatement (cf. ci-dessus)." -ForegroundColor Red
} elseif ($Verdict -eq 'À VÉRIFIER') {
  Write-Host "Confiance : INCOMPLÈTE — au moins un élément nécessite une vérification manuelle avant de pouvoir conclure." -ForegroundColor Yellow
} elseif ($ScanImages) {
  Write-Host "Confiance : COMPLÈTE dans la limite de ce script — hôte, conteneurs actifs ET images Docker Desktop locales ont tous été sondés, aucune trace de PHP vulnérable." -ForegroundColor Green
} else {
  Write-Host "Confiance : PARTIELLE — mode lecture seule : seuls l'hôte et les conteneurs ACTIFS ont été inspectés. Une image Docker Desktop locale non démarrée peut contenir un PHP vulnérable sans apparaître ici. Relancer avec -ScanImages pour être certain." -ForegroundColor Yellow
}
Write-Host "[LIMITE] Ce script n'exploite pas la faille et ne prouve pas l'absence de compromission. La recherche sur disque est bornée aux chemins -Path (par défaut XAMPP/WAMP/PHP/IIS) : une installation ailleurs peut être invisible. Les conteneurs Windows (non-WSL2) ne sont pas sondés par la commande 'sh' utilisée ici."
Write-Host "Références : https://www.php.net/  |  https://learn.microsoft.com/iis/  |  https://security-tracker.debian.org/"

switch ($Verdict) {
  'VULNÉRABLE'  { exit 2 }
  'À VÉRIFIER'  { exit 1 }
  default       { exit 0 }
}
