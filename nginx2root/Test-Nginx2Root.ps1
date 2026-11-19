<#
.SYNOPSIS
  Script UNIQUE et autonome (n'appelle aucun autre fichier), en LECTURE SEULE par défaut, pour
  Windows. Audite la machine locale pour « NGINX2Root » (CVE-2026-123007 / CVE-2026-123633),
  deux failles nginx critiques (RCE non authentifiée via HTTP/2). Voir README.md.

.DESCRIPTION
  Recherche nginx sous Windows : nginx.exe dans le PATH et dans les emplacements courants
  (installeur officiel, service Windows), les processus/services actifs, et les conteneurs
  Docker Desktop (WSL2/Linux, même sonde que la version bash/Linux).

  DEUX MODES :
    - Lecture seule (PAR DÉFAUT) : inspecte l'hôte et exécute une commande de lecture dans les
      conteneurs Docker Desktop DÉJÀ EN COURS D'EXÉCUTION (docker exec). Ne crée, ne démarre, ne
      modifie et ne supprime RIEN.
    - -ScanImages : en plus, lance un conteneur ÉPHÉMÈRE et ISOLÉ (docker run --rm --network none)
      pour chaque image locale, le temps d'y chercher un nginx vulnérable, puis le détruit
      immédiatement. Seul mode pouvant révéler une image vulnérable NON démarrée (donc invisible
      en lecture seule).

  N'exploite rien. Ne modifie rien.

.PARAMETER Path
  Répertoires où chercher nginx.exe. Par défaut : emplacements d'installation Windows les plus
  courants.

.PARAMETER Fast
  Ignore la recherche récursive sur le système de fichiers (rapide, mais ne détecte que le nginx
  déjà dans le PATH ou tournant en service/processus).

.PARAMETER ScanImages
  Sonde aussi les images Docker Desktop locales via un conteneur éphémère (--network none,
  détruit après usage). Sans cette option : lecture seule.

.EXAMPLE
  .\Test-Nginx2Root.ps1
.EXAMPLE
  .\Test-Nginx2Root.ps1 -ScanImages -Path 'C:\nginx'
#>

[CmdletBinding()]
param(
  [string[]]$Path = @('C:\nginx', 'C:\Program Files\nginx', 'C:\Program Files (x86)\nginx'),
  [switch]$Fast,
  [switch]$ScanImages
)

$ErrorActionPreference = 'SilentlyContinue'

function Write-Section($title) { Write-Host "`n===== $title =====" -ForegroundColor Cyan }

Write-Host "NGINX2Root (CVE-2026-123007 / CVE-2026-123633) — inventaire local"
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

function Write-Req($name, $ok, $koText) {
  Write-Host ("  {0,-12} {1}" -f $name, $(if ($ok) { 'disponible' } else { $koText }))
}
Write-Req 'PowerShell'  $PsOk 'ko (voir ERREUR ci-dessus)'
Write-Req 'docker.exe'  ([bool]$dockerExe) 'absent -> conteneurs/images Docker Desktop non sondés'
if ($Fast) { Write-Host "  (-Fast : recherche récursive sur le système de fichiers ignorée)" }

if (-not $PsOk) {
  Write-Host ""
  Write-Host "[ERREUR] Prérequis non satisfaits, arrêt avant toute vérification." -ForegroundColor Red
  exit 1
}

$Findings = New-Object System.Collections.Generic.List[string]
$Counts = @{ VULNERABLE = 0; OK = 0; UNKNOWN = 0 }

function Add-Finding {
  param([ValidateSet('VULNERABLE','OK','UNKNOWN')][string]$Verdict, [string]$Text)
  $Counts[$Verdict]++
  $tag = switch ($Verdict) { 'VULNERABLE' { '[VULNÉRABLE] ' } 'OK' { '[CORRIGÉ]    ' } default { '[À VÉRIFIER] ' } }
  $Findings.Add("$tag $Text")
}

function Add-NginxVersionFinding {
  # Branche 1.30 (stable) corrigée à partir de .7 ; branche 1.31 (mainline) corrigée à partir de
  # .9. Toute branche < 1.30 est dans la plage affectée et sans correctif amont dédié (branches
  # non maintenues) : traitée comme vulnérable. Toute branche > 1.31 est postérieure à cet avis.
  param([string]$RawVersion, [string]$Context, [bool]$IsPlus = $false)
  if ($IsPlus) {
    Add-Finding UNKNOWN "$Context : nginx Plus détecté (version affichée $RawVersion) — comparer manuellement sur le portail support F5 (builds corrigés 37.0.8.1/37.3.0.1 et 37.0.7.1/37.2.0.1)"
    return
  }
  if ($RawVersion -notmatch '^(\d+)\.(\d+)\.(\d+)') {
    Add-Finding UNKNOWN "$Context : version illisible ($RawVersion)"
    return
  }
  $major = [int]$Matches[1]; $minor = [int]$Matches[2]; $patch = [int]$Matches[3]
  if ($major -ne 1) {
    Add-Finding UNKNOWN "$Context : nginx $RawVersion, numéro de version non reconnu par ce script"
  } elseif ($minor -lt 30) {
    Add-Finding VULNERABLE "$Context : nginx $RawVersion (< 1.30.7 / < 1.31.9) — CVE-2026-123007/123633 (RCE non authentifiée) + 8 autres CVE du lot du 18/11/2026"
  } elseif ($minor -eq 30) {
    if ($patch -lt 7) { Add-Finding VULNERABLE "$Context : nginx $RawVersion < 1.30.7" } else { Add-Finding OK "$Context : nginx $RawVersion >= 1.30.7" }
  } elseif ($minor -eq 31) {
    if ($patch -lt 9) { Add-Finding VULNERABLE "$Context : nginx $RawVersion < 1.31.9" } else { Add-Finding OK "$Context : nginx $RawVersion >= 1.31.9" }
  } else {
    Add-Finding OK "$Context : nginx $RawVersion (branche postérieure à l'avis du 18/11/2026)"
  }
}

function Get-NginxInfoFromExe {
  # EXÉCUTION réservée au nginx.exe résolu depuis le PATH de l'opérateur ou un service/processus
  # déjà en cours (même frontière de confiance qu'ailleurs dans ce dépôt) -- jamais sur un binaire
  # trouvé par une simple recherche sur disque non vérifiée.
  param([string]$ExePath)
  $result = @{ Version = $null; IsPlus = $false }
  try {
    $line = (& $ExePath -v 2>&1 | Select-Object -First 1) -join ' '
    if ($line -match 'nginx/(\d+\.\d+\.\d+)') { $result.Version = $Matches[1] }
    $Vline = (& $ExePath -V 2>&1) -join ' '
    if ($Vline -match '(?i)plus') { $result.IsPlus = $true }
  } catch {}
  return $result
}

# ============================================================
Write-Section "1. nginx dans le PATH"
# ============================================================
$nginxInPath = Get-Command nginx.exe -ErrorAction SilentlyContinue
if ($nginxInPath) {
  Write-Host "  $($nginxInPath.Source)"
  $info = Get-NginxInfoFromExe $nginxInPath.Source
  if ($info.Version) { Add-NginxVersionFinding $info.Version "hôte (nginx.exe du PATH)" $info.IsPlus }
  else { Add-Finding UNKNOWN "hôte (nginx.exe du PATH) : version indéterminée" }
} else {
  Write-Host "  Aucun nginx.exe dans le PATH."
}

# ============================================================
Write-Section "2. Installations nginx connues (emplacements courants)"
# ============================================================
if (-not $Fast) {
  $nginxBins = foreach ($p in $Path) {
    if (Test-Path $p) { Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue -Include 'nginx.exe' }
  }
  $nginxBins = $nginxBins | Sort-Object FullName -Unique
  if ($nginxBins) {
    foreach ($b in $nginxBins) {
      Write-Host "  $($b.FullName)"
      $info = Get-NginxInfoFromExe $b.FullName
      if ($info.Version) { Add-NginxVersionFinding $info.Version $b.FullName $info.IsPlus }
      else { Add-Finding UNKNOWN "$($b.FullName) : version indéterminée (exécution impossible ou sortie inattendue) — vérifier manuellement." }
    }
  } else {
    Write-Host "  Aucun nginx.exe trouvé sous : $($Path -join ', ')"
  }
} else {
  Write-Host "  (-Fast : recherche récursive ignorée)"
}

# ============================================================
Write-Section "3. Services et processus nginx"
# ============================================================
$procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '^nginx$' }
if ($procs) {
  $procs | Select-Object Id, ProcessName, Path | Format-Table -AutoSize | Out-String | Write-Host
  foreach ($p in ($procs | Where-Object { $_.Path } | Select-Object -ExpandProperty Path -Unique)) {
    $info = Get-NginxInfoFromExe $p
    if ($info.Version) { Add-NginxVersionFinding $info.Version "processus actif ($p)" $info.IsPlus }
  }
} else {
  Write-Host "  Aucun processus nginx trouvé."
}
$svcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'nginx' -or $_.DisplayName -match 'nginx' }
if ($svcs) { $svcs | Select-Object Name, Status, DisplayName | Format-Table -AutoSize | Out-String | Write-Host }

# ============================================================
Write-Section "4. Docker Desktop (conteneurs Linux via WSL2)"
# ============================================================
# Même sonde POSIX que la version bash/Linux, exécutée via docker exec / docker run.
$probe = @'
nginx_bin=$(command -v nginx 2>/dev/null)
[ -z "$nginx_bin" ] && for p in /usr/sbin/nginx /usr/local/nginx/sbin/nginx; do [ -x "$p" ] && nginx_bin="$p" && break; done
[ -z "$nginx_bin" ] && exit 0
vline=$("$nginx_bin" -v 2>&1); Vline=$("$nginx_bin" -V 2>&1)
ver=$(printf "%s" "$vline" | sed -n "s#.*nginx/\([0-9][0-9.]*\).*#\1#p" | head -n1)
[ -n "$ver" ] && echo "VER $ver"
printf "%s" "$Vline" | grep -qi "plus" && echo "PLUS 1"
true
'@

if ($dockerExe) {
  $containers = & $dockerExe.Source ps --format '{{.Names}}' 2>$null
  Write-Host "-- conteneurs EN COURS (exec, lecture seule) --"
  foreach ($c in $containers) {
    $out = & $dockerExe.Source exec $c sh -c $probe 2>$null
    $rc = $LASTEXITCODE
    if (-not $out) {
      if ($rc -ne 0) { Add-Finding UNKNOWN "conteneur $c : sonde impossible (docker exec a échoué, code retour $rc — pas de shell ou conteneur arrêté) — vérifier manuellement." }
      continue
    }
    $ver = ($out | Where-Object { $_ -match '^VER ' } | Select-Object -First 1 | ForEach-Object { ($_ -split ' ', 2)[1] })
    $isPlus = [bool]($out | Where-Object { $_ -match '^PLUS ' })
    if (-not $ver) { continue }
    Write-Host "  conteneur $c : version=$ver plus=$isPlus"
    Add-NginxVersionFinding $ver "conteneur $c" $isPlus
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
      $ver = ($out | Where-Object { $_ -match '^VER ' } | Select-Object -First 1 | ForEach-Object { ($_ -split ' ', 2)[1] })
      $isPlus = [bool]($out | Where-Object { $_ -match '^PLUS ' })
      if (-not $ver) { continue }
      Write-Host "  image $img : version=$ver plus=$isPlus"
      Add-NginxVersionFinding $ver "image $img" $isPlus
    }
  } else {
    Write-Host "  (mode lecture seule : images locales non sondées — relancer avec -ScanImages pour les inclure)"
  }
} else {
  Write-Host "  docker.exe non trouvé (Docker Desktop absent ou non démarré) : section ignorée."
}

# ============================================================
Write-Section "5. Conclusion"
# ============================================================
$Findings | ForEach-Object { Write-Host $_ }
Write-Host ""
$Verdict = 'NON CONCERNÉ'
if ($Counts.VULNERABLE -gt 0) {
  $Verdict = 'VULNÉRABLE'
  Write-Host "[VULNÉRABLE] $($Counts.VULNERABLE) installation(s) nginx < version corrigée. Mettre à jour vers 1.30.7/1.31.9 (ou l'équivalent nginx Plus) en urgence ; si HTTP/2 ne peut pas être désactivé immédiatement en attendant, prioriser le patch." -ForegroundColor Red
} elseif ($Counts.UNKNOWN -gt 0) {
  $Verdict = 'À VÉRIFIER'
  Write-Host "[À VÉRIFIER] $($Counts.UNKNOWN) élément(s) sans verdict automatique fiable (version non lisible, nginx Plus, etc.). Compléter à la main." -ForegroundColor Yellow
} elseif ($Counts.OK -gt 0) {
  $Verdict = 'OK'
  Write-Host "[OK] nginx détecté, toutes les versions sont >= versions corrigées." -ForegroundColor Green
} else {
  Write-Host "[NON CONCERNÉ] Aucun nginx trouvé dans le périmètre scanné (PATH, emplacements connus, processus/services, conteneurs actifs)." -ForegroundColor Green
}

Write-Host ""
if ($Verdict -eq 'VULNÉRABLE') {
  Write-Host "Confiance : élément vulnérable CONFIRMÉ — pas d'ambiguïté, agir immédiatement (cf. ci-dessus)." -ForegroundColor Red
} elseif ($Verdict -eq 'À VÉRIFIER') {
  Write-Host "Confiance : INCOMPLÈTE — au moins un élément nécessite une vérification manuelle avant de pouvoir conclure." -ForegroundColor Yellow
} elseif ($ScanImages) {
  Write-Host "Confiance : COMPLÈTE dans la limite de ce script — hôte, conteneurs actifs ET images Docker Desktop locales ont tous été sondés, aucune trace de nginx vulnérable." -ForegroundColor Green
} else {
  Write-Host "Confiance : PARTIELLE — mode lecture seule : seuls l'hôte et les conteneurs ACTIFS ont été inspectés. Une image Docker Desktop locale non démarrée peut contenir un nginx vulnérable sans apparaître ici. Relancer avec -ScanImages pour être certain." -ForegroundColor Yellow
}
Write-Host "[LIMITE] Ce script n'exploite pas la faille et ne prouve pas l'absence de compromission. La recherche sur disque est bornée aux chemins -Path. Les conteneurs Windows natifs (non-WSL2) ne sont pas sondés par la commande 'sh' utilisée ici."
Write-Host "Références : https://nginx.org/en/security_advisories.html  |  https://security-tracker.debian.org/  |  https://ubuntu.com/security/notices/"

switch ($Verdict) {
  'VULNÉRABLE'  { exit 2 }
  'À VÉRIFIER'  { exit 1 }
  default       { exit 0 }
}
