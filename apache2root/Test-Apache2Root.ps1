<#
.SYNOPSIS
  Script UNIQUE et autonome (n'appelle aucun autre fichier), en LECTURE SEULE par défaut, pour
  Windows. Audite la machine locale pour « Apache2Root » (CVE-2026-119618), race condition dans
  mod_http2 d'Apache HTTP Server pouvant mener à une RCE non authentifiée. Voir README.md.

.DESCRIPTION
  Recherche Apache httpd sous Windows : httpd.exe dans le PATH et dans les emplacements courants
  (XAMPP, WAMP, Apache Lounge/Apache24, installeur officiel), les processus/services actifs, et
  les conteneurs Docker Desktop (WSL2/Linux, même sonde que la version bash/Linux).

  SÉCURITÉ : seul le httpd.exe résolu depuis le PATH de l'opérateur (section 1) est exécuté
  (`-v`, `-M`). Un binaire trouvé par recherche sur disque (section 2) ou appartenant à un
  processus/service déjà en cours (section 3) n'est JAMAIS exécuté -- uniquement lu via ses
  métadonnées de version Win32 et une lecture statique de son fichier de configuration voisin
  (conf\httpd.conf) -- pour qu'un utilisateur non administrateur ne puisse pas faire exécuter un
  faux binaire déposé dans un dossier scanné par ce script, souvent lancé en administrateur.

  DEUX MODES :
    - Lecture seule (PAR DÉFAUT) : inspecte l'hôte et exécute une commande de lecture dans les
      conteneurs Docker Desktop DÉJÀ EN COURS D'EXÉCUTION (docker exec). Ne crée, ne démarre, ne
      modifie et ne supprime RIEN.
    - -ScanImages : en plus, lance un conteneur ÉPHÉMÈRE et ISOLÉ (docker run --rm --network none)
      pour chaque image locale, le temps d'y chercher un Apache vulnérable, puis le détruit
      immédiatement. Seul mode pouvant révéler une image vulnérable NON démarrée.

  N'exploite rien. Ne modifie rien.

.PARAMETER Path
  Répertoires où chercher httpd.exe. Par défaut : emplacements d'installation Windows les plus
  courants (XAMPP, WAMP, Apache Lounge).

.PARAMETER Fast
  Ignore la recherche récursive sur le système de fichiers (rapide, mais ne détecte que l'Apache
  déjà dans le PATH ou tournant en service/processus).

.PARAMETER ScanImages
  Sonde aussi les images Docker Desktop locales via un conteneur éphémère (--network none,
  détruit après usage). Sans cette option : lecture seule.

.EXAMPLE
  .\Test-Apache2Root.ps1
.EXAMPLE
  .\Test-Apache2Root.ps1 -ScanImages -Path 'C:\xampp\apache'
#>

[CmdletBinding()]
param(
  [string[]]$Path = @('C:\xampp\apache', 'C:\wamp64\bin\apache', 'C:\Apache24', 'C:\Program Files\Apache Software Foundation'),
  [switch]$Fast,
  [switch]$ScanImages
)

$ErrorActionPreference = 'SilentlyContinue'

function Write-Section($title) { Write-Host "`n===== $title =====" -ForegroundColor Cyan }

Write-Host "Apache2Root (CVE-2026-119618) — inventaire local"
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

function Add-ApacheVersionFinding {
  # Plage amont affectée : 2.4.55 à 2.4.70 inclus (CVE-2026-119618, race condition dans
  # assign_headers() de mod_http2) ; corrigé à partir de 2.4.71. Apache ne fournit pas de binaires
  # Windows officiels : les builds Windows (Apache Lounge, XAMPP, WAMP) n'ont pas de rétroportage
  # distro -- seule la version amont compte ici, pas de table Ubuntu/Debian comme côté Linux.
  param([string]$RawVersion, [string]$Context)
  if ($RawVersion -notmatch '^(\d+)\.(\d+)\.(\d+)') {
    Add-Finding UNKNOWN "$Context : version illisible ($RawVersion)"
    return
  }
  $major = [int]$Matches[1]; $minor = [int]$Matches[2]; $patch = [int]$Matches[3]
  if ($major -ne 2 -or $minor -ne 4) {
    Add-Finding UNKNOWN "$Context : Apache $RawVersion, numéro de version non reconnu par ce script"
  } elseif ($patch -lt 55) {
    Add-Finding OK "$Context : Apache $RawVersion (< 2.4.55, hors plage affectée)"
  } elseif ($patch -le 70) {
    Add-Finding VULNERABLE "$Context : Apache $RawVersion (2.4.55-2.4.70) — CVE-2026-119618 (RCE non authentifiée, race condition dans mod_http2/assign_headers())"
  } else {
    Add-Finding OK "$Context : Apache $RawVersion (>= 2.4.71)"
  }
}

function Test-Http2ConfNear {
  # Lecture STATIQUE uniquement d'un conf\httpd.conf voisin du binaire (bin\httpd.exe -> ..\conf\
  # httpd.conf, disposition standard Apache Lounge/XAMPP/WAMP). Jamais d'exécution. Retourne
  # 'oui' / 'non' / 'inconnu' (config introuvable ou illisible -- ne jamais déduire 'non' par
  # défaut dans ce cas, le script retombe sur [À VÉRIFIER] plus haut).
  param([string]$ExePath)
  try {
    $binDir = Split-Path -Parent $ExePath
    $base = Split-Path -Parent $binDir
    $conf = Join-Path $base 'conf\httpd.conf'
    if (-not (Test-Path -LiteralPath $conf)) { return 'inconnu' }
    $lines = Get-Content -LiteralPath $conf -ErrorAction Stop
    foreach ($l in $lines) {
      if ($l -match '^\s*#') { continue }
      if ($l -match '(?i)^\s*LoadModule\s+http2_module') { return 'oui' }
    }
    return 'non'
  } catch { return 'inconnu' }
}

function Get-ApacheInfoFromExe {
  # EXÉCUTION réservée au httpd.exe résolu depuis le PATH de l'opérateur (section 1 ci-dessous) --
  # même frontière de confiance que nginx.exe dans nginx2root/Test-Nginx2Root.ps1. JAMAIS sur un
  # binaire trouvé par recherche sur disque ou par un processus/service déjà en cours.
  param([string]$ExePath)
  $result = @{ Version = $null; Http2 = 'inconnu' }
  try {
    $line = (& $ExePath -v 2>&1 | Select-Object -First 1) -join ' '
    if ($line -match 'Apache/(\d+\.\d+\.\d+)') { $result.Version = $Matches[1] }
  } catch {}
  try {
    $mods = (& $ExePath -M 2>&1) -join "`n"
    if ($mods -match '(?i)http2_module') { $result.Http2 = 'oui' } else { $result.Http2 = 'non' }
  } catch {}
  return $result
}

function Get-ApacheVersionStatic {
  # Lecture de version SANS exécution, pour un binaire trouvé par recherche sur disque (section 2)
  # ou appartenant à un processus/service déjà en cours (section 3). Même principe que
  # Get-NginxVersionStatic dans nginx2root/Test-Nginx2Root.ps1.
  param([string]$ExePath)
  try {
    $fv = (Get-Item -LiteralPath $ExePath -ErrorAction Stop).VersionInfo
    if ($fv.ProductVersion -and $fv.ProductVersion -match '\d+\.\d+\.\d+') { return $Matches[0] }
    if ($fv.FileVersion -and $fv.FileVersion -match '\d+\.\d+\.\d+') { return $Matches[0] }
  } catch {}
  try {
    $bytes = [System.IO.File]::ReadAllBytes($ExePath)
    $text = [System.Text.Encoding]::ASCII.GetString($bytes)
    if ($text -match 'Apache/(\d+\.\d+\.\d+)') { return $Matches[1] }
  } catch {}
  return $null
}

# ============================================================
Write-Section "1. Apache dans le PATH"
# ============================================================
$apacheInPath = Get-Command httpd.exe -ErrorAction SilentlyContinue
if ($apacheInPath) {
  Write-Host "  $($apacheInPath.Source)"
  $info = Get-ApacheInfoFromExe $apacheInPath.Source
  if (-not $info.Version) {
    Add-Finding UNKNOWN "hôte (httpd.exe du PATH) : version indéterminée"
  } elseif ($info.Http2 -eq 'non') {
    Write-Host "  module mod_http2 non chargé — CVE-2026-119618 ne s'applique pas tant qu'il reste désactivé."
  } elseif ($info.Http2 -eq 'inconnu') {
    Add-Finding UNKNOWN "hôte (httpd.exe du PATH) : liste des modules illisible (httpd -M a échoué) — impossible de confirmer si mod_http2 est chargé"
  } else {
    Add-ApacheVersionFinding $info.Version "hôte (httpd.exe du PATH)"
  }
} else {
  Write-Host "  Aucun httpd.exe dans le PATH."
}

# ============================================================
Write-Section "2. Installations Apache connues (emplacements courants)"
# ============================================================
if (-not $Fast) {
  $apacheBins = foreach ($p in $Path) {
    if (Test-Path $p) { Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue -Include 'httpd.exe' }
  }
  $apacheBins = $apacheBins | Sort-Object FullName -Unique
  if ($apacheBins) {
    foreach ($b in $apacheBins) {
      Write-Host "  $($b.FullName)"
      $ver = Get-ApacheVersionStatic $b.FullName
      if (-not $ver) {
        Add-Finding UNKNOWN "$($b.FullName) : version illisible statiquement (ni métadonnée Win32, ni chaîne 'Apache/X.Y.Z' trouvée dans le binaire) ; non exécuté par sécurité -- vérifier manuellement après avoir confirmé que le fichier n'est pas modifiable par un compte non administrateur."
        continue
      }
      $http2 = Test-Http2ConfNear $b.FullName
      if ($http2 -eq 'non') {
        Write-Host "      module mod_http2 non chargé (conf\httpd.conf voisin lu statiquement) — non concerné."
      } elseif ($http2 -eq 'inconnu') {
        Add-Finding UNKNOWN "$($b.FullName) : conf\httpd.conf voisin introuvable ou illisible -- impossible de confirmer si mod_http2 est chargé, vérifier manuellement"
      } else {
        Add-ApacheVersionFinding $ver $b.FullName
      }
    }
  } else {
    Write-Host "  Aucun httpd.exe trouvé sous : $($Path -join ', ')"
  }
} else {
  Write-Host "  (-Fast : recherche récursive ignorée)"
}

# ============================================================
Write-Section "3. Services et processus Apache"
# ============================================================
$procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match '^httpd$' }
if ($procs) {
  $procs | Select-Object Id, ProcessName, Path | Format-Table -AutoSize | Out-String | Write-Host
  foreach ($p in ($procs | Where-Object { $_.Path } | Select-Object -ExpandProperty Path -Unique)) {
    # Lecture statique uniquement -- même principe que la section 2.
    $ver = Get-ApacheVersionStatic $p
    if (-not $ver) {
      Add-Finding UNKNOWN "processus actif ($p) : version illisible statiquement -- vérifier manuellement."
      continue
    }
    $http2 = Test-Http2ConfNear $p
    if ($http2 -eq 'non') {
      Write-Host "      processus actif ($p) : module mod_http2 non chargé — non concerné."
    } elseif ($http2 -eq 'inconnu') {
      Add-Finding UNKNOWN "processus actif ($p) : conf\httpd.conf voisin introuvable -- impossible de confirmer si mod_http2 est chargé"
    } else {
      Add-ApacheVersionFinding $ver "processus actif ($p)"
    }
  }
} else {
  Write-Host "  Aucun processus httpd trouvé."
}
$svcs = Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'apache' -or $_.DisplayName -match 'Apache' }
if ($svcs) { $svcs | Select-Object Name, Status, DisplayName | Format-Table -AutoSize | Out-String | Write-Host }

# ============================================================
Write-Section "4. Docker Desktop (conteneurs Linux via WSL2)"
# ============================================================
# Même sonde POSIX que la version bash/Linux (vérifie présence du binaire, version, et si le
# module mod_http2 est chargé via apache2ctl/httpd -M, best-effort).
$probe = @'
bin=$(command -v apache2 2>/dev/null); [ -z "$bin" ] && bin=$(command -v httpd 2>/dev/null)
[ -z "$bin" ] && for p in /usr/sbin/apache2 /usr/sbin/httpd; do [ -x "$p" ] && bin="$p" && break; done
[ -z "$bin" ] && exit 0
vline=$("$bin" -v 2>&1)
ver=$(printf "%s" "$vline" | sed -n "s#.*Apache/\([0-9][0-9.]*\).*#\1#p" | head -n1)
[ -n "$ver" ] && echo "VER $ver"
mods=""
if command -v apache2ctl >/dev/null 2>&1; then mods=$(apache2ctl -M 2>/dev/null)
elif command -v apachectl >/dev/null 2>&1; then mods=$(apachectl -M 2>/dev/null)
else mods=$("$bin" -M 2>/dev/null); fi
if [ -n "$mods" ]; then
  printf "%s" "$mods" | grep -qi "http2_module" && echo "HTTP2 1" || echo "HTTP2 0"
else
  echo "HTTP2 unk"
fi
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
    $http2line = ($out | Where-Object { $_ -match '^HTTP2 ' } | Select-Object -First 1 | ForEach-Object { ($_ -split ' ', 2)[1] })
    if (-not $ver) { continue }
    Write-Host "  conteneur $c : version=$ver http2=$http2line"
    if ($http2line -eq '0') { Write-Host "      module mod_http2 non chargé — non concerné." }
    elseif ($http2line -eq 'unk') { Add-Finding UNKNOWN "conteneur $c : liste des modules illisible -- impossible de confirmer si mod_http2 est chargé" }
    else { Add-ApacheVersionFinding $ver "conteneur $c" }
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
      $http2line = ($out | Where-Object { $_ -match '^HTTP2 ' } | Select-Object -First 1 | ForEach-Object { ($_ -split ' ', 2)[1] })
      if (-not $ver) { continue }
      Write-Host "  image $img : version=$ver http2=$http2line"
      if ($http2line -eq '0') { Write-Host "      module mod_http2 non chargé — non concerné." }
      elseif ($http2line -eq 'unk') { Add-Finding UNKNOWN "image $img : liste des modules illisible -- impossible de confirmer si mod_http2 est chargé" }
      else { Add-ApacheVersionFinding $ver "image $img" }
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
  Write-Host "[VULNÉRABLE] $($Counts.VULNERABLE) installation(s) Apache < 2.4.71 avec mod_http2 chargé. Mettre à jour vers 2.4.71+ en priorité, ou désactiver mod_http2 en attendant (voir correction)." -ForegroundColor Red
} elseif ($Counts.UNKNOWN -gt 0) {
  $Verdict = 'À VÉRIFIER'
  Write-Host "[À VÉRIFIER] $($Counts.UNKNOWN) élément(s) sans verdict automatique fiable (version non lisible, modules non listables, etc.). Compléter à la main." -ForegroundColor Yellow
} elseif ($Counts.OK -gt 0) {
  $Verdict = 'OK'
  Write-Host "[OK] Apache détecté avec mod_http2 actif, toutes les versions sont >= 2.4.71." -ForegroundColor Green
} else {
  Write-Host "[NON CONCERNÉ] Aucun Apache vulnérable trouvé (absent, ou mod_http2 non chargé partout) dans le périmètre scanné." -ForegroundColor Green
}

Write-Host ""
if ($Verdict -eq 'VULNÉRABLE') {
  Write-Host "Confiance : élément vulnérable CONFIRMÉ — pas d'ambiguïté, agir rapidement (cf. ci-dessus)." -ForegroundColor Red
} elseif ($Verdict -eq 'À VÉRIFIER') {
  Write-Host "Confiance : INCOMPLÈTE — au moins un élément nécessite une vérification manuelle avant de pouvoir conclure." -ForegroundColor Yellow
} elseif ($ScanImages) {
  Write-Host "Confiance : COMPLÈTE dans la limite de ce script — hôte, conteneurs actifs ET images Docker Desktop locales ont tous été sondés." -ForegroundColor Green
} else {
  Write-Host "Confiance : PARTIELLE — mode lecture seule : seuls l'hôte et les conteneurs ACTIFS ont été inspectés. Relancer avec -ScanImages pour être certain." -ForegroundColor Yellow
}
Write-Host "[LIMITE] Ce script n'exploite pas la faille et ne prouve pas l'absence de compromission. Les binaires trouvés par recherche sur disque ou par un processus/service déjà en cours ne sont jamais exécutés (sécurité) : leur version est lue statiquement, et le statut mod_http2 est déduit d'une lecture statique de conf\httpd.conf voisin (best-effort, peut échouer sur une disposition de fichiers non standard). Les conteneurs Windows natifs (non-WSL2) ne sont pas sondés par la commande 'sh' utilisée ici. Le module standalone mod_h2 (projet GitHub icing/mod_h2, build séparé) n'est pas distingué du module intégré par ce script Windows -- voir README pour ce cas sur Linux."
Write-Host "Références : https://httpd.apache.org/security/vulnerabilities_24.html  |  https://security-tracker.debian.org/  |  https://ubuntu.com/security/notices/"

switch ($Verdict) {
  'VULNÉRABLE'  { exit 2 }
  'À VÉRIFIER'  { exit 1 }
  default       { exit 0 }
}
