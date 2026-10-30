<#
.SYNOPSIS
  Script UNIQUE et autonome (n'appelle aucun autre fichier), en LECTURE SEULE par défaut,
  pour Windows. Audite la machine locale pour Broccoli2Shell / Node2Shell / HTTP2Shell
  (CVE-2026-111497, décodeur Brotli). Voir README.md pour l'explication complète.

.DESCRIPTION
  Recherche les composants qui embarquent un décodeur Brotli vulnérable :
  .NET (runtimes partagés + applications autonomes "self-contained"), Python
  (Brotli/brotlicffi), Node.js, IIS (module de compression brotli.dll — à
  vérifier séparément, ce n'est pas le même code), copies embarquées connues
  (7-Zip, DuckDB, woff2…), et conteneurs Docker Desktop (WSL2/Linux).

  DEUX MODES :
    - Lecture seule (PAR DÉFAUT) : inspecte l'hôte et exécute une commande de lecture dans
      les conteneurs Docker Desktop DÉJÀ EN COURS D'EXÉCUTION (docker exec). Ne crée, ne
      démarre, ne modifie et ne supprime RIEN.
    - -ScanImages : en plus du mode lecture seule, lance un conteneur ÉPHÉMÈRE et ISOLÉ
      (docker run --rm --network none) pour chaque image locale, le temps d'y chercher une
      bibliothèque Brotli vulnérable, puis le détruit immédiatement. C'est le seul mode qui
      peut révéler une image vulnérable qui n'est PAS actuellement démarrée (donc invisible
      en lecture seule) — nécessaire pour être réellement certain que la machine n'est pas
      concernée.

  N'exploite rien. Ne modifie rien.

  Avant toute vérification, la section « 0. Prérequis » contrôle la version de PowerShell
  et les commandes disponibles (dotnet.exe, docker.exe, node.exe) et affiche ce qui sera
  ignoré en conséquence — jamais une erreur brute.

.PARAMETER Path
  Répertoires où chercher les fichiers *.runtimeconfig.json, *.dist-info
  (Python) et les binaires à copie embarquée. Par défaut : quelques racines
  de déploiement courantes (IIS, Program Files, ProgramData).

.PARAMETER Fast
  Ignore la recherche sur le système de fichiers (rapide, mais ne détecte
  que les runtimes/paquets installés via leurs gestionnaires standards).

.PARAMETER ScanImages
  Sonde aussi les images Docker Desktop locales via un conteneur éphémère
  (--network none, détruit après usage). Sans cette option : lecture seule.

.EXAMPLE
  .\Test-Broccoli2Shell.ps1
.EXAMPLE
  .\Test-Broccoli2Shell.ps1 -ScanImages -Path 'D:\apps','E:\sites'
#>

[CmdletBinding()]
param(
  [string[]]$Path = @('C:\inetpub', 'C:\Program Files', 'C:\Program Files (x86)', 'C:\ProgramData'),
  [switch]$Fast,
  [switch]$ScanImages
)

$ErrorActionPreference = 'SilentlyContinue'

function Write-Section($title) { Write-Host "`n===== $title =====" -ForegroundColor Cyan }

Write-Host "Broccoli2Shell (CVE-2026-111497) — inventaire local"
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
$dotnetExe = Get-Command dotnet.exe -ErrorAction SilentlyContinue
$dockerExe = Get-Command docker.exe -ErrorAction SilentlyContinue
$nodeExe   = Get-Command node.exe -ErrorAction SilentlyContinue

function Write-Req($name, $ok, $koText) {
  Write-Host ("  {0,-12} {1}" -f $name, $(if ($ok) { 'disponible' } else { $koText }))
}
Write-Req 'PowerShell' $PsOk 'ko (voir ERREUR ci-dessus)'
Write-Req 'dotnet.exe' ([bool]$dotnetExe) 'absent -> runtimes .NET partagés non listés (self-contained toujours recherché via -Path)'
Write-Req 'docker.exe' ([bool]$dockerExe) 'absent -> conteneurs/images Docker Desktop non sondés'
Write-Req 'node.exe'   ([bool]$nodeExe)   'absent'
if ($Fast) { Write-Host "  (-Fast : recherche sur le système de fichiers ignorée pour Python/.NET self-contained/copies embarquées)" }

if (-not $PsOk) {
  Write-Host ""
  Write-Host "[ERREUR] Prérequis non satisfaits, arrêt avant toute vérification." -ForegroundColor Red
  exit 1
}

# ---- Tables de versions corrigées (vérifiées au 30/10/2026 — à recontrôler si la date a changé) ----
$DotnetFixed = @{ '8' = [version]'8.0.33'; '9' = [version]'9.0.22'; '10' = [version]'10.0.14' }
$PyBrotliFixed     = '1.2.1'
$PyBrotliCffiFixed = '1.2.1.0'
$NodeFixedLines    = @('22.23.4', '24.22.1', '26.12.1')  # lignes EOL (20.x et antérieures, 21.x, 23.x, 25.x) : pas de correctif, migration nécessaire

$Findings = New-Object System.Collections.Generic.List[string]
$Counts = @{ VULNERABLE = 0; OK = 0; UNKNOWN = 0 }

function Add-Finding {
  param([ValidateSet('VULNERABLE','OK','UNKNOWN')][string]$Verdict, [string]$Text)
  $Counts[$Verdict]++
  $tag = switch ($Verdict) { 'VULNERABLE' { '[VULNÉRABLE] ' } 'OK' { '[CORRIGÉ]    ' } default { '[À VÉRIFIER] ' } }
  $Findings.Add("$tag $Text")
}

function Compare-SemVer {
  # Compare deux chaînes "X.Y.Z[.W]" ; renvoie $true si $a < $b. Repli simple si le parse échoue.
  param([string]$a, [string]$b)
  try {
    $va = [version]($a -replace '[^0-9.]', '')
    $vb = [version]($b -replace '[^0-9.]', '')
    return ($va -lt $vb)
  } catch {
    return ([string]::Compare($a, $b, [System.StringComparison]::Ordinal) -lt 0)
  }
}

# ============================================================
Write-Section "1. .NET — runtimes partagés"
# ============================================================
if ($dotnetExe) {
  $runtimes = & $dotnetExe.Source --list-runtimes 2>$null
  $runtimes | ForEach-Object { Write-Host "  $_" }
  foreach ($line in $runtimes) {
    if ($line -match '^(Microsoft\.(?:NETCore|AspNetCore)\.App)\s+([0-9.]+)') {
      $name = $Matches[1]; $ver = $Matches[2]
      try { $major = ([version]$ver).Major } catch { $major = $null }
      if ($major -and $DotnetFixed.ContainsKey("$major")) {
        $fixedVer = $DotnetFixed["$major"]
        if ([version]$ver -lt $fixedVer) {
          Add-Finding VULNERABLE "hôte : $name $ver (< $fixedVer)"
        } else {
          Add-Finding OK "hôte : $name $ver (>= $fixedVer)"
        }
      } else {
        Add-Finding UNKNOWN "hôte : $name $ver — branche .NET 11+ ou EOL, vérifier l'avis Microsoft (dotnet.microsoft.com/platform/support) directement."
      }
    }
  }
} else {
  Write-Host "  dotnet.exe non trouvé dans le PATH : runtimes partagés non listés."
}

Write-Host "-- Déploiements .NET autonomes (self-contained) : embarquent leur propre runtime, invisibles ci-dessus --"
if (-not $Fast) {
  $cfgFiles = foreach ($p in $Path) {
    if (Test-Path $p) { Get-ChildItem -Path $p -Filter '*.runtimeconfig.json' -Recurse -File -ErrorAction SilentlyContinue }
  }
  if ($cfgFiles) {
    foreach ($f in $cfgFiles) {
      try {
        $json = Get-Content $f.FullName -Raw | ConvertFrom-Json
        $fw = $json.runtimeOptions.framework
        if (-not $fw) { $fw = $json.runtimeOptions.frameworks | Select-Object -First 1 }
        if ($fw) {
          $name = $fw.name; $ver = $fw.version
          Write-Host "  $($f.FullName) -> $name $ver"
          try { $major = ([version]$ver).Major } catch { $major = $null }
          if ($major -and $DotnetFixed.ContainsKey("$major")) {
            $fixedVer = $DotnetFixed["$major"]
            if ([version]$ver -lt $fixedVer) { Add-Finding VULNERABLE "self-contained $($f.FullName) : $name $ver (< $fixedVer)" }
            else { Add-Finding OK "self-contained $($f.FullName) : $name $ver (>= $fixedVer)" }
          } else {
            Add-Finding UNKNOWN "self-contained $($f.FullName) : $name $ver — vérifier manuellement."
          }
        }
      } catch { Write-Host "  $($f.FullName) -> illisible" }
    }
  } else {
    Write-Host "  Aucun *.runtimeconfig.json trouvé sous : $($Path -join ', ')"
  }
} else {
  Write-Host "  (-Fast : recherche sur le système de fichiers ignorée)"
}

# ============================================================
Write-Section "2. IIS — module de compression Brotli"
# ============================================================
$brotliDll = Get-ChildItem -Path "$env:SystemRoot\System32\inetsrv" -Filter 'brotli.dll' -ErrorAction SilentlyContinue
if ($brotliDll) {
  foreach ($d in $brotliDll) { Write-Host "  $($d.FullName) : version fichier $($d.VersionInfo.FileVersion)" }
  Add-Finding UNKNOWN "IIS brotli.dll présent — implémentation Microsoft distincte de celle de Google/Brotli ; vérifier le correctif via Windows Update / l'avis IIS, pas via ce script."
} else {
  Write-Host "  Module IIS brotli.dll non trouvé (IIS absent ou compression Brotli non installée)."
}

# ============================================================
Write-Section "3. Python — paquets Brotli / brotlicffi"
# ============================================================
$found = $false
if (-not $Fast) {
  $searchRoots = $Path + @("$env:LOCALAPPDATA\Programs\Python", 'C:\Python*', 'C:\ProgramData\Anaconda3', 'C:\ProgramData\Miniconda3')
  $diFolders = foreach ($p in $searchRoots) {
    if (Test-Path $p) { Get-ChildItem -Path $p -Directory -Recurse -ErrorAction SilentlyContinue -Filter '*brotli*' |
        Where-Object { $_.Name -match '\.dist-info$' } }
  }
  foreach ($di in $diFolders) {
    $found = $true
    $meta = Join-Path $di.FullName 'METADATA'
    $name = ($di.Name -replace '-[0-9].*$', '')
    $ver = $null
    if (Test-Path $meta) { $ver = (Select-String -Path $meta -Pattern '^Version:\s*(.+)$' | Select-Object -First 1).Matches[0].Groups[1].Value }
    Write-Host "  $($di.FullName) -> $name $ver"
    if ($ver) {
      switch -Regex ($name.ToLower()) {
        '^brotli$'     { if (Compare-SemVer $ver $PyBrotliFixed)     { Add-Finding VULNERABLE "Python Brotli $ver (< $PyBrotliFixed) dans $($di.FullName)" }     else { Add-Finding OK "Python Brotli $ver dans $($di.FullName)" } }
        '^brotlicffi$' { if (Compare-SemVer $ver $PyBrotliCffiFixed) { Add-Finding VULNERABLE "Python brotlicffi $ver (< $PyBrotliCffiFixed) dans $($di.FullName)" } else { Add-Finding OK "Python brotlicffi $ver dans $($di.FullName)" } }
      }
    }
  }
}
if (-not $found) { Write-Host "  Aucun paquet Python Brotli/brotlicffi trouvé sous : $($Path -join ', ') (recherche limitée, pas un scan disque complet)." }
Write-Host "  Rappel : si la mise à jour est impossible, désinstaller Brotli/brotlicffi fait retomber les clients HTTP (urllib3/requests/aiohttp/httpx) sur gzip/deflate."

# ============================================================
Write-Section "4. Node.js"
# ============================================================
if ($nodeExe) {
  $v = (& $nodeExe.Source -v 2>$null) -replace '^v', ''
  Write-Host "  $($nodeExe.Source) -> v$v"
  $okLine = $false
  foreach ($f in $NodeFixedLines) {
    $vMajor = ($v -split '\.')[0]; $fMajor = ($f -split '\.')[0]
    if ($vMajor -eq $fMajor -and -not (Compare-SemVer $v $f)) { $okLine = $true }
  }
  if ($okLine) { Add-Finding OK "Node.js $v ($($nodeExe.Source))" }
  else { Add-Finding VULNERABLE "Node.js $v ($($nodeExe.Source)) — comparer à la ligne majeure correspondante (corrigé : $($NodeFixedLines -join ', ')) ; lignes EOL (20.x et antérieures, 21.x, 23.x, 25.x) sans correctif, migration nécessaire" }
} else {
  Write-Host "  node.exe non trouvé dans le PATH."
}

# ============================================================
Write-Section "5. Copies embarquées connues de Brotli (7-Zip, DuckDB, woff2…)"
# ============================================================
if (-not $Fast) {
  $embedNames = @('duckdb.exe','7z.exe','7za.exe','7zr.exe','7zFM.exe','7zG.exe','woff2_compress.exe','woff2_decompress.exe')
  $embedFound = foreach ($p in $Path) {
    if (Test-Path $p) { Get-ChildItem -Path $p -Recurse -File -ErrorAction SilentlyContinue -Include $embedNames }
  }
  if ($embedFound) {
    foreach ($e in $embedFound) {
      Write-Host "  $($e.FullName) (version fichier : $($e.VersionInfo.FileVersion))"
      Add-Finding UNKNOWN "binaire embarquant potentiellement sa propre copie de Brotli : $($e.FullName) — vérifier l'éditeur, la mise à jour système ne le corrige pas."
    }
  } else {
    Write-Host "  Aucun binaire connu trouvé sous : $($Path -join ', ')"
  }
} else {
  Write-Host "  (-Fast : recherche ignorée)"
}

# ============================================================
Write-Section "6. Docker Desktop (conteneurs Linux via WSL2)"
# ============================================================
# Même sonde POSIX que la version bash/Linux, exécutée via docker exec / docker run.
$probe = @'
if [ -r /etc/os-release ]; then . /etc/os-release; echo "OSREL ${ID:-} ${VERSION_ID:-}"; fi
dpkg -l 2>/dev/null | awk "tolower(\$0) ~ /brotli/ {print \"PKGDPKG\",\$2,\$3}"
rpm -qa --qf "PKGRPM %{NAME} %{VERSION}-%{RELEASE}\n" 2>/dev/null | grep -i brotli
apk info -vv 2>/dev/null | awk "\$1 ~ /^brotli-libs-/ {n=\$1; sub(/^brotli-libs-/,\"\",n); print \"PKGAPK brotli-libs\",n}"
command -v node >/dev/null 2>&1 && echo "NODE $(node -v 2>/dev/null)"
command -v dotnet >/dev/null 2>&1 && dotnet --list-runtimes 2>/dev/null | sed "s/^/DOTNET /"
true
'@

if ($dockerExe) {
  $containers = & $dockerExe.Source ps --format '{{.Names}}' 2>$null
  Write-Host "-- conteneurs EN COURS (exec, lecture seule) --"
  foreach ($c in $containers) {
    $out = & $dockerExe.Source exec $c sh -c $probe 2>$null
    if (-not $out) { continue }
    Write-Host "  -- conteneur $c --"
    $out | ForEach-Object { Write-Host "    $_" }
    $cid = ($out | Where-Object { $_ -match '^OSREL' } | ForEach-Object { ($_ -split '\s+')[1] }) -join ''
    $cver = ($out | Where-Object { $_ -match '^OSREL' } | ForEach-Object { ($_ -split '\s+')[2] }) -join ''
    foreach ($line in $out) {
      if ($line -match '^NODE\s+v?([0-9.]+)') { Add-Finding UNKNOWN "conteneur $c : Node.js $($Matches[1]) — comparer à $($NodeFixedLines -join ', ')" }
      elseif ($line -match '^DOTNET\s+(\S+)\s+([0-9.]+)') { Add-Finding UNKNOWN "conteneur $c : .NET $($Matches[1]) $($Matches[2]) — comparer à 8.0.33/9.0.22/10.0.14/11 RC3+" }
      elseif ($line -match '^PKGDPKG\s+(\S+)\s+(\S+)') { Add-Finding UNKNOWN "conteneur $c : paquet $($Matches[1]) $($Matches[2]) (distro $cid $cver) — comparer à security-tracker.debian.org / ubuntu.com/security/notices pour cette distribution+version" }
      elseif ($line -match '^PKGAPK\s+(\S+)\s+(\S+)') { Add-Finding UNKNOWN "conteneur $c : $($Matches[1]) $($Matches[2]) (alpine $cver) — comparer à security.alpinelinux.org" }
      elseif ($line -match '^PKGRPM\s+(\S+)\s+(\S+)') { Add-Finding UNKNOWN "conteneur $c : paquet $($Matches[1]) $($Matches[2]) (rpm) — vérifier l'avis Red Hat/Fedora manuellement" }
    }
  }
  if ($ScanImages) {
    Write-Host "-- images locales (conteneur ÉPHÉMÈRE --network none, détruit après usage) --"
    $images = & $dockerExe.Source images --format '{{.Repository}}:{{.Tag}}' 2>$null | Where-Object { $_ -notmatch '<none>' } | Sort-Object -Unique
    foreach ($img in $images) {
      $out = & $dockerExe.Source run --rm --network none --entrypoint sh $img -c $probe 2>$null
      if (-not $out) { continue }
      Write-Host "  -- image $img --"
      $out | ForEach-Object { Write-Host "    $_" }
      foreach ($line in $out) {
        if ($line -match '^NODE\s+v?([0-9.]+)') { Add-Finding UNKNOWN "image $img : Node.js $($Matches[1]) — comparer à $($NodeFixedLines -join ', ')" }
        elseif ($line -match '^DOTNET\s+(\S+)\s+([0-9.]+)') { Add-Finding UNKNOWN "image $img : .NET $($Matches[1]) $($Matches[2]) — comparer à 8.0.33/9.0.22/10.0.14/11 RC3+" }
        elseif ($line -match '^PKGDPKG\s+(\S+)\s+(\S+)') { Add-Finding UNKNOWN "image $img : paquet $($Matches[1]) $($Matches[2]) — comparer à la distribution correspondante" }
        elseif ($line -match '^PKGAPK\s+(\S+)\s+(\S+)') { Add-Finding UNKNOWN "image $img : $($Matches[1]) $($Matches[2]) (alpine) — comparer à security.alpinelinux.org" }
        elseif ($line -match '^PKGRPM\s+(\S+)\s+(\S+)') { Add-Finding UNKNOWN "image $img : paquet $($Matches[1]) $($Matches[2]) (rpm) — vérifier manuellement" }
      }
    }
  } else {
    Write-Host "  (mode lecture seule : images locales non sondées — relancer avec -ScanImages pour les inclure)"
  }
} else {
  Write-Host "  docker.exe non trouvé (Docker Desktop absent ou non démarré) : section ignorée."
}

# ============================================================
Write-Section "7. Conclusion"
# ============================================================
$Findings | ForEach-Object { Write-Host $_ }
Write-Host ""
$Verdict = 'NON CONCERNÉ'
if ($Counts.VULNERABLE -gt 0) {
  $Verdict = 'VULNÉRABLE'
  Write-Host "[VULNÉRABLE] $($Counts.VULNERABLE) élément(s) confirmé(s) sous la version corrigée. Mettre à jour PUIS redémarrer les processus/pools IIS concernés : ils gardent le décodeur vulnérable en mémoire jusqu'au redémarrage." -ForegroundColor Red
} elseif ($Counts.UNKNOWN -gt 0) {
  $Verdict = 'À VÉRIFIER'
  Write-Host "[À VÉRIFIER] $($Counts.UNKNOWN) élément(s) sans verdict automatique fiable (IIS brotli.dll, conteneur à comparer manuellement, copie embarquée, .NET 11+, etc.). Compléter à la main." -ForegroundColor Yellow
} elseif ($Counts.OK -gt 0) {
  $Verdict = 'OK'
  Write-Host "[OK] Tous les éléments détectés sont à jour." -ForegroundColor Green
} else {
  Write-Host "[NON CONCERNÉ] Aucune trace de Brotli (.NET, Python, Node.js, IIS, Docker) trouvée dans le périmètre scanné." -ForegroundColor Green
}

Write-Host ""
if ($Verdict -eq 'VULNÉRABLE') {
  Write-Host "Confiance : élément vulnérable CONFIRMÉ — pas d'ambiguïté, agir immédiatement (cf. ci-dessus)." -ForegroundColor Red
} elseif ($Verdict -eq 'À VÉRIFIER') {
  Write-Host "Confiance : INCOMPLÈTE — au moins un élément nécessite une vérification manuelle avant de pouvoir conclure." -ForegroundColor Yellow
} elseif ($ScanImages) {
  Write-Host "Confiance : COMPLÈTE dans la limite de ce script — hôte, conteneurs actifs ET images Docker Desktop locales ont tous été sondés, aucune trace de Brotli vulnérable." -ForegroundColor Green
} else {
  Write-Host "Confiance : PARTIELLE — mode lecture seule : seuls l'hôte et les conteneurs ACTIFS ont été inspectés. Une image Docker Desktop locale non démarrée peut contenir un Brotli vulnérable sans apparaître ici. Relancer avec -ScanImages pour être certain." -ForegroundColor Yellow
}
Write-Host "[LIMITE] Ce script n'exploite pas la faille et ne prouve pas l'absence de compromission. La recherche sur disque est bornée aux chemins -Path (par défaut IIS/Program Files/ProgramData) : une application déployée ailleurs peut être invisible. Les conteneurs Windows (non-WSL2) ne sont pas sondés par la commande 'sh' utilisée ici."
Write-Host "Références : CVE-2026-111497 | GHSA-9v8h-qqgm-4m35 | https://msrc.microsoft.com/ | https://nodejs.org/en/blog/vulnerability/"

switch ($Verdict) {
  'VULNÉRABLE'  { exit 2 }
  'À VÉRIFIER'  { exit 1 }
  default       { exit 0 }
}
