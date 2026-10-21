<#
.SYNOPSIS
  ORBITRON php2shell exposure checker (Windows)   v1.0.0 (2026-10-21)
  CVE-2026-109618 / CVE-2026-109619 ("php2shell")

.DESCRIPTION
  READ-ONLY. Does not change configuration, install anything, open network
  connections or test for the vulnerability. It inventories PHP runtimes and
  reports:
    - php.exe / php-cgi.exe found in common install paths, PATH, running
      processes, IIS FastCGI configuration and Apache (XAMPP/WAMP) configs
    - effective session.upload_progress.* and related settings per runtime
      (evaluated with the same php.ini / -c / PHPRC that IIS FastCGI uses)
    - per-directory overrides (.user.ini / .htaccess) under IIS site roots
      and given web roots, plus "-d" overrides in FastCGI arguments
    - running PHP / web server processes
  Windows PHP builds are upstream builds, so fix status is decided by the
  upstream version once the fixed versions are configured.

.PARAMETER PhpPath     Additional php.exe / php-cgi.exe paths to inspect.
.PARAMETER WebRoot     Additional web roots to scan for .user.ini/.htaccess.
.PARAMETER DeepScan    Search all fixed drives for php*.exe (slow).
.PARAMETER Json        Print JSON only.
.PARAMETER OutFile     Write the JSON report to this file.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\php2shell-check.ps1 -OutFile report.json

.NOTES
  Exit codes: 0 = no PHP found, 1 = PHP found and all runtimes confirmed
  patched, 2 = PHP found and at least one runtime NOT confirmed patched.
  Requires Windows PowerShell 5.1+ (or PowerShell 7). Run elevated to read
  IIS configuration. License: MIT. Provided as-is, without warranty.
#>
[CmdletBinding()]
param(
  [string[]]$PhpPath = @(),
  [string[]]$WebRoot = @(),
  [switch]$DeepScan,
  [switch]$Json,
  [string]$OutFile
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Continue'

# Accept comma separated lists also when called via -File
$PhpPath = @($PhpPath | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
$WebRoot = @($WebRoot | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

$ScriptVersion   = '1.0.0'
$Cves            = @('CVE-2026-109618', 'CVE-2026-109619')
# EMPTY until the official PHP advisory is published (2026-10-21 14:00 UTC).
# Fill ONLY from https://www.php.net/ , e.g. '8.2.35 8.3.36 8.4.27 8.5.12'
$FixedUpstream   = if ($env:PHP2SHELL_FIXED_UPSTREAM) { $env:PHP2SHELL_FIXED_UPSTREAM } else { '' }
$SupportedBranch = @('8.2', '8.3', '8.4', '8.5')
$Keys = @('session.upload_progress.enabled', 'session.upload_progress.cleanup', 'session.upload_progress.name',
          'session.upload_progress.prefix', 'session.use_strict_mode', 'session.save_handler',
          'session.save_path', 'file_uploads', 'cgi.fix_pathinfo')

function Say([string]$m) { if (-not $Json) { Write-Host $m } }
function Hr { Say ('-' * 78) }
$IsWin = ($env:OS -eq 'Windows_NT')

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
function Invoke-PhpInfo {
  param([string]$Exe, [string]$ExtraArgs = '', [hashtable]$EnvVars = @{})
  try {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $Exe
    $psi.Arguments = ("$ExtraArgs -i").Trim()
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    foreach ($k in $EnvVars.Keys) { $psi.EnvironmentVariables[$k] = $EnvVars[$k] }
    $p = [System.Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $null = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit(20000)) { try { $p.Kill() } catch {}; return $null }
    return $outTask.Result
  } catch { return $null }
}

function ConvertFrom-PhpInfo([string]$Raw) {
  # phpinfo() as text (php.exe) or HTML (php-cgi.exe) -> hashtable key => local value
  $h = @{}
  if (-not $Raw) { return $h }
  $t = $Raw -replace '</td><td[^>]*>', ' => ' -replace '<[^>]+>', '' -replace '&nbsp;', ' ' -replace '&quot;', '"'
  foreach ($line in ($t -split "`r?`n")) {
    $parts = $line -split '\s*=>\s*'
    if ($parts.Count -ge 2) {
      $k = $parts[0].Trim()
      if ($k -and -not $h.ContainsKey($k)) { $h[$k] = $parts[1].Trim() }
    }
  }
  return $h
}

function Get-Branch([string]$v) { if ($v -match '^(\d+\.\d+)') { $Matches[1] } else { '' } }

function Get-FixStatus([string]$v) {
  if (-not $FixedUpstream) { return 'pending - official advisory not yet published' }
  $br = Get-Branch $v
  foreach ($fv in ($FixedUpstream -split '\s+' | Where-Object { $_ })) {
    if ((Get-Branch $fv) -eq $br) {
      try {
        $cur = [version]($v -replace '[^0-9.].*$', '')
        $fix = [version]$fv
        if ($cur -ge $fix) { return "patched (upstream >= $fv)" } else { return "NOT PATCHED (upstream < $fv)" }
      } catch { return "unknown (could not parse version '$v')" }
    }
  }
  return "NOT PATCHED - no upstream fix for branch $br (upgrade required)"
}

function Expand-Path([string]$p) {
  if (-not $p) { return $p }
  [Environment]::ExpandEnvironmentVariables($p.Trim('"'))
}

# ----------------------------------------------------------------------------
# 1. Discover runtimes (exe + how it is launched)
# ----------------------------------------------------------------------------
$targets = New-Object System.Collections.ArrayList   # objects: Exe, Args, Env, Source
function Add-Target([string]$Exe, [string]$ArgStr = '', [hashtable]$EnvVars = @{}, [string]$Source = '') {
  if (-not $Exe) { return }
  $Exe = Expand-Path $Exe
  if (-not (Test-Path -LiteralPath $Exe -PathType Leaf)) { return }
  $full = (Resolve-Path -LiteralPath $Exe).ProviderPath
  $envKey = ($EnvVars.GetEnumerator() | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join ';'
  foreach ($t in $targets) {
    if ($t.Exe -eq $full -and $t.Args -eq $ArgStr -and $t.EnvKey -eq $envKey) {
      if ($t.Source -notlike "*$Source*") { $t.Source = "$($t.Source), $Source" }
      return
    }
  }
  [void]$targets.Add([pscustomobject]@{ Exe = $full; Args = $ArgStr; Env = $EnvVars; EnvKey = $envKey; Source = $Source })
}

$siteRoots = New-Object System.Collections.ArrayList
$fastCgiOverrides = New-Object System.Collections.ArrayList

# 1a. IIS FastCGI + site roots
$appHost = if ($env:windir) { Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config' } else { '' }
if ($IsWin -and $appHost -and (Test-Path -LiteralPath $appHost)) {
  try {
    [xml]$x = Get-Content -LiteralPath $appHost -Raw
    $apps = $x.SelectNodes('//system.webServer/fastCgi/application')
    foreach ($a in $apps) {
      $envs = @{}
      foreach ($ev in $a.SelectNodes('environmentVariables/environmentVariable')) { $envs[$ev.name] = Expand-Path $ev.value }
      $argStr = [string]$a.arguments
      Add-Target -Exe $a.fullPath -ArgStr $argStr -EnvVars $envs -Source 'IIS FastCGI'
      if ($argStr -match 'session\.upload_progress') { [void]$fastCgiOverrides.Add("IIS FastCGI arguments: $($a.fullPath) $argStr") }
    }
    foreach ($vd in $x.SelectNodes('//sites/site/application/virtualDirectory')) {
      $pp = Expand-Path $vd.physicalPath
      if ($pp -and (Test-Path -LiteralPath $pp)) { [void]$siteRoots.Add($pp) }
    }
  } catch { Say "WARNING: could not parse $appHost ($($_.Exception.Message)). Run elevated." }
}

# 1b. Apache httpd.conf (XAMPP, WAMP, Apache Lounge)
$apacheConfs = @()
foreach ($g in @('C:\xampp\apache\conf\httpd.conf', 'C:\Apache24\conf\httpd.conf', 'C:\wamp*\bin\apache\*\conf\httpd.conf',
                 'C:\Program Files\Apache*\conf\httpd.conf', 'C:\laragon\bin\apache\*\conf\httpd.conf')) {
  if ($IsWin) { $apacheConfs += @(Get-ChildItem -Path $g -ErrorAction SilentlyContinue) }
}
foreach ($c in $apacheConfs) {
  $txt = Get-Content -LiteralPath $c.FullName -ErrorAction SilentlyContinue
  $iniDir = ($txt | Where-Object { $_ -match '^\s*PHPIniDir\s+"?([^"]+)"?' } | Select-Object -First 1)
  if ($iniDir -and ($iniDir -match '^\s*PHPIniDir\s+"?([^"]+)"?')) { $iniDir = $Matches[1] } else { $iniDir = $null }
  $mod = ($txt | Where-Object { $_ -match '^\s*LoadModule\s+php\w*_module\s+"?([^"]+)"?' } | Select-Object -First 1)
  if ($mod -and ($mod -match '^\s*LoadModule\s+php\w*_module\s+"?([^"]+)"?')) {
    $modDir = Split-Path -Parent $Matches[1]
    $phpExe = Join-Path $modDir 'php.exe'
    $argStr = ''
    if ($iniDir) { $argStr = "-c `"$iniDir`"" }
    Add-Target -Exe $phpExe -ArgStr $argStr -Source "Apache mod_php ($($c.FullName))"
  }
  foreach ($l in ($txt | Where-Object { $_ -match '^\s*DocumentRoot\s+"?([^"]+)"?' })) {
    if ($l -match '^\s*DocumentRoot\s+"?([^"]+)"?' -and (Test-Path -LiteralPath $Matches[1])) { [void]$siteRoots.Add($Matches[1]) }
  }
  foreach ($l in ($txt | Select-String -Pattern 'session\.upload_progress')) {
    [void]$fastCgiOverrides.Add("Apache config: $($c.FullName):$($l.LineNumber): $($l.Line.Trim())")
  }
}

# 1c. Common install locations
$globs = @('C:\php*', 'C:\tools\php*', 'C:\xampp\php', 'C:\wamp*\bin\php\php*', 'C:\laragon\bin\php\*',
           "$env:ProgramFiles\PHP*", "$env:ProgramFiles\PHP\*", "${env:ProgramFiles(x86)}\PHP*", "${env:ProgramFiles(x86)}\PHP\*",
           "$env:ProgramFiles\iis express\PHP\*", "${env:ProgramFiles(x86)}\iis express\PHP\*",
           "${env:ProgramFiles(x86)}\Plesk\Additional\PleskPHP*", "${env:ProgramFiles(x86)}\Parallels\Plesk\Additional\PleskPHP*",
           "$env:ProgramFiles\Plesk\Additional\PleskPHP*")
if ($IsWin) {
  foreach ($g in $globs) {
    foreach ($d in @(Get-ChildItem -Path $g -Directory -ErrorAction SilentlyContinue)) {
      foreach ($n in @('php.exe', 'php-cgi.exe')) { Add-Target -Exe (Join-Path $d.FullName $n) -Source 'install path' }
    }
  }
}

# 1d. PATH
foreach ($n in @('php.exe', 'php-cgi.exe', 'php', 'php-cgi')) {
  foreach ($cmd in @(Get-Command $n -All -CommandType Application -ErrorAction SilentlyContinue)) { Add-Target -Exe $cmd.Source -Source 'PATH' }
}

# 1e. Running processes
$procList = @()
try {
  if ($IsWin) {
    $procList = @(Get-CimInstance Win32_Process -ErrorAction Stop | Select-Object Name, ExecutablePath, ProcessId)
  } else {
    $procList = @(Get-Process -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{ Name = $_.ProcessName; ExecutablePath = $_.Path; ProcessId = $_.Id } })
  }
} catch { $procList = @() }
foreach ($p in $procList) {
  if ($p.Name -match '^php(-cgi)?(\.exe)?$' -and $p.ExecutablePath) { Add-Target -Exe $p.ExecutablePath -Source 'running process' }
}

# 1f. Explicit + deep scan
foreach ($pp in $PhpPath) { Add-Target -Exe $pp -Source 'parameter' }
if ($DeepScan -and $IsWin) {
  Say 'Deep scan of fixed drives - this can take several minutes...'
  foreach ($drv in @(Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null })) {
    Get-ChildItem -Path $drv.Root -Recurse -Include 'php.exe', 'php-cgi.exe' -File -Force -ErrorAction SilentlyContinue |
      ForEach-Object { Add-Target -Exe $_.FullName -Source 'deep scan' }
  }
}

# ----------------------------------------------------------------------------
# 2. Inspect runtimes
# ----------------------------------------------------------------------------
Say "ORBITRON php2shell exposure checker v$ScriptVersion  |  $($Cves -join ' ')"
$hostName = [Environment]::MachineName
$osName = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { [Environment]::OSVersion.VersionString }
$now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
Say "Host: $hostName  |  OS: $osName  |  $now"
if (-not $FixedUpstream) { Say 'NOTE: fixed versions not configured yet (official advisory pending).' }

$runtimes = New-Object System.Collections.ArrayList
$anyUnpatched = $false
foreach ($t in $targets) {
  $raw = Invoke-PhpInfo -Exe $t.Exe -ExtraArgs $t.Args -EnvVars $t.Env
  $info = ConvertFrom-PhpInfo $raw
  $ver = $info['PHP Version']
  if (-not $ver) {
    try { $ver = (Get-Item -LiteralPath $t.Exe).VersionInfo.ProductVersion } catch { $ver = '' }
  }
  $br = Get-Branch $ver
  $branchState = if ($SupportedBranch -contains $br) { 'upstream-supported' } else { 'upstream-EOL' }
  $fs = Get-FixStatus $ver
  if ($fs -notlike 'patched*') { $anyUnpatched = $true }
  $settings = [ordered]@{}
  foreach ($k in $Keys) { $settings[$k] = if ($info.ContainsKey($k)) { $info[$k] } else { '' } }

  Hr
  Say "Binary   : $($t.Exe) $($t.Args)"
  Say "Source   : $($t.Source)"
  if ($t.Env.Count -gt 0) { Say ("Env      : " + (($t.Env.GetEnumerator() | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join '; ')) }
  Say "Version  : $ver   (branch ${br}: $branchState)"
  Say "SAPI     : $($info['Server API'])"
  Say "php.ini  : $($info['Loaded Configuration File'])"
  Say "Fix      : $fs"
  if (-not $raw) { Say '   WARNING: could not run phpinfo (-i); settings unknown' }
  foreach ($k in $Keys) { Say ('   {0,-34} {1}' -f $k, $(if ($settings[$k]) { $settings[$k] } else { '<not set>' })) }
  if ($settings['session.upload_progress.enabled'] -match '^(On|1)$') {
    Say '   -> session.upload_progress.enabled is ON (partial mitigation NOT applied; patch is still required)'
  }
  if ($branchState -eq 'upstream-EOL') { Say "   -> Branch $br gets no upstream fix: upgrade to a supported branch." }

  [void]$runtimes.Add([ordered]@{
    binary = $t.Exe; arguments = $t.Args; source = $t.Source; version = $ver; branch = $br
    branch_state = $branchState; server_api = $info['Server API']; php_ini = $info['Loaded Configuration File']
    fix_status = $fs; settings = $settings
  })
}

# ----------------------------------------------------------------------------
# 3. Per-directory and launcher overrides
# ----------------------------------------------------------------------------
Hr
Say 'Overrides of session.upload_progress.* (FastCGI args / Apache config / per-directory):'
$overrides = New-Object System.Collections.ArrayList
foreach ($o in $fastCgiOverrides) { [void]$overrides.Add($o); Say "   $o" }
$roots = @($siteRoots) + @($WebRoot) + @('C:\inetpub\wwwroot', 'C:\xampp\htdocs') | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
foreach ($r in $roots) {
  $files = @(Get-ChildItem -LiteralPath $r -Recurse -Depth 8 -Force -File -Include '.user.ini', '.htaccess' -ErrorAction SilentlyContinue)
  foreach ($f in $files) {
    foreach ($m in @(Select-String -LiteralPath $f.FullName -Pattern '^[^;#]*session\.upload_progress' -ErrorAction SilentlyContinue)) {
      $s = "$($f.FullName):$($m.LineNumber): $($m.Line.Trim())"
      [void]$overrides.Add($s); Say "   [per-dir] $s"
    }
  }
}
if ($overrides.Count -eq 0) { Say '   none found (php.ini values above apply)' }
Say '   Note: .user.ini applies to php-cgi (IIS FastCGI); .htaccess php_flag to Apache mod_php only.'

# ----------------------------------------------------------------------------
# 4. Processes
# ----------------------------------------------------------------------------
Hr
Say 'Running PHP / web server processes:'
$procSummary = @($procList | Where-Object { $_.Name -match '^(php|php-cgi|httpd|w3wp|nginx)(\.exe)?$' } |
  Group-Object Name | ForEach-Object { "$($_.Count)x $($_.Name)" })
if ($procSummary.Count -eq 0) { Say '   none' } else { $procSummary | ForEach-Object { Say "   $_" } }

# ----------------------------------------------------------------------------
# 5. Result
# ----------------------------------------------------------------------------
Hr
if ($runtimes.Count -eq 0) {
  $result = 'no-php-found'; $rc = 0
  Say 'RESULT: no PHP runtime found (use -DeepScan or -PhpPath for custom locations).'
} elseif ($anyUnpatched) {
  $result = 'php-found-not-confirmed-patched'; $rc = 2
  Say "RESULT: PHP found - at least one runtime is NOT confirmed patched against $($Cves -join ' ')."
  Say '        Replace PHP with the fixed build as soon as it is published on windows.php.net;'
  Say '        until then: session.upload_progress.enabled=0 (partial mitigation only),'
  Say '        restrict exposure and enable the ORBITRON php2shell detection rules.'
} else {
  $result = 'php-found-all-confirmed-patched'; $rc = 1
  Say 'RESULT: PHP found - all runtimes confirmed patched (upstream version).'
}

$report = [ordered]@{
  tool = 'orbitron-php2shell-check'; tool_version = $ScriptVersion; cves = $Cves; timestamp = $now
  host = $hostName; os = $osName; fixed_upstream_configured = $FixedUpstream; result = $result
  runtimes = @($runtimes); overrides = @($overrides); processes = @($procSummary)
}
$jsonText = $report | ConvertTo-Json -Depth 6
if ($Json) { Write-Output $jsonText }
if ($OutFile) { $jsonText | Out-File -FilePath $OutFile -Encoding utf8; Say "JSON report written to $OutFile" }
exit $rc
