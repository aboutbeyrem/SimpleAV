<#
.SYNOPSIS
  SimpleAV - lightweight malware scanner and real-time watcher for Windows.

.DESCRIPTION
  SimpleAV was built to detect and contain a real file-infector + loader infection
  (see docs/HOW-IT-WORKS.md). It finds:
    * program files carrying the infector's code (exact byte signature + structural heuristic)
    * real programs disguised as photos/documents (Deep scan)
    * tampered or unsigned Windows system files and DLL hijacks next to explorer.exe
    * malicious startup / persistence entries (Run keys, Winlogon, logon scripts, IFEO,
      scheduled tasks, WMI consumers, AppInit, startup folders)
    * suspicious processes (hidden encoded PowerShell, MSBuild abuse, infected programs running)

  Files containing the infector's EXACT code are quarantined automatically (can be turned off).
  Everything else is only reported - you decide what to do.

  SCOPE: the virus signature (12 exact bytes) matches ONE specific file-infector family. The other checks
  are generic rules based on that malware's techniques, not signatures for other families. SimpleAV is not
  a general-purpose antivirus - keep Windows Defender (or another antivirus) enabled.

.PARAMETER Scan        Full scan of C: (programs + system signatures + startup entries).
.PARAMETER Quick       Scan your user folder only.
.PARAMETER AllDrives   With -Scan: scan every fixed drive.
.PARAMETER Deep        Open EVERY file on every drive (not only programs) and check what it really is.
.PARAMETER Paths       Scan only these folders.
.PARAMETER SigAll      Also verify the digital signature of every program file (slow).
.PARAMETER SkipSystem  Skip the startup-entry and Windows-signature checks (used by the tests).
.PARAMETER Watch       Run the real-time watcher (tray icon + pop-up alerts).
.PARAMETER Quarantine  Move the given file into quarantine.
.PARAMETER Restore     Put a quarantined file back where it came from.
.PARAMETER Install     Install to %USERPROFILE%\SimpleAV, register the watcher (at logon) and a daily scan.
.PARAMETER Uninstall   Remove the scheduled tasks and stop the watcher (logs and quarantine are kept).
.PARAMETER NoPopup     Do not show notifications.
.PARAMETER NoAutoQuarantine  Report exact virus matches instead of quarantining them.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File SimpleAV.ps1 -Scan
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File SimpleAV.ps1 -Deep
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File SimpleAV.ps1 -Quarantine "C:\path\to\file.exe"

.NOTES
  Author : Beyrem
  Version: 1.3.0
  License: MIT
  Data   : %USERPROFILE%\SimpleAV  (override with the SIMPLEAV_HOME environment variable)
#>
param(
  [switch]$Scan, [switch]$Quick, [switch]$AllDrives, [switch]$Deep, [string[]]$Paths, [switch]$SigAll, [switch]$SkipSystem,
  [switch]$Watch, [string]$Quarantine, [string]$Restore, [switch]$Install, [switch]$Uninstall,
  [switch]$NoPopup, [switch]$NoAutoQuarantine, [switch]$TestAlert
)
if ($Deep) { $Scan = $true; $AllDrives = $true }

$ErrorActionPreference = 'SilentlyContinue'
# Byte-level PE inspection (exact 12-byte signature + structural check) and the version number live in one
# shared file, also used by the dashboard. See SimpleAV.Detection.ps1.
. (Join-Path $PSScriptRoot 'SimpleAV.Detection.ps1')
$Version = $SAV_Version   # defined in SimpleAV.Detection.ps1
# Lives in the user profile, NOT under AppData: some sandboxed apps redirect AppData writes.
$AppDir  = if ($env:SIMPLEAV_HOME) { $env:SIMPLEAV_HOME } else { Join-Path $env:USERPROFILE 'SimpleAV' }
$LogDir  = Join-Path $AppDir 'logs'
$QDir    = Join-Path $AppDir 'quarantine'
$ProgFile     = Join-Path $AppDir 'progress.json'
$SettingsFile = Join-Path $AppDir 'settings.json'
$SigCacheFile = Join-Path $AppDir 'sigcache.tsv'
# Exact-prefix match for SimpleAV's own folder. A -like "$AppDir*" wildcard would also skip "SimpleAVUpdate\",
# and breaks on paths that contain [ or ].
$AppPrefix = $AppDir.TrimEnd('\') + '\'
function Test-InAppDir([string]$p) { return ($p.Equals($AppDir.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) -or $p.StartsWith($AppPrefix, [StringComparison]::OrdinalIgnoreCase)) }
# Matches only SimpleAV's own installed scripts, so malware can't hide by putting "SimpleAV.ps1" in its command line.
$SelfCmdRx = '(?i)-File\s+"?(' + [regex]::Escape((Join-Path $AppDir 'SimpleAV')) + '|' + [regex]::Escape((Join-Path $PSScriptRoot 'SimpleAV')) + ')(-App)?\.ps1"?(\s|$)'
$null = New-Item -ItemType Directory -Force -Path $LogDir

$script:Findings    = New-Object System.Collections.Generic.List[object]
$script:LogFile     = $null
$script:Tray        = $null
$script:Skipped     = 0
$script:SkippedList = New-Object System.Collections.Generic.List[string]
$script:Unreadable  = 0
$script:LastWasPE   = $false
$script:ScanMode    = ''
$script:ScanStart   = ''

# ================================================================== detection data
# Placeholder-looking CLSID the loader used to store its payload in the registry.
$FakeClsid = '{A1B2C3D4-E5F6-7890-1234-567890ABCDEF}'
# Command lines typical of this kind of malware (hidden encoded PowerShell, script hosts, MSBuild abuse...).
$BadCmd = '(?i)(frombase64string|usercache|-enc(odedcommand)?\s|\s-e\s+[A-Za-z0-9+/=]{20}|mshta|wscript|cscript|\\msbuild\.exe|regsvr32.+(http|scrobj)|conhost(\.exe)?\s+--headless\s+.*powershell|\\appdata\\local\\temp\\.+\.(exe|dll|ps1|vbs|js|cmd|bat)|downloadstring|invoke-expression|iex\s*\()'
# Security tools that malware tries to block with "debugger" (IFEO) hijacks.
$SecurityTools = 'MpCmdRun.exe','MsMpEng.exe','MpDefenderCoreService.exe','mbam.exe','MBAMService.exe','mbamtray.exe','taskmgr.exe','explorer.exe','regedit.exe','cmd.exe','powershell.exe','SecHealthUI.exe','MRT.exe','msert.exe','procexp.exe','procexp64.exe','Autoruns.exe','Autoruns64.exe'
$SkipDirNames = '$Recycle.Bin','System Volume Information'
$PEExt = '.exe','.dll','.sys','.scr','.node','.cpl','.ocx','.drv','.efi','.pyd','.mui','.winmd','.ax','.ime','.acm','.tsp','.com','.mun'
# A real program hiding behind one of these extensions is a strong malware sign (e.g. a miner saved as .jpeg).
$DisguiseExt = '.jpg','.jpeg','.png','.gif','.bmp','.ico','.webp','.txt','.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.mp3','.mp4','.wav','.avi','.mkv','.mov','.zip','.rar','.7z','.json','.xml','.html','.htm','.css','.log','.ini','.cfg'

# ================================================================== settings
function Get-Settings {
  $s = [ordered]@{ AutoQuarantine = $true }
  if (Test-Path $SettingsFile) { try { $j = Get-Content $SettingsFile -Raw | ConvertFrom-Json; if ($null -ne $j.AutoQuarantine) { $s.AutoQuarantine = [bool]$j.AutoQuarantine } } catch {} }
  return [pscustomobject]$s
}
$AutoQ = (Get-Settings).AutoQuarantine -and -not $NoAutoQuarantine

# ================================================================== logging / progress / alerts
function Start-Log([string]$kind) {
  $script:LogFile = Join-Path $LogDir ("{0}_{1}.log" -f $kind, (Get-Date -Format 'yyyy-MM-dd_HH-mm-ss'))
  "SimpleAV $Version $kind log - started $(Get-Date)" | Set-Content -Path $script:LogFile -Encoding UTF8
}
function Write-Log([string]$msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
  if ($script:LogFile) { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 }
  Write-Host $line
}
function Add-Finding([string]$sev, [string]$kind, [string]$path, [string]$detail) {
  $f = [pscustomobject]@{ Time = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'); Severity = $sev; Kind = $kind; Path = $path; Detail = $detail }
  $script:Findings.Add($f)
  Write-Log ("{0,-6} {1,-26} {2}  -> {3}" -f $sev, $kind, $path, $detail)
  return $f
}
function Set-Progress([string]$state, [string]$phase, [int64]$files) {
  $h = 0; $m = 0
  foreach ($x in $script:Findings) { if ($x.Severity -eq 'HIGH') { $h++ } elseif ($x.Severity -eq 'MEDIUM') { $m++ } }
  $o = [ordered]@{ state = $state; phase = $phase; files = $files; high = $h; medium = $m; findings = $script:Findings.Count
                   pid = $PID; mode = $script:ScanMode; started = $script:ScanStart; updated = (Get-Date).ToString('s'); log = $script:LogFile }
  try { ($o | ConvertTo-Json -Compress) | Set-Content -Path $ProgFile -Encoding UTF8 } catch {}
}
function Init-Tray {
  Add-Type -AssemblyName System.Windows.Forms, System.Drawing
  $script:Tray = New-Object System.Windows.Forms.NotifyIcon
  $ico = Join-Path $AppDir 'SimpleAV.ico'; if (-not (Test-Path $ico)) { $ico = Join-Path $PSScriptRoot 'SimpleAV.ico' }
  $script:Tray.Icon = if (Test-Path $ico) { New-Object System.Drawing.Icon($ico, 16, 16) } else { [System.Drawing.SystemIcons]::Shield }
  $script:Tray.Text = 'SimpleAV is watching'
  $script:Tray.Visible = $true
  $script:Tray.add_BalloonTipClicked({ if ($script:LogFile) { Start-Process notepad.exe -ArgumentList "`"$script:LogFile`"" } })
  $script:Tray.add_DoubleClick({ $app = Join-Path $AppDir 'SimpleAV-App.ps1'; if (Test-Path $app) { Start-Process powershell.exe -ArgumentList "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$app`"" -WindowStyle Hidden } else { Start-Process explorer.exe -ArgumentList "`"$LogDir`"" } })
}
function Show-Alert([string]$title, [string]$text, [string]$level = 'Warning') {
  if ($NoPopup) { return }
  $own = $false
  if (-not $script:Tray) { Init-Tray; $own = $true }
  $script:Tray.BalloonTipIcon  = $level
  $script:Tray.BalloonTipTitle = $title
  $script:Tray.BalloonTipText  = if ($text.Length -gt 250) { $text.Substring(0, 247) + '...' } else { $text }
  $script:Tray.ShowBalloonTip(20000)
  if ($own) {   # one-shot pop-up (scan mode): keep it alive long enough to be clicked
    $end = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $end) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 200 }
    $script:Tray.Visible = $false; $script:Tray.Dispose(); $script:Tray = $null
  }
}

# ================================================================== file checks
# Returns $null if clean, otherwise a reason. Sets $script:LastWasPE when the file really is a Windows program.
function Test-PEInfected([string]$path) {
  $v = Get-PEVerdict $path
  $script:LastWasPE = $v.IsPE
  if ($v.Unreadable) { $script:Unreadable++ }
  return $v.Reason
}

# Walks a folder tree without following junctions; yields program files (or every file with -Deep).
function Get-ScanFiles([string]$root) {
  $stack = New-Object System.Collections.Generic.Stack[string]
  $stack.Push($root)
  while ($stack.Count -gt 0) {
    $d = $stack.Pop()
    try {
      foreach ($sub in [System.IO.Directory]::GetDirectories($d)) {
        if ($SkipDirNames -contains [System.IO.Path]::GetFileName($sub)) { continue }
        if (Test-InAppDir $sub) { continue }
        if (([System.IO.File]::GetAttributes($sub) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        $stack.Push($sub)
      }
    } catch { Add-Skipped $d $_; continue }
    try {
      foreach ($f in [System.IO.Directory]::GetFiles($d)) {
        if ($Deep -or ($PEExt -contains [System.IO.Path]::GetExtension($f).ToLowerInvariant())) { $f }
      }
    } catch { Add-Skipped $d $_ }
  }
}
function Add-Skipped([string]$dir, $err) {
  $script:Skipped++
  if ($script:SkippedList.Count -lt 200) {
    $why = if ($err.Exception -is [System.UnauthorizedAccessException]) { 'no permission' } else { $err.Exception.GetType().Name }
    $script:SkippedList.Add("$dir  ($why)")
  }
}
# selfhash.txt holds one "file|SHA256" line per installed script (a bare hash = SimpleAV.ps1, from 1.2.0).
$SelfFiles = 'SimpleAV.ps1', 'SimpleAV.Detection.ps1', 'SimpleAV-App.ps1'
function Test-SelfIntegrity {
  $hashFile = Join-Path $AppDir 'selfhash.txt'
  if (-not (Test-Path $hashFile)) { return }
  foreach ($line in Get-Content $hashFile) {
    $parts = $line.Trim().Split('|')
    if ($parts.Count -eq 2) { $name = $parts[0]; $want = $parts[1] } elseif ($parts[0]) { $name = 'SimpleAV.ps1'; $want = $parts[0] } else { continue }
    $file = Join-Path $AppDir $name
    $have = if (Test-Path -LiteralPath $file) { (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash } else { 'missing' }
    if ($want -ne $have) { $null = Add-Finding 'HIGH' 'SIMPLEAV MODIFIED' $file 'SimpleAV itself was changed after install - something may be tampering with it' }
  }
}

# Authenticode checks are the slowest part of a scan. Results are cached by path + size + last-write time,
# so an unchanged file is never re-verified; any modification changes the key and forces a fresh check.
$script:SigCache = $null; $script:SigCacheHits = 0
function Get-SigStatus([string]$f) {
  if ($null -eq $script:SigCache) {
    $script:SigCache = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
    if (Test-Path $SigCacheFile) { foreach ($l in [System.IO.File]::ReadAllLines($SigCacheFile)) { $t = $l.LastIndexOf("`t"); if ($t -gt 0) { $script:SigCache[$l.Substring(0, $t)] = $l.Substring($t + 1) } } }
  }
  $key = $f
  try { $fi = New-Object System.IO.FileInfo $f; $key = '{0}|{1}|{2}' -f $f, $fi.Length, $fi.LastWriteTimeUtc.Ticks } catch {}
  $script:SigUsed[$f] = $key
  $st = $null
  if ($script:SigCache.TryGetValue($key, [ref]$st)) { $script:SigCacheHits++; return $st }
  $st = [string](Get-AuthenticodeSignature -LiteralPath $f).Status
  if ($st -and $st -ne 'UnknownError') { $script:SigCache[$key] = $st }       # don't cache transient failures
  return $st
}
$script:SigUsed = New-Object 'System.Collections.Generic.Dictionary[string,string]' ([StringComparer]::OrdinalIgnoreCase)
# Keeps the current entry for every file checked this scan, plus older entries for files this scan didn't
# visit (a Quick scan must not throw away the cache for Program Files). Entries for deleted files are dropped.
function Save-SigCache {
  if ($null -eq $script:SigCache) { return }
  $lines = New-Object System.Collections.Generic.List[string]
  foreach ($kv in $script:SigCache.GetEnumerator()) {
    $path = $kv.Key.Split('|')[0]; $used = $null
    if ($script:SigUsed.TryGetValue($path, [ref]$used)) { if ($used -ne $kv.Key) { continue } }
    elseif (-not [System.IO.File]::Exists($path)) { continue }
    $lines.Add("$($kv.Key)`t$($kv.Value)")
  }
  try { [System.IO.File]::WriteAllLines($SigCacheFile, $lines.ToArray()) } catch {}
}

# ================================================================== quarantine
<# Moves a file into the quarantine folder, renamed to *.quarantined so it can never run, and writes a
   small .txt record (original path, hash, reason). Returns 'ok', 'missing' or 'denied'.
   Only single files are accepted: a folder path is treated as 'missing', never moved wholesale. #>
function Move-ToQuarantine([string]$path, [string]$reason) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return 'missing' }
  $null = New-Item -ItemType Directory -Force -Path $QDir
  $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
  $dest = Join-Path $QDir ('{0}_{1}.quarantined' -f [System.IO.Path]::GetFileName($path), (Get-Date -Format 'yyyyMMdd_HHmmss_fff'))
  try { Move-Item -LiteralPath $path -Destination $dest -Force -ErrorAction Stop }
  catch {   # 'denied' = admin rights could help; 'inuse' = they wouldn't (the file is locked by a running program)
    if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.CategoryInfo.Category -eq 'PermissionDenied' -or ($_.Exception.HResult -band 0xFFFF) -eq 5) { return 'denied' } else { return 'inuse' }
  }
  @("Original path: $path", "SHA256: $hash", "Quarantined: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')", "Reason: $reason") | Set-Content -Path ($dest + '.txt') -Encoding UTF8
  return 'ok'
}
function Invoke-QuarantineCmd([string]$path) {
  Start-Log 'quarantine'
  $r = Move-ToQuarantine $path 'quarantined by user'
  Write-Log "QUARANTINE $path -> $r"
  switch ($r) { 'ok' { exit 0 } 'missing' { exit 2 } 'denied' { exit 5 } default { exit 6 } }
}
<# Exit codes: 0 restored | 2 not a quarantined file | 3 record invalid or file doesn't match its recorded hash
   4 something already exists at the original path (never overwritten) | 5 Windows denied access (admin needed) | 6 other error #>
function Invoke-RestoreCmd([string]$qfile) {
  Start-Log 'restore'
  $rec = "$qfile.txt"
  if (-not (Test-Path -LiteralPath $qfile -PathType Leaf) -or -not (Test-Path -LiteralPath $rec)) { Write-Log "RESTORE failed: not a quarantined file: $qfile"; exit 2 }
  $lines = Get-Content -LiteralPath $rec
  $orig = ($lines | Where-Object { $_ -like 'Original path:*' } | Select-Object -First 1) -replace '^Original path:\s*', ''
  $want = ($lines | Where-Object { $_ -like 'SHA256:*' } | Select-Object -First 1) -replace '^SHA256:\s*', ''
  # The record sits in a user-writable folder, so treat it as untrusted input.
  if (-not $orig -or $orig -notmatch '^[A-Za-z]:\\' -or $orig.IndexOfAny([System.IO.Path]::GetInvalidPathChars()) -ge 0 -or $orig -match '[\*\?]') {
    Write-Log "RESTORE refused: invalid original path in record: '$orig'"; exit 3
  }
  if ($want -and (Get-FileHash -LiteralPath $qfile -Algorithm SHA256).Hash -ne $want.Trim()) {
    Write-Log "RESTORE refused: $qfile does not match the SHA-256 recorded at quarantine time"; exit 3
  }
  if (Test-Path -LiteralPath $orig) { Write-Log "RESTORE refused: $orig already exists (e.g. a clean reinstall) - not overwriting it"; exit 4 }
  try {
    $null = New-Item -ItemType Directory -Force -Path (Split-Path $orig) -ErrorAction Stop
    Move-Item -LiteralPath $qfile -Destination $orig -ErrorAction Stop
    Remove-Item -LiteralPath $rec -Force
    Write-Log "RESTORED $qfile -> $orig"; exit 0
  } catch {
    Write-Log "RESTORE failed: $orig ($($_.Exception.Message))"
    if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.CategoryInfo.Category -eq 'PermissionDenied' -or ($_.Exception.HResult -band 0xFFFF) -eq 5) { exit 5 } else { exit 6 }
  }
}
# Called on every infected file: quarantines EXACT matches automatically (if enabled), reports the rest.
function Handle-Infected([string]$path, [string]$why, [string]$kind) {
  if ($AutoQ -and $why.StartsWith($KnownPrefix)) {
    $r = Move-ToQuarantine $path "auto: $why"
    if ($r -eq 'ok') { return (Add-Finding 'HIGH' 'AUTO-QUARANTINED' $path "$why - moved to quarantine automatically") }
    return (Add-Finding 'HIGH' $kind $path "$why (auto-quarantine failed: $(if ($r -eq 'inuse') { 'file is in use' } else { 'needs admin rights' }))")
  }
  return (Add-Finding 'HIGH' $kind $path $why)
}

# ================================================================== persistence / startup checks
function Get-PersistenceSnapshot {
  $snap = [ordered]@{}
  $runKeys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
             'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
  foreach ($k in $runKeys) {
    if (Test-Path $k) { (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' } | ForEach-Object { $snap["RUN|$k|$($_.Name)"] = [string]$_.Value } }
  }
  $wlU = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon'
  $wlM = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
  $snap['WINLOGON|HKCU|Shell']    = [string]$wlU.Shell
  $snap['WINLOGON|HKLM|Shell']    = [string]$wlM.Shell
  $snap['WINLOGON|HKLM|Userinit'] = [string]$wlM.Userinit
  $envK = Get-ItemProperty 'HKCU:\Environment'
  foreach ($n in 'UserInitMprLogonScript', 'UserCache', 'COR_PROFILER', 'COR_ENABLE_PROFILING') { $v = $envK.$n; if ($v) { $snap["ENV|$n"] = [string]$v } }
  if (Test-Path "HKCU:\Software\Classes\CLSID\$FakeClsid") { $snap["CLSID|$FakeClsid"] = 'present' }
  foreach ($root in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
    Get-ChildItem $root | ForEach-Object { $d = (Get-ItemProperty $_.PSPath).Debugger; if ($d) { $snap["IFEO|$($_.PSChildName)"] = [string]$d } }
  }
  foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows') {
    $a = (Get-ItemProperty $k).AppInit_DLLs; if ($a) { $snap["APPINIT|$k"] = [string]$a }
  }
  foreach ($dir in "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup", "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp") {
    Get-ChildItem $dir -Force -File | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { $snap["STARTUP|$($_.FullName)"] = $_.LastWriteTime.ToString('s') }
  }
  Get-ScheduledTask | ForEach-Object { $t = $_; $snap["TASK|$($t.TaskPath)$($t.TaskName)"] = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; ' }
  Get-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer | ForEach-Object { $snap["WMI|$($_.Name)"] = [string]$_.CommandLineTemplate }
  Get-CimInstance -Namespace root\subscription -ClassName ActiveScriptEventConsumer | ForEach-Object { $snap["WMI|$($_.Name)"] = 'ActiveScript: ' + [string]$_.ScriptText }
  return $snap
}
# Returns @(severity, reason) for a suspicious entry, or $null.
function Test-PersistenceItem([string]$key, [string]$val) {
  $parts = $key.Split('|')
  switch ($parts[0]) {
    'WINLOGON' {
      if ($parts[1] -eq 'HKCU' -and $parts[2] -eq 'Shell' -and $val) { return @('HIGH', 'per-user Winlogon Shell is set - a way to start malware together with Explorer') }
      if ($parts[2] -eq 'Shell' -and $val -and $val.Trim() -ne 'explorer.exe') { return @('HIGH', 'Winlogon Shell changed from explorer.exe') }
      if ($parts[2] -eq 'Userinit' -and $val -and $val.Trim().TrimEnd(',') -ine "$env:SystemRoot\system32\userinit.exe") { return @('HIGH', 'Winlogon Userinit changed') }
      return $null
    }
    'ENV'     { return @('HIGH', "logon/profiler hook in HKCU\Environment ($($parts[1]))") }
    'CLSID'   { return @('HIGH', 'fake CLSID used by the analysed loader to store its payload') }
    'APPINIT' { return @('HIGH', 'AppInit_DLLs set - a DLL is injected into every program') }
    'WMI'     { return @('HIGH', 'WMI event consumer - fileless persistence') }
    'IFEO' {
      if ($SecurityTools -contains $parts[1]) { return @('HIGH', "debugger hijack blocks $($parts[1]) from running") }
      return @('LOW', 'IFEO debugger set (often a "disable Windows Update" tweak)')
    }
    default {
      if ($val -match $BadCmd -and $val -notmatch $SelfCmdRx) { return @('HIGH', 'startup entry runs a suspicious command') }
      if ($parts[0] -eq 'RUN' -and $val -match '(?i)\\appdata\\local\\temp\\') { return @('MEDIUM', 'startup entry runs from the Temp folder') }
      return $null
    }
  }
}
# Copies of MSBuild.exe in user folders (the loader ran its payload through one).
$MsbuildDirs  = @($env:USERPROFILE, $env:ProgramData, $env:PUBLIC) | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\') + '\' }
$MsbuildAllow = '(?i)Microsoft Visual Studio|\\dotnet\\|BuildTools|\\\.nuget\\|\\sdk\\'
function Test-MsbuildCopy([string]$f) {
  if (-not $f.EndsWith('\msbuild.exe', [StringComparison]::OrdinalIgnoreCase) -or $f -match $MsbuildAllow) { return }
  foreach ($d in $MsbuildDirs) {
    if ($f.StartsWith($d, [StringComparison]::OrdinalIgnoreCase)) { $null = Add-Finding 'HIGH' 'MSBUILD COPY' $f 'MSBuild.exe copied into a user folder - a known trick to run hidden code'; return }
  }
}
function Test-Covered([string]$dir, $roots) {
  foreach ($r in $roots) { $rr = $r.TrimEnd('\') + '\'; if (($dir.TrimEnd('\') + '\').StartsWith($rr, [StringComparison]::OrdinalIgnoreCase)) { return $true } }
  return $false
}
function Invoke-PersistenceCheck($roots) {
  Write-Log '--- Checking startup / persistence locations'
  $snap = Get-PersistenceSnapshot
  foreach ($k in $snap.Keys) { $r = Test-PersistenceItem $k $snap[$k]; if ($r) { $null = Add-Finding $r[0] 'STARTUP/PERSISTENCE' $k ("{0} | value: {1}" -f $r[1], $snap[$k]) } }
  # MSBuild copies: folders the main walk will visit anyway are checked there, so they aren't walked twice.
  foreach ($d in $MsbuildDirs) {
    if (Test-Covered $d $roots) { continue }
    foreach ($f in Get-ScanFiles $d) { Test-MsbuildCopy $f }
  }
}

# ================================================================== scan
function Invoke-Scan {
  Start-Log 'scan'
  $t0 = Get-Date
  $script:ScanStart = $t0.ToString('s')
  $script:ScanMode = if ($Paths) { 'Custom' } elseif ($Deep) { 'Deep (every file)' } elseif ($Quick) { 'Quick' } elseif ($AllDrives) { 'All drives' } else { 'Full (C:)' }
  Write-Log "Mode: $($script:ScanMode)"
  Write-Log "Auto-quarantine of exact virus matches: $(if ($AutoQ) { 'ON' } else { 'OFF' })"
  if ($Paths) { $roots = $Paths }
  elseif ($Quick) { $roots = @($env:USERPROFILE) }
  elseif ($AllDrives) { $roots = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.DriveType -eq 'Fixed' -and $_.IsReady } | ForEach-Object { $_.RootDirectory.FullName } }
  else { $roots = @("$env:SystemDrive\") }

  Set-Progress 'running' 'Checking startup entries' 0
  Test-SelfIntegrity
  if (-not $SkipSystem) { Invoke-PersistenceCheck $roots }

  # 1) Windows system files: signatures + DLL hijacks next to explorer.exe
  $sysCount = 0
  if (-not $SkipSystem) {
    Set-Progress 'running' 'Checking Windows system files' 0
    Write-Log '--- Checking signatures of Windows system files'
    $sysTop = @("$env:SystemRoot", "$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64", "$env:SystemRoot\System32\drivers")
    $sys32Names = @{}; Get-ChildItem "$env:SystemRoot\System32" -File -Force | ForEach-Object { $sys32Names[$_.Name.ToLowerInvariant()] = $true }
    # Some old Microsoft runtimes (mfc70, msvcr71...) are legitimately unsigned. Remember the ones present at the
    # first scan; afterwards only NEW or CHANGED unsigned system files are reported.
    $baseFile = Join-Path $AppDir 'known_unsigned_system_files.txt'
    $haveBase = Test-Path $baseFile
    $known = @{}; if ($haveBase) { Get-Content $baseFile | ForEach-Object { $known[$_] = $true } }
    $seed = New-Object System.Collections.Generic.List[string]
    foreach ($d in $sysTop) {
      foreach ($f in [System.IO.Directory]::GetFiles($d)) {
        if (-not ($PEExt -contains [System.IO.Path]::GetExtension($f).ToLowerInvariant())) { continue }
        $sysCount++
        if (($sysCount % 250) -eq 0) { Set-Progress 'running' "Checking Windows system files ($sysCount)" 0 }
        $st = Get-SigStatus $f
        $name = [System.IO.Path]::GetFileName($f).ToLowerInvariant()
        if ($st -eq 'HashMismatch') { $null = Add-Finding 'HIGH' 'TAMPERED SYSTEM FILE' $f 'signature broken - file was modified after Microsoft signed it' }
        elseif ($st -ne 'Valid') {
          if ($d -eq $env:SystemRoot -and $sys32Names.ContainsKey($name)) {
            $null = Add-Finding 'HIGH' 'DLL HIJACK' $f 'unsigned copy of a System32 file placed next to explorer.exe - Explorer loads it instead of the real one'
          } else {
            $key = "$f|" + (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
            if ($known.ContainsKey($key)) { }
            elseif (-not $haveBase) { $seed.Add($key) }
            else { $null = Add-Finding 'MEDIUM' 'NEW UNSIGNED SYSTEM FILE' $f 'unsigned Windows file that is new or changed since the first scan' }
          }
        }
      }
    }
    if (-not $haveBase) { $seed | Set-Content -Path $baseFile -Encoding UTF8; Write-Log "    remembered $($seed.Count) existing unsigned system files as known" }
    Write-Log "    $sysCount system files signature-checked"
  }

  # 2) Walk the roots
  $sigRoots = @("$env:ProgramFiles", "${env:ProgramFiles(x86)}", "$env:LOCALAPPDATA\Programs", "$env:LOCALAPPDATA\Discord")
  $count = 0; $sigCount = 0; $progCount = 0
  foreach ($r in $roots) {
    Write-Log ("--- Scanning {0} under $r" -f $(if ($Deep) { 'EVERY file' } else { 'program files' }))
    Set-Progress 'running' "Scanning $r" $count
    foreach ($f in Get-ScanFiles $r) {
      $count++
      if (($count % 500) -eq 0) { Set-Progress 'running' "Scanning $r" $count }
      $why = Test-PEInfected $f
      if (-not $script:LastWasPE) { continue }          # not a program (only possible with -Deep)
      $progCount++
      if ($why) { $null = Handle-Infected $f $why 'INFECTED FILE'; continue }
      if (-not $SkipSystem) { Test-MsbuildCopy $f }
      $ext = [System.IO.Path]::GetExtension($f).ToLowerInvariant()
      if (-not ($PEExt -contains $ext)) {
        if ($DisguiseExt -contains $ext) { $null = Add-Finding 'HIGH' 'DISGUISED PROGRAM' $f "a real Windows program pretending to be a '$ext' file" }
        else { $null = Add-Finding 'MEDIUM' 'HIDDEN PROGRAM' $f "a Windows program saved with the unusual extension '$ext' - often harmless (game data), sometimes malware" }
      }
      $doSig = $SigAll
      if (-not $doSig) { foreach ($sr in $sigRoots) { if ($sr -and $f.StartsWith($sr + '\', [StringComparison]::OrdinalIgnoreCase)) { $doSig = $true; break } } }
      if ($doSig) {
        $sigCount++
        if ((Get-SigStatus $f) -eq 'HashMismatch') { $null = Add-Finding 'HIGH' 'TAMPERED FILE' $f 'signature broken - file was modified after it was signed' }
      }
    }
  }

  # 3) Summary
  $dur = (Get-Date) - $t0
  $high = @($script:Findings | Where-Object Severity -eq 'HIGH').Count
  $med  = @($script:Findings | Where-Object Severity -eq 'MEDIUM').Count
  $low  = @($script:Findings | Where-Object Severity -eq 'LOW').Count
  $auto = @($script:Findings | Where-Object Kind -eq 'AUTO-QUARANTINED').Count
  Write-Log ("COVERAGE: files opened={0} | programs={1} | folders skipped={2} | files unreadable={3}" -f $count, $progCount, $script:Skipped, $script:Unreadable)
  if ($script:Skipped -gt 0) {
    Write-Log "Folders SimpleAV could not read (Windows blocks normal apps from these; first $($script:SkippedList.Count) shown):"
    foreach ($s in $script:SkippedList) { Write-Log "    SKIPPED $s" }
  }
  Save-SigCache
  Write-Log ("    signature cache: {0} of {1} checks reused from earlier scans" -f $script:SigCacheHits, ($sigCount + $sysCount))
  # Invariant culture: this line is parsed by the dashboard, and e.g. fr-FR would write "54 509" with a no-break space.
  Write-Log ([string]::Format([cultureinfo]::InvariantCulture, "=== DONE in {0:N0} min. Program files checked: {1:N0} (signatures: {2:N0} + {3:N0} system). Findings: HIGH={4} MEDIUM={5} LOW={6} AUTOQ={7}", $dur.TotalMinutes, $progCount, $sigCount, $sysCount, $high, $med, $low, $auto))
  if ($script:Findings.Count) { $script:Findings | Export-Csv -Path ($script:LogFile -replace '\.log$', '.csv') -NoTypeInformation -Encoding UTF8 }
  Set-Progress 'done' 'Finished' $count
  if ($high -gt 0)    { Show-Alert 'SimpleAV: threats found' "$high high-risk item(s) ($auto quarantined automatically), $med medium. Open SimpleAV for details." 'Error' }
  elseif ($med -gt 0) { Show-Alert 'SimpleAV: check needed' "$med medium-risk item(s) found. Open SimpleAV for details." 'Warning' }
  elseif (-not $Quick) { Show-Alert 'SimpleAV: all clear' "Scan finished: $progCount program files checked, nothing found." 'Info' }
}

# ================================================================== real-time watcher
function Invoke-Watch {
  # One watcher per data folder: a named mutex (released automatically if the process dies).
  $sha = New-Object System.Security.Cryptography.SHA256Managed
  $tag = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($AppDir.ToLowerInvariant()))) -replace '-', '').Substring(0, 16)
  $script:WatchMutex = New-Object System.Threading.Mutex($false, "Local\SimpleAV-Watch-$tag")
  $owned = $false
  try { $owned = $script:WatchMutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $owned = $true }
  if (-not $owned) { Write-Host 'SimpleAV watcher already running.'; return }
  Start-Log 'watch'
  Init-Tray
  Test-SelfIntegrity
  Write-Log "Watcher started (auto-quarantine $(if ($AutoQ) { 'ON' } else { 'OFF' })). Checks: new/changed program files, suspicious processes, startup entries."
  $base = Get-PersistenceSnapshot
  foreach ($k in $base.Keys) { $r = Test-PersistenceItem $k $base[$k]; if ($r -and $r[0] -eq 'HIGH') { $null = Add-Finding 'HIGH' 'STARTUP/PERSISTENCE' $k "$($r[1]) | value: $($base[$k])"; Show-Alert 'SimpleAV: suspicious startup entry' "$($r[1])`n$k" 'Error' } }

  # File watchers: user profile + ProgramData (recursive), Windows folder (top level, for DLL hijacks)
  $i = 0
  foreach ($t in @(@{ Path = $env:USERPROFILE; Sub = $true }, @{ Path = $env:SystemRoot; Sub = $false }, @{ Path = $env:ProgramData; Sub = $true })) {
    $w = New-Object System.IO.FileSystemWatcher $t.Path
    $w.IncludeSubdirectories = $t.Sub; $w.InternalBufferSize = 65536
    $w.NotifyFilter = [System.IO.NotifyFilters]'FileName, LastWrite'; $w.EnableRaisingEvents = $true
    $i++
    $null = Register-ObjectEvent -InputObject $w -EventName Created -SourceIdentifier "SAV_C$i"
    $null = Register-ObjectEvent -InputObject $w -EventName Changed -SourceIdentifier "SAV_W$i"
    $null = Register-ObjectEvent -InputObject $w -EventName Renamed -SourceIdentifier "SAV_R$i"
    # Raised when the 64 KB event buffer overflows (changes were lost) or the watched folder becomes unavailable.
    $null = Register-ObjectEvent -InputObject $w -EventName Error -SourceIdentifier "SAV_E$i"
  }

  # Processes are keyed by ID + start time: Windows reuses IDs, so an ID alone could hide a new process.
  $procKey = { param($p) '{0}|{1}' -f $p.ProcessId, $(if ($p.CreationDate) { $p.CreationDate.Ticks } else { 0 }) }
  $seenProcs = @{}; foreach ($p in Get-CimInstance Win32_Process) { $seenProcs[(& $procKey $p)] = $true }
  $pending = @{}
  $lastOverflowLog = [datetime]::MinValue
  $nextProc = Get-Date; $nextPersist = (Get-Date).AddSeconds(60); $nextHeartbeat = (Get-Date).AddHours(1)

  while ($true) {
    [System.Windows.Forms.Application]::DoEvents()
    # Drain every queued file event, then fall through: a burst (npm install, game update) must not
    # starve the process and startup checks below.
    if (Wait-Event -Timeout 1) {
      foreach ($ev in @(Get-Event)) {
        Remove-Event -EventIdentifier $ev.EventIdentifier
        if ($ev.SourceIdentifier -like 'SAV_E*') {
          try { $ev.Sender.EnableRaisingEvents = $true } catch {}
          if (((Get-Date) - $lastOverflowLog).TotalMinutes -ge 1) {
            $lastOverflowLog = Get-Date
            Write-Log "WARNING file watcher on $($ev.Sender.Path): $($ev.SourceEventArgs.GetException().Message) - some file changes were missed; run a Quick scan to be sure"
          }
          continue
        }
        $path = $ev.SourceEventArgs.FullPath
        if ($path -and ($PEExt -contains [System.IO.Path]::GetExtension($path).ToLowerInvariant()) -and -not (Test-InAppDir $path)) { $pending[$path] = (Get-Date).AddSeconds(3) }
      }
    }
    $now = Get-Date

    # New / changed program files (checked once they stop changing)
    foreach ($p in @($pending.Keys)) {
      if ($pending[$p] -gt $now) { continue }
      $pending.Remove($p)
      if (-not (Test-Path -LiteralPath $p)) { continue }
      $why = Test-PEInfected $p
      if ($why) {
        $f = Handle-Infected $p $why 'INFECTED FILE APPEARED'
        $msg = if ($f.Kind -eq 'AUTO-QUARANTINED') { "Infected file caught and quarantined:`n$p" } else { "Something just infected:`n$p" }
        Show-Alert 'SimpleAV: infected file!' $msg 'Error'
      } elseif ($p -like "$env:SystemRoot\*.dll" -and (Test-Path "$env:SystemRoot\System32\$([System.IO.Path]::GetFileName($p))")) {
        if ((Get-AuthenticodeSignature -LiteralPath $p).Status -ne 'Valid') {
          $null = Add-Finding 'HIGH' 'DLL HIJACK APPEARED' $p 'unsigned System32-named DLL dropped next to explorer.exe'
          Show-Alert 'SimpleAV: Explorer hijack!' "Fake system DLL dropped:`n$p" 'Error'
        }
      }
    }

    # New processes, every 15 s
    if ($now -ge $nextProc) {
      $nextProc = $now.AddSeconds(15)
      $current = @{}
      foreach ($p in Get-CimInstance Win32_Process) {
        $key = & $procKey $p
        $current[$key] = $true
        if ($seenProcs.ContainsKey($key)) { continue }
        $cmd = [string]$p.CommandLine; $exe = [string]$p.ExecutablePath
        if ($p.Name -match '(?i)^(powershell|pwsh)\.exe$' -and $cmd -match $SelfCmdRx) { continue }
        if ($p.Name -match '(?i)^(powershell|pwsh|conhost|cmd|mshta|wscript|cscript|rundll32|regsvr32)\.exe$' -and $cmd -match $BadCmd) {
          $null = Add-Finding 'HIGH' 'SUSPICIOUS PROCESS' "$($p.Name) [$($p.ProcessId)]" $cmd
          Show-Alert 'SimpleAV: suspicious hidden command' "$($p.Name) ran a command that looks like malware. Open SimpleAV for details." 'Error'
        } elseif ($p.Name -ieq 'msbuild.exe' -and $exe -notmatch '(?i)\\Microsoft\.NET\\|Microsoft Visual Studio|\\dotnet\\|BuildTools') {
          $null = Add-Finding 'HIGH' 'SUSPICIOUS MSBUILD' $exe $cmd
          Show-Alert 'SimpleAV: MSBuild abuse' "MSBuild started from an unusual folder:`n$exe" 'Error'
        } elseif ($exe) {
          $why = Test-PEInfected $exe
          if ($why) { $null = Add-Finding 'HIGH' 'INFECTED PROGRAM RUNNING' $exe $why; Show-Alert 'SimpleAV: infected program running!' "$exe`nClose it, then quarantine it from SimpleAV." 'Error' }
          elseif ($exe -match '(?i)\\appdata\\local\\temp\\') { $null = Add-Finding 'LOW' 'PROGRAM RAN FROM TEMP' $exe $cmd }
        }
      }
      $seenProcs = $current          # forget processes that have exited, so the table never grows unbounded
    }

    # Startup entries added or changed, every 60 s
    if ($now -ge $nextPersist) {
      $nextPersist = $now.AddSeconds(60)
      $snap = Get-PersistenceSnapshot
      foreach ($k in $snap.Keys) {
        $isNew = -not $base.Contains($k)
        if ($isNew -or ($base[$k] -ne $snap[$k])) {
          $r = Test-PersistenceItem $k $snap[$k]
          $sev = if ($r -and $r[0] -eq 'HIGH') { 'HIGH' } else { 'MEDIUM' }
          $why = if ($r) { $r[1] } elseif ($isNew) { 'new startup entry added' } else { 'startup entry changed' }
          $null = Add-Finding $sev 'STARTUP CHANGE' $k "$why | value: $($snap[$k])"
          Show-Alert $(if ($sev -eq 'HIGH') { 'SimpleAV: suspicious startup entry!' } else { 'SimpleAV: new startup entry' }) "$why`n$k" $(if ($sev -eq 'HIGH') { 'Error' } else { 'Warning' })
        }
      }
      $base = $snap
    }

    if ($now -ge $nextHeartbeat) { $nextHeartbeat = $now.AddHours(1); Write-Log 'heartbeat - watcher running'; Test-SelfIntegrity }
  }
}

# ================================================================== install / uninstall
function Invoke-Install {
  $null = New-Item -ItemType Directory -Force -Path $AppDir
  $src = Split-Path -Parent $PSCommandPath
  $dest = Join-Path $AppDir 'SimpleAV.ps1'
  # Stop a watcher from a previous install first, so the new version actually takes over.
  Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.Name -match '^(powershell|pwsh)\.exe$' -and $_.CommandLine -like "*$dest*-Watch*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
  foreach ($f in $SelfFiles + 'SimpleAV.ico') {
    $from = Join-Path $src $f; $to = Join-Path $AppDir $f
    if ((Test-Path $from) -and ($from -ine $to)) { Copy-Item -LiteralPath $from -Destination $to -Force }
  }
  $SelfFiles | ForEach-Object { '{0}|{1}' -f $_, (Get-FileHash -LiteralPath (Join-Path $AppDir $_) -Algorithm SHA256).Hash } | Set-Content (Join-Path $AppDir 'selfhash.txt')
  $ps   = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
  $user = "$env:USERDOMAIN\$env:USERNAME"
  $set  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Seconds 0)
  $prn  = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
  $watchArgs = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$dest`" -Watch"

  $aW = New-ScheduledTaskAction -Execute $ps -Argument $watchArgs
  $tW = New-ScheduledTaskTrigger -AtLogOn -User $user
  try { Register-ScheduledTask -TaskName 'SimpleAV Watch' -Action $aW -Trigger $tW -Settings $set -Principal $prn -Force -ErrorAction Stop | Out-Null; Write-Host 'Registered task: SimpleAV Watch (starts at logon)' }
  catch {
    Write-Host "Logon task not allowed ($($_.Exception.Message)); using a Startup folder shortcut instead."
    $sh = New-Object -ComObject WScript.Shell; $l = $sh.CreateShortcut((Join-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" 'SimpleAV Watch.lnk'))
    $l.TargetPath = $ps; $l.Arguments = $watchArgs; $l.WindowStyle = 7; $l.Save()
  }
  $aS = New-ScheduledTaskAction -Execute $ps -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$dest`" -Scan -AllDrives"
  $tS = New-ScheduledTaskTrigger -Daily -At '13:00'
  Register-ScheduledTask -TaskName 'SimpleAV Daily Scan' -Action $aS -Trigger $tS -Settings $set -Principal $prn -Force -ErrorAction Stop | Out-Null
  Write-Host 'Registered task: SimpleAV Daily Scan (every day at 13:00, all drives; runs later if the PC was off)'
  try { Start-ScheduledTask -TaskName 'SimpleAV Watch' -ErrorAction Stop } catch { Start-Process $ps -ArgumentList $watchArgs -WindowStyle Hidden }

  $app = Join-Path $AppDir 'SimpleAV-App.ps1'
  if (Test-Path $app) {
    $sh = New-Object -ComObject WScript.Shell
    foreach ($lnkDir in [Environment]::GetFolderPath('Desktop'), (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs')) {
      $l = $sh.CreateShortcut((Join-Path $lnkDir 'SimpleAV.lnk'))
      $l.TargetPath = $ps; $l.Arguments = "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$app`""
      $l.IconLocation = "$(Join-Path $AppDir 'SimpleAV.ico'),0"; $l.WindowStyle = 7; $l.Description = 'SimpleAV - Made by Beyrem'; $l.Save()
      Write-Host "Shortcut: $lnkDir\SimpleAV.lnk"
    }
  }
  Write-Host "SimpleAV $Version installed to $AppDir. Real-time protection is running (shield icon in the tray)."
}
function Invoke-Uninstall {
  Unregister-ScheduledTask -TaskName 'SimpleAV Watch' -Confirm:$false
  Unregister-ScheduledTask -TaskName 'SimpleAV Daily Scan' -Confirm:$false
  Remove-Item (Join-Path "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" 'SimpleAV Watch.lnk') -Force
  foreach ($l in (Join-Path ([Environment]::GetFolderPath('Desktop')) 'SimpleAV.lnk'), (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\SimpleAV.lnk')) { Remove-Item $l -Force }
  Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.Name -match '^(powershell|pwsh)\.exe$' -and $_.CommandLine -match '-File\s+"?[^"]*SimpleAV(-App)?\.ps1' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
  Write-Host "SimpleAV removed (tasks, shortcuts, watcher). Your logs and quarantine are kept in $AppDir."
}

# ================================================================== main
if ($MyInvocation.InvocationName -eq '.') { return }   # dot-sourced (tests): load the functions only
if     ($Install)    { Invoke-Install }
elseif ($Uninstall)  { Invoke-Uninstall }
elseif ($Quarantine) { Invoke-QuarantineCmd $Quarantine }
elseif ($Restore)    { Invoke-RestoreCmd $Restore }
elseif ($TestAlert)  { Start-Log 'test'; Write-Log 'Test alert'; Show-Alert 'SimpleAV test' 'Notifications work.' 'Info' }
elseif ($Watch)      { Invoke-Watch }
elseif ($Scan -or $Quick -or $Paths) { Invoke-Scan }
else { Get-Help $PSCommandPath -Detailed | Out-String | Write-Host }
