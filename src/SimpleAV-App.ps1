<#
.SYNOPSIS
  SimpleAV dashboard - status, scans, threat history, quarantine.
.DESCRIPTION
  Every number shown comes from SimpleAV's own logs plus live checks of your disk:
  for each threat it re-checks whether the file is still there, was deleted, quarantined,
  or replaced by a clean copy.
.PARAMETER SelfTest    Print what the window would show (no window). Used by the tests.
.PARAMETER Screenshot  Render the window to a PNG file and exit.
.NOTES
  Author: Beyrem  |  Version: 1.2.0  |  License: MIT
#>
param([switch]$SelfTest, [string]$Screenshot)
$ErrorActionPreference = 'SilentlyContinue'
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

. (Join-Path $PSScriptRoot 'SimpleAV.Detection.ps1')   # shared detection core + version number
$Version  = $SAV_Version
$Dir     = if ($env:SIMPLEAV_HOME) { $env:SIMPLEAV_HOME } else { Join-Path $env:USERPROFILE 'SimpleAV' }
$Engine   = Join-Path $Dir 'SimpleAV.ps1'
if (-not (Test-Path $Engine)) { $Engine = Join-Path $PSScriptRoot 'SimpleAV.ps1' }   # running straight from the repo
$LogDir   = Join-Path $Dir 'logs'
$ProgFile = Join-Path $Dir 'progress.json'
$HistFile = Join-Path $Dir 'history.csv'      # optional record of a manual cleanup (see docs/HOW-IT-WORKS.md)
$SettingsFile = Join-Path $Dir 'settings.json'
$QDir     = Join-Path $Dir 'quarantine'
$PS       = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$TestPathRx = '\\SimpleAV-test'               # samples created by tests\Run-Tests.ps1

$script:Launched = [datetime]::MinValue
$script:WasScanning = $false
$script:Tick = 0
$script:Anim = 0
$script:Model = $null
$script:RowsKey = ''
$script:Busy = $false        # true while a dialog is open: the refresh timer must not re-enter
$script:InfCache = @{}       # path -> @{ Stamp; Result } so unchanged files aren't re-read every refresh

# Start menu entry (created from here because this window runs as a normal app)
$startLnk = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\SimpleAV.lnk'
if (-not $SelfTest -and -not $Screenshot -and (Test-Path (Join-Path $Dir 'SimpleAV-App.ps1')) -and -not (Test-Path $startLnk)) {
  $sh = New-Object -ComObject WScript.Shell; $l = $sh.CreateShortcut($startLnk)
  $l.TargetPath = $PS; $l.Arguments = "-NoProfile -STA -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Dir\SimpleAV-App.ps1`""
  $l.IconLocation = "$(Join-Path $Dir 'SimpleAV.ico'),0"; $l.WindowStyle = 7; $l.Description = 'SimpleAV - Made by Beyrem'; $l.Save()
}

# ================================================================== design tokens (Apple-like, light)
function RGB([string]$hex) { [System.Drawing.ColorTranslator]::FromHtml($hex) }
$C = @{
  Bg = RGB '#F2F2F7'; Card = RGB '#FFFFFF'; Text = RGB '#1D1D1F'; Sub = RGB '#6E6E73'; Line = RGB '#E5E5EA'; Shadow = [System.Drawing.Color]::FromArgb(22, 0, 0, 0)
  CardEdge = RGB '#E3E3E8'; Border = RGB '#D2D2D7'; Disabled = RGB '#AEAEB2'
  Blue = RGB '#0071E3'; BlueHover = RGB '#0077ED'; BlueDis = RGB '#A8CBF2'
  GreenFill = RGB '#34C759'; GreenText = RGB '#1F7A35'; GreenTint = RGB '#E4F6E8'
  RedFill = RGB '#FF3B30'; RedText = RGB '#C4001A'; RedTint = RGB '#FFE8E6'
  OrangeFill = RGB '#FF9500'; OrangeText = RGB '#A84B00'; OrangeTint = RGB '#FFF1DE'
  GrayFill = RGB '#8E8E93'; GrayTint = RGB '#EEEEF1'; QText = RGB '#3A3A3C'
  BlueTint = RGB '#E6F0FC'
}
$F = @{
  App   = New-Object System.Drawing.Font('Segoe UI Semibold', 17)
  Hero  = New-Object System.Drawing.Font('Segoe UI Semibold', 20)
  Body  = New-Object System.Drawing.Font('Segoe UI', 10.5)
  Sub   = New-Object System.Drawing.Font('Segoe UI', 9.5)
  Cap   = New-Object System.Drawing.Font('Segoe UI Semibold', 8.5)
  Value = New-Object System.Drawing.Font('Segoe UI Semibold', 17)
  Row   = New-Object System.Drawing.Font('Segoe UI Semibold', 10)
  Pill  = New-Object System.Drawing.Font('Segoe UI Semibold', 8.5)
  Btn   = New-Object System.Drawing.Font('Segoe UI Semibold', 10.5)
  Link  = New-Object System.Drawing.Font('Segoe UI', 10)
  Small = New-Object System.Drawing.Font('Segoe UI Semibold', 9)
  Section = New-Object System.Drawing.Font('Segoe UI Semibold', 13)
}

# ================================================================== data
function Get-EngineProcs([string]$flag) {
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -match ('-File\s+"?[^"]*SimpleAV\.ps1"?\s+' + $flag) }
}
function Get-Progress { if (Test-Path $ProgFile) { try { return (Get-Content $ProgFile -Raw | ConvertFrom-Json) } catch {} }; return $null }
function Test-ScanRunning {
  $p = Get-Progress
  if ($p -and $p.state -eq 'running') {
    $proc = Get-Process -Id $p.pid -ErrorAction SilentlyContinue
    # The process must have started before the scan did - otherwise a crashed scan's PID was reused.
    if ($proc -and (-not $p.started -or $proc.StartTime -le ([datetime]$p.started).AddSeconds(5))) { return $true }
  }
  return (((Get-Date) - $script:Launched).TotalSeconds -lt 15)
}
function Get-LastScan {
  foreach ($logFile in Get-ChildItem $LogDir -Filter 'scan_*.log' | Sort-Object LastWriteTime -Descending) {
    $done = Select-String -LiteralPath $logFile.FullName -Pattern '=== DONE in' | Select-Object -Last 1
    if (-not $done) { continue }
    if ((Select-String -LiteralPath $logFile.FullName -Pattern '\] Mode: Custom' -Quiet)) { continue }   # test scans don't count
    $o = [ordered]@{ File = $logFile.FullName; Time = $logFile.LastWriteTime; Mode = 'Full (C:)'; Min = 0; Files = 0; High = 0; Med = 0; Low = 0; Opened = $null; Skipped = $null; Unreadable = $null }
    $ts = [regex]::Match($done.Line, '^\[(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)\]'); if ($ts.Success) { $o.Time = [datetime]::ParseExact($ts.Groups[1].Value, 'yyyy-MM-dd HH:mm:ss', $null) }
    $m = Select-String -LiteralPath $logFile.FullName -Pattern '\] Mode: (.+)$' | Select-Object -First 1; if ($m) { $o.Mode = $m.Matches[0].Groups[1].Value.Trim() }
    # Number groups may hold culture separators from logs written before 1.3 (fr-FR: "54 509"); keep digits only.
    $mm = [regex]::Match($done.Line, 'DONE in ([^a-z]+?) min\. Program files checked: ([^(]+?) \(.*HIGH=(\d+) MEDIUM=(\d+) LOW=(\d+)')
    if ($mm.Success) { $o.Min = [int]($mm.Groups[1].Value -replace '[^\d]', ''); $o.Files = [int64]($mm.Groups[2].Value -replace '[^\d]', ''); $o.High = [int]$mm.Groups[3].Value; $o.Med = [int]$mm.Groups[4].Value; $o.Low = [int]$mm.Groups[5].Value }
    $cv = Select-String -LiteralPath $logFile.FullName -Pattern 'COVERAGE: files opened=(\d+) \| programs=(\d+) \| folders skipped=(\d+) \| files unreadable=(\d+)' | Select-Object -Last 1
    if ($cv) { $g = $cv.Matches[0].Groups; $o.Opened = [int64]$g[1].Value; $o.Skipped = [int]$g[3].Value; $o.Unreadable = [int]$g[4].Value }
    return [pscustomobject]$o
  }
  return $null
}
# original path (lower-case) -> quarantined file
function Get-QuarantineMap {
  $map = @{}
  Get-ChildItem $QDir -Filter '*.quarantined.txt' -Force | ForEach-Object {
    $orig = (Get-Content $_.FullName | Where-Object { $_ -like 'Original path:*' } | Select-Object -First 1) -replace '^Original path:\s*', ''
    $qf = $_.FullName -replace '\.txt$', ''
    if ($orig -and $orig -notmatch $TestPathRx -and (Test-Path -LiteralPath $qf)) { $map[$orig.ToLowerInvariant()] = $qf }   # test samples don't count
  }
  return $map
}
function Get-AutoQuarantine { if (Test-Path $SettingsFile) { try { $j = Get-Content $SettingsFile -Raw | ConvertFrom-Json; if ($null -ne $j.AutoQuarantine) { return [bool]$j.AutoQuarantine } } catch {} }; return $true }
function Test-ScanLogIsTest([string]$csv) { return (Select-String -LiteralPath ($csv -replace '\.csv$', '.log') -Pattern '\] Mode: Custom' -Quiet) }
# Same infection test as the scanner (shared code): is this file STILL infected, or a clean reinstalled copy?
# Returns $true / $false, or $null when the file can't be read (shown as "Check details", not as a threat).
function Test-StillInfected([string]$path) {
  $stamp = ''
  try { $fi = New-Object System.IO.FileInfo $path; $stamp = '{0}|{1}' -f $fi.Length, $fi.LastWriteTimeUtc.Ticks } catch {}
  $c = $script:InfCache[$path]
  if ($c -and $stamp -and $c.Stamp -eq $stamp) { return $c.Result }
  $v = Get-PEVerdict $path
  $res = if ($v.Unreadable) { $null } else { [bool]$v.Reason }
  if ($stamp -and -not $v.Unreadable) { $script:InfCache[$path] = @{ Stamp = $stamp; Result = $res } }
  return $res
}
$InfectedKinds = 'INFECTED FILE', 'INFECTED FILE APPEARED', 'INFECTED PROGRAM RUNNING', 'AUTO-QUARANTINED', 'Infected'

# Live status of a finding: present / running / quarantined / deleted / removed / replaced / stopped / resolved / unknown
function Get-ItemStatus([string]$where, [string]$kind, $qmap, $when = $null) {
  if ($kind -eq 'SIMPLEAV MODIFIED') {
    # selfhash.txt: "file|SHA256" lines (a bare hash = SimpleAV.ps1, written by 1.2.0)
    $want = $null
    foreach ($line in Get-Content (Join-Path $Dir 'selfhash.txt')) {
      $p = $line.Trim().Split('|')
      if ($p.Count -eq 2 -and (Join-Path $Dir $p[0]) -ieq $where) { $want = $p[1] } elseif ($p.Count -eq 1 -and $p[0] -and $where -like '*\SimpleAV.ps1') { $want = $p[0] }
    }
    if ($want -and (Test-Path -LiteralPath $where) -and (Get-FileHash -LiteralPath $where).Hash -eq $want) { return 'resolved' } else { return 'present' }
  }
  if ($where -match '^[A-Za-z]:\\') {
    if (Test-Path -LiteralPath $where) {
      if ($InfectedKinds -contains $kind) {
        $si = Test-StillInfected $where
        if ($null -eq $si) { return 'unknown' }
        if (-not $si) { return 'replaced' }
      }
      return 'present'
    }
    if ($qmap.ContainsKey($where.ToLowerInvariant())) { return 'quarantined' }
    return 'deleted'
  }
  $parts = $where.Split('|', 3)          # registry value names may themselves contain '|'
  $rest  = if ($parts.Count -gt 1) { $where.Substring($parts[0].Length + 1) } else { '' }
  switch ($parts[0]) {
    'WINLOGON' {   # same rules as the engine's Test-PersistenceItem
      $hive = if ($parts[1] -eq 'HKLM') { 'HKLM:\SOFTWARE' } else { 'HKCU:\Software' }
      $v = [string](Get-ItemProperty "$hive\Microsoft\Windows NT\CurrentVersion\Winlogon").($parts[2])
      $bad = switch ($parts[2]) {
        'Shell'    { if ($parts[1] -eq 'HKCU') { [bool]$v } else { $v -and $v.Trim() -ne 'explorer.exe' } }
        'Userinit' { $v -and $v.Trim().TrimEnd(',') -ine "$env:SystemRoot\system32\userinit.exe" }
        default    { $false }
      }
      if ($bad) { return 'present' } else { return 'removed' }
    }
    'ENV'      { if ((Get-Item 'HKCU:\Environment').Property -contains $rest) { return 'present' } else { return 'removed' } }
    'CLSID'    { if (Test-Path "HKCU:\Software\Classes\CLSID\$rest") { return 'present' } else { return 'removed' } }
    'RUN'      { if ((Get-Item $parts[1]).Property -contains $parts[2]) { return 'present' } else { return 'removed' } }
    'IFEO'     { foreach ($r in 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') { if ((Get-ItemProperty "$r\$rest").Debugger) { return 'present' } }; return 'removed' }
    'TASK'     {   # match the folder too, not just the name
      $tp = $rest.Substring(0, $rest.LastIndexOf('\') + 1); $tn = $rest.Substring($rest.LastIndexOf('\') + 1)
      if (Get-ScheduledTask -TaskPath $tp -TaskName $tn) { return 'present' } else { return 'removed' }
    }
    'STARTUP'  { if (Test-Path -LiteralPath $rest) { return 'present' } else { return 'removed' } }
  }
  $pm = [regex]::Match($where, '\[(\d+)\]$')
  if ($pm.Success) {
    # Process IDs get reused: only "running" if that process already existed when the alert was raised.
    $gp = Get-Process -Id ([int]$pm.Groups[1].Value)
    if ($gp -and (-not $when -or $gp.StartTime -le ([datetime]$when).AddSeconds(30))) { return 'running' } else { return 'stopped' }
  }
  return 'unknown'
}
function Get-FriendlyKind([string]$k) {
  $k = ($k -replace ' (APPEARED|RUNNING)$', '').Trim()
  switch ($k) {
    'INFECTED FILE' { 'Infected program file' } 'INFECTED PROGRAM' { 'Infected program file' } 'AUTO-QUARANTINED' { 'Infected program file (auto-quarantined)' }
    'DLL HIJACK' { 'Fake system file next to Explorer' } 'TAMPERED FILE' { 'Tampered program file' } 'TAMPERED SYSTEM FILE' { 'Tampered Windows file' }
    'DISGUISED PROGRAM' { 'Program disguised as another file type' } 'HIDDEN PROGRAM' { 'Program with an unusual file type' }
    'NEW UNSIGNED SYSTEM FILE' { 'New unsigned Windows file' } 'STARTUP/PERSISTENCE' { 'Suspicious startup entry' } 'STARTUP CHANGE' { 'Changed startup entry' }
    'MSBUILD COPY' { 'Build tool copied by malware' } 'SIMPLEAV MODIFIED' { 'SimpleAV file was changed' } 'SUSPICIOUS PROCESS' { 'Suspicious hidden command' }
    'SUSPICIOUS MSBUILD' { 'Build tool abused by malware' }
    default { (Get-Culture).TextInfo.ToTitleCase($k.ToLower()) }
  }
}
function Get-FriendlyWhere([string]$w) {
  $p = $w.Split('|')
  switch ($p[0]) {
    'RUN'      { return "Startup list: $($p[2])" }
    'WINLOGON' { return 'Windows logon settings (Winlogon Shell)' }
    'ENV'      { return "Your user settings: $($p[1])" }
    'CLSID'    { return "Registry key $($p[1])" }
    'IFEO'     { return "Program blocker for $($p[1])" }
    'TASK'     { return "Scheduled task $($p[1])" }
    'STARTUP'  { return "Startup folder: $(Split-Path $p[1] -Leaf)" }
  }
  return $w
}
function Get-Model {
  $m = [ordered]@{}
  $m.WatchOn = @(Get-EngineProcs '-Watch').Count -gt 0
  $m.Scan = Get-LastScan
  $m.Next = (Get-ScheduledTaskInfo -TaskName 'SimpleAV Daily Scan').NextRunTime
  $today = Get-Date -Format 'yyyy-MM-dd'
  $m.AlertsToday = 0
  $qmap = Get-QuarantineMap
  $rows = New-Object System.Collections.Generic.List[object]
  $seen = @{}

  # 1) Cleanup history (grouped by app)
  $hist = @(); if (Test-Path $HistFile) { $hist = @(Import-Csv $HistFile) }
  $deleted = 0
  foreach ($g in ($hist | Where-Object { $_.Group } | Group-Object Group)) {
    $left = 0; $clean = 0
    foreach ($h in $g.Group) {
      $seen[$h.Where.ToLowerInvariant()] = 1
      if (Test-Path -LiteralPath $h.Where) { if ((Test-StillInfected $h.Where) -ne $false) { $left++ } else { $clean++ } }
    }
    $deleted += ($g.Count - $left)
    $st = if ($left) { 'present' } elseif ($clean) { 'replaced' } else { 'deleted' }
    $extra = if ($left) { "`n`n$left of these files are STILL infected on your PC." } elseif ($clean) { "`n`n$clean file(s) have since been replaced by a clean reinstall (checked: no virus code)." } else { '' }
    $rows.Add([pscustomobject]@{ Title = "Infected program files - $($g.Name)"; Where = "$($g.Count) file(s) in the $($g.Name) folder"; Status = $st
      Date = [datetime]$g.Group[0].Date; Detail = "These $($g.Name) program files had virus code attached. They were deleted during the cleanup.`nReinstall $($g.Name) from its official website if you still need it.$extra"; Path = '' })
  }
  foreach ($h in ($hist | Where-Object { -not $_.Group })) {
    $st = Get-ItemStatus $h.Where '' $qmap
    if ($st -eq 'deleted' -and $h.Action -eq 'Quarantined' -and $qmap.ContainsKey($h.Where.ToLowerInvariant())) { $st = 'quarantined' }
    if ($st -in 'deleted', 'removed') { $deleted++ }
    $seen[$h.Where.ToLowerInvariant()] = 1
    $rows.Add([pscustomobject]@{ Title = $h.Threat; Where = (Get-FriendlyWhere $h.Where); Status = $st; Date = [datetime]$h.Date; Detail = "$($h.Threat)`nLocation: $($h.Where)`nAction taken: $($h.Action)"; Path = $(if ($h.Where -match '^[A-Za-z]:\\') { $h.Where } else { '' }); Q = $qmap[$h.Where.ToLowerInvariant()] })
  }

  # 2) Findings from every scan (high + medium)
  foreach ($csv in Get-ChildItem $LogDir -Filter 'scan_*.csv' | Sort-Object LastWriteTime -Descending) {
    if (Test-ScanLogIsTest $csv.FullName) { continue }   # test scans don't count
    foreach ($r in Import-Csv $csv.FullName) {
      if ($r.Severity -notin 'HIGH', 'MEDIUM') { continue }
      if ($r.Kind -eq 'UNSIGNED SYSTEM FILE') { continue }   # old harmless Microsoft runtimes, now remembered as known
      if ($r.Path -match $TestPathRx) { continue }
      $key = ($r.Kind + '|' + $r.Path).ToLowerInvariant()
      if ($seen.ContainsKey($key) -or $seen.ContainsKey($r.Path.ToLowerInvariant())) { continue }
      $seen[$key] = 1
      $rows.Add([pscustomobject]@{ Title = (Get-FriendlyKind $r.Kind); Where = (Get-FriendlyWhere $r.Path); Status = (Get-ItemStatus $r.Path $r.Kind $qmap $r.Time); Date = [datetime]$r.Time; Detail = "$(Get-FriendlyKind $r.Kind)`nLocation: $($r.Path)`nWhy: $($r.Detail)`nRisk: $($r.Severity)"; Path = $(if ($r.Path -match '^[A-Za-z]:\\') { $r.Path } else { '' }); Q = $qmap[$r.Path.ToLowerInvariant()] })
    }
  }

  # 3) Watcher alerts (HIGH = threat rows; count today's HIGH+MEDIUM)
  foreach ($wf in Get-ChildItem $LogDir -Filter 'watch_*.log' | Sort-Object LastWriteTime -Descending | Select-Object -First 30) {
    foreach ($line in Get-Content $wf.FullName) {
      $x = [regex]::Match($line, '^\[(.{19})\] (HIGH|MEDIUM) +(.+?) {2,}(.+?)  -> (.*)$')
      if (-not $x.Success) { continue }
      $when = [datetime]::ParseExact($x.Groups[1].Value, 'yyyy-MM-dd HH:mm:ss', $null); $sev = $x.Groups[2].Value; $kind = $x.Groups[3].Value.Trim(); $where = $x.Groups[4].Value.Trim()
      if ($where -match $TestPathRx) { continue }
      if ($x.Groups[1].Value.StartsWith($today)) { $m.AlertsToday++ }
      if ($sev -ne 'HIGH') { continue }
      $key = ($kind + '|' + $where).ToLowerInvariant(); if ($seen.ContainsKey($key)) { continue }; $seen[$key] = 1
      $rows.Add([pscustomobject]@{ Title = (Get-FriendlyKind $kind); Where = (Get-FriendlyWhere $where); Status = (Get-ItemStatus $where $kind $qmap $when); Date = $when; Detail = "Caught live by the watcher.`nLocation: $where`nWhy: $($x.Groups[5].Value)"; Path = $(if ($where -match '^[A-Za-z]:\\') { $where } else { '' }); Q = $qmap[$where.ToLowerInvariant()] })
    }
  }

  $rank = @{ present = 0; running = 0; unknown = 1; quarantined = 2 }
  $m.Rows = @($rows | Sort-Object @{ Expression = { if ($rank.ContainsKey($_.Status)) { $rank[$_.Status] } else { 3 } } }, @{ Expression = { $_.Date }; Descending = $true })
  $m.Active = @($rows | Where-Object { $_.Status -in 'present', 'running' }).Count
  $m.Quarantined = $qmap.Count
  $m.Removed = $deleted + @($rows | Where-Object { $_.Status -in 'stopped', 'resolved' }).Count
  return [pscustomobject]$m
}
function Get-StatusLook([string]$s) {
  switch ($s) {
    'present'     { @('Still on your PC', $C.RedText, $C.RedTint) }
    'running'     { @('Running now', $C.RedText, $C.RedTint) }
    'quarantined' { @('Quarantined', $C.QText, $C.GrayTint) }
    'deleted'     { @('Deleted', $C.GreenText, $C.GreenTint) }
    'removed'     { @('Removed', $C.GreenText, $C.GreenTint) }
    'replaced'    { @('Replaced (clean)', $C.GreenText, $C.GreenTint) }
    'stopped'     { @('Stopped', $C.GreenText, $C.GreenTint) }
    'resolved'    { @('Resolved', $C.GreenText, $C.GreenTint) }
    default       { @('Check details', $C.OrangeText, $C.OrangeTint) }
  }
}
function Format-When([datetime]$d) {
  $time = if ($d.TimeOfDay.Ticks -eq 0) { '' } else { ', ' + $d.ToString('HH:mm') }   # date-only records show no time
  if ($d.Date -eq (Get-Date).Date) { return 'Today' + $time }
  if ($d.Date -eq (Get-Date).Date.AddDays(-1)) { return 'Yesterday' + $time }
  return $d.ToString('ddd d MMM') + $time
}

# ================================================================== drawing helpers
function New-RoundPath([single]$x, [single]$y, [single]$w, [single]$h, [single]$r) {
  $p = New-Object System.Drawing.Drawing2D.GraphicsPath; $d = $r * 2
  $p.AddArc($x, $y, $d, $d, 180, 90); $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
  $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90); $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90); $p.CloseFigure(); return $p
}
function Set-DoubleBuffer($ctrl) { $ctrl.GetType().GetProperty('DoubleBuffered', [Reflection.BindingFlags]'NonPublic,Instance').SetValue($ctrl, $true, $null) }
function Prep-Graphics($g) { $g.SmoothingMode = 'AntiAlias'; $g.TextRenderingHint = 'ClearTypeGridFit' }
function New-Text($text, $x, $y, $w, $h, $font, $color, $parent) {
  $l = New-Object System.Windows.Forms.Label
  $l.Text = $text; $l.Location = New-Object System.Drawing.Point($x, $y); $l.Size = New-Object System.Drawing.Size($w, $h)
  $l.Font = $font; $l.ForeColor = $color; $l.BackColor = $parent.BackColor; $l.UseMnemonic = $false
  $parent.Controls.Add($l); return $l
}
function New-Link($text, $x, $y, $parent, $onClick) {
  $l = New-Object System.Windows.Forms.LinkLabel
  $l.Text = $text; $l.AutoSize = $true; $l.Location = New-Object System.Drawing.Point($x, $y); $l.Font = $F.Link
  $l.LinkColor = $C.Blue; $l.ActiveLinkColor = $C.BlueHover; $l.DisabledLinkColor = $C.Sub; $l.LinkBehavior = 'HoverUnderline'; $l.BackColor = $parent.BackColor
  $l.Add_LinkClicked($onClick); $parent.Controls.Add($l); return $l
}
# Pill-shaped buttons (custom drawn). 'fill' = primary (blue), 'outline' = secondary (white with grey border)
function New-Pill($text, $x, $y, $w, $h, $parent, $onClick, [string]$style = 'fill') {
  $b = New-Object System.Windows.Forms.Panel
  $b.Location = New-Object System.Drawing.Point($x, $y); $b.Size = New-Object System.Drawing.Size($w, $h); $b.BackColor = $parent.BackColor; $b.Cursor = 'Hand'
  $b.Tag = @{ Text = $text; Fill = $C.Blue; Hover = $C.BlueHover; Fore = [System.Drawing.Color]::White; IsHover = $false; On = $true; Style = $style }
  Set-DoubleBuffer $b
  $b.Add_Paint({ param($s, $e)
    $t = $s.Tag; $g = $e.Graphics; Prep-Graphics $g
    $path = New-RoundPath 0.5 0.5 ($s.Width - 2) ($s.Height - 2) (($s.Height - 2) / 2)
    if ($t.Style -eq 'outline') {
      $bg = if ($t.On -and $t.IsHover) { $C.Bg } else { $C.Card }
      $br = New-Object System.Drawing.SolidBrush($bg); $g.FillPath($br, $path); $br.Dispose()
      $pn = New-Object System.Drawing.Pen($C.Border, 1); $g.DrawPath($pn, $path); $pn.Dispose()
      $fore = if ($t.On) { $C.Blue } else { $C.Disabled }
      $font = $F.Small
    } else {
      $fill = if (-not $t.On) { $C.BlueDis } elseif ($t.IsHover) { $t.Hover } else { $t.Fill }
      $br = New-Object System.Drawing.SolidBrush($fill); $g.FillPath($br, $path); $br.Dispose()
      $fore = $t.Fore; $font = $F.Btn
    }
    $path.Dispose()
    [System.Windows.Forms.TextRenderer]::DrawText($g, $t.Text, $font, $s.ClientRectangle, $fore, [System.Windows.Forms.TextFormatFlags]'HorizontalCenter, VerticalCenter')
  })
  $b.Add_MouseEnter({ $this.Tag.IsHover = $true; $this.Invalidate() })
  $b.Add_MouseLeave({ $this.Tag.IsHover = $false; $this.Invalidate() })
  $b.Add_Click($onClick)
  $parent.Controls.Add($b); return $b
}
function Set-PillEnabled($b, [bool]$on) { $b.Tag.On = $on; $b.Cursor = $(if ($on) { 'Hand' } else { 'Default' }); $b.Invalidate() }
# The SimpleAV logo (same geometry as tools\Build-Icon.ps1): blue gradient shield + white check
function Draw-Logo($g, [single]$x, [single]$y, [single]$size) {
  $k = $size / 33.0
  $P = { param([single]$px, [single]$py) New-Object System.Drawing.PointF(($x + ($px - 4) * $k + (($size - 22 * $k) / 2)), ($y + ($py - 3) * $k)) }
  $path = New-Object System.Drawing.Drawing2D.GraphicsPath
  $path.AddLine((& $P 4 8), (& $P 15 3)); $path.AddLine((& $P 15 3), (& $P 26 8))
  $path.AddBezier((& $P 26 8), (& $P 26 24), (& $P 21 32), (& $P 15 36)); $path.AddBezier((& $P 15 36), (& $P 9 32), (& $P 4 24), (& $P 4 8)); $path.CloseFigure()
  $br = New-Object System.Drawing.Drawing2D.LinearGradientBrush((New-Object System.Drawing.PointF(0, $y)), (New-Object System.Drawing.PointF(0, ($y + $size))), (RGB '#2A8CFF'), (RGB '#0060D0'))
  $g.FillPath($br, $path); $br.Dispose(); $path.Dispose()
  $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, [single](2.6 * $k)); $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
  $g.DrawLines($pen, [System.Drawing.PointF[]]@((& $P 10 19.5), (& $P 14 23.5), (& $P 21 14.5))); $pen.Dispose()
}
function Set-Pill($b, [string]$text, $fill, $hover, [bool]$on) { $b.Tag.Text = $text; $b.Tag.Fill = $fill; $b.Tag.Hover = $hover; $b.Tag.On = $on; $b.Cursor = $(if ($on) { 'Hand' } else { 'Default' }); $b.Invalidate() }

# ================================================================== window
$form = New-Object System.Windows.Forms.Form
$form.Text = 'SimpleAV - Made by Beyrem'
$form.ClientSize = New-Object System.Drawing.Size(1000, 790)
$form.StartPosition = 'CenterScreen'; $form.FormBorderStyle = 'FixedSingle'; $form.MaximizeBox = $false
$IcoFile = @((Join-Path $Dir 'SimpleAV.ico'), (Join-Path $PSScriptRoot 'SimpleAV.ico')) | Where-Object { Test-Path $_ } | Select-Object -First 1
$form.Icon = if ($IcoFile) { New-Object System.Drawing.Icon($IcoFile) } else { [System.Drawing.SystemIcons]::Shield }; $form.BackColor = $C.Bg; $form.Font = $F.Body
Set-DoubleBuffer $form

# Cards are painted on the form (soft shadow + 14px corners); content panels sit inset inside them
$Cards = @(
  @(32, 76, 936, 200),     # hero
  @(32, 296, 296, 140), @(352, 296, 296, 140), @(672, 296, 296, 140),   # stats
  @(32, 456, 936, 284)     # threats
)
# Each card draws itself (soft shadow, 14px corners, hairline border); the returned content panel sits inside it
function New-CardPanel($i) {
  $rect = $Cards[$i]   # careful: PowerShell names are case-insensitive, so never call this $c (it would hide the $C palette)
  $card = New-Object System.Windows.Forms.Panel
  $card.Location = New-Object System.Drawing.Point(($rect[0] - 2), ($rect[1] - 2)); $card.Size = New-Object System.Drawing.Size(($rect[2] + 4), ($rect[3] + 6)); $card.BackColor = $C.Bg
  Set-DoubleBuffer $card
  $card.Add_Paint({ param($s, $e)
    $g = $e.Graphics; Prep-Graphics $g
    $w = [single]($s.Width - 5); $h = [single]($s.Height - 7)
    $sh = New-RoundPath 2 4 $w $h 14; $sb = New-Object System.Drawing.SolidBrush($C.Shadow); $g.FillPath($sb, $sh); $sb.Dispose(); $sh.Dispose()
    $p = New-RoundPath 2 2 $w $h 14; $b = New-Object System.Drawing.SolidBrush($C.Card); $g.FillPath($b, $p); $b.Dispose()
    $bp = New-Object System.Drawing.Pen($C.CardEdge, 1); $g.DrawPath($bp, $p); $bp.Dispose(); $p.Dispose()
  })
  $form.Controls.Add($card)
  $p = New-Object System.Windows.Forms.Panel
  $p.Location = New-Object System.Drawing.Point(12, 12); $p.Size = New-Object System.Drawing.Size(($rect[2] - 20), ($rect[3] - 20)); $p.BackColor = $C.Card
  Set-DoubleBuffer $p; $card.Controls.Add($p); return $p
}

# Header
$hdr = New-Object System.Windows.Forms.Panel; $hdr.Location = New-Object System.Drawing.Point(32, 18); $hdr.Size = New-Object System.Drawing.Size(936, 46); $hdr.BackColor = $C.Bg
$form.Controls.Add($hdr)
$hdr.Add_Paint({ param($s, $e) $g = $e.Graphics; Prep-Graphics $g; Draw-Logo $g 0 4 34 })
$null = New-Text 'SimpleAV' 40 4 120 36 $F.App $C.Text $hdr
$null = New-Text 'Made by Beyrem' 160 14 200 22 $F.Sub $C.Sub $hdr

# Hero
$hero = New-CardPanel 0
$hero.Tag = @{ State = 'ok' }
$hero.Add_Paint({ param($s, $e)
  $g = $e.Graphics; Prep-Graphics $g
  $st = $s.Tag.State
  $fill = switch ($st) { 'ok' { $C.GreenFill } 'warn' { $C.OrangeFill } 'bad' { $C.RedFill } default { $C.Blue } }
  $b = New-Object System.Drawing.SolidBrush($fill); $g.FillEllipse($b, 22, 30, 92, 92); $b.Dispose()
  $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, 8); $pen.StartCap = 'Round'; $pen.EndCap = 'Round'
  if ($st -eq 'ok') { $g.DrawLines($pen, [System.Drawing.PointF[]]@((New-Object System.Drawing.PointF(46, 77)), (New-Object System.Drawing.PointF(61, 92)), (New-Object System.Drawing.PointF(90, 61)))) }
  elseif ($st -eq 'scan') {   # spinner: faint full ring + bright moving arc
    $pen.Width = 7
    $faint = New-Object System.Drawing.Pen([System.Drawing.Color]::FromArgb(90, 255, 255, 255), [single]7); $g.DrawEllipse($faint, [single]44, [single]52, [single]48, [single]48); $faint.Dispose()
    $start = ([double]$script:Anim * 12) % 360
    $pts = for ($a = 0; $a -le 100; $a += 5) { $rad = ($start + $a) * [Math]::PI / 180; New-Object System.Drawing.PointF([single](68 + 24 * [Math]::Cos($rad)), [single](76 + 24 * [Math]::Sin($rad))) }
    $g.DrawLines($pen, [System.Drawing.PointF[]]$pts)
  }
  else { $g.DrawLine($pen, [single]68, [single]52, [single]68, [single]82); $wb = New-Object System.Drawing.SolidBrush([System.Drawing.Color]::White); $g.FillEllipse($wb, [single]63, [single]93, [single]10, [single]10); $wb.Dispose() }
  $pen.Dispose()
  if ($st -eq 'scan') {   # thin indeterminate progress bar
    $track = New-RoundPath 150 150 520 6 3; $tb = New-Object System.Drawing.SolidBrush($C.Line); $g.FillPath($tb, $track); $tb.Dispose(); $track.Dispose()
    $x = 150 + (($script:Anim * 7) % 640) - 120; $x1 = [Math]::Max(150, $x); $x2 = [Math]::Min(670, $x + 120)
    if ($x2 -gt $x1 + 6) { $seg = New-RoundPath $x1 150 ($x2 - $x1) 6 3; $bb = New-Object System.Drawing.SolidBrush($C.Blue); $g.FillPath($bb, $seg); $bb.Dispose(); $seg.Dispose() }
  }
})
$lblHero = New-Text 'Loading...' 146 30 540 40 $F.Hero $C.Text $hero
$lblHeroSub = New-Text '' 148 74 540 64 $F.Body $C.Sub $hero
$lblProg = New-Text '' 148 160 540 20 $F.Sub $C.Sub $hero
# One primary action, three secondary scan types, one help link
$btnScan = New-Pill 'Scan now' 704 28 200 44 $hero { if ($this.Tag.On) { if (Test-ScanRunning) { Stop-Scan } else { Start-Scan '-Scan' 'Full scan' } } }
$btnQuick = New-Pill 'Quick' 704 82 58 30 $hero { if ($this.Tag.On) { Start-Scan '-Quick' 'Quick scan' } } 'outline'
$btnAll   = New-Pill 'All drives' 768 82 78 30 $hero { if ($this.Tag.On -and [System.Windows.Forms.MessageBox]::Show("Scan every program file on all your drives?`n`nThis takes a while. You can keep using your PC.", 'SimpleAV', 'YesNo', 'Question') -eq 'Yes') { Start-Scan '-Scan -AllDrives' 'All-drives scan' } } 'outline'
$btnDeep  = New-Pill 'Deep' 852 82 52 30 $hero { if ($this.Tag.On -and [System.Windows.Forms.MessageBox]::Show("Deep scan opens EVERY file on ALL drives - not just programs - and checks what it really is.`nIt catches programs disguised as photos or documents.`n`nThis is the slowest scan (can take hours). You can keep using your PC.`n`nStart?", 'SimpleAV', 'YesNo', 'Question') -eq 'Yes') { Start-Scan '-Deep' 'Deep scan' } } 'outline'
$tipHero = New-Object System.Windows.Forms.ToolTip
$tipHero.SetToolTip($btnScan, 'Full scan: every program on C:, Windows signatures and startup entries (about 7 minutes)')
$tipHero.SetToolTip($btnQuick, 'Quick scan: your user folder only (a few minutes)')
$tipHero.SetToolTip($btnAll, 'Every program file on every drive')
$tipHero.SetToolTip($btnDeep, 'Opens EVERY file on every drive and checks what it really is (slowest)')
$lnkWhat  = New-Link 'What does a scan check?' 704 124 $hero { Show-Coverage }

# Stat cards
$s1 = New-CardPanel 1; $s2 = New-CardPanel 2; $s3 = New-CardPanel 3
$null = New-Text 'REAL-TIME PROTECTION' 8 6 260 18 $F.Cap $C.Sub $s1
$v1 = New-Text '' 8 26 260 36 $F.Value $C.Text $s1
$d1 = New-Text '' 8 64 260 20 $F.Sub $C.Sub $s1
$e1 = New-Text '' 8 84 170 20 $F.Sub $C.Sub $s1
$lnkWatch = New-Link 'Turn off' 200 83 $s1 { Toggle-Watch }
$null = New-Text 'LAST SCAN' 8 6 260 18 $F.Cap $C.Sub $s2
$v2 = New-Text '' 8 26 260 36 $F.Value $C.Text $s2
$d2 = New-Text '' 8 64 260 20 $F.Sub $C.Sub $s2
$e2 = New-Text '' 8 84 260 20 $F.Sub $C.Sub $s2
$null = New-Text 'THREATS' 8 6 260 18 $F.Cap $C.Sub $s3
$v3 = New-Text '' 8 26 260 36 $F.Value $C.Text $s3
$d3 = New-Text '' 8 64 260 20 $F.Sub $C.Sub $s3
$e3 = New-Text '' 8 84 260 20 $F.Sub $C.Sub $s3

# Threat history
$tp = New-CardPanel 4
$null = New-Text 'Threat history' 8 2 300 28 $F.Section $C.Text $tp
$lblCount = New-Text '' 616 8 300 20 $F.Sub $C.Sub $tp; $lblCount.TextAlign = 'TopRight'
$null = New-Text 'Everything SimpleAV found, and what happened to it. Click a row for details.' 8 28 600 20 $F.Sub $C.Sub $tp
$list = New-Object System.Windows.Forms.Panel
$list.Location = New-Object System.Drawing.Point(0, 54); $list.Size = New-Object System.Drawing.Size(916, 210); $list.AutoScroll = $true; $list.BackColor = $C.Card
Set-DoubleBuffer $list; $tp.Controls.Add($list)
$tip = New-Object System.Windows.Forms.ToolTip; $tip.AutoPopDelay = 15000

# Footer
$foot = New-Object System.Windows.Forms.Panel; $foot.Location = New-Object System.Drawing.Point(32, 752); $foot.Size = New-Object System.Drawing.Size(936, 28); $foot.BackColor = $C.Bg; $form.Controls.Add($foot)
$null = New-Text "SimpleAV $Version  |  Made by Beyrem" 0 4 400 20 $F.Sub $C.Sub $foot
$lnkAuto = New-Link 'Auto-quarantine: On' 430 3 $foot { Toggle-AutoQuarantine }
$tip2 = New-Object System.Windows.Forms.ToolTip
$tip2.SetToolTip($lnkAuto, 'When On, files containing the known virus code are quarantined automatically. Everything else waits for you.')
$null = New-Link 'Open logs' 700 3 $foot { Start-Process explorer.exe -ArgumentList "`"$LogDir`"" }
$null = New-Link 'Open quarantine' 790 3 $foot { $null = New-Item -ItemType Directory -Force -Path $QDir; Start-Process explorer.exe -ArgumentList "`"$QDir`"" }

# ================================================================== rows
function Build-Rows($rows) {
  $list.SuspendLayout(); $list.Controls.Clear()
  if (-not $rows -or $rows.Count -eq 0) {
    $null = New-Text 'Nothing found yet. Run a scan to check your PC.' 8 12 600 24 $F.Body $C.Sub $list
    $list.ResumeLayout(); return
  }
  $y = 0
  foreach ($r in $rows) {
    $p = New-Object System.Windows.Forms.Panel
    $p.Location = New-Object System.Drawing.Point(0, $y); $p.Size = New-Object System.Drawing.Size(($list.ClientSize.Width - 20), 50); $p.BackColor = $C.Card; $p.Cursor = 'Hand'; $p.Tag = $r
    Set-DoubleBuffer $p
    $p.Add_Paint({ param($s, $e)
      $g = $e.Graphics; Prep-Graphics $g; $r = $s.Tag; $look = Get-StatusLook $r.Status
      $sz = [System.Windows.Forms.TextRenderer]::MeasureText($look[0], $F.Pill)
      $pw = $sz.Width + 14; $pill = New-RoundPath 8 14 $pw 22 11
      $pb = New-Object System.Drawing.SolidBrush($look[2]); $g.FillPath($pb, $pill); $pb.Dispose(); $pill.Dispose()
      [System.Windows.Forms.TextRenderer]::DrawText($g, $look[0], $F.Pill, (New-Object System.Drawing.Rectangle(8, 14, $pw, 22)), $look[1], [System.Windows.Forms.TextFormatFlags]'HorizontalCenter, VerticalCenter')
      $tx = 150; $tw = $s.Width - $tx - 150
      [System.Windows.Forms.TextRenderer]::DrawText($g, $r.Title, $F.Row, (New-Object System.Drawing.Rectangle($tx, 6, $tw, 20)), $C.Text, [System.Windows.Forms.TextFormatFlags]'EndEllipsis, NoPrefix')
      [System.Windows.Forms.TextRenderer]::DrawText($g, $r.Where, $F.Sub, (New-Object System.Drawing.Rectangle($tx, 26, $tw, 18)), $C.Sub, [System.Windows.Forms.TextFormatFlags]'PathEllipsis, NoPrefix')
      [System.Windows.Forms.TextRenderer]::DrawText($g, (Format-When $r.Date), $F.Sub, (New-Object System.Drawing.Rectangle(($s.Width - 145), 16, 140, 18)), $C.Sub, [System.Windows.Forms.TextFormatFlags]'Right, NoPrefix')
      $lp = New-Object System.Drawing.Pen($C.Line, 1); $g.DrawLine($lp, $tx, ($s.Height - 1), $s.Width, ($s.Height - 1)); $lp.Dispose()
    })
    $p.Add_MouseEnter({ $this.BackColor = $C.Bg; $this.Invalidate() })
    $p.Add_MouseLeave({ $this.BackColor = $C.Card; $this.Invalidate() })
    $p.Add_Click({ Show-Row $this.Tag })
    $tip.SetToolTip($p, $r.Detail)
    $list.Controls.Add($p); $y += 50
  }
  $list.ResumeLayout()
}
# Runs the engine for a quarantine/restore action and returns its exit code.
# Asks for admin rights ONLY on exit 5 (Windows denied access) - never for a bad record or a file in use.
function Invoke-EngineAction([string]$verb, [string]$target) {
  $argLine = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Engine`" -$verb `"$target`""
  $p = Start-Process $PS -ArgumentList $argLine -WindowStyle Hidden -Wait -PassThru
  if ($p.ExitCode -eq 5) {
    if ([System.Windows.Forms.MessageBox]::Show("Windows needs administrator permission for this file.`n`nContinue? (Windows will ask you to confirm.)", 'SimpleAV', 'YesNo', 'Question') -ne 'Yes') { return -1 }
    try { $p = Start-Process $PS -ArgumentList $argLine -Verb RunAs -WindowStyle Hidden -Wait -PassThru } catch { return -1 }
  }
  return $p.ExitCode
}
$ActionErrors = @{
  2  = 'The file is no longer there.'
  3  = "SimpleAV refused: the quarantine record is invalid, or the quarantined file doesn't match the fingerprint (SHA-256) taken when it was quarantined."
  4  = 'A file already exists at the original location (for example a clean reinstall). SimpleAV never overwrites it. Rename or remove that file first if you really want the old one back.'
  5  = 'Windows denied access, even with administrator rights.'
  6  = 'The file is in use. Close the program using it (or restart your PC), then try again.'
  -1 = 'Cancelled.'
}
function Show-Row($r) {
  $look = Get-StatusLook $r.Status
  $isFile = $r.Path -and (Test-Path -LiteralPath $r.Path)
  # Threat still present -> offer quarantine
  if ($r.Status -eq 'present' -and $isFile) {
    $ans = [System.Windows.Forms.MessageBox]::Show("$($r.Detail)`n`nStatus: $($look[0])`n`nQuarantine it now?`nThe file is moved to SimpleAV's quarantine and renamed so it can never run. You can restore it later.`n`nYes = Quarantine     No = Show in Explorer     Cancel = Close", 'SimpleAV', 'YesNoCancel', 'Warning')
    if ($ans -eq 'Yes') {
      $code = Invoke-EngineAction 'Quarantine' $r.Path
      if ($code -eq 0) { [System.Windows.Forms.MessageBox]::Show("Quarantined:`n$($r.Path)", 'SimpleAV', 'OK', 'Information') | Out-Null }
      else { [System.Windows.Forms.MessageBox]::Show("Could not quarantine the file.`n`n$($ActionErrors[[int]$code])", 'SimpleAV', 'OK', 'Error') | Out-Null }
      $script:RowsKey = ''; Refresh-All
    } elseif ($ans -eq 'No') { Start-Process explorer.exe -ArgumentList "/select,`"$($r.Path)`"" }
    return
  }
  # Quarantined -> offer restore (with a clear warning)
  if ($r.Status -eq 'quarantined' -and $r.Q) {
    $ans = [System.Windows.Forms.MessageBox]::Show("$($r.Detail)`n`nStatus: Quarantined - locked away in:`n$($r.Q)`n`nIt can't run there. Nothing to do.`n`nRestore it to its original place? Only do this if you are SURE it is safe.", 'SimpleAV', 'YesNo', 'Information', 'Button2')
    if ($ans -eq 'Yes') {
      $code = Invoke-EngineAction 'Restore' $r.Q
      if ($code -eq 0) { [System.Windows.Forms.MessageBox]::Show("Restored to:`n$($r.Path)", 'SimpleAV', 'OK', 'Information') | Out-Null }
      else { [System.Windows.Forms.MessageBox]::Show("Could not restore the file.`n`n$($ActionErrors[[int]$code])", 'SimpleAV', 'OK', 'Error') | Out-Null }
      $script:RowsKey = ''; Refresh-All
    }
    return
  }
  $what = switch ($r.Status) {
    'present'     { "It is STILL on your PC. Check the details, then remove it (step-by-step: README, section 'If SimpleAV finds something') and run a new scan." }
    'running'     { 'It is RUNNING right now. Restart your PC, then run a scan.' }
    'quarantined' { 'It was moved into quarantine and renamed so it can never run. Nothing to do.' }
    'deleted'     { 'It was deleted from your PC. Nothing to do.' }
    'removed'     { 'It was removed. Nothing to do.' }
    'replaced'    { 'The infected file was deleted, and a fresh clean copy has been reinstalled since (SimpleAV checked it: no virus code). Nothing to do.' }
    'stopped'     { 'That program is no longer running. Nothing to do.' }
    'resolved'    { 'This was fixed. Nothing to do.' }
    default       { 'SimpleAV cannot check this one automatically. Open the logs for details.' }
  }
  $msg = "$($r.Detail)`n`nStatus: $($look[0])`n$what"
  if ($isFile) {
    if ([System.Windows.Forms.MessageBox]::Show("$msg`n`nShow the file in Explorer?", 'SimpleAV', 'YesNo', 'Information') -eq 'Yes') { Start-Process explorer.exe -ArgumentList "/select,`"$($r.Path)`"" }
  } else { [System.Windows.Forms.MessageBox]::Show($msg, 'SimpleAV', 'OK', 'Information') | Out-Null }
}

# ================================================================== refresh
function Set-Hero([string]$state, [string]$title, [string]$sub) { $hero.Tag.State = $state; $lblHero.Text = $title; $lblHeroSub.Text = $sub; $hero.Invalidate() }
function Refresh-All {
  $m = Get-Model; $script:Model = $m
  # Real-time card
  $v1.Text = $(if ($m.WatchOn) { 'On' } else { 'Off' }); $v1.ForeColor = $(if ($m.WatchOn) { $C.GreenText } else { $C.RedText })
  $d1.Text = $(if ($m.WatchOn) { 'Watching files, programs and startup' } else { "You won't get instant warnings" })
  $e1.Text = $(if ($m.AlertsToday) { "$($m.AlertsToday) alert(s) today" } else { 'No alerts today' })
  $lnkWatch.Text = $(if ($m.WatchOn) { 'Turn off' } else { 'Turn on' })
  $lnkAuto.Text = 'Auto-quarantine: ' + $(if (Get-AutoQuarantine) { 'On' } else { 'Off' })
  # Last scan card
  if ($m.Scan) {
    $v2.Text = Format-When $m.Scan.Time
    $d2.Text = '{0}  |  {1:N0} programs checked' -f $m.Scan.Mode, $m.Scan.Files
    $e2.Text = $(if ($null -eq $m.Scan.Skipped) { 'Next automatic scan: ' + $(if ($m.Next) { Format-When $m.Next } else { 'not set' }) } elseif ($m.Scan.Skipped -gt 0) { "$($m.Scan.Skipped) folder(s) couldn't be read" } else { 'Nothing was skipped' })
  } else { $v2.Text = 'Never'; $d2.Text = 'Run a scan to check your PC'; $e2.Text = '' }
  # Threats card
  $v3.Text = "$($m.Active) active"; $v3.ForeColor = $(if ($m.Active) { $C.RedText } else { $C.GreenText })
  $d3.Text = "$($m.Quarantined) quarantined  |  $($m.Removed) deleted or removed"
  $e3.Text = $(if ($m.Active) { 'See the list below' } else { 'Nothing dangerous left on your PC' })
  # Hero
  if (Test-ScanRunning) { }   # handled by progress
  elseif ($m.Active -gt 0) { Set-Hero 'bad' "$($m.Active) threat(s) need attention" 'They are marked "Still on your PC" in the list below. Click one to see what to do, then run a new scan.' }
  elseif (-not $m.WatchOn) { Set-Hero 'warn' 'Real-time protection is off' 'Turn it on so SimpleAV can warn you the moment something suspicious happens.' }
  elseif (-not $m.Scan) { Set-Hero 'warn' 'Time for a first scan' 'Click Scan now to check every program on C:.' }
  elseif (((Get-Date) - $m.Scan.Time).TotalDays -gt 3) { Set-Hero 'warn' "It's been a while since your last scan" 'Click Scan now to check every program on C:.' }
  else { Set-Hero 'ok' 'Your PC is protected' ("No active threats. Last checked {0}.`nThe watcher is on and keeps an eye on new files and programs." -f (Format-When $m.Scan.Time).ToLower()) }
  $lblCount.Text = '{0} item(s)  |  {1} need attention' -f $m.Rows.Count, $m.Active
  $key = ($m.Rows | ForEach-Object { $_.Status + $_.Title + $_.Where }) -join '|'
  if ($key -ne $script:RowsKey) { $script:RowsKey = $key; Build-Rows $m.Rows }
}
function Refresh-Progress {
  $running = Test-ScanRunning
  foreach ($b in $btnQuick, $btnAll, $btnDeep) { if ($b.Tag.On -eq $running) { Set-PillEnabled $b (-not $running) } }
  if ($running) {
    Set-Pill $btnScan 'Stop scan' $C.GrayFill (RGB '#7C7C80') $true
    $p = Get-Progress
    if ($hero.Tag.State -ne 'scan') { $hero.Tag.State = 'scan'; $hero.Invalidate() }
    if ($p -and $p.state -eq 'running') {
      $lblHero.Text = "$($p.mode) scan in progress"
      $lblHeroSub.Text = "You can keep using your PC.`n" + $p.phase
      $lblProg.Text = '{0:N0} files checked  |  {1} high-risk  |  {2} medium-risk found so far' -f [int64]$p.files, $p.high, $p.medium
    } else { $lblHero.Text = 'Starting scan...'; $lblHeroSub.Text = 'You can keep using your PC.'; $lblProg.Text = '' }
  } else {
    Set-Pill $btnScan 'Scan now' $C.Blue $C.BlueHover $true
    $lblProg.Text = ''
    if ($script:WasScanning) {
      # Reset BEFORE the dialog: the 1 s timer keeps ticking inside a modal message loop, and would
      # otherwise see WasScanning = true again and stack one "Scan finished" dialog per second.
      $script:WasScanning = $false
      $script:Busy = $true
      try {
        Refresh-All
        $s = Get-LastScan
        if ($s) {
          $icon = if ($s.High) { 'Warning' } else { 'Information' }
          $cov = if ($null -ne $s.Skipped) { "`nFolders that couldn't be read: $($s.Skipped)" } else { '' }
          [System.Windows.Forms.MessageBox]::Show(("Scan finished: {0}`n`nPrograms checked: {1:N0}`nHigh-risk found: {2}`nMedium-risk found: {3}{4}`n`nAnything found is listed in Threat history." -f $s.Mode, $s.Files, $s.High, $s.Med, $cov), 'SimpleAV', 'OK', $icon) | Out-Null
        }
      } finally { $script:Busy = $false }
    }
  }
  $script:WasScanning = $running
}

# ================================================================== actions
function Start-Scan([string]$flags, [string]$name) {
  if (Test-ScanRunning) { return }
  Remove-Item $ProgFile -Force
  Start-Process $PS -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Engine`" $flags -NoPopup" -WindowStyle Hidden
  $script:Launched = Get-Date
  Refresh-Progress
}
function Stop-Scan {
  if ([System.Windows.Forms.MessageBox]::Show('Stop the scan that is running?', 'SimpleAV', 'YesNo', 'Question') -ne 'Yes') { return }
  if (-not (Test-ScanRunning)) { Refresh-Progress; return }   # it finished while the question was open
  $p = Get-Progress; if ($p -and $p.pid) { Stop-Process -Id $p.pid -Force }
  Get-EngineProcs '-(Scan|Quick|Deep)' | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
  $script:Launched = [datetime]::MinValue; Remove-Item $ProgFile -Force; $script:WasScanning = $false
  Refresh-Progress; Refresh-All
}
function Toggle-Watch {
  if (@(Get-EngineProcs '-Watch').Count -gt 0) {
    if ([System.Windows.Forms.MessageBox]::Show("Turn off real-time protection?`n`nIt comes back on by itself the next time you log in.", 'SimpleAV', 'YesNo', 'Warning') -eq 'Yes') { Get-EngineProcs '-Watch' | ForEach-Object { Stop-Process -Id $_.ProcessId -Force } }
  } else {
    try { Start-ScheduledTask -TaskName 'SimpleAV Watch' -ErrorAction Stop } catch { Start-Process $PS -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Engine`" -Watch" -WindowStyle Hidden }
    Start-Sleep -Seconds 3
  }
  Refresh-All
}
function Toggle-AutoQuarantine {
  $on = -not (Get-AutoQuarantine)
  $null = New-Item -ItemType Directory -Force -Path $Dir
  ([ordered]@{ AutoQuarantine = $on } | ConvertTo-Json) | Set-Content -Path $SettingsFile -Encoding UTF8
  # restart the watcher so it picks up the new setting
  if (@(Get-EngineProcs '-Watch').Count -gt 0) {
    Get-EngineProcs '-Watch' | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    try { Start-ScheduledTask -TaskName 'SimpleAV Watch' -ErrorAction Stop } catch { Start-Process $PS -ArgumentList "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$Engine`" -Watch" -WindowStyle Hidden }
  }
  $msg = if ($on) { "Auto-quarantine is ON.`n`nFiles containing the known virus code will be quarantined automatically (you can restore them). Everything else still waits for your decision." } else { "Auto-quarantine is OFF.`n`nSimpleAV will only warn you - nothing is moved without your click." }
  [System.Windows.Forms.MessageBox]::Show($msg, 'SimpleAV', 'OK', 'Information') | Out-Null
  Refresh-All
}
function Show-Coverage {
  $s = Get-LastScan
  $last = if ($s -and $null -ne $s.Opened) { "`n`nYour last scan ($($s.Mode), $(Format-When $s.Time)):`n- Files opened: {0:N0}`n- Programs checked: {1:N0}`n- Folders Windows wouldn't let it read: {2}`n- Files that were locked/unreadable: {3}" -f $s.Opened, $s.Files, $s.Skipped, $s.Unreadable } else { '' }
  $txt = @"
Quick scan - every program file in your user folder (where downloads and apps live).
Scan now (Full) - every program file on C:, plus the digital signatures of Windows and your installed apps.
All drives - the same, on every drive (C: to N:).
Deep scan - opens EVERY file on every drive, whatever its name, and checks what it really is. Catches programs disguised as photos or documents.

Every scan also checks all the places a virus can use to start with Windows.

What no scan can see:
- Folders Windows protects from normal apps (the number is shown after each scan and in the log).
- Files packed inside .zip / .rar archives or installers.
- Other virus families. The virus signature (12 exact bytes) only matches ONE file-infector family -
  the one SimpleAV was built for. The other checks are general rules, not signatures for other viruses.
Keep Windows Defender (or another antivirus) on as well - SimpleAV is an extra layer, not a replacement.

Quarantine: files with the known virus code are quarantined automatically (switch in the footer).
Anything else is only reported - click it in Threat history to quarantine or restore it.$last
"@
  [System.Windows.Forms.MessageBox]::Show($txt, 'What does a scan check?', 'OK', 'Information') | Out-Null
}

# ================================================================== timers
$timer = New-Object System.Windows.Forms.Timer; $timer.Interval = 1000
# Skip ticks while a dialog is open: a message box disables the window (CanFocus = false), and refreshing
# underneath it would rebuild the rows or open a second dialog on top.
$timer.Add_Tick({ if ($script:Busy -or -not $form.CanFocus) { return }; $script:Tick++; Refresh-Progress; if (($script:Tick % 15) -eq 0 -and -not $script:WasScanning) { Refresh-All } })
$anim = New-Object System.Windows.Forms.Timer; $anim.Interval = 40
$anim.Add_Tick({ if ($hero.Tag.State -eq 'scan') { $script:Anim++; $hero.Invalidate() } })

if ($SelfTest) {
  Refresh-All; Refresh-Progress
  "HERO [$($hero.Tag.State)]: $($lblHero.Text) | $($lblHeroSub.Text -replace "`n", ' ')"
  "REAL-TIME : $($v1.Text) | $($d1.Text) | $($e1.Text) | link: $($lnkWatch.Text)"
  "LAST SCAN : $($v2.Text) | $($d2.Text) | $($e2.Text)"
  "THREATS   : $($v3.Text) | $($d3.Text) | $($e3.Text)"
  "BUTTON    : $($btnScan.Tag.Text)"
  "COLORS    : card=$($C.Card.Name) bg=$($C.Bg.Name) hero=$($hero.BackColor.Name) heroParent=$($hero.Parent.BackColor.Name) label=$($lblHero.BackColor.Name)"
  "ROWS ($($script:Model.Rows.Count)):"
  foreach ($r in $script:Model.Rows) { '  [{0,-16}] {1}  --  {2}' -f (Get-StatusLook $r.Status)[0], $r.Title, $r.Where }
  return
}
if ($Screenshot) {   # render the real window to a PNG (used for the README)
  # capture exactly what is shown on screen (DrawToBitmap mis-renders nested panels)
  $form.StartPosition = 'Manual'; $form.Location = New-Object System.Drawing.Point(40, 40); $form.ShowInTaskbar = $false; $form.TopMost = $true
  $form.Show(); Refresh-All; Refresh-Progress
  for ($i = 0; $i -lt 25; $i++) { [System.Windows.Forms.Application]::DoEvents(); Start-Sleep -Milliseconds 40 }
  $bmp = New-Object System.Drawing.Bitmap($form.ClientSize.Width, $form.ClientSize.Height)
  $gg = [System.Drawing.Graphics]::FromImage($bmp); $gg.CopyFromScreen($form.PointToScreen((New-Object System.Drawing.Point(0, 0))), (New-Object System.Drawing.Point(0, 0)), $form.ClientSize); $gg.Dispose()
  $bmp.Save($Screenshot, [System.Drawing.Imaging.ImageFormat]::Png); $bmp.Dispose(); $form.Close()
  "saved $Screenshot"; return
}
$form.Add_Shown({ Refresh-All; Refresh-Progress; $timer.Start(); $anim.Start() })
$form.Add_FormClosed({ $timer.Stop(); $anim.Stop() })
[void]$form.ShowDialog()
