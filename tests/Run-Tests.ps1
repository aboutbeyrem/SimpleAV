<#
.SYNOPSIS
  Automated tests for SimpleAV. Uses only harmless samples and a temporary data folder,
  so it never touches your real SimpleAV logs or quarantine.
.DESCRIPTION
  Samples are written to C:\SimpleAV-test-*, outside every folder the real-time watcher watches
  (user profile, ProgramData, C:\Windows). Otherwise an installed watcher would grab the samples
  into your REAL quarantine while the tests run.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tests\Run-Tests.ps1
#>
$ErrorActionPreference = 'Stop'
$repo    = Split-Path -Parent $PSScriptRoot
$engine  = Join-Path $repo 'src\SimpleAV.ps1'
$app     = Join-Path $repo 'src\SimpleAV-App.ps1'
$detect  = Join-Path $repo 'src\SimpleAV.Detection.ps1'
$ps      = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$root    = Join-Path "$env:SystemDrive\" ('SimpleAV-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$home_   = Join-Path $root 'home'
$samples = Join-Path $root 'samples'
$edge    = Join-Path $root 'edge'
$env:SIMPLEAV_HOME = $home_
$script:pass = 0; $script:fail = 0

function Check([string]$name, [bool]$ok, [string]$info = '') {
  if ($ok) { $script:pass++; Write-Host "  PASS  $name" -ForegroundColor Green }
  else     { $script:fail++; Write-Host "  FAIL  $name  $info" -ForegroundColor Red }
}
function Run-Engine([string]$argLine) {
  $p = Start-Process $ps -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$engine`" $argLine" -WindowStyle Hidden -Wait -PassThru
  return $p.ExitCode
}
function Last-Log { Get-ChildItem (Join-Path $home_ 'logs') -Filter 'scan_*.log' | Sort-Object LastWriteTime | Select-Object -Last 1 }
function Last-Findings { $csv = Get-ChildItem (Join-Path $home_ 'logs') -Filter 'scan_*.csv' | Sort-Object LastWriteTime | Select-Object -Last 1; if ($csv) { @(Import-Csv $csv.FullName) } else { @() } }
function Has($findings, [string]$file, [string]$kind) { [bool]($findings | Where-Object { $_.Path -like "*\$file" -and $_.Kind -eq $kind }) }
# Runs a snippet in a fresh PowerShell with the engine dot-sourced (functions only), returns its JSON output.
function Invoke-EngineProbe([string]$body) {
  $probe = Join-Path $root 'probe.ps1'          # a script file: passing multi-line code via -Command mangles quotes
  ". '$engine'`n$body" | Set-Content -LiteralPath $probe -Encoding UTF8
  $out = & $ps -NoProfile -ExecutionPolicy Bypass -File $probe 2>$null | Select-Object -Last 1
  return ($out | ConvertFrom-Json)
}

Write-Host "SimpleAV tests  (temp folder: $root)`n"
try {
  # ---------------------------------------------------------------- 1. syntax
  Write-Host 'Syntax'
  foreach ($f in $engine, $app, $detect) {
    $errs = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$errs)
    Check "$(Split-Path $f -Leaf) parses" ($errs.Count -eq 0) ($errs | Out-String)
  }

  # ---------------------------------------------------------------- 2. deep scan + auto-quarantine
  Write-Host "`nDeep scan of samples (auto-quarantine ON)"
  & (Join-Path $PSScriptRoot 'New-TestSamples.ps1') -Folder $samples -EdgeFolder $edge | Out-Null
  $null = Run-Engine "-Deep -Paths `"$samples`" -SkipSystem -NoPopup"
  $f = Last-Findings
  Check 'exact virus match is auto-quarantined'        (Has $f 'exact_virus.exe' 'AUTO-QUARANTINED')
  Check 'auto-quarantined file left its folder'         (-not (Test-Path (Join-Path $samples 'exact_virus.exe')))
  $q = @(Get-ChildItem (Join-Path $home_ 'quarantine') -Filter 'exact_virus.exe_*.quarantined')
  Check 'quarantined copy + record exist'               ($q.Count -eq 1 -and (Test-Path ($q[0].FullName + '.txt')))
  Check 'heuristic-only sample reported (not moved)'    ((Has $f 'heuristic_only.exe' 'INFECTED FILE') -and (Test-Path (Join-Path $samples 'heuristic_only.exe')))
  Check 'program disguised as .jpeg is HIGH'            (Has $f 'holiday.jpeg' 'DISGUISED PROGRAM')
  Check 'program with unusual extension is MEDIUM'      (Has $f 'game_data.bin' 'HIDDEN PROGRAM')
  Check 'clean program not flagged'                     (-not ($f | Where-Object { $_.Path -like '*\clean.exe' }))
  Check 'text file not flagged'                         (-not ($f | Where-Object { $_.Path -like '*\notes.txt' }))
  Check 'coverage line written'                         ([bool](Select-String -LiteralPath (Last-Log).FullName -Pattern 'COVERAGE: files opened=6 \| programs=5'))
  Check 'summary line uses invariant number format'     ([bool](Select-String -LiteralPath (Last-Log).FullName -Pattern '=== DONE in \d+ min\. Program files checked: [\d,]+ \('))

  # ---------------------------------------------------------------- 3. auto-quarantine OFF
  Write-Host "`nAuto-quarantine OFF"
  & (Join-Path $PSScriptRoot 'New-TestSamples.ps1') -Folder $samples | Out-Null
  Start-Sleep -Seconds 1
  $null = Run-Engine "-Paths `"$samples`" -SkipSystem -NoPopup -NoAutoQuarantine"
  $f = Last-Findings
  Check 'exact match only reported when OFF'           ((Has $f 'exact_virus.exe' 'INFECTED FILE') -and (Test-Path (Join-Path $samples 'exact_virus.exe')))
  Check 'normal scan ignores non-program extensions'    (-not ($f | Where-Object { $_.Path -like '*\holiday.jpeg' }))

  # ---------------------------------------------------------------- 4. PE parsing edge cases
  Write-Host "`nPE parsing edge cases"
  Start-Sleep -Seconds 1
  $null = Run-Engine "-Paths `"$edge`" -SkipSystem -NoPopup -NoAutoQuarantine"
  $f = Last-Findings
  Check '32-bit (PE32) exact match detected'            ((Has $f 'exact_virus32.exe' 'INFECTED FILE') -and ($f | Where-Object { $_.Path -like '*\exact_virus32.exe' }).Detail -like 'known virus code*')
  Check '32-bit structural match detected'              (Has $f 'heuristic32.exe' 'INFECTED FILE')
  Check 'section table past the first 4 KB is parsed'   (Has $f 'far_header.exe' 'INFECTED FILE')

  # ---------------------------------------------------------------- 5. manual quarantine + restore
  Write-Host "`nManual quarantine / restore"
  $target = Join-Path $samples 'heuristic_only.exe'
  $code = Run-Engine "-Quarantine `"$target`""
  Check 'quarantine exit code 0'                        ($code -eq 0) "exit=$code"
  Check 'file moved out'                                (-not (Test-Path $target))
  $qf = Get-ChildItem (Join-Path $home_ 'quarantine') -Filter 'heuristic_only.exe_*.quarantined' | Select-Object -First 1
  Check 'record has original path and SHA-256'          ([bool](Select-String -LiteralPath ($qf.FullName + '.txt') -SimpleMatch "Original path: $target") -and [bool](Select-String -LiteralPath ($qf.FullName + '.txt') -Pattern '^SHA256: [0-9A-F]{64}$'))
  $code = Run-Engine "-Restore `"$($qf.FullName)`""
  Check 'restore exit code 0'                           ($code -eq 0) "exit=$code"
  Check 'file is back in place'                         (Test-Path $target)
  Check 'quarantine record removed'                     (-not (Test-Path ($qf.FullName + '.txt')))
  Check 'quarantining a missing file fails cleanly'     ((Run-Engine "-Quarantine `"$samples\does_not_exist.exe`"") -eq 2)
  $folderTarget = Join-Path $samples 'a_folder'; $null = New-Item -ItemType Directory $folderTarget
  Check 'a folder is never quarantined wholesale'       (((Run-Engine "-Quarantine `"$folderTarget`"") -eq 2) -and (Test-Path $folderTarget))

  # ---------------------------------------------------------------- 6. restore safety
  Write-Host "`nRestore safety"
  $null = Run-Engine "-Quarantine `"$target`""
  $qf = Get-ChildItem (Join-Path $home_ 'quarantine') -Filter 'heuristic_only.exe_*.quarantined' | Sort-Object LastWriteTime | Select-Object -Last 1
  'clean reinstalled copy' | Set-Content $target
  $code = Run-Engine "-Restore `"$($qf.FullName)`""
  Check 'restore refuses to overwrite an existing file' ($code -eq 4) "exit=$code"
  Check 'existing file left untouched'                  ((Get-Content $target) -eq 'clean reinstalled copy')
  Check 'quarantined copy kept after refusal'           (Test-Path -LiteralPath $qf.FullName)
  Remove-Item $target
  $rec = $qf.FullName + '.txt'; $orig = Get-Content $rec
  ($orig -replace '^SHA256: .*$', ('SHA256: ' + ('0' * 64))) | Set-Content $rec
  $code = Run-Engine "-Restore `"$($qf.FullName)`""
  Check 'restore refuses a file whose hash changed'     (($code -eq 3) -and -not (Test-Path $target)) "exit=$code"
  ($orig -replace '^Original path: .*$', 'Original path: ..\..\Startup\evil.exe') | Set-Content $rec
  $code = Run-Engine "-Restore `"$($qf.FullName)`""
  Check 'restore refuses a tampered (relative) path'    ($code -eq 3) "exit=$code"
  $orig | Set-Content $rec
  Check 'restore works again with the genuine record'   ((Run-Engine "-Restore `"$($qf.FullName)`"") -eq 0)

  # ---------------------------------------------------------------- 7. signature cache
  Write-Host "`nSignature cache"
  Start-Sleep -Seconds 1
  $null = Run-Engine "-Paths `"$samples`" -SkipSystem -NoPopup -NoAutoQuarantine -SigAll"
  Start-Sleep -Seconds 1
  $null = Run-Engine "-Paths `"$samples`" -SkipSystem -NoPopup -NoAutoQuarantine -SigAll"
  $m = Select-String -LiteralPath (Last-Log).FullName -Pattern 'signature cache: (\d+) of (\d+) checks reused' | Select-Object -Last 1
  Check 'second scan reuses every unchanged signature'  ($m -and [int]$m.Matches[0].Groups[1].Value -gt 0 -and $m.Matches[0].Groups[1].Value -eq $m.Matches[0].Groups[2].Value) "$($m.Line)"
  Check 'cache file written'                            (Test-Path (Join-Path $home_ 'sigcache.tsv'))

  # ---------------------------------------------------------------- 8. startup-entry rules + self-exclusion
  Write-Host "`nStartup-entry rules"
  $j = Invoke-EngineProbe @'
$self = "powershell.exe -NoProfile -File `"$(Join-Path $AppDir 'SimpleAV.ps1')`" -Watch"
[ordered]@{
  hkcuShell = (Test-PersistenceItem 'WINLOGON|HKCU|Shell' 'explorer.exe,conhost.exe --headless powershell -c x')[0]
  hklmOk    = [string](Test-PersistenceItem 'WINLOGON|HKLM|Shell' 'explorer.exe')
  logonScr  = (Test-PersistenceItem 'ENV|UserInitMprLogonScript' 'powershell -w hidden')[0]
  ifeoDef   = (Test-PersistenceItem 'IFEO|MpCmdRun.exe' 'svchost.exe')[0]
  ifeoOther = (Test-PersistenceItem 'IFEO|wuauclt.exe' 'x')[0]
  runB64    = (Test-PersistenceItem 'RUN|HKCU:\x|evil' 'powershell -c [Convert]::FromBase64String(1)')[0]
  runSelf   = [string](Test-PersistenceItem 'RUN|HKCU:\x|s' $self)
  runSpoof  = (Test-PersistenceItem 'RUN|HKCU:\x|e' 'powershell -w hidden -c "iex(irm x)" #SimpleAV.ps1')[0]
  runBenign = [string](Test-PersistenceItem 'RUN|HKCU:\x|d' '"C:\Program Files\Discord\Update.exe" --processStart Discord.exe')
  inApp     = Test-InAppDir (Join-Path $AppDir 'logs\x.exe')
  sibling   = Test-InAppDir ($AppDir.TrimEnd('\') + 'Update\x.exe')
} | ConvertTo-Json -Compress
'@
  Check 'per-user Winlogon Shell is HIGH'               ($j.hkcuShell -eq 'HIGH')
  Check 'default HKLM Shell is clean'                   ($j.hklmOk -eq '')
  Check 'logon script hook is HIGH'                     ($j.logonScr -eq 'HIGH')
  Check 'IFEO on Defender is HIGH, on others LOW'       ($j.ifeoDef -eq 'HIGH' -and $j.ifeoOther -eq 'LOW')
  Check 'Base64 startup command is HIGH'                ($j.runB64 -eq 'HIGH')
  Check "SimpleAV's own startup entry is not flagged"   ($j.runSelf -eq '')
  Check 'malware mentioning "SimpleAV.ps1" is flagged'  ($j.runSpoof -eq 'HIGH')
  Check 'normal app startup entry is not flagged'       ($j.runBenign -eq '')
  Check 'self-exclusion covers SimpleAV folder only'    ($j.inApp -eq $true -and $j.sibling -eq $false)

  # ---------------------------------------------------------------- 9. dashboard
  Write-Host "`nDashboard"
  $out = & $ps -NoProfile -STA -ExecutionPolicy Bypass -File $app -SelfTest 2>&1 | Out-String
  Check 'dashboard self-test runs'                      ($out -match 'HERO \[') $out
  Check 'test scans are not counted as real scans'      ($out -match 'LAST SCAN : Never') $out
  Check 'test samples not counted as quarantined'       ($out -match 'THREATS   : 0 active \| 0 quarantined') $out
  # A log written by 1.2.0 on a French-language Windows: "54 509" with a no-break space.
  $fake = Join-Path $home_ 'logs\scan_2026-01-01_00-00-00.log'
  @('[2026-01-01 00:00:00] Mode: Full (C:)',
    '[2026-01-01 00:07:00] COVERAGE: files opened=54509 | programs=54509 | folders skipped=3 | files unreadable=0',
    "[2026-01-01 00:07:00] === DONE in 7 min. Program files checked: 54$([char]0xA0)509 (signatures: 1 + 2 system). Findings: HIGH=0 MEDIUM=0 LOW=0 AUTOQ=0") | Set-Content $fake -Encoding UTF8
  $out = & $ps -NoProfile -STA -ExecutionPolicy Bypass -File $app -SelfTest 2>&1 | Out-String
  Check 'program count survives fr-FR number format'    ($out -match "54[\s,\.\u00A0\u202F]?509 programs checked") $out
}
finally {
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item Env:\SIMPLEAV_HOME -ErrorAction SilentlyContinue
}
Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
exit $script:fail
