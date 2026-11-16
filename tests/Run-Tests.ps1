<#
.SYNOPSIS
  Automated tests for SimpleAV. Uses only harmless samples and a temporary data folder,
  so it never touches your real SimpleAV logs or quarantine.
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File tests\Run-Tests.ps1
#>
$ErrorActionPreference = 'Stop'
$repo    = Split-Path -Parent $PSScriptRoot
$engine  = Join-Path $repo 'src\SimpleAV.ps1'
$app     = Join-Path $repo 'src\SimpleAV-App.ps1'
$ps      = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$root    = Join-Path $env:TEMP ('SimpleAV-test-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$home_   = Join-Path $root 'home'
$samples = Join-Path $root 'samples'
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
function Last-Findings { $csv = Get-ChildItem (Join-Path $home_ 'logs') -Filter 'scan_*.csv' | Sort-Object LastWriteTime | Select-Object -Last 1; if ($csv) { @(Import-Csv $csv.FullName) } else { @() } }
function Has($findings, [string]$file, [string]$kind) { [bool]($findings | Where-Object { $_.Path -like "*\$file" -and $_.Kind -eq $kind }) }

Write-Host "SimpleAV tests  (temp folder: $root)`n"
try {
  # ---------------------------------------------------------------- 1. syntax
  Write-Host 'Syntax'
  foreach ($f in $engine, $app) {
    $errs = $null; [void][System.Management.Automation.Language.Parser]::ParseFile($f, [ref]$null, [ref]$errs)
    Check "$(Split-Path $f -Leaf) parses" ($errs.Count -eq 0) ($errs | Out-String)
  }

  # ---------------------------------------------------------------- 2. deep scan + auto-quarantine
  Write-Host "`nDeep scan of samples (auto-quarantine ON)"
  & (Join-Path $PSScriptRoot 'New-TestSamples.ps1') -Folder $samples | Out-Null
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
  $log = Get-ChildItem (Join-Path $home_ 'logs') -Filter 'scan_*.log' | Sort-Object LastWriteTime | Select-Object -Last 1
  Check 'coverage line written'                         ([bool](Select-String -LiteralPath $log.FullName -Pattern 'COVERAGE: files opened=6 \| programs=5'))

  # ---------------------------------------------------------------- 3. auto-quarantine OFF
  Write-Host "`nAuto-quarantine OFF"
  & (Join-Path $PSScriptRoot 'New-TestSamples.ps1') -Folder $samples | Out-Null
  Start-Sleep -Seconds 1
  $null = Run-Engine "-Paths `"$samples`" -SkipSystem -NoPopup -NoAutoQuarantine"
  $f = Last-Findings
  Check 'exact match only reported when OFF'           ((Has $f 'exact_virus.exe' 'INFECTED FILE') -and (Test-Path (Join-Path $samples 'exact_virus.exe')))
  Check 'normal scan ignores non-program extensions'    (-not ($f | Where-Object { $_.Path -like '*\holiday.jpeg' }))

  # ---------------------------------------------------------------- 4. manual quarantine + restore
  Write-Host "`nManual quarantine / restore"
  $target = Join-Path $samples 'heuristic_only.exe'
  $code = Run-Engine "-Quarantine `"$target`""
  Check 'quarantine exit code 0'                        ($code -eq 0) "exit=$code"
  Check 'file moved out'                                (-not (Test-Path $target))
  $qf = Get-ChildItem (Join-Path $home_ 'quarantine') -Filter 'heuristic_only.exe_*.quarantined' | Select-Object -First 1
  Check 'record has original path'                      ([bool](Select-String -LiteralPath ($qf.FullName + '.txt') -SimpleMatch "Original path: $target"))
  $code = Run-Engine "-Restore `"$($qf.FullName)`""
  Check 'restore exit code 0'                           ($code -eq 0) "exit=$code"
  Check 'file is back in place'                         (Test-Path $target)
  Check 'quarantine record removed'                     (-not (Test-Path ($qf.FullName + '.txt')))
  Check 'quarantining a missing file fails cleanly'     ((Run-Engine "-Quarantine `"$samples\does_not_exist.exe`"") -eq 2)

  # ---------------------------------------------------------------- 5. dashboard
  Write-Host "`nDashboard"
  $out = & $ps -NoProfile -STA -ExecutionPolicy Bypass -File $app -SelfTest 2>&1 | Out-String
  Check 'dashboard self-test runs'                      ($out -match 'HERO \[') $out
  Check 'test scans are not counted as real scans'      ($out -match 'LAST SCAN : Never') $out
}
finally {
  Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
  Remove-Item Env:\SIMPLEAV_HOME -ErrorAction SilentlyContinue
}
Write-Host ("`n{0} passed, {1} failed" -f $script:pass, $script:fail) -ForegroundColor $(if ($script:fail) { 'Red' } else { 'Green' })
exit $script:fail
