<#
.SYNOPSIS
  Creates HARMLESS sample files for testing SimpleAV.
.DESCRIPTION
  The "infected" samples are tiny fake Windows program headers that contain the infector's
  12 marker bytes but NO runnable code - they cannot execute and are not malware.
  Samples:
    exact_virus.exe     entry point in a writable+executable .reloc section, starting with the marker bytes
    heuristic_only.exe  same layout, but without the marker bytes (structural detection only)
    clean.exe           normal layout (entry point in .text)
    holiday.jpeg        a copy of notepad.exe renamed to .jpeg  (disguised program)
    game_data.bin       a copy of notepad.exe with an unusual extension
    notes.txt           plain text
#>
param([Parameter(Mandatory)] [string]$Folder)

function New-FakePE([string]$path, [bool]$infectedLayout, [bool]$withMarker) {
  $d = New-Object byte[] 4096
  $d[0] = 0x4D; $d[1] = 0x5A                                                       # 'MZ'
  [BitConverter]::GetBytes([int32]0x80).CopyTo($d, 0x3C)                           # e_lfanew
  $pe = 0x80
  [Text.Encoding]::ASCII.GetBytes("PE`0`0").CopyTo($d, $pe)
  [BitConverter]::GetBytes([uint16]0x8664).CopyTo($d, $pe + 4)                     # x64
  [BitConverter]::GetBytes([uint16]2).CopyTo($d, $pe + 6)                          # 2 sections
  [BitConverter]::GetBytes([uint16]0xF0).CopyTo($d, $pe + 20)                      # optional header size
  [BitConverter]::GetBytes([uint16]0x20B).CopyTo($d, $pe + 24)                     # PE32+
  $ep = if ($infectedLayout) { 0x2010 } else { 0x1010 }
  [BitConverter]::GetBytes([uint32]$ep).CopyTo($d, $pe + 40)
  $so = $pe + 24 + 0xF0
  [Text.Encoding]::ASCII.GetBytes(".text`0`0`0").CopyTo($d, $so)
  foreach ($pair in @(@(8, 0x200), @(12, 0x1000), @(16, 0x200), @(20, 0x400))) { [BitConverter]::GetBytes([uint32]$pair[1]).CopyTo($d, $so + $pair[0]) }
  [BitConverter]::GetBytes([uint32]0x60000020).CopyTo($d, $so + 36)
  $s2 = $so + 40
  [Text.Encoding]::ASCII.GetBytes(".reloc`0`0").CopyTo($d, $s2)
  foreach ($pair in @(@(8, 0x200), @(12, 0x2000), @(16, 0x200), @(20, 0x600))) { [BitConverter]::GetBytes([uint32]$pair[1]).CopyTo($d, $s2 + $pair[0]) }
  $ch = if ($infectedLayout) { [uint32]3758096448 } else { [uint32]0x42000040 }    # 0xE0000040 (RWX) vs 0x42000040
  [BitConverter]::GetBytes($ch).CopyTo($d, $s2 + 36)
  if ($withMarker) { ([byte[]](0xE8,0xD9,0x00,0x00,0x00,0x48,0x8D,0x58,0xFB,0x51,0x52,0x41)).CopyTo($d, 0x610) }
  [IO.File]::WriteAllBytes($path, $d)
}

$null = New-Item -ItemType Directory -Force -Path $Folder
New-FakePE (Join-Path $Folder 'exact_virus.exe') $true $true
New-FakePE (Join-Path $Folder 'heuristic_only.exe') $true $false
New-FakePE (Join-Path $Folder 'clean.exe') $false $false
Copy-Item "$env:SystemRoot\System32\notepad.exe" (Join-Path $Folder 'holiday.jpeg')
Copy-Item "$env:SystemRoot\System32\notepad.exe" (Join-Path $Folder 'game_data.bin')
'just some text' | Set-Content (Join-Path $Folder 'notes.txt')
Get-ChildItem $Folder | Select-Object Name, Length
