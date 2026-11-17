<#
.SYNOPSIS
  Creates HARMLESS sample files for testing SimpleAV.
.DESCRIPTION
  The "infected" samples are tiny hand-built Windows program headers that contain the infector's
  12 marker bytes but NO runnable code - they cannot execute and are not malware.
  Samples in -Folder:
    exact_virus.exe     entry point in a writable+executable .reloc section, starting with the marker bytes
    heuristic_only.exe  same layout, but without the marker bytes (structural detection only)
    clean.exe           normal layout (entry point in .text)
    holiday.jpeg        a copy of notepad.exe renamed to .jpeg  (disguised program)
    game_data.bin       a copy of notepad.exe with an unusual extension
    notes.txt           plain text
  Edge cases in -EdgeFolder (optional):
    exact_virus32.exe   32-bit (PE32) program with the marker bytes
    heuristic32.exe     32-bit program, structural pattern only
    far_header.exe      PE header at offset 0xF00, so the section table ends past the first 4 KB
#>
param([Parameter(Mandatory)] [string]$Folder, [string]$EdgeFolder)

function New-FakePE([string]$path, [bool]$infectedLayout, [bool]$withMarker, [int]$bits = 64, [int]$peOff = 0x80) {
  $opt  = if ($bits -eq 32) { 0xE0 } else { 0xF0 }                                  # optional header size
  $so   = $peOff + 24 + $opt                                                        # section table offset
  $raw1 = [int]([Math]::Max(0x400, [Math]::Ceiling(($so + 80) / 0x200) * 0x200))    # .text raw data
  $raw2 = $raw1 + 0x200                                                             # .reloc raw data
  $d = New-Object byte[] ([Math]::Max(4096, $raw2 + 0x200))
  $d[0] = 0x4D; $d[1] = 0x5A                                                        # 'MZ'
  [BitConverter]::GetBytes([int32]$peOff).CopyTo($d, 0x3C)                          # e_lfanew
  [Text.Encoding]::ASCII.GetBytes("PE`0`0").CopyTo($d, $peOff)
  [BitConverter]::GetBytes([uint16]$(if ($bits -eq 32) { 0x14C } else { 0x8664 })).CopyTo($d, $peOff + 4)   # machine
  [BitConverter]::GetBytes([uint16]2).CopyTo($d, $peOff + 6)                        # 2 sections
  [BitConverter]::GetBytes([uint16]$opt).CopyTo($d, $peOff + 20)
  [BitConverter]::GetBytes([uint16]$(if ($bits -eq 32) { 0x10B } else { 0x20B })).CopyTo($d, $peOff + 24)   # PE32 / PE32+
  $ep = if ($infectedLayout) { 0x2010 } else { 0x1010 }
  [BitConverter]::GetBytes([uint32]$ep).CopyTo($d, $peOff + 40)                     # AddressOfEntryPoint
  [Text.Encoding]::ASCII.GetBytes(".text`0`0`0").CopyTo($d, $so)
  foreach ($pair in @(@(8, 0x200), @(12, 0x1000), @(16, 0x200), @(20, $raw1))) { [BitConverter]::GetBytes([uint32]$pair[1]).CopyTo($d, $so + $pair[0]) }
  [BitConverter]::GetBytes([uint32]0x60000020).CopyTo($d, $so + 36)
  $s2 = $so + 40
  [Text.Encoding]::ASCII.GetBytes(".reloc`0`0").CopyTo($d, $s2)
  foreach ($pair in @(@(8, 0x200), @(12, 0x2000), @(16, 0x200), @(20, $raw2))) { [BitConverter]::GetBytes([uint32]$pair[1]).CopyTo($d, $s2 + $pair[0]) }
  $ch = if ($infectedLayout) { [uint32]3758096448 } else { [uint32]0x42000040 }     # 0xE0000040 (RWX) vs 0x42000040
  [BitConverter]::GetBytes($ch).CopyTo($d, $s2 + 36)
  if ($withMarker) { ([byte[]](0xE8,0xD9,0x00,0x00,0x00,0x48,0x8D,0x58,0xFB,0x51,0x52,0x41)).CopyTo($d, $raw2 + 0x10) }
  [IO.File]::WriteAllBytes($path, $d)
}

$null = New-Item -ItemType Directory -Force -Path $Folder
New-FakePE (Join-Path $Folder 'exact_virus.exe') $true $true
New-FakePE (Join-Path $Folder 'heuristic_only.exe') $true $false
New-FakePE (Join-Path $Folder 'clean.exe') $false $false
Copy-Item "$env:SystemRoot\System32\notepad.exe" (Join-Path $Folder 'holiday.jpeg')
Copy-Item "$env:SystemRoot\System32\notepad.exe" (Join-Path $Folder 'game_data.bin')
'just some text' | Set-Content (Join-Path $Folder 'notes.txt')

if ($EdgeFolder) {
  $null = New-Item -ItemType Directory -Force -Path $EdgeFolder
  New-FakePE (Join-Path $EdgeFolder 'exact_virus32.exe') $true $true 32
  New-FakePE (Join-Path $EdgeFolder 'heuristic32.exe') $true $false 32
  New-FakePE (Join-Path $EdgeFolder 'far_header.exe') $true $true 64 0xF00
}
Get-ChildItem $Folder | Select-Object Name, Length
