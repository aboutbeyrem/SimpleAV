<#
.SYNOPSIS
  SimpleAV detection core: byte-level inspection of Windows programs (PE files).
.DESCRIPTION
  Dot-sourced by both the engine (SimpleAV.ps1) and the dashboard (SimpleAV-App.ps1), so the scanner and
  the dashboard's "is this file still infected?" check can never disagree.

  Two detections, both read from the file's CONTENT (never its name or date):
    1) EXACT: the infector's 12-byte code sits at the program's entry point.
    2) STRUCTURAL: the entry point was moved into the LAST section, which is a data section
       (.reloc/.rsrc/...) marked read + write + execute - how this infector family patches programs.
.NOTES
  Author: Beyrem  |  License: MIT
#>

# First 12 bytes of the infector's code, found at the entry point of every infected file analysed.
$script:SAV_Version = '1.3.0'
$script:KnownStub   = [byte[]](0xE8,0xD9,0x00,0x00,0x00,0x48,0x8D,0x58,0xFB,0x51,0x52,0x41)
$script:KnownPrefix = 'known virus code'
$script:DataSections = @('.reloc', '.rsrc', '.data', '.pdata', '.idata', '.tls', '.rdata')
$script:HeaderMax    = 65536   # never read more than this to parse headers

<# Returns a verdict object:
     IsPE       - the file really is a Windows program (MZ + PE signature)
     Reason     - $null if clean, otherwise why it was flagged (exact matches start with $KnownPrefix)
     Unreadable - the file could not be opened (locked / no permission) #>
function Get-PEVerdict([string]$path) {
  $v = [pscustomobject]@{ IsPE = $false; Reason = $null; Unreadable = $false }
  $fs = $null
  try {
    $fs  = [System.IO.File]::Open($path, 'Open', 'Read', 'ReadWrite, Delete')
    $buf = New-Object byte[] 4096
    $n   = $fs.Read($buf, 0, 4096)
    if ($n -lt 64 -or $buf[0] -ne 0x4D -or $buf[1] -ne 0x5A) { return $v }           # 'MZ'
    $pe = [BitConverter]::ToInt32($buf, 0x3C)
    if ($pe -lt 0 -or $pe -gt ($script:HeaderMax - 64) -or ($pe + 64) -gt $fs.Length) { return $v }
    # Headers bigger than 4 KB (padded DOS stub, many sections): read just enough, up to $HeaderMax.
    if (($pe + 64) -gt $n) { $buf = Read-Head $fs ([Math]::Min($script:HeaderMax, $fs.Length)); $n = $buf.Length }
    if ([BitConverter]::ToUInt32($buf, $pe) -ne 17744) { return $v }                   # 'PE\0\0'
    $v.IsPE = $true
    $nsec  = [BitConverter]::ToUInt16($buf, $pe + 6)
    $optsz = [BitConverter]::ToUInt16($buf, $pe + 20)
    $ep    = [int64][BitConverter]::ToUInt32($buf, $pe + 40)                           # same offset in PE32 and PE32+
    $so    = $pe + 24 + $optsz
    $end   = $so + $nsec * 40
    if ($nsec -eq 0 -or $ep -eq 0) { return $v }
    if ($end -gt $n) {
      if ($end -gt [Math]::Min($script:HeaderMax, $fs.Length)) { return $v }          # malformed / truncated
      $buf = Read-Head $fs $end; $n = $buf.Length
    }
    $epIdx = -1; $epName = ''; $epVA = 0; $epRP = 0; $epCh = 0
    for ($i = 0; $i -lt $nsec; $i++) {
      $b  = $so + $i * 40
      $vs = [int64][BitConverter]::ToUInt32($buf, $b + 8)
      $va = [int64][BitConverter]::ToUInt32($buf, $b + 12)
      $rs = [int64][BitConverter]::ToUInt32($buf, $b + 16)
      $rp = [int64][BitConverter]::ToUInt32($buf, $b + 20)
      $ch = [int64][BitConverter]::ToUInt32($buf, $b + 36)
      if ($ep -ge $va -and $ep -lt ($va + [Math]::Max($vs, $rs))) {
        $epIdx = $i; $epVA = $va; $epRP = $rp; $epCh = $ch
        $epName = [Text.Encoding]::ASCII.GetString($buf, $b, 8).TrimEnd([char]0)
      }
    }
    if ($epIdx -lt 0) { return $v }
    # Entry point RVA -> file offset, then read the 12 bytes that actually run first.
    $off  = $epRP + ($ep - $epVA)
    $stub = New-Object byte[] 12
    if ($off -ge 0 -and ($off + 12) -le $fs.Length) { $null = $fs.Seek($off, 'Begin'); $null = $fs.Read($stub, 0, 12) }
    $same = $true; for ($k = 0; $k -lt 12; $k++) { if ($stub[$k] -ne $script:KnownStub[$k]) { $same = $false; break } }
    if ($same) { $v.Reason = "$($script:KnownPrefix) at entry point (section $epName)"; return $v }
    $rwx = (($epCh -band 3758096384) -eq 3758096384)                                   # 0xE0000000 = execute+read+write
    if ($epIdx -eq ($nsec - 1) -and ($script:DataSections -contains $epName) -and $rwx) {
      $v.Reason = "entry point moved into writable+executable '$epName' section (file-infector pattern)"
    }
    return $v
  } catch { $v.Unreadable = $true; return $v } finally { if ($fs) { $fs.Dispose() } }
}
function Read-Head($fs, [int64]$len) {
  $b = New-Object byte[] $len
  $null = $fs.Seek(0, 'Begin'); $got = 0
  while ($got -lt $len) { $r = $fs.Read($b, $got, $len - $got); if ($r -le 0) { break }; $got += $r }
  return $b
}
