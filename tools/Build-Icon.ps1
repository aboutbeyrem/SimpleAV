<#
.SYNOPSIS
  Builds src\SimpleAV.ico (16-256 px) from the same shield + check mark drawn in the app header,
  so the window, taskbar, tray and shortcuts all show the same logo.
#>
param([string]$Out = (Join-Path (Split-Path -Parent $PSScriptRoot) 'src\SimpleAV.ico'))
Add-Type -AssemblyName System.Drawing

function New-LogoBitmap([int]$s) {
  $bmp = New-Object System.Drawing.Bitmap($s, $s, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
  $g = [System.Drawing.Graphics]::FromImage($bmp)
  $g.SmoothingMode = 'AntiAlias'; $g.PixelOffsetMode = 'HighQuality'; $g.Clear([System.Drawing.Color]::Transparent)
  # Shield geometry (same as the header): box x 4..26, y 3..36  -> scale to fill the square
  $k = ($s * 0.94) / 33.0
  $ox = ($s - 22 * $k) / 2 - 4 * $k
  $oy = ($s - 33 * $k) / 2 - 3 * $k
  function P([single]$x, [single]$y) { New-Object System.Drawing.PointF(($ox + $x * $k), ($oy + $y * $k)) }
  $path = New-Object System.Drawing.Drawing2D.GraphicsPath
  $path.AddLine((P 4 8), (P 15 3)); $path.AddLine((P 15 3), (P 26 8))
  $path.AddBezier((P 26 8), (P 26 24), (P 21 32), (P 15 36)); $path.AddBezier((P 15 36), (P 9 32), (P 4 24), (P 4 8)); $path.CloseFigure()
  $top = [System.Drawing.ColorTranslator]::FromHtml('#2A8CFF'); $bot = [System.Drawing.ColorTranslator]::FromHtml('#0060D0')
  $br = New-Object System.Drawing.Drawing2D.LinearGradientBrush((New-Object System.Drawing.PointF(0, 0)), (New-Object System.Drawing.PointF(0, $s)), $top, $bot)
  $g.FillPath($br, $path)
  $pen = New-Object System.Drawing.Pen([System.Drawing.Color]::White, [single]([Math]::Max(1.6, 2.6 * $k)))
  $pen.StartCap = 'Round'; $pen.EndCap = 'Round'; $pen.LineJoin = 'Round'
  $g.DrawLines($pen, [System.Drawing.PointF[]]@((P 10 19.5), (P 14 23.5), (P 21 14.5)))
  $pen.Dispose(); $br.Dispose(); $path.Dispose(); $g.Dispose()
  return $bmp
}

# ICO file = header + directory + PNG images (supported since Windows Vista)
$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
$pngs = foreach ($s in $sizes) { $b = New-LogoBitmap $s; $ms = New-Object IO.MemoryStream; $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png); $b.Dispose(); ,($ms.ToArray()) }
$icoStream = New-Object IO.MemoryStream; $w = New-Object IO.BinaryWriter($icoStream)
$w.Write([uint16]0); $w.Write([uint16]1); $w.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
  $s = $sizes[$i]; $len = $pngs[$i].Length
  $w.Write([byte]$(if ($s -ge 256) { 0 } else { $s })); $w.Write([byte]$(if ($s -ge 256) { 0 } else { $s }))
  $w.Write([byte]0); $w.Write([byte]0); $w.Write([uint16]1); $w.Write([uint16]32); $w.Write([uint32]$len); $w.Write([uint32]$offset)
  $offset += $len
}
foreach ($p in $pngs) { $w.Write($p) }
$w.Flush(); [IO.File]::WriteAllBytes($Out, $icoStream.ToArray())
# Also save a large PNG for the README
$big = New-LogoBitmap 256; $big.Save((Join-Path (Split-Path -Parent $PSScriptRoot) 'docs\logo.png'), [System.Drawing.Imaging.ImageFormat]::Png); $big.Dispose()
"wrote $Out ($((Get-Item $Out).Length) bytes)"
