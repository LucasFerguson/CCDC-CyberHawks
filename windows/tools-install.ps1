<#
.SYNOPSIS
Download common tools to C:\Tools

.DESCRIPTION
Creates C:\Tools if missing and downloads Sysinternals, Wireshark, and Firefox installers.
#>

$toolsDir = "C:\Tools"
if (!(Test-Path $toolsDir)) {
    New-Item -ItemType Directory -Path $toolsDir | Out-Null
}

$downloads = @(
    @{ Name = "Sysinternals"; Url = "https://download.sysinternals.com/files/SysinternalsSuite.zip" }
    @{ Name = "Wireshark";    Url = "https://2.na.dl.wireshark.org/win64/Wireshark-latest-x64.exe" }
    @{ Name = "Firefox";      Url = "https://download.mozilla.org/?product=firefox-latest-ssl&os=win64&lang=en-US" }
)

function Format-Bytes {
    param([long]$Bytes)
    if ($Bytes -lt 1KB) { return "$Bytes B" }
    if ($Bytes -lt 1MB) { return "{0:N1} KB" -f ($Bytes / 1KB) }
    if ($Bytes -lt 1GB) { return "{0:N1} MB" -f ($Bytes / 1MB) }
    return "{0:N2} GB" -f ($Bytes / 1GB)
}

function Format-Seconds {
    param([double]$Seconds)
    if ($Seconds -lt 0 -or [double]::IsNaN($Seconds) -or [double]::IsInfinity($Seconds)) { return "unknown" }
    $ts = [TimeSpan]::FromSeconds($Seconds)
    if ($ts.TotalHours -ge 1) { return "{0:hh\:mm\:ss}" -f $ts }
    return "{0:mm\:ss}" -f $ts
}

function Get-ContentLength {
    param([string]$Url)
    try {
        $resp = Invoke-WebRequest -Method Head -Uri $Url -MaximumRedirection 5 -ErrorAction Stop
        return [long]$resp.Headers["Content-Length"]
    } catch {
        return 0
    }
}

function Download-File {
    param(
        [string]$Url,
        [string]$OutFile
    )

    $maxAttempts = 3
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    } catch { }

    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $OutFile -ErrorAction Stop
            return $true
        } catch {
            if ($attempt -ge $maxAttempts) { return $false }
            Start-Sleep -Seconds 2
        }
    }
}

$ProgressPreference = "SilentlyContinue"

Write-Host "Usability note: if this runs longer than 10 minutes, press Ctrl+C and install directly from the URLs below."
Write-Host "Planned downloads:"
foreach ($item in $downloads) {
    Write-Host " - $($item.Name): $($item.Url)"
}

$sizes = @{}
$knownTotal = 0
foreach ($item in $downloads) {
    $len = Get-ContentLength -Url $item.Url
    $sizes[$item.Name] = $len
    if ($len -gt 0) { $knownTotal += $len }
}
if ($knownTotal -gt 0) {
    Write-Host ("Estimated total size (known): {0}" -f (Format-Bytes $knownTotal))
    $etaSlow = ($knownTotal * 8) / (5MB * 8)
    $etaFast = ($knownTotal * 8) / (20MB * 8)
    Write-Host ("Estimated time at ~5 MB/s: {0}" -f (Format-Seconds $etaSlow))
    Write-Host ("Estimated time at ~20 MB/s: {0}" -f (Format-Seconds $etaFast))
} else {
    Write-Host "Estimated total size: unknown (server did not provide content length)."
}

$total = $downloads.Count
$index = 0
foreach ($item in $downloads) {
    $index++
    Write-Host "Downloading $($item.Name) ($index of $total)..."
    $ext = if ($item.Url -like "*.zip*") { ".zip" } else { ".exe" }
    $outFile = Join-Path $toolsDir "$($item.Name)$ext"
    if (Test-Path $outFile) {
        $size = (Get-Item $outFile).Length
        if ($size -gt 0) {
            Write-Host "Already exists: $outFile (skipping). Remaining: $($total - $index)"
            continue
        }
    }

    $ok = Download-File -Url $item.Url -OutFile $outFile
    if ($ok -and (Test-Path $outFile)) {
        Write-Host "Finished $($item.Name). Saved to $outFile. Remaining: $($total - $index)"
    } else {
        Write-Host "Failed to download $($item.Name). Remaining: $($total - $index)"
    }
}

$missing = @()
foreach ($item in $downloads) {
    $ext = if ($item.Url -like "*.zip*") { ".zip" } else { ".exe" }
    $outFile = Join-Path $toolsDir "$($item.Name)$ext"
    if (!(Test-Path $outFile) -or ((Get-Item $outFile).Length -le 0)) {
        $missing += $item.Name
    }
}

if ($missing.Count -gt 0) {
    Write-Host "Missing downloads: $($missing -join ', ')"
} else {
    Write-Host "All downloads present."
}
