param(
	[string]$OutDir = $PSScriptRoot,
	[int]$BurstThreshold = 50,
	[string[]]$AllowSuffix = @(".microsoft.com", ".windows.com", ".office.com", ".github.com"),
	[switch]$ShowRawXml
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $OutDir) { $OutDir = (Get-Location).Path }
$logFile = Join-Path $OutDir "dns_audit.log"

$logName = "Microsoft-Windows-DNS-Client/Operational"

Write-Host "Monitoring DNS Client log for queries (UDP-ish visibility)..." -ForegroundColor Cyan
Write-Host "Logging to: $logFile"
Write-Host "Tip: run as admin for best visibility.`n"

$bucket = @{}
$bucketStart = Get-Date

$start = Get-Date

while ($true) {
	$events = Get-WinEvent -FilterHashtable @{
		LogName   = $logName
		StartTime = $start
	} -ErrorAction SilentlyContinue

	$start = Get-Date

	foreach ($e in $events) {
		$ts = $e.TimeCreated.ToString("HH:mm:ss")

		$xml = [xml]$e.ToXml()
		$eventId = [int]$xml.Event.System.EventID


		$data = @{}
		foreach ($d in $xml.Event.EventData.Data) {
			$name = $d.Name
			$val = if ($null -ne $d) { [string]$d.InnerText } else { "" }
			if ($name) { $data[$name] = $val }
		}

		$qname = $data["QueryName"]
		$qtype = $data["QueryType"]
		$server = $data["ServerIpAddress"]
		$procId = $data["ProcessId"]
		$image = $data["ImageName"]

		# Fallbacks when fields are only in Message text
		if (-not $qname -and $e.Message -match "name\s+([^,]+)") { $qname = $matches[1].Trim() }
		if (-not $qtype -and $e.Message -match "type\s+(\d+)") { $qtype = $matches[1] }
		if (-not $server -and $e.Message -match "DNS Server\s+([0-9\.]+)") { $server = $matches[1] }
		if (-not $procId -and $e.Message -match "client PID\s+(\d+)") { $procId = $matches[1] }

		if (-not $image -and $procId) {
			try {
				$p = Get-Process -Id $procId -ErrorAction SilentlyContinue
				if ($p) { $image = $p.Name }
			}
			catch {}
		}



		$who = if ($image) { $image } elseif ($procId) { "PID:$procId" } else { "UnknownProc" }

		$msg = "[$ts] DNS QUERY | $who | $qtype | $qname"
		if ($server) { $msg += " | Server: $server" }

		$now = Get-Date
		if (($now - $bucketStart).TotalSeconds -ge 60) {
			$bucket.Clear()
			$bucketStart = $now
		}

		if (-not $bucket.ContainsKey("TOTAL")) { $bucket["TOTAL"] = 0 }
		$bucket["TOTAL"]++

		if ($who) {
			if (-not $bucket.ContainsKey($who)) { $bucket[$who] = 0 }
			$bucket[$who]++
		}

		$isAllowed = $false
		foreach ($s in $AllowSuffix) {
			if ($qname.ToLower().EndsWith($s.ToLower())) { $isAllowed = $true; break }
		}

		if (-not $isAllowed) {
			Write-Host "!! DNS ALERT !! $msg" -ForegroundColor Yellow
		}
		else {
			Write-Host $msg -ForegroundColor Green
		}

		if ($ShowRawXml) {
			Write-Host $xml.OuterXml
		}

		$msg | Out-File -FilePath $logFile -Append
	}

	if ($bucket.ContainsKey("TOTAL") -and $bucket["TOTAL"] -ge $BurstThreshold) {
		Write-Host "!! DNS BURST ALERT !! Queries in last minute: $($bucket["TOTAL"])" -ForegroundColor Red -BackgroundColor Black
	}

	Start-Sleep -Milliseconds 250
}