$currentDir = $PSScriptRoot
if (!$currentDir) { $currentDir = Get-Location }

$logFile = "$currentDir\net_audit.log"
$summaryFile = "$currentDir\connection_summary.txt"
$safeIpsFile = "$currentDir\safe-ips.txt"

# Track connections: Key -> @{ Count, Name, Path, FirstSeen }
$history = @{}

if (!(Test-Path $safeIpsFile)) { New-Item $safeIpsFile -ItemType File | Out-Null; "8.8.8.8" | Out-File $safeIpsFile }

Write-Host "Monitoring for C2... Logs at: $currentDir" -ForegroundColor Cyan
Write-Host "Console will only show NEW or HIGH-FREQUENCY connections.`n"

# states that catch short lived sockets
$watchStates = @("Established", "SynSent", "TimeWait", "CloseWait", "FinWait1", "FinWait2")

while ($true) {
	$safeIps = Get-Content $safeIpsFile -ErrorAction SilentlyContinue |
	Where-Object { $_ -match "^\d+\.\d+\.\d+\.\d+$" }

	$timestamp = (Get-Date).ToString("HH:mm:ss")

	# Cache processes once per loop (fast); avoids Get-Process per connection
	$procMap = @{}
	Get-Process -ErrorAction SilentlyContinue | ForEach-Object { $procMap[$_.Id] = $_ }

	$conns = Get-NetTCPConnection -ErrorAction SilentlyContinue |
	Where-Object { $watchStates -contains $_.State } |
	Where-Object { $_.RemoteAddress -and $_.RemoteAddress -notmatch "^(127\.0\.0\.1|::1|0\.0\.0\.0)$" } |
	Where-Object { $_.RemoteAddress -notin $safeIps }

	foreach ($c in $conns) {
		$procId = $c.OwningProcess
		$remote = "$($c.RemoteAddress):$($c.RemotePort)"

		$proc = $null
		if ($procMap.ContainsKey($procId)) { $proc = $procMap[$procId] }

		$pName = if ($proc) { $proc.Name } else { "Unknown" }
		$pPath = if ($proc -and $proc.Path) { $proc.Path } else { "" }

		# Key should not include PID; we want to spot repeat patterns even if PID changes
		$key = "$pName -> $remote"

		if (-not $history.ContainsKey($key)) {
			$history[$key] = @{ Count = 1; Name = $pName; Path = $pPath }

			# Only fetch command line for NEW items; CIM is slow
			$pCmd = ""
			try {
				$pCmd = (Get-CimInstance Win32_Process -Filter "ProcessId = $procId" -ErrorAction SilentlyContinue).CommandLine
			}
			catch {}

			# DETECTION LOGIC
			$isSuspicious = $false
			$reason = ""

			# 1. Path Check (common user-writable locations)
			if ($pPath -match "Temp|Users\\Public|AppData") {
				$isSuspicious = $true
				$reason = "UNUSUAL PATH"
			}

			# 2. SVCHOST masquerade, but only if we actually have a path
			if ($pName -eq "svchost") {
				if ($pPath -and $pPath -notmatch "\\Windows\\System32\\svchost\.exe$") {
					$isSuspicious = $true
					$reason = "SVCHOST NOT SYSTEM32"
				}
			}

			$msg = "[$timestamp] NEW: [$pName] ($($c.State)) -> $remote"

			if ($isSuspicious) {
				Write-Host "!! ALERT: $reason !! $msg" -ForegroundColor Red -BackgroundColor Black
				if ($pPath) { Write-Host "   Path: $pPath" -ForegroundColor Red }
			}
			else {
				Write-Host $msg -ForegroundColor Green
			}

			"[$timestamp] NEW | $pName | $remote | State: $($c.State) | PID: $procId | Path: $pPath | Cmd: $pCmd" |
			Out-File $logFile -Append
		}
		else {
			$history[$key].Count++
			$count = $history[$key].Count
			if ($count % 50 -eq 0) {
				Write-Host "[$timestamp] MILESTONE ($count`x): [$pName] -> $remote" -ForegroundColor Cyan
			}
		}
	}

	$summaryData = $history.GetEnumerator() |
	Sort-Object { $_.Value.Count } -Descending |
	ForEach-Object { "{0,6}x | {1,-15} | {2}" -f $_.Value.Count, $_.Value.Name, $_.Key }

	$summaryData | Out-File -FilePath $summaryFile -Force

	Start-Sleep -Milliseconds 100
}