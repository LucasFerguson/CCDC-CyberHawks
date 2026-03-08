param(
	[string]$BindIP = "8.8.8.8",
	[int]$Port = 9999,
	[int]$IntervalMs = 100,
	[int]$DurationSec = 5,
	[switch]$SendHttpGet
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Start a local TCP listener in a background job
$listenerJob = Start-Job -ScriptBlock {
	param($BindIP, $Port)
	$endpoint = New-Object System.Net.IPEndPoint ([System.Net.IPAddress]::Parse($BindIP), $Port)
	$listener = New-Object System.Net.Sockets.TcpListener $endpoint
	$listener.Start()
	try {
		while ($true) {
			$client = $listener.AcceptTcpClient()
			try { $client.Close() } catch {}
		}
	}
 finally {
		try { $listener.Stop() } catch {}
	}
} -ArgumentList $BindIP, $Port

Start-Sleep -Milliseconds 200

# Now generate short-lived TCP connections
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$attempts = 0
$connected = 0

try {
	while ($sw.Elapsed.TotalSeconds -lt $DurationSec) {
		$attempts++
		$client = New-Object System.Net.Sockets.TcpClient
		try {
			$iar = $client.BeginConnect($BindIP, $Port, $null, $null)
			if (-not $iar.AsyncWaitHandle.WaitOne(300)) { throw "Connect timeout" }
			$client.EndConnect($iar)
			$connected++

			if ($SendHttpGet) {
				$stream = $client.GetStream()
				$req = "GET /health HTTP/1.1`r`nHost: $BindIP`r`nConnection: close`r`n`r`n"
				$bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
				$stream.Write($bytes, 0, $bytes.Length)
				$stream.Flush()
			}
		}
		catch {
			# ignore; this is a test harness
		}
		finally {
			try { $client.Close() } catch {}
		}

		Start-Sleep -Milliseconds $IntervalMs
	}
}
finally {
	try { Stop-Job -Job $listenerJob -ErrorAction SilentlyContinue | Out-Null } catch {}
	try { Remove-Job -Job $listenerJob -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
}

[pscustomobject]@{
	Target      = "$BindIP`:$Port"
	IntervalMs  = $IntervalMs
	DurationSec = $DurationSec
	Attempts    = $attempts
	Connected   = $connected
	HttpGet     = [bool]$SendHttpGet
}