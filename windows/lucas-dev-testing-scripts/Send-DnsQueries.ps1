param(
	[string[]]$Names = @(
		"lucasferguson.net"
	),
	[int]$Repeat = 30,
	[int]$IntervalMs = 200,
	[string]$DnsServer = ""   # optional, e.g. "192.168.192.150"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "Generating DNS queries..." -ForegroundColor Cyan
if ($DnsServer) { Write-Host "Using DNS server: $DnsServer" -ForegroundColor Cyan }

$made = 0
for ($i = 1; $i -le $Repeat; $i++) {
	foreach ($n in $Names) {
		try {
			if ($DnsServer) {
				Resolve-DnsName -Name $n -Type A -Server $DnsServer -NoHostsFile -DnsOnly -ErrorAction SilentlyContinue | Out-Null
			}
			else {
				Resolve-DnsName -Name $n -Type A -NoHostsFile -DnsOnly -ErrorAction SilentlyContinue | Out-Null
			}
			$made++
		}
		catch {}
		Start-Sleep -Milliseconds $IntervalMs
	}
}

[pscustomobject]@{
	QueriesAttempted = $made
	Repeat           = $Repeat
	IntervalMs       = $IntervalMs
	DnsServer        = if ($DnsServer) { $DnsServer } else { "(system default)" }
}