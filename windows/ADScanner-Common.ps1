#Requires -Version 5.1
<#
.SYNOPSIS
    Shared infrastructure for AD-Hardener.ps1 and AD-Monitor.ps1
.DESCRIPTION
    Contains logging, privilege checks, module dependency checks,
    environment auto-detection, remote communication helpers,
    config file management, and dry-run framework.
#>

# ── Script-wide state ────────────────────────────────────────────────
$Script:ADScannerRoot = Join-Path $PSScriptRoot "ADScanner"
$Script:ConfigPath    = Join-Path $Script:ADScannerRoot "config"
$Script:LogPath       = Join-Path $Script:ADScannerRoot "logs"
$Script:ReportPath    = Join-Path $Script:ADScannerRoot "reports"
$Script:LogFile       = Join-Path $Script:LogPath "adscanner.log"
$Script:SettingsFile  = Join-Path $Script:ConfigPath "settings.json"
$Script:IsOnDC        = $false
$Script:TargetDC      = $null
$Script:DomainName    = $null
$Script:SessionActions = @()   # Track actions for report generation
$Script:SessionFindings = @()  # Track findings for report generation
$Script:SessionErrors  = @()   # Track errors for report generation
$Script:AvailableModules = @{} # Track which modules are available

# ── Logging ──────────────────────────────────────────────────────────

$Script:LogColors = @{
    'INFO'    = 'Green'
    'CHECK'   = 'Cyan'
    'FINDING' = 'Cyan'
    'ACTION'  = 'Green'
    'DRY-RUN' = 'Yellow'
    'WARNING' = 'Yellow'
    'ERROR'   = 'Red'
    'ALERT'   = 'Red'
}

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('INFO','CHECK','FINDING','ACTION','DRY-RUN','WARNING','ERROR','ALERT')]
        [string]$Level,

        [Parameter(Mandatory)]
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$timestamp] [$Level] $Message"

    # Console output with color
    $color = $Script:LogColors[$Level]
    Write-Host $entry -ForegroundColor $color

    # File output (create directory if needed)
    if (-not (Test-Path $Script:LogPath)) {
        New-Item -Path $Script:LogPath -ItemType Directory -Force | Out-Null
    }
    Add-Content -Path $Script:LogFile -Value $entry -Encoding UTF8

    # Track for reporting
    switch ($Level) {
        'ACTION'  { $Script:SessionActions  += $entry }
        'DRY-RUN' { $Script:SessionActions  += $entry }
        'FINDING' { $Script:SessionFindings += $entry }
        'ALERT'   { $Script:SessionFindings += $entry }
        'ERROR'   { $Script:SessionErrors   += $entry }
        'WARNING' { $Script:SessionErrors   += $entry }
    }
}

# ── Directory Initialization ─────────────────────────────────────────

function Initialize-ADScannerDirectory {
    [CmdletBinding()]
    param()

    $dirs = @($Script:ADScannerRoot, $Script:ConfigPath, $Script:LogPath, $Script:ReportPath)
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
            Write-Log -Level INFO -Message "Created directory: $dir"
        }
    }

    # Create default config files if they don't exist
    Initialize-DefaultConfigs
}

function Initialize-DefaultConfigs {
    [CmdletBinding()]
    param()

    # settings.json
    if (-not (Test-Path $Script:SettingsFile)) {
        $defaultSettings = @{
            PollIntervalMinutes      = 5
            RetryCount               = 3
            RetryDelaySeconds        = 5
            SuspiciousTaskDays       = 7
            PasswordAgeDays          = 90
            BruteForceThreshold      = 10
            PasswordSprayThreshold   = 5
            KerberoastThreshold      = 3
            Version                  = "1.0.0"
        }
        $defaultSettings | ConvertTo-Json -Depth 4 | Set-Content -Path $Script:SettingsFile -Encoding UTF8
        Write-Log -Level INFO -Message "Created default settings file: $Script:SettingsFile"
    }

    # service-whitelist.csv
    $whitelistFile = Join-Path $Script:ConfigPath "service-whitelist.csv"
    if (-not (Test-Path $whitelistFile)) {
        $whitelistContent = @"
# Service Whitelist for DNS Servers
# Edit this file to add or remove services that should be allowed on DNS servers.
# Columns: ServiceName, DisplayName, Reason
# Any running service NOT in this list will be flagged for review.
ServiceName,DisplayName,Reason
DNS,DNS Server,Core DNS service
NTDS,Active Directory Domain Services,Core AD service
kdc,Kerberos Key Distribution Center,Authentication service
Netlogon,Netlogon,Domain authentication and trust service
ADWS,Active Directory Web Services,AD PowerShell module dependency
DFSR,DFS Replication,AD replication service
IsmServ,Intersite Messaging,AD site replication
RpcSs,Remote Procedure Call (RPC),Core Windows service
RpcEptMapper,RPC Endpoint Mapper,Core Windows service
DcomLaunch,DCOM Server Process Launcher,Core Windows service
EventLog,Windows Event Log,Logging service
Schedule,Task Scheduler,Core Windows service
wuauserv,Windows Update,Patch management
CryptSvc,Cryptographic Services,Certificate and encryption
Winmgmt,Windows Management Instrumentation,WMI management
WinRM,Windows Remote Management (WS-Management),Remote management
RemoteRegistry,Remote Registry,Remote management
BFE,Base Filtering Engine,Firewall dependency
MpsSvc,Windows Defender Firewall,Network security
WinDefend,Windows Defender Antivirus Service,Endpoint security
W32Time,Windows Time,Time synchronization
LanmanServer,Server,File and print sharing
LanmanWorkstation,Workstation,Network connectivity
SamSs,Security Accounts Manager,Core security service
LSM,Local Session Manager,Session management
gpsvc,Group Policy Client,Group Policy processing
ProfSvc,User Profile Service,Profile management
Dhcp,DHCP Client,Network configuration
Dnscache,DNS Client,DNS resolution
NlaSvc,Network Location Awareness,Network detection
nsi,Network Store Interface Service,Network information
PlugPlay,Plug and Play,Device management
Power,Power,Power management
TrustedInstaller,Windows Modules Installer,Windows Update dependency
SENS,System Event Notification Service,System events
EventSystem,COM+ Event System,Event notification
lmhosts,TCP/IP NetBIOS Helper,Name resolution
"@
        Set-Content -Path $whitelistFile -Value $whitelistContent -Encoding UTF8
        Write-Log -Level INFO -Message "Created default service whitelist: $whitelistFile"
    }

    # canary-accounts.csv
    $canaryFile = Join-Path $Script:ConfigPath "canary-accounts.csv"
    if (-not (Test-Path $canaryFile)) {
        $canaryContent = @"
# Canary / Honey Token Accounts
# Any logon or auth attempt for these accounts triggers an alert.
# These should be accounts that exist in AD but are never legitimately used.
# Columns: SamAccountName, Description
SamAccountName,Description
"@
        Set-Content -Path $canaryFile -Value $canaryContent -Encoding UTF8
        Write-Log -Level INFO -Message "Created default canary accounts file: $canaryFile"
    }

    # dns-servers.csv
    $dnsFile = Join-Path $Script:ConfigPath "dns-servers.csv"
    if (-not (Test-Path $dnsFile)) {
        $dnsContent = @"
# DNS Server List
# Edit this file to add DNS servers to target.
# Columns: Hostname, IPAddress, LastDiscovered
# Leave IPAddress blank if unknown - it will be resolved automatically.
Hostname,IPAddress,LastDiscovered
"@
        Set-Content -Path $dnsFile -Value $dnsContent -Encoding UTF8
        Write-Log -Level INFO -Message "Created default DNS servers file: $dnsFile"
    }
}

# ── Settings Management ──────────────────────────────────────────────

function Get-ADScannerSettings {
    [CmdletBinding()]
    param()

    if (-not (Test-Path $Script:SettingsFile)) {
        Initialize-DefaultConfigs
    }

    try {
        $content = Get-Content -Path $Script:SettingsFile -Raw -ErrorAction Stop
        $settings = $content | ConvertFrom-Json
        return $settings
    }
    catch {
        Write-Log -Level ERROR -Message "Could not read settings file: $_"
        Write-Log -Level WARNING -Message "Backing up corrupted settings file and creating new defaults."
        $backupPath = "$Script:SettingsFile.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        if (Test-Path $Script:SettingsFile) {
            Copy-Item -Path $Script:SettingsFile -Destination $backupPath -Force
        }
        Remove-Item -Path $Script:SettingsFile -Force -ErrorAction SilentlyContinue
        Initialize-DefaultConfigs
        $content = Get-Content -Path $Script:SettingsFile -Raw
        return ($content | ConvertFrom-Json)
    }
}

function Save-ADScannerSettings {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [PSObject]$Settings
    )

    try {
        $Settings | ConvertTo-Json -Depth 4 | Set-Content -Path $Script:SettingsFile -Encoding UTF8
    }
    catch {
        Write-Log -Level ERROR -Message "Could not save settings: $_"
    }
}

# ── CSV Config Helpers ───────────────────────────────────────────────

function Import-CSVConfig {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [string[]]$RequiredColumns,

        [string]$FriendlyName = "config file"
    )

    if (-not (Test-Path $Path)) {
        Write-Log -Level WARNING -Message "$FriendlyName not found at $Path"
        return $null
    }

    try {
        # Read lines, skip comment lines starting with #
        $lines = Get-Content -Path $Path -Encoding UTF8 | Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' }
        if ($lines.Count -eq 0) {
            Write-Log -Level WARNING -Message "$FriendlyName is empty: $Path"
            return @()
        }

        $csvText = $lines -join "`n"
        $data = $csvText | ConvertFrom-Csv

        # Validate required columns
        if ($data.Count -gt 0) {
            $actualColumns = $data[0].PSObject.Properties.Name
            foreach ($col in $RequiredColumns) {
                if ($col -notin $actualColumns) {
                    Write-Log -Level ERROR -Message "$FriendlyName is missing required column '$col'. Expected columns: $($RequiredColumns -join ', '). Found: $($actualColumns -join ', ')"
                    Write-Host "`nPlease fix the file at: $Path" -ForegroundColor Yellow
                    Write-Host "Each row needs these columns: $($RequiredColumns -join ', ')" -ForegroundColor Yellow
                    return $null
                }
            }
        }

        return $data
    }
    catch {
        Write-Log -Level ERROR -Message "Could not read $FriendlyName at ${Path}: $_"
        Write-Host "`nThe file might have formatting errors. Open it in Notepad and check that:" -ForegroundColor Yellow
        Write-Host "  - The first non-comment line is the header row" -ForegroundColor Yellow
        Write-Host "  - Each data row has the same number of columns as the header" -ForegroundColor Yellow
        Write-Host "  - Values with commas are wrapped in double quotes" -ForegroundColor Yellow

        $backupPath = "$Path.bak.$(Get-Date -Format 'yyyyMMddHHmmss')"
        Write-Host "`nWould you like to back up this file and recreate it with defaults? (Y/N)" -ForegroundColor Yellow
        $choice = Read-Host
        if ($choice -eq 'Y' -or $choice -eq 'y') {
            Copy-Item -Path $Path -Destination $backupPath -Force
            Write-Log -Level INFO -Message "Backed up corrupted file to $backupPath"
            Remove-Item -Path $Path -Force
            Initialize-DefaultConfigs
            return (Import-CSVConfig -Path $Path -RequiredColumns $RequiredColumns -FriendlyName $FriendlyName)
        }
        return $null
    }
}

# ── Privilege & Environment Checks ───────────────────────────────────

function Test-Privileges {
    [CmdletBinding()]
    param()

    Write-Log -Level INFO -Message "Checking privileges..."
    $allGood = $true

    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "`n[PROBLEM] You are not running PowerShell as Administrator." -ForegroundColor Red
        Write-Host "  How to fix: Close this window, right-click PowerShell, and select" -ForegroundColor Yellow
        Write-Host "  'Run as administrator'. Then run this script again." -ForegroundColor Yellow
        $allGood = $false
    }
    else {
        Write-Log -Level INFO -Message "Running as Administrator: Yes"
    }

    # Check if user is a Domain Admin
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
        $samName = $currentUser.Split('\')[-1]
        $isDomainAdmin = $samName -in $domainAdmins

        if (-not $isDomainAdmin) {
            # Also check Enterprise Admins
            try {
                $enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" -ErrorAction Stop | Select-Object -ExpandProperty SamAccountName
                $isDomainAdmin = $samName -in $enterpriseAdmins
            }
            catch { }
        }

        if (-not $isDomainAdmin) {
            Write-Host "`n[PROBLEM] You are not a Domain Admin or Enterprise Admin." -ForegroundColor Red
            Write-Host "  How to fix: Log in with a Domain Admin account, or ask your" -ForegroundColor Yellow
            Write-Host "  administrator to add your account to the Domain Admins group." -ForegroundColor Yellow
            $allGood = $false
        }
        else {
            Write-Log -Level INFO -Message "Domain Admin privileges: Yes (running as $currentUser)"
        }
    }
    catch {
        Write-Host "`n[PROBLEM] Cannot verify Domain Admin status - unable to query Active Directory." -ForegroundColor Red
        Write-Host "  Error: $_" -ForegroundColor Yellow
        $allGood = $false
    }

    # Test AD connectivity
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        $Script:DomainName = $domain.DNSRoot
        Write-Log -Level INFO -Message "Active Directory reachable: $($Script:DomainName)"
    }
    catch {
        Write-Host "`n[PROBLEM] Cannot reach Active Directory." -ForegroundColor Red
        Write-Host "  This could mean:" -ForegroundColor Yellow
        Write-Host "  - You're not connected to the domain network" -ForegroundColor Yellow
        Write-Host "  - DNS is misconfigured on this machine" -ForegroundColor Yellow
        Write-Host "  - The domain controller is down" -ForegroundColor Yellow
        Write-Host "  How to fix: Make sure this computer is joined to the domain and" -ForegroundColor Yellow
        Write-Host "  can reach a domain controller. Try: nslookup $env:USERDNSDOMAIN" -ForegroundColor Yellow
        $allGood = $false
    }

    return $allGood
}

function Test-ModuleDependencies {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$RequiredModules
    )

    $moduleDescriptions = @{
        'ActiveDirectory' = "Needed to query and modify Active Directory users, groups, and computers."
        'PSWindowsUpdate' = "Needed to remotely trigger Windows Updates on domain computers."
        'DnsServer'       = "Needed to check and change DNS server settings (zone transfers, logging, etc.)."
        'GroupPolicy'     = "Needed to create and modify Group Policy Objects (GPOs) for domain-wide settings."
    }

    $moduleDependencies = @{
        'PSWindowsUpdate' = @(1)           # Feature 1: Patching
        'DnsServer'       = @(3, 4, 8)     # Features 3, 4, 8
        'GroupPolicy'     = @(2)           # Feature 2 (GPO options)
    }

    Write-Log -Level INFO -Message "Checking required PowerShell modules..."
    $allAvailable = $true

    foreach ($moduleName in $RequiredModules) {
        $available = Get-Module -ListAvailable -Name $moduleName -ErrorAction SilentlyContinue
        $desc = $moduleDescriptions[$moduleName]

        if ($available) {
            Write-Host "  [OK] $moduleName" -ForegroundColor Green
            $Script:AvailableModules[$moduleName] = $true
        }
        else {
            Write-Host "`n  [MISSING] $moduleName" -ForegroundColor Yellow
            if ($desc) {
                Write-Host "    What it does: $desc" -ForegroundColor Gray
            }
            if ($moduleDependencies.ContainsKey($moduleName)) {
                $features = $moduleDependencies[$moduleName] -join ', '
                Write-Host "    Menu options that need it: $features" -ForegroundColor Gray
            }

            Write-Host "    Would you like to install it now? (Y/N)" -ForegroundColor Yellow
            $choice = Read-Host "    "
            if ($choice -eq 'Y' -or $choice -eq 'y') {
                try {
                    Write-Host "    Installing $moduleName..." -ForegroundColor Cyan
                    Install-Module -Name $moduleName -Force -Scope CurrentUser -ErrorAction Stop
                    Import-Module -Name $moduleName -ErrorAction Stop
                    Write-Host "    [OK] $moduleName installed successfully." -ForegroundColor Green
                    $Script:AvailableModules[$moduleName] = $true
                }
                catch {
                    Write-Host "    [FAILED] Could not install ${moduleName}: ${_}" -ForegroundColor Red
                    $Script:AvailableModules[$moduleName] = $false
                    $allAvailable = $false
                }
            }
            else {
                Write-Host "    Skipped. Features requiring $moduleName will be unavailable." -ForegroundColor Yellow
                $Script:AvailableModules[$moduleName] = $false
                $allAvailable = $false
            }
        }
    }

    return $allAvailable
}

function Test-ModuleAvailable {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ModuleName
    )

    if ($Script:AvailableModules.ContainsKey($ModuleName)) {
        return $Script:AvailableModules[$ModuleName]
    }

    $available = $null -ne (Get-Module -ListAvailable -Name $ModuleName -ErrorAction SilentlyContinue)
    $Script:AvailableModules[$ModuleName] = $available
    return $available
}

function Initialize-Environment {
    [CmdletBinding()]
    param()

    Write-Log -Level INFO -Message "Detecting environment..."

    # Check if running on a DC
    try {
        $os = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
        $isDC = $os.ProductType -eq 2  # 2 = Domain Controller

        if (-not $isDC) {
            # Double-check by looking for AD DS role
            try {
                $addsRole = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction Stop
                $isDC = $addsRole.Installed
            }
            catch {
                # Get-WindowsFeature might not be available on workstations
                $isDC = $false
            }
        }
    }
    catch {
        $isDC = $false
    }

    if ($isDC) {
        $Script:IsOnDC = $true
        $Script:TargetDC = $env:COMPUTERNAME
        Write-Log -Level INFO -Message "Running on Domain Controller: $($Script:TargetDC)"
    }
    else {
        $Script:IsOnDC = $false
        Write-Log -Level INFO -Message "Running on a remote workstation (not a DC)."

        # Try to detect a DC
        try {
            $dc = (Get-ADDomainController -Discover -ErrorAction Stop).HostName
            if ($dc -is [array]) { $dc = $dc[0] }
            $Script:TargetDC = $dc
            Write-Log -Level INFO -Message "Targeting Domain Controller: $($Script:TargetDC)"
        }
        catch {
            Write-Host "Could not auto-detect a Domain Controller." -ForegroundColor Yellow
            Write-Host "Please enter the hostname or IP of a DC to target:" -ForegroundColor Yellow
            $Script:TargetDC = Read-Host
            if ([string]::IsNullOrWhiteSpace($Script:TargetDC)) {
                Write-Log -Level ERROR -Message "No Domain Controller specified. Cannot continue."
                return $false
            }
            Write-Log -Level INFO -Message "Targeting Domain Controller: $($Script:TargetDC)"
        }
    }

    return $true
}

# ── AD Cmdlet Wrapper ────────────────────────────────────────────────
# Returns a hashtable of common parameters to pass to AD cmdlets
# when running remotely (adds -Server parameter)

function Get-ADTargetParams {
    [CmdletBinding()]
    param()

    if ($Script:IsOnDC) {
        return @{}
    }
    else {
        return @{ Server = $Script:TargetDC }
    }
}

# ── Remote Machine Communication ─────────────────────────────────────

function Test-RemoteConnectivity {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [int]$RetryCount = 3,
        [int]$RetryDelaySeconds = 5
    )

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        # Test basic connectivity
        $pingResult = Test-Connection -ComputerName $ComputerName -Count 1 -Quiet -ErrorAction SilentlyContinue
        if (-not $pingResult) {
            if ($attempt -lt $RetryCount) {
                Write-Log -Level WARNING -Message "Cannot reach $ComputerName (attempt $attempt/$RetryCount). Retrying in $RetryDelaySeconds seconds..."
                Start-Sleep -Seconds $RetryDelaySeconds
                continue
            }
            Write-Log -Level ERROR -Message "Could not reach $ComputerName after $RetryCount retries (ping failed)."
            return $false
        }

        # Test WinRM
        try {
            $wsmanResult = Test-WSMan -ComputerName $ComputerName -ErrorAction Stop
            Write-Log -Level INFO -Message "Connected to $ComputerName (WinRM OK)."
            return $true
        }
        catch {
            if ($attempt -eq 1) {
                Write-Host "`n$ComputerName is reachable but WinRM (Windows Remote Management) is not enabled." -ForegroundColor Yellow
                Write-Host "WinRM lets this script send commands to remote computers. It's a built-in Windows feature." -ForegroundColor Gray
                Write-Host "Would you like to enable it on $ComputerName? (Y/N)" -ForegroundColor Yellow
                $choice = Read-Host
                if ($choice -eq 'Y' -or $choice -eq 'y') {
                    try {
                        # Try to enable WinRM via WMI
                        $enableResult = Invoke-WmiMethod -ComputerName $ComputerName -Path "Win32_Process" -Name Create -ArgumentList "cmd.exe /c winrm quickconfig -q" -ErrorAction Stop
                        Write-Log -Level ACTION -Message "Enabled WinRM on $ComputerName"
                        Start-Sleep -Seconds 5
                        continue
                    }
                    catch {
                        Write-Log -Level ERROR -Message "Could not enable WinRM on ${ComputerName}: $_"
                    }
                }
            }

            if ($attempt -lt $RetryCount) {
                Write-Log -Level WARNING -Message "WinRM not available on $ComputerName (attempt $attempt/$RetryCount). Retrying in $RetryDelaySeconds seconds..."
                Start-Sleep -Seconds $RetryDelaySeconds
                continue
            }
            Write-Log -Level ERROR -Message "Could not reach $ComputerName after $RetryCount retries (WinRM failed)."
            return $false
        }
    }

    return $false
}

function Invoke-RemoteCommand {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ComputerName,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [hashtable]$ArgumentList,

        [int]$RetryCount = 3,
        [int]$RetryDelaySeconds = 5
    )

    for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
        try {
            $params = @{
                ComputerName = $ComputerName
                ScriptBlock  = $ScriptBlock
                ErrorAction  = 'Stop'
            }
            if ($ArgumentList) {
                $params['ArgumentList'] = $ArgumentList
            }
            $result = Invoke-Command @params
            return $result
        }
        catch {
            if ($attempt -lt $RetryCount) {
                Write-Log -Level WARNING -Message "Remote command failed on $ComputerName (attempt $attempt/$RetryCount): $_"
                Start-Sleep -Seconds $RetryDelaySeconds
            }
            else {
                Write-Log -Level ERROR -Message "Remote command failed on $ComputerName after $RetryCount retries: $_"
                return $null
            }
        }
    }
}

# ── Dry-Run Framework ────────────────────────────────────────────────

function Invoke-WithDryRun {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Description,

        [Parameter(Mandatory)]
        [scriptblock]$Action,

        [string]$DryRunMessage
    )

    if (-not $DryRunMessage) {
        $DryRunMessage = "Would $Description (no changes made)"
    }

    Write-Host "`n--- Preview (Dry Run) ---" -ForegroundColor Yellow
    Write-Host $Description -ForegroundColor Yellow
    Write-Host "-------------------------" -ForegroundColor Yellow

    Write-Host "`nThis is a preview (dry-run). Would you like to apply these changes? (Y/N)" -ForegroundColor Yellow
    $choice = Read-Host
    if ($choice -eq 'Y' -or $choice -eq 'y') {
        try {
            & $Action
            Write-Log -Level ACTION -Message $Description
            return $true
        }
        catch {
            Write-Log -Level ERROR -Message "Failed to $Description`: $_"
            return $false
        }
    }
    else {
        Write-Log -Level 'DRY-RUN' -Message $DryRunMessage
        return $false
    }
}

# ── DNS Server Discovery ─────────────────────────────────────────────

function Get-DNSServerList {
    [CmdletBinding()]
    param()

    $dnsFile = Join-Path $Script:ConfigPath "dns-servers.csv"
    $servers = @()

    # Load saved servers
    $saved = Import-CSVConfig -Path $dnsFile -RequiredColumns @('Hostname','IPAddress','LastDiscovered') -FriendlyName "DNS servers list"
    if ($saved) {
        foreach ($s in $saved) {
            if (-not [string]::IsNullOrWhiteSpace($s.Hostname)) {
                $servers += $s.Hostname
            }
        }
    }

    # Try auto-discovery
    Write-Log -Level CHECK -Message "Discovering DNS servers in the domain..."
    try {
        $adParams = Get-ADTargetParams
        $dnsComputers = Get-ADComputer -Filter { ServicePrincipalName -like "DNS/*" } -Properties ServicePrincipalName @adParams |
            Select-Object -ExpandProperty Name

        foreach ($dc in $dnsComputers) {
            if ($dc -notin $servers) {
                $servers += $dc
            }
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Auto-discovery of DNS servers failed: $_"
    }

    if ($servers.Count -gt 0) {
        Write-Host "`nDiscovered DNS servers:" -ForegroundColor Cyan
        for ($i = 0; $i -lt $servers.Count; $i++) {
            Write-Host "  $($i+1). $($servers[$i])" -ForegroundColor White
        }
    }
    else {
        Write-Host "`nNo DNS servers found automatically." -ForegroundColor Yellow
    }

    Write-Host "`nWould you like to add any DNS servers manually? (Enter hostnames comma-separated, or press Enter to skip)" -ForegroundColor Yellow
    $manual = Read-Host
    if (-not [string]::IsNullOrWhiteSpace($manual)) {
        $manualServers = $manual -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        foreach ($ms in $manualServers) {
            if ($ms -notin $servers) {
                $servers += $ms
            }
        }
    }

    # Save updated list
    if ($servers.Count -gt 0) {
        $csvLines = @("# DNS Server List", "# Columns: Hostname, IPAddress, LastDiscovered", "Hostname,IPAddress,LastDiscovered")
        $now = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        foreach ($s in $servers) {
            $ip = ""
            try { $ip = [System.Net.Dns]::GetHostAddresses($s) | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1 -ExpandProperty IPAddressToString } catch {}
            $csvLines += "$s,$ip,$now"
        }
        Set-Content -Path $dnsFile -Value ($csvLines -join "`n") -Encoding UTF8
    }

    return $servers
}

function Select-DNSServers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$AvailableServers
    )

    if ($AvailableServers.Count -eq 0) {
        Write-Host "No DNS servers available." -ForegroundColor Red
        return @()
    }

    if ($AvailableServers.Count -eq 1) {
        Write-Host "Using DNS server: $($AvailableServers[0])" -ForegroundColor Green
        return $AvailableServers
    }

    Write-Host "`nSelect DNS server(s) to target:" -ForegroundColor Cyan
    for ($i = 0; $i -lt $AvailableServers.Count; $i++) {
        Write-Host "  $($i+1). $($AvailableServers[$i])" -ForegroundColor White
    }
    Write-Host "  A. All servers" -ForegroundColor White

    $choice = Read-Host "`nEnter number(s) comma-separated, or 'A' for all"
    if ($choice -eq 'A' -or $choice -eq 'a') {
        return $AvailableServers
    }

    $selected = @()
    $nums = $choice -split ',' | ForEach-Object { $_.Trim() }
    foreach ($num in $nums) {
        $idx = 0
        if ([int]::TryParse($num, [ref]$idx) -and $idx -ge 1 -and $idx -le $AvailableServers.Count) {
            $selected += $AvailableServers[$idx - 1]
        }
    }

    if ($selected.Count -eq 0) {
        Write-Host "No valid selection. Using all servers." -ForegroundColor Yellow
        return $AvailableServers
    }

    return $selected
}

# ── Report Generation ────────────────────────────────────────────────

function New-ADScannerReport {
    [CmdletBinding()]
    param(
        [string]$ScriptName = "AD Scanner",
        [switch]$PrintToConsole
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd-HHmmss"
    $reportFile = Join-Path $Script:ReportPath "report-$timestamp.txt"

    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $machineName = $env:COMPUTERNAME

    $reportLines = @()
    $reportLines += "=" * 70
    $reportLines += "  $ScriptName Report"
    $reportLines += "  Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $reportLines += "  Run by: $currentUser on $machineName"
    $reportLines += "  Domain: $($Script:DomainName)"
    $reportLines += "=" * 70
    $reportLines += ""

    if ($Script:SessionFindings.Count -gt 0) {
        $reportLines += "--- FINDINGS & ALERTS ---"
        foreach ($f in $Script:SessionFindings) {
            $reportLines += "  $f"
        }
        $reportLines += ""
    }

    if ($Script:SessionActions.Count -gt 0) {
        $reportLines += "--- ACTIONS TAKEN ---"
        foreach ($a in $Script:SessionActions) {
            $reportLines += "  $a"
        }
        $reportLines += ""
    }

    if ($Script:SessionErrors.Count -gt 0) {
        $reportLines += "--- ERRORS & WARNINGS ---"
        foreach ($e in $Script:SessionErrors) {
            $reportLines += "  $e"
        }
        $reportLines += ""
    }

    if ($Script:SessionFindings.Count -eq 0 -and $Script:SessionActions.Count -eq 0 -and $Script:SessionErrors.Count -eq 0) {
        $reportLines += "No findings, actions, or errors recorded in this session."
        $reportLines += ""
    }

    $reportLines += "=" * 70
    $reportLines += "  End of Report"
    $reportLines += "=" * 70

    $reportContent = $reportLines -join "`r`n"

    if (-not (Test-Path $Script:ReportPath)) {
        New-Item -Path $Script:ReportPath -ItemType Directory -Force | Out-Null
    }
    Set-Content -Path $reportFile -Value $reportContent -Encoding UTF8
    Write-Log -Level INFO -Message "Report saved to: $reportFile"

    if ($PrintToConsole) {
        Write-Host ""
        foreach ($line in $reportLines) {
            Write-Host $line -ForegroundColor Cyan
        }
    }

    return $reportFile
}

# ── User Input Helpers ───────────────────────────────────────────────

function Read-UserChoice {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,

        [Parameter(Mandatory)]
        [string[]]$ValidChoices,

        [string]$Default
    )

    while ($true) {
        if ($Default) {
            Write-Host "$Prompt [$Default]: " -ForegroundColor Yellow -NoNewline
        }
        else {
            Write-Host "${Prompt}: " -ForegroundColor Yellow -NoNewline
        }

        $input = Read-Host
        if ([string]::IsNullOrWhiteSpace($input) -and $Default) {
            return $Default
        }

        if ($input -in $ValidChoices) {
            return $input
        }

        Write-Host "Invalid choice. Please enter one of: $($ValidChoices -join ', ')" -ForegroundColor Red
    }
}

function Read-YesNo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Prompt,

        [bool]$Default = $true
    )

    $defaultText = if ($Default) { "Y" } else { "N" }
    $result = Read-UserChoice -Prompt "$Prompt (Y/N)" -ValidChoices @('Y','y','N','n','Yes','yes','No','no') -Default $defaultText
    return ($result -match '^[Yy]')
}
