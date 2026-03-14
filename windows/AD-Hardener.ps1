#Requires -Version 5.1
<#
.SYNOPSIS
    AD Hardener - Interactive Active Directory hardening and scanning script.
.DESCRIPTION
    Provides 9 hardening and scanning features for Active Directory environments,
    including patching, RDP restriction, DNS hardening, service auditing,
    admin account hardening, advanced auditing, Kerberoasting detection,
    DNS zone transfer security, and suspicious scheduled task detection.
.NOTES
    Version: 1.0.0
    Requires: ADScanner-Common.ps1 in the same directory
#>

# ── Dot-source shared infrastructure ──────────────────────────────────
. (Join-Path $PSScriptRoot "ADScanner-Common.ps1")

# ── Script Variables ──────────────────────────────────────────────────
$Script:Version = "1.0.0"
$Script:CompletedFeatures = @{}
$Script:HealthCheckData = $null

# ══════════════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════════════

function Show-Banner {
    $banner = @"

    ___    ____       __  __               __
   /   |  / __ \     / / / /___ __________/ /__  ____  ___  _____
  / /| | / / / /    / /_/ / __ ``/ ___/ __  / _ \/ __ \/ _ \/ ___/
 / ___ |/ /_/ /    / __  / /_/ / /  / /_/ /  __/ / / /  __/ /
/_/  |_/_____/    /_/ /_/\__,_/_/   \__,_/\___/_/ /_/\___/_/

                Active Directory Hardener v$Script:Version

"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host "  Harden and scan your Active Directory environment." -ForegroundColor Gray
    Write-Host "  All changes support dry-run preview before applying." -ForegroundColor Gray
    Write-Host ""
}

# ══════════════════════════════════════════════════════════════════════
#  HEALTH CHECK
# ══════════════════════════════════════════════════════════════════════

function Invoke-HealthCheck {
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "  Domain Health Check Overview" -ForegroundColor Cyan
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host ""

    $adParams = Get-ADTargetParams
    $healthData = @{}

    # Domain and forest info
    try {
        $domain = Get-ADDomain @adParams -ErrorAction Stop
        $forest = Get-ADForest @adParams -ErrorAction Stop
        $healthData['DomainName'] = $domain.DNSRoot
        $healthData['ForestName'] = $forest.Name
        $healthData['ForestLevel'] = $forest.ForestMode
        $healthData['DomainLevel'] = $domain.DomainMode
        Write-Host "  Domain:        $($domain.DNSRoot)" -ForegroundColor White
        Write-Host "  Forest:        $($forest.Name)" -ForegroundColor White
        Write-Host "  Forest Level:  $($forest.ForestMode)" -ForegroundColor White
        Write-Host "  Domain Level:  $($domain.DomainMode)" -ForegroundColor White
    }
    catch {
        Write-Host "  [ERROR] Could not retrieve domain/forest info: $_" -ForegroundColor Red
    }

    Write-Host ""

    # Computer counts
    try {
        $allComputers = Get-ADComputer -Filter * -Properties Enabled @adParams -ErrorAction Stop
        $enabledCount = ($allComputers | Where-Object { $_.Enabled -eq $true }).Count
        $disabledCount = ($allComputers | Where-Object { $_.Enabled -ne $true }).Count
        $totalCount = $allComputers.Count
        $healthData['TotalComputers'] = $totalCount
        $healthData['EnabledComputers'] = $enabledCount
        $healthData['DisabledComputers'] = $disabledCount
        Write-Host "  Computers:     $totalCount total ($enabledCount enabled, $disabledCount disabled)" -ForegroundColor White
    }
    catch {
        Write-Host "  [ERROR] Could not count computers: $_" -ForegroundColor Red
    }

    # DNS servers
    try {
        $dnsComputers = Get-ADComputer -Filter { ServicePrincipalName -like "DNS/*" } -Properties ServicePrincipalName @adParams -ErrorAction Stop
        $dnsCount = $dnsComputers.Count
        $healthData['DNSServerCount'] = $dnsCount
        Write-Host "  DNS Servers:   $dnsCount found" -ForegroundColor White
    }
    catch {
        $healthData['DNSServerCount'] = 0
        Write-Host "  DNS Servers:   Unknown (query failed)" -ForegroundColor Yellow
    }

    # Admin groups
    try {
        $domainAdmins = Get-ADGroupMember -Identity "Domain Admins" @adParams -ErrorAction Stop
        $daCount = $domainAdmins.Count
        $healthData['DomainAdminCount'] = $daCount
        Write-Host "  Domain Admins: $daCount members" -ForegroundColor White
    }
    catch {
        $healthData['DomainAdminCount'] = 0
        Write-Host "  Domain Admins: Unknown (query failed)" -ForegroundColor Yellow
    }

    try {
        $enterpriseAdmins = Get-ADGroupMember -Identity "Enterprise Admins" @adParams -ErrorAction Stop
        $eaCount = $enterpriseAdmins.Count
        $healthData['EnterpriseAdminCount'] = $eaCount
        Write-Host "  Enterprise Admins: $eaCount members" -ForegroundColor White
    }
    catch {
        $healthData['EnterpriseAdminCount'] = 0
        Write-Host "  Enterprise Admins: Unknown (query failed)" -ForegroundColor Yellow
    }

    Write-Host ""

    # Audit policy
    try {
        $auditOutput = auditpol /get /category:* 2>&1
        $noAuditCount = ($auditOutput | Select-String "No Auditing").Count
        $totalPolicies = ($auditOutput | Select-String "(Success|Failure|No Auditing)").Count
        $configuredCount = $totalPolicies - $noAuditCount
        $healthData['AuditConfigured'] = $configuredCount
        $healthData['AuditTotal'] = $totalPolicies
        if ($noAuditCount -gt 0) {
            Write-Host "  Audit Policy:  $configuredCount of $totalPolicies subcategories configured ($noAuditCount not audited)" -ForegroundColor Yellow
        }
        else {
            Write-Host "  Audit Policy:  All $totalPolicies subcategories configured" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  Audit Policy:  Could not retrieve (run as admin)" -ForegroundColor Yellow
    }

    Write-Host ""

    # Quick issues summary
    $issues = @()

    if ($healthData.ContainsKey('DomainAdminCount') -and $healthData['DomainAdminCount'] -gt 5) {
        $issues += "HIGH: $($healthData['DomainAdminCount']) Domain Admins (recommended: 5 or fewer)"
    }
    if ($healthData.ContainsKey('EnterpriseAdminCount') -and $healthData['EnterpriseAdminCount'] -gt 3) {
        $issues += "MEDIUM: $($healthData['EnterpriseAdminCount']) Enterprise Admins (recommended: 3 or fewer)"
    }
    if ($healthData.ContainsKey('AuditConfigured') -and $healthData.ContainsKey('AuditTotal')) {
        if ($healthData['AuditConfigured'] -lt ($healthData['AuditTotal'] / 2)) {
            $issues += "HIGH: Less than half of audit subcategories are configured"
        }
    }
    if ($healthData.ContainsKey('DisabledComputers') -and $healthData['DisabledComputers'] -gt 20) {
        $issues += "LOW: $($healthData['DisabledComputers']) disabled computer accounts (consider cleanup)"
    }

    # Check for built-in Administrator enabled
    try {
        $builtinAdmin = Get-ADUser -Filter { SID -like "*-500" } -Properties Enabled @adParams -ErrorAction Stop
        if ($builtinAdmin.Enabled -eq $true) {
            $issues += "MEDIUM: Built-in Administrator account is enabled"
        }
    }
    catch { }

    if ($issues.Count -gt 0) {
        Write-Host "  Quick Issues Found:" -ForegroundColor Yellow
        foreach ($issue in $issues) {
            $color = "Yellow"
            if ($issue -match "^HIGH:") { $color = "Red" }
            if ($issue -match "^LOW:") { $color = "Gray" }
            Write-Host "    - $issue" -ForegroundColor $color
        }
    }
    else {
        Write-Host "  No obvious issues detected at a glance." -ForegroundColor Green
    }

    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host ""

    $Script:HealthCheckData = $healthData
    Write-Log -Level FINDING -Message "Health check complete: $($issues.Count) issue(s) found."
}

# ══════════════════════════════════════════════════════════════════════
#  MAIN MENU
# ══════════════════════════════════════════════════════════════════════

function Show-MainMenu {
    $menuItems = @(
        @{ Num = "1"; Label = "Patch All Domain Computers";        Modules = @("PSWindowsUpdate") }
        @{ Num = "2"; Label = "Restrict RDP Access";               Modules = @() }
        @{ Num = "3"; Label = "Harden DNS Server Configuration";   Modules = @("DnsServer") }
        @{ Num = "4"; Label = "Disable Unnecessary Services";      Modules = @("DnsServer") }
        @{ Num = "5"; Label = "Harden Administrator Accounts";     Modules = @() }
        @{ Num = "6"; Label = "Enable Advanced Auditing";          Modules = @() }
        @{ Num = "7"; Label = "Detect Kerberoastable Accounts";    Modules = @() }
        @{ Num = "8"; Label = "Secure DNS Zone Transfers";         Modules = @("DnsServer") }
        @{ Num = "9"; Label = "Check Suspicious Scheduled Tasks";  Modules = @() }
        @{ Num = "10"; Label = "Check AD Misconfigurations (Permissions)"; Modules = @() }
    )

    Write-Host ""
    Write-Host "===== AD Hardener - Main Menu =====" -ForegroundColor Cyan
    Write-Host ""

    foreach ($item in $menuItems) {
        $prefix = " "
        $suffix = ""
        $color = "White"

        # Check if completed
        if ($Script:CompletedFeatures.ContainsKey($item.Num) -and $Script:CompletedFeatures[$item.Num]) {
            $suffix = " [DONE]"
            $color = "Green"
        }

        # Check for missing modules
        $missingModule = $null
        foreach ($mod in $item.Modules) {
            if (-not (Test-ModuleAvailable -ModuleName $mod)) {
                $missingModule = $mod
                break
            }
        }

        if ($missingModule) {
            Write-Host " $($item.Num). $($item.Label)  (requires $missingModule)" -ForegroundColor DarkGray
        }
        else {
            Write-Host " $($item.Num). $($item.Label)$suffix" -ForegroundColor $color
        }
    }

    Write-Host ""
    Write-Host " H. Help - Explain what each option does" -ForegroundColor Yellow
    Write-Host " R. Generate Report" -ForegroundColor Yellow
    Write-Host " Q. Quit" -ForegroundColor Yellow
    Write-Host ""
}

# ══════════════════════════════════════════════════════════════════════
#  HELP
# ══════════════════════════════════════════════════════════════════════

function Show-Help {
    Write-Host ""
    Write-Host "===== AD Hardener - Help =====" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "1. Patch All Domain Computers" -ForegroundColor White
    Write-Host "   Finds all computers in Active Directory and installs Windows Updates" -ForegroundColor Gray
    Write-Host "   on them remotely. You can pick which machines to update, and the script" -ForegroundColor Gray
    Write-Host "   will check connectivity first. Great for keeping your domain patched" -ForegroundColor Gray
    Write-Host "   against known vulnerabilities. Requires the PSWindowsUpdate module." -ForegroundColor Gray
    Write-Host ""

    Write-Host "2. Restrict RDP Access" -ForegroundColor White
    Write-Host "   Controls who can log in via Remote Desktop (RDP) and where RDP traffic" -ForegroundColor Gray
    Write-Host "   can come from. You can restrict it per-machine or domain-wide using" -ForegroundColor Gray
    Write-Host "   Group Policy. This reduces the attack surface for brute-force and" -ForegroundColor Gray
    Write-Host "   lateral movement attacks." -ForegroundColor Gray
    Write-Host ""

    Write-Host "3. Harden DNS Server Configuration" -ForegroundColor White
    Write-Host "   Secures your DNS servers by limiting who can administer them and" -ForegroundColor Gray
    Write-Host "   enabling detailed logging. DNS is critical infrastructure and a common" -ForegroundColor Gray
    Write-Host "   attack target, so securing it reduces your domain's attack surface." -ForegroundColor Gray
    Write-Host ""

    Write-Host "4. Disable Unnecessary Services" -ForegroundColor White
    Write-Host "   Scans DNS servers for running services that are not in the approved" -ForegroundColor Gray
    Write-Host "   whitelist. Unnecessary services increase the attack surface. You can" -ForegroundColor Gray
    Write-Host "   disable or stop them individually." -ForegroundColor Gray
    Write-Host ""

    Write-Host "5. Harden Administrator Accounts" -ForegroundColor White
    Write-Host "   Reviews all privileged accounts (Domain Admins, Enterprise Admins," -ForegroundColor Gray
    Write-Host "   Schema Admins, built-in Administrator). Checks password age, delegation" -ForegroundColor Gray
    Write-Host "   settings, and activity. Offers to fix common issues like missing" -ForegroundColor Gray
    Write-Host "   'Account is sensitive' flags or old passwords." -ForegroundColor Gray
    Write-Host ""

    Write-Host "6. Enable Advanced Auditing" -ForegroundColor White
    Write-Host "   Configures Windows audit policies so you can detect attacks and" -ForegroundColor Gray
    Write-Host "   suspicious activity in your event logs. Without proper auditing," -ForegroundColor Gray
    Write-Host "   attackers can operate undetected. Also increases log sizes and enables" -ForegroundColor Gray
    Write-Host "   command-line logging in process creation events." -ForegroundColor Gray
    Write-Host ""

    Write-Host "7. Detect Kerberoastable Accounts" -ForegroundColor White
    Write-Host "   Finds accounts with Service Principal Names (SPNs) that attackers" -ForegroundColor Gray
    Write-Host "   could 'Kerberoast' to crack their passwords offline. Evaluates risk" -ForegroundColor Gray
    Write-Host "   based on encryption type, password age, and privilege level. Provides" -ForegroundColor Gray
    Write-Host "   specific remediation advice for high-risk accounts." -ForegroundColor Gray
    Write-Host ""

    Write-Host "8. Secure DNS Zone Transfers" -ForegroundColor White
    Write-Host "   Checks if your DNS zones allow unrestricted zone transfers, which" -ForegroundColor Gray
    Write-Host "   lets anyone dump all DNS records. This gives attackers a full map of" -ForegroundColor Gray
    Write-Host "   your network. The script can restrict transfers to authorized servers" -ForegroundColor Gray
    Write-Host "   only or disable them entirely." -ForegroundColor Gray
    Write-Host ""

    Write-Host "9. Check Suspicious Scheduled Tasks" -ForegroundColor White
    Write-Host "   Scans computers for scheduled tasks that look suspicious: tasks running" -ForegroundColor Gray
    Write-Host "   as SYSTEM, with encoded commands, from unusual paths, recently created," -ForegroundColor Gray
    Write-Host "   or with names mimicking legitimate tasks. Attackers often use scheduled" -ForegroundColor Gray
    Write-Host "   tasks for persistence." -ForegroundColor Gray
    Write-Host ""

    Write-Host "10. Check AD Misconfigurations (Permissions)" -ForegroundColor White
    Write-Host "   Scans Active Directory for common security misconfigurations that tools" -ForegroundColor Gray
    Write-Host "   like BloodHound exploit. Checks for dangerous ACL permissions (GenericAll," -ForegroundColor Gray
    Write-Host "   WriteDACL, WriteOwner, etc.) on sensitive objects, unconstrained delegation," -ForegroundColor Gray
    Write-Host "   AS-REP roastable accounts, DCSync rights, weak machine account quotas," -ForegroundColor Gray
    Write-Host "   passwords in descriptions, reversible encryption, LDAP signing, and more." -ForegroundColor Gray
    Write-Host "   For each finding, you can choose to fix it immediately." -ForegroundColor Gray
    Write-Host ""

    Write-Host "Press Enter to return to the menu..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

# ══════════════════════════════════════════════════════════════════════
#  FEATURE 1: Patch All Domain Computers
# ══════════════════════════════════════════════════════════════════════

function Invoke-PatchComputers {
    Write-Host ""
    Write-Host "===== Feature 1: Patch All Domain Computers =====" -ForegroundColor Cyan
    Write-Host ""

    if (-not (Test-ModuleAvailable -ModuleName "PSWindowsUpdate")) {
        Write-Host "This feature requires the PSWindowsUpdate module, which is not installed." -ForegroundColor Red
        Write-Host "Please install it with: Install-Module PSWindowsUpdate -Force" -ForegroundColor Yellow
        return
    }

    $adParams = Get-ADTargetParams

    # Query all enabled computers
    Write-Log -Level CHECK -Message "Querying enabled domain computers..."
    try {
        $computers = Get-ADComputer -Filter { Enabled -eq $true } -Properties Name, OperatingSystem, LastLogonDate @adParams -ErrorAction Stop
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to query domain computers: $_"
        return
    }

    if ($computers.Count -eq 0) {
        Write-Host "No enabled computers found in the domain." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "Found $($computers.Count) enabled computer(s):" -ForegroundColor White
    Write-Host ""
    Write-Host ("{0,-5} {1,-25} {2,-30} {3,-15}" -f "#", "Name", "OS", "Last Logon") -ForegroundColor Cyan
    Write-Host ("-" * 75) -ForegroundColor Gray
    for ($i = 0; $i -lt $computers.Count; $i++) {
        $comp = $computers[$i]
        $lastLogon = if ($comp.LastLogonDate) { $comp.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
        $os = if ($comp.OperatingSystem) { $comp.OperatingSystem } else { "Unknown" }
        if ($os.Length -gt 28) { $os = $os.Substring(0, 28) }
        Write-Host ("{0,-5} {1,-25} {2,-30} {3,-15}" -f ($i + 1), $comp.Name, $os, $lastLogon) -ForegroundColor White
    }

    # Let user exclude some
    Write-Host ""
    Write-Host "Enter numbers to EXCLUDE from patching (comma-separated), or press Enter for all:" -ForegroundColor Yellow
    $excludeInput = Read-Host
    $targetComputers = @()
    if ([string]::IsNullOrWhiteSpace($excludeInput)) {
        $targetComputers = $computers
    }
    else {
        $excludeNums = $excludeInput -split ',' | ForEach-Object { $_.Trim() }
        $excludeIndices = @()
        foreach ($num in $excludeNums) {
            $idx = 0
            if ([int]::TryParse($num, [ref]$idx)) {
                $excludeIndices += ($idx - 1)
            }
        }
        for ($i = 0; $i -lt $computers.Count; $i++) {
            if ($i -notin $excludeIndices) {
                $targetComputers += $computers[$i]
            }
        }
    }

    if ($targetComputers.Count -eq 0) {
        Write-Host "No computers selected for patching." -ForegroundColor Yellow
        return
    }

    Write-Host ""
    Write-Host "Will patch $($targetComputers.Count) computer(s)." -ForegroundColor White

    # Dry-run preview
    $description = "Install Windows Updates on $($targetComputers.Count) computer(s): $($targetComputers.Name -join ', ')"
    $doApply = Invoke-WithDryRun -Description $description -Action {
        # Test connectivity and patch
        $successCount = 0
        $failCount = 0
        $rebootNeeded = @()

        for ($i = 0; $i -lt $targetComputers.Count; $i++) {
            $comp = $targetComputers[$i]
            $percent = [math]::Round(($i / $targetComputers.Count) * 100)
            Write-Host "`r  [$percent%] Patching $($comp.Name)..." -ForegroundColor Cyan -NoNewline

            if (-not (Test-RemoteConnectivity -ComputerName $comp.Name)) {
                Write-Log -Level WARNING -Message "Skipping $($comp.Name) - unreachable."
                $failCount++
                continue
            }

            try {
                # Invoke Windows Update remotely
                Invoke-WUJob -ComputerName $comp.Name -Script {
                    Import-Module PSWindowsUpdate
                    Install-WindowsUpdate -AcceptAll -AutoReboot -ErrorAction Stop
                } -Confirm:$false -RunNow -ErrorAction Stop

                Write-Log -Level ACTION -Message "Triggered Windows Update on $($comp.Name)"
                $successCount++

                # Check pending reboot
                $rebootStatus = Invoke-RemoteCommand -ComputerName $comp.Name -ScriptBlock {
                    $reboot = $false
                    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -ErrorAction SilentlyContinue) {
                        $reboot = $true
                    }
                    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue) {
                        $reboot = $true
                    }
                    return $reboot
                }
                if ($rebootStatus) {
                    $rebootNeeded += $comp.Name
                }
            }
            catch {
                Write-Log -Level ERROR -Message "Failed to patch $($comp.Name): $_"
                $failCount++
            }
        }

        Write-Host "" # Clear progress line
        Write-Host ""
        Write-Host "===== Patching Summary =====" -ForegroundColor Cyan
        Write-Host "  Successful: $successCount" -ForegroundColor Green
        Write-Host "  Failed:     $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
        if ($rebootNeeded.Count -gt 0) {
            Write-Host "  Pending Reboot: $($rebootNeeded -join ', ')" -ForegroundColor Yellow
        }
    }

    $Script:CompletedFeatures["1"] = $true
    Write-Host ""
    Write-Host "Press Enter to return to the menu..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

# ══════════════════════════════════════════════════════════════════════
#  FEATURE 2: Restrict RDP Access
# ══════════════════════════════════════════════════════════════════════

function Invoke-RestrictRDP {
    Write-Host ""
    Write-Host "===== Feature 2: Restrict RDP Access =====" -ForegroundColor Cyan

    while ($true) {
        Write-Host ""
        Write-Host "  2a. Restrict RDP users per machine (local group)" -ForegroundColor White
        Write-Host "  2b. Restrict RDP users domain-wide (GPO)" -ForegroundColor $(if (Test-ModuleAvailable -ModuleName "GroupPolicy") { "White" } else { "DarkGray" })
        Write-Host "  2c. Restrict RDP by firewall per machine (local)" -ForegroundColor White
        Write-Host "  2d. Restrict RDP by firewall domain-wide (GPO)" -ForegroundColor $(if (Test-ModuleAvailable -ModuleName "GroupPolicy") { "White" } else { "DarkGray" })
        Write-Host "  B.  Back to main menu" -ForegroundColor Yellow
        Write-Host ""

        $choice = Read-UserChoice -Prompt "Select option" -ValidChoices @('2a','2b','2c','2d','a','b','c','d','B') -Default 'B'

        switch ($choice.ToLower()) {
            { $_ -eq '2a' -or $_ -eq 'a' } { Invoke-RDP-LocalGroup; break }
            { $_ -eq '2b' -or $_ -eq 'b' -and $choice -ne 'B' } {
                if (Test-ModuleAvailable -ModuleName "GroupPolicy") {
                    Invoke-RDP-GPOUsers
                }
                else {
                    Write-Host "  This option requires the GroupPolicy module." -ForegroundColor Red
                }
                break
            }
            { $_ -eq '2c' -or $_ -eq 'c' } { Invoke-RDP-LocalFirewall; break }
            { $_ -eq '2d' -or $_ -eq 'd' } {
                if (Test-ModuleAvailable -ModuleName "GroupPolicy") {
                    Invoke-RDP-GPOFirewall
                }
                else {
                    Write-Host "  This option requires the GroupPolicy module." -ForegroundColor Red
                }
                break
            }
            'b' {
                if ($choice -eq 'B') { return }
                break
            }
            default { return }
        }
    }

    $Script:CompletedFeatures["2"] = $true
}

function Invoke-RDP-LocalGroup {
    Write-Host ""
    Write-Host "--- 2a: Restrict RDP Users Per Machine (Local Group) ---" -ForegroundColor Cyan
    Write-Host ""

    $adParams = Get-ADTargetParams

    # Get target computers
    Write-Host "Enter computer name(s) to configure (comma-separated):" -ForegroundColor Yellow
    $inputNames = Read-Host
    if ([string]::IsNullOrWhiteSpace($inputNames)) {
        Write-Host "No computers specified." -ForegroundColor Yellow
        return
    }

    $computerNames = $inputNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

    # Get allowed users/groups
    Write-Host "Enter users/groups to ALLOW RDP access (comma-separated, e.g. Domain Admins,HelpDesk):" -ForegroundColor Yellow
    $allowedInput = Read-Host
    if ([string]::IsNullOrWhiteSpace($allowedInput)) {
        Write-Host "No users specified. Aborting." -ForegroundColor Yellow
        return
    }
    $allowedMembers = $allowedInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

    foreach ($compName in $computerNames) {
        Write-Host ""
        Write-Log -Level CHECK -Message "Processing $compName..."

        if (-not (Test-RemoteConnectivity -ComputerName $compName)) {
            Write-Log -Level WARNING -Message "Skipping $compName - unreachable."
            continue
        }

        # Show current members
        $currentMembers = Invoke-RemoteCommand -ComputerName $compName -ScriptBlock {
            try {
                $group = [ADSI]"WinNT://./Remote Desktop Users,group"
                $members = @()
                $group.Invoke("Members") | ForEach-Object {
                    $members += $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                }
                return $members
            }
            catch {
                return @()
            }
        }

        Write-Host "  Current 'Remote Desktop Users' members on ${compName}:" -ForegroundColor White
        if ($currentMembers -and $currentMembers.Count -gt 0) {
            foreach ($m in $currentMembers) {
                Write-Host "    - $m" -ForegroundColor Gray
            }
        }
        else {
            Write-Host "    (empty)" -ForegroundColor Gray
        }

        $description = "Set Remote Desktop Users on $compName to: $($allowedMembers -join ', ')"
        Invoke-WithDryRun -Description $description -Action {
            Invoke-RemoteCommand -ComputerName $compName -ScriptBlock {
                param($members)
                $group = [ADSI]"WinNT://./Remote Desktop Users,group"
                # Remove all current members
                try {
                    $group.Invoke("Members") | ForEach-Object {
                        $name = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                        try { $group.Remove($_.GetType().InvokeMember("AdsPath", 'GetProperty', $null, $_, $null)) } catch { }
                    }
                }
                catch { }
                # Add specified members
                foreach ($m in $members) {
                    try {
                        $group.Add("WinNT://$env:USERDOMAIN/$m,group")
                    }
                    catch {
                        try {
                            $group.Add("WinNT://$env:USERDOMAIN/$m,user")
                        }
                        catch {
                            Write-Warning "Could not add $m to Remote Desktop Users: $_"
                        }
                    }
                }
            } -ArgumentList @{ members = $allowedMembers }
            Write-Log -Level ACTION -Message "Updated Remote Desktop Users on $compName"
        } | Out-Null
    }

    $Script:CompletedFeatures["2"] = $true
}

function Invoke-RDP-GPOUsers {
    Write-Host ""
    Write-Host "--- 2b: Restrict RDP Users Domain-Wide (GPO) ---" -ForegroundColor Cyan
    Write-Host ""

    # List existing GPOs
    try {
        $gpos = Get-GPO -All -ErrorAction Stop | Sort-Object DisplayName
        Write-Host "Existing GPOs:" -ForegroundColor White
        for ($i = 0; $i -lt $gpos.Count; $i++) {
            Write-Host "  $($i + 1). $($gpos[$i].DisplayName)" -ForegroundColor White
        }
        Write-Host "  N. Create new GPO" -ForegroundColor Yellow
        Write-Host ""
    }
    catch {
        Write-Log -Level ERROR -Message "Could not list GPOs: $_"
        return
    }

    $gpoChoice = Read-Host "Select GPO number or N for new"
    $targetGPO = $null

    if ($gpoChoice -eq 'N' -or $gpoChoice -eq 'n') {
        Write-Host "Enter name for the new GPO:" -ForegroundColor Yellow
        $gpoName = Read-Host
        if ([string]::IsNullOrWhiteSpace($gpoName)) {
            Write-Host "No name specified. Aborting." -ForegroundColor Yellow
            return
        }
        $description = "Create GPO '$gpoName' for RDP restriction"
        Invoke-WithDryRun -Description $description -Action {
            $targetGPO = New-GPO -Name $gpoName -ErrorAction Stop
            Write-Log -Level ACTION -Message "Created GPO: $gpoName"
        } | Out-Null

        if (-not $targetGPO) {
            try { $targetGPO = Get-GPO -Name $gpoName -ErrorAction Stop } catch { }
        }
    }
    else {
        $idx = 0
        if ([int]::TryParse($gpoChoice, [ref]$idx) -and $idx -ge 1 -and $idx -le $gpos.Count) {
            $targetGPO = $gpos[$idx - 1]
        }
        else {
            Write-Host "Invalid selection." -ForegroundColor Red
            return
        }
    }

    if (-not $targetGPO) {
        Write-Host "No GPO selected." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "Selected GPO: $($targetGPO.DisplayName)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Enter users/groups to ALLOW RDP access (comma-separated):" -ForegroundColor Yellow
    $allowedInput = Read-Host
    if ([string]::IsNullOrWhiteSpace($allowedInput)) {
        Write-Host "No users specified. Aborting." -ForegroundColor Yellow
        return
    }
    $allowedMembers = $allowedInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

    $description = "Configure GPO '$($targetGPO.DisplayName)' to restrict RDP to: $($allowedMembers -join ', ')"
    Invoke-WithDryRun -Description $description -Action {
        # Set User Rights Assignment: Allow log on through Remote Desktop Services
        $gpoId = $targetGPO.Id.ToString()
        $domainName = $Script:DomainName

        # Build the GptTmpl.inf content for user rights
        $sids = @()
        foreach ($member in $allowedMembers) {
            try {
                $adObj = Get-ADObject -Filter { Name -eq $member -or SamAccountName -eq $member } -Properties objectSid @(Get-ADTargetParams) -ErrorAction Stop | Select-Object -First 1
                if ($adObj.objectSid) {
                    $sids += "*$($adObj.objectSid)"
                }
                else {
                    $sids += $member
                }
            }
            catch {
                $sids += $member
            }
        }

        $sidsString = $sids -join ','
        $infPath = "\\$domainName\SYSVOL\$domainName\Policies\{$gpoId}\Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

        # Ensure directory exists
        $infDir = Split-Path $infPath -Parent
        if (-not (Test-Path $infDir)) {
            New-Item -Path $infDir -ItemType Directory -Force | Out-Null
        }

        $infContent = @"
[Unicode]
Unicode=yes
[Version]
signature="`$CHICAGO`$"
Revision=1
[Privilege Rights]
SeRemoteInteractiveLogonRight = $sidsString
"@
        Set-Content -Path $infPath -Value $infContent -Encoding Unicode
        Write-Log -Level ACTION -Message "Configured RDP user rights in GPO '$($targetGPO.DisplayName)'"
    } | Out-Null

    $Script:CompletedFeatures["2"] = $true
}

function Invoke-RDP-LocalFirewall {
    Write-Host ""
    Write-Host "--- 2c: Restrict RDP by Firewall Per Machine ---" -ForegroundColor Cyan
    Write-Host ""

    Write-Host "Enter computer name(s) to configure (comma-separated):" -ForegroundColor Yellow
    $inputNames = Read-Host
    if ([string]::IsNullOrWhiteSpace($inputNames)) {
        Write-Host "No computers specified." -ForegroundColor Yellow
        return
    }
    $computerNames = $inputNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

    Write-Host "Enter allowed source IP addresses for RDP (comma-separated):" -ForegroundColor Yellow
    Write-Host "  Example: 10.0.1.0/24,10.0.2.50,192.168.1.0/24" -ForegroundColor Gray
    $ipInput = Read-Host
    if ([string]::IsNullOrWhiteSpace($ipInput)) {
        Write-Host "No IPs specified. Aborting." -ForegroundColor Yellow
        return
    }
    $allowedIPs = $ipInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

    foreach ($compName in $computerNames) {
        Write-Host ""
        Write-Log -Level CHECK -Message "Processing $compName..."

        if (-not (Test-RemoteConnectivity -ComputerName $compName)) {
            Write-Log -Level WARNING -Message "Skipping $compName - unreachable."
            continue
        }

        $description = "Configure RDP firewall rule on $compName to allow only: $($allowedIPs -join ', ')"
        Invoke-WithDryRun -Description $description -Action {
            Invoke-RemoteCommand -ComputerName $compName -ScriptBlock {
                param($ips)
                $ruleName = "AD-Hardener-RDP-Restrict"
                # Remove existing rule if present
                Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue

                # Block all RDP first by disabling the default rule
                $defaultRDP = Get-NetFirewallRule -DisplayGroup "Remote Desktop" -ErrorAction SilentlyContinue
                if ($defaultRDP) {
                    $defaultRDP | Set-NetFirewallRule -Enabled False -ErrorAction SilentlyContinue
                }

                # Create new rule allowing only specified IPs
                New-NetFirewallRule -DisplayName $ruleName `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort 3389 `
                    -RemoteAddress $ips `
                    -Action Allow `
                    -Enabled True `
                    -Profile Any `
                    -Description "Created by AD-Hardener: restricts RDP to specific IPs" `
                    -ErrorAction Stop | Out-Null
            } -ArgumentList @{ ips = $allowedIPs }
            Write-Log -Level ACTION -Message "Configured RDP firewall restriction on $compName"
        } | Out-Null
    }

    $Script:CompletedFeatures["2"] = $true
}

function Invoke-RDP-GPOFirewall {
    Write-Host ""
    Write-Host "--- 2d: Restrict RDP by Firewall Domain-Wide (GPO) ---" -ForegroundColor Cyan
    Write-Host ""

    # List GPOs
    try {
        $gpos = Get-GPO -All -ErrorAction Stop | Sort-Object DisplayName
        Write-Host "Existing GPOs:" -ForegroundColor White
        for ($i = 0; $i -lt $gpos.Count; $i++) {
            Write-Host "  $($i + 1). $($gpos[$i].DisplayName)" -ForegroundColor White
        }
        Write-Host "  N. Create new GPO" -ForegroundColor Yellow
        Write-Host ""
    }
    catch {
        Write-Log -Level ERROR -Message "Could not list GPOs: $_"
        return
    }

    $gpoChoice = Read-Host "Select GPO number or N for new"
    $targetGPO = $null

    if ($gpoChoice -eq 'N' -or $gpoChoice -eq 'n') {
        Write-Host "Enter name for the new GPO:" -ForegroundColor Yellow
        $gpoName = Read-Host
        if ([string]::IsNullOrWhiteSpace($gpoName)) {
            Write-Host "No name specified. Aborting." -ForegroundColor Yellow
            return
        }
        $description = "Create GPO '$gpoName' for RDP firewall restriction"
        Invoke-WithDryRun -Description $description -Action {
            $targetGPO = New-GPO -Name $gpoName -ErrorAction Stop
            Write-Log -Level ACTION -Message "Created GPO: $gpoName"
        } | Out-Null
        if (-not $targetGPO) {
            try { $targetGPO = Get-GPO -Name $gpoName -ErrorAction Stop } catch { }
        }
    }
    else {
        $idx = 0
        if ([int]::TryParse($gpoChoice, [ref]$idx) -and $idx -ge 1 -and $idx -le $gpos.Count) {
            $targetGPO = $gpos[$idx - 1]
        }
        else {
            Write-Host "Invalid selection." -ForegroundColor Red
            return
        }
    }

    if (-not $targetGPO) {
        Write-Host "No GPO selected." -ForegroundColor Red
        return
    }

    Write-Host ""
    Write-Host "Enter allowed source IP addresses for RDP (comma-separated):" -ForegroundColor Yellow
    $ipInput = Read-Host
    if ([string]::IsNullOrWhiteSpace($ipInput)) {
        Write-Host "No IPs specified. Aborting." -ForegroundColor Yellow
        return
    }
    $allowedIPs = $ipInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }

    $description = "Configure RDP firewall rule in GPO '$($targetGPO.DisplayName)' allowing: $($allowedIPs -join ', ')"
    Invoke-WithDryRun -Description $description -Action {
        $gpoId = $targetGPO.Id.ToString()
        $domainName = $Script:DomainName

        # Configure firewall rule via GPO registry-based policy
        $gpoPath = "\\$domainName\SYSVOL\$domainName\Policies\{$gpoId}\Machine\Microsoft\Windows\WindowsFirewall"

        # Use Set-GPRegistryValue to configure firewall settings
        $regKey = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules"
        $ruleValue = "v2.32|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=3389|RA4=$($allowedIPs -join ',')|Name=AD-Hardener-RDP-Restrict|Desc=RDP restricted by AD-Hardener|"

        Set-GPRegistryValue -Name $targetGPO.DisplayName `
            -Key $regKey `
            -ValueName "AD-Hardener-RDP-Restrict" `
            -Type String `
            -Value $ruleValue `
            -ErrorAction Stop

        Write-Log -Level ACTION -Message "Configured RDP firewall rule in GPO '$($targetGPO.DisplayName)'"
    } | Out-Null

    $Script:CompletedFeatures["2"] = $true
}

# ══════════════════════════════════════════════════════════════════════
#  FEATURE 3: Harden DNS Server Configuration
# ══════════════════════════════════════════════════════════════════════

function Invoke-HardenDNS {
    Write-Host ""
    Write-Host "===== Feature 3: Harden DNS Server Configuration =====" -ForegroundColor Cyan

    if (-not (Test-ModuleAvailable -ModuleName "DnsServer")) {
        Write-Host "This feature requires the DnsServer module, which is not installed." -ForegroundColor Red
        return
    }

    while ($true) {
        Write-Host ""
        Write-Host "  3a. Limit DNS Administration (DnsAdmins group)" -ForegroundColor White
        Write-Host "  3b. Enable DNS Server Logging" -ForegroundColor White
        Write-Host "  B.  Back to main menu" -ForegroundColor Yellow
        Write-Host ""

        $choice = Read-UserChoice -Prompt "Select option" -ValidChoices @('3a','3b','a','b','B') -Default 'B'

        switch ($choice.ToLower()) {
            { $_ -eq '3a' -or $_ -eq 'a' } { Invoke-LimitDNSAdmin; break }
            { $_ -eq '3b' -and $choice -ne 'B' } { Invoke-EnableDNSLogging; break }
            'b' {
                if ($choice -eq 'B') { return }
                Invoke-EnableDNSLogging
                break
            }
            default { return }
        }
    }
}

function Invoke-LimitDNSAdmin {
    Write-Host ""
    Write-Host "--- 3a: Limit DNS Administration ---" -ForegroundColor Cyan
    Write-Host ""

    $adParams = Get-ADTargetParams

    # Show current DnsAdmins members
    Write-Log -Level CHECK -Message "Checking DnsAdmins group membership..."
    try {
        $dnsAdmins = Get-ADGroupMember -Identity "DnsAdmins" @adParams -ErrorAction Stop
        Write-Host ""
        Write-Host "Current DnsAdmins members:" -ForegroundColor White
        if ($dnsAdmins.Count -eq 0) {
            Write-Host "  (empty)" -ForegroundColor Gray
        }
        else {
            for ($i = 0; $i -lt $dnsAdmins.Count; $i++) {
                $member = $dnsAdmins[$i]
                Write-Host "  $($i + 1). $($member.SamAccountName) ($($member.objectClass))" -ForegroundColor White
            }
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Could not query DnsAdmins group: $_"
        return
    }

    if ($dnsAdmins.Count -gt 0) {
        Write-Host ""
        Write-Host "Enter numbers of members to REMOVE from DnsAdmins (comma-separated), or press Enter to skip:" -ForegroundColor Yellow
        $removeInput = Read-Host
        if (-not [string]::IsNullOrWhiteSpace($removeInput)) {
            $removeNums = $removeInput -split ',' | ForEach-Object { $_.Trim() }
            foreach ($num in $removeNums) {
                $idx = 0
                if ([int]::TryParse($num, [ref]$idx) -and $idx -ge 1 -and $idx -le $dnsAdmins.Count) {
                    $memberToRemove = $dnsAdmins[$idx - 1]
                    $description = "Remove '$($memberToRemove.SamAccountName)' from DnsAdmins group"
                    Invoke-WithDryRun -Description $description -Action {
                        Remove-ADGroupMember -Identity "DnsAdmins" -Members $memberToRemove -Confirm:$false @adParams -ErrorAction Stop
                        Write-Log -Level ACTION -Message "Removed $($memberToRemove.SamAccountName) from DnsAdmins"
                    } | Out-Null
                }
            }
        }
    }

    # Offer to add specific members
    Write-Host ""
    Write-Host "Enter usernames to ADD to DnsAdmins (comma-separated), or press Enter to skip:" -ForegroundColor Yellow
    $addInput = Read-Host
    if (-not [string]::IsNullOrWhiteSpace($addInput)) {
        $addMembers = $addInput -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        foreach ($member in $addMembers) {
            $description = "Add '$member' to DnsAdmins group"
            Invoke-WithDryRun -Description $description -Action {
                Add-ADGroupMember -Identity "DnsAdmins" -Members $member @adParams -ErrorAction Stop
                Write-Log -Level ACTION -Message "Added $member to DnsAdmins"
            } | Out-Null
        }
    }

    Write-Log -Level FINDING -Message "DnsAdmins group review completed."
    $Script:CompletedFeatures["3"] = $true
}

function Invoke-EnableDNSLogging {
    Write-Host ""
    Write-Host "--- 3b: Enable DNS Server Logging ---" -ForegroundColor Cyan
    Write-Host ""

    $servers = Get-DNSServerList
    if ($servers.Count -eq 0) {
        Write-Host "No DNS servers found." -ForegroundColor Yellow
        return
    }
    $selectedServers = Select-DNSServers -AvailableServers $servers

    foreach ($server in $selectedServers) {
        Write-Host ""
        Write-Host "=== DNS Logging on $server ===" -ForegroundColor Cyan

        # Show current logging status
        try {
            $diagLogging = Get-DnsServerDiagnostics -ComputerName $server -ErrorAction Stop
            Write-Host ""
            Write-Host "Current DNS Diagnostic Logging:" -ForegroundColor White
            Write-Host "  Queries:              $($diagLogging.QueryReceived)" -ForegroundColor $(if ($diagLogging.QueryReceived) { "Green" } else { "Yellow" })
            Write-Host "  Answers:              $($diagLogging.SendResponse)" -ForegroundColor $(if ($diagLogging.SendResponse) { "Green" } else { "Yellow" })
            Write-Host "  Notifications:        $($diagLogging.Notifications)" -ForegroundColor $(if ($diagLogging.Notifications) { "Green" } else { "Yellow" })
            Write-Host "  Updates:              $($diagLogging.Update)" -ForegroundColor $(if ($diagLogging.Update) { "Green" } else { "Yellow" })
            Write-Host "  Questions:            $($diagLogging.Questions)" -ForegroundColor $(if ($diagLogging.Questions) { "Green" } else { "Yellow" })
            Write-Host "  Unmatched Responses:  $($diagLogging.UnmatchedResponse)" -ForegroundColor $(if ($diagLogging.UnmatchedResponse) { "Green" } else { "Yellow" })
            Write-Host "  Log File Path:        $($diagLogging.LogFilePath)" -ForegroundColor White
            Write-Host "  Max Log File Size:    $($diagLogging.MaxMBFileSize) MB" -ForegroundColor White
        }
        catch {
            Write-Log -Level WARNING -Message "Could not retrieve DNS diagnostics for ${server}: $_"
            continue
        }

        # Check if all categories are enabled
        $allEnabled = $diagLogging.QueryReceived -and $diagLogging.SendResponse -and $diagLogging.Notifications -and $diagLogging.Update -and $diagLogging.Questions

        if (-not $allEnabled) {
            Write-Host ""
            Write-Host "  Not all logging categories are enabled." -ForegroundColor Yellow

            $description = "Enable all DNS diagnostic logging on $server"
            Invoke-WithDryRun -Description $description -Action {
                Set-DnsServerDiagnostics -ComputerName $server `
                    -All $true `
                    -ErrorAction Stop

                # Set log file path and size
                Set-DnsServerDiagnostics -ComputerName $server `
                    -LogFilePath "C:\Windows\System32\dns\dns.log" `
                    -MaxMBFileSize 500 `
                    -ErrorAction Stop

                Write-Log -Level ACTION -Message "Enabled all DNS diagnostic logging on $server"
            } | Out-Null
        }
        else {
            Write-Host ""
            Write-Host "  All logging categories are already enabled." -ForegroundColor Green
        }

        # Also enable DNS analytical and audit event logging
        Write-Host ""
        $enableAnalytical = Read-YesNo -Prompt "  Enable DNS analytical event logging on $server?" -Default $true
        if ($enableAnalytical) {
            $description = "Enable DNS analytical event logging on $server"
            Invoke-WithDryRun -Description $description -Action {
                Invoke-RemoteCommand -ComputerName $server -ScriptBlock {
                    $logName = "Microsoft-Windows-DNSServer/Analytical"
                    $log = New-Object System.Diagnostics.Eventing.Reader.EventLogConfiguration $logName
                    $log.IsEnabled = $true
                    $log.MaximumSizeInBytes = 1073741824  # 1 GB
                    $log.SaveChanges()
                }
                Write-Log -Level ACTION -Message "Enabled DNS analytical event logging on $server"
            } | Out-Null
        }
    }

    $Script:CompletedFeatures["3"] = $true
}

# ══════════════════════════════════════════════════════════════════════
#  FEATURE 4: Disable Unnecessary Services
# ══════════════════════════════════════════════════════════════════════

function Invoke-DisableServices {
    Write-Host ""
    Write-Host "===== Feature 4: Disable Unnecessary Services on DNS Servers =====" -ForegroundColor Cyan
    Write-Host ""

    if (-not (Test-ModuleAvailable -ModuleName "DnsServer")) {
        Write-Host "This feature requires the DnsServer module, which is not installed." -ForegroundColor Red
        return
    }

    # Load service whitelist
    $whitelistFile = Join-Path $Script:ConfigPath "service-whitelist.csv"
    $whitelist = Import-CSVConfig -Path $whitelistFile -RequiredColumns @('ServiceName','DisplayName','Reason') -FriendlyName "Service whitelist"
    if (-not $whitelist) {
        Write-Host "Could not load service whitelist. Please check the file at:" -ForegroundColor Red
        Write-Host "  $whitelistFile" -ForegroundColor Yellow
        return
    }

    $whitelistedNames = $whitelist | ForEach-Object { $_.ServiceName }

    # Get DNS servers
    $servers = Get-DNSServerList
    if ($servers.Count -eq 0) {
        Write-Host "No DNS servers found." -ForegroundColor Yellow
        return
    }
    $selectedServers = Select-DNSServers -AvailableServers $servers

    foreach ($server in $selectedServers) {
        Write-Host ""
        Write-Host "=== Services on $server ===" -ForegroundColor Cyan

        if (-not (Test-RemoteConnectivity -ComputerName $server)) {
            Write-Log -Level WARNING -Message "Skipping $server - unreachable."
            continue
        }

        # Get running services
        try {
            $services = Invoke-RemoteCommand -ComputerName $server -ScriptBlock {
                Get-Service | Where-Object { $_.Status -eq 'Running' } |
                    Select-Object Name, DisplayName, StartType, Status
            }
        }
        catch {
            Write-Log -Level ERROR -Message "Could not enumerate services on ${server}: $_"
            continue
        }

        if (-not $services -or $services.Count -eq 0) {
            Write-Host "  No running services returned." -ForegroundColor Yellow
            continue
        }

        # Compare against whitelist
        $nonWhitelisted = @()
        foreach ($svc in $services) {
            if ($svc.Name -notin $whitelistedNames) {
                $nonWhitelisted += $svc
            }
        }

        Write-Host ""
        Write-Host "  Total running services: $($services.Count)" -ForegroundColor White
        Write-Host "  Whitelisted:            $($services.Count - $nonWhitelisted.Count)" -ForegroundColor Green
        Write-Host "  Non-whitelisted:        $($nonWhitelisted.Count)" -ForegroundColor $(if ($nonWhitelisted.Count -gt 0) { "Yellow" } else { "Green" })

        if ($nonWhitelisted.Count -eq 0) {
            Write-Host "  All running services are whitelisted." -ForegroundColor Green
            Write-Log -Level FINDING -Message "All services on $server are whitelisted."
            continue
        }

        Write-Host ""
        Write-Host ("{0,-5} {1,-25} {2,-40} {3,-12}" -f "#", "Service Name", "Display Name", "Start Type") -ForegroundColor Cyan
        Write-Host ("-" * 82) -ForegroundColor Gray
        for ($i = 0; $i -lt $nonWhitelisted.Count; $i++) {
            $svc = $nonWhitelisted[$i]
            $displayName = if ($svc.DisplayName.Length -gt 38) { $svc.DisplayName.Substring(0, 38) } else { $svc.DisplayName }
            Write-Host ("{0,-5} {1,-25} {2,-40} {3,-12}" -f ($i + 1), $svc.Name, $displayName, $svc.StartType) -ForegroundColor White
        }

        Write-Log -Level FINDING -Message "$($nonWhitelisted.Count) non-whitelisted services found on $server"

        # Process each non-whitelisted service
        Write-Host ""
        Write-Host "For each non-whitelisted service, choose action:" -ForegroundColor Yellow
        Write-Host "  D = Disable (stop + set to Disabled)" -ForegroundColor Gray
        Write-Host "  S = Stop only (leave start type unchanged)" -ForegroundColor Gray
        Write-Host "  K = Skip" -ForegroundColor Gray
        Write-Host "  A = Skip all remaining" -ForegroundColor Gray
        Write-Host ""

        $skipAll = $false
        foreach ($svc in $nonWhitelisted) {
            if ($skipAll) { break }

            $action = Read-UserChoice -Prompt "  $($svc.Name) ($($svc.DisplayName))" -ValidChoices @('D','d','S','s','K','k','A','a') -Default 'K'

            switch ($action.ToUpper()) {
                'D' {
                    $description = "Disable and stop service '$($svc.Name)' on $server"
                    Invoke-WithDryRun -Description $description -Action {
                        Invoke-RemoteCommand -ComputerName $server -ScriptBlock {
                            param($serviceName)
                            Stop-Service -Name $serviceName -Force -ErrorAction Stop
                            Set-Service -Name $serviceName -StartupType Disabled -ErrorAction Stop
                        } -ArgumentList @{ serviceName = $svc.Name }
                        Write-Log -Level ACTION -Message "Disabled service $($svc.Name) on $server"
                    } | Out-Null
                }
                'S' {
                    $description = "Stop service '$($svc.Name)' on $server"
                    Invoke-WithDryRun -Description $description -Action {
                        Invoke-RemoteCommand -ComputerName $server -ScriptBlock {
                            param($serviceName)
                            Stop-Service -Name $serviceName -Force -ErrorAction Stop
                        } -ArgumentList @{ serviceName = $svc.Name }
                        Write-Log -Level ACTION -Message "Stopped service $($svc.Name) on $server"
                    } | Out-Null
                }
                'A' { $skipAll = $true }
                default { }
            }
        }
    }

    $Script:CompletedFeatures["4"] = $true
    Write-Host ""
    Write-Host "Press Enter to return to the menu..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

# ══════════════════════════════════════════════════════════════════════
#  FEATURE 5: Harden Administrator Accounts
# ══════════════════════════════════════════════════════════════════════

function Invoke-HardenAdmins {
    Write-Host ""
    Write-Host "===== Feature 5: Harden Administrator Accounts =====" -ForegroundColor Cyan
    Write-Host ""

    $adParams = Get-ADTargetParams
    $settings = Get-ADScannerSettings
    $passwordAgeDays = if ($settings.PasswordAgeDays) { $settings.PasswordAgeDays } else { 90 }

    $adminAccounts = @()

    # Gather admin group members
    $groups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
    foreach ($groupName in $groups) {
        try {
            $members = Get-ADGroupMember -Identity $groupName @adParams -ErrorAction Stop -Recursive
            foreach ($member in $members) {
                if ($member.objectClass -eq 'user') {
                    $existing = $adminAccounts | Where-Object { $_.SamAccountName -eq $member.SamAccountName }
                    if (-not $existing) {
                        try {
                            $user = Get-ADUser -Identity $member.SamAccountName -Properties `
                                SamAccountName, Enabled, PasswordLastSet, LastLogonDate, `
                                AccountNotDelegated, AdminCount, MemberOf, SID `
                                @adParams -ErrorAction Stop

                            $memberOfGroups = @()
                            foreach ($g in $groups) {
                                try {
                                    $gMembers = Get-ADGroupMember -Identity $g @adParams -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
                                    if ($user.SamAccountName -in $gMembers) {
                                        $memberOfGroups += $g
                                    }
                                }
                                catch { }
                            }

                            $pwAge = if ($user.PasswordLastSet) {
                                [math]::Round(((Get-Date) - $user.PasswordLastSet).TotalDays)
                            }
                            else { 9999 }

                            $isBuiltIn = $user.SID.Value -match '-500$'

                            $adminAccounts += [PSCustomObject]@{
                                SamAccountName       = $user.SamAccountName
                                Enabled              = $user.Enabled
                                PasswordLastSet      = $user.PasswordLastSet
                                PasswordAgeDays      = $pwAge
                                LastLogonDate        = $user.LastLogonDate
                                AccountNotDelegated  = $user.AccountNotDelegated
                                AdminCount           = $user.AdminCount
                                Groups               = ($memberOfGroups -join ', ')
                                IsBuiltIn            = $isBuiltIn
                            }
                        }
                        catch {
                            Write-Log -Level WARNING -Message "Could not query user $($member.SamAccountName): $_"
                        }
                    }
                }
            }
        }
        catch {
            Write-Log -Level WARNING -Message "Could not enumerate group ${groupName}: $_"
        }
    }

    # Also ensure built-in Administrator is included
    try {
        $builtinAdmin = Get-ADUser -Filter { SID -like "*-500" } -Properties `
            SamAccountName, Enabled, PasswordLastSet, LastLogonDate, `
            AccountNotDelegated, AdminCount, SID @adParams -ErrorAction Stop

        $existing = $adminAccounts | Where-Object { $_.SamAccountName -eq $builtinAdmin.SamAccountName }
        if (-not $existing) {
            $pwAge = if ($builtinAdmin.PasswordLastSet) {
                [math]::Round(((Get-Date) - $builtinAdmin.PasswordLastSet).TotalDays)
            }
            else { 9999 }

            $adminAccounts += [PSCustomObject]@{
                SamAccountName       = $builtinAdmin.SamAccountName
                Enabled              = $builtinAdmin.Enabled
                PasswordLastSet      = $builtinAdmin.PasswordLastSet
                PasswordAgeDays      = $pwAge
                LastLogonDate        = $builtinAdmin.LastLogonDate
                AccountNotDelegated  = $builtinAdmin.AccountNotDelegated
                AdminCount           = $builtinAdmin.AdminCount
                Groups               = "Built-in Administrator"
                IsBuiltIn            = $true
            }
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Could not query built-in Administrator: $_"
    }

    if ($adminAccounts.Count -eq 0) {
        Write-Host "No admin accounts found." -ForegroundColor Yellow
        return
    }

    # Display summary table
    Write-Host ""
    Write-Host ("{0,-5} {1,-22} {2,-9} {3,-10} {4,-14} {5,-12} {6,-20}" -f "#", "Account", "Enabled", "PW Age", "Delegation", "Last Logon", "Groups") -ForegroundColor Cyan
    Write-Host ("-" * 92) -ForegroundColor Gray

    for ($i = 0; $i -lt $adminAccounts.Count; $i++) {
        $acct = $adminAccounts[$i]
        $enabledStr = if ($acct.Enabled) { "Yes" } else { "No" }
        $pwAgeStr = "$($acct.PasswordAgeDays)d"
        $delegStr = if ($acct.AccountNotDelegated) { "Protected" } else { "VULNERABLE" }
        $lastLogon = if ($acct.LastLogonDate) { $acct.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
        $groupsStr = $acct.Groups
        if ($groupsStr.Length -gt 18) { $groupsStr = $groupsStr.Substring(0, 18) }

        $color = "White"
        if (-not $acct.AccountNotDelegated) { $color = "Yellow" }
        if ($acct.PasswordAgeDays -gt $passwordAgeDays) { $color = "Yellow" }
        if ($acct.IsBuiltIn -and $acct.Enabled) { $color = "Yellow" }

        Write-Host ("{0,-5} {1,-22} {2,-9} {3,-10} {4,-14} {5,-12} {6,-20}" -f ($i + 1), $acct.SamAccountName, $enabledStr, $pwAgeStr, $delegStr, $lastLogon, $groupsStr) -ForegroundColor $color
    }

    # Log findings
    $vulnerableDelegation = $adminAccounts | Where-Object { -not $_.AccountNotDelegated }
    $oldPasswords = $adminAccounts | Where-Object { $_.PasswordAgeDays -gt $passwordAgeDays }
    $inactiveAccounts = $adminAccounts | Where-Object { $_.LastLogonDate -and ((Get-Date) - $_.LastLogonDate).TotalDays -gt 90 }
    $builtinEnabled = $adminAccounts | Where-Object { $_.IsBuiltIn -and $_.Enabled }

    if ($vulnerableDelegation.Count -gt 0) {
        Write-Log -Level FINDING -Message "$($vulnerableDelegation.Count) admin account(s) without 'Account is sensitive' delegation protection"
    }
    if ($oldPasswords.Count -gt 0) {
        Write-Log -Level FINDING -Message "$($oldPasswords.Count) admin account(s) with passwords older than $passwordAgeDays days"
    }
    if ($builtinEnabled.Count -gt 0) {
        Write-Log -Level FINDING -Message "Built-in Administrator account is enabled"
    }

    # Remediation options
    Write-Host ""
    Write-Host "Remediation options:" -ForegroundColor Cyan
    Write-Host ""

    # 1: Set delegation flag
    if ($vulnerableDelegation.Count -gt 0) {
        $setDeleg = Read-YesNo -Prompt "Set 'Account is sensitive and cannot be delegated' on vulnerable accounts?" -Default $true
        if ($setDeleg) {
            foreach ($acct in $vulnerableDelegation) {
                $description = "Set AccountNotDelegated flag on '$($acct.SamAccountName)'"
                Invoke-WithDryRun -Description $description -Action {
                    Set-ADUser -Identity $acct.SamAccountName -AccountNotDelegated $true @adParams -ErrorAction Stop
                    Write-Log -Level ACTION -Message "Set AccountNotDelegated on $($acct.SamAccountName)"
                } | Out-Null
            }
        }
    }

    # 2: Force password reset
    if ($oldPasswords.Count -gt 0) {
        Write-Host ""
        $resetPw = Read-YesNo -Prompt "Force password change at next logon for accounts with old passwords?" -Default $false
        if ($resetPw) {
            foreach ($acct in $oldPasswords) {
                $description = "Force password change at next logon for '$($acct.SamAccountName)'"
                Invoke-WithDryRun -Description $description -Action {
                    Set-ADUser -Identity $acct.SamAccountName -ChangePasswordAtLogon $true @adParams -ErrorAction Stop
                    Write-Log -Level ACTION -Message "Forced password change for $($acct.SamAccountName)"
                } | Out-Null
            }
        }
    }

    # 3: Remove inactive admin accounts from groups
    if ($inactiveAccounts.Count -gt 0) {
        Write-Host ""
        Write-Host "Inactive accounts (no logon in 90+ days):" -ForegroundColor Yellow
        foreach ($acct in $inactiveAccounts) {
            $lastStr = if ($acct.LastLogonDate) { $acct.LastLogonDate.ToString("yyyy-MM-dd") } else { "Never" }
            Write-Host "  - $($acct.SamAccountName) (last logon: $lastStr)" -ForegroundColor Yellow
        }
        $removeInactive = Read-YesNo -Prompt "Remove inactive accounts from admin groups?" -Default $false
        if ($removeInactive) {
            foreach ($acct in $inactiveAccounts) {
                foreach ($groupName in $groups) {
                    try {
                        $gMembers = Get-ADGroupMember -Identity $groupName @adParams -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName
                        if ($acct.SamAccountName -in $gMembers) {
                            $description = "Remove '$($acct.SamAccountName)' from '$groupName'"
                            Invoke-WithDryRun -Description $description -Action {
                                Remove-ADGroupMember -Identity $groupName -Members $acct.SamAccountName -Confirm:$false @adParams -ErrorAction Stop
                                Write-Log -Level ACTION -Message "Removed $($acct.SamAccountName) from $groupName"
                            } | Out-Null
                        }
                    }
                    catch { }
                }
            }
        }
    }

    # 4: Disable built-in Administrator
    if ($builtinEnabled.Count -gt 0) {
        Write-Host ""
        $disableBuiltin = Read-YesNo -Prompt "Disable the built-in Administrator account?" -Default $false
        if ($disableBuiltin) {
            foreach ($acct in $builtinEnabled) {
                $description = "Disable built-in Administrator account '$($acct.SamAccountName)'"
                Invoke-WithDryRun -Description $description -Action {
                    Disable-ADAccount -Identity $acct.SamAccountName @adParams -ErrorAction Stop
                    Write-Log -Level ACTION -Message "Disabled built-in Administrator $($acct.SamAccountName)"
                } | Out-Null
            }
        }
    }

    $Script:CompletedFeatures["5"] = $true
    Write-Host ""
    Write-Host "Press Enter to return to the menu..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

# ══════════════════════════════════════════════════════════════════════
#  FEATURE 6: Enable Advanced Auditing
# ══════════════════════════════════════════════════════════════════════

function Invoke-AdvancedAuditing {
    Write-Host ""
    Write-Host "===== Feature 6: Enable Advanced Auditing =====" -ForegroundColor Cyan
    Write-Host ""

    # Show current audit policy
    Write-Log -Level CHECK -Message "Retrieving current audit policy..."
    try {
        $currentAudit = auditpol /get /category:* 2>&1
    }
    catch {
        Write-Log -Level ERROR -Message "Could not retrieve audit policy: $_"
        return
    }

    # Define recommended audit settings
    $recommendedAudit = @(
        @{ Subcategory = "Credential Validation";                Setting = "Success and Failure" }
        @{ Subcategory = "Kerberos Authentication Service";      Setting = "Success and Failure" }
        @{ Subcategory = "Kerberos Service Ticket Operations";   Setting = "Success and Failure" }
        @{ Subcategory = "Other Account Logon Events";           Setting = "Success and Failure" }
        @{ Subcategory = "Application Group Management";         Setting = "Success and Failure" }
        @{ Subcategory = "Computer Account Management";          Setting = "Success and Failure" }
        @{ Subcategory = "Distribution Group Management";        Setting = "Success" }
        @{ Subcategory = "Other Account Management Events";      Setting = "Success" }
        @{ Subcategory = "Security Group Management";            Setting = "Success and Failure" }
        @{ Subcategory = "User Account Management";              Setting = "Success and Failure" }
        @{ Subcategory = "DPAPI Activity";                       Setting = "Success and Failure" }
        @{ Subcategory = "Process Creation";                     Setting = "Success" }
        @{ Subcategory = "Process Termination";                  Setting = "Success" }
        @{ Subcategory = "Logon";                                Setting = "Success and Failure" }
        @{ Subcategory = "Logoff";                               Setting = "Success" }
        @{ Subcategory = "Account Lockout";                      Setting = "Success and Failure" }
        @{ Subcategory = "Special Logon";                        Setting = "Success" }
        @{ Subcategory = "Other Logon/Logoff Events";            Setting = "Success and Failure" }
        @{ Subcategory = "Audit Policy Change";                  Setting = "Success and Failure" }
        @{ Subcategory = "Authentication Policy Change";         Setting = "Success" }
        @{ Subcategory = "Authorization Policy Change";          Setting = "Success" }
        @{ Subcategory = "Sensitive Privilege Use";              Setting = "Success and Failure" }
        @{ Subcategory = "Directory Service Access";             Setting = "Success and Failure" }
        @{ Subcategory = "Directory Service Changes";            Setting = "Success and Failure" }
        @{ Subcategory = "Security System Extension";            Setting = "Success and Failure" }
        @{ Subcategory = "System Integrity";                     Setting = "Success and Failure" }
        @{ Subcategory = "Security State Change";                Setting = "Success" }
    )

    # Parse current settings and show comparison
    Write-Host ""
    Write-Host ("{0,-45} {1,-25} {2,-25}" -f "Subcategory", "Current", "Proposed") -ForegroundColor Cyan
    Write-Host ("-" * 95) -ForegroundColor Gray

    $changesToMake = @()
    foreach ($rec in $recommendedAudit) {
        # Find current value from auditpol output
        $currentValue = "Unknown"
        $matchLine = $currentAudit | Where-Object { $_ -match [regex]::Escape($rec.Subcategory) } | Select-Object -First 1
        if ($matchLine) {
            if ($matchLine -match 'Success and Failure') { $currentValue = "Success and Failure" }
            elseif ($matchLine -match 'Success') { $currentValue = "Success" }
            elseif ($matchLine -match 'Failure') { $currentValue = "Failure" }
            elseif ($matchLine -match 'No Auditing') { $currentValue = "No Auditing" }
        }

        $color = if ($currentValue -eq $rec.Setting) { "Green" } else { "Yellow" }
        Write-Host ("{0,-45} {1,-25} {2,-25}" -f $rec.Subcategory, $currentValue, $rec.Setting) -ForegroundColor $color

        if ($currentValue -ne $rec.Setting) {
            $changesToMake += $rec
        }
    }

    if ($changesToMake.Count -eq 0) {
        Write-Host ""
        Write-Host "All recommended audit policies are already configured." -ForegroundColor Green
        Write-Log -Level FINDING -Message "All recommended audit policies already configured."
    }
    else {
        Write-Host ""
        Write-Host "$($changesToMake.Count) audit subcategories need updating." -ForegroundColor Yellow

        $description = "Apply $($changesToMake.Count) audit policy changes"
        Invoke-WithDryRun -Description $description -Action {
            foreach ($change in $changesToMake) {
                $subcategory = $change.Subcategory
                $setting = $change.Setting

                $auditArgs = "/set /subcategory:`"$subcategory`""
                switch ($setting) {
                    "Success and Failure" { $auditArgs += " /success:enable /failure:enable" }
                    "Success"             { $auditArgs += " /success:enable /failure:disable" }
                    "Failure"             { $auditArgs += " /success:disable /failure:enable" }
                }

                $result = cmd /c "auditpol $auditArgs" 2>&1
                if ($LASTEXITCODE -ne 0) {
                    Write-Log -Level WARNING -Message "Failed to set audit for '$subcategory': $result"
                }
                else {
                    Write-Log -Level ACTION -Message "Set audit policy: $subcategory = $setting"
                }
            }
        } | Out-Null
    }

    # Enable command line in process creation events
    Write-Host ""
    Write-Host "--- Command Line in Process Creation Events ---" -ForegroundColor Cyan
    try {
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
        $currentCmdLine = $null
        if (Test-Path $regPath) {
            $currentCmdLine = (Get-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
        }

        if ($currentCmdLine -eq 1) {
            Write-Host "  Command line logging in process creation events: Enabled" -ForegroundColor Green
        }
        else {
            Write-Host "  Command line logging in process creation events: Disabled" -ForegroundColor Yellow
            $description = "Enable command line in process creation audit events"
            Invoke-WithDryRun -Description $description -Action {
                if (-not (Test-Path $regPath)) {
                    New-Item -Path $regPath -Force | Out-Null
                }
                Set-ItemProperty -Path $regPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord
                Write-Log -Level ACTION -Message "Enabled command line in process creation events"
            } | Out-Null
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Could not check/set command line logging: $_"
    }

    # Increase event log sizes
    Write-Host ""
    Write-Host "--- Event Log Sizes ---" -ForegroundColor Cyan
    $logs = @(
        @{ Name = "Security";    RecommendedMB = 1024 }
        @{ Name = "System";      RecommendedMB = 256  }
        @{ Name = "Application"; RecommendedMB = 256  }
    )

    foreach ($log in $logs) {
        try {
            $eventLog = Get-WinEvent -ListLog $log.Name -ErrorAction Stop
            $currentMB = [math]::Round($eventLog.MaximumSizeInBytes / 1MB)
            $recommendedBytes = $log.RecommendedMB * 1MB

            if ($currentMB -lt $log.RecommendedMB) {
                Write-Host "  $($log.Name) log: ${currentMB}MB (recommended: $($log.RecommendedMB)MB)" -ForegroundColor Yellow
                $description = "Increase $($log.Name) event log to $($log.RecommendedMB)MB"
                Invoke-WithDryRun -Description $description -Action {
                    $el = Get-WinEvent -ListLog $log.Name
                    $el.MaximumSizeInBytes = $recommendedBytes
                    $el.SaveChanges()
                    Write-Log -Level ACTION -Message "Increased $($log.Name) log to $($log.RecommendedMB)MB"
                } | Out-Null
            }
            else {
                Write-Host "  $($log.Name) log: ${currentMB}MB (OK)" -ForegroundColor Green
            }
        }
        catch {
            Write-Log -Level WARNING -Message "Could not check $($log.Name) log: $_"
        }
    }

    $Script:CompletedFeatures["6"] = $true
    Write-Host ""
    Write-Host "Press Enter to return to the menu..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

# ══════════════════════════════════════════════════════════════════════
#  FEATURE 7: Detect Kerberoastable Accounts
# ══════════════════════════════════════════════════════════════════════

function Invoke-DetectKerberoast {
    Write-Host ""
    Write-Host "===== Feature 7: Detect Kerberoastable Accounts =====" -ForegroundColor Cyan
    Write-Host ""

    $adParams = Get-ADTargetParams
    $settings = Get-ADScannerSettings
    $passwordAgeDays = if ($settings.PasswordAgeDays) { $settings.PasswordAgeDays } else { 90 }

    Write-Log -Level CHECK -Message "Querying users with Service Principal Names (SPNs)..."

    try {
        $spnUsers = Get-ADUser -Filter { ServicePrincipalName -like "*" } -Properties `
            SamAccountName, ServicePrincipalName, Enabled, PasswordLastSet, `
            AdminCount, MemberOf, msDS-SupportedEncryptionTypes, Description `
            @adParams -ErrorAction Stop
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to query SPN users: $_"
        return
    }

    if ($spnUsers.Count -eq 0) {
        Write-Host "No user accounts with SPNs found." -ForegroundColor Green
        Write-Log -Level FINDING -Message "No Kerberoastable accounts found."
        $Script:CompletedFeatures["7"] = $true
        return
    }

    # Get privileged group members for reference
    $privilegedUsers = @()
    foreach ($group in @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")) {
        try {
            $members = Get-ADGroupMember -Identity $group @adParams -ErrorAction SilentlyContinue -Recursive
            foreach ($m in $members) {
                if ($m.SamAccountName -notin $privilegedUsers) {
                    $privilegedUsers += $m.SamAccountName
                }
            }
        }
        catch { }
    }

    # Analyze each account
    $results = @()
    foreach ($user in $spnUsers) {
        # Determine encryption type
        $encTypes = $user.'msDS-SupportedEncryptionTypes'
        $usesRC4 = $false
        $usesAES = $false
        if ($null -eq $encTypes -or $encTypes -eq 0) {
            $usesRC4 = $true  # Default is RC4 if not specified
        }
        else {
            if ($encTypes -band 0x4) { $usesRC4 = $true }
            if ($encTypes -band 0x8) { $usesAES = $true }   # AES128
            if ($encTypes -band 0x10) { $usesAES = $true }  # AES256
        }

        $encString = ""
        if ($usesRC4 -and $usesAES) { $encString = "RC4+AES" }
        elseif ($usesRC4) { $encString = "RC4" }
        elseif ($usesAES) { $encString = "AES" }
        else { $encString = "RC4 (default)" }

        # Password age
        $pwAge = if ($user.PasswordLastSet) {
            [math]::Round(((Get-Date) - $user.PasswordLastSet).TotalDays)
        }
        else { 9999 }

        # Privileged
        $isPrivileged = $user.SamAccountName -in $privilegedUsers

        # Risk assessment
        $riskScore = 0
        $riskReasons = @()

        if ($usesRC4 -and -not $usesAES) {
            $riskScore += 3
            $riskReasons += "RC4-only encryption"
        }
        if ($pwAge -gt 365) {
            $riskScore += 3
            $riskReasons += "Password older than 1 year ($pwAge days)"
        }
        elseif ($pwAge -gt $passwordAgeDays) {
            $riskScore += 2
            $riskReasons += "Password older than $passwordAgeDays days ($pwAge days)"
        }
        if ($isPrivileged) {
            $riskScore += 4
            $riskReasons += "Member of privileged group"
        }
        if ($user.AdminCount -eq 1) {
            $riskScore += 1
            $riskReasons += "AdminCount=1"
        }
        if ($user.Enabled) {
            $riskScore += 1
        }
        else {
            $riskScore -= 2
        }

        $risk = "LOW"
        if ($riskScore -ge 6) { $risk = "HIGH" }
        elseif ($riskScore -ge 3) { $risk = "MEDIUM" }

        $spns = $user.ServicePrincipalName -join '; '
        if ($spns.Length -gt 40) { $spns = $spns.Substring(0, 40) + "..." }

        $results += [PSCustomObject]@{
            SamAccountName = $user.SamAccountName
            Enabled        = $user.Enabled
            Encryption     = $encString
            PasswordAge    = $pwAge
            Privileged     = $isPrivileged
            AdminCount     = $user.AdminCount
            Risk           = $risk
            RiskScore      = $riskScore
            Reasons        = ($riskReasons -join '; ')
            SPNs           = $spns
        }
    }

    # Sort by risk score descending
    $results = $results | Sort-Object -Property RiskScore -Descending

    # Display table
    Write-Host ""
    Write-Host "Found $($results.Count) Kerberoastable account(s):" -ForegroundColor White
    Write-Host ""
    Write-Host ("{0,-5} {1,-22} {2,-8} {3,-12} {4,-8} {5,-10} {6,-8}" -f "#", "Account", "Enabled", "Encryption", "PW Age", "Privileged", "Risk") -ForegroundColor Cyan
    Write-Host ("-" * 73) -ForegroundColor Gray

    for ($i = 0; $i -lt $results.Count; $i++) {
        $r = $results[$i]
        $color = switch ($r.Risk) {
            "HIGH"   { "Red" }
            "MEDIUM" { "Yellow" }
            default  { "White" }
        }
        $enabledStr = if ($r.Enabled) { "Yes" } else { "No" }
        $privStr = if ($r.Privileged) { "YES" } else { "No" }
        $pwAgeStr = "$($r.PasswordAge)d"

        Write-Host ("{0,-5} {1,-22} {2,-8} {3,-12} {4,-8} {5,-10} {6,-8}" -f ($i + 1), $r.SamAccountName, $enabledStr, $r.Encryption, $pwAgeStr, $privStr, $r.Risk) -ForegroundColor $color
    }

    # Log findings
    $highRisk = $results | Where-Object { $_.Risk -eq "HIGH" }
    $mediumRisk = $results | Where-Object { $_.Risk -eq "MEDIUM" }
    Write-Log -Level FINDING -Message "Kerberoastable accounts: $($results.Count) total, $($highRisk.Count) HIGH risk, $($mediumRisk.Count) MEDIUM risk"

    # Show details for HIGH risk
    if ($highRisk.Count -gt 0) {
        Write-Host ""
        Write-Host "--- HIGH Risk Account Details ---" -ForegroundColor Red
        foreach ($hr in $highRisk) {
            Write-Host ""
            Write-Host "  Account: $($hr.SamAccountName)" -ForegroundColor Red
            Write-Host "  SPNs:    $($hr.SPNs)" -ForegroundColor White
            Write-Host "  Reasons: $($hr.Reasons)" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  Remediation steps:" -ForegroundColor Cyan
            if ($hr.Encryption -match 'RC4' -and $hr.Encryption -notmatch 'AES') {
                Write-Host "    1. Enable AES encryption: Set-ADUser $($hr.SamAccountName) -KerberosEncryptionType AES128,AES256" -ForegroundColor Gray
            }
            if ($hr.PasswordAge -gt $passwordAgeDays) {
                Write-Host "    2. Reset password (use a long, random password, 25+ characters)" -ForegroundColor Gray
            }
            if ($hr.Privileged) {
                Write-Host "    3. Consider removing this account from privileged groups" -ForegroundColor Gray
                Write-Host "       or using a Managed Service Account (gMSA) instead" -ForegroundColor Gray
            }
            Write-Host "    4. Consider converting to a Group Managed Service Account (gMSA)" -ForegroundColor Gray

            Write-Log -Level ALERT -Message "HIGH risk Kerberoastable account: $($hr.SamAccountName) - $($hr.Reasons)"
        }
    }

    $Script:CompletedFeatures["7"] = $true
    Write-Host ""
    Write-Host "Press Enter to return to the menu..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

# ══════════════════════════════════════════════════════════════════════
#  FEATURE 8: Secure DNS Zone Transfers
# ══════════════════════════════════════════════════════════════════════

function Invoke-SecureZoneTransfers {
    Write-Host ""
    Write-Host "===== Feature 8: Secure DNS Zone Transfers =====" -ForegroundColor Cyan
    Write-Host ""

    if (-not (Test-ModuleAvailable -ModuleName "DnsServer")) {
        Write-Host "This feature requires the DnsServer module, which is not installed." -ForegroundColor Red
        return
    }

    $servers = Get-DNSServerList
    if ($servers.Count -eq 0) {
        Write-Host "No DNS servers found." -ForegroundColor Yellow
        return
    }
    $selectedServers = Select-DNSServers -AvailableServers $servers

    $allZoneResults = @()

    foreach ($server in $selectedServers) {
        Write-Host ""
        Write-Host "=== Zone Transfers on $server ===" -ForegroundColor Cyan

        try {
            $zones = Get-DnsServerZone -ComputerName $server -ErrorAction Stop |
                Where-Object { $_.ZoneType -ne 'Forwarder' -and $_.ZoneName -ne 'TrustAnchors' }
        }
        catch {
            Write-Log -Level ERROR -Message "Could not query DNS zones on ${server}: $_"
            continue
        }

        if ($zones.Count -eq 0) {
            Write-Host "  No zones found." -ForegroundColor Yellow
            continue
        }

        Write-Host ""
        Write-Host ("{0,-5} {1,-35} {2,-18} {3,-15} {4,-10}" -f "#", "Zone Name", "Zone Type", "Transfer Setting", "Risk") -ForegroundColor Cyan
        Write-Host ("-" * 83) -ForegroundColor Gray

        $zoneIndex = 0
        foreach ($zone in $zones) {
            $zoneIndex++

            # Determine zone transfer setting
            $transferSetting = "Unknown"
            $risk = "LOW"

            try {
                $zoneTransfer = Get-DnsServerZone -Name $zone.ZoneName -ComputerName $server -ErrorAction Stop

                switch ($zoneTransfer.SecureSecondaries) {
                    'NoTransfer'           { $transferSetting = "Disabled"; $risk = "LOW" }
                    'TransferAnyServer'    { $transferSetting = "To Any Server"; $risk = "HIGH" }
                    'TransferToZoneNameServer' { $transferSetting = "NS Records Only"; $risk = "LOW" }
                    'TransferToSecureServers'  { $transferSetting = "Specified Only"; $risk = "LOW" }
                    default {
                        # Check the integer value
                        $secVal = [int]$zoneTransfer.SecureSecondaries
                        switch ($secVal) {
                            0 { $transferSetting = "To Any Server"; $risk = "HIGH" }
                            1 { $transferSetting = "NS Records Only"; $risk = "LOW" }
                            2 { $transferSetting = "Specified Only"; $risk = "LOW" }
                            3 { $transferSetting = "Disabled"; $risk = "LOW" }
                            default { $transferSetting = "Unknown ($secVal)"; $risk = "MEDIUM" }
                        }
                    }
                }
            }
            catch {
                $transferSetting = "Error"
                $risk = "MEDIUM"
            }

            $color = switch ($risk) {
                "HIGH"   { "Red" }
                "MEDIUM" { "Yellow" }
                default  { "White" }
            }

            $zoneName = $zone.ZoneName
            if ($zoneName.Length -gt 33) { $zoneName = $zoneName.Substring(0, 33) }

            Write-Host ("{0,-5} {1,-35} {2,-18} {3,-15} {4,-10}" -f $zoneIndex, $zoneName, $zone.ZoneType, $transferSetting, $risk) -ForegroundColor $color

            $allZoneResults += [PSCustomObject]@{
                Server          = $server
                ZoneName        = $zone.ZoneName
                ZoneType        = $zone.ZoneType
                TransferSetting = $transferSetting
                Risk            = $risk
            }
        }

        # Offer remediation for risky zones
        $riskyZones = $allZoneResults | Where-Object { $_.Server -eq $server -and ($_.Risk -eq 'HIGH' -or $_.Risk -eq 'MEDIUM') }

        if ($riskyZones.Count -gt 0) {
            Write-Host ""
            Write-Log -Level FINDING -Message "$($riskyZones.Count) zone(s) on $server have open or risky transfer settings"

            foreach ($rz in $riskyZones) {
                Write-Host ""
                Write-Host "Zone '$($rz.ZoneName)' allows: $($rz.TransferSetting)" -ForegroundColor Yellow
                $action = Read-UserChoice -Prompt "  Action: (R)estrict to NS records, (D)isable transfers, (S)kip" -ValidChoices @('R','r','D','d','S','s') -Default 'S'

                switch ($action.ToUpper()) {
                    'R' {
                        $description = "Restrict zone transfers for '$($rz.ZoneName)' on $server to NS record servers only"
                        Invoke-WithDryRun -Description $description -Action {
                            Set-DnsServerZoneTransferPolicy -Name $rz.ZoneName -ComputerName $server -SecureSecondaries TransferToZoneNameServer -ErrorAction SilentlyContinue
                            # Fallback: use Set-DnsServerPrimaryZone if available
                            try {
                                Set-DnsServerPrimaryZone -Name $rz.ZoneName -ComputerName $server -SecureSecondaries 1 -ErrorAction Stop
                            }
                            catch {
                                # Try the zone setting directly
                                dnscmd $server /ZoneResetSecondaries $rz.ZoneName /SecureNs 2>&1 | Out-Null
                            }
                            Write-Log -Level ACTION -Message "Restricted zone transfers for $($rz.ZoneName) on $server"
                        } | Out-Null
                    }
                    'D' {
                        $description = "Disable zone transfers for '$($rz.ZoneName)' on $server"
                        Invoke-WithDryRun -Description $description -Action {
                            try {
                                Set-DnsServerPrimaryZone -Name $rz.ZoneName -ComputerName $server -SecureSecondaries 3 -ErrorAction Stop
                            }
                            catch {
                                dnscmd $server /ZoneResetSecondaries $rz.ZoneName /NoXfr 2>&1 | Out-Null
                            }
                            Write-Log -Level ACTION -Message "Disabled zone transfers for $($rz.ZoneName) on $server"
                        } | Out-Null
                    }
                }
            }
        }
        else {
            Write-Host ""
            Write-Host "  All zones on $server have secure transfer settings." -ForegroundColor Green
        }
    }

    $Script:CompletedFeatures["8"] = $true
    Write-Host ""
    Write-Host "Press Enter to return to the menu..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

# ══════════════════════════════════════════════════════════════════════
#  FEATURE 9: Check Suspicious Scheduled Tasks
# ══════════════════════════════════════════════════════════════════════

function Invoke-CheckScheduledTasks {
    Write-Host ""
    Write-Host "===== Feature 9: Check Suspicious Scheduled Tasks =====" -ForegroundColor Cyan
    Write-Host ""

    $settings = Get-ADScannerSettings
    $suspiciousDays = if ($settings.SuspiciousTaskDays) { $settings.SuspiciousTaskDays } else { 7 }

    # Choose scope
    Write-Host "Select scope:" -ForegroundColor Cyan
    Write-Host "  1. DNS servers only" -ForegroundColor White
    Write-Host "  2. Specific computer(s)" -ForegroundColor White
    Write-Host "  3. All domain computers" -ForegroundColor White
    Write-Host ""

    $scopeChoice = Read-UserChoice -Prompt "Select scope" -ValidChoices @('1','2','3') -Default '1'
    $targetComputers = @()

    switch ($scopeChoice) {
        '1' {
            $servers = Get-DNSServerList
            if ($servers.Count -eq 0) {
                Write-Host "No DNS servers found." -ForegroundColor Yellow
                return
            }
            $targetComputers = Select-DNSServers -AvailableServers $servers
        }
        '2' {
            Write-Host "Enter computer name(s) (comma-separated):" -ForegroundColor Yellow
            $inputNames = Read-Host
            if ([string]::IsNullOrWhiteSpace($inputNames)) {
                Write-Host "No computers specified." -ForegroundColor Yellow
                return
            }
            $targetComputers = $inputNames -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
        }
        '3' {
            $adParams = Get-ADTargetParams
            try {
                $computers = Get-ADComputer -Filter { Enabled -eq $true } @adParams -ErrorAction Stop
                $targetComputers = $computers | Select-Object -ExpandProperty Name
                Write-Host "Found $($targetComputers.Count) computers." -ForegroundColor White
            }
            catch {
                Write-Log -Level ERROR -Message "Could not query domain computers: $_"
                return
            }
        }
    }

    if ($targetComputers.Count -eq 0) {
        Write-Host "No target computers." -ForegroundColor Yellow
        return
    }

    # Suspicious indicators
    $suspiciousPaths = @(
        'C:\Users\Public',
        'C:\ProgramData',
        'C:\Windows\Temp',
        'C:\Temp',
        '%TEMP%',
        '%APPDATA%',
        '%PUBLIC%'
    )

    $suspiciousPatterns = @(
        'powershell.*-enc',
        'powershell.*-e ',
        'powershell.*encodedcommand',
        'cmd.*/c.*powershell',
        'cmd.*/c.*bitsadmin',
        'cmd.*/c.*certutil',
        'mshta',
        'wscript.*http',
        'cscript.*http',
        'regsvr32.*/s.*/u',
        'rundll32.*javascript',
        'schtasks.*/create'
    )

    $legitimateTaskPaths = @(
        '\Microsoft\',
        '\Adobe\',
        '\Google\',
        '\Mozilla\',
        '\Windows Defender\'
    )

    $allSuspiciousTasks = @{}

    foreach ($computer in $targetComputers) {
        Write-Host ""
        Write-Log -Level CHECK -Message "Scanning scheduled tasks on $computer..."

        if (-not (Test-RemoteConnectivity -ComputerName $computer)) {
            Write-Log -Level WARNING -Message "Skipping $computer - unreachable."
            continue
        }

        try {
            $tasks = Invoke-RemoteCommand -ComputerName $computer -ScriptBlock {
                param($days)
                $results = @()
                $now = Get-Date
                $schtasks = Get-ScheduledTask -ErrorAction SilentlyContinue

                foreach ($task in $schtasks) {
                    try {
                        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
                        $actions = $task.Actions | ForEach-Object {
                            $execute = $_.Execute
                            $args = $_.Arguments
                            if ($args) { "$execute $args" } else { $execute }
                        }
                        $actionStr = $actions -join '; '

                        $principal = $task.Principal.UserId
                        $runLevel = $task.Principal.RunLevel

                        $createdDate = $null
                        if ($task.Date) {
                            try { $createdDate = [datetime]$task.Date } catch { }
                        }

                        $results += [PSCustomObject]@{
                            TaskName    = $task.TaskName
                            TaskPath    = $task.TaskPath
                            State       = $task.State.ToString()
                            RunAs       = $principal
                            RunLevel    = $runLevel.ToString()
                            Actions     = $actionStr
                            CreatedDate = $createdDate
                            DaysOld     = if ($createdDate) { [math]::Round(($now - $createdDate).TotalDays) } else { -1 }
                        }
                    }
                    catch { }
                }
                return $results
            } -ArgumentList @{ days = $suspiciousDays }
        }
        catch {
            Write-Log -Level ERROR -Message "Failed to retrieve tasks from ${computer}: $_"
            continue
        }

        if (-not $tasks -or $tasks.Count -eq 0) {
            Write-Host "  No tasks returned from $computer." -ForegroundColor Gray
            continue
        }

        # Analyze each task for suspicion
        $suspicious = @()
        foreach ($task in $tasks) {
            $flags = @()

            # Check: runs as SYSTEM
            if ($task.RunAs -match 'SYSTEM|LocalSystem') {
                $flags += "Runs as SYSTEM"
            }

            # Check: encoded commands
            if ($task.Actions -match '(?i)-enc|-e |encodedcommand') {
                $flags += "Encoded command"
            }

            # Check: suspicious paths
            foreach ($sp in $suspiciousPaths) {
                if ($task.Actions -match [regex]::Escape($sp)) {
                    $flags += "Suspicious path: $sp"
                    break
                }
            }

            # Check: suspicious patterns
            foreach ($pattern in $suspiciousPatterns) {
                if ($task.Actions -match "(?i)$pattern") {
                    $flags += "Suspicious pattern"
                    break
                }
            }

            # Check: recently created
            if ($task.DaysOld -ge 0 -and $task.DaysOld -le $suspiciousDays) {
                $flags += "Created within last $suspiciousDays days"
            }

            # Check: disguised name (legitimate path but unusual content)
            $isInLegitPath = $false
            foreach ($lp in $legitimateTaskPaths) {
                if ($task.TaskPath -like "*$lp*") {
                    $isInLegitPath = $true
                    break
                }
            }

            # Tasks NOT in legitimate paths that run as SYSTEM are more suspicious
            if (-not $isInLegitPath -and ($task.RunAs -match 'SYSTEM|LocalSystem')) {
                $flags += "Non-standard path with SYSTEM"
            }

            # Check: high run level with no standard path
            if ($task.RunLevel -match 'Highest' -and -not $isInLegitPath) {
                $flags += "Highest privilege, non-standard path"
            }

            if ($flags.Count -gt 0) {
                $task | Add-Member -NotePropertyName 'Flags' -NotePropertyValue ($flags -join '; ') -Force
                $suspicious += $task
            }
        }

        Write-Host "  Total tasks: $($tasks.Count), Suspicious: $($suspicious.Count)" -ForegroundColor White

        if ($suspicious.Count -gt 0) {
            $allSuspiciousTasks[$computer] = $suspicious
        }
    }

    # Display results grouped by machine
    if ($allSuspiciousTasks.Count -eq 0) {
        Write-Host ""
        Write-Host "No suspicious scheduled tasks found on any machine." -ForegroundColor Green
        Write-Log -Level FINDING -Message "No suspicious scheduled tasks found."
        $Script:CompletedFeatures["9"] = $true
        Write-Host ""
        Write-Host "Press Enter to return to the menu..." -ForegroundColor Yellow
        Read-Host | Out-Null
        return
    }

    $totalSuspicious = 0
    foreach ($key in $allSuspiciousTasks.Keys) {
        $totalSuspicious += $allSuspiciousTasks[$key].Count
    }
    Write-Log -Level FINDING -Message "$totalSuspicious suspicious scheduled task(s) found across $($allSuspiciousTasks.Count) machine(s)"

    foreach ($computer in $allSuspiciousTasks.Keys) {
        $tasks = $allSuspiciousTasks[$computer]
        Write-Host ""
        Write-Host "=== Suspicious Tasks on $computer ($($tasks.Count)) ===" -ForegroundColor Red
        Write-Host ""

        for ($i = 0; $i -lt $tasks.Count; $i++) {
            $task = $tasks[$i]
            $createdStr = if ($task.CreatedDate) { $task.CreatedDate.ToString("yyyy-MM-dd") } else { "Unknown" }
            Write-Host "  $($i + 1). $($task.TaskPath)$($task.TaskName)" -ForegroundColor Yellow
            Write-Host "     State:   $($task.State)" -ForegroundColor White
            Write-Host "     RunAs:   $($task.RunAs)" -ForegroundColor White
            Write-Host "     Created: $createdStr" -ForegroundColor White
            $actionDisplay = $task.Actions
            if ($actionDisplay.Length -gt 80) { $actionDisplay = $actionDisplay.Substring(0, 80) + "..." }
            Write-Host "     Action:  $actionDisplay" -ForegroundColor White
            Write-Host "     Flags:   $($task.Flags)" -ForegroundColor Red
            Write-Host ""
        }

        # Offer to disable
        $disableTasks = Read-YesNo -Prompt "Disable suspicious tasks on $computer?" -Default $false
        if ($disableTasks) {
            Write-Host "Enter task numbers to disable (comma-separated), or 'A' for all:" -ForegroundColor Yellow
            $disableInput = Read-Host

            $tasksToDisable = @()
            if ($disableInput -eq 'A' -or $disableInput -eq 'a') {
                $tasksToDisable = $tasks
            }
            else {
                $nums = $disableInput -split ',' | ForEach-Object { $_.Trim() }
                foreach ($num in $nums) {
                    $idx = 0
                    if ([int]::TryParse($num, [ref]$idx) -and $idx -ge 1 -and $idx -le $tasks.Count) {
                        $tasksToDisable += $tasks[$idx - 1]
                    }
                }
            }

            foreach ($task in $tasksToDisable) {
                $description = "Disable scheduled task '$($task.TaskPath)$($task.TaskName)' on $computer"
                Invoke-WithDryRun -Description $description -Action {
                    Invoke-RemoteCommand -ComputerName $computer -ScriptBlock {
                        param($taskName, $taskPath)
                        Disable-ScheduledTask -TaskName $taskName -TaskPath $taskPath -ErrorAction Stop
                    } -ArgumentList @{ taskName = $task.TaskName; taskPath = $task.TaskPath }
                    Write-Log -Level ACTION -Message "Disabled task $($task.TaskPath)$($task.TaskName) on $computer"
                } | Out-Null
            }
        }
    }

    $Script:CompletedFeatures["9"] = $true
    Write-Host ""
    Write-Host "Press Enter to return to the menu..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

# ══════════════════════════════════════════════════════════════════════
#  FEATURE 10: AD MISCONFIGURATION CHECK
# ══════════════════════════════════════════════════════════════════════

function Invoke-CheckADMisconfigurations {
    Write-Host ""
    Write-Host "===== Check AD Misconfigurations (Permissions) =====" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "This scan checks for common Active Directory misconfigurations that" -ForegroundColor Gray
    Write-Host "attackers and tools like BloodHound exploit. It focuses on dangerous" -ForegroundColor Gray
    Write-Host "permissions, weak configurations, and attack paths." -ForegroundColor Gray
    Write-Host ""

    $adParams = Get-ADTargetParams
    $findingCount = 0

    # ── Check 1: AS-REP Roastable accounts ──────────────────────────
    Write-Log -Level CHECK -Message "Checking for AS-REP Roastable accounts (Kerberos pre-auth disabled)..."
    try {
        $asrepUsers = Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true -and Enabled -eq $true } @adParams `
            -Properties DoesNotRequirePreAuth, MemberOf, PasswordLastSet -ErrorAction Stop

        if ($asrepUsers) {
            $asrepUsers = @($asrepUsers)
            foreach ($user in $asrepUsers) {
                $findingCount++
                $pwdAge = if ($null -ne $user.PasswordLastSet) { ((Get-Date) - $user.PasswordLastSet).Days } else { "Unknown" }
                Write-Log -Level FINDING -Message "AS-REP Roastable: $($user.SamAccountName) (password age: $pwdAge days)"
            }

            Write-Host ""
            Write-Host "  Found $($asrepUsers.Count) account(s) with Kerberos pre-authentication disabled." -ForegroundColor Red
            Write-Host "  AS-REP Roasting lets attackers request encrypted data for these accounts" -ForegroundColor Yellow
            Write-Host "  and crack their passwords offline - no credentials needed to start." -ForegroundColor Yellow
            Write-Host ""

            $fix = Read-YesNo -Prompt "  Enable Kerberos pre-authentication on all $($asrepUsers.Count) account(s)?" -Default $true
            if ($fix) {
                foreach ($user in $asrepUsers) {
                    $applied = Invoke-WithDryRun -Description "Enable Kerberos pre-auth on '$($user.SamAccountName)'" -Action {
                        Set-ADAccountControl -Identity $user.SamAccountName @adParams -DoesNotRequirePreAuth $false -ErrorAction Stop
                    }
                }
            }
        }
        else {
            Write-Host "  [OK] No AS-REP Roastable accounts found." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level ERROR -Message "AS-REP Roastable check failed: $_"
    }

    # ── Check 2: Unconstrained Delegation ────────────────────────────
    Write-Log -Level CHECK -Message "Checking for Unconstrained Delegation..."
    try {
        # Computers with unconstrained delegation (excluding DCs, which need it)
        $dcs = @(Get-ADDomainController -Filter * @adParams -ErrorAction Stop | Select-Object -ExpandProperty Name)

        $unconstrainedComputers = Get-ADComputer -Filter { TrustedForDelegation -eq $true -and Enabled -eq $true } @adParams `
            -Properties TrustedForDelegation -ErrorAction Stop |
            Where-Object { $_.Name -notin $dcs }

        $unconstrainedUsers = Get-ADUser -Filter { TrustedForDelegation -eq $true -and Enabled -eq $true } @adParams `
            -Properties TrustedForDelegation -ErrorAction Stop

        $unconstrainedAll = @()
        if ($unconstrainedComputers) { $unconstrainedAll += @($unconstrainedComputers) }
        if ($unconstrainedUsers) { $unconstrainedAll += @($unconstrainedUsers) }

        if ($unconstrainedAll.Count -gt 0) {
            foreach ($obj in $unconstrainedAll) {
                $findingCount++
                $objType = if ($obj.objectClass -eq 'computer') { "Computer" } else { "User" }
                Write-Log -Level FINDING -Message "Unconstrained Delegation: $objType '$($obj.SamAccountName)'"
            }

            Write-Host ""
            Write-Host "  Found $($unconstrainedAll.Count) non-DC object(s) with unconstrained delegation." -ForegroundColor Red
            Write-Host "  Unconstrained delegation means any user who authenticates to this machine" -ForegroundColor Yellow
            Write-Host "  will leave a copy of their Kerberos ticket behind. An attacker who" -ForegroundColor Yellow
            Write-Host "  compromises this machine can steal those tickets and impersonate any user," -ForegroundColor Yellow
            Write-Host "  including Domain Admins." -ForegroundColor Yellow
            Write-Host ""

            foreach ($obj in $unconstrainedAll) {
                $objType = if ($obj.objectClass -eq 'computer') { "Computer" } else { "User" }
                $fix = Read-YesNo -Prompt "  Disable unconstrained delegation on $objType '$($obj.SamAccountName)'?" -Default $true
                if ($fix) {
                    Invoke-WithDryRun -Description "Disable unconstrained delegation on '$($obj.SamAccountName)'" -Action {
                        Set-ADAccountControl -Identity $obj.SamAccountName @adParams -TrustedForDelegation $false -ErrorAction Stop
                    } | Out-Null
                }
            }
        }
        else {
            Write-Host "  [OK] No non-DC objects with unconstrained delegation found." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Unconstrained delegation check failed: $_"
    }

    # ── Check 3: Accounts with Reversible Encryption ─────────────────
    Write-Log -Level CHECK -Message "Checking for accounts with reversible encryption..."
    try {
        $reversibleUsers = Get-ADUser -Filter { AllowReversiblePasswordEncryption -eq $true -and Enabled -eq $true } @adParams `
            -Properties AllowReversiblePasswordEncryption -ErrorAction Stop

        if ($reversibleUsers) {
            $reversibleUsers = @($reversibleUsers)
            foreach ($user in $reversibleUsers) {
                $findingCount++
                Write-Log -Level FINDING -Message "Reversible encryption enabled: $($user.SamAccountName)"
            }

            Write-Host ""
            Write-Host "  Found $($reversibleUsers.Count) account(s) with reversible encryption enabled." -ForegroundColor Red
            Write-Host "  This stores passwords in a way that can be decrypted back to plaintext." -ForegroundColor Yellow
            Write-Host "  It's almost the same as storing passwords in clear text and should" -ForegroundColor Yellow
            Write-Host "  never be needed in modern environments." -ForegroundColor Yellow
            Write-Host ""

            $fix = Read-YesNo -Prompt "  Disable reversible encryption on all $($reversibleUsers.Count) account(s)?" -Default $true
            if ($fix) {
                foreach ($user in $reversibleUsers) {
                    Invoke-WithDryRun -Description "Disable reversible encryption on '$($user.SamAccountName)'" -Action {
                        Set-ADUser -Identity $user.SamAccountName @adParams -AllowReversiblePasswordEncryption $false -ErrorAction Stop
                    } | Out-Null
                }
            }
        }
        else {
            Write-Host "  [OK] No accounts with reversible encryption found." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Reversible encryption check failed: $_"
    }

    # ── Check 4: Passwords stored in AD description field ────────────
    Write-Log -Level CHECK -Message "Checking for passwords in user description fields..."
    try {
        $suspiciousUsers = Get-ADUser -Filter { Enabled -eq $true } @adParams `
            -Properties Description -ErrorAction Stop |
            Where-Object {
                $_.Description -match '(?i)(pass(word|wd)?|pwd|p@ss|cred(ential)?)\s*[:=]' -or
                $_.Description -match '(?i)(pass(word|wd)?|pwd|p@ss)\s+is\s+' -or
                $_.Description -match '(?i)temp(orary)?\s*(pass|pwd)'
            }

        if ($suspiciousUsers) {
            $suspiciousUsers = @($suspiciousUsers)
            foreach ($user in $suspiciousUsers) {
                $findingCount++
                Write-Log -Level FINDING -Message "Possible password in description: $($user.SamAccountName) - '$($user.Description)'"
            }

            Write-Host ""
            Write-Host "  Found $($suspiciousUsers.Count) account(s) with possible passwords in the Description field." -ForegroundColor Red
            Write-Host "  The Description field is readable by ALL authenticated domain users." -ForegroundColor Yellow
            Write-Host "  Any password stored here is effectively public within the domain." -ForegroundColor Yellow
            Write-Host ""

            foreach ($user in $suspiciousUsers) {
                Write-Host "    $($user.SamAccountName): `"$($user.Description)`"" -ForegroundColor White
                $fix = Read-YesNo -Prompt "    Clear the description for '$($user.SamAccountName)'?" -Default $false
                if ($fix) {
                    Invoke-WithDryRun -Description "Clear description on '$($user.SamAccountName)'" -Action {
                        Set-ADUser -Identity $user.SamAccountName @adParams -Description $null -ErrorAction Stop
                    } | Out-Null
                }
            }
        }
        else {
            Write-Host "  [OK] No obvious passwords found in description fields." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Password in description check failed: $_"
    }

    # ── Check 5: Machine Account Quota ───────────────────────────────
    Write-Log -Level CHECK -Message "Checking Machine Account Quota (ms-DS-MachineAccountQuota)..."
    try {
        $domainDN = (Get-ADDomain @adParams -ErrorAction Stop).DistinguishedName
        $domainObj = Get-ADObject -Identity $domainDN @adParams -Properties 'ms-DS-MachineAccountQuota' -ErrorAction Stop
        $quota = $domainObj.'ms-DS-MachineAccountQuota'

        if ($null -eq $quota) { $quota = 10 }  # Default is 10

        if ($quota -gt 0) {
            $findingCount++
            Write-Log -Level FINDING -Message "Machine Account Quota is $quota (should be 0)"

            Write-Host ""
            Write-Host "  Machine Account Quota is set to $quota." -ForegroundColor Red
            Write-Host "  This means ANY authenticated user can join up to $quota computers to the domain." -ForegroundColor Yellow
            Write-Host "  Attackers abuse this to create machine accounts they control, which can" -ForegroundColor Yellow
            Write-Host "  then be used in relay attacks (RBCD, Silver Ticket) to compromise servers." -ForegroundColor Yellow
            Write-Host "  Best practice is to set this to 0." -ForegroundColor Yellow
            Write-Host ""

            $fix = Read-YesNo -Prompt "  Set Machine Account Quota to 0?" -Default $true
            if ($fix) {
                Invoke-WithDryRun -Description "Set ms-DS-MachineAccountQuota to 0 on domain root" -Action {
                    Set-ADObject -Identity $domainDN @adParams -Replace @{ 'ms-DS-MachineAccountQuota' = 0 } -ErrorAction Stop
                } | Out-Null
            }
        }
        else {
            Write-Host "  [OK] Machine Account Quota is already 0." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Machine Account Quota check failed: $_"
    }

    # ── Check 6: DCSync permissions (Replicating Directory Changes) ──
    Write-Log -Level CHECK -Message "Checking for accounts with DCSync rights..."
    try {
        $domainDN = (Get-ADDomain @adParams -ErrorAction Stop).DistinguishedName

        # DCSync requires these two GUIDs:
        # Replicating Directory Changes:     1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
        # Replicating Directory Changes All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
        $acl = Get-Acl -Path "AD:\$domainDN" -ErrorAction Stop

        $replicateGuid = [Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
        $replicateAllGuid = [Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

        # Known-safe SIDs (Domain Controllers, Enterprise DCs, Domain Admins, Enterprise Admins, SYSTEM)
        $domain = Get-ADDomain @adParams -ErrorAction Stop
        $safeSIDs = @(
            "$($domain.DomainSID)-516"   # Domain Controllers
            "$($domain.DomainSID)-498"   # Enterprise Read-Only DCs
            "$($domain.DomainSID)-512"   # Domain Admins
            "$($domain.DomainSID)-519"   # Enterprise Admins
            "S-1-5-18"                   # SYSTEM
            "S-1-5-32-544"              # Administrators
        )

        $dcsyncAccounts = @()
        foreach ($ace in $acl.Access) {
            if ($ace.ActiveDirectoryRights -match 'ExtendedRight' -and $ace.AccessControlType -eq 'Allow') {
                if ($ace.ObjectType -eq $replicateGuid -or $ace.ObjectType -eq $replicateAllGuid) {
                    $sidString = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    if ($sidString -notin $safeSIDs) {
                        $identityName = $ace.IdentityReference.Value
                        $rightName = if ($ace.ObjectType -eq $replicateGuid) { "Replicating Directory Changes" } else { "Replicating Directory Changes All" }
                        $dcsyncAccounts += [PSCustomObject]@{
                            Identity = $identityName
                            SID      = $sidString
                            Right    = $rightName
                        }
                    }
                }
            }
        }

        # Deduplicate by identity
        $uniqueDCSync = $dcsyncAccounts | Sort-Object Identity, Right -Unique

        if ($uniqueDCSync.Count -gt 0) {
            foreach ($entry in $uniqueDCSync) {
                $findingCount++
                Write-Log -Level FINDING -Message "DCSync right: '$($entry.Identity)' has '$($entry.Right)'"
            }

            Write-Host ""
            Write-Host "  Found $($uniqueDCSync.Count) unexpected DCSync permission(s)!" -ForegroundColor Red
            Write-Host "  DCSync (Replicating Directory Changes) lets an account request password" -ForegroundColor Yellow
            Write-Host "  hashes for ANY user in the domain - including krbtgt (Golden Ticket)." -ForegroundColor Yellow
            Write-Host "  Only Domain Controllers and domain admin groups should have this right." -ForegroundColor Yellow
            Write-Host ""

            $fmt = "  {0,-35} {1,-40}"
            Write-Host ($fmt -f "Identity", "Right") -ForegroundColor White
            Write-Host ($fmt -f ("-" * 35), ("-" * 40)) -ForegroundColor Gray
            foreach ($entry in $uniqueDCSync) {
                Write-Host ($fmt -f $entry.Identity, $entry.Right) -ForegroundColor Red
            }
            Write-Host ""

            foreach ($entry in $uniqueDCSync) {
                $fix = Read-YesNo -Prompt "  Remove DCSync right '$($entry.Right)' from '$($entry.Identity)'?" -Default $true
                if ($fix) {
                    Invoke-WithDryRun -Description "Remove '$($entry.Right)' from '$($entry.Identity)' on domain root" -Action {
                        $currentAcl = Get-Acl -Path "AD:\$domainDN" -ErrorAction Stop
                        $targetGuid = if ($entry.Right -eq "Replicating Directory Changes") { $replicateGuid } else { $replicateAllGuid }
                        $rulesToRemove = $currentAcl.Access | Where-Object {
                            $_.IdentityReference.Value -eq $entry.Identity -and
                            $_.ObjectType -eq $targetGuid -and
                            $_.AccessControlType -eq 'Allow'
                        }
                        foreach ($rule in $rulesToRemove) {
                            $currentAcl.RemoveAccessRule($rule) | Out-Null
                        }
                        Set-Acl -Path "AD:\$domainDN" -AclObject $currentAcl -ErrorAction Stop
                    } | Out-Null
                }
            }
        }
        else {
            Write-Host "  [OK] No unexpected DCSync permissions found." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level ERROR -Message "DCSync permissions check failed: $_"
    }

    # ── Check 7: Dangerous ACLs on privileged groups ─────────────────
    Write-Log -Level CHECK -Message "Checking for dangerous ACLs on sensitive AD objects..."
    try {
        $domainDN = (Get-ADDomain @adParams -ErrorAction Stop).DistinguishedName
        $domain = Get-ADDomain @adParams -ErrorAction Stop

        # Sensitive targets to check
        $sensitiveTargets = @(
            @{ Name = "Domain Admins";       DN = "CN=Domain Admins,CN=Users,$domainDN" }
            @{ Name = "Enterprise Admins";   DN = "CN=Enterprise Admins,CN=Users,$domainDN" }
            @{ Name = "Schema Admins";       DN = "CN=Schema Admins,CN=Users,$domainDN" }
            @{ Name = "Administrators";      DN = "CN=Administrators,CN=Builtin,$domainDN" }
            @{ Name = "Domain Controllers";  DN = "OU=Domain Controllers,$domainDN" }
            @{ Name = "AdminSDHolder";       DN = "CN=AdminSDHolder,CN=System,$domainDN" }
            @{ Name = "Domain Root";         DN = $domainDN }
            @{ Name = "krbtgt Account";      DN = "CN=krbtgt,CN=Users,$domainDN" }
        )

        # Dangerous rights to flag
        $dangerousRights = @(
            'GenericAll',
            'GenericWrite',
            'WriteOwner',
            'WriteDacl',
            'Self'
        )

        # Also flag these extended rights by GUID
        $dangerousExtendedRights = @{
            '00299570-246d-11d0-a768-00aa006e0529' = 'User-Force-Change-Password'
            'ab721a54-1e2f-11d0-9819-00aa0040529b' = 'Send-As'
            '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicating-Directory-Changes'
            '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' = 'Replicating-Directory-Changes-All'
        }

        # Safe principals that are expected to have permissions
        $safePrincipals = @(
            'NT AUTHORITY\SYSTEM',
            'NT AUTHORITY\SELF',
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS',
            'BUILTIN\Administrators',
            'BUILTIN\Account Operators',
            'BUILTIN\Pre-Windows 2000 Compatible Access'
        )
        # Also treat Domain Admins, Enterprise Admins, SYSTEM SIDs as safe
        $safeSIDPrefixes = @(
            "$($domain.DomainSID)-512"   # Domain Admins
            "$($domain.DomainSID)-519"   # Enterprise Admins
            "$($domain.DomainSID)-516"   # Domain Controllers
            "$($domain.DomainSID)-500"   # Administrator
            "S-1-5-18"                   # SYSTEM
            "S-1-5-32-544"              # Administrators
            "S-1-3-0"                   # CREATOR OWNER
            "S-1-5-10"                  # SELF
        )

        $aclFindings = @()

        foreach ($target in $sensitiveTargets) {
            try {
                $objExists = Get-ADObject -Identity $target.DN @adParams -ErrorAction Stop
            }
            catch {
                Write-Log -Level WARNING -Message "Could not find '$($target.Name)' at $($target.DN)"
                continue
            }

            try {
                $acl = Get-Acl -Path "AD:\$($target.DN)" -ErrorAction Stop
            }
            catch {
                Write-Log -Level WARNING -Message "Could not read ACL on '$($target.Name)': $_"
                continue
            }

            foreach ($ace in $acl.Access) {
                if ($ace.AccessControlType -ne 'Allow') { continue }

                $identityName = $ace.IdentityReference.Value

                # Skip known-safe principals
                if ($identityName -in $safePrincipals) { continue }

                # Check SID
                $isSafe = $false
                try {
                    $sid = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
                    if ($sid -in $safeSIDPrefixes) { $isSafe = $true }
                }
                catch {
                    # Orphaned SID - could be a deleted account, flag it
                }
                if ($isSafe) { continue }

                $isDangerous = $false
                $rightDescription = ""

                # Check for dangerous AD rights
                $adRights = $ace.ActiveDirectoryRights.ToString()
                foreach ($dr in $dangerousRights) {
                    if ($adRights -match $dr) {
                        $isDangerous = $true
                        $rightDescription = $adRights
                        break
                    }
                }

                # Check for dangerous extended rights
                if (-not $isDangerous -and $adRights -match 'ExtendedRight') {
                    $guidStr = $ace.ObjectType.ToString()
                    if ($dangerousExtendedRights.ContainsKey($guidStr)) {
                        $isDangerous = $true
                        $rightDescription = $dangerousExtendedRights[$guidStr]
                    }
                }

                # Check for WriteProperty on sensitive attributes
                if (-not $isDangerous -and $adRights -match 'WriteProperty') {
                    # Flag WriteProperty with empty GUID (means all properties)
                    $guidStr = $ace.ObjectType.ToString()
                    if ($guidStr -eq '00000000-0000-0000-0000-000000000000') {
                        $isDangerous = $true
                        $rightDescription = "WriteProperty (ALL attributes)"
                    }
                }

                if ($isDangerous) {
                    $aclFindings += [PSCustomObject]@{
                        Target       = $target.Name
                        TargetDN     = $target.DN
                        Identity     = $identityName
                        Rights       = $rightDescription
                        IsInherited  = $ace.IsInherited
                        ACE          = $ace
                    }
                }
            }
        }

        if ($aclFindings.Count -gt 0) {
            Write-Host ""
            Write-Host "  Found $($aclFindings.Count) dangerous ACL permission(s) on sensitive objects!" -ForegroundColor Red
            Write-Host ""
            Write-Host "  These permissions give non-admin accounts the ability to modify" -ForegroundColor Yellow
            Write-Host "  privileged groups, take ownership of sensitive objects, or change" -ForegroundColor Yellow
            Write-Host "  security settings - all common BloodHound attack paths." -ForegroundColor Yellow
            Write-Host ""

            $fmt = "  {0,-22} {1,-30} {2,-35} {3,-10}"
            Write-Host ($fmt -f "Target", "Identity", "Rights", "Inherited") -ForegroundColor White
            Write-Host ($fmt -f ("-" * 22), ("-" * 30), ("-" * 35), ("-" * 10)) -ForegroundColor Gray

            foreach ($f in $aclFindings) {
                $findingCount++
                $inheritLabel = if ($f.IsInherited) { "Yes" } else { "No" }
                Write-Host ($fmt -f $f.Target, $f.Identity, $f.Rights, $inheritLabel) -ForegroundColor Red
                Write-Log -Level FINDING -Message "Dangerous ACL: '$($f.Identity)' has '$($f.Rights)' on '$($f.Target)' (Inherited: $inheritLabel)"
            }

            Write-Host ""

            # Only offer to fix non-inherited ACEs (inherited ones must be fixed at the source)
            $fixableFindings = @($aclFindings | Where-Object { -not $_.IsInherited })
            $inheritedFindings = @($aclFindings | Where-Object { $_.IsInherited })

            if ($inheritedFindings.Count -gt 0) {
                Write-Host "  Note: $($inheritedFindings.Count) finding(s) are inherited from a parent object." -ForegroundColor Yellow
                Write-Host "  Inherited permissions must be fixed on the parent object or by" -ForegroundColor Yellow
                Write-Host "  disabling inheritance on the target." -ForegroundColor Yellow
                Write-Host ""
            }

            if ($fixableFindings.Count -gt 0) {
                Write-Host "  $($fixableFindings.Count) permission(s) can be removed directly:" -ForegroundColor Cyan
                Write-Host ""

                foreach ($f in $fixableFindings) {
                    $fix = Read-YesNo -Prompt "  Remove '$($f.Rights)' from '$($f.Identity)' on '$($f.Target)'?" -Default $true
                    if ($fix) {
                        Invoke-WithDryRun -Description "Remove '$($f.Rights)' from '$($f.Identity)' on '$($f.Target)'" -Action {
                            $currentAcl = Get-Acl -Path "AD:\$($f.TargetDN)" -ErrorAction Stop
                            $currentAcl.RemoveAccessRule($f.ACE) | Out-Null
                            Set-Acl -Path "AD:\$($f.TargetDN)" -AclObject $currentAcl -ErrorAction Stop
                        } | Out-Null
                    }
                }
            }
        }
        else {
            Write-Host "  [OK] No dangerous ACLs found on sensitive objects." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Dangerous ACL check failed: $_"
    }

    # ── Check 8: Constrained Delegation Misconfigurations ────────────
    Write-Log -Level CHECK -Message "Checking for constrained delegation with protocol transition..."
    try {
        $constrainedComputers = Get-ADComputer -Filter { TrustedToAuthForDelegation -eq $true -and Enabled -eq $true } @adParams `
            -Properties TrustedToAuthForDelegation, msDS-AllowedToDelegateTo -ErrorAction Stop

        $constrainedUsers = Get-ADUser -Filter { TrustedToAuthForDelegation -eq $true -and Enabled -eq $true } @adParams `
            -Properties TrustedToAuthForDelegation, msDS-AllowedToDelegateTo -ErrorAction Stop

        $constrainedAll = @()
        if ($constrainedComputers) { $constrainedAll += @($constrainedComputers) }
        if ($constrainedUsers) { $constrainedAll += @($constrainedUsers) }

        if ($constrainedAll.Count -gt 0) {
            Write-Host ""
            Write-Host "  Found $($constrainedAll.Count) account(s) with constrained delegation + protocol transition." -ForegroundColor Red
            Write-Host "  Protocol transition ('Use any authentication protocol') lets these accounts" -ForegroundColor Yellow
            Write-Host "  impersonate ANY user to the listed services without the user actually" -ForegroundColor Yellow
            Write-Host "  authenticating. An attacker who compromises one of these accounts can" -ForegroundColor Yellow
            Write-Host "  impersonate a Domain Admin to the target services." -ForegroundColor Yellow
            Write-Host ""

            foreach ($obj in $constrainedAll) {
                $findingCount++
                $objType = if ($obj.objectClass -eq 'computer') { "Computer" } else { "User" }
                $delegateTo = $obj.'msDS-AllowedToDelegateTo' -join ', '
                Write-Log -Level FINDING -Message "Constrained delegation with protocol transition: $objType '$($obj.SamAccountName)' -> $delegateTo"
                Write-Host "    $objType`: $($obj.SamAccountName)" -ForegroundColor White
                Write-Host "      Delegates to: $delegateTo" -ForegroundColor Gray

                $fix = Read-YesNo -Prompt "    Disable protocol transition on '$($obj.SamAccountName)'? (Keeps constrained delegation but requires actual user auth)" -Default $false
                if ($fix) {
                    Invoke-WithDryRun -Description "Disable protocol transition on '$($obj.SamAccountName)'" -Action {
                        Set-ADAccountControl -Identity $obj.SamAccountName @adParams -TrustedToAuthForDelegation $false -ErrorAction Stop
                    } | Out-Null
                }
            }
        }
        else {
            Write-Host "  [OK] No constrained delegation with protocol transition found." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Constrained delegation check failed: $_"
    }

    # ── Check 9: Resource-Based Constrained Delegation on DCs ────────
    Write-Log -Level CHECK -Message "Checking for RBCD on Domain Controllers..."
    try {
        $dcList = Get-ADDomainController -Filter * @adParams -ErrorAction Stop
        $rbcdFindings = @()

        foreach ($dc in $dcList) {
            try {
                $comp = Get-ADComputer -Identity $dc.Name @adParams `
                    -Properties msDS-AllowedToActOnBehalfOfOtherIdentity -ErrorAction Stop

                $rbcd = $comp.'msDS-AllowedToActOnBehalfOfOtherIdentity'
                if ($null -ne $rbcd) {
                    $rbcdAcl = New-Object Security.AccessControl.RawSecurityDescriptor($rbcd, 0)
                    foreach ($ace in $rbcdAcl.DiscretionaryAcl) {
                        $sid = $ace.SecurityIdentifier
                        $name = ""
                        try { $name = $sid.Translate([System.Security.Principal.NTAccount]).Value } catch { $name = $sid.Value }
                        $rbcdFindings += [PSCustomObject]@{
                            DC       = $dc.Name
                            Identity = $name
                            SID      = $sid.Value
                            DCDN     = $comp.DistinguishedName
                        }
                    }
                }
            }
            catch {
                Write-Log -Level WARNING -Message "Could not check RBCD on DC '$($dc.Name)': $_"
            }
        }

        if ($rbcdFindings.Count -gt 0) {
            foreach ($r in $rbcdFindings) {
                $findingCount++
                Write-Log -Level FINDING -Message "RBCD on DC '$($r.DC)': '$($r.Identity)' can impersonate users to this DC"
            }

            Write-Host ""
            Write-Host "  Found $($rbcdFindings.Count) RBCD delegation(s) on Domain Controllers!" -ForegroundColor Red
            Write-Host "  Resource-Based Constrained Delegation (RBCD) on a DC means the listed" -ForegroundColor Yellow
            Write-Host "  accounts can impersonate any user to the DC - effectively giving them" -ForegroundColor Yellow
            Write-Host "  Domain Admin access. This is a common privilege escalation path." -ForegroundColor Yellow
            Write-Host ""

            foreach ($r in $rbcdFindings) {
                Write-Host "    DC: $($r.DC) <- $($r.Identity)" -ForegroundColor White

                $fix = Read-YesNo -Prompt "    Remove RBCD entry for '$($r.Identity)' on DC '$($r.DC)'?" -Default $true
                if ($fix) {
                    Invoke-WithDryRun -Description "Remove RBCD entry for '$($r.Identity)' on DC '$($r.DC)'" -Action {
                        Set-ADComputer -Identity $r.DC @adParams `
                            -PrincipalsAllowedToDelegateToAccount $null -ErrorAction Stop
                    } | Out-Null
                }
            }
        }
        else {
            Write-Host "  [OK] No RBCD configured on Domain Controllers." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level ERROR -Message "RBCD on DCs check failed: $_"
    }

    # ── Check 10: LDAP Signing Not Required ──────────────────────────
    Write-Log -Level CHECK -Message "Checking if LDAP signing is required..."
    try {
        $dcTarget = $Script:TargetDC
        $regResult = Invoke-Command -ComputerName $dcTarget -ScriptBlock {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
            $val = Get-ItemProperty -Path $path -Name "LDAPServerIntegrity" -ErrorAction SilentlyContinue
            if ($null -eq $val) { return 1 }  # Default = 1 (none/negotiate)
            return $val.LDAPServerIntegrity
        } -ErrorAction Stop

        if ($regResult -ne 2) {
            $findingCount++
            $currentSetting = switch ($regResult) {
                0 { "None" }
                1 { "Negotiate (default - does not require signing)" }
                2 { "Required" }
                default { "Unknown ($regResult)" }
            }
            Write-Log -Level FINDING -Message "LDAP signing is not required (current: $currentSetting)"

            Write-Host ""
            Write-Host "  LDAP signing is NOT required (current setting: $currentSetting)." -ForegroundColor Red
            Write-Host "  Without LDAP signing, attackers on your network can intercept and" -ForegroundColor Yellow
            Write-Host "  modify LDAP traffic between clients and domain controllers (LDAP relay)." -ForegroundColor Yellow
            Write-Host "  Setting this to 'Required' prevents relay and man-in-the-middle attacks." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  WARNING: Enabling required LDAP signing may break older clients or" -ForegroundColor Yellow
            Write-Host "  applications that don't support signing. Test in your environment first." -ForegroundColor Yellow
            Write-Host ""

            $fix = Read-YesNo -Prompt "  Require LDAP signing on DC '$dcTarget'?" -Default $false
            if ($fix) {
                Invoke-WithDryRun -Description "Set LDAP signing to Required on '$dcTarget'" -Action {
                    Invoke-Command -ComputerName $dcTarget -ScriptBlock {
                        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
                        Set-ItemProperty -Path $path -Name "LDAPServerIntegrity" -Value 2 -ErrorAction Stop
                    } -ErrorAction Stop
                } | Out-Null
            }
        }
        else {
            Write-Host "  [OK] LDAP signing is required." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Could not check LDAP signing (requires remote access to DC): $_"
    }

    # ── Check 11: LDAP Channel Binding ───────────────────────────────
    Write-Log -Level CHECK -Message "Checking if LDAP channel binding is enforced..."
    try {
        $dcTarget = $Script:TargetDC
        $regResult = Invoke-Command -ComputerName $dcTarget -ScriptBlock {
            $path = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
            $val = Get-ItemProperty -Path $path -Name "LdapEnforceChannelBinding" -ErrorAction SilentlyContinue
            if ($null -eq $val) { return 0 }  # Default = 0 (disabled)
            return $val.LdapEnforceChannelBinding
        } -ErrorAction Stop

        if ($regResult -ne 2) {
            $findingCount++
            $currentSetting = switch ($regResult) {
                0 { "Disabled (default)" }
                1 { "When supported (partial)" }
                2 { "Always (fully enforced)" }
                default { "Unknown ($regResult)" }
            }
            Write-Log -Level FINDING -Message "LDAP channel binding is not enforced (current: $currentSetting)"

            Write-Host ""
            Write-Host "  LDAP channel binding is NOT enforced (current: $currentSetting)." -ForegroundColor Red
            Write-Host "  Channel binding (EPA) ties LDAP sessions to the TLS connection," -ForegroundColor Yellow
            Write-Host "  preventing LDAP relay attacks even over LDAPS." -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  WARNING: Enforcing channel binding may break clients that don't" -ForegroundColor Yellow
            Write-Host "  support Extended Protection for Authentication. Test first." -ForegroundColor Yellow
            Write-Host ""

            $fix = Read-YesNo -Prompt "  Enforce LDAP channel binding on DC '$dcTarget'?" -Default $false
            if ($fix) {
                Invoke-WithDryRun -Description "Set LDAP channel binding to Always on '$dcTarget'" -Action {
                    Invoke-Command -ComputerName $dcTarget -ScriptBlock {
                        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
                        Set-ItemProperty -Path $path -Name "LdapEnforceChannelBinding" -Value 2 -ErrorAction Stop
                    } -ErrorAction Stop
                } | Out-Null
            }
        }
        else {
            Write-Host "  [OK] LDAP channel binding is enforced." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level WARNING -Message "Could not check LDAP channel binding (requires remote access to DC): $_"
    }

    # ── Check 12: Print Spooler on Domain Controllers ────────────────
    Write-Log -Level CHECK -Message "Checking for Print Spooler service on Domain Controllers..."
    try {
        $dcList = Get-ADDomainController -Filter * @adParams -ErrorAction Stop

        foreach ($dc in $dcList) {
            try {
                $spooler = Invoke-Command -ComputerName $dc.Name -ScriptBlock {
                    Get-Service -Name Spooler -ErrorAction Stop
                } -ErrorAction Stop

                if ($spooler.Status -eq 'Running') {
                    $findingCount++
                    Write-Log -Level FINDING -Message "Print Spooler is running on DC '$($dc.Name)'"

                    Write-Host ""
                    Write-Host "  Print Spooler is RUNNING on DC '$($dc.Name)'." -ForegroundColor Red
                    Write-Host "  The Print Spooler service on a DC enables the 'Printer Bug' attack:" -ForegroundColor Yellow
                    Write-Host "  an attacker can force the DC to authenticate to a machine they control" -ForegroundColor Yellow
                    Write-Host "  and relay those credentials. DCs should never run the Print Spooler." -ForegroundColor Yellow
                    Write-Host ""

                    $fix = Read-YesNo -Prompt "  Stop and disable Print Spooler on DC '$($dc.Name)'?" -Default $true
                    if ($fix) {
                        Invoke-WithDryRun -Description "Stop and disable Print Spooler on DC '$($dc.Name)'" -Action {
                            Invoke-Command -ComputerName $dc.Name -ScriptBlock {
                                Stop-Service -Name Spooler -Force -ErrorAction Stop
                                Set-Service -Name Spooler -StartupType Disabled -ErrorAction Stop
                            } -ErrorAction Stop
                        } | Out-Null
                    }
                }
                else {
                    Write-Host "  [OK] Print Spooler is not running on DC '$($dc.Name)'." -ForegroundColor Green
                }
            }
            catch {
                Write-Log -Level WARNING -Message "Could not check Print Spooler on DC '$($dc.Name)': $_"
            }
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Print Spooler on DCs check failed: $_"
    }

    # ── Check 13: GPO Permissions ────────────────────────────────────
    Write-Log -Level CHECK -Message "Checking for non-standard GPO modification permissions..."
    try {
        if (Test-ModuleAvailable -ModuleName "GroupPolicy") {
            $gpos = Get-GPO -All @adParams -ErrorAction Stop

            $gpoFindings = @()

            foreach ($gpo in $gpos) {
                try {
                    $gpoPerms = Get-GPPermission -Guid $gpo.Id -All @adParams -ErrorAction Stop

                    foreach ($perm in $gpoPerms) {
                        if ($perm.Permission -match 'GpoEdit|GpoEditDeleteModifySecurity' -and
                            $perm.Trustee.SidType -ne 'WellKnownGroup') {

                            $trusteeName = $perm.Trustee.Name
                            $trusteeDomain = $perm.Trustee.Domain
                            $fullName = if ($trusteeDomain) { "$trusteeDomain\$trusteeName" } else { $trusteeName }

                            # Skip known-safe
                            if ($trusteeName -in @('Domain Admins', 'Enterprise Admins', 'SYSTEM')) { continue }

                            $gpoFindings += [PSCustomObject]@{
                                GPOName    = $gpo.DisplayName
                                GPOID      = $gpo.Id
                                Identity   = $fullName
                                Permission = $perm.Permission
                            }
                        }
                    }
                }
                catch {
                    # Some GPOs may not be readable
                }
            }

            if ($gpoFindings.Count -gt 0) {
                foreach ($f in $gpoFindings) {
                    $findingCount++
                    Write-Log -Level FINDING -Message "GPO edit permission: '$($f.Identity)' can edit GPO '$($f.GPOName)'"
                }

                Write-Host ""
                Write-Host "  Found $($gpoFindings.Count) non-standard GPO edit permission(s)!" -ForegroundColor Red
                Write-Host "  Anyone who can edit a GPO can push malicious settings or scripts" -ForegroundColor Yellow
                Write-Host "  to every computer the GPO applies to - often the entire domain." -ForegroundColor Yellow
                Write-Host ""

                $fmt = "  {0,-30} {1,-30} {2,-25}"
                Write-Host ($fmt -f "GPO Name", "Identity", "Permission") -ForegroundColor White
                Write-Host ($fmt -f ("-" * 30), ("-" * 30), ("-" * 25)) -ForegroundColor Gray
                foreach ($f in $gpoFindings) {
                    Write-Host ($fmt -f $f.GPOName, $f.Identity, $f.Permission) -ForegroundColor Red
                }
                Write-Host ""

                foreach ($f in $gpoFindings) {
                    $fix = Read-YesNo -Prompt "  Remove edit permission for '$($f.Identity)' on GPO '$($f.GPOName)'?" -Default $true
                    if ($fix) {
                        Invoke-WithDryRun -Description "Remove edit permission for '$($f.Identity)' on GPO '$($f.GPOName)'" -Action {
                            Set-GPPermission -Guid $f.GPOID -TargetName $f.Identity -TargetType User `
                                -PermissionLevel None @adParams -ErrorAction Stop
                        } | Out-Null
                    }
                }
            }
            else {
                Write-Host "  [OK] No non-standard GPO edit permissions found." -ForegroundColor Green
            }
        }
        else {
            Write-Host "  [SKIP] GroupPolicy module not available. Skipping GPO permission check." -ForegroundColor DarkGray
        }
    }
    catch {
        Write-Log -Level ERROR -Message "GPO permissions check failed: $_"
    }

    # ── Check 14: AdminCount orphans ─────────────────────────────────
    Write-Log -Level CHECK -Message "Checking for AdminCount orphans (former admins with stale protections)..."
    try {
        $adminCountUsers = Get-ADUser -Filter { AdminCount -eq 1 -and Enabled -eq $true } @adParams `
            -Properties AdminCount, MemberOf -ErrorAction Stop

        $privilegedGroupDNs = @()
        $privilegedGroupNames = @('Domain Admins', 'Enterprise Admins', 'Schema Admins',
            'Administrators', 'Account Operators', 'Server Operators', 'Backup Operators',
            'Print Operators', 'Cert Publishers', 'DnsAdmins')

        foreach ($pgName in $privilegedGroupNames) {
            try {
                $pg = Get-ADGroup -Identity $pgName @adParams -ErrorAction Stop
                $privilegedGroupDNs += $pg.DistinguishedName
            }
            catch { }
        }

        $orphans = @()
        if ($adminCountUsers) {
            foreach ($user in @($adminCountUsers)) {
                $isStillPrivileged = $false
                foreach ($memberOf in $user.MemberOf) {
                    if ($memberOf -in $privilegedGroupDNs) {
                        $isStillPrivileged = $true
                        break
                    }
                }
                if (-not $isStillPrivileged) {
                    $orphans += $user
                }
            }
        }

        if ($orphans.Count -gt 0) {
            foreach ($user in $orphans) {
                $findingCount++
                Write-Log -Level FINDING -Message "AdminCount orphan: $($user.SamAccountName) has AdminCount=1 but is not in any privileged group"
            }

            Write-Host ""
            Write-Host "  Found $($orphans.Count) AdminCount orphan(s)." -ForegroundColor Red
            Write-Host "  These accounts have AdminCount=1 (set when they were in a privileged group)" -ForegroundColor Yellow
            Write-Host "  but are no longer members of any privileged group. The AdminCount flag" -ForegroundColor Yellow
            Write-Host "  prevents inheritance of new permissions and blocks AdminSDHolder from" -ForegroundColor Yellow
            Write-Host "  cleaning up their ACLs - leaving potentially stale, overprivileged ACLs." -ForegroundColor Yellow
            Write-Host ""

            $fix = Read-YesNo -Prompt "  Clear AdminCount on all $($orphans.Count) orphan account(s)?" -Default $true
            if ($fix) {
                foreach ($user in $orphans) {
                    Invoke-WithDryRun -Description "Clear AdminCount on '$($user.SamAccountName)'" -Action {
                        Set-ADUser -Identity $user.SamAccountName @adParams -Replace @{ AdminCount = 0 } -ErrorAction Stop
                        # Re-enable inheritance
                        $userDN = $user.DistinguishedName
                        $aclPath = "AD:\$userDN"
                        $acl = Get-Acl -Path $aclPath -ErrorAction Stop
                        $acl.SetAccessRuleProtection($false, $true)
                        Set-Acl -Path $aclPath -AclObject $acl -ErrorAction Stop
                    } | Out-Null
                }
            }
        }
        else {
            Write-Host "  [OK] No AdminCount orphans found." -ForegroundColor Green
        }
    }
    catch {
        Write-Log -Level ERROR -Message "AdminCount orphan check failed: $_"
    }

    # ── Summary ──────────────────────────────────────────────────────
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host "  AD Misconfiguration Scan Complete" -ForegroundColor Cyan
    Write-Host ""
    if ($findingCount -eq 0) {
        Write-Host "  No misconfigurations found! Your AD looks well-hardened." -ForegroundColor Green
    }
    else {
        Write-Host "  Total findings: $findingCount" -ForegroundColor Yellow
        Write-Host "  Review the log and report for full details." -ForegroundColor Yellow
    }
    Write-Host "=" * 60 -ForegroundColor Cyan
    Write-Host ""

    $Script:CompletedFeatures["10"] = $true

    Write-Host "Press Enter to return to the menu..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

# ══════════════════════════════════════════════════════════════════════
#  REPORT GENERATION
# ══════════════════════════════════════════════════════════════════════

function Invoke-GenerateReport {
    Write-Host ""
    Write-Host "===== Generating Report =====" -ForegroundColor Cyan
    Write-Host ""

    $reportFile = New-ADScannerReport -ScriptName "AD Hardener v$Script:Version" -PrintToConsole
    Write-Host ""
    Write-Host "Report saved to: $reportFile" -ForegroundColor Green
    Write-Host ""
    Write-Host "Press Enter to return to the menu..." -ForegroundColor Yellow
    Read-Host | Out-Null
}

# ══════════════════════════════════════════════════════════════════════
#  MAIN ENTRY POINT
# ══════════════════════════════════════════════════════════════════════

function Start-ADHardener {
    # 1. Banner
    Show-Banner

    # 2. Privilege check
    Write-Host "--- Privilege Check ---" -ForegroundColor Cyan
    $privOk = Test-Privileges
    if (-not $privOk) {
        Write-Host ""
        Write-Host "Privilege checks failed. Please resolve the issues above and try again." -ForegroundColor Red
        return
    }
    Write-Host ""

    # 3. Module dependency check
    Write-Host "--- Module Dependency Check ---" -ForegroundColor Cyan
    Test-ModuleDependencies -RequiredModules @('ActiveDirectory', 'PSWindowsUpdate', 'DnsServer', 'GroupPolicy')
    Write-Host ""

    # 4. Environment auto-detection
    Write-Host "--- Environment Detection ---" -ForegroundColor Cyan
    $envOk = Initialize-Environment
    if (-not $envOk) {
        Write-Host ""
        Write-Host "Environment detection failed. Cannot continue." -ForegroundColor Red
        return
    }
    Write-Host ""

    # 5. Initialize directory structure
    Initialize-ADScannerDirectory

    # 6. Health check overview
    Invoke-HealthCheck

    # 7. Main menu loop
    while ($true) {
        Show-MainMenu

        $choice = Read-UserChoice -Prompt "Select option" -ValidChoices @('1','2','3','4','5','6','7','8','9','10','H','h','R','r','Q','q') -Default 'Q'

        switch ($choice.ToUpper()) {
            '1' {
                if (Test-ModuleAvailable -ModuleName "PSWindowsUpdate") {
                    Invoke-PatchComputers
                }
                else {
                    Write-Host "  Feature 1 requires the PSWindowsUpdate module." -ForegroundColor Red
                    Write-Host "  Install with: Install-Module PSWindowsUpdate -Force" -ForegroundColor Yellow
                }
            }
            '2' {
                Invoke-RestrictRDP
            }
            '3' {
                if (Test-ModuleAvailable -ModuleName "DnsServer") {
                    Invoke-HardenDNS
                }
                else {
                    Write-Host "  Feature 3 requires the DnsServer module." -ForegroundColor Red
                }
            }
            '4' {
                if (Test-ModuleAvailable -ModuleName "DnsServer") {
                    Invoke-DisableServices
                }
                else {
                    Write-Host "  Feature 4 requires the DnsServer module." -ForegroundColor Red
                }
            }
            '5' {
                Invoke-HardenAdmins
            }
            '6' {
                Invoke-AdvancedAuditing
            }
            '7' {
                Invoke-DetectKerberoast
            }
            '8' {
                if (Test-ModuleAvailable -ModuleName "DnsServer") {
                    Invoke-SecureZoneTransfers
                }
                else {
                    Write-Host "  Feature 8 requires the DnsServer module." -ForegroundColor Red
                }
            }
            '9' {
                Invoke-CheckScheduledTasks
            }
            '10' {
                Invoke-CheckADMisconfigurations
            }
            'H' {
                Show-Help
            }
            'R' {
                Invoke-GenerateReport
            }
            'Q' {
                Write-Host ""
                Write-Host "Generating final report before exit..." -ForegroundColor Cyan
                New-ADScannerReport -ScriptName "AD Hardener v$Script:Version" -PrintToConsole | Out-Null
                Write-Host ""
                Write-Host "Thank you for using AD Hardener. Stay secure!" -ForegroundColor Green
                Write-Host ""
                return
            }
        }
    }
}

# Run the script
Start-ADHardener
