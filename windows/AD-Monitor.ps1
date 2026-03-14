#Requires -Version 5.1
<#
.SYNOPSIS
    Continuous monitoring daemon for Active Directory users and groups.
.DESCRIPTION
    Monitors all AD users and groups for membership changes, new account creation,
    password changes, account status changes, and privilege escalation.
    Compares live state against a locally maintained baseline.
.NOTES
    Version: 1.1.0
    Requires: ActiveDirectory module, Administrator privileges, domain connectivity.
#>

# ── Dot-source shared infrastructure ────────────────────────────────
. (Join-Path $PSScriptRoot "ADScanner-Common.ps1")

# ── Script-scoped state ─────────────────────────────────────────────
$Script:MonitorVersion       = "1.1.0"
$Script:UsersBaselineFile    = Join-Path $Script:ConfigPath "users-baseline.csv"
$Script:GroupsBaselineFile   = Join-Path $Script:ConfigPath "groups-baseline.csv"
$Script:UsersBaseline        = @()
$Script:GroupsBaseline       = @()
$Script:PollCount            = 0
$Script:PollIntervalSec      = 300   # default 5 minutes
$Script:LastPollTime         = $null
$Script:MonitorRunning       = $false
$Script:CanaryAccounts       = @()
$Script:AdminSDHolderBaseline = $null
$Script:CanaryAccountsFile   = Join-Path $Script:ConfigPath "canary-accounts.csv"

# ── Banner ───────────────────────────────────────────────────────────

function Show-Banner {
    Write-Host ""
    Write-Host "    ___    ____       __  ___            _ __            " -ForegroundColor Cyan
    Write-Host "   /   |  / __ \     /  |/  /___  ____  (_) /_____  _____" -ForegroundColor Cyan
    Write-Host "  / /| | / / / /    / /|_/ / __ \/ __ \/ / __/ __ \/ ___/" -ForegroundColor Cyan
    Write-Host " / ___ |/ /_/ /    / /  / / /_/ / / / / / /_/ /_/ / /    " -ForegroundColor Cyan
    Write-Host "/_/  |_/_____/    /_/  /_/\____/_/ /_/_/\__/\____/_/     " -ForegroundColor Cyan
    Write-Host ""
    Write-Host "        Active Directory Monitor v$Script:MonitorVersion" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Continuously watches for changes to AD users and groups." -ForegroundColor Gray
    Write-Host "  Compares live AD state against your approved baseline." -ForegroundColor Gray
    Write-Host ""
}

# ── Snapshot Helpers ─────────────────────────────────────────────────

function Get-AllUsersSnapshot {
    [CmdletBinding()]
    param()

    $adParams = Get-ADTargetParams
    $domainPrefix = $Script:DomainName.Split('.')[0].ToUpper()
    $users = @()

    try {
        $adUsers = Get-ADUser -Filter * @adParams -Properties SamAccountName, Enabled, LockedOut, PasswordLastSet, MemberOf, AdminCount -ErrorAction Stop

        foreach ($u in $adUsers) {
            $users += [PSCustomObject]@{
                Username        = "$domainPrefix\$($u.SamAccountName)"
                SamAccountName  = $u.SamAccountName
                Enabled         = [string]$u.Enabled
                LockedOut       = [string]$u.LockedOut
                PasswordLastSet = if ($null -ne $u.PasswordLastSet) { $u.PasswordLastSet.ToString("yyyy-MM-dd HH:mm:ss") } else { "" }
                AdminCount      = [string]$u.AdminCount
            }
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to query AD users: $_"
    }

    return $users
}

function Get-AllGroupMembershipsSnapshot {
    [CmdletBinding()]
    param()

    $adParams = Get-ADTargetParams
    $domainPrefix = $Script:DomainName.Split('.')[0].ToUpper()
    $memberships = @()

    try {
        $groups = Get-ADGroup -Filter * @adParams -ErrorAction Stop

        foreach ($group in $groups) {
            try {
                $members = Get-ADGroupMember -Identity $group.SID @adParams -ErrorAction Stop
                foreach ($member in $members) {
                    $memberships += [PSCustomObject]@{
                        GroupName       = $group.Name
                        MemberUsername  = "$domainPrefix\$($member.SamAccountName)"
                        MemberSam      = $member.SamAccountName
                        MemberType     = $member.objectClass
                    }
                }
            }
            catch {
                # Some groups (e.g. with foreign security principals) may error
                Write-Log -Level WARNING -Message "Could not enumerate members of group '$($group.Name)': $_"
            }
        }
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to query AD groups: $_"
    }

    return $memberships
}

# ── Baseline Save / Load ────────────────────────────────────────────

function Save-UsersBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Users
    )

    $lines = @()
    $lines += "# Users Baseline - Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $lines += "# Columns: Username, SamAccountName, Enabled, LockedOut, PasswordLastSet, AdminCount"
    $lines += "Username,SamAccountName,Enabled,LockedOut,PasswordLastSet,AdminCount"

    foreach ($u in $Users) {
        $pwdLastSet = $u.PasswordLastSet
        if ($null -eq $pwdLastSet) { $pwdLastSet = "" }
        $lines += "$($u.Username),$($u.SamAccountName),$($u.Enabled),$($u.LockedOut),$pwdLastSet,$($u.AdminCount)"
    }

    if (-not (Test-Path $Script:ConfigPath)) {
        New-Item -Path $Script:ConfigPath -ItemType Directory -Force | Out-Null
    }

    Set-Content -Path $Script:UsersBaselineFile -Value ($lines -join "`r`n") -Encoding UTF8
    Write-Log -Level INFO -Message "Users baseline saved ($($Users.Count) users) to $Script:UsersBaselineFile"
}

function Save-GroupsBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Memberships
    )

    $lines = @()
    $lines += "# Groups Baseline - Generated $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    $lines += "# Columns: GroupName, MemberUsername, MemberSam, MemberType"
    $lines += "GroupName,MemberUsername,MemberSam,MemberType"

    foreach ($m in $Memberships) {
        $lines += "$($m.GroupName),$($m.MemberUsername),$($m.MemberSam),$($m.MemberType)"
    }

    if (-not (Test-Path $Script:ConfigPath)) {
        New-Item -Path $Script:ConfigPath -ItemType Directory -Force | Out-Null
    }

    Set-Content -Path $Script:GroupsBaselineFile -Value ($lines -join "`r`n") -Encoding UTF8

    $uniqueGroups = ($Memberships | Select-Object -ExpandProperty GroupName -Unique).Count
    Write-Log -Level INFO -Message "Groups baseline saved ($($Memberships.Count) memberships across $uniqueGroups groups) to $Script:GroupsBaselineFile"
}

function Load-UsersBaseline {
    [CmdletBinding()]
    param()

    $data = Import-CSVConfig -Path $Script:UsersBaselineFile `
        -RequiredColumns @('Username','SamAccountName','Enabled','PasswordLastSet') `
        -FriendlyName "Users Baseline"

    if ($null -eq $data) { return $null }
    return @($data)
}

function Load-GroupsBaseline {
    [CmdletBinding()]
    param()

    $data = Import-CSVConfig -Path $Script:GroupsBaselineFile `
        -RequiredColumns @('GroupName','MemberUsername','MemberSam') `
        -FriendlyName "Groups Baseline"

    if ($null -eq $data) { return $null }
    return @($data)
}

# ── Baseline Summary ────────────────────────────────────────────────

function Show-BaselineSummary {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "Current Baseline Summary:" -ForegroundColor Cyan
    Write-Host ("-" * 55) -ForegroundColor Gray

    $enabledUsers = @($Script:UsersBaseline | Where-Object { $_.Enabled -eq 'True' })
    $disabledUsers = @($Script:UsersBaseline | Where-Object { $_.Enabled -ne 'True' })
    Write-Host "  Users: $($Script:UsersBaseline.Count) total ($($enabledUsers.Count) enabled, $($disabledUsers.Count) disabled)" -ForegroundColor White

    $uniqueGroups = @($Script:GroupsBaseline | Select-Object -ExpandProperty GroupName -Unique)
    Write-Host "  Groups: $($uniqueGroups.Count) with memberships tracked" -ForegroundColor White
    Write-Host "  Group memberships: $($Script:GroupsBaseline.Count) total entries" -ForegroundColor White

    # Show privileged groups specifically
    $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Account Operators', 'Server Operators', 'Backup Operators', 'DnsAdmins',
        'Group Policy Creator Owners')
    $privFound = @()
    foreach ($pg in $privilegedGroups) {
        $members = @($Script:GroupsBaseline | Where-Object { $_.GroupName -eq $pg })
        if ($members.Count -gt 0) {
            $privFound += "    $pg`: $($members.Count) member(s)"
        }
    }
    if ($privFound.Count -gt 0) {
        Write-Host ""
        Write-Host "  Privileged groups:" -ForegroundColor Yellow
        foreach ($line in $privFound) {
            Write-Host $line -ForegroundColor White
        }
    }

    Write-Host ("-" * 55) -ForegroundColor Gray
    Write-Host ""
}

# ── Baseline Display ─────────────────────────────────────────────────

function Show-SnapshotDetails {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Users,

        [Parameter(Mandatory)]
        [array]$Memberships
    )

    # Display all user accounts
    $enabledUsers = @($Users | Where-Object { $_.Enabled -eq 'True' })
    $disabledUsers = @($Users | Where-Object { $_.Enabled -ne 'True' })

    Write-Host ""
    Write-Host "--- User Accounts ($($Users.Count) found) ---" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Enabled: $($enabledUsers.Count)  |  Disabled: $($disabledUsers.Count)" -ForegroundColor Gray
    Write-Host ""

    $fmt = "  {0,-30} {1,-10} {2,-10} {3,-20}"
    Write-Host ($fmt -f "Username", "Enabled", "Locked", "Password Last Set") -ForegroundColor White
    Write-Host ($fmt -f ("-" * 30), ("-" * 10), ("-" * 10), ("-" * 20)) -ForegroundColor Gray

    foreach ($u in ($Users | Sort-Object Username)) {
        $line = $fmt -f $u.Username, $u.Enabled, $u.LockedOut, $u.PasswordLastSet
        if ($u.Enabled -ne 'True') {
            Write-Host $line -ForegroundColor Yellow
        }
        elseif ($u.LockedOut -eq 'True') {
            Write-Host $line -ForegroundColor Red
        }
        else {
            Write-Host $line -ForegroundColor Gray
        }
    }

    Write-Host ""

    # Display all groups and their members
    $uniqueGroups = @($Memberships | Select-Object -ExpandProperty GroupName -Unique)

    Write-Host "--- Groups ($($uniqueGroups.Count) groups, $($Memberships.Count) total memberships) ---" -ForegroundColor Cyan
    Write-Host ""

    foreach ($groupName in ($uniqueGroups | Sort-Object)) {
        $groupMembers = @($Memberships | Where-Object { $_.GroupName -eq $groupName })
        Write-Host "  $groupName ($($groupMembers.Count) member(s)):" -ForegroundColor White
        foreach ($m in ($groupMembers | Sort-Object MemberUsername)) {
            $typeLabel = ""
            if ($m.MemberType -eq 'group') {
                $typeLabel = " [group]"
            }
            elseif ($m.MemberType -eq 'computer') {
                $typeLabel = " [computer]"
            }
            Write-Host "    - $($m.MemberUsername)$typeLabel" -ForegroundColor Gray
        }
    }

    Write-Host ""
    Write-Host ("-" * 55) -ForegroundColor Gray
}

# ── Baseline Initialization ─────────────────────────────────────────

function Initialize-Baseline {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "No baseline found. Starting baseline initialization..." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "I'll capture the current state of ALL users and group memberships" -ForegroundColor Gray
    Write-Host "in your domain so I can alert you if anything changes." -ForegroundColor Gray
    Write-Host ""

    Write-Log -Level CHECK -Message "Capturing current AD users..."
    $users = Get-AllUsersSnapshot
    if ($users.Count -eq 0) {
        Write-Host "No users found in AD. Please verify connectivity and try again." -ForegroundColor Red
        return $false
    }

    Write-Log -Level CHECK -Message "Capturing current AD group memberships (this may take a moment)..."
    $memberships = Get-AllGroupMembershipsSnapshot

    Show-SnapshotDetails -Users $users -Memberships $memberships

    Write-Host ""
    $confirmed = Read-YesNo -Prompt "Save this as the known-good baseline?" -Default $true
    if (-not $confirmed) {
        Write-Host "Baseline initialization cancelled." -ForegroundColor Yellow
        return $false
    }

    Save-UsersBaseline -Users $users
    Save-GroupsBaseline -Memberships $memberships

    $Script:UsersBaseline = $users
    $Script:GroupsBaseline = $memberships

    Show-BaselineSummary
    Write-Log -Level INFO -Message "Baseline initialized: $($users.Count) users, $($memberships.Count) group memberships."
    return $true
}

# ── Interactive Baseline Update (B key) ──────────────────────────────

function Update-BaselineInteractive {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "===== Baseline Update =====" -ForegroundColor Cyan

    Show-BaselineSummary

    Write-Host "What would you like to do?" -ForegroundColor Yellow
    Write-Host "  1. Refresh baseline from current AD state (re-snapshot everything)" -ForegroundColor White
    Write-Host "  2. Accept all current alerts into baseline (mark current state as OK)" -ForegroundColor White
    Write-Host "  3. Cancel" -ForegroundColor White

    $choice = Read-Host "Enter choice"

    switch ($choice) {
        '1' {
            Write-Log -Level CHECK -Message "Refreshing baseline from current AD state..."
            $users = Get-AllUsersSnapshot
            $memberships = Get-AllGroupMembershipsSnapshot

            if ($users.Count -gt 0) {
                Show-SnapshotDetails -Users $users -Memberships $memberships

                $confirm = Read-YesNo -Prompt "Save this as the new baseline?" -Default $true
                if ($confirm) {
                    Save-UsersBaseline -Users $users
                    Save-GroupsBaseline -Memberships $memberships
                    $Script:UsersBaseline = $users
                    $Script:GroupsBaseline = $memberships
                    Write-Host "  Baseline refreshed." -ForegroundColor Green
                }
                else {
                    Write-Host "  Baseline unchanged." -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "  Failed to query AD. Baseline unchanged." -ForegroundColor Red
            }
        }
        '2' {
            Write-Log -Level CHECK -Message "Accepting current AD state as baseline..."
            $users = Get-AllUsersSnapshot
            $memberships = Get-AllGroupMembershipsSnapshot

            if ($users.Count -gt 0) {
                Show-SnapshotDetails -Users $users -Memberships $memberships

                $confirm = Read-YesNo -Prompt "Accept this as the new baseline?" -Default $true
                if ($confirm) {
                    Save-UsersBaseline -Users $users
                    Save-GroupsBaseline -Memberships $memberships
                    $Script:UsersBaseline = $users
                    $Script:GroupsBaseline = $memberships
                    Write-Host "  Current state accepted as new baseline." -ForegroundColor Green
                }
                else {
                    Write-Host "  Baseline unchanged." -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "  Failed to query AD. Baseline unchanged." -ForegroundColor Red
            }
        }
        default {
            Write-Host "  Cancelled." -ForegroundColor Yellow
        }
    }

    Write-Host "===== Resuming Monitoring =====" -ForegroundColor Cyan
    Write-Host ""
}

# ── Monitoring Check Functions ───────────────────────────────────────

function Check-UserChanges {
    <#
    .SYNOPSIS
        Compares current AD users against the users baseline.
        Detects: new users, deleted users, enabled/disabled changes,
        lockouts, password changes.
    #>
    [CmdletBinding()]
    param()

    $currentUsers = Get-AllUsersSnapshot
    $alertCount = 0

    # Build lookup hashtables for fast comparison
    $baselineLookup = @{}
    foreach ($bu in $Script:UsersBaseline) {
        $baselineLookup[$bu.SamAccountName] = $bu
    }

    $currentLookup = @{}
    foreach ($cu in $currentUsers) {
        $currentLookup[$cu.SamAccountName] = $cu
    }

    # Check for new users (in current but not in baseline)
    foreach ($cu in $currentUsers) {
        if (-not $baselineLookup.ContainsKey($cu.SamAccountName)) {
            $alertCount++
            Write-Log -Level ALERT -Message "New user account detected: $($cu.Username) (Enabled: $($cu.Enabled))"
        }
    }

    # Check for deleted users (in baseline but not in current)
    foreach ($bu in $Script:UsersBaseline) {
        if (-not $currentLookup.ContainsKey($bu.SamAccountName)) {
            $alertCount++
            Write-Log -Level ALERT -Message "User account DELETED from AD: $($bu.Username)"
        }
    }

    # Check for status and password changes
    foreach ($cu in $currentUsers) {
        if ($baselineLookup.ContainsKey($cu.SamAccountName)) {
            $bu = $baselineLookup[$cu.SamAccountName]

            # Enabled/disabled change
            if ($cu.Enabled -ne $bu.Enabled) {
                $alertCount++
                if ($cu.Enabled -eq 'True') {
                    Write-Log -Level ALERT -Message "User account ENABLED: $($cu.Username) (was disabled in baseline)"
                }
                else {
                    Write-Log -Level ALERT -Message "User account DISABLED: $($cu.Username) (was enabled in baseline)"
                }
            }

            # Lockout
            if ($cu.LockedOut -eq 'True' -and $bu.LockedOut -ne 'True') {
                $alertCount++
                Write-Log -Level WARNING -Message "User account LOCKED OUT: $($cu.Username)"
            }

            # Password change
            if ($cu.PasswordLastSet -ne $bu.PasswordLastSet -and $cu.PasswordLastSet -ne "") {
                $alertCount++
                Write-Log -Level FINDING -Message "Password changed for user: $($cu.Username) (new: $($cu.PasswordLastSet), baseline: $($bu.PasswordLastSet))"
            }
        }
    }

    return [PSCustomObject]@{
        AlertCount   = $alertCount
        CurrentCount = $currentUsers.Count
        CurrentUsers = $currentUsers
    }
}

function Check-GroupMembershipChanges {
    <#
    .SYNOPSIS
        Compares current group memberships against the groups baseline.
        Detects: members added to groups, members removed from groups,
        new groups, deleted groups.
    #>
    [CmdletBinding()]
    param()

    $currentMemberships = Get-AllGroupMembershipsSnapshot
    $alertCount = 0

    # Build lookup sets: "GroupName|MemberSam"
    $baselineSet = @{}
    foreach ($bm in $Script:GroupsBaseline) {
        $key = "$($bm.GroupName)|$($bm.MemberSam)"
        $baselineSet[$key] = $bm
    }

    $currentSet = @{}
    foreach ($cm in $currentMemberships) {
        $key = "$($cm.GroupName)|$($cm.MemberSam)"
        $currentSet[$key] = $cm
    }

    # Privileged groups get higher-severity alerts
    $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators',
        'Account Operators', 'Server Operators', 'Backup Operators', 'DnsAdmins',
        'Group Policy Creator Owners')

    # Members added to groups (in current but not baseline)
    foreach ($key in $currentSet.Keys) {
        if (-not $baselineSet.ContainsKey($key)) {
            $cm = $currentSet[$key]
            $alertCount++
            $isPrivileged = $cm.GroupName -in $privilegedGroups
            if ($isPrivileged) {
                Write-Log -Level ALERT -Message "Member ADDED to privileged group '$($cm.GroupName)': $($cm.MemberUsername)"

                # Prompt for action on privileged group additions
                Write-Host ""
                Write-Host "  ALERT: $($cm.MemberUsername) was added to $($cm.GroupName)" -ForegroundColor Red
                Write-Host "  This is a privileged group - this could indicate an attack." -ForegroundColor Yellow
                Write-Host "  What would you like to do?" -ForegroundColor Yellow
                Write-Host "    D = Disable the account" -ForegroundColor White
                Write-Host "    R = Remove from group" -ForegroundColor White
                Write-Host "    I = Ignore (accept into baseline)" -ForegroundColor White
                Write-Host "    S = Skip (do nothing for now)" -ForegroundColor White
                $action = Read-Host "  Choice"

                $adParams = Get-ADTargetParams

                switch ($action.ToUpper()) {
                    'D' {
                        try {
                            Disable-ADAccount -Identity $cm.MemberSam @adParams -ErrorAction Stop
                            Write-Log -Level ACTION -Message "Disabled account: $($cm.MemberUsername)"
                            Write-Host "  Account disabled." -ForegroundColor Green
                        }
                        catch {
                            Write-Log -Level ERROR -Message "Failed to disable account '$($cm.MemberUsername)': $_"
                        }
                    }
                    'R' {
                        try {
                            Remove-ADGroupMember -Identity $cm.GroupName -Members $cm.MemberSam @adParams -Confirm:$false -ErrorAction Stop
                            Write-Log -Level ACTION -Message "Removed $($cm.MemberUsername) from $($cm.GroupName)"
                            Write-Host "  Removed from group." -ForegroundColor Green
                        }
                        catch {
                            Write-Log -Level ERROR -Message "Failed to remove '$($cm.MemberUsername)' from '$($cm.GroupName)': $_"
                        }
                    }
                    'I' {
                        Write-Log -Level INFO -Message "Accepted $($cm.MemberUsername) in $($cm.GroupName) into baseline"
                        Write-Host "  Will be included in next baseline refresh." -ForegroundColor Green
                    }
                    default {
                        Write-Log -Level WARNING -Message "Skipped action for new member: $($cm.MemberUsername) in $($cm.GroupName)"
                        Write-Host "  Skipped." -ForegroundColor Yellow
                    }
                }
            }
            else {
                Write-Log -Level FINDING -Message "Member ADDED to group '$($cm.GroupName)': $($cm.MemberUsername)"
            }
        }
    }

    # Members removed from groups (in baseline but not current)
    foreach ($key in $baselineSet.Keys) {
        if (-not $currentSet.ContainsKey($key)) {
            $bm = $baselineSet[$key]
            $alertCount++
            $isPrivileged = $bm.GroupName -in $privilegedGroups
            if ($isPrivileged) {
                Write-Log -Level ALERT -Message "Member REMOVED from privileged group '$($bm.GroupName)': $($bm.MemberUsername)"
            }
            else {
                Write-Log -Level FINDING -Message "Member REMOVED from group '$($bm.GroupName)': $($bm.MemberUsername)"
            }
        }
    }

    # Check for entirely new groups
    $baselineGroups = @($Script:GroupsBaseline | Select-Object -ExpandProperty GroupName -Unique)
    $currentGroups = @($currentMemberships | Select-Object -ExpandProperty GroupName -Unique)
    foreach ($cg in $currentGroups) {
        if ($cg -notin $baselineGroups) {
            $alertCount++
            Write-Log -Level ALERT -Message "New group detected: '$cg'"
        }
    }

    # Check for deleted groups
    foreach ($bg in $baselineGroups) {
        if ($bg -notin $currentGroups) {
            $alertCount++
            Write-Log -Level ALERT -Message "Group DELETED from AD: '$bg'"
        }
    }

    return [PSCustomObject]@{
        AlertCount          = $alertCount
        CurrentMemberships  = $currentMemberships
    }
}

function Check-EventLogAlerts {
    <#
    .SYNOPSIS
        Checks Security event log for new account creation (4720),
        group membership additions (4728, 4732, 4756), and
        group membership removals (4729, 4733, 4757).
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0

    $startTime = $Script:LastPollTime
    if ($null -eq $startTime) {
        $startTime = (Get-Date).AddSeconds(-$Script:PollIntervalSec)
    }

    $dcTarget = $Script:TargetDC

    # Event ID 4720 = user account created
    try {
        $events = Get-WinEvent -ComputerName $dcTarget -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4720
            StartTime = $startTime
        } -ErrorAction Stop

        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $performer  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            Write-Log -Level ALERT -Message "New account created: '$targetUser' by '$performer' at $($evt.TimeCreated)"
            $alertCount++
        }
    }
    catch [Exception] {
        $msg = $_.Exception.Message
        if ($msg -notlike "*No events were found*") {
            Write-Log -Level WARNING -Message "Could not query event log for new accounts: $msg"
        }
    }

    # Event ID 4726 = user account deleted
    try {
        $events = Get-WinEvent -ComputerName $dcTarget -FilterHashtable @{
            LogName   = 'Security'
            Id        = 4726
            StartTime = $startTime
        } -ErrorAction Stop

        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $performer  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            Write-Log -Level ALERT -Message "Account deleted: '$targetUser' by '$performer' at $($evt.TimeCreated)"
            $alertCount++
        }
    }
    catch [Exception] {
        $msg = $_.Exception.Message
        if ($msg -notlike "*No events were found*") {
            Write-Log -Level WARNING -Message "Could not query event log for deleted accounts: $msg"
        }
    }

    # Event IDs for group member add: 4728 (global), 4732 (local), 4756 (universal)
    try {
        $events = Get-WinEvent -ComputerName $dcTarget -FilterHashtable @{
            LogName   = 'Security'
            Id        = @(4728, 4732, 4756)
            StartTime = $startTime
        } -ErrorAction Stop

        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $memberName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'MemberName' }).'#text'
            $memberSid  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'MemberSid' }).'#text'
            $groupName  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $performer  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            Write-Log -Level ALERT -Message "Member added to group: '$memberName' added to '$groupName' by '$performer' at $($evt.TimeCreated)"
            $alertCount++
        }
    }
    catch [Exception] {
        $msg = $_.Exception.Message
        if ($msg -notlike "*No events were found*") {
            Write-Log -Level WARNING -Message "Could not query event log for group additions: $msg"
        }
    }

    # Event IDs for group member remove: 4729 (global), 4733 (local), 4757 (universal)
    try {
        $events = Get-WinEvent -ComputerName $dcTarget -FilterHashtable @{
            LogName   = 'Security'
            Id        = @(4729, 4733, 4757)
            StartTime = $startTime
        } -ErrorAction Stop

        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $memberName = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'MemberName' }).'#text'
            $groupName  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $performer  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            Write-Log -Level ALERT -Message "Member removed from group: '$memberName' removed from '$groupName' by '$performer' at $($evt.TimeCreated)"
            $alertCount++
        }
    }
    catch [Exception] {
        $msg = $_.Exception.Message
        if ($msg -notlike "*No events were found*") {
            Write-Log -Level WARNING -Message "Could not query event log for group removals: $msg"
        }
    }

    # Event ID 4723/4724 = password change/reset
    try {
        $events = Get-WinEvent -ComputerName $dcTarget -FilterHashtable @{
            LogName   = 'Security'
            Id        = @(4723, 4724)
            StartTime = $startTime
        } -ErrorAction Stop

        foreach ($evt in $events) {
            $xml = [xml]$evt.ToXml()
            $targetUser = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'TargetUserName' }).'#text'
            $performer  = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'SubjectUserName' }).'#text'
            $evtType = if ($evt.Id -eq 4723) { "changed their password" } else { "password was reset by '$performer'" }
            Write-Log -Level FINDING -Message "Password event: '$targetUser' $evtType at $($evt.TimeCreated)"
            $alertCount++
        }
    }
    catch [Exception] {
        $msg = $_.Exception.Message
        if ($msg -notlike "*No events were found*") {
            Write-Log -Level WARNING -Message "Could not query event log for password changes: $msg"
        }
    }

    return $alertCount
}

# ── Event-Log Helper ─────────────────────────────────────────────────

function Get-EventsSince {
    <#
    .SYNOPSIS
        Queries a Windows event log on the target DC for events since the last poll.
        Returns an empty array (not an error) when no events match.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$LogName,

        [Parameter(Mandatory)]
        [int[]]$EventIDs,

        [datetime]$Since
    )

    if ($null -eq $Since) {
        $Since = (Get-Date).AddSeconds(-$Script:PollIntervalSec)
    }

    try {
        $events = Get-WinEvent -ComputerName $Script:TargetDC -FilterHashtable @{
            LogName   = $LogName
            Id        = $EventIDs
            StartTime = $Since
        } -ErrorAction Stop
        return @($events)
    }
    catch [Exception] {
        if ($_.Exception.Message -notlike "*No events were found*") {
            Write-Log -Level WARNING -Message "Could not query $LogName for event(s) $($EventIDs -join ','): $($_.Exception.Message)"
        }
        return @()
    }
}

function Get-EventDataField {
    <#
    .SYNOPSIS
        Extracts a named field from EventData XML.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [xml]$EventXml,

        [Parameter(Mandatory)]
        [string]$FieldName
    )

    $node = $EventXml.Event.EventData.Data | Where-Object { $_.Name -eq $FieldName }
    if ($node) { return $node.'#text' }
    return $null
}

# ── Advanced Attacker Detection Checks ────────────────────────────────

function Check-KerberoastingActivity {
    <#
    .SYNOPSIS
        Detects Kerberoasting by looking for Event 4769 (Kerberos Service Ticket
        requested) with RC4 encryption (TicketEncryptionType 0x17).
        Alerts when a single user requests RC4 tickets above the threshold.
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }
    $settings = Get-ADScannerSettings
    $threshold = if ($settings.PSObject.Properties['KerberoastThreshold']) { $settings.KerberoastThreshold } else { 3 }

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(4769) -Since $startTime

    # Group by requesting user, filter for RC4 (0x17 = 23 decimal)
    $rc4Requests = @{}
    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $encType = Get-EventDataField -EventXml $xml -FieldName 'TicketEncryptionType'
        if ($encType -eq '0x17') {
            $requestUser = Get-EventDataField -EventXml $xml -FieldName 'TargetUserName'
            $serviceName = Get-EventDataField -EventXml $xml -FieldName 'ServiceName'
            $clientUser  = Get-EventDataField -EventXml $xml -FieldName 'IpAddress'
            $key = Get-EventDataField -EventXml $xml -FieldName 'TargetUserName'
            # Group by the account requesting the ticket
            $reqAccount = Get-EventDataField -EventXml $xml -FieldName 'TargetDomainName'
            $reqUser = Get-EventDataField -EventXml $xml -FieldName 'IpAddress'
            if (-not $rc4Requests.ContainsKey($reqUser)) {
                $rc4Requests[$reqUser] = @()
            }
            $rc4Requests[$reqUser] += $serviceName
        }
    }

    foreach ($source in $rc4Requests.Keys) {
        $count = $rc4Requests[$source].Count
        if ($count -ge $threshold) {
            $alertCount++
            $targets = ($rc4Requests[$source] | Select-Object -Unique) -join ', '
            Write-Log -Level ALERT -Message "Possible Kerberoasting detected! Source $source requested $count RC4 service tickets (threshold: $threshold). Targets: $targets"
        }
    }

    return $alertCount
}

function Check-ASREPRoasting {
    <#
    .SYNOPSIS
        Detects AS-REP Roasting by looking for Event 4768 (Kerberos Authentication
        Ticket requested) where PreAuthType is 0 (no pre-authentication).
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(4768) -Since $startTime

    $noPreAuth = @{}
    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $preAuthType = Get-EventDataField -EventXml $xml -FieldName 'PreAuthType'
        if ($preAuthType -eq '0') {
            $targetUser = Get-EventDataField -EventXml $xml -FieldName 'TargetUserName'
            $sourceIP   = Get-EventDataField -EventXml $xml -FieldName 'IpAddress'
            if (-not $noPreAuth.ContainsKey($targetUser)) {
                $noPreAuth[$targetUser] = @()
            }
            $noPreAuth[$targetUser] += $sourceIP
        }
    }

    foreach ($user in $noPreAuth.Keys) {
        $alertCount++
        $sources = ($noPreAuth[$user] | Select-Object -Unique) -join ', '
        $count = $noPreAuth[$user].Count
        Write-Log -Level ALERT -Message "Possible AS-REP Roasting! $count pre-auth-disabled TGT request(s) for '$user' from: $sources"
    }

    return $alertCount
}

function Check-DCSyncAttack {
    <#
    .SYNOPSIS
        Detects DCSync attacks by looking for Event 4662 (directory service object accessed)
        with the replication GUIDs, where the subject is NOT a DC machine account.
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    # DS-Replication-Get-Changes and DS-Replication-Get-Changes-All GUIDs
    $replicationGUIDs = @(
        '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
        '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
    )

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(4662) -Since $startTime

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $properties = Get-EventDataField -EventXml $xml -FieldName 'Properties'
        if ($null -eq $properties) { continue }

        $hasReplicationGUID = $false
        foreach ($guid in $replicationGUIDs) {
            if ($properties -like "*$guid*") {
                $hasReplicationGUID = $true
                break
            }
        }

        if ($hasReplicationGUID) {
            $subjectUser = Get-EventDataField -EventXml $xml -FieldName 'SubjectUserName'
            # DC machine accounts end with $ — those are normal replication
            if ($subjectUser -and -not $subjectUser.EndsWith('$')) {
                $alertCount++
                $subjectDomain = Get-EventDataField -EventXml $xml -FieldName 'SubjectDomainName'
                Write-Log -Level ALERT -Message "Possible DCSync attack! Replication rights used by non-machine account: $subjectDomain\$subjectUser at $($evt.TimeCreated)"
            }
        }
    }

    return $alertCount
}

function Check-BruteForceSpray {
    <#
    .SYNOPSIS
        Detects brute force and password spray attacks by analyzing Event 4625
        (failed logon). Alerts if a single IP targets many accounts (spray) or
        a single account has many failures (brute force).
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }
    $settings = Get-ADScannerSettings
    $bruteThreshold = if ($settings.PSObject.Properties['BruteForceThreshold']) { $settings.BruteForceThreshold } else { 10 }
    $sprayThreshold = if ($settings.PSObject.Properties['PasswordSprayThreshold']) { $settings.PasswordSprayThreshold } else { 5 }

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(4625) -Since $startTime

    # Track by source IP -> distinct targets, and by target -> failure count
    $sourceToTargets = @{}
    $targetFailures  = @{}

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $targetUser = Get-EventDataField -EventXml $xml -FieldName 'TargetUserName'
        $sourceIP   = Get-EventDataField -EventXml $xml -FieldName 'IpAddress'
        if ([string]::IsNullOrWhiteSpace($sourceIP)) { $sourceIP = "unknown" }

        # Track source -> targets
        if (-not $sourceToTargets.ContainsKey($sourceIP)) {
            $sourceToTargets[$sourceIP] = @{}
        }
        $sourceToTargets[$sourceIP][$targetUser] = $true

        # Track target failures
        if (-not $targetFailures.ContainsKey($targetUser)) {
            $targetFailures[$targetUser] = 0
        }
        $targetFailures[$targetUser]++
    }

    # Check for password spray (one IP -> many distinct accounts)
    foreach ($ip in $sourceToTargets.Keys) {
        $distinctTargets = $sourceToTargets[$ip].Keys.Count
        if ($distinctTargets -ge $sprayThreshold) {
            $alertCount++
            $targets = ($sourceToTargets[$ip].Keys | Select-Object -First 5) -join ', '
            $more = if ($distinctTargets -gt 5) { " (and $($distinctTargets - 5) more)" } else { "" }
            Write-Log -Level ALERT -Message "Possible password spray! Source $ip targeted $distinctTargets distinct accounts (threshold: $sprayThreshold). Targets: $targets$more"
        }
    }

    # Check for brute force (many failures for one account)
    foreach ($user in $targetFailures.Keys) {
        if ($targetFailures[$user] -ge $bruteThreshold) {
            $alertCount++
            Write-Log -Level ALERT -Message "Possible brute force! Account '$user' had $($targetFailures[$user]) failed logons (threshold: $bruteThreshold)"
        }
    }

    return $alertCount
}

function Check-FailedLogons {
    <#
    .SYNOPSIS
        Reports every individual failed logon attempt (Event 4625) since the last poll.
        Unlike Check-BruteForceSpray which only alerts on threshold-based patterns,
        this check logs each failed attempt so admins have full visibility.
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(4625) -Since $startTime

    # Status codes for user-friendly failure reasons
    $statusMessages = @{
        '0xC000006A' = 'incorrect password'
        '0xC0000064' = 'account does not exist'
        '0xC0000234' = 'account locked out'
        '0xC0000072' = 'account disabled'
        '0xC000006F' = 'logon outside allowed hours'
        '0xC0000070' = 'logon from unauthorized workstation'
        '0xC0000193' = 'account expired'
        '0xC0000071' = 'password expired'
        '0xC0000133' = 'clock skew too great'
        '0xC0000224' = 'password must be changed at next logon'
    }

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $targetUser   = Get-EventDataField -EventXml $xml -FieldName 'TargetUserName'
        $targetDomain = Get-EventDataField -EventXml $xml -FieldName 'TargetDomainName'
        $sourceIP     = Get-EventDataField -EventXml $xml -FieldName 'IpAddress'
        $workstation  = Get-EventDataField -EventXml $xml -FieldName 'WorkstationName'
        $logonType    = Get-EventDataField -EventXml $xml -FieldName 'LogonType'
        $subStatus    = Get-EventDataField -EventXml $xml -FieldName 'SubStatus'
        $status       = Get-EventDataField -EventXml $xml -FieldName 'Status'

        # Skip empty/anonymous
        if ([string]::IsNullOrWhiteSpace($targetUser) -or $targetUser -eq 'ANONYMOUS LOGON') { continue }

        # Determine the reason using SubStatus first (more specific), then Status
        $reasonCode = if ($subStatus -and $subStatus -ne '0x0') { $subStatus.ToUpper() } else { if ($status) { $status.ToUpper() } else { $null } }
        $reason = "unknown reason"
        if ($reasonCode -and $statusMessages.ContainsKey($reasonCode)) {
            $reason = $statusMessages[$reasonCode]
        }
        elseif ($reasonCode) {
            $reason = "status $reasonCode"
        }

        $sourceInfo = if (-not [string]::IsNullOrWhiteSpace($sourceIP) -and $sourceIP -ne '-') { $sourceIP } else { $workstation }
        if ([string]::IsNullOrWhiteSpace($sourceInfo)) { $sourceInfo = "unknown source" }

        $alertCount++
        Write-Log -Level FINDING -Message "Failed logon: '$targetDomain\$targetUser' from $sourceInfo ($reason) at $($evt.TimeCreated)"
    }

    return $alertCount
}

function Check-SuspiciousLogons {
    <#
    .SYNOPSIS
        Detects suspicious logon patterns: admin accounts on non-DC machines,
        and NTLM authentication on Kerberos-capable accounts (Pass-the-Hash indicator).
        Event 4624, LogonType 3 (network), 9 (NewCredentials), 10 (RemoteInteractive).
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(4624) -Since $startTime

    # Get admin accounts from baseline for checking
    $adminSams = @{}
    $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins', 'Administrators')
    foreach ($m in $Script:GroupsBaseline) {
        if ($m.GroupName -in $privilegedGroups) {
            $adminSams[$m.MemberSam] = $m.GroupName
        }
    }

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $logonType = Get-EventDataField -EventXml $xml -FieldName 'LogonType'
        if ($logonType -notin @('3', '9', '10')) { continue }

        $targetUser   = Get-EventDataField -EventXml $xml -FieldName 'TargetUserName'
        $targetDomain = Get-EventDataField -EventXml $xml -FieldName 'TargetDomainName'
        $authPackage  = Get-EventDataField -EventXml $xml -FieldName 'AuthenticationPackageName'
        $workstation  = Get-EventDataField -EventXml $xml -FieldName 'WorkstationName'
        $sourceIP     = Get-EventDataField -EventXml $xml -FieldName 'IpAddress'

        # Skip machine accounts
        if ($targetUser -and $targetUser.EndsWith('$')) { continue }
        # Skip anonymous / empty
        if ([string]::IsNullOrWhiteSpace($targetUser) -or $targetUser -eq 'ANONYMOUS LOGON') { continue }

        # Check: admin account logging into non-DC machine
        if ($adminSams.ContainsKey($targetUser)) {
            $logonTarget = $evt.MachineName
            if ($logonTarget -and $logonTarget -ne $Script:TargetDC -and $logonTarget -ne "$($Script:TargetDC).$($Script:DomainName)") {
                $alertCount++
                Write-Log -Level ALERT -Message "Admin logon on non-DC! '$targetDomain\$targetUser' ($($adminSams[$targetUser])) logged into $logonTarget from $sourceIP (LogonType $logonType)"
            }
        }

        # Check: NTLM auth on domain account (Pass-the-Hash indicator)
        if ($authPackage -eq 'NTLM' -and $targetDomain -and $targetDomain -ne $env:COMPUTERNAME -and $targetDomain -ne 'NT AUTHORITY') {
            $alertCount++
            Write-Log -Level ALERT -Message "NTLM logon for domain account (possible Pass-the-Hash): '$targetDomain\$targetUser' from $sourceIP/$workstation (LogonType $logonType)"
        }
    }

    return $alertCount
}

function Check-LogTampering {
    <#
    .SYNOPSIS
        Detects Security log clearing via Event 1102. Any occurrence is a critical alert.
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(1102) -Since $startTime

    foreach ($evt in $events) {
        $alertCount++
        $xml = [xml]$evt.ToXml()
        $subjectUser   = $null
        $subjectDomain = $null
        # Event 1102 stores user data in UserData, not EventData
        $userDataNode = $xml.Event.UserData
        if ($userDataNode -and $userDataNode.LogFileCleared) {
            $subjectUser   = $userDataNode.LogFileCleared.SubjectUserName
            $subjectDomain = $userDataNode.LogFileCleared.SubjectDomainName
        }
        if ($subjectUser) {
            Write-Log -Level ALERT -Message "CRITICAL: Security log was CLEARED by $subjectDomain\$subjectUser at $($evt.TimeCreated)!"
        }
        else {
            Write-Log -Level ALERT -Message "CRITICAL: Security log was CLEARED at $($evt.TimeCreated)!"
        }
    }

    return $alertCount
}

function Check-HoneyTokenActivity {
    <#
    .SYNOPSIS
        Detects any authentication activity (logon, failed logon, TGT request)
        involving canary/honey token accounts. Any occurrence is a critical alert.
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    if ($Script:CanaryAccounts.Count -eq 0) { return 0 }

    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    # Build a lookup set of canary SAM account names
    $canarySet = @{}
    foreach ($c in $Script:CanaryAccounts) {
        $canarySet[$c.SamAccountName.ToLower()] = $c.Description
    }

    # Check logon success (4624), logon failure (4625), TGT request (4768)
    $events = Get-EventsSince -LogName 'Security' -EventIDs @(4624, 4625, 4768) -Since $startTime

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $targetUser = Get-EventDataField -EventXml $xml -FieldName 'TargetUserName'
        if ($null -eq $targetUser) { continue }

        if ($canarySet.ContainsKey($targetUser.ToLower())) {
            $alertCount++
            $sourceIP = Get-EventDataField -EventXml $xml -FieldName 'IpAddress'
            $desc = $canarySet[$targetUser.ToLower()]
            $eventType = switch ($evt.Id) {
                4624 { "successful logon" }
                4625 { "failed logon" }
                4768 { "Kerberos TGT request" }
                default { "authentication event (ID $($evt.Id))" }
            }
            Write-Log -Level ALERT -Message "CRITICAL: Honey token account '$targetUser' triggered! Event: $eventType from $sourceIP at $($evt.TimeCreated). Description: $desc"
        }
    }

    return $alertCount
}

function Check-GPOModifications {
    <#
    .SYNOPSIS
        Detects Group Policy Object modifications via Event 5136 (directory object modified)
        where the DN contains CN=Policies,CN=System.
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(5136) -Since $startTime

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $objectDN = Get-EventDataField -EventXml $xml -FieldName 'ObjectDN'
        if ($null -eq $objectDN) { continue }
        if ($objectDN -notlike "*CN=Policies,CN=System*") { continue }

        $alertCount++
        $subjectUser   = Get-EventDataField -EventXml $xml -FieldName 'SubjectUserName'
        $subjectDomain = Get-EventDataField -EventXml $xml -FieldName 'SubjectDomainName'
        $attrName      = Get-EventDataField -EventXml $xml -FieldName 'AttributeLDAPDisplayName'
        Write-Log -Level ALERT -Message "GPO modified! '$objectDN' attribute '$attrName' changed by $subjectDomain\$subjectUser at $($evt.TimeCreated)"
    }

    return $alertCount
}

function Check-MachineAccountCreation {
    <#
    .SYNOPSIS
        Detects new computer account creation via Event 4741.
        Extra alert if the creator is not a domain admin.
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    # Get admin SAMs for comparison
    $adminSams = @{}
    $privilegedGroups = @('Domain Admins', 'Enterprise Admins', 'Schema Admins')
    foreach ($m in $Script:GroupsBaseline) {
        if ($m.GroupName -in $privilegedGroups) {
            $adminSams[$m.MemberSam] = $true
        }
    }

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(4741) -Since $startTime

    foreach ($evt in $events) {
        $alertCount++
        $xml = [xml]$evt.ToXml()
        $targetComputer = Get-EventDataField -EventXml $xml -FieldName 'TargetUserName'
        $performer      = Get-EventDataField -EventXml $xml -FieldName 'SubjectUserName'
        $performerDomain = Get-EventDataField -EventXml $xml -FieldName 'SubjectDomainName'

        $level = "ALERT"
        $extra = ""
        if (-not $adminSams.ContainsKey($performer)) {
            $extra = " (creator is NOT a domain admin!)"
        }
        Write-Log -Level ALERT -Message "New computer account created: '$targetComputer' by $performerDomain\$performer at $($evt.TimeCreated)$extra"
    }

    return $alertCount
}

function Check-SPNModification {
    <#
    .SYNOPSIS
        Detects SPN modifications via Event 5136 where the modified attribute
        is servicePrincipalName on a user object. Critical if the target has AdminCount=1.
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(5136) -Since $startTime

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $attrName = Get-EventDataField -EventXml $xml -FieldName 'AttributeLDAPDisplayName'
        if ($attrName -ne 'servicePrincipalName') { continue }

        $objectDN      = Get-EventDataField -EventXml $xml -FieldName 'ObjectDN'
        $objectClass   = Get-EventDataField -EventXml $xml -FieldName 'ObjectClass'
        $subjectUser   = Get-EventDataField -EventXml $xml -FieldName 'SubjectUserName'
        $subjectDomain = Get-EventDataField -EventXml $xml -FieldName 'SubjectDomainName'
        $attrValue     = Get-EventDataField -EventXml $xml -FieldName 'AttributeValue'

        # Only alert on user objects, not computer objects
        if ($objectClass -eq 'computer') { continue }

        $alertCount++
        $severity = "ALERT"
        $extra = ""

        # Check if the target account has AdminCount=1
        try {
            $adParams = Get-ADTargetParams
            # Extract SAM from DN
            $targetObj = Get-ADUser -Filter { DistinguishedName -eq $objectDN } -Properties AdminCount @adParams -ErrorAction SilentlyContinue
            if ($targetObj -and $targetObj.AdminCount -eq 1) {
                $extra = " CRITICAL: target has AdminCount=1 (admin account)!"
            }
        }
        catch { }

        Write-Log -Level ALERT -Message "SPN modified on '$objectDN' by $subjectDomain\$subjectUser at $($evt.TimeCreated). New SPN value: $attrValue.$extra"
    }

    return $alertCount
}

function Check-DCPersistence {
    <#
    .SYNOPSIS
        Detects persistence mechanisms on Domain Controllers: scheduled task creation
        (Event 4698) and service installation (Event 7045 from System log).
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    # Event 4698 = Scheduled task created (Security log)
    $events = Get-EventsSince -LogName 'Security' -EventIDs @(4698) -Since $startTime

    foreach ($evt in $events) {
        $alertCount++
        $xml = [xml]$evt.ToXml()
        $subjectUser   = Get-EventDataField -EventXml $xml -FieldName 'SubjectUserName'
        $subjectDomain = Get-EventDataField -EventXml $xml -FieldName 'SubjectDomainName'
        $taskName      = Get-EventDataField -EventXml $xml -FieldName 'TaskName'
        $taskContent   = Get-EventDataField -EventXml $xml -FieldName 'TaskContent'

        $cmdInfo = ""
        if ($taskContent) {
            # Try to extract the command from the task XML
            try {
                $taskXml = [xml]$taskContent
                $execNode = $taskXml.Task.Actions.Exec
                if ($execNode) {
                    $cmdInfo = " Command: $($execNode.Command) $($execNode.Arguments)"
                }
            }
            catch { }
        }

        Write-Log -Level ALERT -Message "Scheduled task created on DC! Task: '$taskName' by $subjectDomain\$subjectUser at $($evt.TimeCreated).$cmdInfo"
    }

    # Event 7045 = New service installed (System log)
    $svcEvents = Get-EventsSince -LogName 'System' -EventIDs @(7045) -Since $startTime

    foreach ($evt in $svcEvents) {
        $alertCount++
        $xml = [xml]$evt.ToXml()
        # Event 7045 stores data differently - in EventData without named fields
        $dataNodes = $xml.Event.EventData.Data
        $serviceName = if ($dataNodes.Count -ge 1) { $dataNodes[0].'#text' } else { "unknown" }
        $imagePath   = if ($dataNodes.Count -ge 2) { $dataNodes[1].'#text' } else { "unknown" }
        $serviceType = if ($dataNodes.Count -ge 3) { $dataNodes[2].'#text' } else { "unknown" }
        $startType   = if ($dataNodes.Count -ge 4) { $dataNodes[3].'#text' } else { "unknown" }
        $accountName = if ($dataNodes.Count -ge 5) { $dataNodes[4].'#text' } else { "unknown" }

        Write-Log -Level ALERT -Message "New service installed on DC! Service: '$serviceName' Path: '$imagePath' Account: '$accountName' at $($evt.TimeCreated)"
    }

    return $alertCount
}

function Check-LsassAccess {
    <#
    .SYNOPSIS
        Detects potential credential dumping by monitoring Event 4663 (object access)
        where the object name contains 'lsass'. Skips known-safe processes.
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(4663) -Since $startTime

    # Known safe processes that legitimately access LSASS
    $safeProcesses = @(
        'wininit.exe', 'csrss.exe', 'lsass.exe', 'services.exe', 'svchost.exe',
        'MsMpEng.exe', 'MsSense.exe', 'NisSrv.exe', 'WmiPrvSE.exe',
        'taskhostw.exe', 'winlogon.exe', 'LogonUI.exe'
    )

    foreach ($evt in $events) {
        $xml = [xml]$evt.ToXml()
        $objectName = Get-EventDataField -EventXml $xml -FieldName 'ObjectName'
        if ($null -eq $objectName -or $objectName -notlike "*lsass*") { continue }

        $processName = Get-EventDataField -EventXml $xml -FieldName 'ProcessName'
        $subjectUser = Get-EventDataField -EventXml $xml -FieldName 'SubjectUserName'

        # Check if the process is known safe
        $isSafe = $false
        foreach ($safe in $safeProcesses) {
            if ($processName -like "*\$safe") {
                $isSafe = $true
                break
            }
        }

        if (-not $isSafe) {
            $alertCount++
            Write-Log -Level ALERT -Message "Possible credential dumping! LSASS accessed by process '$processName' as user '$subjectUser' at $($evt.TimeCreated)"
        }
    }

    return $alertCount
}

function Check-TrustChanges {
    <#
    .SYNOPSIS
        Detects domain trust creation (Event 4706) and removal (Event 4707).
        Any occurrence is an alert.
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0
    $startTime = if ($Script:LastPollTime) { $Script:LastPollTime } else { (Get-Date).AddSeconds(-$Script:PollIntervalSec) }

    $events = Get-EventsSince -LogName 'Security' -EventIDs @(4706, 4707) -Since $startTime

    foreach ($evt in $events) {
        $alertCount++
        $xml = [xml]$evt.ToXml()
        $subjectUser   = Get-EventDataField -EventXml $xml -FieldName 'SubjectUserName'
        $subjectDomain = Get-EventDataField -EventXml $xml -FieldName 'SubjectDomainName'
        $trustName     = Get-EventDataField -EventXml $xml -FieldName 'TrustName'
        if ($null -eq $trustName) {
            $trustName = Get-EventDataField -EventXml $xml -FieldName 'DomainName'
        }

        $action = if ($evt.Id -eq 4706) { "CREATED" } else { "REMOVED" }
        Write-Log -Level ALERT -Message "Domain trust $action! Trust: '$trustName' by $subjectDomain\$subjectUser at $($evt.TimeCreated)"
    }

    return $alertCount
}

function Check-AdminSDHolderACL {
    <#
    .SYNOPSIS
        Reads the ACL on CN=AdminSDHolder,CN=System,<domainDN> each poll cycle
        and compares against the baseline. Alerts on any change.
    #>
    [CmdletBinding()]
    param()

    $alertCount = 0

    try {
        $adParams = Get-ADTargetParams
        $domain = Get-ADDomain @adParams -ErrorAction Stop
        $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$($domain.DistinguishedName)"

        # Get current ACL
        $adDriveMounted = $false
        if (-not (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)) {
            try {
                New-PSDrive -Name AD -PSProvider ActiveDirectory -Root "//RootDSE/" -ErrorAction Stop | Out-Null
                $adDriveMounted = $true
            }
            catch {
                Write-Log -Level WARNING -Message "Could not mount AD: drive for AdminSDHolder ACL check: $_"
                return 0
            }
        }

        $aclPath = "AD:\$adminSDHolderDN"
        $currentACL = Get-Acl -Path $aclPath -ErrorAction Stop

        # Serialize the ACL to a comparable string
        $aclEntries = @()
        foreach ($ace in $currentACL.Access) {
            $aclEntries += "$($ace.IdentityReference)|$($ace.ActiveDirectoryRights)|$($ace.AccessControlType)|$($ace.InheritanceType)|$($ace.ObjectType)"
        }
        $aclEntries = $aclEntries | Sort-Object
        $currentACLString = $aclEntries -join "`n"

        if ($null -eq $Script:AdminSDHolderBaseline) {
            # First run — capture baseline
            $Script:AdminSDHolderBaseline = $currentACLString
            Write-Log -Level INFO -Message "AdminSDHolder ACL baseline captured ($($aclEntries.Count) ACEs)."
        }
        else {
            # Compare
            if ($currentACLString -ne $Script:AdminSDHolderBaseline) {
                $alertCount++
                Write-Log -Level ALERT -Message "CRITICAL: AdminSDHolder ACL has been modified! This affects the permissions on ALL protected admin accounts."

                # Show what changed
                $baselineEntries = $Script:AdminSDHolderBaseline -split "`n"
                $currentEntries = $currentACLString -split "`n"

                $added = $currentEntries | Where-Object { $_ -notin $baselineEntries }
                $removed = $baselineEntries | Where-Object { $_ -notin $currentEntries }

                foreach ($a in $added) {
                    $parts = $a -split '\|'
                    Write-Log -Level ALERT -Message "  ACE ADDED: $($parts[0]) - $($parts[1]) ($($parts[2]))"
                }
                foreach ($r in $removed) {
                    $parts = $r -split '\|'
                    Write-Log -Level ALERT -Message "  ACE REMOVED: $($parts[0]) - $($parts[1]) ($($parts[2]))"
                }

                # Update baseline to current (so we don't re-alert each cycle)
                $Script:AdminSDHolderBaseline = $currentACLString
            }
        }

        if ($adDriveMounted) {
            Remove-PSDrive -Name AD -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log -Level WARNING -Message "AdminSDHolder ACL check failed: $_"
    }

    return $alertCount
}

# ── Canary Account Management ─────────────────────────────────────────

function Load-CanaryAccounts {
    [CmdletBinding()]
    param()

    $data = Import-CSVConfig -Path $Script:CanaryAccountsFile `
        -RequiredColumns @('SamAccountName','Description') `
        -FriendlyName "Canary Accounts"

    if ($null -eq $data) { return @() }
    return @($data | Where-Object { -not [string]::IsNullOrWhiteSpace($_.SamAccountName) })
}

function Update-CanaryAccountsInteractive {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "===== Canary / Honey Token Accounts =====" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Canary accounts are decoy accounts that exist in AD but are never" -ForegroundColor Gray
    Write-Host "legitimately used. Any authentication attempt against them is a" -ForegroundColor Gray
    Write-Host "strong indicator of an attacker enumerating or testing credentials." -ForegroundColor Gray
    Write-Host ""

    if ($Script:CanaryAccounts.Count -gt 0) {
        Write-Host "Current canary accounts:" -ForegroundColor Yellow
        for ($i = 0; $i -lt $Script:CanaryAccounts.Count; $i++) {
            Write-Host "  $($i+1). $($Script:CanaryAccounts[$i].SamAccountName) - $($Script:CanaryAccounts[$i].Description)" -ForegroundColor White
        }
    }
    else {
        Write-Host "No canary accounts configured." -ForegroundColor Yellow
    }

    Write-Host ""
    Write-Host "What would you like to do?" -ForegroundColor Yellow
    Write-Host "  1. Add a canary account" -ForegroundColor White
    Write-Host "  2. Remove a canary account" -ForegroundColor White
    Write-Host "  3. Cancel" -ForegroundColor White

    $choice = Read-Host "Enter choice"

    switch ($choice) {
        '1' {
            Write-Host "Enter the SamAccountName of the canary account:" -ForegroundColor Yellow
            $sam = Read-Host
            if ([string]::IsNullOrWhiteSpace($sam)) {
                Write-Host "  Cancelled." -ForegroundColor Yellow
                return
            }
            Write-Host "Enter a description (what is this account for?):" -ForegroundColor Yellow
            $desc = Read-Host
            if ([string]::IsNullOrWhiteSpace($desc)) { $desc = "Canary account" }

            $Script:CanaryAccounts += [PSCustomObject]@{
                SamAccountName = $sam
                Description    = $desc
            }
            Save-CanaryAccounts
            Write-Host "  Added '$sam' as a canary account." -ForegroundColor Green
            Write-Log -Level INFO -Message "Added canary account: $sam"
        }
        '2' {
            if ($Script:CanaryAccounts.Count -eq 0) {
                Write-Host "  No canary accounts to remove." -ForegroundColor Yellow
                return
            }
            Write-Host "Enter the number to remove:" -ForegroundColor Yellow
            $num = Read-Host
            $idx = 0
            if ([int]::TryParse($num, [ref]$idx) -and $idx -ge 1 -and $idx -le $Script:CanaryAccounts.Count) {
                $removed = $Script:CanaryAccounts[$idx - 1].SamAccountName
                $Script:CanaryAccounts = @($Script:CanaryAccounts | Where-Object { $_.SamAccountName -ne $removed })
                Save-CanaryAccounts
                Write-Host "  Removed '$removed'." -ForegroundColor Green
                Write-Log -Level INFO -Message "Removed canary account: $removed"
            }
            else {
                Write-Host "  Invalid selection." -ForegroundColor Yellow
            }
        }
        default {
            Write-Host "  Cancelled." -ForegroundColor Yellow
        }
    }

    Write-Host "===== Resuming Monitoring =====" -ForegroundColor Cyan
    Write-Host ""
}

function Save-CanaryAccounts {
    [CmdletBinding()]
    param()

    $lines = @()
    $lines += "# Canary / Honey Token Accounts"
    $lines += "# Any logon or auth attempt for these accounts triggers an alert."
    $lines += "# These should be accounts that exist in AD but are never legitimately used."
    $lines += "# Columns: SamAccountName, Description"
    $lines += "SamAccountName,Description"

    foreach ($c in $Script:CanaryAccounts) {
        $desc = $c.Description -replace '"', '""'
        if ($desc -match ',') {
            $lines += "$($c.SamAccountName),`"$desc`""
        }
        else {
            $lines += "$($c.SamAccountName),$desc"
        }
    }

    Set-Content -Path $Script:CanaryAccountsFile -Value ($lines -join "`r`n") -Encoding UTF8
}

# ── Poll Interval Selection ──────────────────────────────────────────

function Select-PollInterval {
    [CmdletBinding()]
    param()

    Write-Host ""
    Write-Host "How often should I check for changes?" -ForegroundColor Yellow
    Write-Host "  1. Every minute" -ForegroundColor White
    Write-Host "  2. Every 3 minutes" -ForegroundColor White
    Write-Host "  3. Every 5 minutes [default]" -ForegroundColor White
    Write-Host "  4. Every 10 minutes" -ForegroundColor White
    Write-Host ""
    Write-Host "Note: Each poll queries all users and groups. On large domains," -ForegroundColor Gray
    Write-Host "shorter intervals may cause noticeable load." -ForegroundColor Gray

    $choice = Read-Host "Enter choice (1-4)"

    switch ($choice) {
        '1' { $Script:PollIntervalSec = 60;  Write-Host "  Polling every 1 minute." -ForegroundColor Green }
        '2' { $Script:PollIntervalSec = 180; Write-Host "  Polling every 3 minutes." -ForegroundColor Green }
        '4' { $Script:PollIntervalSec = 600; Write-Host "  Polling every 10 minutes." -ForegroundColor Green }
        default { $Script:PollIntervalSec = 300; Write-Host "  Polling every 5 minutes." -ForegroundColor Green }
    }
}

# ── Graceful Shutdown ────────────────────────────────────────────────

function Stop-Monitor {
    [CmdletBinding()]
    param()

    $Script:MonitorRunning = $false
    Write-Host ""
    Write-Host ""
    Write-Host "===== AD Monitor Shutting Down =====" -ForegroundColor Yellow

    Write-Log -Level INFO -Message "AD Monitor stopped after $Script:PollCount poll(s)."

    $generateReport = Read-YesNo -Prompt "Would you like to generate a session report?" -Default $true
    if ($generateReport) {
        New-ADScannerReport -ScriptName "AD Monitor" -PrintToConsole
    }

    Write-Host ""
    Write-Host "Goodbye." -ForegroundColor Cyan
}

# ── Monitoring Loop ──────────────────────────────────────────────────

function Start-MonitoringLoop {
    [CmdletBinding()]
    param()

    $Script:MonitorRunning = $true
    $intervalMinutes = [math]::Round($Script:PollIntervalSec / 60, 1)

    Write-Host ""
    Write-Host "===== AD Monitor - Running (polling every $intervalMinutes minutes) =====" -ForegroundColor Cyan
    Write-Host "Press Ctrl+C to stop | B = Update baseline | C = Canary accounts | R = Generate report" -ForegroundColor Gray
    Write-Host ""

    [Console]::TreatControlCAsInput = $true

    try {
        while ($Script:MonitorRunning) {
            # ── Perform poll ─────────────────────────────────────
            $Script:PollCount++
            $pollStart = Get-Date
            $timeStamp = Get-Date -Format "HH:mm:ss"

            $totalAlerts = 0

            # 1. User changes (new/deleted users, enabled/disabled, password, lockout)
            $userResult = $null
            try {
                $userResult = Check-UserChanges
                $totalAlerts += $userResult.AlertCount
            }
            catch {
                Write-Log -Level ERROR -Message "User changes check failed: $_"
            }

            # 2. Group membership changes
            $groupResult = $null
            try {
                $groupResult = Check-GroupMembershipChanges
                $totalAlerts += $groupResult.AlertCount
            }
            catch {
                Write-Log -Level ERROR -Message "Group membership check failed: $_"
            }

            # 3. Event log alerts (account creation/deletion, group changes, password events)
            $eventAlerts = 0
            try {
                $eventAlerts = Check-EventLogAlerts
                $totalAlerts += $eventAlerts
            }
            catch {
                Write-Log -Level ERROR -Message "Event log check failed: $_"
            }

            # 4. Kerberoasting detection
            try { $totalAlerts += Check-KerberoastingActivity }
            catch { Write-Log -Level ERROR -Message "Kerberoasting check failed: $_" }

            # 5. AS-REP Roasting detection
            try { $totalAlerts += Check-ASREPRoasting }
            catch { Write-Log -Level ERROR -Message "AS-REP Roasting check failed: $_" }

            # 6. DCSync attack detection
            try { $totalAlerts += Check-DCSyncAttack }
            catch { Write-Log -Level ERROR -Message "DCSync check failed: $_" }

            # 7. Brute force / password spray detection
            try { $totalAlerts += Check-BruteForceSpray }
            catch { Write-Log -Level ERROR -Message "Brute force/spray check failed: $_" }

            # 8. Individual failed logon attempts
            try { $totalAlerts += Check-FailedLogons }
            catch { Write-Log -Level ERROR -Message "Failed logons check failed: $_" }

            # 9. Suspicious logons (admin on non-DC, NTLM/PtH)
            try { $totalAlerts += Check-SuspiciousLogons }
            catch { Write-Log -Level ERROR -Message "Suspicious logons check failed: $_" }

            # 9. Log tampering detection
            try { $totalAlerts += Check-LogTampering }
            catch { Write-Log -Level ERROR -Message "Log tampering check failed: $_" }

            # 10. Honey token / canary account activity
            try { $totalAlerts += Check-HoneyTokenActivity }
            catch { Write-Log -Level ERROR -Message "Honey token check failed: $_" }

            # 11. GPO modifications
            try { $totalAlerts += Check-GPOModifications }
            catch { Write-Log -Level ERROR -Message "GPO modification check failed: $_" }

            # 12. Machine account creation
            try { $totalAlerts += Check-MachineAccountCreation }
            catch { Write-Log -Level ERROR -Message "Machine account creation check failed: $_" }

            # 13. SPN modification detection
            try { $totalAlerts += Check-SPNModification }
            catch { Write-Log -Level ERROR -Message "SPN modification check failed: $_" }

            # 14. DC persistence (scheduled tasks, services on DCs)
            try { $totalAlerts += Check-DCPersistence }
            catch { Write-Log -Level ERROR -Message "DC persistence check failed: $_" }

            # 15. LSASS access detection
            try { $totalAlerts += Check-LsassAccess }
            catch { Write-Log -Level ERROR -Message "LSASS access check failed: $_" }

            # 16. Domain trust changes
            try { $totalAlerts += Check-TrustChanges }
            catch { Write-Log -Level ERROR -Message "Trust changes check failed: $_" }

            # 17. AdminSDHolder ACL changes
            try { $totalAlerts += Check-AdminSDHolderACL }
            catch { Write-Log -Level ERROR -Message "AdminSDHolder ACL check failed: $_" }

            # ── Summary line ──────────────────────────────────────
            $userCount = $Script:UsersBaseline.Count
            $groupCount = @($Script:GroupsBaseline | Select-Object -ExpandProperty GroupName -Unique).Count
            $currentUserCount = 0
            if ($null -ne $userResult) {
                $currentUserCount = $userResult.CurrentCount
            }

            if ($totalAlerts -eq 0) {
                Write-Host "[$timeStamp] Poll #$($Script:PollCount) - All clear. $userCount users, $groupCount groups in baseline. No changes detected." -ForegroundColor Green
            }
            else {
                Write-Host "[$timeStamp] Poll #$($Script:PollCount) - $totalAlerts change(s) detected! Baseline: $userCount users, $groupCount groups. Current: $currentUserCount users." -ForegroundColor Red
            }

            $Script:LastPollTime = $pollStart

            # ── Sleep with keypress checking ──────────────────────
            $sleepEnd = (Get-Date).AddSeconds($Script:PollIntervalSec)

            while ((Get-Date) -lt $sleepEnd -and $Script:MonitorRunning) {
                if ([Console]::KeyAvailable) {
                    $key = [Console]::ReadKey($true)

                    # Check for Ctrl+C
                    if ($key.Key -eq 'C' -and $key.Modifiers -band [ConsoleModifiers]::Control) {
                        Stop-Monitor
                        return
                    }

                    # Check for B (baseline update)
                    if ($key.Key -eq 'B') {
                        Update-BaselineInteractive
                        Write-Host ""
                        Write-Host "===== AD Monitor - Running (polling every $intervalMinutes minutes) =====" -ForegroundColor Cyan
                        Write-Host "Press Ctrl+C to stop | B = Update baseline | C = Canary accounts | R = Generate report" -ForegroundColor Gray
                        Write-Host ""
                    }

                    # Check for C (canary accounts)
                    if ($key.Key -eq 'C' -and -not ($key.Modifiers -band [ConsoleModifiers]::Control)) {
                        Update-CanaryAccountsInteractive
                        Write-Host ""
                        Write-Host "===== AD Monitor - Running (polling every $intervalMinutes minutes) =====" -ForegroundColor Cyan
                        Write-Host "Press Ctrl+C to stop | B = Update baseline | C = Canary accounts | R = Generate report" -ForegroundColor Gray
                        Write-Host ""
                    }

                    # Check for R (report)
                    if ($key.Key -eq 'R') {
                        Write-Host ""
                        New-ADScannerReport -ScriptName "AD Monitor" -PrintToConsole
                        Write-Host ""
                        Write-Host "===== AD Monitor - Running (polling every $intervalMinutes minutes) =====" -ForegroundColor Cyan
                        Write-Host "Press Ctrl+C to stop | B = Update baseline | C = Canary accounts | R = Generate report" -ForegroundColor Gray
                        Write-Host ""
                    }
                }

                Start-Sleep -Milliseconds 250
            }
        }
    }
    finally {
        [Console]::TreatControlCAsInput = $false
    }
}

# ══════════════════════════════════════════════════════════════════════
# ── MAIN ENTRY POINT ─────────────────────────────────────────────────
# ══════════════════════════════════════════════════════════════════════

# 1. Banner
Show-Banner

# 2. Privilege check
if (-not (Test-Privileges)) {
    Write-Host ""
    Write-Host "Privilege checks failed. Please resolve the issues above and try again." -ForegroundColor Red
    exit 1
}

# 3. Module dependencies
Test-ModuleDependencies -RequiredModules @('ActiveDirectory')

# 4. Environment auto-detection
if (-not (Initialize-Environment)) {
    Write-Host ""
    Write-Host "Environment detection failed. Cannot continue." -ForegroundColor Red
    exit 1
}

# 5. Initialize directory structure
Initialize-ADScannerDirectory

# 6. Baseline check
$usersBaselineExists = Test-Path $Script:UsersBaselineFile
$groupsBaselineExists = Test-Path $Script:GroupsBaselineFile

if (-not $usersBaselineExists -or -not $groupsBaselineExists) {
    # Also check for legacy admin-baseline.csv and inform user
    $legacyBaseline = Join-Path $Script:ConfigPath "admin-baseline.csv"
    if (Test-Path $legacyBaseline) {
        Write-Host ""
        Write-Host "Found legacy admin-baseline.csv from an older version." -ForegroundColor Yellow
        Write-Host "The monitor now tracks ALL users and groups, not just admins." -ForegroundColor Yellow
        Write-Host "A new baseline will be created. The old file will be kept for reference." -ForegroundColor Yellow
    }

    $baselineOk = Initialize-Baseline
    if (-not $baselineOk) {
        Write-Host "Baseline initialization failed. Cannot start monitoring." -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Log -Level INFO -Message "Loading users baseline from $Script:UsersBaselineFile"
    $Script:UsersBaseline = Load-UsersBaseline
    Write-Log -Level INFO -Message "Loading groups baseline from $Script:GroupsBaselineFile"
    $Script:GroupsBaseline = Load-GroupsBaseline

    if ($null -eq $Script:UsersBaseline -or $null -eq $Script:GroupsBaseline) {
        Write-Host ""
        $reinit = Read-YesNo -Prompt "Baseline files could not be loaded. Reinitialize?" -Default $true
        if ($reinit) {
            $baselineOk = Initialize-Baseline
            if (-not $baselineOk) {
                Write-Host "Baseline initialization failed. Cannot start monitoring." -ForegroundColor Red
                exit 1
            }
        }
        else {
            Write-Host "Cannot monitor without a valid baseline. Exiting." -ForegroundColor Red
            exit 1
        }
    }
    else {
        Show-BaselineSummary
        Write-Log -Level INFO -Message "Baseline loaded: $($Script:UsersBaseline.Count) users, $($Script:GroupsBaseline.Count) group memberships."
    }
}

# 7. Load canary accounts
$Script:CanaryAccounts = @(Load-CanaryAccounts)
if ($Script:CanaryAccounts.Count -gt 0) {
    Write-Log -Level INFO -Message "Loaded $($Script:CanaryAccounts.Count) canary/honey token account(s) for monitoring."
}
else {
    Write-Host ""
    Write-Host "No canary (honey token) accounts are configured." -ForegroundColor Gray
    Write-Host "Press 'C' during monitoring to add canary accounts, or edit:" -ForegroundColor Gray
    Write-Host "  $Script:CanaryAccountsFile" -ForegroundColor Gray
}

# 8. Poll interval selection
Select-PollInterval

# 9. Start monitoring
Start-MonitoringLoop
