<#
CCDC Baseline Capture Script
- Captures a clean baseline of services, scheduled tasks, local users/admins, startup persistence, listeners,
  processes, installed software, and exports System/Security logs.
- Safe to run repeatedly. Output files are timestamped.

Run as Administrator.
Tested on Windows Server 2019/2022.

Created by Lucas Ferguson
2026-02-13
#>

$ErrorActionPreference = 'Stop'

# -------- Settings --------
$Root = "C:\IRBaseline\$env:COMPUTERNAME"
New-Item -ItemType Directory -Force -Path $Root | Out-Null
$Stamp = Get-Date -Format "yyyyMMdd_HHmmss"

$ErrFile = Join-Path $Root "errors_$Stamp.txt"
function Write-Err($msg) {
  $line = "[{0}] {1}" -f (Get-Date -Format "s"), $msg
  $line | Out-File -FilePath $ErrFile -Append -Encoding utf8
}

function Try-Run([string]$Name, [scriptblock]$Block) {
  try {
    & $Block
  } catch {
    Write-Err "$Name failed: $($_.Exception.Message)"
  }
}

# -------- 1) Services (includes binary path) --------
Try-Run "Services" {
  Get-CimInstance Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, StartName, PathName |
    Sort-Object Name |
    Export-Csv (Join-Path $Root "Services_$Stamp.csv") -NoTypeInformation
}

# -------- 2) Scheduled Tasks (with action command) --------
Try-Run "ScheduledTasks" {
  Get-ScheduledTask | ForEach-Object {
    $t = $_
    $actions = ($t.Actions | ForEach-Object { "{0} {1}" -f $_.Execute, $_.Arguments }) -join " | "
    $info = $null
    try { $info = Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath } catch { }

    [pscustomobject]@{
      TaskName = $t.TaskName
      TaskPath = $t.TaskPath
      State    = if ($info) { $info.State } else { $null }
      RunAs    = $t.Principal.UserId
      Author   = $t.RegistrationInfo.Author
      Actions  = $actions
    }
  } |
  Sort-Object TaskPath, TaskName |
  Export-Csv (Join-Path $Root "ScheduledTasks_$Stamp.csv") -NoTypeInformation

  # Also write a compact fingerprint list that is easy to diff quickly
  Get-ScheduledTask | ForEach-Object {
    $t = $_
    $a = ($t.Actions | ForEach-Object { "{0} {1}" -f $_.Execute, $_.Arguments }) -join " | "
    "{0}{1} :: {2}" -f $t.TaskPath, $t.TaskName, $a
  } | Sort-Object | Set-Content (Join-Path $Root "TasksFingerprint_$Stamp.txt") -Encoding utf8
}

# -------- 3) Local users + local admins --------
Try-Run "LocalUsers" {
  Get-LocalUser |
    Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires |
    Sort-Object Name |
    Export-Csv (Join-Path $Root "LocalUsers_$Stamp.csv") -NoTypeInformation
}

Try-Run "LocalAdmins" {
  Get-LocalGroupMember -Group "Administrators" |
    Select-Object Name, ObjectClass, PrincipalSource |
    Sort-Object Name |
    Export-Csv (Join-Path $Root "LocalAdmins_$Stamp.csv") -NoTypeInformation
}

# -------- 4) Startup persistence: Run/RunOnce keys (normalized) --------
Try-Run "RunKeys" {
  $runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
  )

  $runRows = foreach ($rk in $runKeys) {
    if (Test-Path $rk) {
      $item = Get-ItemProperty -Path $rk
      $props = $item.PSObject.Properties |
        Where-Object { $_.Name -notmatch '^PS(Path|ParentPath|ChildName|Drive|Provider)$' }

      foreach ($p in $props) {
        [pscustomobject]@{
          Key   = $rk
          Name  = $p.Name
          Value = [string]$p.Value
        }
      }
    }
  }

  $runRows |
    Sort-Object Key, Name |
    Export-Csv (Join-Path $Root "RunKeys_$Stamp.csv") -NoTypeInformation
}

# -------- 5) Listeners, connections, and processes --------
Try-Run "ListeningPorts" {
  Get-NetTCPConnection -State Listen |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Sort-Object LocalPort |
    Export-Csv (Join-Path $Root "ListeningPorts_$Stamp.csv") -NoTypeInformation
}

Try-Run "NetUDPEndpoints" {
  # UDP does not have a Listen state like TCP; dump endpoints
  Get-NetUDPEndpoint |
    Select-Object LocalAddress, LocalPort, OwningProcess |
    Sort-Object LocalPort |
    Export-Csv (Join-Path $Root "UDPEndpoints_$Stamp.csv") -NoTypeInformation
}

Try-Run "Processes" {
  Get-Process |
    Select-Object Id, ProcessName, Path, StartTime -ErrorAction SilentlyContinue |
    Sort-Object Id |
    Export-Csv (Join-Path $Root "Processes_$Stamp.csv") -NoTypeInformation
}

# Optional: map PIDs to services for quick triage
Try-Run "ServiceProcessMap" {
  Get-CimInstance Win32_Service |
    Where-Object { $_.ProcessId -and $_.ProcessId -ne 0 } |
    Select-Object Name, DisplayName, ProcessId, StartName, State, PathName |
    Sort-Object ProcessId |
    Export-Csv (Join-Path $Root "ServiceProcessMap_$Stamp.csv") -NoTypeInformation
}

# -------- 6) Installed software (registry uninstall keys) --------
Try-Run "InstalledSoftware" {
  $paths = @(
    'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*',
    'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
  )

  Get-ItemProperty $paths -ErrorAction SilentlyContinue |
    Where-Object { $_.DisplayName } |
    Select-Object DisplayName, DisplayVersion, Publisher, InstallDate |
    Sort-Object DisplayName |
    Export-Csv (Join-Path $Root "InstalledSoftware_$Stamp.csv") -NoTypeInformation
}

# -------- 7) Basic host and domain join facts --------
Try-Run "HostInfo" {
  $cs = Get-CimInstance Win32_ComputerSystem
  $os = Get-CimInstance Win32_OperatingSystem
  [pscustomobject]@{
    ComputerName  = $env:COMPUTERNAME
    OS            = $os.Caption
    OSVersion     = $os.Version
    BuildNumber   = $os.BuildNumber
    InstallDate   = $os.InstallDate
    LastBootUp    = $os.LastBootUpTime
    PartOfDomain  = $cs.PartOfDomain
    Domain        = $cs.Domain
    Manufacturer  = $cs.Manufacturer
    Model         = $cs.Model
  } | Export-Csv (Join-Path $Root "HostInfo_$Stamp.csv") -NoTypeInformation
}

# -------- 8) Key event logs (export to EVTX) --------
Try-Run "ExportSystemLog" {
  wevtutil epl System (Join-Path $Root "System_$Stamp.evtx") /ow:true
}

Try-Run "ExportSecurityLog" {
  wevtutil epl Security (Join-Path $Root "Security_$Stamp.evtx") /ow:true
}

# -------- Done marker --------
"Baseline capture complete: $Stamp" | Set-Content (Join-Path $Root "DONE_$Stamp.txt") -Encoding utf8
if (Test-Path $ErrFile) {
  "Completed with some errors. See: $ErrFile" | Add-Content (Join-Path $Root "DONE_$Stamp.txt")
}