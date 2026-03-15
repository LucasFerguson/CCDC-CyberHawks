# install_python_and_requests.ps1
$ErrorActionPreference = "Stop"

$PythonVersion = "3.12.2"
$InstallerName = "python-$PythonVersion-amd64.exe"
$InstallerUrl = "https://www.python.org/ftp/python/$PythonVersion/$InstallerName"
$InstallerPath = "$env:TEMP\$InstallerName"

Write-Host "[+] Downloading Python installer from $InstallerUrl"
Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerPath

Write-Host "[+] Installing Python silently"
Start-Process -FilePath $InstallerPath -ArgumentList @(
	"/quiet",
	"InstallAllUsers=1",
	"PrependPath=1",
	"Include_test=0",
	"SimpleInstall=1"
) -Wait -NoNewWindow

Write-Host "[+] Refreshing PATH for this session"
$env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
[System.Environment]::GetEnvironmentVariable("Path", "User")

Write-Host "[+] Verifying Python install"
$pythonCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pythonCmd) {
	throw "Python was not found in PATH after install."
}

python --version

Write-Host "[+] Upgrading pip"
python -m pip install --upgrade pip

Write-Host "[+] Installing requests"
python -m pip install requests

Write-Host "[+] Done"