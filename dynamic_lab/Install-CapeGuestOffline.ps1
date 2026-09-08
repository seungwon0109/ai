[CmdletBinding()]
param(
    [string]$AssetDrive,
    [string]$GuestIp = "192.168.56.10",
    [int]$PrefixLength = 24,
    [string]$InstallRoot = "C:\CAPE",
    [string]$AnalysisUser = "cape"
)

$ErrorActionPreference = "Stop"
$pythonHash = "5EE42C4EEE1E6B4464BB23722F90B45303F79442DF63083F05322F1785F5FDDE"
$sysmonHash = "A60AA845457406383277AFDEAD35BD90C7804572B99901D239CC974841DF2528"
$agentHash = "73650C79106050207E248E04A0B13B50E464D0AEF131105EEBE08F8C5764AC36"

if (-not $AssetDrive) {
    $assetVolume = Get-Volume -FileSystemLabel "CAPE_ASSETS" -ErrorAction Stop
    $AssetDrive = "$($assetVolume.DriveLetter):"
}

function Assert-Hash {
    param([string]$Path, [string]$Expected)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required asset missing: $Path"
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    if ($actual -ne $Expected) {
        throw "SHA-256 verification failed for $Path"
    }
}

$pythonInstaller = Join-Path $AssetDrive "python-3.11.9-amd64.exe"
$sysmonExe = Join-Path $AssetDrive "Sysmon64.exe"
$sysmonConfig = Join-Path $AssetDrive "sysmon-config.xml"
$agentSource = Join-Path $AssetDrive "agent.py"

Assert-Hash -Path $pythonInstaller -Expected $pythonHash
Assert-Hash -Path $sysmonExe -Expected $sysmonHash
Assert-Hash -Path $agentSource -Expected $agentHash

$sysmonSignature = Get-AuthenticodeSignature -LiteralPath $sysmonExe
if ($sysmonSignature.Status -ne "Valid" -or $sysmonSignature.SignerCertificate.Subject -notmatch "Microsoft") {
    throw "Sysmon Microsoft signature verification failed."
}

$adapter = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
if (-not $adapter) {
    throw "No active analysis network adapter was found."
}
$existingIp = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
if (-not ($existingIp | Where-Object IPAddress -eq $GuestIp)) {
    $existingIp | Where-Object PrefixOrigin -eq "Dhcp" | Remove-NetIPAddress -Confirm:$false
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $GuestIp -PrefixLength $PrefixLength | Out-Null
}
Set-NetConnectionProfile -InterfaceIndex $adapter.ifIndex -NetworkCategory Private

$pythonArgs = @("/quiet", "InstallAllUsers=1", "PrependPath=1", "Include_test=0", "Include_launcher=1")
$pythonProcess = Start-Process -FilePath $pythonInstaller -ArgumentList $pythonArgs -Wait -PassThru
if ($pythonProcess.ExitCode -ne 0) {
    throw "Python installation failed with exit code $($pythonProcess.ExitCode)."
}
$pythonExe = "C:\Program Files\Python311\python.exe"
if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
    throw "Python executable was not found after installation."
}

New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
Copy-Item -LiteralPath $agentSource -Destination (Join-Path $InstallRoot "agent.py") -Force
Copy-Item -LiteralPath $sysmonExe -Destination (Join-Path $InstallRoot "Sysmon64.exe") -Force
Copy-Item -LiteralPath $sysmonConfig -Destination (Join-Path $InstallRoot "sysmon-config.xml") -Force

& (Join-Path $InstallRoot "Sysmon64.exe") -accepteula -i (Join-Path $InstallRoot "sysmon-config.xml")
if ($LASTEXITCODE -ne 0) {
    throw "Sysmon installation failed with exit code $LASTEXITCODE."
}

$agentArgument = ('"{0}\agent.py" 0.0.0.0 8000' -f $InstallRoot)
$analysisIdentity = "$env:COMPUTERNAME\$AnalysisUser"
$taskAction = New-ScheduledTaskAction -Execute $pythonExe -Argument $agentArgument
$taskTrigger = New-ScheduledTaskTrigger -AtLogOn -User $analysisIdentity
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $analysisIdentity -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName "CAPE Agent" -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Force | Out-Null

Get-NetFirewallRule -DisplayName "CAPE Agent 8000" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "CAPE Agent 8000" -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8000 -Profile Private | Out-Null
Start-ScheduledTask -TaskName "CAPE Agent"
Start-Sleep -Seconds 2

$sysmonService = Get-Service -Name Sysmon64 -ErrorAction Stop
$agentListening = Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue
if ($sysmonService.Status -ne "Running" -or -not $agentListening) {
    throw "Guest verification failed: Sysmon or CAPE Agent is not running."
}
$agentProcess = Get-Process -Id $agentListening[0].OwningProcess -ErrorAction Stop
if ($agentProcess.SessionId -eq 0) {
    throw "CAPE Agent must run in the interactive analysis-user session, not Session 0."
}

Write-Host "Guest IP: $GuestIp/$PrefixLength"
Write-Host "Sysmon: running"
Write-Host "CAPE Agent: listening on TCP 8000 in session $($agentProcess.SessionId)"
Write-Host "Offline guest preparation completed."
