[CmdletBinding()]
param(
    [string]$SysmonConfig = "$PSScriptRoot\sysmon-config.xml",
    [string]$InstallRoot = "C:\CAPE",
    [string]$AnalysisUser = "cape"
)

$ErrorActionPreference = "Stop"
$capeAgentUrl = "https://raw.githubusercontent.com/kevoreilly/CAPEv2/e451de454137e0d44ab1ce1f72eae2e2bccfa78a/agent/agent.py"
$capeAgentSha256 = "73650c79106050207e248e04a0b13b50e464d0aef131105eebe08f8c5764ac36"

function Test-MicrosoftSignature {
    param([Parameter(Mandatory = $true)][string]$Path)
    $signature = Get-AuthenticodeSignature -LiteralPath $Path
    if ($signature.Status -ne "Valid" -or $signature.SignerCertificate.Subject -notmatch "Microsoft") {
        throw "Sysmon signature verification failed: $($signature.Status)"
    }
}

if (-not (Test-Path -LiteralPath $SysmonConfig -PathType Leaf)) {
    throw "Sysmon configuration was not found: $SysmonConfig"
}

New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
$zipPath = Join-Path $env:TEMP "Sysmon.zip"
$extractPath = Join-Path $env:TEMP "Sysmon"
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile $zipPath
Expand-Archive -LiteralPath $zipPath -DestinationPath $extractPath -Force
$sysmon = Join-Path $extractPath "Sysmon64.exe"
if (-not (Test-Path -LiteralPath $sysmon -PathType Leaf)) {
    throw "Sysmon64.exe was not present in the official archive."
}

Test-MicrosoftSignature -Path $sysmon
Copy-Item -LiteralPath $sysmon -Destination (Join-Path $InstallRoot "Sysmon64.exe") -Force
Copy-Item -LiteralPath $SysmonConfig -Destination (Join-Path $InstallRoot "sysmon-config.xml") -Force
& (Join-Path $InstallRoot "Sysmon64.exe") -accepteula -i (Join-Path $InstallRoot "sysmon-config.xml")
if ($LASTEXITCODE -ne 0) {
    throw "Sysmon installation failed with exit code $LASTEXITCODE."
}

$agentPath = Join-Path $InstallRoot "agent.py"
Invoke-WebRequest -Uri $capeAgentUrl -OutFile $agentPath
$agentHash = (Get-FileHash -LiteralPath $agentPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($agentHash -ne $capeAgentSha256) {
    throw "CAPE Agent hash verification failed."
}
$python = (Get-Command python.exe -ErrorAction SilentlyContinue).Source
if (-not $python) {
    throw "Install Python 3.x in the disposable VM before running this script."
}

$analysisIdentity = "$env:COMPUTERNAME\$AnalysisUser"
$task = New-ScheduledTaskAction -Execute $python -Argument "`"$agentPath`" 0.0.0.0 8000"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $analysisIdentity
$taskPrincipal = New-ScheduledTaskPrincipal -UserId $analysisIdentity -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName "CAPE Agent" -Action $task -Trigger $trigger -Principal $taskPrincipal -Force | Out-Null
Start-ScheduledTask -TaskName "CAPE Agent"
Write-Host "CAPE guest preparation completed. Verify Sysmon channel and CAPE Agent before taking the Ready snapshot."
