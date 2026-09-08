[CmdletBinding()]
param(
    [string]$AnalysisUser = "cape"
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window inside CAPE-Win11."
}

$python = "C:\Program Files\Python311\python.exe"
$agent = "C:\CAPE\agent.py"
$taskName = "CAPE Agent"
$analysisIdentity = "$env:COMPUTERNAME\$AnalysisUser"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Guest Python was not found: $python"
}
if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) {
    throw "CAPE Agent was not found: $agent"
}

$action = New-ScheduledTaskAction `
    -Execute $python `
    -Argument "`"$agent`" 0.0.0.0 8000"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $analysisIdentity
$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId $analysisIdentity `
    -LogonType Interactive `
    -RunLevel Highest

Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $taskPrincipal `
    -Force | Out-Null

$firewallRuleName = "CAPE-Agent-In-TCP"
$firewallRule = Get-NetFirewallRule `
    -Name $firewallRuleName `
    -ErrorAction SilentlyContinue
if (-not $firewallRule) {
    New-NetFirewallRule `
        -Name $firewallRuleName `
        -DisplayName "CAPE Agent (isolated host only)" `
        -Enabled True `
        -Profile Any `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 8000 `
        -RemoteAddress "192.168.56.1" | Out-Null
}
else {
    Set-NetFirewallRule `
        -Name $firewallRuleName `
        -Enabled True `
        -Profile Any `
        -Direction Inbound `
        -Action Allow `
        -Protocol TCP `
        -LocalPort 8000 `
        -RemoteAddress "192.168.56.1"
}
$sysmon = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue
if (-not $sysmon) {
    Write-Warning "Sysmon64 service was not found. CAPE Agent repair will continue."
}
elseif ($sysmon.Status -ne "Running") {
    Write-Warning "Sysmon64 is not running. CAPE Agent repair will continue."
}

Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 4

$task = Get-ScheduledTask -TaskName $taskName
$taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
$listener = Get-NetTCPConnection `
    -State Listen `
    -LocalPort 8000 `
    -ErrorAction SilentlyContinue

if ($task.State -ne "Running") {
    throw "CAPE Agent scheduled task is not running. LastTaskResult=$($taskInfo.LastTaskResult)"
}
if (-not $listener) {
    throw "CAPE Agent is not listening on TCP port 8000."
}
$agentProcess = Get-Process -Id $listener[0].OwningProcess -ErrorAction Stop
if ($agentProcess.SessionId -eq 0) {
    throw "CAPE Agent must run in the interactive analysis-user session, not Session 0."
}

Write-Host "CAPE Agent repair completed."
Write-Host "Task state: $($task.State)"
Write-Host "Run as: $($task.Principal.UserId)"
Write-Host "Trigger: AtLogOn"
Write-Host "Session ID: $($agentProcess.SessionId)"
Write-Host "Listener: $($listener[0].LocalAddress):$($listener[0].LocalPort)"
Write-Host "Leave this VM running and return to the host terminal."
