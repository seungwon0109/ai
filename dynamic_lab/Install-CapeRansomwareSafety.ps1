[CmdletBinding()]
param(
    [string]$SourceWrapper = "C:\CAPE\Start-CapeAgentLab.ps1",
    [string]$TaskName = "CAPE Agent"
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}
if (-not (Test-Path -LiteralPath $SourceWrapper -PathType Leaf)) {
    throw "CAPE startup wrapper was not found: $SourceWrapper"
}

$action = New-ScheduledTaskAction `
    -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$SourceWrapper`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId "SYSTEM" `
    -LogonType ServiceAccount `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $taskPrincipal `
    -Force | Out-Null

Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableScriptScanning $true

$preference = Get-MpPreference
if ($preference.ExclusionPath -notcontains "C:\Users\cape\AppData\Local\Temp") {
    Add-MpPreference -ExclusionPath "C:\Users\cape\AppData\Local\Temp"
}

$status = Get-MpComputerStatus
$task = Get-ScheduledTask -TaskName $TaskName

[ordered]@{
    installed = $true
    task_execute = $task.Actions.Execute
    task_arguments = $task.Actions.Arguments
    task_user = $task.Principal.UserId
    tamper_protected = $status.IsTamperProtected
    realtime_protection = $status.RealTimeProtectionEnabled
    behavior_monitor = $status.BehaviorMonitorEnabled
    ioav_protection = $status.IoavProtectionEnabled
} | ConvertTo-Json -Depth 4
