[CmdletBinding()]
param(
    [string]$TaskName = "CAPE Agent",
    [string]$GuestUser = "cape",
    [string]$Wrapper = "C:\CAPE\Start-CapeAgentLab.ps1"
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}
if (-not (Test-Path -LiteralPath $Wrapper -PathType Leaf)) {
    throw "CAPE safety wrapper was not found: $Wrapper"
}
if (-not (Get-LocalUser -Name $GuestUser -ErrorAction SilentlyContinue)) {
    throw "CAPE analysis user was not found: $GuestUser"
}

$action = New-ScheduledTaskAction `
    -Execute "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$Wrapper`""
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $GuestUser
$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId $GuestUser `
    -LogonType Interactive `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $taskPrincipal `
    -Force | Out-Null

$task = Get-ScheduledTask -TaskName $TaskName
[ordered]@{
    installed = $true
    task_name = $task.TaskName
    execute = $task.Actions.Execute
    arguments = $task.Actions.Arguments
    trigger_user = $task.Triggers.UserId
    run_as = $task.Principal.UserId
    logon_type = $task.Principal.LogonType.ToString()
    run_level = $task.Principal.RunLevel.ToString()
} | ConvertTo-Json -Depth 4
