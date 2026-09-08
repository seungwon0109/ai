[CmdletBinding()]
param(
    [string]$AnalysisUser = "cape",
    [string]$TaskName = "CAPE Agent"
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script with administrator rights inside CAPE-Win11."
}

$python = "C:\Program Files\Python311\python.exe"
$agent = "C:\CAPE\agent.py"
$analysisIdentity = "$env:COMPUTERNAME\$AnalysisUser"

if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
    throw "Guest Python was not found: $python"
}
if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) {
    throw "CAPE Agent was not found: $agent"
}
if (-not (Get-LocalUser -Name $AnalysisUser -ErrorAction SilentlyContinue)) {
    throw "Analysis user was not found: $AnalysisUser"
}

$interactiveSession = Get-CimInstance Win32_LogonSession |
    Where-Object LogonType -eq 2 |
    ForEach-Object {
        $session = $_
        Get-CimAssociatedInstance -InputObject $session -Association Win32_LoggedOnUser |
            Where-Object { $_.Name -eq $AnalysisUser } |
            ForEach-Object { $session }
    } |
    Select-Object -First 1
if (-not $interactiveSession) {
    throw "The analysis user is not logged on interactively: $analysisIdentity"
}

$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $deadline = (Get-Date).AddSeconds(20)
    do {
        Start-Sleep -Milliseconds 500
        $listener = Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue
    } while ($listener -and (Get-Date) -lt $deadline)
}

$action = New-ScheduledTaskAction `
    -Execute $python `
    -Argument "`"$agent`" 0.0.0.0 8000"
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $analysisIdentity
$taskPrincipal = New-ScheduledTaskPrincipal `
    -UserId $analysisIdentity `
    -LogonType Interactive `
    -RunLevel Highest

Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $taskPrincipal `
    -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName

$deadline = (Get-Date).AddSeconds(30)
do {
    Start-Sleep -Seconds 1
    $listener = Get-NetTCPConnection -State Listen -LocalPort 8000 -ErrorAction SilentlyContinue |
        Select-Object -First 1
} while (-not $listener -and (Get-Date) -lt $deadline)
if (-not $listener) {
    throw "CAPE Agent did not listen on TCP port 8000."
}

$agentProcess = Get-Process -Id $listener.OwningProcess -ErrorAction Stop
if ($agentProcess.SessionId -eq 0) {
    throw "CAPE Agent is still running in Session 0."
}

$result = [ordered]@{
    migrated_at = (Get-Date).ToString("o")
    task_name = $TaskName
    run_as = (Get-ScheduledTask -TaskName $TaskName).Principal.UserId
    trigger = "AtLogOn"
    process_id = $agentProcess.Id
    session_id = $agentProcess.SessionId
    listener = "$($listener.LocalAddress):$($listener.LocalPort)"
}
$result | ConvertTo-Json | Set-Content -LiteralPath "C:\CAPE\agent-migration.json" -Encoding UTF8
