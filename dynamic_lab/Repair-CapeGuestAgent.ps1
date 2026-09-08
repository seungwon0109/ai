[CmdletBinding()]
param(
    [string]$VmName = "CAPE-Win11",
    [string]$SourceSnapshot = "Ready",
    [string]$NewSnapshot = "Ready-AgentStartup",
    [string]$GuestUser = "cape",
    [string]$GuestAddress = "192.168.56.10",
    [string]$Distro = "Ubuntu-24.04"
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window."
}

$vm = Get-VM -Name $VmName -ErrorAction Stop
$source = Get-VMSnapshot -VMName $VmName -Name $SourceSnapshot -ErrorAction Stop
if (Get-VMSnapshot -VMName $VmName -Name $NewSnapshot -ErrorAction SilentlyContinue) {
    throw "Snapshot already exists and was not overwritten: $NewSnapshot"
}

if ($vm.State -ne "Off") {
    Stop-VM -Name $VmName -Force -Confirm:$false
}
Restore-VMSnapshot -VMSnapshot $source -Confirm:$false
Start-VM -Name $VmName

$credential = Get-Credential `
    -UserName $GuestUser `
    -Message "Enter the password for the CAPE-Win11 guest account."

$deadline = (Get-Date).AddMinutes(3)
$sessionReady = $false
while ((Get-Date) -lt $deadline) {
    try {
        Invoke-Command `
            -VMName $VmName `
            -Credential $credential `
            -ScriptBlock { $env:COMPUTERNAME } `
            -ErrorAction Stop | Out-Null
        $sessionReady = $true
        break
    }
    catch {
        Start-Sleep -Seconds 5
    }
}
if (-not $sessionReady) {
    throw "PowerShell Direct could not connect to the guest within three minutes."
}

$guestResult = Invoke-Command `
    -VMName $VmName `
    -Credential $credential `
    -ScriptBlock {
        $ErrorActionPreference = "Stop"
        $python = "C:\Program Files\Python311\python.exe"
        $agent = "C:\CAPE\agent.py"
        $taskName = "CAPE Agent"

        if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
            throw "Guest Python was not found: $python"
        }
        if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) {
            throw "CAPE Agent was not found: $agent"
        }

        $action = New-ScheduledTaskAction `
            -Execute $python `
            -Argument "`"$agent`" 0.0.0.0 8000"
        $trigger = New-ScheduledTaskTrigger -AtLogOn -User $using:GuestUser
        $taskPrincipal = New-ScheduledTaskPrincipal `
            -UserId $using:GuestUser `
            -LogonType Interactive `
            -RunLevel Highest

        Register-ScheduledTask `
            -TaskName $taskName `
            -Action $action `
            -Trigger $trigger `
            -Principal $taskPrincipal `
            -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Start-Sleep -Seconds 4

        $task = Get-ScheduledTask -TaskName $taskName
        $listener = Get-NetTCPConnection `
            -State Listen `
            -LocalPort 8000 `
            -ErrorAction SilentlyContinue
        if ($task.State -ne "Running" -or -not $listener) {
            throw "CAPE Agent task or TCP listener did not start."
        }

        [pscustomobject]@{
            TaskState = $task.State
            ListenAddress = $listener[0].LocalAddress
            ListenPort = $listener[0].LocalPort
            RunAs = $task.Principal.UserId
        }
    }

$guestResult | Format-List

if (-not (Test-NetConnection `
    -ComputerName $GuestAddress `
    -Port 8000 `
    -InformationLevel Quiet)) {
    throw "The host cannot reach CAPE Agent at $GuestAddress`:8000."
}

Stop-VM -Name $VmName -Force -Confirm:$false
Checkpoint-VM -Name $VmName -SnapshotName $NewSnapshot

& wsl.exe -d $Distro -u root -- crudini --set `
    /home/cape/CAPEv2/conf/hyperv.conf cape-win11 snapshot $NewSnapshot
if ($LASTEXITCODE -ne 0) {
    throw "Unable to update CAPE hyperv.conf."
}
& wsl.exe -d $Distro -u root -- systemctl restart cape
if ($LASTEXITCODE -ne 0) {
    throw "Unable to restart the CAPE scheduler."
}

Write-Host "CAPE Agent interactive logon trigger: verified"
Write-Host "Host-to-agent TCP test: passed"
Write-Host "New checkpoint created: $NewSnapshot"
Write-Host "CAPE machine snapshot updated: $NewSnapshot"
Write-Host "VM remains powered off."
