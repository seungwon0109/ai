[CmdletBinding()]
param(
    [string]$VmName = "CAPE-Win11",
    [string]$AssetDiskPath = "D:\CAPE-Lab\CAPE-Assets.vhdx",
    [string]$SnapshotName = "Ready"
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window."
}

$vm = Get-VM -Name $VmName -ErrorAction Stop
if ($vm.State -ne "Off") {
    Stop-VM -Name $VmName -Force -Confirm:$false
    $deadline = (Get-Date).AddMinutes(6)
    while ((Get-VM -Name $VmName).State -ne "Off") {
        if ((Get-Date) -gt $deadline) {
            throw "The guest did not shut down within six minutes. Shut it down from Windows and run this script again."
        }
        Start-Sleep -Seconds 2
    }
}

$assetDisk = Get-VMHardDiskDrive -VMName $VmName |
    Where-Object Path -eq $AssetDiskPath
if ($assetDisk) {
    Remove-VMHardDiskDrive -VMHardDiskDrive $assetDisk
}

$dvd = Get-VMDvdDrive -VMName $VmName
if ($dvd.Path) {
    Set-VMDvdDrive -VMName $VmName -ControllerNumber $dvd.ControllerNumber -ControllerLocation $dvd.ControllerLocation -Path $null
}

$osDisk = Get-VMHardDiskDrive -VMName $VmName |
    Where-Object Path -ne $AssetDiskPath |
    Select-Object -First 1
if (-not $osDisk) {
    throw "The Windows OS disk was not found."
}
Set-VMFirmware -VMName $VmName -FirstBootDevice $osDisk

if (Get-VMSnapshot -VMName $VmName -Name $SnapshotName -ErrorAction SilentlyContinue) {
    throw "Snapshot already exists: $SnapshotName. It was not overwritten."
}
Checkpoint-VM -Name $VmName -SnapshotName $SnapshotName

Write-Host "Asset disk detached: $AssetDiskPath"
Write-Host "Installation ISO disconnected."
Write-Host "Checkpoint created: $SnapshotName"
Write-Host "VM remains powered off for CAPE machinery control."
