[CmdletBinding()]
param(
    [string]$VmName = "CAPE-Win11",
    [string]$AssetSource = $PSScriptRoot,
    [string]$DiskPath = "D:\CAPE-Lab\CAPE-Assets.vhdx"
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window."
}
if (-not (Get-VM -Name $VmName -ErrorAction SilentlyContinue)) {
    throw "VM was not found: $VmName"
}
if (Test-Path -LiteralPath $DiskPath) {
    throw "Asset disk already exists: $DiskPath"
}

$required = @(
    "assets\python-3.11.9-amd64.exe",
    "assets\Sysmon\Sysmon64.exe",
    "assets\agent.py",
    "sysmon-config.xml",
    "Install-CapeGuestOffline.ps1"
)
foreach ($relative in $required) {
    if (-not (Test-Path -LiteralPath (Join-Path $AssetSource $relative) -PathType Leaf)) {
        throw "Required source file missing: $relative"
    }
}

$mountedVhd = New-VHD -Path $DiskPath -Dynamic -SizeBytes 1GB | Mount-VHD -Passthru
try {
    $disk = $mountedVhd | Get-Disk
    Initialize-Disk -Number $disk.Number -PartitionStyle GPT | Out-Null
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
    Format-Volume -Partition $partition -FileSystem NTFS -NewFileSystemLabel "CAPE_ASSETS" -Confirm:$false | Out-Null
    $driveRoot = "$($partition.DriveLetter):\"
    Copy-Item -LiteralPath (Join-Path $AssetSource "assets\python-3.11.9-amd64.exe") -Destination $driveRoot
    Copy-Item -LiteralPath (Join-Path $AssetSource "assets\Sysmon\Sysmon64.exe") -Destination $driveRoot
    Copy-Item -LiteralPath (Join-Path $AssetSource "assets\agent.py") -Destination $driveRoot
    Copy-Item -LiteralPath (Join-Path $AssetSource "sysmon-config.xml") -Destination $driveRoot
    Copy-Item -LiteralPath (Join-Path $AssetSource "Install-CapeGuestOffline.ps1") -Destination $driveRoot
}
finally {
    Dismount-VHD -Path $DiskPath
}

Add-VMHardDiskDrive -VMName $VmName -Path $DiskPath
Write-Host "Offline CAPE assets attached to $VmName."
Write-Host "Inside the VM, open the CAPE_ASSETS drive and run Install-CapeGuestOffline.ps1 as Administrator."
