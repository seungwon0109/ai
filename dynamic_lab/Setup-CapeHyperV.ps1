[CmdletBinding()]
param(
    [string]$VmName = "CAPE-Win11",
    [string]$SwitchName = "CAPE-Lab",
    [string]$LabRoot = "D:\CAPE-Lab",
    [string]$IsoPath = "C:\Users\Arast\Downloads\Win11_25H2_Korean_x64_v2.iso",
    [string]$HostIp = "192.168.56.1",
    [int]$MemoryGB = 8,
    [int]$ProcessorCount = 6,
    [int]$DiskGB = 100
)

$ErrorActionPreference = "Stop"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
    throw "Run this script from an elevated PowerShell window."
}
if (-not (Get-Command New-VM -ErrorAction SilentlyContinue)) {
    throw "Hyper-V PowerShell is unavailable. Enable Hyper-V and reboot first."
}
if (-not (Test-Path -LiteralPath $IsoPath -PathType Leaf)) {
    throw "Windows ISO was not found: $IsoPath"
}
if (Get-VM -Name $VmName -ErrorAction SilentlyContinue) {
    throw "VM already exists: $VmName. No changes were made."
}

$switch = Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue
if ($switch -and $switch.SwitchType -ne "Internal") {
    throw "Existing switch '$SwitchName' is not Internal. No changes were made."
}
if (-not $switch) {
    $switch = New-VMSwitch -Name $SwitchName -SwitchType Internal
}

$adapterName = "vEthernet ($SwitchName)"
$adapter = Get-NetAdapter -Name $adapterName -ErrorAction Stop
$ipv4 = Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
if ($ipv4 -and -not ($ipv4 | Where-Object IPAddress -eq $HostIp)) {
    throw "The CAPE internal adapter already has another IPv4 address. No address was changed."
}
if (-not ($ipv4 | Where-Object IPAddress -eq $HostIp)) {
    New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress $HostIp -PrefixLength 24 | Out-Null
}

New-Item -ItemType Directory -Force -Path $LabRoot | Out-Null
$vhdPath = Join-Path $LabRoot "$VmName.vhdx"
New-VHD -Path $vhdPath -Dynamic -SizeBytes ($DiskGB * 1GB) | Out-Null
New-VM -Name $VmName -Generation 2 -MemoryStartupBytes ($MemoryGB * 1GB) -VHDPath $vhdPath -SwitchName $SwitchName | Out-Null
Set-VMProcessor -VMName $VmName -Count $ProcessorCount
Set-VMMemory -VMName $VmName -DynamicMemoryEnabled $false
Set-VM -Name $VmName -AutomaticCheckpointsEnabled $false -AutomaticStartAction Nothing -AutomaticStopAction ShutDown
Set-VMFirmware -VMName $VmName -EnableSecureBoot On -SecureBootTemplate "MicrosoftWindows"
Add-VMDvdDrive -VMName $VmName -Path $IsoPath | Out-Null
Start-VM -Name $VmName | Out-Null

Write-Host ""
Write-Host "CAPE isolated Windows VM was created and started."
Write-Host "VM name:     $VmName"
Write-Host "Lab switch:  $SwitchName (Internal only; no personal-network access)"
Write-Host "Host address:$HostIp/24"
Write-Host ""
Write-Host "Install Windows, then configure the guest with static IP 192.168.56.10/24."
Write-Host "Do not give the analysis guest an Internet-facing network adapter."
Write-Host "After guest preparation, create a Hyper-V snapshot named Ready."
Write-Host "Open its console with: vmconnect.exe localhost $VmName"
