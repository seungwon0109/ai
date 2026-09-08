$ErrorActionPreference = "Stop"

$vmName = "CAPE-Win11"
$expectedVhdRoot = "D:\CAPE-Lab\"
$vm = Get-VM -Name $vmName

if ($vm.State -ne "Off") {
    Stop-VM -Name $vmName -Force -Confirm:$false
    $deadline = (Get-Date).AddMinutes(2)
    do {
        Start-Sleep -Seconds 2
        $vm = Get-VM -Name $vmName
    } while ($vm.State -ne "Off" -and (Get-Date) -lt $deadline)
}
if ((Get-VM -Name $vmName).State -ne "Off") {
    throw "Guest did not shut down cleanly within two minutes."
}

$vhdPath = (Get-VMHardDiskDrive -VMName $vmName |
    Select-Object -First 1 -ExpandProperty Path)
$fullVhdPath = [IO.Path]::GetFullPath($vhdPath)
if (-not $fullVhdPath.StartsWith(
    $expectedVhdRoot,
    [StringComparison]::OrdinalIgnoreCase
)) {
    throw "Refusing to mount unexpected VHD path: $fullVhdPath"
}

$mounted = $false
try {
    $vhd = Mount-VHD -Path $fullVhdPath -ReadOnly -Passthru
    $mounted = $true
    $disk = $vhd | Get-Disk
    $volumes = @(
        $disk |
            Get-Partition |
            Get-Volume -ErrorAction SilentlyContinue |
            Where-Object { $_.DriveLetter }
    )
    $windowsVolume = $volumes |
        Where-Object {
            Test-Path -LiteralPath "$($_.DriveLetter):\Windows\System32"
        } |
        Select-Object -First 1
    if (-not $windowsVolume) {
        throw "Mounted Windows volume did not receive a drive letter."
    }

    $guestRoot = "$($windowsVolume.DriveLetter):\"
    $statusPath = Join-Path $guestRoot "CAPE\lab-startup-status.json"
    $wrapperPath = Join-Path $guestRoot "CAPE\Start-CapeAgentLab.ps1"

    [ordered]@{
        vm_state = (Get-VM -Name $vmName).State.ToString()
        vhd_path = $fullVhdPath
        mounted_read_only = $true
        guest_root = $guestRoot
        status_exists = Test-Path -LiteralPath $statusPath -PathType Leaf
        startup_status = $(
            if (Test-Path -LiteralPath $statusPath -PathType Leaf) {
                Get-Content -Raw -LiteralPath $statusPath
            }
        )
        wrapper_exists = Test-Path -LiteralPath $wrapperPath -PathType Leaf
    } | ConvertTo-Json -Depth 5
}
finally {
    if ($mounted) {
        Dismount-VHD -Path $fullVhdPath
    }
}


