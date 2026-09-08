[CmdletBinding()]
param(
    [string]$Distro = "Ubuntu-24.04",
    [string]$GuestAddress = "192.168.56.10",
    [string]$LabHostAddress = "192.168.56.1",
    [int]$ResultServerPort = 2042
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window."
}

# Start WSL and resolve its current address. WSL2 addresses are not persistent.
& wsl.exe -d $Distro -u root -- true
if ($LASTEXITCODE -ne 0) {
    throw "Unable to start WSL distribution: $Distro"
}
$wslAddresses = (& wsl.exe -d $Distro -u root -- hostname -I).Trim()
$wslAddress = ($wslAddresses -split "\s+" |
    Where-Object { $_ -match "^\d{1,3}(\.\d{1,3}){3}$" } |
    Select-Object -First 1)
if (-not $wslAddress) {
    throw "Unable to determine the WSL IPv4 address."
}
$wslDefaultRoute = (& wsl.exe -d $Distro -u root -- ip -4 route show default).Trim()
$gatewayMatch = [regex]::Match($wslDefaultRoute, "\bvia\s+(\d{1,3}(?:\.\d{1,3}){3})\b")
if (-not $gatewayMatch.Success) {
    throw "Unable to determine the Windows-side WSL gateway address."
}
$wslGateway = $gatewayMatch.Groups[1].Value

# Keep a Windows-side WSL handle open while CAPE analyses are running.
$keepAlive = Get-CimInstance Win32_Process -Filter "Name='wsl.exe'" |
    Where-Object {
        $_.CommandLine -like "*-d $Distro*" -and
        $_.CommandLine -like "*sleep infinity*"
    } |
    Select-Object -First 1
if (-not $keepAlive) {
    $keepAliveProcess = Start-Process -FilePath "wsl.exe" -ArgumentList @(
        "-d", $Distro, "-u", "root", "--", "sleep", "infinity"
    ) -WindowStyle Hidden -PassThru
    Start-Sleep -Seconds 1
    if ($keepAliveProcess.HasExited) {
        throw "Unable to start the CAPE WSL keepalive process."
    }
}
# Replace only the dedicated CAPE ResultServer forwarding rule.
& netsh.exe interface portproxy delete v4tov4 `
    listenaddress=$LabHostAddress listenport=$ResultServerPort | Out-Null
& netsh.exe interface portproxy add v4tov4 `
    listenaddress=$LabHostAddress listenport=$ResultServerPort `
    connectaddress=$wslAddress connectport=$ResultServerPort
if ($LASTEXITCODE -ne 0) {
    throw "Unable to configure the CAPE ResultServer port proxy."
}

# Portproxy replaces the guest source address with the current WSL gateway.
# Keep CAPE's trusted single-VM source alias synchronized across WSL restarts.
& wsl.exe -d $Distro -u root -- crudini --set `
    /home/cape/CAPEv2/conf/cuckoo.conf resultserver proxy_source_ip $wslGateway
if ($LASTEXITCODE -ne 0) {
    throw "Unable to configure the CAPE ResultServer proxy source alias."
}

$ruleName = "CAPE-ResultServer-In-TCP"
$rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
if (-not $rule) {
    New-NetFirewallRule `
        -Name $ruleName `
        -DisplayName "CAPE ResultServer (isolated guest only)" `
        -Enabled True `
        -Direction Inbound `
        -Protocol TCP `
        -Action Allow `
        -Profile Any `
        -LocalAddress $LabHostAddress `
        -LocalPort $ResultServerPort `
        -RemoteAddress $GuestAddress | Out-Null
}
else {
    Set-NetFirewallRule `
        -Name $ruleName `
        -Enabled True `
        -Direction Inbound `
        -Action Allow `
        -Profile Any `
        -LocalAddress $LabHostAddress `
        -RemoteAddress $GuestAddress `
        -Protocol TCP `
        -LocalPort $ResultServerPort
}

$services = @(
    "mongodb",
    "postgresql",
    "suricata",
    "cape-rooter",
    "cape-processor",
    "cape-web",
    "cape"
)
& wsl.exe -d $Distro -u root -- systemctl restart @services
if ($LASTEXITCODE -ne 0) {
    throw "One or more CAPE services failed to restart."
}

Write-Host "CAPE controller started."
Write-Host "WSL address: $wslAddress"
Write-Host "ResultServer: $LabHostAddress`:$ResultServerPort -> $wslAddress`:$ResultServerPort"
Write-Host "Portproxy source accepted by CAPE: $wslGateway"
Write-Host "Guest allowed: $GuestAddress"
Write-Host ""
& wsl.exe -d $Distro -u root -- systemctl --no-pager --plain `
    status cape cape-processor cape-rooter cape-web mongodb postgresql suricata
