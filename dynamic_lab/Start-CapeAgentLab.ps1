$ErrorActionPreference = "SilentlyContinue"

$statusPath = "C:\CAPE\lab-startup-status.json"
$guestAddress = "192.168.56.10"
$agentPath = "C:\CAPE\agent.py"
$pythonPath = "C:\Program Files\Python311\python.exe"
$tempExclusion = "C:\Users\cape\AppData\Local\Temp"

function Ensure-BlockRule {
    param(
        [string]$Name,
        [ValidateSet("TCP", "UDP")]
        [string]$Protocol,
        [string]$Ports
    )

    $rule = Get-NetFirewallRule -DisplayName $Name -ErrorAction SilentlyContinue
    if (-not $rule) {
        New-NetFirewallRule `
            -DisplayName $Name `
            -Direction Outbound `
            -Action Block `
            -Enabled True `
            -Profile Any `
            -Protocol $Protocol `
            -RemotePort ($Ports -split ",") | Out-Null
    }
    else {
        Set-NetFirewallRule `
            -DisplayName $Name `
            -Direction Outbound `
            -Action Block `
            -Enabled True `
            -Profile Any | Out-Null
    }
}

Ensure-BlockRule -Name "CAPE-Block-Worm-TCP-Out" -Protocol TCP -Ports "135,139,445"
Ensure-BlockRule -Name "CAPE-Block-Worm-UDP-Out" -Protocol UDP -Ports "137,138"

$defenderReady = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    Set-MpPreference -DisableRealtimeMonitoring $true
    Set-MpPreference -DisableBehaviorMonitoring $true
    Set-MpPreference -DisableIOAVProtection $true
    Set-MpPreference -DisableScriptScanning $true

    $preference = Get-MpPreference
    if ($preference.ExclusionPath -notcontains $tempExclusion) {
        Add-MpPreference -ExclusionPath $tempExclusion
    }

    Start-Sleep -Seconds 2
    $defender = Get-MpComputerStatus
    if (
        -not $defender.IsTamperProtected -and
        -not $defender.RealTimeProtectionEnabled -and
        -not $defender.BehaviorMonitorEnabled -and
        -not $defender.IoavProtectionEnabled
    ) {
        $defenderReady = $true
        break
    }
}

$activeAddresses = @(
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -ne "127.0.0.1" -and
            $_.AddressState -eq "Preferred"
        } |
        Select-Object -ExpandProperty IPAddress
)
$defaultRoutes = @(
    Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" `
        -ErrorAction SilentlyContinue |
        Where-Object { $_.State -eq "Alive" }
)
$tcpRule = Get-NetFirewallRule -DisplayName "CAPE-Block-Worm-TCP-Out" `
    -ErrorAction SilentlyContinue
$udpRule = Get-NetFirewallRule -DisplayName "CAPE-Block-Worm-UDP-Out" `
    -ErrorAction SilentlyContinue

$networkReady = (
    $activeAddresses.Count -eq 1 -and
    $activeAddresses[0] -eq $guestAddress -and
    $defaultRoutes.Count -eq 0
)
$tcpRuleReady = @(
    $tcpRule | Where-Object {
        $_.Enabled.ToString() -in @("True", "1") -and
        $_.Action.ToString() -in @("Block", "4")
    }
).Count -gt 0
$udpRuleReady = @(
    $udpRule | Where-Object {
        $_.Enabled.ToString() -in @("True", "1") -and
        $_.Action.ToString() -in @("Block", "4")
    }
).Count -gt 0
$firewallReady = $tcpRuleReady -and $udpRuleReady
$agentFilesReady = (
    (Test-Path -LiteralPath $pythonPath -PathType Leaf) -and
    (Test-Path -LiteralPath $agentPath -PathType Leaf)
)

$startupStatus = [ordered]@{
    timestamp = (Get-Date).ToString("o")
    defender_ready = $defenderReady
    network_ready = $networkReady
    firewall_ready = $firewallReady
    agent_files_ready = $agentFilesReady
    active_ipv4 = $activeAddresses
    default_route_count = $defaultRoutes.Count
    tamper_protected = $defender.IsTamperProtected
    realtime_protection = $defender.RealTimeProtectionEnabled
    behavior_monitor = $defender.BehaviorMonitorEnabled
    ioav_protection = $defender.IoavProtectionEnabled
}
$startupStatus |
    ConvertTo-Json -Depth 4 |
    Set-Content -LiteralPath $statusPath -Encoding UTF8

if (
    -not $defenderReady -or
    -not $networkReady -or
    -not $firewallReady -or
    -not $agentFilesReady
) {
    exit 10
}

& $pythonPath $agentPath 0.0.0.0 8000

