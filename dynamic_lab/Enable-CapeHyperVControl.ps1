[CmdletBinding()]
param(
    [string]$PublicKeyPath = "$PSScriptRoot\cape_hyperv.pub",
    [string]$AllowedRemoteAddress = "172.19.0.0/20"
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell window."
}
if (-not (Test-Path -LiteralPath $PublicKeyPath -PathType Leaf)) {
    throw "CAPE Hyper-V public key was not found: $PublicKeyPath"
}

$publicKey = (Get-Content -Raw -LiteralPath $PublicKeyPath).Trim()
if ($publicKey -notmatch "^ssh-ed25519\s+") {
    throw "Unexpected CAPE public key format."
}

$capability = Get-WindowsCapability -Online |
    Where-Object Name -Like "OpenSSH.Server*" |
    Select-Object -First 1
if (-not $capability) {
    throw "OpenSSH Server Windows capability was not found."
}
if ($capability.State -ne "Installed") {
    Add-WindowsCapability -Online -Name $capability.Name | Out-Null
}

Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd

$sshRoot = "C:\ProgramData\ssh"
$authorizedKeys = Join-Path $sshRoot "administrators_authorized_keys"
New-Item -ItemType Directory -Force -Path $sshRoot | Out-Null

$existingKeys = @()
if (Test-Path -LiteralPath $authorizedKeys -PathType Leaf) {
    $existingKeys = Get-Content -LiteralPath $authorizedKeys
}
if ($existingKeys -notcontains $publicKey) {
    Add-Content -LiteralPath $authorizedKeys -Value $publicKey -Encoding ascii
}

& icacls.exe $authorizedKeys /inheritance:r | Out-Null
& icacls.exe $authorizedKeys /grant "*S-1-5-18:F" | Out-Null
& icacls.exe $authorizedKeys /grant "*S-1-5-32-544:F" | Out-Null

$firewallRule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
if (-not $firewallRule) {
    New-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -DisplayName "OpenSSH SSH Server (CAPE WSL only)" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -RemoteAddress $AllowedRemoteAddress | Out-Null
}
else {
    Set-NetFirewallRule `
        -Name "OpenSSH-Server-In-TCP" `
        -Enabled True `
        -Direction Inbound `
        -Action Allow `
        -Profile Any `
        -Protocol TCP `
        -LocalPort 22 `
        -RemoteAddress $AllowedRemoteAddress
}

Restart-Service -Name sshd

Write-Host "OpenSSH Server: running"
Write-Host "Authorized CAPE key: $authorizedKeys"
Write-Host "Allowed source network: $AllowedRemoteAddress"
Write-Host "Hyper-V SSH user: $env:USERNAME"
