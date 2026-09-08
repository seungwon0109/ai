$ErrorActionPreference = "Stop"

$vm = Get-VM -Name "CAPE-Win11"
$adapter = Get-VMNetworkAdapter -VMName "CAPE-Win11"
$interface = Get-NetIPInterface `
    -InterfaceAlias "vEthernet (CAPE-Lab)" `
    -AddressFamily IPv4
$labNats = @(
    Get-NetNat -ErrorAction SilentlyContinue |
        Where-Object {
            $_.InternalIPInterfaceAddressPrefix -like "192.168.56.*"
        }
)
$labSwitch = Get-VMSwitch -Name "CAPE-Lab"
$checkpoints = @(
    Get-VMSnapshot -VMName "CAPE-Win11" |
        Select-Object Name, CreationTime
)
$hostBlockRules = @(
    Get-NetFirewallRule -ErrorAction SilentlyContinue |
        Where-Object {
            $_.DisplayName -like "CAPE*Block*" -or
            $_.DisplayName -like "CAPE*Guest*"
        } |
        Select-Object DisplayName, Enabled, Direction, Action
)

[ordered]@{
    vm_name = $vm.Name
    vm_state = $vm.State.ToString()
    vm_status = $vm.Status
    switch_name = $adapter.SwitchName
    switch_type = $labSwitch.SwitchType.ToString()
    vm_addresses = @($adapter.IPAddresses)
    ipv4_forwarding = $interface.Forwarding.ToString()
    matching_nat_count = $labNats.Count
    checkpoints = $checkpoints
    host_block_rules = $hostBlockRules
} | ConvertTo-Json -Depth 6
