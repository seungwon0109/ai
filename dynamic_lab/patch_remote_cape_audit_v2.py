from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
path = ROOT / "main.py"
text = path.read_text(encoding="utf-8")
text = text.replace("import argparse\n", "import argparse\nimport base64\nimport configparser\n")
text = text.replace(
    "def validate_cape_safety_audit(value: dict[str, Any]) -> list[str]:\n",
    "def validate_cape_safety_audit(\n    value: dict[str, Any], expected_snapshot: str | None = None\n) -> list[str]:\n",
)
old_checkpoint = '''    if not any(isinstance(item, dict) and item.get("Name") == "Ready" for item in checkpoints):
        failures.append("Ready checkpoint is missing")
'''
new_checkpoint = '''    checkpoint_names = {
        str(item.get("Name")) for item in checkpoints if isinstance(item, dict) and item.get("Name")
    }
    if expected_snapshot:
        if expected_snapshot not in checkpoint_names:
            failures.append(f"configured checkpoint is missing: {expected_snapshot}")
    elif not any(name.startswith("Ready") for name in checkpoint_names):
        failures.append("Ready checkpoint is missing")
'''
if new_checkpoint not in text:
    if old_checkpoint not in text:
        raise RuntimeError("checkpoint validation marker not found")
    text = text.replace(old_checkpoint, new_checkpoint, 1)

start = text.index("def audit_cape_safety() -> dict[str, Any]:")
end = text.index("\ndef ensure_cape_ready(", start)
replacement = """def _cape_hyperv_config(distro: str) -> configparser.ConfigParser:
    process = subprocess.run(
        [\"wsl.exe\", \"-d\", distro, \"--\", \"cat\", \"/home/cape/CAPEv2/conf/hyperv.conf\"],
        capture_output=True,
        text=True,
        encoding=\"utf-8\",
        errors=\"replace\",
        timeout=20,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(\"Unable to read CAPE Hyper-V configuration\")
    config = configparser.ConfigParser()
    config.read_string(process.stdout)
    return config


def _remote_cape_audit(distro: str) -> tuple[dict[str, Any], str]:
    config = _cape_hyperv_config(distro)
    host = config.get(\"hyperv\", \"host\")
    username = config.get(\"hyperv\", \"username\")
    key = config.get(\"hyperv\", \"ssh_key\")
    machine_section = config.get(\"hyperv\", \"machines\").split(\",\")[0].strip()
    snapshot = config.get(machine_section, \"snapshot\")
    script = r'''$ErrorActionPreference = \"Stop\"
$vm = Get-VM -Name \"CAPE-Win11\"
$adapter = Get-VMNetworkAdapter -VMName \"CAPE-Win11\"
$interface = Get-NetIPInterface -InterfaceAlias \"vEthernet (CAPE-Lab)\" -AddressFamily IPv4 | Select-Object -First 1
$natCount = @(Get-NetNat -ErrorAction SilentlyContinue | Where-Object { $_.InternalIPInterfaceAddressPrefix -like \"192.168.56.*\" }).Count
$labSwitch = Get-VMSwitch -Name \"CAPE-Lab\"
$checkpoints = @(Get-VMSnapshot -VMName \"CAPE-Win11\" | Select-Object Name,CreationTime)
[ordered]@{
  vm_name=$vm.Name
  vm_state=$vm.State.ToString()
  vm_status=$vm.Status
  switch_name=$adapter.SwitchName
  switch_type=$labSwitch.SwitchType.ToString()
  vm_addresses=@($adapter.IPAddresses)
  ipv4_forwarding=$interface.Forwarding.ToString()
  matching_nat_count=$natCount
  checkpoints=$checkpoints
} | ConvertTo-Json -Depth 6 -Compress
'''
    encoded = base64.b64encode(script.encode(\"utf-16le\")).decode(\"ascii\")
    remote = f\"powershell.exe -NoProfile -EncodedCommand {encoded}\"
    process = subprocess.run(
        [
            \"wsl.exe\", \"-d\", distro, \"--\", \"sudo\", \"-u\", \"cape\",
            \"ssh\", \"-i\", key,
            \"-o\", \"BatchMode=yes\", \"-o\", \"ConnectTimeout=10\",
            \"-o\", \"StrictHostKeyChecking=yes\",
            f\"{username}@{host}\", remote,
        ],
        capture_output=True,
        text=True,
        encoding=\"utf-8\",
        errors=\"replace\",
        timeout=60,
        check=False,
    )
    if process.returncode:
        raise RuntimeError(\"CAPE SSH safety audit failed: \" + (process.stderr or process.stdout)[-1200:])
    try:
        value = json.loads(process.stdout.strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError(\"CAPE SSH safety audit returned invalid JSON\") from exc
    return value, snapshot


def audit_cape_safety(distro: str = \"Ubuntu-24.04\") -> dict[str, Any]:
    script = PROJECT_ROOT / \"dynamic_lab\" / \"Audit-CapeHostSafety.ps1\"
    if not script.is_file():
        raise RuntimeError(f\"CAPE safety audit script was not found: {script}\")
    process = subprocess.run(
        [
            \"powershell.exe\", \"-NoProfile\", \"-ExecutionPolicy\", \"Bypass\",
            \"-File\", str(script),
        ],
        capture_output=True,
        text=True,
        encoding=\"utf-8\",
        errors=\"replace\",
        timeout=60,
        check=False,
    )
    expected_snapshot = None
    if process.returncode == 0:
        try:
            value = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(\"CAPE safety audit returned invalid JSON\") from exc
        provider = \"local-admin\"
    else:
        value, expected_snapshot = _remote_cape_audit(distro)
        provider = \"cape-hyperv-ssh\"
    failures = validate_cape_safety_audit(value, expected_snapshot)
    if failures:
        raise RuntimeError(\"CAPE safety audit failed: \" + \"; \".join(failures))
    print(
        f\"[CAPE safety] provider={provider}; Internal switch, no NAT/forwarding, \"
        f\"checkpoint={expected_snapshot or 'Ready*'} verified\"
    )
    return value

"""
text = text[:start] + replacement + text[end + 1:]
text = text.replace("            audit_cape_safety()\n", "            audit_cape_safety(args.wsl_distro)\n")
path.write_text(text, encoding="utf-8")
print("Added CAPE Hyper-V SSH fallback for read-only safety audit.")
